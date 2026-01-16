//
// Copyright 2020 IBM Corporation

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package operator

import (
	"context"
	"fmt"
	"time"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	certmgrv1 "github.com/IBM/ibm-iam-operator/internal/api/certmanager/v1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const DefaultClusterIssuer = "cs-ca-issuer"
const Certv1alpha1APIVersion = "certmanager.k8s.io/v1alpha1"

func (r *AuthenticationReconciler) handleCertificates(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	authCR := &operatorv1alpha1.Authentication{}
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)
	log.Info("Ensure all Certificates are present and the correct GVK")
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	certificateFieldsList := r.generateCertificateFieldsList(debugCtx, authCR)
	certificateSubreconcilers := []subreconciler.Fn{
		r.removeV1Alpha1Certs(authCR, certificateFieldsList),
		r.cleanupDefaultSAMLCertificate(authCR),
		r.createV1CertificatesIfNotPresent(authCR, certificateFieldsList),
		r.addLabelIfMissing(certificateFieldsList),
	}
	for _, fn := range certificateSubreconcilers {
		if result, err = fn(debugCtx); subreconciler.ShouldHaltOrRequeue(result, err) {
			return
		}
	}

	return
}

type reconcileCertificateFields struct {
	types.NamespacedName
	SecretName  string
	CommonName  string
	DNSNames    []string
	IPAddresses []string
}

func (r *AuthenticationReconciler) generateCertificateFieldsList(ctx context.Context, authCR *operatorv1alpha1.Authentication) []*reconcileCertificateFields {
	certList := []*reconcileCertificateFields{
		{
			NamespacedName: types.NamespacedName{
				Name:      "platform-auth-cert",
				Namespace: authCR.Namespace,
			},
			SecretName:  "platform-auth-secret",
			CommonName:  "platform-auth-service",
			DNSNames:    []string{},
			IPAddresses: []string{"127.0.0.1", "::1"},
		},
		{
			NamespacedName: types.NamespacedName{
				Name:      "identity-provider-cert",
				Namespace: authCR.Namespace,
			},
			SecretName: "identity-provider-secret",
			CommonName: "platform-identity-provider",
			DNSNames:   []string{fmt.Sprintf("platform-identity-provider.%s.svc", authCR.Namespace)},
		},
		{
			NamespacedName: types.NamespacedName{
				Name:      "platform-identity-management",
				Namespace: authCR.Namespace,
			},
			SecretName: "platform-identity-management",
			CommonName: "platform-identity-management",
			DNSNames:   []string{fmt.Sprintf("platform-identity-management.%s.svc", authCR.Namespace)},
		},
	}

	// Only create saml-auth-cert if NOT using custom ingress certificate for SAML
	// When custom cert with IM label is used, we don't need the default certificate
	if !r.shouldUseCustomIngressCertForSAML(ctx, authCR) {
		certList = append(certList, &reconcileCertificateFields{
			NamespacedName: types.NamespacedName{
				Name:      "saml-auth-cert",
				Namespace: authCR.Namespace,
			},
			SecretName: "saml-auth-secret",
			CommonName: "saml-auth",
			DNSNames:   []string{},
		})
	}

	return certList
}

func (r *AuthenticationReconciler) shouldUseCustomIngressCertForSAML(ctx context.Context, authCR *operatorv1alpha1.Authentication) bool {
	if !authCR.HasCustomIngressCertificate() {
		return false
	}
	ingressSecret := *authCR.Spec.Config.Ingress.Secret
	// Only use custom cert if it has the IM label
	return r.hasIMLabel(ctx, ingressSecret, authCR.Namespace)
}

func (r *AuthenticationReconciler) hasIMLabel(ctx context.Context, secretName, namespace string) bool {
	log := logf.FromContext(ctx)

	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret)
	if err != nil {
		log.V(1).Info("Secret not found or error retrieving it", "secret", secretName, "error", err)
		return false
	}

	if labels := secret.GetLabels(); labels != nil {
		if val, exists := labels["app.kubernetes.io/part-of"]; exists && val == "im" {
			return true
		}
	}

	return false
}

func (r *AuthenticationReconciler) GetSAMLCertificateSecretNameWithLabelCheck(ctx context.Context, authCR *operatorv1alpha1.Authentication) string {
	log := logf.FromContext(ctx)
	const defaultSAMLCertSecret = "saml-auth-secret"

	log.Info("Checking SAML certificate secret with label validation")

	// Check routerCertSecret if explicitly set
	routerCertSecret := authCR.Spec.AuthService.RouterCertSecret
	log.Info("RouterCertSecret value", "secret", routerCertSecret, "isEmpty", routerCertSecret == "", "isDefault", routerCertSecret == defaultSAMLCertSecret)

	if routerCertSecret != "" && routerCertSecret != defaultSAMLCertSecret {
		hasLabel := r.hasIMLabel(ctx, routerCertSecret, authCR.Namespace)
		log.Info("Checking routerCertSecret for IM label", "secret", routerCertSecret, "hasLabel", hasLabel)
		if hasLabel {
			log.Info("Using routerCertSecret with IM label", "secret", routerCertSecret)
			return routerCertSecret
		}
		log.Info("RouterCertSecret configured but missing 'app.kubernetes.io/part-of=im' label; falling back to default", "secret", routerCertSecret)
		return defaultSAMLCertSecret
	}

	// Check custom ingress certificate if routerCertSecret is not set or is default
	if authCR.HasCustomIngressCertificate() {
		ingressSecret := *authCR.Spec.Config.Ingress.Secret
		log.Info("Checking custom ingress secret", "secret", ingressSecret)

		hasLabel := r.hasIMLabel(ctx, ingressSecret, authCR.Namespace)
		log.Info("Custom ingress secret label check", "secret", ingressSecret, "hasLabel", hasLabel)

		if hasLabel {
			log.Info("Using custom ingress certificate secret with IM label", "secret", ingressSecret)
			return ingressSecret
		}
		log.Info("Custom ingress secret configured but missing 'app.kubernetes.io/part-of=im' label; using default", "secret", ingressSecret)
	} else {
		log.Info("No custom ingress certificate configured")
	}

	// default
	log.Info("Using default SAML certificate", "secret", defaultSAMLCertSecret)
	return defaultSAMLCertSecret
}

// removeV1Alpha1Certs removes v1alpha1 Certificates for IM so that they can be replaced with cert-manager.io/v1 Certificates.
func (r *AuthenticationReconciler) removeV1Alpha1Certs(authCR *operatorv1alpha1.Authentication, fieldsList []*reconcileCertificateFields) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		log := logf.FromContext(ctx)
		log.Info("Removing v1alpha1 Certificates for IM, if present")

		if !ctrlcommon.ClusterHasCertificateV1Alpha1(&r.DiscoveryClient) {
			log.Info("Cluster does not have v1alpha1 Certificate API; skipping")
			return subreconciler.ContinueReconciling()
		}

		allV1Alpha1CertReconcilers := make([]subreconciler.Fn, 0)
		for _, fields := range fieldsList {
			allV1Alpha1CertReconcilers = append(allV1Alpha1CertReconcilers, r.removeV1Alpha1Cert(authCR, fields))
		}
		results := []*ctrl.Result{}
		errs := []error{}
		for _, reconcileV1Alpha1Cert := range allV1Alpha1CertReconcilers {
			result, err = reconcileV1Alpha1Cert(ctx)
			results = append(results, result)
			errs = append(errs, err)
		}

		result, err = ctrlcommon.ReduceSubreconcilerResultsAndErrors(results, errs)
		if subreconciler.ShouldContinue(result, err) {
			log.Info("No v1alpha1 Certificates exist for IM")
		} else if subreconciler.ShouldRequeue(result, err) && err == nil {
			log.Info("v1alpha1 Certificates were removed; requeueing")
		} else if err != nil {
			log.Info("Encountered an issue while trying to remove v1alpha1 Certificates for IM")
		}

		return
	}
}

func (r *AuthenticationReconciler) removeV1Alpha1Cert(_ *operatorv1alpha1.Authentication, fields *reconcileCertificateFields) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		log := logf.FromContext(ctx, "Certificate.Name", fields.Name)

		log.Info("Cluster has certmanager.k8s.io/v1alpha1 API; replacing v1alpha1 Certificate if present")

		gvk := schema.GroupVersionKind{
			Group:   "certmanager.k8s.io",
			Version: "v1alpha1",
			Kind:    "Certificate",
		}

		unstrCert := &unstructured.Unstructured{}
		unstrCert.SetGroupVersionKind(gvk)

		if err = r.Get(ctx, fields.NamespacedName, unstrCert); k8sErrors.IsNotFound(err) {
			log.Info("No v1alpha1 Certificate to delete; continue")
			return subreconciler.ContinueReconciling()
		} else if err != nil {
			log.Error(err, "Failed to retrieve v1alpha1 Certificate")
			return subreconciler.RequeueWithError(err)
		}
		if unstrCert.GetAPIVersion() != Certv1alpha1APIVersion {
			log.Info("API version is not v1alpha1, continue")
			return subreconciler.ContinueReconciling()
		}
		log.Info("API version is v1alpha1; deleting Certificate")
		if err = r.Delete(ctx, unstrCert); err != nil {
			log.Error(err, "Failed to delete")
			return subreconciler.RequeueWithError(err)
		}
		log.Info("Successfully deleted")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
}

// cleanupDefaultSAMLCertificate removes the default saml-auth-cert when a custom ingress certificate is configured.
func (r *AuthenticationReconciler) cleanupDefaultSAMLCertificate(authCR *operatorv1alpha1.Authentication) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		log := logf.FromContext(ctx)

		if !r.shouldUseCustomIngressCertForSAML(ctx, authCR) {
			log.V(1).Info("Not using custom ingress certificate for SAML; skipping cleanup")
			return subreconciler.ContinueReconciling()
		}

		log.Info("Custom ingress certificate configured for SAML with IM label; attempting to delete default saml-auth-cert")

		cert := &certmgrv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "saml-auth-cert",
				Namespace: authCR.Namespace,
			},
		}

		if err = r.Delete(ctx, cert); k8sErrors.IsNotFound(err) {
			log.V(1).Info("Default saml-auth-cert does not exist; nothing to cleanup")
			return subreconciler.ContinueReconciling()
		} else if err != nil {
			log.Error(err, "Failed to delete saml-auth-cert Certificate")
			return subreconciler.RequeueWithError(err)
		}

		log.Info("Successfully deleted default saml-auth-cert Certificate")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
}

// createV1CertificatesIfNotPresent creates cert-manager.io/v1 Certificates for
// IM if they do not already exist.
func (r *AuthenticationReconciler) createV1CertificatesIfNotPresent(authCR *operatorv1alpha1.Authentication, fieldsList []*reconcileCertificateFields) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		log := logf.FromContext(ctx)
		log.Info("Create v1 Certificates if not present")

		allV1CertReconcilers := make([]subreconciler.Fn, 0)
		for _, fields := range fieldsList {
			allV1CertReconcilers = append(allV1CertReconcilers, r.createV1CertificateIfNotPresent(authCR, fields))
		}
		results := []*ctrl.Result{}
		errs := []error{}
		for _, reconcileV1Cert := range allV1CertReconcilers {
			result, err = reconcileV1Cert(ctx)
			results = append(results, result)
			errs = append(errs, err)
		}

		result, err = ctrlcommon.ReduceSubreconcilerResultsAndErrors(results, errs)
		if subreconciler.ShouldContinue(result, err) {
			log.Info("No v1 Certificates to create for IM")
		} else if subreconciler.ShouldRequeue(result, err) && err == nil {
			log.Info("v1 Certificates were created; requeueing")
		} else if err != nil {
			log.Info("Encountered an issue while trying to create v1 Certificates for IM")
		}

		return
	}
}

// createV1CertificateIfNotPresent checks for the presence of the Certificate identified by the provided fields and
// creates a Certificate if one is not found. Does not update the Certificate if it already exists with different values
// than the ones provided.
func (r *AuthenticationReconciler) createV1CertificateIfNotPresent(authCR *operatorv1alpha1.Authentication, fields *reconcileCertificateFields) subreconciler.Fn {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		log := logf.FromContext(ctx, "Certificate.Name", fields.Name)
		cert := &certmgrv1.Certificate{}
		err = r.Get(ctx, fields.NamespacedName, cert)
		if err == nil {
			return subreconciler.ContinueReconciling()
		} else if !k8sErrors.IsNotFound(err) {
			log.Error(err, "Failed to get Certificate")
			return subreconciler.RequeueWithError(err)
		}
		// Define a new Certificate
		var newCertificate *certmgrv1.Certificate
		newCertificate, err = r.generateCertificateObject(authCR, fields)
		if err != nil {
			err = fmt.Errorf("failed to generate a new Certificate object: %w", err)
			return
		}
		log.Info("Creating a new Certificate")
		err = r.Create(ctx, newCertificate)
		if k8sErrors.IsAlreadyExists(err) {
			log.Info("Certificate already exists; continuing")
			return subreconciler.ContinueReconciling()
		} else if err != nil {
			log.Error(err, "Failed to create new Certificate")
			return subreconciler.RequeueWithError(err)
		}
		log.Info("Certificate created")
		// Certificate created successfully - return and requeue
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
}

// addLabelIfMissing adds "manage-cert-rotation": "true" label to the certificate if not exist
func (r *AuthenticationReconciler) addLabelIfMissing(fieldsList []*reconcileCertificateFields) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		log := logf.FromContext(ctx)
		log.Info("Add any labels that are missing to Certificates")
		allV1CertReconcilers := make([]subreconciler.Fn, 0)
		for _, fields := range fieldsList {
			allV1CertReconcilers = append(allV1CertReconcilers, r.updateCertWithLabel(fields))
		}
		results := []*ctrl.Result{}
		errs := []error{}
		for _, reconcileV1Cert := range allV1CertReconcilers {
			result, err = reconcileV1Cert(ctx)
			results = append(results, result)
			errs = append(errs, err)
		}

		result, err = ctrlcommon.ReduceSubreconcilerResultsAndErrors(results, errs)
		if subreconciler.ShouldContinue(result, err) {
			log.Info("No certificates to be labeled")
		} else if subreconciler.ShouldRequeue(result, err) && err == nil {
			log.Info("Certificates were labeled; requeueing")
		} else if err != nil {
			log.Info("Encountered an issue while trying to label certificates")
		}

		return
	}
}

func (r *AuthenticationReconciler) updateCertWithLabel(fields *reconcileCertificateFields) subreconciler.Fn {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		log := logf.FromContext(ctx, "Certificate.Name", fields.Name)
		cert := &certmgrv1.Certificate{}
		err = r.Get(ctx, fields.NamespacedName, cert)
		if err != nil {
			log.Error(err, "Failed to get Certificate for labelling")
			return subreconciler.RequeueWithError(err)
		}
		certRotationKey := "manage-cert-rotation"
		labelValue, exists := cert.Labels[certRotationKey]
		if exists && labelValue != "yes" {
			return subreconciler.ContinueReconciling()
		}
		log.Info("Updating Certificate with label manage-cert-rotation: true")
		cert.Labels[certRotationKey] = "true"
		err = r.Update(ctx, cert)
		if err != nil {
			log.Error(err, "Failed to update Certificate with label")
			return subreconciler.RequeueWithError(err)
		}
		// Certificate label updated successfully - return and requeue
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
}

func (r *AuthenticationReconciler) generateCertificateObject(authCR *operatorv1alpha1.Authentication, fields *reconcileCertificateFields) (certificate *certmgrv1.Certificate, err error) {
	metaLabels := map[string]string{
		"app":                          fields.CommonName,
		"app.kubernetes.io/instance":   "ibm-iam-operator",
		"app.kubernetes.io/managed-by": "ibm-iam-operator",
		"app.kubernetes.io/name":       fields.CommonName,
		"manage-cert-rotation":         "yes",
	}

	certificate = &certmgrv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fields.Name,
			Labels:    metaLabels,
			Namespace: fields.Namespace,
		},
		Spec: certmgrv1.CertificateSpec{
			CommonName: fields.CommonName,
			SecretName: fields.SecretName,
			IsCA:       false,
			DNSNames:   append(fields.DNSNames, fields.CommonName),
			IssuerRef: certmgrv1.ObjectReference{
				Name: DefaultClusterIssuer,
				Kind: certmgrv1.IssuerKind,
			},
			Duration: &metav1.Duration{
				Duration: 9552 * time.Hour, /* 398 days */
			},
			RenewBefore: &metav1.Duration{
				Duration: 2880 * time.Hour, /* 120 days (3 months) */
			},
			IPAddresses: fields.IPAddresses,
		},
	}

	// Set Authentication instance as the owner and controller of the Certificate
	err = controllerutil.SetControllerReference(authCR, certificate, r.Client.Scheme())

	return
}
