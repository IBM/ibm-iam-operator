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
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "handleCertificates")
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	certificateFieldsList := generateCertificateFieldsList(authCR)
	certificateSubreconcilers := []subreconciler.Fn{
		r.removeV1Alpha1Certs(authCR, certificateFieldsList),
		r.createV1CertificatesIfNotPresent(authCR, certificateFieldsList),
		r.addLabelIfMissing(certificateFieldsList),
	}
	reqLogger.Info("Reconciling Certificates")
	fnCtx := ctrl.LoggerInto(ctx, reqLogger)
	for _, fn := range certificateSubreconcilers {
		if result, err = fn(fnCtx); subreconciler.ShouldHaltOrRequeue(result, err) {
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

func generateCertificateFieldsList(authCR *operatorv1alpha1.Authentication) []*reconcileCertificateFields {
	return []*reconcileCertificateFields{
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
		{
			NamespacedName: types.NamespacedName{
				Name:      "saml-auth-cert",
				Namespace: authCR.Namespace,
			},
			SecretName: "saml-auth-secret",
			CommonName: "saml-auth",
			DNSNames:   []string{},
		},
	}
}

// removeV1Alpha1Certs removes v1alpha1 Certificates for IM so that they can be replaced with cert-manager.io/v1 Certificates.
func (r *AuthenticationReconciler) removeV1Alpha1Certs(authCR *operatorv1alpha1.Authentication, fieldsList []*reconcileCertificateFields) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := ctrl.LoggerFrom(ctx)
		reqLogger.Info("Removing v1alpha1 Certificates for IM, if present")

		if !ctrlcommon.ClusterHasCertificateV1Alpha1(&r.DiscoveryClient) {
			reqLogger.Info("Cluster does not have v1alpha1 Certificate API; skipping")
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
			reqLogger.Info("No v1alpha1 Certificates exist for IM")
		} else if subreconciler.ShouldRequeue(result, err) && err == nil {
			reqLogger.Info("v1alpha1 Certificates were removed; requeueing")
		} else if err != nil {
			reqLogger.Info("Encountered an issue while trying to remove v1alpha1 Certificates for IM")
		}

		return
	}
}

func (r *AuthenticationReconciler) removeV1Alpha1Cert(_ *operatorv1alpha1.Authentication, fields *reconcileCertificateFields) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := ctrl.LoggerFrom(ctx, "Certificate.Name", fields.Name, "Certificate.Namespace", fields.Namespace)

		reqLogger.Info("Cluster has certmanager.k8s.io/v1alpha1 API; replacing v1alpha1 Certificate if present")

		gvk := schema.GroupVersionKind{
			Group:   "certmanager.k8s.io",
			Version: "v1alpha1",
			Kind:    "Certificate",
		}

		unstrCert := &unstructured.Unstructured{}
		unstrCert.SetGroupVersionKind(gvk)

		if err = r.Get(ctx, fields.NamespacedName, unstrCert); k8sErrors.IsNotFound(err) {
			reqLogger.Info("No v1alpha1 Certificate to delete; continue")
			return subreconciler.ContinueReconciling()
		} else if err != nil {
			reqLogger.Error(err, "Failed to retrieve v1alpha1 Certificate")
			return subreconciler.RequeueWithError(err)
		}
		if unstrCert.GetAPIVersion() == Certv1alpha1APIVersion {
			reqLogger.Info("API version is v1alpha1; deleting Certificate")
			err = r.Delete(ctx, unstrCert)
			if err != nil {
				reqLogger.Error(err, "Failed to delete")
				return subreconciler.RequeueWithError(err)
			} else {
				reqLogger.Info("Successfully deleted")
				return subreconciler.RequeueWithDelay(defaultLowerWait)
			}
		}
		reqLogger.Info("API version is not v1alpha1, continue")
		return subreconciler.ContinueReconciling()
	}
}

// createV1CertificatesIfNotPresent creates cert-manager.io/v1 Certificates for
// IM if they do not already exist.
func (r *AuthenticationReconciler) createV1CertificatesIfNotPresent(authCR *operatorv1alpha1.Authentication, fieldsList []*reconcileCertificateFields) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := ctrl.LoggerFrom(ctx)

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
			reqLogger.Info("No v1 Certificates to create for IM")
		} else if subreconciler.ShouldRequeue(result, err) && err == nil {
			reqLogger.Info("v1 Certificates were created; requeueing")
		} else if err != nil {
			reqLogger.Info("Encountered an issue while trying to create v1 Certificates for IM")
		}

		return
	}
}

// createV1CertificateIfNotPresent checks for the presence of the Certificate identified by the provided fields and
// creates a Certificate if one is not found. Does not update the Certificate if it already exists with different values
// than the ones provided.
func (r *AuthenticationReconciler) createV1CertificateIfNotPresent(authCR *operatorv1alpha1.Authentication, fields *reconcileCertificateFields) subreconciler.Fn {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := ctrl.LoggerFrom(ctx, "Certificate.Name", fields.Name, "Certificate.Namespace", fields.Namespace)
		cert := &certmgrv1.Certificate{}
		err = r.Get(ctx, fields.NamespacedName, cert)
		if k8sErrors.IsNotFound(err) {
			// Define a new Certificate
			newCertificate := r.generateCertificateObject(authCR, fields)
			if newCertificate == nil {
				err = fmt.Errorf("failed to generate a new Certificate object")
				return
			}
			reqLogger.Info("Creating a new Certificate")
			err = r.Create(ctx, newCertificate)
			if k8sErrors.IsAlreadyExists(err) {
				reqLogger.Info("Certificate already exists; continuing")
				return subreconciler.ContinueReconciling()
			} else if err != nil {
				reqLogger.Error(err, "Failed to create new Certificate")
				return subreconciler.RequeueWithError(err)
			}
			reqLogger.Info("Certificate created")
			// Certificate created successfully - return and requeue
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		} else if err != nil {
			reqLogger.Error(err, "Failed to get Certificate")
			return subreconciler.RequeueWithError(err)
		}
		return subreconciler.ContinueReconciling()
	}
}

// addLabelIfMissing adds "manage-cert-rotation": "true" label to the certificate if not exist
func (r *AuthenticationReconciler) addLabelIfMissing(fieldsList []*reconcileCertificateFields) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := ctrl.LoggerFrom(ctx)

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
			reqLogger.Info("No certificates to be labeled")
		} else if subreconciler.ShouldRequeue(result, err) && err == nil {
			reqLogger.Info("Certificates were labeled; requeueing")
		} else if err != nil {
			reqLogger.Info("Encountered an issue while trying to label certificates")
		}

		return
	}
}

func (r *AuthenticationReconciler) updateCertWithLabel(fields *reconcileCertificateFields) subreconciler.Fn {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := ctrl.LoggerFrom(ctx, "Certificate.Name", fields.Name, "Certificate.Namespace", fields.Namespace)
		cert := &certmgrv1.Certificate{}
		err = r.Get(ctx, fields.NamespacedName, cert)
		if err == nil {
			certRotationKey := "manage-cert-rotation"
			labelValue, exists := cert.Labels[certRotationKey]
			if !exists || labelValue == "yes" {
				reqLogger.Info("Updating Certificate with label manage-cert-rotation: true")
				cert.Labels[certRotationKey] = "true"
				err = r.Update(ctx, cert)
				if err != nil {
					reqLogger.Error(err, "Failed to update Certificate with label")
					return subreconciler.RequeueWithError(err)
				}
				// Certificate label updated successfully - return and requeue
				return subreconciler.RequeueWithDelay(defaultLowerWait)
			}
			return subreconciler.ContinueReconciling()
		} else {
			reqLogger.Error(err, "Failed to get Certificate for labelling")
			return subreconciler.RequeueWithError(err)
		}
	}
}

func (r *AuthenticationReconciler) generateCertificateObject(authCR *operatorv1alpha1.Authentication, fields *reconcileCertificateFields) *certmgrv1.Certificate {
	metaLabels := map[string]string{
		"app":                          fields.CommonName,
		"app.kubernetes.io/instance":   "ibm-iam-operator",
		"app.kubernetes.io/managed-by": "ibm-iam-operator",
		"app.kubernetes.io/name":       fields.CommonName,
		"manage-cert-rotation":         "yes",
	}

	certificate := &certmgrv1.Certificate{
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
	err := controllerutil.SetControllerReference(authCR, certificate, r.Client.Scheme())
	if err != nil {
		return nil
	}
	return certificate
}
