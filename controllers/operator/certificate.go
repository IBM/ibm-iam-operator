//
// Copyright 2020 IBM Corporation
//
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
	"time"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	certmgrv1 "github.com/ibm/ibm-cert-manager-operator/apis/cert-manager/v1"
	cmmeta "github.com/ibm/ibm-cert-manager-operator/apis/meta.cert-manager/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var certificateData map[string]map[string]string

const DefaultClusterIssuer = "cs-ca-issuer"
const Certv1alpha1APIVersion = "certmanager.k8s.io/v1alpha1"

func generateCertificateData(instance *operatorv1alpha1.Authentication) {
	completeName := "platform-identity-management." + instance.Namespace + ".svc"
	completeNameProvider := "platform-identity-provider." + instance.Namespace + ".svc"
	certificateData = map[string]map[string]string{
		"platform-auth-cert": {
			"secretName": "platform-auth-secret",
			"cn":         "platform-auth-service",
		},
		"identity-provider-cert": {
			"secretName":   "identity-provider-secret",
			"cn":           "platform-identity-provider",
			"completeName": completeNameProvider,
		},
		"platform-identity-management": {
			"secretName":   "platform-identity-management",
			"cn":           "platform-identity-management",
			"completeName": completeName,
		},
		"saml-auth-cert": {
			"secretName": "saml-auth-secret",
			"cn":         "saml-auth",
		},
	}
}

func (r *AuthenticationReconciler) handleCertificate(instance *operatorv1alpha1.Authentication, currentCertificate *certmgrv1.Certificate, needToRequeue *bool) (err error) {

	generateCertificateData(instance)

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)

	for certificate := range certificateData {
		// Delete v1alpha1 Certificate
		r.deleteCertsv1alpha1(context.TODO(), instance, r.Scheme, certificate)
		err = r.Client.Get(context.TODO(), types.NamespacedName{Name: certificate, Namespace: instance.Namespace}, currentCertificate)
		if err != nil && errors.IsNotFound(err) {
			// Define a new Certificate
			newCertificate := generateCertificateObject(instance, r.Scheme, certificate)
			reqLogger.Info("Creating a new Certificate", "Certificate.Namespace", instance.Namespace, "Certificate.Name", certificate)
			err = r.Client.Create(context.TODO(), newCertificate)
			if err != nil {
				reqLogger.Error(err, "Failed to create new Certificate", "Certificate.Namespace", instance.Namespace, "Certificate.Name", certificate)
				return
			}
			// Certificate created successfully - return and requeue
			*needToRequeue = true
		} else if err != nil {
			reqLogger.Error(err, "Failed to get Certificate")
			return
		}

	}
	return
}

func generateCertificateObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, certificateName string) *certmgrv1.Certificate {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	metaLabels := map[string]string{
		"app":                          certificateData[certificateName]["cn"],
		"app.kubernetes.io/instance":   "ibm-iam-operator",
		"app.kubernetes.io/managed-by": "ibm-iam-operator",
		"app.kubernetes.io/name":       certificateData[certificateName]["cn"],
	}

	certificate := &certmgrv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certificateName,
			Labels:    metaLabels,
			Namespace: instance.Namespace,
		},
		Spec: certmgrv1.CertificateSpec{
			CommonName: certificateData[certificateName]["cn"],
			SecretName: certificateData[certificateName]["secretName"],
			IsCA:       false,
			DNSNames:   []string{certificateData[certificateName]["cn"]},
			IssuerRef: cmmeta.ObjectReference{
				Name: DefaultClusterIssuer,
				Kind: certmgrv1.IssuerKind,
			},
			Duration: &metav1.Duration{
				Duration: 9552 * time.Hour, /* 398 days */
			},
			RenewBefore: &metav1.Duration{
				Duration: 2880 * time.Hour, /* 120 days (3 months) */
			},
		},
	}
	if certificateName == "platform-identity-management" {
		certificate.Spec.DNSNames = append(certificate.Spec.DNSNames, certificateData[certificateName]["completeName"])
	}
	if certificateName == "identity-provider-cert" {
		certificate.Spec.DNSNames = append(certificate.Spec.DNSNames, certificateData[certificateName]["completeName"])
	}
	if certificateName == "platform-auth-cert" {
		certificate.Spec.IPAddresses = []string{"127.0.0.1", "::1"}
	}

	// Set Authentication instance as the owner and controller of the Certificate
	err := controllerutil.SetControllerReference(instance, certificate, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Certificate")
		return nil
	}
	return certificate
}

func (r *AuthenticationReconciler) deleteCertsv1alpha1(ctx context.Context, instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, certificateName string) {
	reqLogger := log.WithValues("func", "deleteCertsv1alpha1", "instance.Name", instance.Name, "instance.Namespace", instance.Namespace)

	cfg, err := config.GetConfig()
	if err != nil {
		reqLogger.Error(err, "Could not obtain cluster config")
	}

	certClient, err := client.New(cfg, client.Options{})
	if err != nil {
		reqLogger.Error(err, "Failed to create client")
	}

	key := types.NamespacedName{Name: certificateName, Namespace: instance.Namespace}

	gvk := schema.GroupVersionKind{
		Group:   "certmanager.k8s.io",
		Version: "v1alpha1",
		Kind:    "Certificate",
	}

	unstrCert := &unstructured.Unstructured{}
	unstrCert.SetGroupVersionKind(gvk)

	err = certClient.Get(ctx, key, unstrCert)

	if err != nil {
		if !errors.IsNotFound(err) {
			reqLogger.Info("Unable to load v1alpha1 certificate - most likely this means the CRD doesn't exist and this can be ignored")
		}
		return
	}
	reqLogger.Info("Checking for existing certificate", "Certificate.Namespace", instance.Namespace, "Certificate found, checking api version", certificateName)
	reqLogger.Info("Checking for existing certificate", "Certificate.Namespace", instance.Namespace, "API version is: "+unstrCert.GetAPIVersion())
	if unstrCert.GetAPIVersion() == Certv1alpha1APIVersion {
		reqLogger.Info("deleting cert: " + certificateName)
		err = certClient.Delete(ctx, unstrCert)
		if err != nil {
			reqLogger.Error(err, "Failed to delete")
		} else {
			reqLogger.Info("Successfully deleted")
		}
	} else {
		reqLogger.Info("API version is NOT v1alpha1, returning..")
	}
}
