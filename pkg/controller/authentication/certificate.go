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

package authentication

import (
	"context"
	//certmgr "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	//certmgrv1alpha1 "github.com/ibm/ibm-cert-manager-operator/apis/certmanager/v1alpha1"
	certmgr "github.com/IBM/ibm-iam-operator/pkg/apis/certmanager/v1alpha1"
	//certmgrv1 "github.com/IBM/ibm-iam-operator/pkg/apis/certmanager/v1"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var certificateData map[string]map[string]string
//const DefaultClusterIssuer = "cs-ca-issuer"
const Certv1alpha1APIVersion = "certmanager.k8s.io/v1alpha1"

func generateCertificateData(instance *operatorv1alpha1.Authentication) {
	completeName := "platform-identity-management." + instance.Namespace + ".svc"
	certificateData = map[string]map[string]string{
		"platform-auth-cert": {
			"secretName": "platform-auth-secret",
			"cn":         "platform-auth-service",
		},
		"identity-provider-cert": {
			"secretName": "identity-provider-secret",
			"cn":         "platform-identity-provider",
		},
		"platform-identity-management": {
			"secretName":   "platform-identity-management",
			"cn":           "platform-identity-management",
			"completeName": completeName,
		},
	}
}

func (r *ReconcileAuthentication) handleCertificate(instance *operatorv1alpha1.Authentication, currentCertificate *certmgr.Certificate, requeueResult *bool) error {

	generateCertificateData(instance)

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	for certificate := range certificateData {
		// Delete v1alpha1 Certificate
		r.deleteCertsv1alpha1(context.TODO(),instance, r.scheme, certificate)
		err = r.client.Get(context.TODO(), types.NamespacedName{Name: certificate, Namespace: instance.Namespace}, currentCertificate)
		if err != nil && errors.IsNotFound(err) {
			// Define a new Certificate
			newCertificate := generateCertificateObject(instance, r.scheme, certificate)
			reqLogger.Info("Creating a new Certificate", "Certificate.Namespace", instance.Namespace, "Certificate.Name", certificate)
			err = r.client.Create(context.TODO(), newCertificate)
			if err != nil {
				reqLogger.Error(err, "Failed to create new Certificate", "Certificate.Namespace", instance.Namespace, "Certificate.Name", certificate)
				return err
			}
			// Certificate created successfully - return and requeue
			*requeueResult = true
		} else if err != nil {
			reqLogger.Error(err, "Failed to get Certificate")
			return err
		}

	}
	return nil
}

func generateCertificateObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, certificateName string) *certmgr.Certificate {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	certSpec := certmgr.CertificateSpec{
		SecretName: certificateData[certificateName]["secretName"],
		IssuerRef: certmgr.ObjectReference{
			Name: "cs-ca-issuer",
			Kind: certmgr.IssuerKind,
		},
		CommonName: certificateData[certificateName]["cn"],
		DNSNames:   []string{certificateData[certificateName]["cn"]},
	}
	if certificateName == "platform-identity-management" {
		certSpec.DNSNames = append(certSpec.DNSNames, certificateData[certificateName]["completeName"])
	}
	if certificateName == "platform-auth-cert" {
		certSpec.IPAddresses = []string{"127.0.0.1", "::1"}
	}
	newCertificate := &certmgr.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certificateName,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": certificateData[certificateName]["cn"]},
		},
		Spec: certSpec,
	}

	// Set Authentication instance as the owner and controller of the Certificate
	err := controllerutil.SetControllerReference(instance, newCertificate, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Certificate")
		return nil
	}
	return newCertificate
}

func (r *ReconcileAuthentication) deleteCertsv1alpha1(ctx context.Context, instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, certificateName string) {
	reqLogger := log.WithValues("func", "deleteCertsv1alpha1", "instance.Name", instance.Name, "instance.Namespace", instance.Namespace)

	certificate := &certmgr.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certificateName,
			Namespace: instance.Namespace,
		},
	}
	err := r.client.Get(ctx, types.NamespacedName{Name: certificateName, Namespace: instance.Namespace}, certificate)

	if err != nil {
		if !errors.IsNotFound(err) {
			reqLogger.Info("Unable to load v1alpha1 certificate - most likely this means the CRD doesn't exist and this can be ignored")
		}
		return
	}
	reqLogger.Info("Certificate "+ certificateName+" found, checking api version..")
	reqLogger.Info("API version is: " + certificate.APIVersion)
	if certificate.APIVersion == Certv1alpha1APIVersion {
		reqLogger.Info("deleting cert: " + certificateName)
		err = r.client.Delete(ctx, certificate)
		if err != nil {
			reqLogger.Error(err, "Failed to delete")
		} else {
			reqLogger.Info("Successfully deleted")
		}
	} else {
		reqLogger.Info("API version is NOT v1alpha1, returning..")
	}
}
