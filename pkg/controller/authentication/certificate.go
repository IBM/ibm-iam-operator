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

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	certmgr "github.com/IBM/ibm-iam-operator/pkg/apis/certmanager/v1alpha1"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
)

var certificateData map[string]map[string]string

func generateCertificateData(instance *operatorv1alpha1.Authentication) {
	certificateData = map[string]map[string]string{
		"platform-auth-cert": map[string]string{
			"secretName": "platform-auth-secret",
			"cn":         "platform-auth-service",
		},
		"identity-provider-cert": map[string]string{
			"secretName": "identity-provider-secret",
			"cn":         "platform-identity-provider",
		},
		"platform-identity-management": map[string]string{
			"secretName":   "platform-identity-management",
			"cn":           "platform-identity-management",
			"completeName": "platform-identity-management.ibm-common-services.svc",
		},
	}
}

func (r *ReconcileAuthentication) handleCertificate(instance *operatorv1alpha1.Authentication, currentCertificate *certmgr.Certificate, requeueResult *bool) error {

	generateCertificateData(instance)

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	for certificate, _ := range certificateData {
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
			Name: "cs-ca-clusterissuer",
			Kind: certmgr.ClusterIssuerKind,
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
			Labels:    map[string]string{"app": "auth-idp"},
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
