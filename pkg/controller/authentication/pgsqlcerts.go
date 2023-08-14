//
// Copyright 2022 IBM Corporation
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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	certmgrv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var EDBCRName string = "im-store-edb"
var namespace string

// IamPgsqlServerCertificateValues defines the values of iam-postgres certificate
type IamPgsqlServerCertificateValues struct {
	Name       string
	SecretName string
	CN         []string
}

type IamPgsqlClientCACertificateValues struct {
	Name       string
	SecretName string
	CommonName string
}

var iamPgsqlServerCertificateValues = IamPgsqlServerCertificateValues{
	Name:       "im-pgsql-server-cert",
	SecretName: "im-pgsql-server-cert",
	CN: []string{EDBCRName + "-rw", EDBCRName + "-rw" + "." + namespace, EDBCRName + "-rw" + "." + namespace + "." + "svc",
		EDBCRName + "-ro", EDBCRName + "-ro" + "." + namespace, EDBCRName + "-ro" + "." + namespace + "." + "svc",
		EDBCRName + "-r", EDBCRName + "-r" + "." + namespace, EDBCRName + "-r" + "." + namespace + "." + "svc"},
}

var iamPostgresClientCertificateValues = IamPgsqlClientCACertificateValues{
	Name:       "im-pgsql-client-cert",
	SecretName: "im-pgsql-client-cert",
	CommonName: "streaming_replica",
}

// create required certificates for postgresql cluster
func (r *ReconcileAuthentication) handlePgsqlCerts(instance *operatorv1alpha1.Authentication, currentCertificate *certmgrv1.Certificate, needToRequeue *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", namespace, "Instance.Name", instance.Name)
	namespace = instance.Namespace
	serverCrt := iamPgsqlServerCertificateValues.Name
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: serverCrt, Namespace: namespace}, currentCertificate)
	if err != nil && k8serrors.IsNotFound(err) {
		// Define a new Server certificate
		newCertificate := r.certificateForEDBCluster(instance, serverCrt)
		reqLogger.Info("EDB:: Creating a new server Certificate", "Certificate.Namespace", namespace, "Certificate.Name", serverCrt)
		err = r.client.Create(context.TODO(), newCertificate)
		if err != nil {
			reqLogger.Error(err, "EDB:: Failed to create new Certificate", "Certificate.Namespace", namespace, "Certificate.Name", serverCrt)
			return err
		}
		// Server Certificate created successfully - return and requeue
		*needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "EDB:: Failed to get Server Certificate")
		return err
	}
	reqLogger.Info("EDB:: Server cert is ALREADY PRESENT")
	clientCrt := iamPostgresClientCertificateValues.Name
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: clientCrt, Namespace: namespace}, currentCertificate)
	if err != nil && k8serrors.IsNotFound(err) {
		// Define a new Client certificate
		newCertificate := r.certificateForEDBClient(instance, clientCrt)
		reqLogger.Info("EDB:: Creating a new client Certificate", "Certificate.Namespace", namespace, "Certificate.Name", clientCrt)
		err = r.client.Create(context.TODO(), newCertificate)
		if err != nil {
			reqLogger.Error(err, "EDB:: Failed to create new Certificate", "Certificate.Namespace", namespace, "Certificate.Name", clientCrt)
			return err
		}
		// Client Certificate created successfully - return and requeue
		*needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "EDB:: Failed to get Client Certificate")
		return err
	}
	reqLogger.Info("EDB:: Client cert is ALREADY PRESENT")
	return nil

}

func (r *ReconcileAuthentication) certificateForEDBCluster(instance *operatorv1alpha1.Authentication, cert string) *certmgrv1.Certificate {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	edbServerCertificate := &certmgrv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "security-iam", "k8s.enterprisedb.io/reload": ""},
		},
		Spec: certmgrv1.CertificateSpec{
			SecretName: iamPgsqlServerCertificateValues.SecretName,
			IssuerRef: cmmeta1.ObjectReference{
				Name: "cs-ca-issuer",
				Kind: certmgrv1.IssuerKind,
			},
			DNSNames: iamPgsqlServerCertificateValues.CN,
			Usages:   []certmgrv1.KeyUsage{"server auth"},
		},
	}

	// Set Pap instance as the owner and controller of the Certificate
	err := controllerutil.SetControllerReference(instance, edbServerCertificate, r.scheme)
	if err != nil {
		reqLogger.Error(err, "EDB:: Failed to set owner for Certificate")
		return nil
	}
	return edbServerCertificate
}

func (r *ReconcileAuthentication) certificateForEDBClient(instance *operatorv1alpha1.Authentication, cert string) *certmgrv1.Certificate {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	edbClientCertificate := &certmgrv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "security-iam", "k8s.enterprisedb.io/reload": ""},
		},
		Spec: certmgrv1.CertificateSpec{
			SecretName: iamPostgresClientCertificateValues.SecretName,
			IssuerRef: cmmeta1.ObjectReference{
				Name: "cs-ca-issuer",
				Kind: certmgrv1.IssuerKind,
			},
			CommonName: iamPostgresClientCertificateValues.CommonName,
			Usages:     []certmgrv1.KeyUsage{"client auth"},
		},
	}

	// Set Pap instance as the owner and controller of the Certificate
	err := controllerutil.SetControllerReference(instance, edbClientCertificate, r.scheme)
	if err != nil {
		reqLogger.Error(err, "EDB:: Failed to set owner for Certificate")
		return nil
	}
	return edbClientCertificate

}
