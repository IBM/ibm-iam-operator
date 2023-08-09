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
	"reflect"

	certmgr "github.com/IBM/ibm-iam-operator/pkg/apis/certmanager/v1alpha1"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var EDBCRName string = "im-store-edb"
var namespace string

// IamPsqlServerCertificateValues defines the values of iam-postgres certificate
type IamPsqlServerCertificateValues struct {
	Name       string
	SecretName string
	CN         []string
}
type IamPsqlServerCACertificateValues struct {
	Name       string
	SecretName string
	CommonName string
}
type IamPsqlClientCACertificateValues struct {
	Name       string
	SecretName string
	CommonName string
}

var iamPsqlServerCertificateValues = IamPsqlServerCertificateValues{
	Name:       "im-psql-server-cert",
	SecretName: "iam-postgres-server-cert",
	CN: []string{EDBCRName + "-rw", EDBCRName + "-rw" + "." + namespace, EDBCRName + "-rw" + "." + namespace + "." + "svc",
		EDBCRName + "-ro", EDBCRName + "-ro" + "." + namespace, EDBCRName + "-ro" + "." + namespace + "." + "svc",
		EDBCRName + "-r", EDBCRName + "-r" + "." + namespace, EDBCRName + "-r" + "." + namespace + "." + "svc"},
}

var iamPostgresClientCertificateValues = IamPsqlServerCACertificateValues{
	Name:       "iam-postgres-client-cert",
	SecretName: "iam-postgres-client-cert",
	CommonName: "streaming_replica",
}

func (r *ReconcileAuthentication) handlePsqlServerCert(instance *operatorv1alpha1.Authentication, currentCertificate *certmgr.Certificate, needToRequeue *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", namespace, "Instance.Name", instance.Name)
	namespace = instance.Namespace
	serverCrt := iamPsqlServerCertificateValues.Name
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

func (r *ReconcileAuthentication) certificateForEDBCluster(instance *enterprisedbv1.Cluster, cert string) *certmgr.Certificate {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	edbServerCertificate := &certmgr.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "security-iam", "k8s.enterprisedb.io/reload": ""},
		},
		Spec: certmgr.CertificateSpec{
			SecretName: iamPsqlServerCertificateValues.SecretName,
			IssuerRef: certmgr.ObjectReference{
				Name: "cs-ca-issuer",
				Kind: certmgr.IssuerKind,
			},
			DNSNames: iamPsqlServerCertificateValues.CN,
			Usages:   []certmgr.KeyUsage{"server auth"},
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

func (r *ReconcileAuthentication) certificateForEDBClient(instance *enterprisedbv1.Cluster, cert string) *certmgr.Certificate {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	edbClientCertificate := &certmgr.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "security-iam", "k8s.enterprisedb.io/reload": ""},
		},
		Spec: certmgr.CertificateSpec{
			SecretName: iamPostgresClientCertificateValues.SecretName,
			IssuerRef: certmgr.ObjectReference{
				Name: "cs-ca-issuer",
				Kind: certmgr.IssuerKind,
			},
			CommonName: iamPostgresClientCertificateValues.CommonName,
			Usages:     []certmgr.KeyUsage{"client auth"},
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

// EqualCerts returns a Boolean
func compareClusterCerts(expected *enterprisedbv1.Cluster, found *enterprisedbv1.Cluster) bool {
	// Check only certificate data
	// We can probably allow spec.Instances, spec.Resources change
	return !reflect.DeepEqual(expected.Spec.Certificates, found.Spec.Certificates)
}
