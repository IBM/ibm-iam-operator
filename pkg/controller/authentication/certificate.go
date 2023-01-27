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
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	certmgr "github.com/IBM/ibm-iam-operator/pkg/apis/certmanager/v1alpha1"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var certificateData map[string]map[string]string

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

	reqLogger.Info("Creating or updating new secret", "Certificate.Namespace", instance.Namespace, "Secret.Name", "ibmcloud-cluster-ca-cert")
	// create or update cluster-ca-secret
	stop := WaitForTimeout(10 * time.Minute)
	// get ca.crt from platform-auth-cert
	secret, err := r.waitForSecret(instance, "platform-auth-cert", stop)
	if err != nil {
		reqLogger.Error(err, "Failed to get Secret platform-auth-cert")
		return err
	}

	var caCert = secret.Data["ca.crt"]

	// Create or update secret ibmcloud-cluster-ca-cert with ca.crt from platform-auth-cert
	if err := r.createClusterCACert(instance, r.scheme, ClusterSecretName, instance.Namespace, caCert); err != nil {
		return fmt.Errorf("failure creating or updating ibmcloud-cluster-ca-cert secret: %v", err)
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

// create ibmcloud-cluster-ca-cert
func (r *ReconcileAuthentication) createClusterCACert(i *operatorv1alpha1.Authentication, scheme *runtime.Scheme, secretName, ns string, caCert []byte) error {

	reqLogger := log.WithValues("Instance.Namespace", i.Namespace, "Instance.Name", i.Name)

	// create ibmcloud-cluster-ca-cert
	labels := map[string]string{
		"app":                          "auth-idp",
		"component":                    "auth-idp",
		"app.kubernetes.io/component":  "auth-idp",
		"app.kubernetes.io/name":       "auth-idp",
		"app.kubernetes.io/instance":   "auth-idp",
		"app.kubernetes.io/managed-by": "",
	}
	clusterSecret := &core.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind: "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: ns,
			Labels:    labels,
		},
		Data: map[string][]byte{
			"ca.crt": caCert,
		},
	}

	if err := controllerutil.SetControllerReference(i, clusterSecret, scheme); err != nil {
		reqLogger.Error(err, "Error setting controller reference on secret:")
	}
	err := r.client.Create(context.TODO(), clusterSecret)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return fmt.Errorf("failure creating secret for %q: %v", secretName, err)
		}

		klog.Infof("Trying to update secret: %s as it already existed.", secretName)
		// Update config
		current := &core.Secret{}
		err := r.client.Get(context.TODO(), types.NamespacedName{Name: secretName, Namespace: i.Namespace}, current)
		if err != nil {
			return fmt.Errorf("failure getting secret: %q  for %q: ", secretName, err)
		}

		// no data change, just return
		if reflect.DeepEqual(clusterSecret.Data, current.Data) {
			klog.Infof("No change found from the secret: %s, skip updating current secret.", secretName)
			return nil
		}

		json, _ := json.Marshal(clusterSecret)
		klog.Infof("Found change from secret %s, trying to update it.", json)
		current.Data = clusterSecret.Data

		// Apply the latest change to configmap
		if err = r.client.Update(context.TODO(), current); err != nil {
			return fmt.Errorf("failure updating secret: %v for %q: ", secretName, err)
		}
	}

	reqLogger.Info("Successfully created or updated secret %q", secretName)
	return nil
}

func (r *ReconcileAuthentication) waitForSecret(instance *operatorv1alpha1.Authentication, name string, stopCh <-chan struct{}) (*core.Secret, error) {
	klog.Infof("Waiting for secret: %s ...", name)
	s := &core.Secret{}

	err := wait.PollImmediateUntil(2*time.Second, func() (done bool, err error) {
		if err := r.client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: instance.Namespace}, s); err != nil {
			return false, nil
		}
		return true, nil
	}, stopCh)

	return s, err
}

// waitForTimeout returns a stop channel that closes when the specified timeout is reached
func WaitForTimeout(timeout time.Duration) <-chan struct{} {
	stopChWithTimeout := make(chan struct{})
	go func() {
		for range time.After(timeout) {
		}
		close(stopChWithTimeout)
	}()
	return stopChWithTimeout
}
