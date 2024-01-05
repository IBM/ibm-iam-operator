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
	"reflect"
	"time"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	ctrlCommon "github.com/IBM/ibm-iam-operator/controllers/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var rule2 = `^([a-zA-Z0-9]){32,}$`
var rule3 = `^([a-zA-Z0-9]){16,}$`
var adminPassword = ctrlCommon.GenerateRandomString(rule2)
var scimAdminPassword = ctrlCommon.GenerateRandomString(rule2)
var encryptionKey = ctrlCommon.GenerateRandomString(rule2)
var wlpClientRegistrationSecret = ctrlCommon.GenerateRandomString(rule2)
var encryptionIV = ctrlCommon.GenerateRandomString(rule3)

func generateSecretData(instance *operatorv1alpha1.Authentication, wlpClientID string, wlpClientSecret string) map[string]map[string][]byte {

	secretData := map[string]map[string][]byte{
		"platform-auth-ldaps-ca-cert": {
			"certificate": []byte(""),
		},
		"platform-auth-idp-credentials": {
			"admin_username": []byte(instance.Spec.Config.DefaultAdminUser),
			"admin_password": []byte(adminPassword),
		},
		"platform-auth-scim-credentials": {
			"scim_admin_username": []byte(instance.Spec.Config.ScimAdminUser),
			"scim_admin_password": []byte(scimAdminPassword),
		},
		"platform-auth-idp-encryption": {
			"ENCRYPTION_KEY": []byte(encryptionKey),
			"ENCRYPTION_IV":  []byte(encryptionIV),
			"algorithm":      []byte("aes256"),
			"inputEncoding":  []byte("utf8"),
			"outputEncoding": []byte("hex"),
		},
		"oauth-client-secret": {
			"WLP_CLIENT_REGISTRATION_SECRET": []byte(wlpClientRegistrationSecret),
			"DEFAULT_ADMIN_USER":             []byte(instance.Spec.Config.DefaultAdminUser),
		},
		"platform-oidc-credentials": {
			"WLP_CLIENT_ID":                     []byte(wlpClientID),
			"WLP_CLIENT_SECRET":                 []byte(wlpClientSecret),
			"WLP_SCOPE":                         []byte("openid+profile+email"),
			"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(wlpClientRegistrationSecret),
			"IBMID_CLIENT_SECRET":               []byte("903305fb599c8328a4d86d4cbdd07368"),
			"IBMID_PROFILE_CLIENT_SECRET":       []byte("C1bR0rO7kE0cE3xM2tV1gI0mG1cH3jK4dD7iQ8rW6pF1aF4mQ5"),
		},
		//@posriniv - verify once again - This is a dummy cert which has to be replaced by the user
		"platform-auth-ibmid-jwk": {
			"cert": []byte(""),
		},
		"platform-auth-ibmid-ssl-chain": {
			"cert": []byte(""),
		},
	}
	return secretData
}

func (r *AuthenticationReconciler) handleSecret(instance *operatorv1alpha1.Authentication, wlpClientID string, wlpClientSecret string, currentSecret *corev1.Secret, needToRequeue *bool) error {

	secretData := generateSecretData(instance, wlpClientID, wlpClientSecret)

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	for secret := range secretData {
		err = r.Client.Get(context.TODO(), types.NamespacedName{Name: secret, Namespace: instance.Namespace}, currentSecret)
		if err != nil {
			if errors.IsNotFound(err) {
				// Define a new Secret
				newSecret := generateSecretObject(instance, r.Scheme, secret, secretData[secret])
				reqLogger.Info("Creating a new Secret", "Secret.Namespace", instance.Namespace, "Secret.Name", secret)
				err = r.Client.Create(context.TODO(), newSecret)
				if err != nil {
					reqLogger.Error(err, "Failed to create new Secret", "Secret.Namespace", instance.Namespace, "Secret.Name", secret)
					return err
				}
				// Secret created successfully - return and requeue
				*needToRequeue = true
			} else {
				reqLogger.Error(err, "Failed to get Secret", "Secret.Namespace", instance.Namespace, "Secret.Name", secret)
				return err
			}
		} else {
			secretUpdateRequired := false
			if secret == "platform-auth-idp-encryption" {
				if _, keyExists := currentSecret.Data["ENCRYPTION_IV"]; !keyExists {
					reqLogger.Info("Updating an existing Secret", "Secret.Namespace", currentSecret.Namespace, "Secret.Name", currentSecret.Name)
					newSecret := generateSecretObject(instance, r.Scheme, secret, secretData[secret])
					currentSecret.Data["ENCRYPTION_IV"] = newSecret.Data["ENCRYPTION_IV"]
					secretUpdateRequired = true
				}
			}
			if secretUpdateRequired {
				err = r.Client.Update(context.TODO(), currentSecret)
				if err != nil {
					reqLogger.Error(err, "Failed to update an existing Secret", "Secret.Namespace", currentSecret.Namespace, "Secret.Name", currentSecret.Name)
					return err
				}
			}
		}

	}

	reqLogger.Info("Creating or updating new secret", "Certificate.Namespace", instance.Namespace, "Secret.Name", "ibmcloud-cluster-ca-cert")
	// create or update cluster-ca-secret
	stop := WaitForTimeout(10 * time.Minute)
	// get ca.crt from platform-auth-secret
	secret, err := r.waitForSecret(instance, "platform-auth-secret", stop)
	if err != nil {
		reqLogger.Error(err, "Failed to get Secret platform-auth-secret")
		return err
	}

	var caCert = secret.Data["ca.crt"]

	// Create or update secret ibmcloud-cluster-ca-cert with ca.crt from platform-auth-secret
	if err := r.createClusterCACert(instance, r.Scheme, ClusterSecretName, instance.Namespace, caCert, needToRequeue); err != nil {
		reqLogger.Error(err, "failure creating or updating ibmcloud-cluster-ca-cert secret")
		return err
	}

	return nil

}

func generateSecretObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, secretName string, secretData map[string][]byte) *corev1.Secret {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name, "Secret.Name", secretName)
	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: instance.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}

	// Set Authentication instance as the owner and controller of the Secret
	err := controllerutil.SetControllerReference(instance, newSecret, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Secret")
		return nil
	}
	return newSecret
}

func (r *AuthenticationReconciler) waitForSecret(instance *operatorv1alpha1.Authentication, name string, stopCh <-chan struct{}) (*corev1.Secret, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)

	reqLogger.Info("Waiting for secret", "Certificate.Namespace", instance.Namespace, "Secret.Name", name)

	s := &corev1.Secret{}

	err := wait.PollImmediateUntil(2*time.Second, func() (done bool, err error) {
		if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: instance.Namespace}, s); err != nil {
			return false, nil
		}
		return true, nil
	}, stopCh)

	return s, err
}

// create ibmcloud-cluster-ca-cert
func (r *AuthenticationReconciler) createClusterCACert(i *operatorv1alpha1.Authentication, scheme *runtime.Scheme, secretName, ns string, caCert []byte, needToRequeue *bool) (err error) {

	reqLogger := log.WithValues("Instance.Namespace", i.Namespace, "Instance.Name", i.Name, "Secret.Name", secretName)

	// create ibmcloud-cluster-ca-cert
	labels := map[string]string{
		"app":                          "platform-auth-service",
		"component":                    "platform-auth-service",
		"app.kubernetes.io/component":  "platform-auth-service",
		"app.kubernetes.io/name":       "platform-auth-service",
		"app.kubernetes.io/instance":   "platform-auth-service",
		"app.kubernetes.io/managed-by": "",
	}
	clusterSecret := &corev1.Secret{
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

	if err = controllerutil.SetControllerReference(i, clusterSecret, scheme); err != nil {
		reqLogger.Error(err, "Failed to create secret")
		return
	}
	err = r.Client.Create(context.TODO(), clusterSecret)
	if err == nil {
		reqLogger.Info("Successfully created secret")
		return
	} else if !errors.IsAlreadyExists(err) {
		reqLogger.Error(err, "Failed to create secret")
		return err
	}

	// Confirm that the secret, ibmcloud-cluster-ca-cert, is created by IM-Operator before further usage
	current := &corev1.Secret{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: secretName, Namespace: i.Namespace}, current)
	if err != nil {
		reqLogger.Error(err, "Failed to get existing secret")
		return
	}

	reqLogger.Info("Comparing calculated to observed secret")
	// If data and ownership are the same, return
	if reflect.DeepEqual(clusterSecret.Data, current.Data) && reflect.DeepEqual(clusterSecret.GetOwnerReferences(), current.GetOwnerReferences()) {
		reqLogger.Info("No significant changes found; skipping update.")
		return
	}

	if !ctrlCommon.IsControllerOf(i, current) {
		reqLogger.Info("The secret is already controlled by another object; deleting it and recreating in another loop")
		err = r.Client.Delete(context.TODO(), current)
		if err != nil {
			reqLogger.Error(err, "Failed to delete the secret")
		} else {
			*needToRequeue = true
		}
		return
	}

	reqLogger.Info("Detected change, trying to update it")
	current.Data = clusterSecret.Data

	// Apply the latest change to configmap
	if err = r.Client.Update(context.TODO(), current); err != nil {
		reqLogger.Error(err, "Failed to update secret")
		return err
	}
	reqLogger.Info("Secret updated")

	return
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
