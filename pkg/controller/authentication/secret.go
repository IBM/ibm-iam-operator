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
	"reflect"
	"time"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	utils "github.com/IBM/ibm-iam-operator/pkg/utils"
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
var adminPassword = utils.GenerateRandomString(rule2)
var scimAdminPassword = utils.GenerateRandomString(rule2)
var encryptionKey = utils.GenerateRandomString(rule2)
var wlpClientRegistrationSecret = utils.GenerateRandomString(rule2)
var encryptionIV = utils.GenerateRandomString(rule3)

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

func (r *ReconcileAuthentication) handleSecret(instance *operatorv1alpha1.Authentication, wlpClientID string, wlpClientSecret string, currentSecret *corev1.Secret, needToRequeue *bool) error {

	secretData := generateSecretData(instance, wlpClientID, wlpClientSecret)

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	for secret := range secretData {
		err = r.client.Get(context.TODO(), types.NamespacedName{Name: secret, Namespace: instance.Namespace}, currentSecret)
		if err != nil {
			if errors.IsNotFound(err) {
				// Define a new Secret
				newSecret := generateSecretObject(instance, r.scheme, secret, secretData[secret])
				reqLogger.Info("Creating a new Secret", "Secret.Namespace", instance.Namespace, "Secret.Name", secret)
				err = r.client.Create(context.TODO(), newSecret)
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
					newSecret := generateSecretObject(instance, r.scheme, secret, secretData[secret])
					currentSecret.Data["ENCRYPTION_IV"] = newSecret.Data["ENCRYPTION_IV"]
					secretUpdateRequired = true
				}
			}
			if secretUpdateRequired {
				err = r.client.Update(context.TODO(), currentSecret)
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
	if err := r.createClusterCACert(instance, r.scheme, ClusterSecretName, instance.Namespace, caCert, needToRequeue); err != nil {
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

func (r *ReconcileAuthentication) waitForSecret(instance *operatorv1alpha1.Authentication, name string, stopCh <-chan struct{}) (*corev1.Secret, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)

	reqLogger.Info("Waiting for secret", "Certificate.Namespace", instance.Namespace, "Secret.Name", name)

	s := &corev1.Secret{}

	err := wait.PollImmediateUntil(2*time.Second, func() (done bool, err error) {
		if err := r.client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: instance.Namespace}, s); err != nil {
			return false, nil
		}
		return true, nil
	}, stopCh)

	return s, err
}

// create ibmcloud-cluster-ca-cert
func (r *ReconcileAuthentication) createClusterCACert(i *operatorv1alpha1.Authentication, scheme *runtime.Scheme, secretName, ns string, caCert []byte, needToRequeue *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", i.Namespace, "Instance.Name", i.Name)

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

	if err := controllerutil.SetControllerReference(i, clusterSecret, scheme); err != nil {
		reqLogger.Error(err, "Error setting controller reference on secret:")
	}
	err := r.client.Create(context.TODO(), clusterSecret)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			reqLogger.Error(err, "failure creating secret for ibmcloud-cluster-ca-cert")
			return err
		}
		// Confirm that secret ibmcloud-cluster-ca-cert  is created by IM-Operator before further usage
		if errors.IsAlreadyExists(err) {
			current := &corev1.Secret{}
			existerr := r.client.Get(context.TODO(), types.NamespacedName{Name: secretName, Namespace: i.Namespace}, current)
			if existerr == nil {
				ownerRefs := current.OwnerReferences
				var ownRef string
				for _, ownRefs := range ownerRefs {
					ownRef = ownRefs.Kind
				}
				if ownRef == "ManagementIngress" {
					reqLogger.Error(err, "ibmcloud-cluster-ca-cert secret is already created by managementingress , IM installation may not proceed further until the secret is removed")
					*needToRequeue = true
					return nil
				} else if ownRef != "Authentication" {
					reqLogger.Error(err, "Can't determine the secret ownership , IM installation may not proceed further until the secret is removed")
					*needToRequeue = true
					return nil
				}
			}
		}
		reqLogger.Info("Trying to update secret: as it already existed.", "Certificate.Namespace", i.Namespace, "Secret.Name", secretName)

		// Update config
		current := &corev1.Secret{}
		err := r.client.Get(context.TODO(), types.NamespacedName{Name: secretName, Namespace: i.Namespace}, current)
		if err != nil {
			reqLogger.Error(err, "failure getting secret ibmcloud-cluster-ca-cert")
			return err
		}

		// no data change, just return
		if reflect.DeepEqual(clusterSecret.Data, current.Data) {
			reqLogger.Info("No change found from the secret: skip updating current secret.", "Certificate.Namespace", i.Namespace, "Secret.Name", secretName)
			return nil
		}
		reqLogger.Info("Found change from secret %s, trying to update it", "Certificate.Namespace", i.Namespace, "Secret.Name", secretName)
		current.Data = clusterSecret.Data

		// Apply the latest change to configmap
		if err = r.client.Update(context.TODO(), current); err != nil {
			reqLogger.Error(err, "failure updating secret ibmcloud-cluster-ca-cert")
			return err
		}
	}
	reqLogger.Info("Successfully created or updated secret", "Certificate.Namespace", i.Namespace, "Secret.Name", secretName)
	return nil
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
