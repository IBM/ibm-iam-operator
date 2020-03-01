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
	"crypto/md5"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func generateSecretData(instance *operatorv1alpha1.Authentication) map[string]map[string][]byte {

	md5Hash := md5.Sum([]byte(instance.Spec.Config.ClusterName + "encryption_key"))
	encryptionKey := string(md5Hash[:])
	secretData := map[string]map[string][]byte{
		"platform-auth-ldaps-ca-cert": map[string][]byte{
			"certificate": []byte(""),
		},
		"platform-auth-idp-credentials": map[string][]byte{
			"admin_username": []byte(instance.Spec.Config.DefaultAdminUser),
			"admin_password": []byte(instance.Spec.Config.DefaultAdminPassword),
		},
		"platform-auth-idp-encryption": map[string][]byte{
			"ENCRYPTION_KEY": []byte(encryptionKey),
			"algorithm":      []byte("aes256"),
			"inputEncoding":  []byte("utf8"),
			"outputEncoding": []byte("hex"),
		},
		"platform-oidc-credentials": map[string][]byte{
			"WLP_CLIENT_ID":                     []byte(instance.Spec.Config.WLPClientID),
			"WLP_CLIENT_SECRET":                 []byte(instance.Spec.Config.WLPClientSecret),
			"WLP_SCOPE":                         []byte("openid+profile+email"),
			"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(instance.Spec.Config.WLPClientRegistrationSecret),
			"IBMID_CLIENT_SECRET":               []byte("903305fb599c8328a4d86d4cbdd07368"),
			"IBMID_PROFILE_CLIENT_SECRET":       []byte("C1bR0rO7kE0cE3xM2tV1gI0mG1cH3jK4dD7iQ8rW6pF1aF4mQ5"),
		},
		//@posriniv - verify once again - This is a dummy cert which has to be replaced by the user
		"platform-auth-ibmid-jwk": map[string][]byte{
			"cert": []byte(""),
		},
		"platform-auth-ibmid-ssl-chain": map[string][]byte{
			"cert": []byte(""),
		},
	}
	return secretData
}

func (r *ReconcileAuthentication) handleSecret(instance *operatorv1alpha1.Authentication, currentSecret *corev1.Secret, requeueResult *bool) error {

	secretData := generateSecretData(instance)

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	for secret, _ := range secretData {
		err = r.client.Get(context.TODO(), types.NamespacedName{Name: secret, Namespace: instance.Namespace}, currentSecret)
		if err != nil && errors.IsNotFound(err) {
			// Define a new Secret
			newSecret := generateSecretObject(instance, r.scheme, secret, secretData[secret])
			reqLogger.Info("Creating a new Secret", "Secret.Namespace", instance.Namespace, "Secret.Name", secret)
			err = r.client.Create(context.TODO(), newSecret)
			if err != nil {
				reqLogger.Error(err, "Failed to create new Secret", "Secret.Namespace", instance.Namespace, "Secret.Name", secret)
				return err
			}
			// Secret created successfully - return and requeue
			*requeueResult = true
		} else if err != nil {
			reqLogger.Error(err, "Failed to get Secret")
			return err
		}

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
