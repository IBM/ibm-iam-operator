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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	clientv1 "github.com/openshift/api/oauth/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func (r *ReconcileAuthentication) handleClient(instance *operatorv1alpha1.Authentication, currentClient *clientv1.OAuthClient, clientId string, clientSecret string, requeueResult *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	err = r.client.Get(context.TODO(), types.NamespacedName{Name: clientId, Namespace: ""}, currentClient)
	if err != nil && errors.IsNotFound(err) {
		// Define a new User
		newClient := generateClientObject(instance, r.scheme, clientId, clientSecret)
		reqLogger.Info("Creating a new Client", "User.Namespace", instance.Namespace, "ClientId", clientId)
		err = r.client.Create(context.TODO(), newClient)
		if err != nil {
			reqLogger.Error(err, "Failed to create new client", "Client.Namespace", instance.Namespace, "ClientId", clientId)
			return err
		}
		// User created successfully - return and requeue
		*requeueResult = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get OAuthClient")
		return err
	}

	return nil

}

func generateClientObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, clientId string, clientSecret string) *clientv1.OAuthClient {

	newClient := &clientv1.OAuthClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: clientId,
		},
		RedirectURIs: []string{"https://ICP_CONSOLE_URL/auth/liberty/callback"},
		Secret: clientSecret,
	}

	return newClient
}