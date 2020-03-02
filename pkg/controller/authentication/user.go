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
	userv1 "github.com/openshift/api/user/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (r *ReconcileAuthentication) handleUser(instance *operatorv1alpha1.Authentication, currentUser *userv1.User, requeueResult *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	user := instance.Spec.Config.DefaultAdminUser
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: user, Namespace: instance.Namespace}, currentUser)
	if err != nil && errors.IsNotFound(err) {
		// Define a new User
		newUser := generateUserObject(instance, r.scheme, user)
		reqLogger.Info("Creating a new User", "User.Namespace", instance.Namespace, "User.Name", user)
		err = r.client.Create(context.TODO(), newUser)
		if err != nil {
			reqLogger.Error(err, "Failed to create new User", "User.Namespace", instance.Namespace, "User.Name", user)
			return err
		}
		// User created successfully - return and requeue
		*requeueResult = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get User")
		return err
	}

	return nil

}

func generateUserObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, userName string) *userv1.User {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	

	newUser := &userv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userName,
		},
		Identities: []string{},
		Groups: []string{},
	}

	return newUser
}

