//
// Copyright 2023 IBM Corporation
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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (r *AuthenticationReconciler) createClusterRole(instance *operatorv1alpha1.Authentication) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	// Define a new ClusterRole
	operandClusterRole := r.iamOperandClusterRole(instance)
	reqLogger.Info("Creating ibm-iam-operand-restricted clusterrole")
	err := r.Client.Create(context.TODO(), operandClusterRole)
	if err != nil {
		reqLogger.Info("Failed to create ibm-iam-operand-restricted clusterrole or its already present")
	}
	// ClusterRole created successfully - return and requeue

}
func (r *AuthenticationReconciler) iamOperandClusterRole(instance *operatorv1alpha1.Authentication) *rbacv1.ClusterRole {

	// reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	operandClusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ibm-iam-operand-restricted",
			Labels:    map[string]string{"app.kubernetes.io/instance": "ibm-iam-operator", "app.kubernetes.io/managed-by": "ibm-iam-operator", "app.kubernetes.io/name": "ibm-iam-operator"},
			Namespace: "",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"user.openshift.io"},
				Resources: []string{"users", "groups", "identities"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
	return operandClusterRole

}
