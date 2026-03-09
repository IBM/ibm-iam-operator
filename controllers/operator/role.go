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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *AuthenticationReconciler) createRole(instance *operatorv1alpha1.Authentication) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	roleName := "ibm-iam-operand-restricted"

	// Check if Role already exists
	existingRole := &rbacv1.Role{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: roleName, Namespace: instance.Namespace}, existingRole)

	if errors.IsNotFound(err) {
		// Define a new Role
		operandRole := r.iamOperandRole(instance)
		reqLogger.Info("Creating ibm-iam-operand-restricted role")
		err = r.Client.Create(context.TODO(), operandRole)
		if err != nil {
			reqLogger.Error(err, "Failed to create ibm-iam-operand-restricted role")
		}
	} else if err != nil {
		reqLogger.Error(err, "Failed to get role")
	} else {
		// Role exists, check if controller reference is set
		hasControllerRef := false
		for _, ownerRef := range existingRole.GetOwnerReferences() {
			if ownerRef.Controller != nil && *ownerRef.Controller {
				hasControllerRef = true
				break
			}
		}

		if !hasControllerRef {
			reqLogger.Info("Role exists but missing controller reference, setting it now", "name", roleName)
			err = controllerutil.SetControllerReference(instance, existingRole, r.Scheme)
			if err != nil {
				reqLogger.Error(err, "Failed to set controller reference for existing role")
				return
			}
			err = r.Client.Update(context.TODO(), existingRole)
			if err != nil {
				reqLogger.Error(err, "Failed to update role with controller reference")
				return
			}
			reqLogger.Info("Successfully set controller reference for existing role", "name", roleName)
		}
	}

}
func (r *AuthenticationReconciler) iamOperandRole(instance *operatorv1alpha1.Authentication) *rbacv1.Role {

	// reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	operandRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ibm-iam-operand-restricted",
			Labels:    map[string]string{"app.kubernetes.io/instance": "ibm-iam-operator", "app.kubernetes.io/managed-by": "ibm-iam-operator", "app.kubernetes.io/name": "ibm-iam-operator"},
			Namespace: instance.Namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"oidc.security.ibm.com"},
				Resources: []string{"clients", "clients/finalizers", "clients/status"},
				Verbs:     []string{"create", "delete", "watch", "get", "list", "patch", "update"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"secrets", "services", "endpoints"},
				Verbs:     []string{"create", "delete", "watch", "get", "list", "patch", "update"},
			},
		},
	}
	// Set Authentication instance as the owner and controller for role
	err := controllerutil.SetControllerReference(instance, operandRole, r.Scheme)
	if err != nil {
		return nil
	}
	return operandRole

}
