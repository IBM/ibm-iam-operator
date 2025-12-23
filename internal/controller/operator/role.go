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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/opdev/subreconciler"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *AuthenticationReconciler) createRole(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure Role is present")

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	// Define role names to create
	roleNames := []string{
		"platform-identity-provider",
		"platform-identity-management",
	}
	// Track if any role was created
	anyCreated := false
	// Create all roles in a loop
	for _, roleName := range roleNames {
		operandRole := r.iamOperandRole(authCR, roleName)
		err = r.Client.Create(debugCtx, operandRole)
		if k8sErrors.IsAlreadyExists(err) {
			log.Info("Role is already present", "roleName", roleName)
			continue
		} else if err != nil {
			log.Error(err, "Failed to create Role", "roleName", roleName)
			return subreconciler.RequeueWithError(err)
		}
		log.Info("Role created successfully", "roleName", roleName)
		anyCreated = true
	}
	// If any role was created, requeue to ensure all are ready
	if anyCreated {
		log.Info("Roles created successfully")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	log.Info("All Roles already exist")
	return subreconciler.ContinueReconciling()

}

func (r *AuthenticationReconciler) iamOperandRole(instance *operatorv1alpha1.Authentication, rolename string) *rbacv1.Role {

	var operandRole *rbacv1.Role

	switch rolename {
	case "platform-identity-provider":
		operandRole = &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rolename,
				Labels:    map[string]string{"app.kubernetes.io/instance": "ibm-iam-operator", "app.kubernetes.io/managed-by": "ibm-iam-operator", "app.kubernetes.io/name": "ibm-iam-operator"},
				Namespace: instance.Namespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"endpoints"},
					Verbs:     []string{"get"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Verbs:     []string{"get", "patch"},
				},
				{
					APIGroups: []string{"oidc.security.ibm.com"},
					Resources: []string{"clients"},
					Verbs:     []string{"create", "update", "get", "delete"},
				},
			},
		}

	case "platform-identity-management":
		operandRole = &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rolename,
				Labels:    map[string]string{"app.kubernetes.io/instance": "ibm-iam-operator", "app.kubernetes.io/managed-by": "ibm-iam-operator", "app.kubernetes.io/name": "ibm-iam-operator"},
				Namespace: instance.Namespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"endpoints"},
					Verbs:     []string{"get"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Verbs:     []string{"get", "patch"},
				},
			},
		}
	}

	return operandRole
}
