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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *AuthenticationReconciler) createRoleBinding(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure RoleBinding is present")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	// Define role names to be used to create rolebinding
	roleNames := []string{
		"platform-identity-provider",
		"platform-identity-management",
	}
	// Track if any rolebinding was created
	anyCreated := false

	// Create all rolebindings in a loop
	for _, roleName := range roleNames {
		operandRB := r.iamOperandRB(authCR, roleName)
		err = r.Client.Create(ctx, operandRB)
		if k8sErrors.IsAlreadyExists(err) {
			log.Info("RoleBinding is already present", "roleBindingName", roleName)
			continue
		} else if err != nil {
			log.Error(err, "Failed to create RoleBinding", "roleBindingName", roleName)
			return subreconciler.RequeueWithError(err)
		}
		log.Info("Rolebinding created successfully", "roleBindingName", roleName)
		anyCreated = true
	}
	// If any rolebinding was created, requeue to ensure all are ready
	if anyCreated {
		log.Info("Rolebindings created successfully")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	log.Info("All Rolebindings already exist")
	return subreconciler.ContinueReconciling()

}

func (r *AuthenticationReconciler) iamOperandRB(instance *operatorv1alpha1.Authentication, rolename string) *rbacv1.RoleBinding {

	operandRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rolename,
			Namespace: instance.Namespace,
			Labels:    common.MergeMaps(nil, map[string]string{"app.kubernetes.io/instance": "ibm-iam-operator", "app.kubernetes.io/name": "ibm-iam-operator"}, common.GetCommonLabels()),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     rolename,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      rolename,
				Namespace: instance.Namespace,
			},
		},
	}
	return operandRB
}
