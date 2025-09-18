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
	"github.com/opdev/subreconciler"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *AuthenticationReconciler) createRoleBinding(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx, "RoleBinding.Name", "ibm-iam-operand-restricted")
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure RoleBinding is present")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	// Define a new RoleBinding
	operandRB := r.iamOperandRB(authCR)
	debugLog.Info("Creating RoleBinding")
	err = r.Client.Create(ctx, operandRB)
	if k8sErrors.IsAlreadyExists(err) {
		log.Info("RoleBinding is already present")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		log.Error(err, "Failed to create RoleBinding")
		return subreconciler.RequeueWithError(err)
	}

	log.Info("Created RoleBinding successfully")
	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

func (r *AuthenticationReconciler) iamOperandRB(instance *operatorv1alpha1.Authentication) *rbacv1.RoleBinding {
	operandRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ibm-iam-operand-restricted",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app.kubernetes.io/instance": "ibm-iam-operator", "app.kubernetes.io/managed-by": "ibm-iam-operator", "app.kubernetes.io/name": "ibm-iam-operator"},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     "ibm-iam-operand-restricted",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "ibm-iam-operand-restricted",
				Namespace: instance.Namespace,
			},
		},
	}
	return operandRB
}
