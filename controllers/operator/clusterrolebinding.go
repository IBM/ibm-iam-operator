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
	"fmt"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	"github.com/opdev/subreconciler"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// handleClusterRoleBinding creates a ClusterRoleBinding that binds the ibm-iam-operand-restricted ClusterRole to the
// ibm-iam-operand-restricted ServiceAccount in the services namespace for this Authentication instance.
func (r *AuthenticationReconciler) handleClusterRoleBinding(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "handleClusterRoleBinding")
	reqLogger.Info("Ensure that the ClusterRoleBinding is created")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	name := fmt.Sprintf("ibm-iam-operand-restricted-%s", authCR.Namespace)

	crb := iamOperandCRB(authCR, name)

	reqLogger = reqLogger.WithValues("ClusterRoleBinding.Name", name)
	if err = r.Create(ctx, crb); k8sErrors.IsAlreadyExists(err) {
		reqLogger.Info("ClusterRoleBinding already exists, continuing")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		reqLogger.Error(err, "Failed to create ClusterRoleBinding")
		return subreconciler.RequeueWithError(err)
	}
	reqLogger.Info("Created ClusterRoleBinding successfully")
	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

func iamOperandCRB(instance *operatorv1alpha1.Authentication, name string) *rbacv1.ClusterRoleBinding {
	operandCRB := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app.kubernetes.io/instance":   "ibm-iam-operator",
				"app.kubernetes.io/managed-by": "ibm-iam-operator",
				"app.kubernetes.io/name":       "ibm-iam-operator",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
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
	return operandCRB

}
