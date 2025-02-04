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
	ctrlcommon "github.com/IBM/ibm-iam-operator/controllers/common"
	"github.com/opdev/subreconciler"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

func (r *AuthenticationReconciler) handleClusterRoles(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := log.WithValues("subreconciler", "handleClusterRoles")

	canCreateClusterRoles, err := r.hasAPIAccess(ctx, "", rbacv1.SchemeGroupVersion, "clusterroles", []string{"create"})
	if !canCreateClusterRoles {
		reqLogger.Info("The Operator's ServiceAccount does not have the necessary accesses to create the ClusterRole; skipping")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		return subreconciler.RequeueWithError(err)
	}

	if !ctrlcommon.ClusterHasOpenShiftUserGroupVersion(&r.DiscoveryClient) {
		reqLogger.Info("user.openshift.io/v1 was not found on the cluster; skipping")
		return subreconciler.ContinueReconciling()
	}

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	operandClusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "ibm-iam-operand-restricted",
			Labels: map[string]string{"app.kubernetes.io/instance": "ibm-iam-operator", "app.kubernetes.io/managed-by": "ibm-iam-operator", "app.kubernetes.io/name": "ibm-iam-operator"},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"user.openshift.io"},
				Resources: []string{"users", "groups", "identities"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
	reqLogger = reqLogger.WithValues("ClusterRole.Name", operandClusterRole.Name)
	if err := r.Create(ctx, operandClusterRole); k8sErrors.IsAlreadyExists(err) {
		reqLogger.Info("ClusterRole already exists; continuing")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		reqLogger.Info("Encountered an unexpected error while trying to create ClusterRole", "error", err.Error())
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
	reqLogger.Info("ClusterRole created")
	return subreconciler.RequeueWithDelay(defaultLowerWait)
}
