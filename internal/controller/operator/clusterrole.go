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
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *AuthenticationReconciler) handleClusterRoles(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Optionally create ClusterRole if OpenShift authentication is available on the cluster")
	canCreateClusterRoles, err := r.hasAPIAccess(debugCtx, "", rbacv1.SchemeGroupVersion.Group, "clusterroles", []string{"create"})
	if !canCreateClusterRoles {
		log.Info("The Operator's ServiceAccount does not have the necessary accesses to create the ClusterRole; skipping")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		log.Error(err, "Failed to determine whether the Operator's ServiceAccount has the necessary accesses to create the ClusterRole")
		return subreconciler.RequeueWithError(err)
	}

	if !ctrlcommon.ClusterHasOpenShiftUserGroupVersion(&r.DiscoveryClient) {
		log.Info("user.openshift.io/v1 was not found on the cluster; skipping")
		return subreconciler.ContinueReconciling()
	}

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
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
	log = log.WithValues("ClusterRole.Name", operandClusterRole.Name)
	if err := r.Create(debugCtx, operandClusterRole); k8sErrors.IsAlreadyExists(err) {
		log.Info("ClusterRole already exists; continuing")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		log.Info("Encountered an unexpected error while trying to create ClusterRole", "error", err.Error())
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
	log.Info("ClusterRole created successfully")
	return subreconciler.RequeueWithDelay(defaultLowerWait)
}
