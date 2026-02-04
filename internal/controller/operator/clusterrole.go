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
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
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
	// Define role names to create
	clusterRoleNames := []string{
		"platform-identity-provider",
		"platform-identity-management",
	}
	// Track if any clusterrole was created
	anyCreated := false
	// Create all roles in a loop
	for _, clusterRoleName := range clusterRoleNames {
		operandClusterRole := r.iamOperandClusterRole(authCR, clusterRoleName)
		err = r.Client.Create(debugCtx, operandClusterRole)
		if k8sErrors.IsAlreadyExists(err) {
			log.Info("ClusterRole already exists; continuing")
			continue
		} else if err != nil {
			log.Info("Encountered an unexpected error while trying to create ClusterRole", "error", err.Error())
			return subreconciler.RequeueWithError(err)
		}
		log.Info("ClusterRole created successfully", "ClusterRole", clusterRoleName)
		anyCreated = true
	}
	if anyCreated {
		log.Info("ClusterRoles created successfully")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	log.Info("All ClusterRoles already exist")
	return subreconciler.ContinueReconciling()
}

func (r *AuthenticationReconciler) iamOperandClusterRole(instance *operatorv1alpha1.Authentication, rolename string) *rbacv1.ClusterRole {

	var operandClusterRole *rbacv1.ClusterRole

	switch rolename {
	case "platform-identity-provider":
		operandClusterRole = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   rolename,
				Labels: common.MergeMaps(nil, map[string]string{"app.kubernetes.io/instance": "ibm-iam-operator", "app.kubernetes.io/name": "ibm-iam-operator"}, common.GetCommonLabels()),
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"user.openshift.io"},
					Resources: []string{"users", "groups"},
					Verbs:     []string{"get", "list"},
				},
			},
		}

	case "platform-identity-management":
		operandClusterRole = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   rolename,
				Labels: common.MergeMaps(nil, map[string]string{"app.kubernetes.io/instance": "ibm-iam-operator", "app.kubernetes.io/name": "ibm-iam-operator"}, common.GetCommonLabels()),
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"user.openshift.io"},
					Resources: []string{"users", "groups"},
					Verbs:     []string{"get", "list"},
				},
			},
		}
	}
	return operandClusterRole
}
