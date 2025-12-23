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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// handleClusterRoleBindings creates a ClusterRoleBinding that binds the platform-identity-provider and platform-identity-management ClusterRole to the
// platform-identity-provider and platform-identity-management ServiceAccount in the services namespace for this Authentication instance.
func (r *AuthenticationReconciler) handleClusterRoleBindings(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Optionally create ClusterRoleBinding if OpenShift authentication is available on the cluster")

	canCreateCRB, err := r.hasAPIAccess(debugCtx, "", rbacv1.SchemeGroupVersion.Group, "clusterrolebindings", []string{"create"})
	if !canCreateCRB {
		log.Info("The Operator's ServiceAccount does not have the necessary accesses to create the ClusterRoleBinding; skipping")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
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
	// Define role names to be used to create rolebinding
	roleNames := []string{
		"platform-identity-provider",
		"platform-identity-management",
	}
	// Track if any clusterrolebinding was created
	anyCreated := false
	// Create all rolebindings in a loop
	for _, roleName := range roleNames {
		operandCRB := r.iamOperandCRB(authCR, roleName)
		err = r.Client.Create(ctx, operandCRB)
		if k8sErrors.IsAlreadyExists(err) {
			log.Info("ClusterRoleBinding is already present")
			continue
		} else if err != nil {
			log.Error(err, "Failed to create ClusterRoleBinding", "ClusterRoleBinding", roleName)
			return subreconciler.RequeueWithError(err)
		}
		log.Info("ClusterRolebinding created successfully", "ClusterRoleBinding", roleName)
		anyCreated = true
	}
	if anyCreated {
		log.Info("ClusterRolebindings created successfully")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	log.Info("All ClusterRolebindings already exist")
	return subreconciler.ContinueReconciling()

}

func (r *AuthenticationReconciler) iamOperandCRB(instance *operatorv1alpha1.Authentication, rolename string) *rbacv1.ClusterRoleBinding {

	name := fmt.Sprintf(rolename+"-%s", instance.Namespace)

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
	return operandCRB
}
