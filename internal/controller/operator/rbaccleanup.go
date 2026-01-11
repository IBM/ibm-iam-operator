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
	"fmt"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/opdev/subreconciler"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *AuthenticationReconciler) cleanupOldRBAC(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Cleanup ibm-iam-operand-restricted ServiceAccount, Role, Rolebinding, ClusterRole and Clusterrolebinding if present")

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	crbname := fmt.Sprintf("ibm-iam-operand-restricted-%s", authCR.Namespace)

	// Check if operator has permission to delete ClusterRoleBinding
	canDeleteCRB, err := r.hasAPIAccess(debugCtx, "", rbacv1.SchemeGroupVersion.Group, "clusterrolebindings", []string{"delete"})
	if err != nil {
		log.Error(err, "Failed to check delete permission for ClusterRoleBinding")
		return subreconciler.RequeueWithError(err)
	}

	if !canDeleteCRB {
		log.Info("Operator does not have permission to delete ClusterRoleBinding, skipping deletion")
	} else {
		// Delete ClusterRoleBinding
		clusterRoleBinding := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: crbname,
			},
		}
		err = r.Client.Delete(debugCtx, clusterRoleBinding)
		if err != nil && !k8sErrors.IsNotFound(err) {
			log.Error(err, "Failed to delete ClusterRoleBinding ibm-iam-operand-restricted")
			return subreconciler.RequeueWithError(err)
		}
		if err == nil {
			log.Info("ClusterRoleBinding deleted successfully")
		}
	}

	// Check if operator has permission to delete ClusterRole
	canDeleteCR, err := r.hasAPIAccess(debugCtx, "", rbacv1.SchemeGroupVersion.Group, "clusterroles", []string{"delete"})
	if err != nil {
		log.Error(err, "Failed to check delete permission for ClusterRole")
		return subreconciler.RequeueWithError(err)
	}

	if !canDeleteCR {
		log.Info("Operator does not have permission to delete ClusterRole, skipping deletion")
	} else {
		// Delete ClusterRole
		clusterRole := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ibm-iam-operand-restricted",
			},
		}
		err = r.Client.Delete(debugCtx, clusterRole)
		if err != nil && !k8sErrors.IsNotFound(err) {
			log.Error(err, "Failed to delete ClusterRole ibm-iam-operand-restricted")
			return subreconciler.RequeueWithError(err)
		}
		if err == nil {
			log.Info("ClusterRole ibm-iam-operand-restricted deleted successfully")
		}
	}

	// Delete RoleBinding
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ibm-iam-operand-restricted",
			Namespace: authCR.Namespace,
		},
	}
	err = r.Client.Delete(debugCtx, roleBinding)
	if err != nil && !k8sErrors.IsNotFound(err) {
		log.Error(err, "Failed to delete RoleBinding ibm-iam-operand-restricted")
		return subreconciler.RequeueWithError(err)
	}
	if err == nil {
		log.Info("RoleBinding ibm-iam-operand-restricted deleted successfully")
	}

	// Delete Role
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ibm-iam-operand-restricted",
			Namespace: authCR.Namespace,
		},
	}
	err = r.Client.Delete(debugCtx, role)
	if err != nil && !k8sErrors.IsNotFound(err) {
		log.Error(err, "Failed to delete Role ibm-iam-operand-restricted")
		return subreconciler.RequeueWithError(err)
	}
	if err == nil {
		log.Info("Role ibm-iam-operand-restricted deleted successfully")
	}
	// Delete ServiceAccount
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ibm-iam-operand-restricted",
			Namespace: authCR.Namespace,
		},
	}
	err = r.Client.Delete(debugCtx, sa)
	if err != nil && !k8sErrors.IsNotFound(err) {
		log.Error(err, "Failed to delete ServiceAccount ibm-iam-operand-restricted")
		return subreconciler.RequeueWithError(err)
	}
	if err == nil {
		log.Info("ServiceAccount ibm-iam-operand-restricted deleted successfully")
	}

	log.Info("Cleanup of ibm-iam-operand-restricted resources completed")
	return subreconciler.ContinueReconciling()
}
