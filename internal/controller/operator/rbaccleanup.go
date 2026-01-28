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
	"sigs.k8s.io/controller-runtime/pkg/client"
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

	// Create list of namespaced resources to delete
	objectsToDelete := []client.Object{
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ibm-iam-operand-restricted",
				Namespace: authCR.Namespace,
			},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ibm-iam-operand-restricted",
				Namespace: authCR.Namespace,
			},
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ibm-iam-operand-restricted",
				Namespace: authCR.Namespace,
			},
		},
	}

	// Check if operator has permission to delete ClusterRoleBinding
	canDeleteCRB, err := r.hasAPIAccess(debugCtx, "", rbacv1.SchemeGroupVersion.Group, "clusterrolebindings", []string{"delete"})
	if err != nil {
		log.Error(err, "Failed to check delete permission for ClusterRoleBinding")
		return subreconciler.RequeueWithError(err)
	}

	if !canDeleteCRB {
		log.Info("Operator does not have permission to delete ClusterRoleBinding, skipping deletion")
	} else {
		// Add ClusterRoleBinding to deletion list
		objectsToDelete = append(objectsToDelete, &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: crbname,
			},
		})
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
		// Add ClusterRole to deletion list
		objectsToDelete = append(objectsToDelete, &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ibm-iam-operand-restricted",
			},
		})
	}

	for _, obj := range objectsToDelete {
		deleteLog := log.WithValues("Object.Name", obj.GetName(), "Object.Kind", obj.GetObjectKind().GroupVersionKind().Kind)
		if err = r.Client.Delete(debugCtx, obj); k8sErrors.IsNotFound(err) {
			deleteLog.Info("Object not found; skipping")
		} else if err != nil && !k8sErrors.IsNotFound(err) {
			deleteLog.Error(err, "Failed to delete Object")
			return subreconciler.RequeueWithError(err)
		} else {
			deleteLog.Info("Object deleted successfully")
		}
	}

	log.Info("Cleanup of ibm-iam-operand-restricted resources completed")
	return subreconciler.ContinueReconciling()
}
