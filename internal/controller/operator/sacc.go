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

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *AuthenticationReconciler) createSA(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	operandSAKey := types.NamespacedName{Name: "ibm-iam-operand-restricted", Namespace: req.Namespace}
	log := logf.FromContext(ctx, "ServiceAccount.Name", operandSAKey.Name)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure ServiceAccount is present")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	serviceAccount := &corev1.ServiceAccount{}
	err = r.Client.Get(debugCtx, operandSAKey, serviceAccount)
	if err == nil {
		log.Info("ServiceAccount already exists")
		return subreconciler.ContinueReconciling()
	} else if !k8sErrors.IsNotFound(err) {
		log.Error(err, "Failed to get ServiceAccount")
		return subreconciler.RequeueWithError(err)
	}
	debugLog.Info("Did not find ServiceAccount")
	// Define a new operand ServiceAccount
	operandSA := generateSAObject(ctx, authCR, r.Scheme, operandSAKey.Name)
	debugLog.Info("Creating ServiceAccount")
	err = r.Client.Create(debugCtx, operandSA)
	if err != nil {
		log.Error(err, "Failed to create ServiceAccount")
		return
	}
	// serviceaccount created successfully - return and requeue
	log.Info("Created ServiceAccount")
	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

func (r *AuthenticationReconciler) handleServiceAccount(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	operandSAKey := types.NamespacedName{Name: "ibm-iam-operand-restricted", Namespace: req.Namespace}
	log := logf.FromContext(ctx, "ServiceAccount.Name", operandSAKey.Name)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	// step 1. Get console url to form redirecturi
	var consoleURL string
	if result, err = r.getClusterAddress(authCR, &consoleURL)(debugCtx); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	redirectURI := "https://" + consoleURL + "/auth/liberty/callback"

	// Get existing annotations from SA
	serviceAccount := &corev1.ServiceAccount{}
	if err = r.Client.Get(debugCtx, operandSAKey, serviceAccount); err != nil {
		log.Error(err, "Failed to GET ServiceAccount")
		return subreconciler.RequeueWithError(err)
	}

	if serviceAccount.ObjectMeta.Annotations == nil {
		serviceAccount.ObjectMeta.Annotations = make(map[string]string)
	}
	serviceAccount.ObjectMeta.Annotations["serviceaccounts.openshift.io/oauth-redirecturi.first"] = redirectURI

	// update the SAcc with this annotation
	if err = r.Client.Update(debugCtx, serviceAccount); err != nil {
		// error updating annotation
		log.Error(err, "Error updating annotation in ServiceAccount")
		return subreconciler.RequeueWithError(err)
	}

	log.Info("ServiceAccount is updated with annotation successfully")
	return
}

func generateSAObject(ctx context.Context, instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, operandSAName string) *corev1.ServiceAccount {
	log := logf.FromContext(ctx)
	metaLabels := map[string]string{
		"app.kubernetes.io/instance":   "ibm-iam-operator",
		"app.kubernetes.io/managed-by": "ibm-iam-operator",
		"app.kubernetes.io/name":       "ibm-iam-operator",
	}

	operandSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      operandSAName,
			Labels:    metaLabels,
			Namespace: instance.Namespace,
		},
	}

	// Set Authentication instance as the owner and controller of the operand serviceaccount
	err := controllerutil.SetControllerReference(instance, operandSA, scheme)
	if err != nil {
		log.Error(err, "Failed to set owner for serviceaccount")
		return nil
	}
	return operandSA
}
