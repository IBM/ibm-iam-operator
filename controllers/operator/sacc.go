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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *AuthenticationReconciler) createSA(instance *operatorv1alpha1.Authentication, currentSA *corev1.ServiceAccount, needToRequeue *bool) (err error) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	operandSAName := "ibm-iam-operand-restricted"

	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: operandSAName, Namespace: instance.Namespace}, currentSA)

	// Handle errors other than NotFound
	if err != nil && !errors.IsNotFound(err) {
		reqLogger.Error(err, "Failed to get serviceaccount")
		return err
	}

	// ServiceAccount doesn't exist, create it
	if errors.IsNotFound(err) {
		reqLogger.Info("Did not find ServiceAccount", "name", operandSAName, "namespace", instance.Namespace)
		operandSA := generateSAObject(instance, r.Scheme, operandSAName)
		reqLogger.Info("Creating a ibm-iam-operand-restricted serviceaccount")

		if err = r.Client.Create(context.TODO(), operandSA); err != nil {
			reqLogger.Error(err, "Failed to create ibm-iam-operand-restricted serviceaccount")
			return err
		}

		// Set Authentication instance as the owner and controller for serviceaccount
		if err = controllerutil.SetControllerReference(instance, operandSA, r.Scheme); err != nil {
			reqLogger.Error(err, "Failed to set controller reference for new serviceaccount")
			return err
		}

		*needToRequeue = true
		return nil
	}

	// ServiceAccount exists, check if controller reference is set
	if hasControllerReference(currentSA) {
		return nil
	}

	// Controller reference is missing, set it
	reqLogger.Info("ServiceAccount exists but missing controller reference, setting it now", "name", operandSAName)

	if err = controllerutil.SetControllerReference(instance, currentSA, r.Scheme); err != nil {
		reqLogger.Error(err, "Failed to set controller reference for existing serviceaccount")
		return err
	}

	if err = r.Client.Update(context.TODO(), currentSA); err != nil {
		reqLogger.Error(err, "Failed to update serviceaccount with controller reference")
		return err
	}

	reqLogger.Info("Successfully set controller reference for existing serviceaccount", "name", operandSAName)
	*needToRequeue = true

	return nil
}

// hasControllerReference checks if the object has a controller reference set
func hasControllerReference(obj metav1.Object) bool {
	for _, ownerRef := range obj.GetOwnerReferences() {
		if ownerRef.Controller != nil && *ownerRef.Controller {
			return true
		}
	}
	return false
}

func (r *AuthenticationReconciler) handleServiceAccount(instance *operatorv1alpha1.Authentication, needToRequeue *bool) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	// step 1. Get console url to form redirecturi
	consoleURL := r.getConsoleURL(instance, needToRequeue)
	var redirectURI string
	if consoleURL == "" {
		reqLogger.Info("Problem retriving consoleURL")
	} else {
		redirectURI = "https://" + consoleURL + "/auth/liberty/callback"
	}
	// Get exsting annotations from SA
	sAccName := "ibm-iam-operand-restricted"
	serviceAccount := &corev1.ServiceAccount{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: sAccName, Namespace: instance.Namespace}, serviceAccount)
	if err != nil {
		reqLogger.Error(err, "failed to GET ServiceAccount ibm-iam-operand-restricted")
	} else {
		if serviceAccount.ObjectMeta.Annotations != nil {
			serviceAccount.ObjectMeta.Annotations["serviceaccounts.openshift.io/oauth-redirecturi.first"] = redirectURI
		} else {
			serviceAccount.ObjectMeta.Annotations = make(map[string]string)
			serviceAccount.ObjectMeta.Annotations["serviceaccounts.openshift.io/oauth-redirecturi.first"] = redirectURI
		}
		// update the SAcc with this annotation
		errUpdate := r.Client.Update(context.TODO(), serviceAccount)
		if errUpdate != nil {
			// error updating annotation
			reqLogger.Error(errUpdate, "error updating annotation in ServiceAccount")
		} else {
			// annotation got updated properly
			reqLogger.Info("ibm-iam-operand-restricted SA is updated with annotation successfully")
		}
	}
	return
}

func generateSAObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, operndSAName string) *corev1.ServiceAccount {
	metaLabels := map[string]string{
		"app.kubernetes.io/instance":   "ibm-iam-operator",
		"app.kubernetes.io/managed-by": "ibm-iam-operator",
		"app.kubernetes.io/name":       "ibm-iam-operator",
	}

	operandSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      operndSAName,
			Labels:    metaLabels,
			Namespace: instance.Namespace,
		},
	}
	return operandSA
}

// getConsoleURL retrives the cp-console host
func (r *AuthenticationReconciler) getConsoleURL(instance *operatorv1alpha1.Authentication, needToRequeue *bool) (icpConsoleURL string) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	proxyConfigMapName := "ibmcloud-cluster-info"
	proxyConfigMap := &corev1.ConfigMap{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: proxyConfigMapName, Namespace: instance.Namespace}, proxyConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Error(err, "The configmap ", proxyConfigMapName, " is not created yet")
			return
		}
		reqLogger.Error(err, "Failed to get ConfigMap", proxyConfigMapName)
		*needToRequeue = true
		return
	}
	var ok bool
	icpConsoleURL, ok = proxyConfigMap.Data["cluster_address"]

	if !ok {
		reqLogger.Error(nil, "The configmap", proxyConfigMapName, "doesn't contain cluster_address address")
		*needToRequeue = true
		return
	}
	return
}
