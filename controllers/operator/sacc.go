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
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Did not find ServiceAccount", "name", operandSAName, "namespace", instance.Namespace)
		// Define a new operand ServiceAccount
		operandSA := generateSAObject(instance, r.Scheme, operandSAName)
		reqLogger.Info("Creating a ibm-iam-operand-restricted serviceaccount")
		err = r.Client.Create(context.TODO(), operandSA)
		if err != nil {
			reqLogger.Error(err, "Failed to create ibm-iam-operand-restricted serviceaccount")
			return
		}
		// serviceaccount created successfully - return and requeue
		*needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get serviceaccount")
		return
	}

	return
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
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
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

	// Set Authentication instance as the owner and controller of the operand serviceaccount
	err := controllerutil.SetControllerReference(instance, operandSA, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for serviceaccount")
		return nil
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
