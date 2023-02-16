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

package authentication

import (
	"context"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	res "github.com/IBM/ibm-iam-operator/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *ReconcileAuthentication) createSA(instance *operatorv1alpha1.Authentication, currentSA *corev1.ServiceAccount) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error
	operandSAName := "ibm-iam-operand-restricted"

	err = r.client.Get(context.TODO(), types.NamespacedName{Name: operandSAName, Namespace: instance.Namespace}, currentSA)
	if err != nil && errors.IsNotFound(err) {
		// Define a new operand ServiceAccount
		operandSA := generateSAObject(instance, r.scheme, operandSAName)
		reqLogger.Info("Creating a ibm-iam-operand-restricted serviceaccount")
		err = r.client.Create(context.TODO(), operandSA)
		if err != nil {
			reqLogger.Error(err, "Failed to create ibm-iam-operand-restricted serviceaccount")
			return err
		}
		// serviceaccount created successfully - return and requeue
		r.needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get serviceaccount")
		return err
	}

	return nil
}

func (r *ReconcileAuthentication) handleServiceAccount(instance *operatorv1alpha1.Authentication) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	// Get exsting annotations from SA
	sAccName := "ibm-iam-operand-restricted"
	serviceAccount := &corev1.ServiceAccount{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: sAccName, Namespace: instance.Namespace}, serviceAccount)
	if err != nil {
		reqLogger.Error(err, "failed to GET ServiceAccount ibm-iam-operand-restricted")
	} else if !res.IsOAuthAnnotationExists(serviceAccount.ObjectMeta.Annotations) {
		if serviceAccount.ObjectMeta.Annotations != nil {
			serviceAccount.ObjectMeta.Annotations["serviceaccounts.openshift.io/oauth-redirectreference.first"] = "{\"kind\":\"OAuthRedirectReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"Route\",\"name\":\"common-web-ui-callback\"}}"
		} else {
			serviceAccount.ObjectMeta.Annotations = make(map[string]string)
			serviceAccount.ObjectMeta.Annotations["serviceaccounts.openshift.io/oauth-redirectreference.first"] = "{\"kind\":\"OAuthRedirectReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"Route\",\"name\":\"common-web-ui-callback\"}}"
		}
		// update the SAcc with this annotation
		errUpdate := r.client.Update(context.TODO(), serviceAccount)
		if errUpdate != nil {
			// error updating annotation
			reqLogger.Error(errUpdate, "error updating annotation in ServiceAccount")
		} else {
			// annotation got updated properly
			reqLogger.Info("ibm-iam-operand-restricted SA is updated with annotation successfully")
		}
	} else {
		reqLogger.Info("Annotation already present")
		//do nothing
	}

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
