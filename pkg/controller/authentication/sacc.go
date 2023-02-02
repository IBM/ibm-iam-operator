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
	"strconv"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	res "github.com/IBM/ibm-iam-operator/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
)

func (r *ReconcileAuthentication) handleServiceAccount(instance *operatorv1alpha1.Authentication) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	authIdpConfigMapName := "platform-auth-idp"
	authIdpConfigMap := &corev1.ConfigMap{}
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: authIdpConfigMapName, Namespace: instance.Namespace}, authIdpConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Error(err, "The configmap ", authIdpConfigMapName, " is not created yet")
			return err
		}
		reqLogger.Error(err, "Failed to get ConfigMap", authIdpConfigMapName)
		return err
	}

	isOSAuthEnabled, _ := strconv.ParseBool(authIdpConfigMap.Data["OSAUTH_ENABLED"])
	if isOSAuthEnabled {
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

	return nil

}
