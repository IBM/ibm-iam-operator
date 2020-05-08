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

package authentication

import (
	"context"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	"io/ioutil"
	reg "k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

var defaultTimeoutSeconds int32 = 10

func (r *ReconcileAuthentication) handleWebhook(instance *operatorv1alpha1.Authentication, currentWebhook *reg.MutatingWebhookConfiguration, requeueResult *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error
	webhook := "namespace-admission-config"

	err = r.client.Get(context.TODO(), types.NamespacedName{Name: webhook, Namespace: ""}, currentWebhook)
	if err != nil && errors.IsNotFound(err) {
		// Define a new Webhook
		newWebhook := generateWebhookObject(instance, r.scheme, webhook)
		reqLogger.Info("Creating a new Webhook", "Webhook.Namespace", instance.Namespace, "Webhook.Name", webhook)
		err = r.client.Create(context.TODO(), newWebhook)
		if err != nil {
			reqLogger.Error(err, "Failed to create new webhook", "Webhook.Namespace", instance.Namespace, "Webhook.Name", webhook)
			return err
		}
		// User created successfully - return and requeue
		*requeueResult = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Webhook")
		return err
	}

	return nil

}

func generateWebhookObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, webhook string) *reg.MutatingWebhookConfiguration {

	servicePath := "/identity/api/v1/users/validateandmutate"
	failurePolicy := reg.Ignore
	certData, _ := ioutil.ReadFile("/certs/ca.crt")
	newWebhook := &reg.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: webhook,
		},
		Webhooks: []reg.MutatingWebhook{
			reg.MutatingWebhook{
				Name:          "iam.hooks.securityenforcement.admission.cloud.ibm.com",
				FailurePolicy: &failurePolicy,
				ClientConfig: reg.WebhookClientConfig{
					CABundle: certData,
					Service: &reg.ServiceReference{
						Name:      "platform-identity-management",
						Namespace: "ibm-common-services",
						Path:      &servicePath,
					},
				},
				NamespaceSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						metav1.LabelSelectorRequirement{
							Key:      "icp",
							Values:   []string{"system"},
							Operator: metav1.LabelSelectorOpNotIn,
						},
					},
				},
				Rules: []reg.RuleWithOperations{
					reg.RuleWithOperations{
						Rule: reg.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"*"},
							Resources:   []string{"namespaces"},
						},
						Operations: []reg.OperationType{reg.Create, reg.Update, reg.Delete, reg.Connect},
					},
				},
				TimeoutSeconds: &defaultTimeoutSeconds,
			},
		},
	}

	return newWebhook
}
