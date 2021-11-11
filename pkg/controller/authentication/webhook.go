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
	reg "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

var defaultTimeoutSeconds int32 = 10

func (r *ReconcileAuthentication) handleWebhook(instance *operatorv1alpha1.Authentication, currentWebhook *reg.MutatingWebhookConfiguration, requeueResult *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error
	// These code changes handles all use cases:
	// - fresh install in saas or on-prem mode and
	// - upgrade on older releases in on-prem mode
	webhook := "namespace-admission-config"
	if instance.Spec.Config.IBMCloudSaas {
		// in saas mode
		webhook = webhook + "-" + instance.Namespace
	} else if instance.Spec.Config.OnPremMultipleDeploy {
		// multiple deployment in on-prem mode
		// check if webhook with old name "namespace-admission-config" exist
		err = r.client.Get(context.TODO(), types.NamespacedName{Name: webhook, Namespace: ""}, currentWebhook)
		webhook = webhook + "-" + instance.Namespace
		if err == nil {
			// found existing webhook namespace-admission-config, upgrade the name and return
			// Update() does not work, use delete --> create to re-create
			reqLogger.Info("updating existing webhook namespace-admission-config", "Webhook.Namespace", instance.Namespace, "Webhook.Name", webhook)
			err = r.client.Delete(context.TODO(), currentWebhook)
			if err != nil {
				reqLogger.Error(err, "Failed to re-create an existing webhook when deleting the old one", "Webhook.Namespace", currentWebhook.Namespace, "Webhook.Name", currentWebhook.Name)
				return err
			}
			currentWebhook.ObjectMeta.Name = webhook
			currentWebhook.ObjectMeta.ResourceVersion = ""
			currentWebhook.Webhooks[0].Name = instance.Namespace + "." + "iam.hooks.securityenforcement.admission.cloud.ibm.com"
			err = r.client.Create(context.TODO(), currentWebhook)
			if err != nil {
				reqLogger.Error(err, "Failed to re-create an existing webhook when creating the new one", "Webhook.Namespace", currentWebhook.Namespace, "Webhook.Name", currentWebhook.Name)
				return err
			}
			return nil
		}
	}

	err = r.client.Get(context.TODO(), types.NamespacedName{Name: webhook, Namespace: ""}, currentWebhook)
	if err != nil {

		if errors.IsNotFound(err) {
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
		} else {
			reqLogger.Error(err, "Failed to get an existing webhook", "Webhook.Namespace", instance.Namespace, "Webhook.Name", webhook)
			return err
		}
	} else {
		// generate new webhook with v1 if it exists and copy the annotations
		//currentWebhook := generateWebhookObject(instance, r.scheme, webhook)
		//currentWebhook.ManagedFields = nil
		//reqLogger.Info("Updating an existing Webhook", "Webhook.Namespace", currentWebhook.Namespace, "Webhook.Details", currentWebhook)
		if currentWebhook.ObjectMeta.Annotations == nil {
			reqLogger.Info("Updating an existing Webhook", "Webhook.Namespace", currentWebhook.Namespace, "Webhook.Name", currentWebhook.Name)
			currentWebhook.ObjectMeta.Annotations = map[string]string{
				"certmanager.k8s.io/inject-ca-from": instance.Namespace + "/platform-identity-management",
			}
			err = r.client.Update(context.TODO(), currentWebhook)
			if err != nil {
				reqLogger.Error(err, "Failed to update an existing webhook", "Webhook.Namespace", currentWebhook.Namespace, "Webhook.Name", currentWebhook.Name)
				return err
			}
		}
	}

	return nil

}

func generateWebhookObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, webhook string) *reg.MutatingWebhookConfiguration {

	servicePath := "/identity/api/v1/users/validateandmutate"
	failurePolicy := reg.Ignore

	hooksName := "iam.hooks.securityenforcement.admission.cloud.ibm.com"
	if instance.Spec.Config.IBMCloudSaas {
		// in saas mode
		hooksName = instance.Namespace + "." + hooksName
	} else if instance.Spec.Config.OnPremMultipleDeploy {
		// multiple deployment in on-prem mode
		hooksName = instance.Namespace + "." + hooksName
	}
	sideEffectClass := reg.SideEffectClass("None")
	newWebhook := &reg.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: webhook,
			Annotations: map[string]string{
				"certmanager.k8s.io/inject-ca-from": instance.Namespace + "/platform-identity-management",
			},
		},
		Webhooks: []reg.MutatingWebhook{
			{
				Name:          hooksName,
				FailurePolicy: &failurePolicy,
				ClientConfig: reg.WebhookClientConfig{
					Service: &reg.ServiceReference{
						Name:      "platform-identity-management",
						Namespace: instance.Namespace,
						Path:      &servicePath,
					},
				},
				NamespaceSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "icp",
							Values:   []string{"system"},
							Operator: metav1.LabelSelectorOpNotIn,
						},
					},
				},
				SideEffects:             &sideEffectClass,
				AdmissionReviewVersions: []string{"v1"},
				Rules: []reg.RuleWithOperations{
					{
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
