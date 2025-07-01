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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var ingressList []string = []string{
	"ibmid-ui-callback",
	"id-mgmt",
	"idmgmt-v2-api",
	"platform-auth",
	"platform-id-provider",
	"platform-login",
	"platform-oidc-block",
	"platform-oidc",
	"saml-ui-callback",
	"version-idmgmt",
	"social-login-callback",
}

func (r *AuthenticationReconciler) ReconcileRemoveIngresses(ctx context.Context, instance *operatorv1alpha1.Authentication, needToRequeue *bool) {
	reqLogger := log.WithValues("func", "ReconcileRemoveIngresses")

	//No error checking as we will just make a best attempt to remove the legacy ingresses
	//Do not fail based on inability to delete the ingresses
	//TODO Add ingress names here
	for _, iname := range ingressList {
		err := r.DeleteIngress(ctx, iname, instance.Namespace, needToRequeue)
		if err != nil {
			reqLogger.Info("Failed to delete legacy ingress " + iname)
		}
	}
}

func (r *AuthenticationReconciler) DeleteIngress(ctx context.Context, ingressName string, ingressNS string, needToRequeue *bool) error {
	reqLogger := log.WithValues("func", "deleteIngress", "Name", ingressName, "Namespace", ingressNS)

	ingress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ingressName,
			Namespace: ingressNS,
		},
	}

	err := r.Client.Get(ctx, types.NamespacedName{Name: ingress.Name, Namespace: ingress.Namespace}, ingress)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		reqLogger.Error(err, "Failed to get legacy ingress")
		return err
	}

	// Delete ingress if found
	err = r.Client.Delete(ctx, ingress)
	if err != nil {
		reqLogger.Error(err, "Failed to delete legacy ingress")
		return err
	}

	reqLogger.Info("Deleted legacy ingress")
	*needToRequeue = true
	return nil
}
