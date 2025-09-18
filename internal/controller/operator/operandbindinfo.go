//
// Copyright 2025 IBM Corporation
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
	"reflect"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const bindInfoName = "ibm-iam-bindinfo"

func (r *AuthenticationReconciler) handleOperandBindInfo(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure OperandBindInfo is present when supported on the cluster")
	if !ctrlcommon.ClusterHasOperandBindInfoAPIResource(&r.DiscoveryClient) {
		log.Info("The OperandBindInfo API resource is not supported by this cluster")
		return subreconciler.ContinueReconciling()
	}

	log = log.WithValues("OperandBindInfo.Name", bindInfoName)
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	generated := &operatorv1alpha1.OperandBindInfo{}
	if err = generateOperandBindInfo(authCR, r.Client.Scheme(), generated); err != nil {
		log.Error(err, "Failed to generate OperandBindInfo")
		return subreconciler.RequeueWithError(err)
	}
	observed := &operatorv1alpha1.OperandBindInfo{}

	err = r.Get(debugCtx, types.NamespacedName{Name: bindInfoName, Namespace: req.Namespace}, observed)
	if k8sErrors.IsNotFound(err) {
		if err = r.Create(debugCtx, generated); err != nil {
			log.Error(err, "Encountered an unexpected error while creating OperandBindInfo")
			return subreconciler.RequeueWithError(err)
		}
		log.Info("OperandBindInfo created; requeueing")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	} else if err != nil {
		log.Error(err, "Unexpected error was encountered while trying to get OperandBindInfo")
		return subreconciler.RequeueWithError(err)
	}

	updated := false
	if !reflect.DeepEqual(observed.Spec, generated.Spec) {
		debugLog.Info("OperandBindInfo specs differ; updating")
		observed.Spec = generated.Spec
		updated = true
	}

	if !ctrlcommon.IsOwnerOf(r.Client.Scheme(), authCR, observed) {
		if err = controllerutil.SetOwnerReference(authCR, observed, r.Client.Scheme()); err != nil {
			log.Error(err, "Failed to set owner reference on OperandBindInfo")
			return subreconciler.RequeueWithError(err)
		}
		updated = true
	}

	if !updated {
		log.Info("No changes to OperandBindInfo; continue")
		return subreconciler.ContinueReconciling()
	}

	if err = r.Update(debugCtx, observed); err != nil {
		log.Error(err, "Encountered an unexpected error while updating OperandBindInfo")
		return subreconciler.RequeueWithError(err)
	}
	log.Info("Updated the OperandBindInfo; requeueing")
	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

func generateOperandBindInfo(authCR *operatorv1alpha1.Authentication, scheme *runtime.Scheme, generated *operatorv1alpha1.OperandBindInfo) (err error) {
	*generated = operatorv1alpha1.OperandBindInfo{
		ObjectMeta: v1.ObjectMeta{
			Name:      bindInfoName,
			Namespace: authCR.Namespace,
		},
		TypeMeta: v1.TypeMeta{
			APIVersion: "operator.ibm.com/v1alpha1",
			Kind:       "OperandBindInfo",
		},
		Spec: operatorv1alpha1.OperandBindInfoSpec{
			Operand:     "ibm-im-operator",
			Registry:    "common-service",
			Description: "Binding information that should be accessible to iam adopters",
			Bindings: map[string]operatorv1alpha1.Bindable{
				"public-oidc-creds": {
					Secret: "platform-oidc-credentials",
				},
				"public-auth-creds": {
					Secret: "platform-auth-idp-credentials",
				},
				"public-scim-creds": {
					Secret: "platform-auth-scim-credentials",
				},
				"public-auth-cert": {
					Secret: "platform-auth-secret",
				},
				"public-cam-secret": {
					Secret: "oauth-client-secret",
				},
				"public-cam-map": {
					Configmap: "oauth-client-map",
				},
				"public-auth-config": {
					Configmap: "platform-auth-idp",
				},
				"public-ibmcloud-config": {
					Configmap: "ibmcloud-cluster-info",
				},
				"public-ibmcloudca-secret": {
					Secret: "ibmcloud-cluster-ca-cert",
				},
			},
		},
	}
	err = controllerutil.SetOwnerReference(authCR, generated, scheme)
	return
}
