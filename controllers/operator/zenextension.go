//
// Copyright 2024 IBM Corporation
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
	"reflect"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	zenv1 "github.com/IBM/ibm-iam-operator/apis/zen.cpd.ibm.com/v1"
	ctrlCommon "github.com/IBM/ibm-iam-operator/controllers/common"
	"github.com/opdev/subreconciler"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const NginxConf = "bedrock-iam-locations.conf"
const Extensions = "extensions"
const ZenProductConfigmapName = "product-configmap"
const ImZenExtName = "iam-zen-extension"
const URL_PREFIX = "URL_PREFIX"

var IamNginxConfig = `location /idmgmt/ {
  proxy_set_header Host $host;
  proxy_set_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
  proxy_pass https://platform-identity-management.%[1]s.svc:4500;
  proxy_buffer_size   256k;
  proxy_buffers   4 256k;
  proxy_read_timeout 180s;
  rewrite /idmgmt/(.*) /$1 break;
}
location /v1/auth/ {
  proxy_set_header Host $host;
  proxy_set_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
  proxy_pass https://platform-identity-provider.%[1]s.svc:4300;
  proxy_buffer_size   256k;
  proxy_buffers   4 256k;
  proxy_read_timeout 180s;
}
location /idprovider/ {
  proxy_set_header Host $host;
  proxy_set_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
  proxy_pass https://platform-identity-provider.%[1]s.svc:4300/;
  proxy_buffer_size   256k;
  proxy_buffers   4 256k;
  proxy_read_timeout 180s;
}
location /login {
  proxy_set_header Host $host;
  proxy_set_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
  proxy_pass https://platform-identity-provider.%[1]s.svc:4300/;
  proxy_buffer_size   256k;
  proxy_buffers   4 256k;
  proxy_read_timeout 180s;
  rewrite /login /v1/auth/authorize?client_id=%s&redirect_uri=https://%s/auth/liberty/callback&response_type=code&scope=openid+email+profile&orig=/login  break;
}
location /oidc {
  proxy_set_header Host $host;
  proxy_set_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
  proxy_pass https://platform-auth-service.%[1]s.svc:9443;
  proxy_buffer_size   256k;
  proxy_buffers   4 256k;
  proxy_read_timeout 180s;
}
location /ibm/saml20/defaultSP/acs {
  proxy_set_header Host $host;
  proxy_set_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
  proxy_pass https://platform-auth-service.%[1]s.svc:9443;
  proxy_read_timeout 180s;
}
location /ibm/api/social-login {
  proxy_set_header Host $host;
  proxy_set_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
  proxy_set_header zen-namespace-domain $nsdomain;
  proxy_pass https://platform-auth-service.%[1]s.svc:9443;
  proxy_read_timeout 180s;
}
`
var IamNginxExtensions = `[
  {
    "extension_point_id": "zen_front_door",
    "extension_name": "bedrock-iam-locations",
    "details": {
      "location_conf": "bedrock-iam-locations.conf"
    }
  }
]
`

type ZenExtensionWithSpec struct {
	metav1.ObjectMeta
	metav1.TypeMeta
	Status zenv1.ZenExtensionStatus
	Spec   map[string]any
}

func (zs *ZenExtensionWithSpec) ToUnstructured(s *runtime.Scheme) (u *unstructured.Unstructured, err error) {
	noSpec := &zenv1.ZenExtension{
		ObjectMeta: zs.ObjectMeta,
		TypeMeta:   zs.TypeMeta,
		Status:     zs.Status,
	}
	u = &unstructured.Unstructured{}
	if err = s.Convert(noSpec, u, nil); err != nil {
		return nil, err
	}
	u.Object["spec"] = zs.Spec
	return u, nil
}

func getZenExtensionWithSpec(s *runtime.Scheme, u *unstructured.Unstructured) (zs *ZenExtensionWithSpec, err error) {
	noSpec := &zenv1.ZenExtension{}
	if err = s.Convert(u, noSpec, nil); err != nil {
		return nil, err
	}

	spec, ok := u.Object["spec"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("failed to get spec from unstructured ZenExtension")
	}
	zs = &ZenExtensionWithSpec{
		ObjectMeta: noSpec.ObjectMeta,
		TypeMeta:   noSpec.TypeMeta,
		Spec:       spec,
		Status:     noSpec.Status,
	}

	return
}

func (r *AuthenticationReconciler) getOrCreateZenExtension(ctx context.Context, observed, desired client.Object) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)
	err = r.Get(ctx, types.NamespacedName{Name: desired.GetName(), Namespace: desired.GetNamespace()}, observed)
	// Create if not found
	if k8sErrors.IsNotFound(err) {
		reqLogger.Info("ZenExtension not found, creating")
		if err = r.Create(ctx, desired); k8sErrors.IsAlreadyExists(err) {
			reqLogger.Info("ZenExtension already exists; continuing")
			return subreconciler.ContinueReconciling()
		} else if err != nil {
			reqLogger.Error(err, "Failed to create ZenExtension")
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("Created ZenExtension")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	} else if err != nil {
		reqLogger.Error(err, "Failed to get ZenExtension")
		return subreconciler.RequeueWithError(err)
	}

	reqLogger.Info("Found ZenExtension")
	return subreconciler.ContinueReconciling()
}

func (r *AuthenticationReconciler) createOrUpdateZenExtension(authCR *operatorv1alpha1.Authentication) subreconciler.Fn {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := logf.FromContext(ctx)
		if !authCR.Spec.Config.ZenFrontDoor {
			return subreconciler.ContinueReconciling()
		}

		reqLogger.Info("Zen front door requested - Ensure that ZenExtension is updated with correct front door config")
		if !ctrlCommon.ClusterHasZenExtensionGroupVersion(&r.DiscoveryClient) {
			reqLogger.Info("Zen front door has been requested, but the ZenExtension CRD does not exist - reconciliation of ZenExtension not possible")
			return subreconciler.ContinueReconciling()
		}

		zenHost := ""
		//Get the routehost from the ibmcloud-cluster-info configmap
		if zenHost, err = r.getZenHost(ctx, authCR); err != nil {
			reqLogger.Error(err, "Could not get Zen host value")
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		}

		var unstrObserved, unstrDesired *unstructured.Unstructured
		desiredZenExt := &ZenExtensionWithSpec{}
		if subResult, err := r.getDesiredZenExtension(ctx, authCR, zenHost, desiredZenExt); subreconciler.ShouldRequeue(subResult, err) {
			return subResult, err
		}

		if unstrDesired, err = desiredZenExt.ToUnstructured(r.Scheme); err != nil {
			reqLogger.Info("Failed to convert generated ZenExtension to unstructured", "reason", err.Error())
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		}

		unstrObserved = &unstructured.Unstructured{
			Object: map[string]any{"kind": "ZenExtension", "apiVersion": zenv1.GroupVersion.String()},
		}

		if subResult, err := r.getOrCreateZenExtension(ctx, unstrObserved, unstrDesired); subreconciler.ShouldRequeue(subResult, err) {
			return subResult, err
		}

		var observedZenExt *ZenExtensionWithSpec
		if observedZenExt, err = getZenExtensionWithSpec(r.Scheme, unstrObserved); err != nil {
			reqLogger.Info("Failed to convert unstructured into ZenExtension", "reason", err.Error())
			return subreconciler.RequeueWithDelay(opreqWait)
		}

		if reflect.DeepEqual(observedZenExt.Spec, desiredZenExt.Spec) {
			reqLogger.Info("No changes to ZenExtension; continue")
			return subreconciler.ContinueReconciling()
		}

		// Update if not equal
		observedZenExt.Spec[NginxConf] = desiredZenExt.Spec[NginxConf]
		observedZenExt.Spec[Extensions] = desiredZenExt.Spec[Extensions]

		if unstrObserved, err = observedZenExt.ToUnstructured(r.Scheme); err != nil {
			reqLogger.Info("Failed to convert to unstructured for update", "reason", err.Error())
			return subreconciler.RequeueWithDelay(opreqWait)
		}

		if err = r.Update(ctx, unstrObserved); err != nil {
			reqLogger.Error(err, "Failed to update ZenExtension")
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("Updated ZenExtension successfully")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
}

func (r *AuthenticationReconciler) removeZenExtension(authCR *operatorv1alpha1.Authentication) subreconciler.Fn {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := logf.FromContext(ctx)
		if authCR.Spec.Config.ZenFrontDoor {
			return subreconciler.ContinueReconciling()
		}

		reqLogger.Info("Zen front door not enabled")
		observedZenExt := &zenv1.ZenExtension{}
		frontDoorKey := types.NamespacedName{Name: ImZenExtName, Namespace: authCR.Namespace}
		if err = r.Get(ctx, frontDoorKey, observedZenExt); k8sErrors.IsNotFound(err) {
			reqLogger.Info("Zen front door not found; continuing")
			return subreconciler.ContinueReconciling()
		} else if err != nil {
			reqLogger.Error(err, "Zen front door is disabled, but could not get iam ZenExtension for cleanup")
			return subreconciler.RequeueWithError(err)
		}

		//Delete the existing zen extension
		if err = r.Delete(ctx, observedZenExt); k8sErrors.IsNotFound(err) {
			reqLogger.Info("ZenExtension not found; no deletion needed")
			return subreconciler.ContinueReconciling()
		} else if err != nil {
			reqLogger.Info("Zen front door disabled, but iam zenextension exists and could not be deleted", "reason", err.Error())
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("Zen front door deleted successfully")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
}

// handleZenExtension manages the generation of the ZenExtension when iam behind the zen front door is requested
func (r *AuthenticationReconciler) handleZenFrontDoor(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	subLogger := logf.FromContext(ctx).WithValues(
		"subreconciler", "handleZenFrontDoor",
		"ZenExtension.Name", ImZenExtName,
		"ZenExtension.Namespace", req.Namespace)
	subCtx := logf.IntoContext(ctx, subLogger)

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(subCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	//In addition to reconciling the zen extension, we must set the proper value of
	//cluster_address_auth in the ibmcloud-cluster-info configmap
	fns := []subreconciler.Fn{
		r.removeZenExtension(authCR),
		r.createOrUpdateZenExtension(authCR),
	}

	for _, fn := range fns {
		if result, err = fn(subCtx); subreconciler.ShouldRequeue(result, err) {
			return
		}
	}

	return subreconciler.ContinueReconciling()
}

func (r *AuthenticationReconciler) getDesiredZenExtension(ctx context.Context, authCR *operatorv1alpha1.Authentication, zenHost string, desiredZenExt *ZenExtensionWithSpec) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)
	wlpClientID := ""
	if result, err = r.getWlpClientID(authCR, &wlpClientID)(ctx); subreconciler.ShouldRequeue(result, err) {
		return
	}

	*desiredZenExt = ZenExtensionWithSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ImZenExtName,
			Namespace: authCR.Namespace,
		},
		Spec: map[string]any{
			NginxConf:  fmt.Sprintf(IamNginxConfig, authCR.Namespace, wlpClientID, zenHost),
			Extensions: IamNginxExtensions,
		},
	}

	err = controllerutil.SetControllerReference(authCR, desiredZenExt, r.Client.Scheme())
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for route")
		return subreconciler.RequeueWithError(err)
	}

	return subreconciler.ContinueReconciling()
}
