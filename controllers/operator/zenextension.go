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
	"github.com/go-logr/logr"
	"github.com/opdev/subreconciler"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
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
  proxy_read_timeout 180s;
  rewrite /idmgmt/(.*) /$1 break;
}
location /v1/auth/ {
  proxy_set_header Host $host;
  proxy_set_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
  proxy_pass https://platform-identity-provider.%[1]s.svc:4300;
  proxy_read_timeout 180s;
}
location /idauth {
  proxy_set_header Host $host;
  proxy_set_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
  proxy_pass https://platform-auth-service.%[1]s.svc:9443;
  proxy_read_timeout 180s;
  rewrite /idauth/(.*) /$1 break;
  rewrite /idauth / break;
}
location /idprovider/ {
  proxy_set_header Host $host;
  proxy_set_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
  proxy_pass https://platform-identity-provider.%[1]s.svc:4300/;
  proxy_read_timeout 180s;
}
location /login {
  proxy_set_header Host $host;
  proxy_set_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
  proxy_pass https://platform-identity-provider.%[1]s.svc:4300/;
  proxy_read_timeout 180s;
  rewrite /login /v1/auth/authorize?client_id=%s&redirect_uri=https://%s/auth/liberty/callback&response_type=code&scope=openid+email+profile&orig=/login  break;
}
location /oidc {
  proxy_set_header Host $host;
  proxy_set_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
  proxy_pass https://platform-auth-service.%[1]s.svc:9443;
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

// handleZenExtension manages the generation of the ZenExtension when iam behind the zen front door is requested
func (r *AuthenticationReconciler) handleZenExtension(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	uiZenExtName := "common-web-ui-zen-extension"
	needToRequeue := false

	reqLogger := logf.FromContext(ctx).WithValues(
		"subreconciler", "handleZenExtension",
		"ZenExtension.Name", ImZenExtName,
		"ZenExtension.Namespace", req.Namespace)

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	zenHost := ""

	if authCR.Spec.Config.ZenFrontDoor {
		reqLogger.Info("Zen front door requested - Ensure that ZenExtension is updated with correct front door config")

		if ctrlCommon.ClusterHasZenExtensionGroupVersion(&r.DiscoveryClient) {
			commonWebUIZenExt := &zenv1.ZenExtension{}
			err = r.Get(ctx, types.NamespacedName{Name: uiZenExtName, Namespace: authCR.Namespace}, commonWebUIZenExt)
			if err != nil {
				if k8sErrors.IsNotFound(err) {
					reqLogger.Info("ZenExtension:common-web-ui-zen-extension does not exist - nothing to reconcile; continuing")
				} else if err != nil {
					reqLogger.Error(err, "Failed to get ZenExtension:common-web-ui-zen-extension - Not Requeuing, assume zen is not installed")
				}
				return subreconciler.ContinueReconciling()
			}
			//Get the routehost from the ibmcloud-cluster-info configmap
			zenHost, err = r.getZenHost(ctx, authCR, &needToRequeue, reqLogger)
			if err != nil {
				return subreconciler.RequeueWithError(err)
			}
			if needToRequeue {
				return subreconciler.RequeueWithDelay(opreqWait)
			}

			desiredZenExt := &zenv1.ZenExtension{}
			if result, err := r.getDesiredZenExtension(ctx, authCR, zenHost, desiredZenExt); subreconciler.ShouldRequeue(result, err) {
				return subreconciler.RequeueWithError(err)
			}
			if needToRequeue {
				return subreconciler.RequeueWithDelay(opreqWait)
			}

			observedZenExt := &zenv1.ZenExtension{}
			err = r.Get(ctx, types.NamespacedName{Name: ImZenExtName, Namespace: authCR.Namespace}, observedZenExt)

			if k8sErrors.IsNotFound(err) {
				reqLogger.Info("ZenExtension not found, creating")

				if err = r.Create(ctx, desiredZenExt); k8sErrors.IsAlreadyExists(err) {
					reqLogger.Info("ZenExtension already exists; continuing")
					return subreconciler.ContinueReconciling()
				} else if err != nil {
					reqLogger.Error(err, "Failed to create ZenExtension")
					return subreconciler.RequeueWithError(err)
				}
				reqLogger.Info("Created ZenExtension")
				return subreconciler.RequeueWithDelay(opreqWait)
			} else if err != nil {
				reqLogger.Error(err, "Failed to get ZenExtension")
				return subreconciler.RequeueWithError(err)
			}

			if !reflect.DeepEqual(observedZenExt.Spec, desiredZenExt.Spec) {

				observedZenExt.Spec[NginxConf] = desiredZenExt.Spec[NginxConf]
				observedZenExt.Spec[Extensions] = desiredZenExt.Spec[Extensions]
				if err = r.Update(ctx, observedZenExt); err != nil {
					reqLogger.Error(err, "Failed to update ZenExtension")
					return subreconciler.RequeueWithError(err)
				}
				reqLogger.Info("Updated ZenExtension successfully")
				return subreconciler.RequeueWithDelay(defaultLowerWait)
			}
			reqLogger.Info("No changes to ZenExtension; continue")
		} else {
			reqLogger.Info("Error - Zen front door has been requested, but the ZenExtension CRD does not exist - reconciliation of ZenExtension not possible")
		}
	} else {
		//The zen front door is disabled, if the zen extension exists, delete it
		reqLogger.Info("Zen front door disabled")

		observedZenExt := &zenv1.ZenExtension{}
		zext_err := r.Get(ctx, types.NamespacedName{Name: ImZenExtName, Namespace: authCR.Namespace}, observedZenExt)
		if zext_err == nil {
			//Delete the existing zen extension
			derr := r.Delete(ctx, observedZenExt)
			if derr != nil {
				if !k8sErrors.IsNotFound(derr) {
					reqLogger.Info("WARNING zen front door disabled, but iam zenextension exists and could not be deleted", "error", derr)
				}
			} else {
				reqLogger.Info("Iam zen extension deleted successfully")
			}
		} else {
			//error getting zen extension, only report if its not a notfound error
			if !k8sErrors.IsNotFound(zext_err) {
				reqLogger.Error(zext_err, "Zen front door is disabled, but could not get iam zenextension for cleanup")
			}
		}
	}

	//In addition to reconciling the zen extension, we must set the proper value of
	//cluster_address_auth in the ibmcloud-cluster-info configmap

	clusterInfoConfigMap := &corev1.ConfigMap{}
	clusterAddressFieldName := "cluster_address"
	clusterAddressAuthFieldName := "cluster_address_auth"

	authHost := ""
	fns := []subreconciler.Fn{
		r.getClusterInfoConfigMap(authCR, clusterInfoConfigMap),
		r.verifyConfigMapHasCorrectOwnership(authCR, clusterInfoConfigMap),
		r.verifyConfigMapHasField(authCR, clusterAddressFieldName, clusterInfoConfigMap),
	}

	for _, fn := range fns {
		if result, err = fn(ctx); subreconciler.ShouldRequeue(result, err) {
			return
		}
	}

	if authCR.Spec.Config.ZenFrontDoor && ctrlCommon.ClusterHasZenExtensionGroupVersion(&r.DiscoveryClient) {
		//authHost must be set to the zen front door
		//is should be set from above
		authHost = zenHost
	} else {
		authHost = clusterInfoConfigMap.Data[clusterAddressFieldName]
	}

	desiredFields := map[string]string{
		clusterAddressAuthFieldName: authHost,
	}
	return r.ensureConfigMapHasEqualFields(authCR, desiredFields, clusterInfoConfigMap)(ctx)
}

func (r *AuthenticationReconciler) getDesiredZenExtension(ctx context.Context, authCR *operatorv1alpha1.Authentication, zenHost string, desiredZenExt *zenv1.ZenExtension) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)
	wlpClientID := ""
	if result, err = r.getWlpClientID(authCR, &wlpClientID)(ctx); subreconciler.ShouldRequeue(result, err) {
		return
	}

	*desiredZenExt = zenv1.ZenExtension{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ImZenExtName,
			Namespace: authCR.Namespace,
		},
		Spec: map[string]string{
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

func (r *AuthenticationReconciler) getZenHost(ctx context.Context, authCR *operatorv1alpha1.Authentication, needToRequeue *bool, reqLogger logr.Logger) (zenHost string, err error) {
	zenHost = ""

	//Get the routehost from the ibmcloud-cluster-info configmap
	productConfigMap := &corev1.ConfigMap{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: ZenProductConfigmapName, Namespace: authCR.Namespace}, productConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Zen product configmap doesnot exist - requeuing until it does")
			*needToRequeue = true
			err = nil
			return
		}
		reqLogger.Error(err, "Failed to get Zen product configmap "+ZenProductConfigmapName)
		return
	}

	if productConfigMap.Data == nil || len(productConfigMap.Data[URL_PREFIX]) == 0 {
		err = fmt.Errorf("Zen %s is not set in configmap %s", URL_PREFIX, ZenProductConfigmapName)
		return
	}

	zenHost = productConfigMap.Data[URL_PREFIX]
	return
}
