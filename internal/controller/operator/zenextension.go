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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	zenv1 "github.com/IBM/ibm-iam-operator/internal/api/zen.cpd.ibm.com/v1"
	common "github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const ImZenExtName = "iam-zen-extension"

type ZenExtensionWithSpec struct {
	metav1.ObjectMeta
	metav1.TypeMeta
	Status zenv1.ZenExtensionStatus
	Spec   map[string]any
}

// handleZenExtension manages the generation of the ZenExtension when iam behind the zen front door is requested
func (r *AuthenticationReconciler) handleZenFrontDoor(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)

	log.Info("Remove ZenExtension if present")
	if !common.ClusterHasZenExtensionGroupVersion(&r.DiscoveryClient) {
		log.Info("ZenExtension resource is not supported; skipping")
		return subreconciler.ContinueReconciling()
	}
	log = log.WithValues("ZenExtension.Name", ImZenExtName)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	//In addition to reconciling the zen extension, we must set the proper value of
	//cluster_address_auth in the ibmcloud-cluster-info configmap
	subreconcilers := common.Subreconcilers{
		r.removeZenExtension(authCR),
	}

	return subreconcilers.Reconcile(debugCtx)
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

func (r *AuthenticationReconciler) removeZenExtension(authCR *operatorv1alpha1.Authentication) common.SecondaryReconcilerFn {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		log := logf.FromContext(ctx, "ZenExtension.Name", ImZenExtName)
		log.Info("Removing ZenExtension")
		observedZenExt := &zenv1.ZenExtension{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ImZenExtName,
				Namespace: authCR.Namespace,
			},
		}
		//Delete the existing zen extension
		if err = r.Delete(ctx, observedZenExt); k8sErrors.IsNotFound(err) {
			log.Info("ZenExtension not found; no deletion needed")
			return subreconciler.ContinueReconciling()
		} else if meta.IsNoMatchError(err) {
			log.Info("Could not delete the ZenExtension because the resource does not appear to be supported on this cluster")
			log.Info("Skipping ZenExtension deletion")
			return subreconciler.ContinueReconciling()
		} else if err != nil {
			log.Info("Failed to delete the ZenExtension due to an unexpected error", "err", err.Error())
			return subreconciler.RequeueWithError(err)
		}
		log.Info("Zen front door deleted successfully")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
}
