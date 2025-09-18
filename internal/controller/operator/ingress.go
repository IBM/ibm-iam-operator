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
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	routev1 "github.com/openshift/api/route/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *AuthenticationReconciler) removeIngresses(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure all Ingresses are deleted when Routes are supported")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	if !common.ClusterHasRouteGroupVersion(&r.DiscoveryClient) {
		log.Info("GVK is not available on cluster; leaving Ingresses in place", "Kind", "Route", "Group", routev1.GroupVersion.Group, "Version", routev1.GroupVersion.Version)
		return subreconciler.ContinueReconciling()
	}

	subRec := common.NewLazySubreconcilers(
		r.removeIngress("ibmid-ui-callback", req.Namespace),
		r.removeIngress("id-mgmt", req.Namespace),
		r.removeIngress("idmgmt-v2-api", req.Namespace),
		r.removeIngress("platform-auth", req.Namespace),
		r.removeIngress("platform-id-provider", req.Namespace),
		r.removeIngress("platform-login", req.Namespace),
		r.removeIngress("platform-oidc-block", req.Namespace),
		r.removeIngress("platform-oidc", req.Namespace),
		r.removeIngress("saml-ui-callback", req.Namespace),
		r.removeIngress("version-idmgmt", req.Namespace),
		r.removeIngress("social-login-callback", req.Namespace),
	)

	return subRec.Reconcile(debugCtx)
}

func (r *AuthenticationReconciler) removeIngress(name string, namespace string) common.SecondaryReconcilerFn {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		log := logf.FromContext(ctx, "Ingress.Name", name)

		ingress := &netv1.Ingress{}
		err = r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, ingress)
		if errors.IsNotFound(err) {
			log.Info("Ingress not found; continuing")
			return subreconciler.ContinueReconciling()
		} else if err != nil {
			log.Error(err, "Failed to get Ingress")
			return subreconciler.RequeueWithError(err)
		}

		// Delete ingress if found
		err = r.Delete(ctx, ingress)
		if err != nil {
			log.Error(err, "Failed to delete Ingress")
			return subreconciler.RequeueWithError(err)
		}

		log.Info("Deleted Ingress")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
}
