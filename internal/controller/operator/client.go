/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package operator

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/api/oidc.security/v1"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// syncClientHostnames iterates through all Clients in all namespaces visible to
// the Operator and updates the hostnames present in their .spec.oidcLibertyClient fields.
func (r *AuthenticationReconciler) syncClientHostnames(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)
	log.Info("Syncing Client CRs to use latest Authentication configuration")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		log.Info("Failed to retrieve Authentication CR for status update")
		return
	}
	debugLog.Info("Listing Clients")
	clientList := &oidcsecurityv1.ClientList{}
	if err = r.List(debugCtx, clientList); err != nil {
		log.Error(err, "Failed to list Clients in all watch namespaces")
		return subreconciler.RequeueWithError(err)
	}

	debugLog.Info("Get the cluster address from ConfigMap", "ConfigMap.Name", ClusterInfoConfigmapName)
	var clusterAddress string
	if result, err = r.getClusterAddress(authCR, &clusterAddress)(debugCtx); subreconciler.ShouldHaltOrRequeue(result, err) {
		log.Error(err, "Could not get the cluster_address due to an unexpected error", "ConfigMap.Name", ClusterInfoConfigmapName)
		return subreconciler.RequeueWithError(err)
	}

	subRecs := common.Subreconcilers{}
	for _, clientCR := range clientList.Items {
		if isOwnedByZenService(&clientCR) {
			debugLog.Info("Client is for Zen; skipping", "Client.Name", clientCR.Name)
			continue
		}
		subRecs = append(subRecs, r.updateClientCRURIs(&clientCR, clusterAddress))
	}
	return subRecs.Reconcile(debugCtx)
}

func isOwnedByZenService(obj client.Object) bool {
	for _, ownerRef := range obj.GetOwnerReferences() {
		if ownerRef.APIVersion == "zen.cpd.ibm.com/v1" && ownerRef.Kind == "ZenService" {
			return true
		}
	}
	return false
}

func (r *AuthenticationReconciler) updateClientCRURIs(clientCR *oidcsecurityv1.Client, clusterAddress string) common.SecondaryReconcilerFn {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		log := logf.FromContext(ctx, "Client.Name", clientCR.Name, "hostname", clusterAddress)
		modified := false
		for _, uris := range []*[]string{
			&clientCR.Spec.OidcLibertyClient.LogoutUris,
			&clientCR.Spec.OidcLibertyClient.RedirectUris,
			&clientCR.Spec.OidcLibertyClient.TrustedUris,
		} {
			newURIs, err := replaceURIListHostnames(*uris, clusterAddress)
			if err != nil {
				log.Error(err, "Failed to replace hostnames in all URIs for Client")
				return subreconciler.RequeueWithError(err)
			}
			if !slices.Equal(*uris, newURIs) {
				*uris = newURIs
				modified = true
			}
		}
		if !modified {
			log.Info("No URIs need to be updated on Client")
			return subreconciler.ContinueReconciling()
		} else {
			log.Info("URIs on Client were updated with new hostname")
		}

		if err = r.Update(ctx, clientCR); err != nil {
			log.Error(err, "Failed to update Client with new URIs")
			return subreconciler.RequeueWithError(err)
		}
		log.Info("Successfully updated the hostname in URIs on Client")

		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
}

func replaceURIListHostnames(uris []string, newHostname string) (newURIs []string, err error) {
	newURIs = []string{}
	errs := []error{}
	for _, uriString := range uris {
		u, err := url.Parse(uriString)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to replace hostname in URI: %w", err))
			continue
		}
		oldHostname := u.Hostname()
		newURI := strings.Replace(uriString, oldHostname, newHostname, 1)
		newURIs = append(newURIs, newURI)
	}
	if len(errs) > 0 {
		err = fmt.Errorf("failed to make all hostname replacements in Client CR URIs: %w", errors.Join(errs...))
		return []string{}, err
	}
	return
}
