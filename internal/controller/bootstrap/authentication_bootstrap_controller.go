/*
Copyright 2025 IBM Corporation

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

package bootstrap

import (
	"context"
	"fmt"
	"strconv"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/IBM/ibm-iam-operator/internal/version"
	"github.com/opdev/subreconciler"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// BootStrapReconciler handles modifications to the Authentication CR before it is reconciled by the
// main Authentication controller
type BootstrapReconciler struct {
	client.Client
}

func (r *BootstrapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := logf.FromContext(ctx).WithName("controller_authentication_bootstrap")
	subCtx := logf.IntoContext(ctx, log)
	if subResult, err := r.makeAuthenticationCorrections(subCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		if err != nil {
			log.Error(err, "An error was encountered during Authentication bootstrap")
		} else {
			log.Info("Needed to requeue during Authentication bootstrap")
		}
		return subreconciler.Evaluate(subResult, err)
	}
	log.Info("Authentication bootstrap successful")
	return
}

// SetupWithManager sets up the controller with the Manager.
func (r *BootstrapReconciler) SetupWithManager(mgr ctrl.Manager) error {

	authCtrl := ctrl.NewControllerManagedBy(mgr)

	bootstrapPred := predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetLabels()[ctrlcommon.ManagerVersionLabel] != version.Version
	})

	authCtrl.Watches(&operatorv1alpha1.Authentication{}, &handler.EnqueueRequestForObject{}, builder.WithPredicates(bootstrapPred))
	return authCtrl.Named("controller_authentication_bootstrap").Complete(r)
}

// makeAuthenticationCorrections handles changes that need to happen to the Authentication CR for compatibility reasons.
func (r *BootstrapReconciler) makeAuthenticationCorrections(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	if authCR.Labels[ctrlcommon.ManagerVersionLabel] == version.Version {
		return subreconciler.ContinueReconciling()
	}

	if needsAuditServiceDummyDataReset(authCR) {
		authCR.SetRequiredDummyData()
	}

	if err = r.writeConfigurationsToAuthenticationCR(ctx, authCR); err != nil {
		log.Error(err, "Failed to update the Authentication")
		return subreconciler.RequeueWithError(err)
	}

	authCR.Labels[ctrlcommon.ManagerVersionLabel] = version.Version

	err = r.Update(ctx, authCR)
	if err != nil {
		log.Error(err, "Failed to update the Authentication")
		return subreconciler.RequeueWithError(err)
	}
	log.Info("Performed bootstrap update to Authentication successfully")

	return subreconciler.ContinueReconciling()
}

// writeConfigurationsToAuthenticationCR copies values from the
// platform-auth-idp ConfigMap to the Authentication CR.
func (r *BootstrapReconciler) writeConfigurationsToAuthenticationCR(ctx context.Context, authCR *operatorv1alpha1.Authentication) (err error) {
	platformAuthIDPCM := &corev1.ConfigMap{}
	if err = r.Get(ctx, types.NamespacedName{Name: "platform-auth-idp", Namespace: authCR.Namespace}, platformAuthIDPCM); k8sErrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get ConfigMap: %w", err)
	}
	keys := map[string]any{
		"ROKS_URL":                 &authCR.Spec.Config.ROKSURL,
		"ROKS_USER_PREFIX":         &authCR.Spec.Config.ROKSUserPrefix,
		"ROKS_ENABLED":             &authCR.Spec.Config.ROKSEnabled,
		"BOOTSTRAP_USERID":         &authCR.Spec.Config.BootstrapUserId,
		"CLAIMS_SUPPORTED":         &authCR.Spec.Config.ClaimsSupported,
		"CLAIMS_MAP":               &authCR.Spec.Config.ClaimsMap,
		"DEFAULT_LOGIN":            &authCR.Spec.Config.DefaultLogin,
		"SCOPE_CLAIM":              &authCR.Spec.Config.ScopeClaim,
		"NONCE_ENABLED":            &authCR.Spec.Config.NONCEEnabled,
		"PREFERRED_LOGIN":          &authCR.Spec.Config.PreferredLogin,
		"OIDC_ISSUER_URL":          &authCR.Spec.Config.OIDCIssuerURL,
		"AUDIT_URL":                &authCR.Spec.Config.AuditUrl,
		"AUDIT_SECRET":             &authCR.Spec.Config.AuditSecret,
		"PROVIDER_ISSUER_URL":      &authCR.Spec.Config.ProviderIssuerURL,
		"CLUSTER_NAME":             &authCR.Spec.Config.ClusterName,
		"FIPS_ENABLED":             &authCR.Spec.Config.FIPSEnabled,
		"IBM_CLOUD_SAAS":           &authCR.Spec.Config.IBMCloudSaas,
		"SAAS_CLIENT_REDIRECT_URL": &authCR.Spec.Config.SaasClientRedirectUrl,
		"ATTR_MAPPING_FROM_CONFIG": &authCR.Spec.Config.AttrMappingFromConfig,
	}

	for key, crField := range keys {
		cmValue, ok := platformAuthIDPCM.Data[key]
		if !ok {
			continue
		}
		switch crValue := crField.(type) {
		case *string:
			if *crValue != cmValue {
				*crValue = cmValue
			}
		case *bool:
			cmValueBool, _ := strconv.ParseBool(cmValue)
			if *crValue != cmValueBool {
				*crValue = cmValueBool
			}
		}
	}

	return
}

// needsAuditServiceDummyDataReset compares the state in an Authentication's .spec.auditService and returns whether it
// needs to be overwritten with dummy data.
func needsAuditServiceDummyDataReset(a *operatorv1alpha1.Authentication) bool {
	return a.Spec.AuditService.ImageName != operatorv1alpha1.AuditServiceIgnoreString ||
		a.Spec.AuditService.ImageRegistry != operatorv1alpha1.AuditServiceIgnoreString ||
		a.Spec.AuditService.ImageTag != operatorv1alpha1.AuditServiceIgnoreString ||
		a.Spec.AuditService.SyslogTlsPath != "" ||
		a.Spec.AuditService.Resources != nil
}

func (r *BootstrapReconciler) getLatestAuthentication(ctx context.Context, req ctrl.Request, authentication *operatorv1alpha1.Authentication) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)
	if err := r.Get(ctx, req.NamespacedName, authentication); err != nil {
		if k8sErrors.IsNotFound(err) {
			reqLogger.Info("Authentication not found; skipping reconciliation")
			return subreconciler.DoNotRequeue()
		}
		reqLogger.Error(err, "Failed to get Authentication")
		return subreconciler.RequeueWithError(err)
	}
	return subreconciler.ContinueReconciling()
}
