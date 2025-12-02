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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	authctrl "github.com/IBM/ibm-iam-operator/internal/controller/operator"
	"github.com/IBM/ibm-iam-operator/internal/version"
	"github.com/go-logr/logr"
	"github.com/opdev/subreconciler"
	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// BootStrapReconciler handles modifications to the Authentication CR before it
// is reconciled by the main Authentication controller; this is meant to handle
// edge cases that are encountered during upgrades.
type BootstrapReconciler struct {
	client.Client
	DiscoveryClient *discovery.DiscoveryClient
}

func (r *BootstrapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := logf.FromContext(ctx).WithName("controller_authentication_bootstrap")
	subCtx := logf.IntoContext(ctx, log)
	log.Info("Bootstrapping any existing Authentication CR")
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
func (r *BootstrapReconciler) SetupWithManager(mgr ctrl.Manager, log logr.Logger) error {

	authCtrl := ctrl.NewControllerManagedBy(mgr)

	predLog := log.WithName("predicate_authentication_bootstrap").V(1)
	bootstrapPred := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			predLog.Info("Update event", "Label.Version", e.ObjectNew.GetLabels()[common.ManagerVersionLabel], "Controller.Version", version.Version, "match", e.ObjectNew.GetLabels()[common.ManagerVersionLabel] != version.Version)
			return e.ObjectNew.GetLabels()[common.ManagerVersionLabel] != version.Version
		},

		// Allow create events
		CreateFunc: func(e event.CreateEvent) bool {
			predLog.Info("Create event", "Label.Version", e.Object.GetLabels()[common.ManagerVersionLabel], "Controller.Version", version.Version, "match", e.Object.GetLabels()[common.ManagerVersionLabel] != version.Version)
			return e.Object.GetLabels()[common.ManagerVersionLabel] != version.Version
		},

		// Allow delete events
		DeleteFunc: func(e event.DeleteEvent) bool {
			predLog.Info("Delete event", "Label.Version", e.Object.GetLabels()[common.ManagerVersionLabel], "Controller.Version", version.Version, "match", e.Object.GetLabels()[common.ManagerVersionLabel] != version.Version)
			return e.Object.GetLabels()[common.ManagerVersionLabel] != version.Version
		},

		// Allow generic events (e.g., external triggers)
		GenericFunc: func(e event.GenericEvent) bool {
			predLog.Info("Generic event", "Label.Version", e.Object.GetLabels()[common.ManagerVersionLabel], "Controller.Version", version.Version, "match", e.Object.GetLabels()[common.ManagerVersionLabel] != version.Version)
			return e.Object.GetLabels()[common.ManagerVersionLabel] != version.Version
		},
	}

	authCtrl.Watches(&operatorv1alpha1.Authentication{}, &handler.EnqueueRequestForObject{}, builder.WithPredicates(bootstrapPred))
	return authCtrl.Named("controller_authentication_bootstrap").Complete(r)
}

// makeAuthenticationCorrections handles changes that need to happen to the Authentication CR for compatibility reasons.
func (r *BootstrapReconciler) makeAuthenticationCorrections(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	if authCR.Labels[common.ManagerVersionLabel] == version.Version {
		log.Info("Authentication already bootstrapped, so skipping corrections")
		return subreconciler.ContinueReconciling()
	}

	if needsAuditServiceDummyDataReset(authCR) {
		authCR.SetRequiredDummyData()
	}

	if err = r.writeConfigurationsToAuthenticationCR(debugCtx, authCR); err != nil {
		log.Error(err, "Failed to update the Authentication")
		return subreconciler.RequeueWithError(err)
	}

	if err = r.bootstrapIngressCustomization(debugCtx, authCR); err != nil {
		log.Error(err, "Failed to update ingress customization")
		return subreconciler.RequeueWithError(err)
	}

	log.Info("Updating Authentication with version label and bootstrapped values")
	authCR.Labels[common.ManagerVersionLabel] = version.Version

	err = r.Update(debugCtx, authCR)
	if err != nil {
		log.Error(err, "Failed to update the Authentication")
		return subreconciler.RequeueWithError(err)
	}
	log.Info("Performed bootstrap update to Authentication successfully")

	return subreconciler.ContinueReconciling()
}

func (r *BootstrapReconciler) deleteOnpremConfigMap(ctx context.Context, namespace string) (err error) {
	cmName := "cs-onprem-tenant-config"
	log := logf.FromContext(ctx, "ConfigMap.Name", cmName)
	log.Info("ConfigMap no longer needed, so attempt to delete it")
	log.Info("Attempting to get ConfigMap")
	cm := &corev1.ConfigMap{}
	if err = r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: namespace}, cm); k8sErrors.IsNotFound(err) {
		log.Info("ConfigMap not found, nothing to delete")
		return nil
	} else if err != nil {
		log.Error(err, "An unexpected error occurred while trying to get the ConfigMap")
		return
	}
	log.Info("Attempting to delete ConfigMap")
	err = r.Delete(ctx, cm)
	if k8sErrors.IsGone(err) || k8sErrors.IsNotFound(err) {
		log.Info("ConfigMap not found, nothing to do")
		return nil
	} else if err != nil {
		log.Error(err, "An unexpected error occurred while trying to delete the ConfigMap")
	} else {
		log.Info("Deleted ConfigMap")
	}
	return
}

func (r *BootstrapReconciler) bootstrapIngressCustomization(ctx context.Context, authCR *operatorv1alpha1.Authentication) (err error) {
	modified, err := r.setIngressFromCustomizationCM(ctx, authCR)
	if modified && err == nil {
		return r.deleteOnpremConfigMap(ctx, authCR.Namespace)
	} else if err != nil {
		return
	}
	err = r.setIngressHostnameIfCustomized(ctx, authCR)
	if err != nil {
		return
	}
	return r.setIngressSecretIfCustomized(ctx, authCR)
}

func (r *BootstrapReconciler) setIngressFromCustomizationCM(ctx context.Context, authCR *operatorv1alpha1.Authentication) (modified bool, err error) {
	cmName := "cs-onprem-tenant-config"
	log := logf.FromContext(ctx, "ConfigMap.Name", cmName)
	cm := &corev1.ConfigMap{}
	if err = r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: authCR.Namespace}, cm); k8sErrors.IsNotFound(err) {
		log.Info("Did not find ConfigMap")
		return false, nil
	} else if err != nil {
		return
	}
	log.Info("Found ConfigMap; setting hostname and secret using fields")
	authCR.Spec.Config.Ingress = &operatorv1alpha1.IngressConfig{
		Hostname: ptr.To(cm.Data["custom_hostname"]),
		Secret:   ptr.To(cm.Data["custom_host_certificate_secret"]),
	}
	return true, nil
}

func setIngressIfNotSet(authCR *operatorv1alpha1.Authentication) {
	if authCR.Spec.Config.Ingress != nil {
		return
	}
	authCR.Spec.Config.Ingress = &operatorv1alpha1.IngressConfig{}
}

func (r *BootstrapReconciler) generateClusterInfo(ctx context.Context, authCR *operatorv1alpha1.Authentication, generated *corev1.ConfigMap) (err error) {
	log := logf.FromContext(ctx)
	var domainName string
	if domainName, err = authctrl.GetCNCFDomain(ctx, r.Client, authCR); err != nil {
		log.Error(err, "Could not retrieve cluster configuration; requeueing")
		return
	}

	// if the env identified as CNCF
	if domainName != "" {
		log.Info("Env type is CNCF")
		err = authctrl.GenerateCNCFClusterInfo(r.Client, r.DiscoveryClient, ctx, authCR, domainName, generated)
	} else {
		log.Info("Env Type is OCP")
		err = authctrl.GenerateOCPClusterInfo(r.Client, r.DiscoveryClient, ctx, authCR, generated)
	}

	if err != nil {
		log.Error(err, "Failed to generate ibmcloud-cluster-info contents")
	}
	return
}

func (r *BootstrapReconciler) setIngressHostnameIfCustomized(ctx context.Context, authCR *operatorv1alpha1.Authentication) (err error) {
	log := logf.FromContext(ctx)
	clusterInfo := &corev1.ConfigMap{}
	if err = r.Get(ctx, types.NamespacedName{Name: common.IBMCloudClusterInfoCMName, Namespace: authCR.Namespace}, clusterInfo); k8sErrors.IsNotFound(err) {
		log.Info("Did not find ConfigMap; assume no hostname customization")
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to detect hostname customization: %w", err)
	}
	generated := &corev1.ConfigMap{}

	log.Info("Generate expected ibmcloud-cluster-info ConfigMap contents")
	if err = r.generateClusterInfo(ctx, authCR, generated); err != nil {
		return fmt.Errorf("failed to detect hostname customization: %w", err)
	} else if clusterInfo.Data["cluster_address"] == generated.Data["cluster_address"] {
		log.Info("cluster_address values are the same; hostname is not customized")
		return
	}
	log.Info("cluster_address values are different; hostname is customized", "found", clusterInfo.Data["cluster_address"], "generated", generated.Data["cluster_address"])
	setIngressIfNotSet(authCR)
	authCR.Spec.Config.Ingress.Hostname = ptr.To(clusterInfo.Data["cluster_address"])
	return
}

// setIngressSecretIfCustomized sets the ingress secret for Authentication CR if
// custom TLS is configured.  It checks for an existing custom TLS secret and,
// if not found, creates one using the TLS configuration from the console Route
// so that the existing TLS configuration is preserved through an upgrade.
func (r *BootstrapReconciler) setIngressSecretIfCustomized(ctx context.Context, authCR *operatorv1alpha1.Authentication) (err error) {
	customTLSSecretName := "custom-tls-secret"
	log := logf.FromContext(ctx, "Secret.Name", customTLSSecretName)
	secret := &corev1.Secret{}
	if err = r.Get(ctx, types.NamespacedName{Name: customTLSSecretName, Namespace: authCR.Namespace}, secret); err == nil {
		if err = validateTLSSecret(secret); err != nil {
			log.Error(err, "Secret does not contain valid X509 TLS certificate values")
			return fmt.Errorf("found Secret does not contain valid TLS certificate values: %w", err)
		}
		log.Info("Found Secret that contains valid TLS certificate chain and key")
		setIngressIfNotSet(authCR)
		authCR.Spec.Config.Ingress.Secret = ptr.To(customTLSSecretName)
		return
	} else if !k8sErrors.IsNotFound(err) {
		log.Error(err, "Unexpected error occurred while trying to retrieve custom TLS certificate Secret")
		return
	}
	consoleRoute := &routev1.Route{}
	consoleName := "cp-console"
	if authCR.Spec.Config.ZenFrontDoor {
		consoleName = "cpd"
	}
	log.Info("Did not find Secret containing custom TLS; check the console Route for current TLS configuration", "Route.Name", consoleName)
	if err = r.Get(ctx, types.NamespacedName{Name: consoleName, Namespace: authCR.Namespace}, consoleRoute); k8sErrors.IsNotFound(err) {
		err = nil
		log.Info("Did not find Route, so no TLS customization will be performed", "Route.Name", consoleName)
		return
	} else if err != nil {
		log.Error(err, "Unexpected error occurred while trying to retrieve console Route", "Route.Name", consoleName)
		return
	}
	// If any of the TLS fields are empty, assume that custom certs are improperly configured and skip bootstrapping
	if consoleRoute.Spec.TLS.Certificate == "" || consoleRoute.Spec.TLS.Key == "" || consoleRoute.Spec.TLS.CACertificate == "" {
		log.Info("Incomplete TLS customization found on console Route, so no TLS customization will be performed", "Route.Name", consoleName)
		return
	}

	secret = &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      customTLSSecretName,
			Namespace: authCR.Namespace,
		},
		TypeMeta: v1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		Data: map[string][]byte{
			"tls.key": []byte(consoleRoute.Spec.TLS.Key),
			"tls.crt": []byte(consoleRoute.Spec.TLS.Certificate),
			"ca.crt":  []byte(consoleRoute.Spec.TLS.CACertificate),
		},
	}
	if err = r.Create(ctx, secret); err != nil {
		return
	}
	setIngressIfNotSet(authCR)
	authCR.Spec.Config.Ingress.Secret = ptr.To(customTLSSecretName)
	return
}

// writeConfigurationsToAuthenticationCR copies values from the
// platform-auth-idp ConfigMap to the Authentication CR.
func (r *BootstrapReconciler) writeConfigurationsToAuthenticationCR(ctx context.Context, authCR *operatorv1alpha1.Authentication) (err error) {
	log := logf.FromContext(ctx, "ConfigMap.Name", "platform-auth-idp")
	platformAuthIDPCM := &corev1.ConfigMap{}
	if err = r.Get(ctx, types.NamespacedName{Name: "platform-auth-idp", Namespace: authCR.Namespace}, platformAuthIDPCM); k8sErrors.IsNotFound(err) {
		log.Info("ConfigMap not found")
		return nil
	} else if err != nil {
		log.Error(err, "Failed to get ConfigMap")
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
		"PROVIDER_ISSUER_URL":      &authCR.Spec.Config.ProviderIssuerURL,
		"CLUSTER_NAME":             &authCR.Spec.Config.ClusterName,
		"FIPS_ENABLED":             &authCR.Spec.Config.FIPSEnabled,
		"IBM_CLOUD_SAAS":           &authCR.Spec.Config.IBMCloudSaas,
		"SAAS_CLIENT_REDIRECT_URL": &authCR.Spec.Config.SaasClientRedirectUrl,
		"ATTR_MAPPING_FROM_CONFIG": &authCR.Spec.Config.AttrMappingFromConfig,
		"AUDIT_URL":                &authCR.Spec.Config.AuditUrl,
		"AUDIT_SECRET":             &authCR.Spec.Config.AuditSecret,
		"LIBERTY_SAMESITE_COOKIE":  &authCR.Spec.Config.LibertySSCookie,
	}

	for key, crField := range keys {
		keyLog := log.WithValues("key", key)
		cmValue, ok := platformAuthIDPCM.Data[key]
		if !ok {
			keyLog.Info("Key not found; continuing")
			continue
		}
		keyLog.Info("Key found", "value", cmValue)
		switch crValue := crField.(type) {

		case *string:
			keyLog.Info("Value type is string")
			if crValue != nil && *crValue != cmValue {
				keyLog.Info("Value of property on CR does not match value for key in ConfigMap")
				*crValue = cmValue
			} else if crValue != nil {
				keyLog.Info("Values match")
			}
		case **string:
			keyLog.Info("Value type is optional string")
			if *crValue == nil {
				keyLog.Info("Property is not set on CR")
				*crValue = ptr.To(cmValue)
			} else if **crValue != cmValue {
				keyLog.Info("Value of property on CR does not match value for key in ConfigMap")
				*crValue = ptr.To(cmValue)
			} else {
				keyLog.Info("Values match")
			}
		case *bool:
			keyLog.Info("Value type is bool")
			cmValueBool, _ := strconv.ParseBool(cmValue)
			if crValue != nil && *crValue != cmValueBool {
				keyLog.Info("Value of property on CR does not match value for key in ConfigMap")
				*crValue = cmValueBool
			} else if crValue != nil {
				keyLog.Info("Values match")
			}
		default:
			keyLog.Info("Value type is unknown; skipping")
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

// validateTLSFiles checks if the provided TLS key, certificate chain, and CA certificate files are valid.
func validateTLSSecret(secret *corev1.Secret) (err error) {
	// Read certificate files
	keyBytes := secret.Data["tls.key"]
	certChainBytes := secret.Data["tls.crt"]
	caCertBytes := secret.Data["ca.crt"]

	_, err = tls.X509KeyPair(certChainBytes, keyBytes)
	if err != nil {
		return fmt.Errorf("failed to form X509 key pair using tls.key and tls.crt: %w", err)
	}

	block, _ := pem.Decode(caCertBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("failed to decode PEM block containing CA certificate")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	// Load certificate chain
	var leafCert *x509.Certificate
	intermediatePool := x509.NewCertPool()

	for {
		block, rest := pem.Decode(certChainBytes)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			certChainBytes = rest
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate chain: %w", err)
		}

		if leafCert == nil {
			leafCert = cert // First certificate is the leaf
		} else {
			intermediatePool.AddCert(cert) // Subsequent certificates are intermediates
		}
		certChainBytes = rest
	}

	if leafCert == nil {
		return fmt.Errorf("no leaf certificate found in chain")
	}

	// Verify options
	verifyOptions := x509.VerifyOptions{
		Roots:         caCertPool,
		Intermediates: intermediatePool,
	}

	// Verify the leaf certificate against the CA
	_, err = leafCert.Verify(verifyOptions)
	if err != nil {
		return fmt.Errorf("leaf certificate verification failed: %w", err)
	}

	return nil
}
