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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"text/template"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/controllers/common"
	"github.com/opdev/subreconciler"
	osconfigv1 "github.com/openshift/api/config/v1"
	"gopkg.in/yaml.v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// getCNCFDomain returns the CNCF domain name set in the global ConfigMap, if
// present. Returns an error when the ConfigMap is not found and returns an
// empty string whenever the ConfigMap is found but the CNCF domain name is not
// set.
func getCNCFDomain(ctx context.Context, cl client.Client, authCR *operatorv1alpha1.Authentication) (domainName string, err error) {
	logger := logf.FromContext(ctx)
	cmName := ctrlcommon.GlobalConfigMapName
	cmNs := authCR.Namespace
	cm := &corev1.ConfigMap{}
	err = cl.Get(ctx, types.NamespacedName{Name: cmName, Namespace: cmNs}, cm)
	if err != nil {
		logger.Error(err, "Failed to get ConfigMap")
		return
	}
	logger.Info("Found ConfigMap", "name", cm.Name, "namespace", cm.Namespace)

	if !strings.EqualFold(cm.Data["kubernetes_cluster_type"], "cncf") {
		return "", nil
	} else if cm.Data["domain_name"] == "" {
		return "", fmt.Errorf("domain name not configured")
	}

	return cm.Data["domain_name"], nil
}

// handleIBMCloudClusterInfo creates the ibmcloud-cluster-info configmap if not created already
func (r *AuthenticationReconciler) handleIBMCloudClusterInfo(ctx context.Context, authCR *operatorv1alpha1.Authentication, observed *corev1.ConfigMap) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("ConfigMap.Namespace", authCR.Namespace, "ConfigMap.Name", ctrlcommon.IBMCloudClusterInfoCMName)
	generated := &corev1.ConfigMap{}
	if err = r.generateIBMCloudClusterInfoConfigMap(ctx, authCR, generated); err != nil {
		return subreconciler.RequeueWithError(err)
	}
	cmKey := types.NamespacedName{Name: ctrlcommon.IBMCloudClusterInfoCMName, Namespace: authCR.Namespace}
	if err = r.Client.Get(ctx, cmKey, observed); k8sErrors.IsNotFound(err) {
		reqLogger.Info("Create new ConfigMap")
		if err = r.Client.Create(ctx, generated); err != nil {
			reqLogger.Error(err, "Failed to create new ConfigMap")
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		}
		reqLogger.Info("Successfully created ConfigMap")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	} else if err != nil {
		reqLogger.Error(err, "Failed to get the ConfigMap")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	updated := false
	controllerKind := ctrlcommon.GetControllerKind(observed)
	if controllerKind == "ManagementIngress" {
		reqLogger.Info("Configmap is already created by managementingress, IM installation may not proceed further until the configmap is removed")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	} else if controllerKind != "Authentication" {
		reqLogger.Info("ConfigMap is not owned by the current Authentication or a ManagementIngress; will attempt to become controller")
		if err = controllerutil.SetControllerReference(authCR, observed, r.Client.Scheme()); err != nil {
			reqLogger.Error(err, "Could not become the controller of the ConfigMap; it may need to be removed")
			return subreconciler.RequeueWithError(err)
		}
		updated = true
	}

	if observed.Labels == nil {
		observed.Labels = map[string]string{"app": "auth-idp"}
		updated = true
	} else if observed.Labels["app"] != "auth-idp" {
		observed.Labels["app"] = "auth-idp"
		updated = true
	} else {
		reqLogger.Info("ibmcloud-cluster-info Configmap is already created by IM operator")
	}

	updateFns := []func(*corev1.ConfigMap, *corev1.ConfigMap) bool{
		updatesValuesWhen(not(observedKeyValueSetTo("cluster_address", generated.Data["cluster_address"])),
			"cluster_address",
			"cluster_address_auth",
			"cluster_endpoint"),
		updatesValuesWhen(not(observedKeySet("cluster_address_auth")), "cluster_address_auth"),
	}

	for _, update := range updateFns {
		updated = update(observed, generated) || updated
	}

	if !updated {
		return subreconciler.ContinueReconciling()
	}

	reqLogger.Info("Attempting to update ibmcloud-cluster-info")
	if err = r.Update(ctx, observed); err != nil {
		reqLogger.Error(err, "Failed to update ConfigMap")
		return subreconciler.RequeueWithError(err)
	}
	reqLogger.Info("Successfully updated ConfigMap; requeueing reconcile")

	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

func (r *AuthenticationReconciler) handleConfigMaps(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	// Ensure that the ibmcloud-cluster-info configmap is created
	ibmCloudClusterInfoCM := &corev1.ConfigMap{}

	var subresult *ctrl.Result
	subresult, err = r.handleIBMCloudClusterInfo(ctx, authCR, ibmCloudClusterInfoCM)
	if subreconciler.ShouldHaltOrRequeue(subresult, err) {
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	cmUpdaters := []*cmUpdater{
		{
			Name:     "platform-auth-idp",
			generate: generateAuthIdpConfigMap,
			update:   updatePlatformAuthIDP,
		},
		{
			Name:     "registration-json",
			generate: generateRegistrationJsonConfigMap,
			update:   updateRegistrationJSON,
			onChange: replaceOIDCClientRegistrationJob,
		},
		{
			Name:     "oauth-client-map",
			generate: generateOAuthClientConfigMap,
		},
		{
			Name:     "registration-script",
			generate: generateRegistrationScriptConfigMap,
		},
	}

	subresults := []*ctrl.Result{}
	errs := []error{}
	for _, updater := range cmUpdaters {
		subresult, err = updater.CreateOrUpdate(ctx, r.Client, authCR, ibmCloudClusterInfoCM)
		subresults = append(subresults, subresult)
		errs = append(errs, err)
	}

	return ctrlcommon.ReduceSubreconcilerResultsAndErrors(subresults, errs)
}

func updateFields(observed, update *corev1.ConfigMap, keys ...string) (updated bool) {
	for _, key := range keys {
		observedVal, ok := observed.Data[key]
		updateVal := update.Data[key]
		if !ok || observedVal != updateVal {
			observed.Data[key] = updateVal
			updated = true
		}
	}
	return
}

type matcherFunc func(*corev1.ConfigMap) bool

func observedKeySet(key string) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		_, ok := observed.Data[key]
		return ok
	}
}

func observedKeyValueSetTo(key, value string) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		observedValue, ok := observed.Data[key]
		if ok && value == observedValue {
			return true
		}
		return false
	}
}

func zenFrontDoorEnabled(authCR *operatorv1alpha1.Authentication) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		return authCR.Spec.Config.ZenFrontDoor
	}
}

func not(isMatch matcherFunc) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		return !isMatch(observed)
	}
}

func and(matchers ...matcherFunc) matcherFunc {
	return func(observed *corev1.ConfigMap) (matches bool) {
		if len(matchers) == 0 {
			return false
		}
		matches = true
		for _, isMatch := range matchers {
			if !isMatch(observed) {
				return false
			}
		}
		return
	}
}

func or(matchers ...matcherFunc) matcherFunc {
	return func(observed *corev1.ConfigMap) (matches bool) {
		matches = false
		for _, isMatch := range matchers {
			if isMatch(observed) {
				return true
			}
		}
		return
	}
}

func observedKeyValueContains(key, value string) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		observedValue, ok := observed.Data[key]
		if ok && strings.Contains(observedValue, value) {
			return true
		}
		return false
	}
}

func updatesValuesWhen(matches matcherFunc, keys ...string) (fn func(*corev1.ConfigMap, *corev1.ConfigMap) bool) {
	return func(observed, updates *corev1.ConfigMap) bool {
		if matches(observed) {
			return updateFields(observed, updates, keys...)
		}
		return false
	}
}

func replaceOIDCClientRegistrationJob(ctx context.Context, cl client.Client, authCR *operatorv1alpha1.Authentication) (err error) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-client-registration",
			Namespace: authCR.Namespace,
		},
	}
	if err = cl.Delete(ctx, job); k8sErrors.IsNotFound(err) {
		return nil
	}
	return
}

func updateRegistrationJSON(observed, generated *corev1.ConfigMap) (updated bool, err error) {
	observedJSON := &registrationJSONData{}
	if err = json.Unmarshal([]byte(observed.Data["platform-oidc-registration.json"]), observedJSON); err != nil {
		return
	}
	generatedJSON := &registrationJSONData{}
	if err = json.Unmarshal([]byte(generated.Data["platform-oidc-registration.json"]), generatedJSON); err != nil {
		return
	}
	if !reflect.DeepEqual(generatedJSON, observedJSON) {
		var newJSON []byte
		if newJSON, err = json.MarshalIndent(generatedJSON, "", "  "); err != nil {
			return
		}

		observed.Data["platform-oidc-registration.json"] = string(newJSON[:])
		updated = true
	}
	if !reflect.DeepEqual(generated.GetOwnerReferences(), observed.GetOwnerReferences()) {
		observed.OwnerReferences = generated.GetOwnerReferences()
		updated = true
	}
	return
}

type cmUpdater struct {
	Name     string
	generate func(context.Context, client.Client, *operatorv1alpha1.Authentication, *corev1.ConfigMap, *corev1.ConfigMap) error
	update   func(*corev1.ConfigMap, *corev1.ConfigMap) (bool, error)
	onChange func(context.Context, client.Client, *operatorv1alpha1.Authentication) error
}

func (u *cmUpdater) CreateOrUpdate(ctx context.Context, cl client.Client, authCR *operatorv1alpha1.Authentication, ibmcloudClusterInfo *corev1.ConfigMap) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("ConfigMap.Namespace", authCR.Namespace, "ConfigMap.Name", u.Name)
	observed := &corev1.ConfigMap{}
	generated := &corev1.ConfigMap{}
	if err = u.generate(ctx, cl, authCR, ibmcloudClusterInfo, generated); err != nil {
		return subreconciler.RequeueWithError(err)
	}
	cmKey := types.NamespacedName{Name: u.Name, Namespace: authCR.Namespace}
	if err = cl.Get(ctx, cmKey, observed); k8sErrors.IsNotFound(err) {
		if err := cl.Create(ctx, generated); k8sErrors.IsAlreadyExists(err) {
			reqLogger.Info("ConfigMap was found while creating")
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		} else if err != nil {
			reqLogger.Info("ConfigMap could not be created for an unexpected reason", "msg", err.Error())
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		}
		reqLogger.Info("ConfigMap created")
		if u.onChange == nil {
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		}

		if err = u.onChange(ctx, cl, authCR); err != nil {
			reqLogger.Info("Error occurred while performing post-update work", "reason", err.Error())
		}
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	if u.update == nil {
		return subreconciler.ContinueReconciling()
	}
	updated := false
	updated, err = u.update(observed, generated)
	if err != nil {
		return subreconciler.RequeueWithError(err)
	} else if !updated {
		return subreconciler.ContinueReconciling()
	}

	if err = cl.Update(ctx, observed); err != nil {
		reqLogger.Info("Failed to update Configmap", "msg", err.Error())
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	reqLogger.Info("ConfigMap updated successfully")
	if u.onChange == nil {
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	if err = u.onChange(ctx, cl, authCR); err != nil {
		reqLogger.Info("Error occurred while performing post-update work", "reason", err.Error())
	}

	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

func updatePlatformAuthIDP(observed, generated *corev1.ConfigMap) (updated bool, err error) {
	updateFns := []func(*corev1.ConfigMap, *corev1.ConfigMap) bool{
		updatesValuesWhen(observedKeyValueSetTo("OS_TOKEN_LENGTH", "45"),
			"OS_TOKEN_LENGTH"),
		updatesValuesWhen(observedKeyValueContains("IDENTITY_MGMT_URL", "127.0.0.1"),
			"IDENTITY_MGMT_URL"),
		updatesValuesWhen(
			observedKeyValueContains("BASE_OIDC_URL", "127.0.0.1"),
			"BASE_OIDC_URL"),
		updatesValuesWhen(
			observedKeyValueContains("IDENTITY_AUTH_DIRECTORY_URL", "127.0.0.1"),
			"IDENTITY_AUTH_DIRECTORY_URL"),
		updatesValuesWhen(
			observedKeyValueContains("IDENTITY_PROVIDER_URL", "127.0.0.1"),
			"IDENTITY_PROVIDER_URL"),
		updatesValuesWhen(not(observedKeySet("LDAP_RECURSIVE_SEARCH")),
			"LDAP_RECURSIVE_SEARCH"),
		updatesValuesWhen(not(observedKeySet("CLAIMS_SUPPORTED")),
			"CLAIMS_SUPPORTED",
			"CLAIMS_MAP",
			"SCOPE_CLAIM",
			"BOOTSTRAP_USERID"),
		updatesValuesWhen(not(observedKeySet("PROVIDER_ISSUER_URL")),
			"PROVIDER_ISSUER_URL"),
		updatesValuesWhen(not(observedKeySet("PREFERRED_LOGIN")),
			"PREFERRED_LOGIN"),
		updatesValuesWhen(not(observedKeyValueSetTo("DEFAULT_LOGIN", generated.Data["DEFAULT_LOGIN"])),
			"DEFAULT_LOGIN"),
		updatesValuesWhen(not(observedKeySet("DB_CONNECT_TIMEOUT")),
			"DB_CONNECT_TIMEOUT",
			"DB_IDLE_TIMEOUT",
			"DB_CONNECT_MAX_RETRIES",
			"DB_POOL_MIN_SIZE",
			"DB_POOL_MAX_SIZE",
			"SEQL_LOGGING"),
		updatesValuesWhen(not(observedKeySet("DB_SSL_MODE")),
			"DB_SSL_MODE"),
		updatesValuesWhen(not(observedKeySet("SCIM_LDAP_ATTRIBUTES_MAPPING")),
			"SCIM_LDAP_ATTRIBUTES_MAPPING",
			"SCIM_LDAP_SEARCH_SIZE_LIMIT",
			"SCIM_LDAP_SEARCH_TIME_LIMIT",
			"SCIM_ASYNC_PARALLEL_LIMIT",
			"SCIM_GET_DISPLAY_FOR_GROUP_USERS"),
		updatesValuesWhen(not(observedKeySet("SCIM_AUTH_CACHE_MAX_SIZE")),
			"SCIM_AUTH_CACHE_MAX_SIZE"),
		updatesValuesWhen(not(observedKeySet("SCIM_AUTH_CACHE_TTL_VALUE")),
			"SCIM_AUTH_CACHE_TTL_VALUE"),
		updatesValuesWhen(not(observedKeySet("AUTH_SVC_LDAP_CONFIG_TIMEOUT")),
			"AUTH_SVC_LDAP_CONFIG_TIMEOUT"),
		updatesValuesWhen(not(observedKeySet("IBM_CLOUD_SAAS")),
			"IBM_CLOUD_SAAS",
			"SAAS_CLIENT_REDIRECT_URL"),
		updatesValuesWhen(not(observedKeySet("ATTR_MAPPING_FROM_CONFIG")),
			"ATTR_MAPPING_FROM_CONFIG"),
		updatesValuesWhen(not(observedKeySet("LDAP_CTX_POOL_INITSIZE")),
			"LDAP_CTX_POOL_INITSIZE",
			"LDAP_CTX_POOL_MAXSIZE",
			"LDAP_CTX_POOL_TIMEOUT",
			"LDAP_CTX_POOL_WAITTIME",
			"LDAP_CTX_POOL_PREFERREDSIZE"),
	}

	if v, ok := generated.Data["ROKS_URL"]; ok {
		updateFns = append(updateFns, updatesValuesWhen(
			not(observedKeyValueSetTo("ROKS_URL", v)), "ROKS_URL"))
	}
	if v, ok := generated.Data["IS_OPENSHIFT_ENV"]; ok {
		updateFns = append(updateFns, updatesValuesWhen(
			not(observedKeyValueSetTo("IS_OPENSHIFT_ENV", v)), "IS_OPENSHIFT_ENV"))
	}

	for _, update := range updateFns {
		updated = update(observed, generated) || updated
	}

	return
}

type registrationJSONData struct {
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	Scope                   string   `json:"scope"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ApplicationType         string   `json:"application_type"`
	SubjectType             string   `json:"subject_type"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	PreauthorizedScope      string   `json:"preauthorized_scope"`
	IntrospectTokens        bool     `json:"introspect_tokens"`
	FunctionalUserGroupIDs  []string `json:"functional_user_groupIds"`
	TrustedURIPrefixes      []string `json:"trusted_uri_prefixes"`
	RedirectURIs            []string `json:"redirect_uris"`
}

func generateAuthIdpConfigMap(ctx context.Context, cl client.Client, authCR *operatorv1alpha1.Authentication, ibmcloudClusterInfo, generated *corev1.ConfigMap) (err error) {
	reqLogger := logf.FromContext(ctx)
	onIBMCloud, _ := isHostedOnIBMCloud(ctx, cl, authCR.Namespace)

	bootStrapUserId := authCR.Spec.Config.BootstrapUserId
	if len(bootStrapUserId) > 0 && strings.EqualFold(bootStrapUserId, "kubeadmin") && onIBMCloud {
		bootStrapUserId = ""
	}

	roksUserPrefix := authCR.Spec.Config.ROKSUserPrefix
	if onIBMCloud || (authCR.Spec.Config.ROKSEnabled && roksUserPrefix == "changeme") {
		roksUserPrefix = "IAM#"
	}

	var desiredRoksUrl string
	if authCR.Spec.Config.ROKSEnabled {
		if desiredRoksUrl, err = readROKSURL(ctx); err != nil {
			reqLogger.Error(err, "Failed to get issuer URL")
			return
		} else if len(desiredRoksUrl) == 0 {
			reqLogger.Error(err, "Failed to get issuer URL")
			err = fmt.Errorf("issuer URL is empty")
			return
		}
	}

	var isOSEnv bool
	if domainName, err := getCNCFDomain(ctx, cl, authCR); err != nil {
		reqLogger.Info("Could not retrieve cluster configuration; requeueing", "reason", err.Error())
		return err
	} else {
		isOSEnv = domainName == ""
	}

	*generated = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-auth-idp",
			Namespace: authCR.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
		},
		Data: map[string]string{
			"BASE_AUTH_URL":                      "/v1",
			"BASE_OIDC_URL":                      "https://platform-auth-service:9443/oidc/endpoint/OP",
			"CLUSTER_NAME":                       authCR.Spec.Config.ClusterName,
			"HTTP_ONLY":                          "false",
			"IDENTITY_AUTH_DIRECTORY_URL":        "https://platform-auth-service:3100",
			"IDENTITY_PROVIDER_URL":              "https://platform-identity-provider:4300",
			"IDENTITY_MGMT_URL":                  "https://platform-identity-management:4500",
			"MASTER_HOST":                        authCR.Spec.Config.ClusterCADomain,
			"NODE_ENV":                           "production",
			"AUDIT_ENABLED_IDPROVIDER":           "false",
			"AUDIT_ENABLED_IDMGMT":               "false",
			"AUDIT_DETAIL":                       "false",
			"LOG_LEVEL_IDPROVIDER":               "info",
			"LOG_LEVEL_AUTHSVC":                  "info",
			"LOG_LEVEL_IDMGMT":                   "info",
			"LOG_LEVEL_MW":                       "info",
			"IDTOKEN_LIFETIME":                   "12h",
			"SESSION_TIMEOUT":                    "43200",
			"OIDC_ISSUER_URL":                    authCR.Spec.Config.OIDCIssuerURL,
			"PDP_REDIS_CACHE_DEFAULT_TTL":        "600",
			"FIPS_ENABLED":                       strconv.FormatBool(authCR.Spec.Config.FIPSEnabled),
			"NONCE_ENABLED":                      strconv.FormatBool(authCR.Spec.Config.NONCEEnabled),
			"ROKS_ENABLED":                       strconv.FormatBool(authCR.Spec.Config.ROKSEnabled),
			"IBM_CLOUD_SAAS":                     strconv.FormatBool(authCR.Spec.Config.IBMCloudSaas),
			"ATTR_MAPPING_FROM_CONFIG":           strconv.FormatBool(authCR.Spec.Config.AttrMappingFromConfig),
			"SAAS_CLIENT_REDIRECT_URL":           authCR.Spec.Config.SaasClientRedirectUrl,
			"ROKS_URL":                           desiredRoksUrl,
			"ROKS_USER_PREFIX":                   roksUserPrefix,
			"CLAIMS_SUPPORTED":                   authCR.Spec.Config.ClaimsSupported,
			"CLAIMS_MAP":                         authCR.Spec.Config.ClaimsMap,
			"SCOPE_CLAIM":                        authCR.Spec.Config.ScopeClaim,
			"BOOTSTRAP_USERID":                   bootStrapUserId,
			"PROVIDER_ISSUER_URL":                authCR.Spec.Config.ProviderIssuerURL,
			"PREFERRED_LOGIN":                    authCR.Spec.Config.PreferredLogin,
			"DEFAULT_LOGIN":                      authCR.Spec.Config.DefaultLogin,
			"LIBERTY_TOKEN_LENGTH":               "1024",
			"OS_TOKEN_LENGTH":                    "51",
			"LIBERTY_DEBUG_ENABLED":              "false",
			"LOGJAM_DHKEYSIZE_2048_BITS_ENABLED": "true",
			"LDAP_RECURSIVE_SEARCH":              "true",
			"AUTH_SVC_LDAP_CONFIG_TIMEOUT":       "25",
			"LDAP_ATTR_CACHE_SIZE":               "2000",
			"LDAP_ATTR_CACHE_TIMEOUT":            "1200s",
			"LDAP_ATTR_CACHE_ENABLED":            "true",
			"LDAP_ATTR_CACHE_SIZELIMIT":          "2000",
			"LDAP_SEARCH_CACHE_SIZE":             "2000",
			"LDAP_SEARCH_CACHE_TIMEOUT":          "1200s",
			"LDAP_SEARCH_CACHE_ENABLED":          "true",
			"LDAP_SEARCH_CACHE_SIZELIMIT":        "2000",
			"IGNORE_LDAP_FILTERS_VALIDATION":     "false",
			"LDAP_SEARCH_EXCLUDE_WILDCARD_CHARS": "false",
			"LDAP_SEARCH_SIZE_LIMIT":             "50",
			"LDAP_SEARCH_TIME_LIMIT":             "10",
			"LDAP_SEARCH_CN_ATTR_ONLY":           "false",
			"LDAP_SEARCH_ID_ATTR_ONLY":           "false",
			"LDAP_CTX_POOL_INITSIZE":             "10",
			"LDAP_CTX_POOL_MAXSIZE":              "50",
			"LDAP_CTX_POOL_TIMEOUT":              "30s",
			"LDAP_CTX_POOL_WAITTIME":             "60s",
			"LDAP_CTX_POOL_PREFERREDSIZE":        "10",
			"IBMID_CLIENT_ID":                    "d3c8d1cf59a77cf73df35b073dfc1dc8",
			"IBMID_CLIENT_ISSUER":                "idaas.iam.ibm.com",
			"IBMID_PROFILE_URL":                  "https://w3-dev.api.ibm.com/profilemgmt/test/ibmidprofileait/v2/users",
			"IBMID_PROFILE_CLIENT_ID":            "1c36586c-cf48-4bce-9b9b-1a0480cc798b",
			"IBMID_PROFILE_FIELDS":               "displayName,name,emails",
			"SAML_NAMEID_FORMAT":                 "unspecified",
			"DB_CONNECT_TIMEOUT":                 "60000",
			"DB_IDLE_TIMEOUT":                    "20000",
			"DB_CONNECT_MAX_RETRIES":             "5",
			"DB_POOL_MIN_SIZE":                   "5",
			"DB_POOL_MAX_SIZE":                   "15",
			"DB_SSL_MODE":                        "require",
			"SEQL_LOGGING":                       "false",
			"SCIM_LDAP_SEARCH_SIZE_LIMIT":        "4500",
			"SCIM_LDAP_SEARCH_TIME_LIMIT":        "10",
			"SCIM_ASYNC_PARALLEL_LIMIT":          "100",
			"SCIM_GET_DISPLAY_FOR_GROUP_USERS":   "true",
			"SCIM_AUTH_CACHE_MAX_SIZE":           "1000",
			"SCIM_AUTH_CACHE_TTL_VALUE":          "60",
			"SCIM_LDAP_ATTRIBUTES_MAPPING":       scimLdapAttributesMapping,
			"IS_OPENSHIFT_ENV":                   strconv.FormatBool(isOSEnv),
		},
	}

	// Set Authentication authCR as the owner and controller of the ConfigMap
	if err = controllerutil.SetControllerReference(authCR, generated, cl.Scheme()); err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
		return
	}

	return
}

func generateRegistrationJsonConfigMap(ctx context.Context, cl client.Client, authCR *operatorv1alpha1.Authentication, ibmcloudClusterInfo, generated *corev1.ConfigMap) (err error) {
	reqLogger := logf.FromContext(ctx)

	// Calculate the ICP Registration Console URI(s)
	icpRegistrationConsoleURIs := []string{}
	const apiRegistrationPath = "/auth/liberty/callback"
	icpConsoleURL := ibmcloudClusterInfo.Data["cluster_address"]
	icpRegistrationConsoleURIs = append(icpRegistrationConsoleURIs, strings.Join([]string{"https://", icpConsoleURL, apiRegistrationPath}, ""))
	parseConsoleURL := strings.Split(icpConsoleURL, ":")
	// If the console URI is using port 443, a copy of the URI without the port number needs to be included as well
	// so that both URIs with and without the port number work
	if len(parseConsoleURL) > 1 && parseConsoleURL[1] == "443" {
		icpRegistrationConsoleURIs = append(icpRegistrationConsoleURIs, strings.Join([]string{"https://", parseConsoleURL[0], apiRegistrationPath}, ""))
	}

	platformOIDCCredentials := &corev1.Secret{}
	objectKey := types.NamespacedName{Name: "platform-oidc-credentials", Namespace: authCR.Namespace}
	if err = cl.Get(ctx, objectKey, platformOIDCCredentials); err != nil {
		reqLogger.Error(err, "Failed to get Secret for registration-json update")
		return
	}

	observedWLPClientID := string(platformOIDCCredentials.Data["WLP_CLIENT_ID"][:])
	observedWLPClientSecret := string(platformOIDCCredentials.Data["WLP_CLIENT_SECRET"][:])

	type tmpRegistrationJsonVals struct {
		WLPClientID, WLPClientSecret, ICPConsoleURL string
		ICPRegistrationConsoleURIs                  []string
	}
	vals := tmpRegistrationJsonVals{
		WLPClientID:                observedWLPClientID,
		WLPClientSecret:            observedWLPClientSecret,
		ICPConsoleURL:              icpConsoleURL,
		ICPRegistrationConsoleURIs: icpRegistrationConsoleURIs,
	}
	registrationJsonTpl := template.Must(template.New("registrationJson").Parse(registrationJson))
	var registrationJsonBytes bytes.Buffer
	if err = registrationJsonTpl.Execute(&registrationJsonBytes, vals); err != nil {
		reqLogger.Error(err, "Failed to execute registrationJson template")
		return
	}

	*generated = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "registration-json",
			Namespace: authCR.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
		},
		Data: map[string]string{
			"platform-oidc-registration.json": registrationJsonBytes.String(),
		},
	}

	// Set Authentication authCR as the owner and controller of the ConfigMap
	if err = controllerutil.SetControllerReference(authCR, generated, cl.Scheme()); err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
	}
	return
}

func generateRegistrationScriptConfigMap(ctx context.Context, cl client.Client, authCR *operatorv1alpha1.Authentication, ibmcloudClusterInfo, generated *corev1.ConfigMap) (err error) {
	reqLogger := logf.FromContext(ctx).WithValues("ConfigMap.Namespace", authCR.Namespace, "ConfigMap.Name", "registration-script")
	*generated = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "registration-script",
			Namespace: authCR.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
		},
		Data: map[string]string{
			"register-client.sh": registerClientScript,
		},
	}

	// Set Authentication authCR as the owner and controller of the ConfigMap
	if err = controllerutil.SetControllerReference(authCR, generated, cl.Scheme()); err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
	}
	return

}

func generateOAuthClientConfigMap(ctx context.Context, cl client.Client, authCR *operatorv1alpha1.Authentication, ibmcloudClusterInfo, generated *corev1.ConfigMap) (err error) {
	reqLogger := logf.FromContext(ctx).WithValues("ConfigMap.Namespace", authCR.Namespace, "ConfigMap.Name", "oauth-client-map")
	icpConsoleURL := ibmcloudClusterInfo.Data["cluster_address"]
	icpProxyURL := ibmcloudClusterInfo.Data["proxy_address"]
	*generated = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oauth-client-map",
			Namespace: authCR.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
		},
		Data: map[string]string{
			"MASTER_IP":         icpConsoleURL,
			"PROXY_IP":          icpProxyURL,
			"CLUSTER_CA_DOMAIN": icpConsoleURL,
			"CLUSTER_NAME":      authCR.Spec.Config.ClusterName,
		},
	}

	// Set Authentication authCR as the owner and controller of the ConfigMap
	if err = controllerutil.SetControllerReference(authCR, generated, cl.Scheme()); err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
	}
	return
}

func (r *AuthenticationReconciler) generateCNCFClusterInfo(ctx context.Context, authCR *operatorv1alpha1.Authentication, domainName string, generated *corev1.ConfigMap) (err error) {
	reqLogger := logf.FromContext(ctx)

	rhttpPort, rhttpsPort, cname := getClusterInfoFromEnv()

	zenHost := ""
	clusterAddress := strings.Join([]string{strings.Join([]string{"cp-console", authCR.Namespace}, "-"), domainName}, ".")
	clusterEndpoint := "https://" + clusterAddress
	clusterAddressAuth := clusterAddress
	if authCR.Spec.Config.ZenFrontDoor && ctrlcommon.ClusterHasZenExtensionGroupVersion(&r.DiscoveryClient) {
		zenHost, err = r.getZenHost(ctx, authCR)
		if err == nil {
			clusterAddressAuth = zenHost
			clusterAddress = zenHost
			clusterEndpoint = "https://" + zenHost
		} else {
			reqLogger.Info("Zen host could not be retrieved; using defaults")
		}
	}

	*generated = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ctrlcommon.IBMCloudClusterInfoCMName,
			Namespace: authCR.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
		},
		Data: map[string]string{
			ClusterAddr:            clusterAddress,
			"cluster_address_auth": clusterAddressAuth,
			ClusterEP:              clusterEndpoint,
			RouteHTTPPort:          rhttpPort,
			RouteHTTPSPort:         rhttpsPort,
			ClusterName:            cname,
			ProxyAddress:           clusterAddress,
			ProviderSVC:            fmt.Sprintf("https://platform-identity-provider.%s.svc:4300", authCR.Namespace),
			IDMgmtSVC:              fmt.Sprintf("https://platform-identity-management.%s.svc:4500", authCR.Namespace),
		},
	}

	return
}

func (r *AuthenticationReconciler) generateOCPClusterInfo(ctx context.Context, authCR *operatorv1alpha1.Authentication, generated *corev1.ConfigMap) (err error) {
	reqLogger := logf.FromContext(ctx)

	rhttpPort, rhttpsPort, cname := getClusterInfoFromEnv()

	domainName, proxyDomainName, err := r.getDomainFromIngressConfig(ctx, authCR)
	if err != nil {
		return
	}

	apiHost, apiPort, err := r.getClusterAPIServerStrFromConsoleConfig(ctx)
	if err != nil {
		return
	}

	zenHost := ""
	clusterAddress := domainName
	clusterEndpoint := "https://" + clusterAddress
	clusterAddressAuth := clusterAddress
	if authCR.Spec.Config.ZenFrontDoor && ctrlcommon.ClusterHasZenExtensionGroupVersion(&r.DiscoveryClient) {
		zenHost, err = r.getZenHost(ctx, authCR)
		if err == nil {
			clusterAddressAuth = zenHost
			clusterAddress = zenHost
			clusterEndpoint = "https://" + zenHost
		} else {
			reqLogger.Info("Zen host could not be retrieved; using defaults")
		}
	}

	*generated = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ctrlcommon.IBMCloudClusterInfoCMName,
			Namespace: authCR.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
		},
		Data: map[string]string{
			ClusterAddr:            clusterAddress,
			"cluster_address_auth": clusterAddressAuth,
			ClusterEP:              clusterEndpoint,
			RouteHTTPPort:          rhttpPort,
			RouteHTTPSPort:         rhttpsPort,
			ClusterName:            cname,
			ClusterAPIServerHost:   apiHost,
			ClusterAPIServerPort:   apiPort,
			ProxyAddress:           proxyDomainName,
			ProviderSVC:            fmt.Sprintf("https://platform-identity-provider.%s.svc:4300", authCR.Namespace),
			IDMgmtSVC:              fmt.Sprintf("https://platform-identity-management.%s.svc:4500", authCR.Namespace),
		},
	}

	return
}

func getClusterInfoFromEnv() (rhttpPort, rhttpsPort, cname string) {
	rhttpPort = os.Getenv("ROUTE_HTTP_PORT")
	if rhttpPort == "" {
		rhttpPort = RouteHTTPPortValue
	}
	rhttpsPort = os.Getenv("ROUTE_HTTPS_PORT")
	if rhttpsPort == "" {
		rhttpsPort = RouteHTTPSPortValue
	}
	cname = os.Getenv("cluster_name")
	if cname == "" {
		cname = ClusterNameValue
	}

	return
}

func (r *AuthenticationReconciler) getZenHost(ctx context.Context, authCR *operatorv1alpha1.Authentication) (zenHost string, err error) {
	reqLogger := logf.FromContext(ctx)
	//Get the routehost from the ibmcloud-cluster-info configmap
	productConfigMap := &corev1.ConfigMap{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: ZenProductConfigmapName, Namespace: authCR.Namespace}, productConfigMap)
	if k8sErrors.IsNotFound(err) {
		reqLogger.Info("Zen product configmap does not exist")
		err = fmt.Errorf("expected product ConfigMap to be present but it was not found")
		return
	} else if err != nil {
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

func (r *AuthenticationReconciler) getDomainFromIngressConfig(ctx context.Context, authCR *operatorv1alpha1.Authentication) (domainName, proxyDomainName string, err error) {
	reqLogger := logf.FromContext(ctx)
	ingressConfigName := "cluster"
	ingressConfig := &osconfigv1.Ingress{}

	clusterClient, err := r.createOrGetClusterClient()
	if err != nil {
		reqLogger.Error(err, "Failure creating or getting cluster client")
		return
	}

	reqLogger.Info("Going to READ openshift ingress cluster config")
	if err = clusterClient.Get(ctx, types.NamespacedName{Name: ingressConfigName}, ingressConfig); err != nil {
		reqLogger.Error(err, "Failed to READ openshift ingress cluster config")
		return
	}

	reqLogger.Info("Successfully READ openshift ingress cluster config")

	var baseDomain string
	multipleauthCRRouteName := strings.Join([]string{"cp-console", authCR.Namespace}, "-")
	multipleauthCRProxyRouteName := strings.Join([]string{"cp-proxy", authCR.Namespace}, "-")
	if len(ingressConfig.Spec.AppsDomain) > 0 {
		baseDomain = ingressConfig.Spec.AppsDomain
	} else {
		baseDomain = ingressConfig.Spec.Domain
	}
	if authCR.Spec.Config.OnPremMultipleDeploy {
		domainName = strings.Join([]string{multipleauthCRRouteName, baseDomain}, ".")
		proxyDomainName = strings.Join([]string{multipleauthCRProxyRouteName, baseDomain}, ".")
	} else {
		domainName = strings.Join([]string{"cp-console", baseDomain}, ".")
		proxyDomainName = strings.Join([]string{"cp-proxy", baseDomain}, ".")
	}

	return
}

func (r *AuthenticationReconciler) getClusterAPIServerStrFromConsoleConfig(ctx context.Context) (apiHost, apiPort string, err error) {
	// get clusterApiServer Details cm console-config from openshift-console ns
	OSconsoleConfigMap := &corev1.ConfigMap{}
	OSConsoleCMKey := types.NamespacedName{Name: "console-config", Namespace: "openshift-console"}
	if err = clusterClient.Get(ctx, OSConsoleCMKey, OSconsoleConfigMap); err != nil {
		err = fmt.Errorf("failed to get console-config configmap from openshift-console namespace: %w", err)
		return
	}

	type consoleConfig struct {
		APIVersion  string `yaml:"apiVersion"`
		ClusterInfo struct {
			MasterPublicURL string `yaml:"masterPublicURL"`
		} `yaml:"clusterInfo"`
	}

	result := &consoleConfig{}
	var apiaddr string
	if err = yaml.Unmarshal([]byte(OSconsoleConfigMap.Data["console-config.yaml"]), result); err != nil {
		err = fmt.Errorf("failed to read console-config.yaml from console-config configmap: %w", err)
		return
	}

	if result.ClusterInfo.MasterPublicURL == "" {
		err = fmt.Errorf("console-config.yaml contains field .clusterInfo.masterPublicURL, but it is not in the expected format")
		return
	}
	apiaddr = strings.TrimPrefix(result.ClusterInfo.MasterPublicURL, "https://")

	pos := strings.LastIndex(apiaddr, ":")
	return apiaddr[0:pos], apiaddr[pos+1:], nil
}

func (r *AuthenticationReconciler) generateIBMCloudClusterInfoConfigMap(ctx context.Context, authCR *operatorv1alpha1.Authentication, generated *corev1.ConfigMap) (err error) {
	reqLogger := logf.FromContext(ctx)
	var domainName string
	if domainName, err = getCNCFDomain(ctx, r.Client, authCR); err != nil {
		reqLogger.Info("Could not retrieve cluster configuration; requeueing", "reason", err.Error())
		return
	}

	// if the env identified as CNCF
	if domainName != "" {
		reqLogger.Info("Env type is CNCF")
		err = r.generateCNCFClusterInfo(ctx, authCR, domainName, generated)
	} else {
		reqLogger.Info("Env Type is OCP")
		err = r.generateOCPClusterInfo(ctx, authCR, generated)
	}

	if err != nil {
		reqLogger.Info("Failed to generate ibmcloud-cluster-info contents", "reason", err.Error())
		return
	}

	// Set Authentication authCR as the owner and controller of the ConfigMap
	if err = controllerutil.SetControllerReference(authCR, generated, r.Client.Scheme()); err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
	}

	return
}

var (
	clusterClient               client.Client
	OpenShiftConfigScheme       = runtime.NewScheme()
	ConfigMapSchemeGroupVersion = schema.GroupVersion{Group: "", Version: "v1"}
	ConfigSchemeGroupVersion    = schema.GroupVersion{Group: "config.openshift.io", Version: "v1"}
)

func (r *AuthenticationReconciler) createOrGetClusterClient() (client.Client, error) {
	// return if cluster client already exists
	if clusterClient != nil {
		return clusterClient, nil
	}
	// get a config to talk to the apiserver
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, err
	}

	if ctrlcommon.ClusterHasRouteGroupVersion(&r.DiscoveryClient) {
		utilruntime.Must(osconfigv1.AddToScheme(OpenShiftConfigScheme))
	}
	utilruntime.Must(corev1.AddToScheme(OpenShiftConfigScheme))

	clusterClient, err = client.New(cfg, client.Options{Scheme: OpenShiftConfigScheme})
	if err != nil {
		return nil, err
	}

	return clusterClient, nil
}

// isHostedOnIBMCloud checks the
func isHostedOnIBMCloud(ctx context.Context, cl client.Client, namespace string) (isPublicCloud bool, err error) {
	reqLogger := logf.FromContext(ctx).V(1)
	cmName := ctrlcommon.IBMCloudClusterInfoCMName
	cm := &corev1.ConfigMap{}
	if err = cl.Get(ctx, types.NamespacedName{Name: cmName, Namespace: namespace}, cm); err != nil {
		reqLogger.Info("Error getting ConfigMap", "ConfigMap.Name", cmName, "ConfigMap.Namespace", namespace, "msg", err.Error())
		return
	}
	host := cm.Data["cluster_kube_apiserver_host"]
	return strings.HasSuffix(host, "cloud.ibm.com"), nil
}

func readROKSURL(ctx context.Context) (issuer string, err error) {
	reqLogger := logf.FromContext(ctx).V(1)

	wellknownURL := "https://kubernetes.default:443/.well-known/oauth-authorization-server"
	tokenFile := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	var caCert []byte
	if caCert, err = os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"); err != nil {
		reqLogger.Error(err, "Failed to read ca cert")
		return "", err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	var content []byte
	if content, err = os.ReadFile(tokenFile); err != nil {
		reqLogger.Info("Failed to read default token", "msg", err.Error())
		return
	}

	token := string(content)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caCertPool}}
	var req *http.Request
	if req, err = http.NewRequest("GET", wellknownURL, nil); err != nil {
		reqLogger.Info("Failed to get well known URL", "msg", err.Error())
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	client := &http.Client{Transport: transport}
	var response *http.Response
	if response, err = client.Do(req); err != nil {
		reqLogger.Info("Failed to get OpenShift server URL", err.Error())
		return
	}

	if response.Status != "200 OK" {
		reqLogger.Info("Response status is not ok", "status", response.Status)
		return "", fmt.Errorf("response status is not 200 OK")
	}

	defer response.Body.Close()
	var result map[string]interface{}
	if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
		reqLogger.Error(err, "Failed to read body from response")
		return
	}
	issuer = result["issuer"].(string)

	return issuer, nil
}
