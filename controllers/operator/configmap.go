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
func (r *AuthenticationReconciler) getCNCFDomain(ctx context.Context, req ctrl.Request) (domainName string, err error) {
	logger := logf.FromContext(ctx)
	cm := &corev1.ConfigMap{}
	cmName := ctrlcommon.GlobalConfigMapName
	cmNs := req.Namespace
	err = r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: cmNs}, cm)
	if err != nil {
		logger.Error(err, "Failed to get ConfigMap")
		return
	}
	logger.Info("Found ConfigMap", "name", cm.Name, "namespace", cm.Namespace)

	clusterTypeValue := cm.Data["kubernetes_cluster_type"]
	if !strings.EqualFold(clusterTypeValue, "cncf") {
		return "", fmt.Errorf("not configured for CNCF")
	}

	if domainName = cm.Data["domain_name"]; domainName == "" {
		return "", fmt.Errorf("domain name not configured")
	}

	return
}

// handleIBMCloudClusterInfo creates the ibmcloud-cluster-info configmap if not created already
func (r *AuthenticationReconciler) handleIBMCloudClusterInfo(ctx context.Context, authCR *operatorv1alpha1.Authentication) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("ConfigMap.Namespace", authCR.Namespace, "ConfigMap.Name", ctrlcommon.IBMCloudClusterInfoCMName)
	observed := &corev1.ConfigMap{}
	var generated *corev1.ConfigMap
	cmKey := types.NamespacedName{Name: ctrlcommon.IBMCloudClusterInfoCMName, Namespace: authCR.Namespace}
	if err = r.Client.Get(ctx, cmKey, observed); k8sErrors.IsNotFound(err) {
		reqLogger.Info("Create new ConfigMap")
		generated = r.ibmcloudClusterInfoConfigMap(authCR, r.RunningOnOpenShiftCluster(), domainName)
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
		if err = controllerutil.SetControllerReference(authCR, observed, r.Scheme); err != nil {
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

	if !updated {
		return subreconciler.ContinueReconciling()
	}

	reqLogger.Info("Became controller and labeled to indicate association with IM; attempting update")
	err = r.Client.Update(ctx, observed)
	if err != nil {
		reqLogger.Error(err, "Failed to update ConfigMap")
		return subreconciler.RequeueWithError(err)
	}
	reqLogger.Info("Successfully updated ConfigMap; requeueing reconcile")

	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

func (r *AuthenticationReconciler) handleConfigMaps(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)

	var isOSEnv bool
	var domainName string
	var newConfigMap *corev1.ConfigMap

	configMapList := []string{"platform-auth-idp", "registration-script", "oauth-client-map", "registration-json"}
	functionList := []func(*operatorv1alpha1.Authentication, *runtime.Scheme) *corev1.ConfigMap{registrationScriptConfigMap}

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	if domainName, err = r.getCNCFDomain(ctx, req); err != nil {
		reqLogger.Info("Could not retrieve global ConfigMap; requeueing", "reason", err.Error())
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	} else if domainName == "" {
		// If a domain name is not returned, the current environment is not CNCF
		isOSEnv = true
	}

	// Ensure that the ibmcloud-cluster-info configmap is created
	r.handleIBMCloudClusterInfo(ctx, req)

	// Public Cloud to be checked from ibmcloud-cluster-info
	var publicCloud bool
	if publicCloud, err = r.isHostedOnIBMCloud(ctx, authCR.Namespace); err != nil {
		reqLogger.Info("Failed to determine whether running on public cloud", "msg", err.Error())
		return
	}

	//icpConsoleURL , icpProxyURL to be fetched from ibmcloud-cluster-info
	proxyConfigMapName := ctrlcommon.IBMCloudClusterInfoCMName
	proxyConfigMap := &corev1.ConfigMap{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: proxyConfigMapName, Namespace: authCR.Namespace}, proxyConfigMap)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			reqLogger.Error(err, "The configmap ", proxyConfigMapName, " is not created yet")
			return
		}
		reqLogger.Error(err, "Failed to get ConfigMap", proxyConfigMapName)
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
	icpProxyURL, ok := proxyConfigMap.Data["proxy_address"]
	if !ok {
		reqLogger.Error(nil, "The configmap", proxyConfigMapName, "doesn't contain proxy address")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
	icpConsoleURL, ok := proxyConfigMap.Data["cluster_address"]

	if !ok {
		reqLogger.Error(nil, "The configmap", proxyConfigMapName, "doesn't contain cluster_address address")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	// TODO: rip this out
	r.handlePlatformAuthIDP(ctx, authCR)

	// Creation the default configmaps
	for index, configMap := range configMapList {
		err = r.Client.Get(ctx, types.NamespacedName{Name: configMap, Namespace: authCR.Namespace}, currentConfigMap)
		if err != nil {
			if k8sErrors.IsNotFound(err) {
				// Define a new ConfigMap
				if configMapList[index] == "registration-json" {
				} else if configMapList[index] == "oauth-client-map" {
					newConfigMap = oauthClientConfigMap(authCR, icpConsoleURL, icpProxyURL, r.Scheme)
				} else {
					newConfigMap = functionList[index](authCR, r.Scheme)
					if configMapList[index] == "platform-auth-idp" {
						// TODO: Be sure this behavior has been carried over to new function
						if authCR.Spec.Config.ROKSEnabled && authCR.Spec.Config.ROKSURL == "https://roks.domain.name:443" { //we enable it by default
							reqLogger.Info("Create platform-auth-idp Configmap roks settings", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
							issuer, err := readROKSURL(context.Background())
							if err != nil {
								reqLogger.Error(err, "Failed to get issuer URL", "ConfigMap.Namespace", authCR.Namespace, "ConfigMap.Name", configMap)
								return subreconciler.RequeueWithError(err)
							}
							newConfigMap.Data["ROKS_ENABLED"] = "true"
							newConfigMap.Data["ROKS_URL"] = issuer
							if authCR.Spec.Config.ROKSUserPrefix == "changeme" { //we change it to empty prefix, that's the new default in 3.5
								if publicCloud {
									newConfigMap.Data["ROKS_USER_PREFIX"] = "IAM#"
								} else {
									newConfigMap.Data["ROKS_USER_PREFIX"] = ""
								}
							} else { // user specifies prefix but does not specify roksEnabled and roksURL we take the user provided prefix
								newConfigMap.Data["ROKS_USER_PREFIX"] = authCR.Spec.Config.ROKSUserPrefix
							}
						} else {
							reqLogger.Info("Honor end user's setting", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
							//if user does not specify the prefix, we set it to IAM# to be consistent with previous release
							if authCR.Spec.Config.ROKSEnabled && authCR.Spec.Config.ROKSURL != "https://roks.domain.name:443" && authCR.Spec.Config.ROKSUserPrefix == "changeme" {
								newConfigMap.Data["ROKS_USER_PREFIX"] = "IAM#"
							}
						}
						reqLogger.Info("Adding new variable to configmap", "Configmap.Namespace", currentConfigMap.Namespace, "isOSEnv", isOSEnv)
						// Detect cluster type - cncf or openshift
						// if global cm, ignore CR, and populate auth-idp with value from global
						// if no global cm, take value from CR - NOT REQD.
						newConfigMap.Data["IS_OPENSHIFT_ENV"] = strconv.FormatBool(r.RunningOnOpenShiftCluster())

					} else {
						//user specifies roksEnabled and roksURL, but not roksPrefix, then we set prefix to IAM# (consistent with previous release behavior)
						if authCR.Spec.Config.ROKSEnabled && authCR.Spec.Config.ROKSURL != "https://roks.domain.name:443" && authCR.Spec.Config.ROKSUserPrefix == "changeme" {
							newConfigMap.Data["ROKS_USER_PREFIX"] = "IAM#"
						}
					}
				}
				reqLogger.Info("Creating a new ConfigMap", "ConfigMap.Namespace", authCR.Namespace, "ConfigMap.Name", configMap)
				err = r.Client.Create(context.TODO(), newConfigMap)
				if err != nil {
					reqLogger.Error(err, "Failed to create new ConfigMap", "ConfigMap.Namespace", authCR.Namespace, "ConfigMap.Name", configMap)
					return
				}
				// ConfigMap created successfully - return and requeue
				return subreconciler.RequeueWithDelay(defaultLowerWait)
			} else {
				reqLogger.Error(err, "Failed to get ConfigMap", "ConfigMap.Namespace", authCR.Namespace, "ConfigMap.Name", configMap)
				return
			}
		} else {

		}
	}

	return subreconciler.ContinueReconciling()
}

func updateFields(observed, updates *corev1.ConfigMap, keys ...string) (updated bool) {
	for _, key := range keys {
		if value, ok := updates.Data[key]; ok && observed.Data[key] != value {
			observed.Data[key] = value
			updated = true
		}
	}
	return
}

type matcherFunc func(*corev1.ConfigMap) bool

func observedKeyValueNotSet(key string) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		_, ok := observed.Data[key]
		return !ok
	}
}

func observedKeyValueSet(key, value string) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		observedValue, ok := observed.Data[key]
		if ok && value == observedValue {
			return true
		}
		return false
	}
}

func not(matches matcherFunc) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		return !matches(observed)
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

func (r *AuthenticationReconciler) handleRegistrationJSON(ctx context.Context, authCR *operatorv1alpha1.Authentication) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)
	cmName := "registration-json"
	cm := &corev1.ConfigMap{}
	// TODO Set icpConsoleURL
	var generatedCM *corev1.ConfigMap
	err = r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: authCR.Namespace}, cm)
	if k8sErrors.IsNotFound(err) {
		generatedCM = generateRegistrationJsonConfigMap(ctx, authCR, icpConsoleURL)
		if generatedCM == nil {
			err = fmt.Errorf("an error occurred during registration-json generation")
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("Creating a new ConfigMap", "ConfigMap.Namespace", authCR.Namespace, "ConfigMap.Name", cmName)
		err = r.Client.Create(ctx, generatedCM)
		if err != nil {
			reqLogger.Error(err, "Failed to create new ConfigMap", "ConfigMap.Namespace", authCR.Namespace, "ConfigMap.Name", cmName)
			return
		}
		// ConfigMap created successfully - return and requeue
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	} else if err != nil {

	}
	generatedCM = generateRegistrationJsonConfigMap(ctx, authCR, icpConsoleURL)
	if generatedCM == nil {
		err = fmt.Errorf("an error occurred during registration-json generation")
		return subreconciler.RequeueWithError(err)
	}
	reqLogger.Info("Calculated new platform-oidc-registration.json")
	var currentRegistrationJSON, newRegistrationJSON *registrationJSONData
	newRegistrationJSON = &registrationJSONData{}
	currentRegistrationJSON = &registrationJSONData{}
	if err = json.Unmarshal([]byte(newConfigMap.Data["platform-oidc-registration.json"]), newRegistrationJSON); err != nil {
		reqLogger.Error(err, "Failed to unmarshal calculated ConfigMap")
		return subreconciler.RequeueWithError(err)
	}
	if err = json.Unmarshal([]byte(currentConfigMap.Data["platform-oidc-registration.json"]), currentRegistrationJSON); err != nil {
		reqLogger.Error(err, "Failed to unmarshal observed ConfigMap")
		return subreconciler.RequeueWithError(err)
	}
	var updatedJSON, updatedOwnerRefs bool
	if !reflect.DeepEqual(newRegistrationJSON, currentRegistrationJSON) {
		reqLogger.Info("Difference found in observed vs calculated platform-oidc-registration.json")
		var newJSON []byte
		if newJSON, err = json.MarshalIndent(newRegistrationJSON, "", "  "); err != nil {
			reqLogger.Error(err, "Failed to marshal JSON for registration-json update")
			return subreconciler.RequeueWithError(err)
		}
		currentConfigMap.Data["platform-oidc-registration.json"] = string(newJSON[:])
		updatedJSON = true
	}
	if !reflect.DeepEqual(newConfigMap.GetOwnerReferences(), currentConfigMap.GetOwnerReferences()) {
		reqLogger.Info("Difference found in observed vs calculated OwnerReferences")
		currentConfigMap.OwnerReferences = newConfigMap.GetOwnerReferences()
		updatedOwnerRefs = true
	}
	if updatedJSON || updatedOwnerRefs {
		reqLogger.Info("Updating ConfigMap")
		if err = r.Client.Update(context.Background(), currentConfigMap); err != nil {
			reqLogger.Error(err, "Failed to update ConfigMap", "Name", "registration-json", "Namespace", authCR.Namespace)
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("ConfigMap successfully updated")
		if updatedJSON {
			reqLogger.Info("Deleting Job to re-run with upated ConfigMap", "Job.Name", "oidc-client-registration")

			job := &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "oidc-client-registration",
					Namespace: authCR.Namespace,
				},
			}
			if err = r.Client.Delete(context.TODO(), job); err != nil {
				if k8sErrors.IsNotFound(err) {
					reqLogger.Info("Job not found on cluster; continuing", "Job.Name", "oidc-client-registration")
					return subreconciler.ContinueReconciling()
				}
				reqLogger.Error(err, "Could not delete job", "Job.Name", "oidc-client-registration")
				return
			}
			reqLogger.Info("Deleted Job", "Job.Name", "oidc-client-registration")
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		}
	} else {
		reqLogger.Info("No ConfigMap update required")
	}
}

func (r *AuthenticationReconciler) handlePlatformAuthIDP(ctx context.Context, authCR *operatorv1alpha1.Authentication) (result *ctrl.Result, err error) {
	cmName := "platform-auth-idp"
	reqLogger := logf.FromContext(ctx).WithValues("ConfigMap.Namespace", authCR.Namespace, "ConfigMap.Name", cmName)
	observed := &corev1.ConfigMap{}
	var desired *corev1.ConfigMap
	err = r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: authCR.Namespace}, observed)
	if k8sErrors.IsNotFound(err) {
		desired = r.authIdpConfigMap(ctx, authCR)
		if err := r.Create(ctx, desired); k8sErrors.IsAlreadyExists(err) {
			reqLogger.Info("ConfigMap was found while creating")
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		} else if err != nil {
			reqLogger.Info("ConfigMap could not be created for an unexpected reason", "msg", err.Error())
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		}
		reqLogger.Info("ConfigMap created")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
	desired = r.authIdpConfigMap(ctx, authCR)
	cmUpdateRequired := false
	desiredRoksUrl := desired.Data["ROKS_URL"]

	updateFns := []func(*corev1.ConfigMap, *corev1.ConfigMap) bool{
		updatesValuesWhen(not(observedKeyValueSet("ROKS_URL", desiredRoksUrl)),
			"ROKS_URL"),
		updatesValuesWhen(not(observedKeyValueSet("IS_OPENSHIFT_ENV", strconv.FormatBool(r.RunningOnOpenShiftCluster()))),
			"IS_OPENSHIFT_ENV"),
		updatesValuesWhen(observedKeyValueSet("OS_TOKEN_LENGTH", "45"),
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
		updatesValuesWhen(observedKeyValueNotSet("LDAP_RECURSIVE_SEARCH"),
			"LDAP_RECURSIVE_SEARCH"),
		updatesValuesWhen(observedKeyValueNotSet("CLAIMS_SUPPORTED"),
			"CLAIMS_SUPPORTED",
			"CLAIMS_MAP",
			"SCOPE_CLAIM",
			"BOOTSTRAP_USERID"),
		updatesValuesWhen(observedKeyValueNotSet("PROVIDER_ISSUER_URL"),
			"PROVIDER_ISSUER_URL"),
		updatesValuesWhen(observedKeyValueNotSet("PREFERRED_LOGIN"),
			"PREFERRED_LOGIN"),
		updatesValuesWhen(observedKeyValueNotSet("DB_CONNECT_TIMEOUT"),
			"DB_CONNECT_TIMEOUT",
			"DB_IDLE_TIMEOUT",
			"DB_CONNECT_MAX_RETRIES",
			"DB_POOL_MIN_SIZE",
			"DB_POOL_MAX_SIZE",
			"SEQL_LOGGING"),
		updatesValuesWhen(observedKeyValueNotSet("DB_SSL_MODE"),
			"DB_SSL_MODE"),
		updatesValuesWhen(observedKeyValueNotSet("SCIM_LDAP_ATTRIBUTES_MAPPING"),
			"SCIM_LDAP_ATTRIBUTES_MAPPING",
			"SCIM_LDAP_SEARCH_SIZE_LIMIT",
			"SCIM_LDAP_SEARCH_TIME_LIMIT",
			"SCIM_ASYNC_PARALLEL_LIMIT",
			"SCIM_GET_DISPLAY_FOR_GROUP_USERS"),
		updatesValuesWhen(observedKeyValueNotSet("SCIM_AUTH_CACHE_MAX_SIZE"),
			"SCIM_AUTH_CACHE_MAX_SIZE"),
		updatesValuesWhen(observedKeyValueNotSet("SCIM_AUTH_CACHE_TTL_VALUE"),
			"SCIM_AUTH_CACHE_TTL_VALUE"),
		updatesValuesWhen(observedKeyValueNotSet("AUTH_SVC_LDAP_CONFIG_TIMEOUT"),
			"AUTH_SVC_LDAP_CONFIG_TIMEOUT"),
		updatesValuesWhen(observedKeyValueNotSet("IBM_CLOUD_SAAS"),
			"IBM_CLOUD_SAAS",
			"SAAS_CLIENT_REDIRECT_URL"),
		updatesValuesWhen(observedKeyValueNotSet("ATTR_MAPPING_FROM_CONFIG"),
			"ATTR_MAPPING_FROM_CONFIG"),
		updatesValuesWhen(observedKeyValueNotSet("LDAP_CTX_POOL_INITSIZE"),
			"LDAP_CTX_POOL_INITSIZE",
			"LDAP_CTX_POOL_MAXSIZE",
			"LDAP_CTX_POOL_TIMEOUT",
			"LDAP_CTX_POOL_WAITTIME",
			"LDAP_CTX_POOL_PREFERREDSIZE"),
	}

	for _, update := range updateFns {
		cmUpdateRequired = update(observed, desired) || cmUpdateRequired
	}

	if !cmUpdateRequired {
		return subreconciler.ContinueReconciling()
	}

	if err = r.Update(ctx, observed); err != nil {
		reqLogger.Info("Failed to update Configmap", "msg", err.Error())
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	reqLogger.Info("ConfigMap updated")

	return subreconciler.RequeueWithDelay(defaultLowerWait)
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

func (r *AuthenticationReconciler) authIdpConfigMap(ctx context.Context, authCR *operatorv1alpha1.Authentication) *corev1.ConfigMap {
	reqLogger := logf.FromContext(ctx)
	onIBMCloud, _ := r.isHostedOnIBMCloud(ctx, authCR.Namespace)
	bootStrapUserId := authCR.Spec.Config.BootstrapUserId
	roksUserPrefix := authCR.Spec.Config.ROKSUserPrefix
	if len(bootStrapUserId) > 0 && strings.EqualFold(bootStrapUserId, "kubeadmin") && onIBMCloud {
		bootStrapUserId = ""
	}
	if onIBMCloud {
		roksUserPrefix = "IAM#"
	}

	newConfigMap := &corev1.ConfigMap{
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
			"ROKS_URL":                           authCR.Spec.Config.ROKSURL,
			"ROKS_USER_PREFIX":                   roksUserPrefix,
			"CLAIMS_SUPPORTED":                   authCR.Spec.Config.ClaimsSupported,
			"CLAIMS_MAP":                         authCR.Spec.Config.ClaimsMap,
			"SCOPE_CLAIM":                        authCR.Spec.Config.ScopeClaim,
			"BOOTSTRAP_USERID":                   bootStrapUserId,
			"PROVIDER_ISSUER_URL":                authCR.Spec.Config.ProviderIssuerURL,
			"PREFERRED_LOGIN":                    authCR.Spec.Config.PreferredLogin,
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
			"IS_OPENSHIFT_ENV":                   strconv.FormatBool(r.RunningOnOpenShiftCluster()),
		},
	}

	if desiredRoksUrl, err := readROKSURL(context.Background()); err == nil && len(desiredRoksUrl) > 0 {
		newConfigMap.Data["ROKS_URL"] = desiredRoksUrl
	}

	// Set Authentication authCR as the owner and controller of the ConfigMap
	err := controllerutil.SetControllerReference(authCR, newConfigMap, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
		return nil
	}
	return newConfigMap
}

func generateRegistrationJsonConfigMap(ctx context.Context, authCR *operatorv1alpha1.Authentication, icpConsoleURL string) *corev1.ConfigMap {
	reqLogger := logf.FromContext(ctx)

	// Calculate the ICP Registration Console URI(s)
	icpRegistrationConsoleURIs := []string{}
	const apiRegistrationPath = "/auth/liberty/callback"
	icpRegistrationConsoleURIs = append(icpRegistrationConsoleURIs, strings.Join([]string{"https://", icpConsoleURL, apiRegistrationPath}, ""))
	parseConsoleURL := strings.Split(icpConsoleURL, ":")
	// If the console URI is using port 443, a copy of the URI without the port number needs to be included as well
	// so that both URIs with and without the port number work
	if len(parseConsoleURL) > 1 && parseConsoleURL[1] == "443" {
		icpRegistrationConsoleURIs = append(icpRegistrationConsoleURIs, strings.Join([]string{"https://", parseConsoleURL[0], apiRegistrationPath}, ""))
	}

	platformOIDCCredentials := &corev1.Secret{}
	objectKey := types.NamespacedName{Name: "platform-oidc-credentials", Namespace: req.Namespace}
	if err = r.Get(ctx, objectKey, platformOIDCCredentials); err != nil {
		reqLogger.Error(err, "Failed to get Secret for registration-json update")
		return subreconciler.RequeueWithError(err)
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
	if err := registrationJsonTpl.Execute(&registrationJsonBytes, vals); err != nil {
		reqLogger.Error(err, "Failed to execute registrationJson template")
		return nil
	}

	newConfigMap := &corev1.ConfigMap{
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
	err := controllerutil.SetControllerReference(authCR, newConfigMap, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
		return nil
	}
	return newConfigMap
}

func registrationScriptConfigMap(authCR *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *corev1.ConfigMap {

	reqLogger := log.WithValues("authCR.Namespace", authCR.Namespace, "authCR.Name", authCR.Name)
	newConfigMap := &corev1.ConfigMap{
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
	err := controllerutil.SetControllerReference(authCR, newConfigMap, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
		return nil
	}
	return newConfigMap

}

func oauthClientConfigMap(authCR *operatorv1alpha1.Authentication, icpConsoleURL string, icpProxyURL string, scheme *runtime.Scheme) *corev1.ConfigMap {

	reqLogger := log.WithValues("authCR.Namespace", authCR.Namespace, "authCR.Name", authCR.Name)
	newConfigMap := &corev1.ConfigMap{
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
	err := controllerutil.SetControllerReference(authCR, newConfigMap, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
		return nil
	}
	return newConfigMap

}

func (r *AuthenticationReconciler) ibmcloudClusterInfoConfigMap(authCR *operatorv1alpha1.Authentication, isOSEnv bool, domainName string) *corev1.ConfigMap {

	reqLogger := log.WithValues("authCR.Namespace", authCR.Namespace, "authCR.Name", authCR.Name)

	rhttpPort := os.Getenv("ROUTE_HTTP_PORT")
	if rhttpPort == "" {
		rhttpPort = RouteHTTPPortValue
	}
	rhttpsPort := os.Getenv("ROUTE_HTTPS_PORT")
	if rhttpsPort == "" {
		rhttpsPort = RouteHTTPSPortValue
	}
	cname := os.Getenv("cluster_name")
	if cname == "" {
		cname = ClusterNameValue
	}
	// if the env identified as CNCF
	if !isOSEnv {
		reqLogger.Info("Env type is CNCF")

		ClusterAddress := strings.Join([]string{strings.Join([]string{"cp-console", authCR.Namespace}, "-"), domainName}, ".")
		ep := "https://" + ClusterAddress

		newConfigMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ctrlcommon.IBMCloudClusterInfoCMName,
				Namespace: authCR.Namespace,
				Labels:    map[string]string{"app": "auth-idp"},
			},
			Data: map[string]string{
				ClusterAddr:    ClusterAddress,
				ClusterEP:      ep,
				RouteHTTPPort:  rhttpPort,
				RouteHTTPSPort: rhttpsPort,
				ClusterName:    cname,
				ProxyAddress:   ClusterAddress,
				ProviderSVC:    "https://platform-identity-provider" + "." + authCR.Namespace + ".svc:4300",
				IDMgmtSVC:      "https://platform-identity-management" + "." + authCR.Namespace + ".svc:4500",
			},
		}

		// Set Authentication authCR as the owner and controller of the ConfigMap
		err := controllerutil.SetControllerReference(authCR, newConfigMap, r.Scheme)
		if err != nil {
			reqLogger.Error(err, "Failed to set owner for ConfigMap")
			return nil
		}
		return newConfigMap

	} else if isOSEnv { // if the env identified as OCP

		reqLogger.Info("Env Type is OCP")
		// get domain name from ingresses.config/cluster from openshift-ingress-operator ns
		var DomainName string
		var ProxyDomainName string
		ingressConfigName := "cluster"
		ingressConfig := &osconfigv1.Ingress{}

		clusterClient, err := r.createOrGetClusterClient()
		if err != nil {
			reqLogger.Error(err, "Failure creating or getting cluster client")
		}

		reqLogger.Info("Going to READ openshift ingress cluster config")
		errGet := clusterClient.Get(context.TODO(), types.NamespacedName{Name: ingressConfigName}, ingressConfig)

		if errGet == nil {
			reqLogger.Info("Successfully READ openshift ingress cluster config")
			appsDomain := ingressConfig.Spec.AppsDomain
			if len(appsDomain) > 0 {
				reqLogger.Info("appsDomain has been configured", "appsDomain.value", appsDomain)

				if authCR.Spec.Config.OnPremMultipleDeploy {
					multipleauthCRRouteName := strings.Join([]string{"cp-console", authCR.Namespace}, "-")
					DomainName = strings.Join([]string{multipleauthCRRouteName, appsDomain}, ".")
					multipleauthCRProxyRouteName := strings.Join([]string{"cp-proxy", authCR.Namespace}, "-")
					ProxyDomainName = strings.Join([]string{multipleauthCRProxyRouteName, appsDomain}, ".")
				} else {
					DomainName = strings.Join([]string{"cp-console", appsDomain}, ".")
					ProxyDomainName = strings.Join([]string{"cp-proxy", appsDomain}, ".")
				}
			} else {
				ingressDomain := ingressConfig.Spec.Domain
				reqLogger.Info("appsDomain is not configured , going to fetch default domain", "ingressDomain.value", ingressDomain)
				if authCR.Spec.Config.OnPremMultipleDeploy {
					multipleauthCRRouteName := strings.Join([]string{"cp-console", authCR.Namespace}, "-")
					DomainName = strings.Join([]string{multipleauthCRRouteName, ingressDomain}, ".")
					multipleauthCRProxyRouteName := strings.Join([]string{"cp-proxy", authCR.Namespace}, "-")
					ProxyDomainName = strings.Join([]string{multipleauthCRProxyRouteName, ingressDomain}, ".")
				} else {
					DomainName = strings.Join([]string{"cp-console", ingressDomain}, ".")
					ProxyDomainName = strings.Join([]string{"cp-proxy", ingressDomain}, ".")
				}
			}
		} else {
			if !k8sErrors.IsNotFound(errGet) {
				reqLogger.Error(errGet, "Failed to READ openshift ingress cluster config")
			}
		}

		// get clusterApiServer Details cm console-config from openshift-console ns
		OSconsoleConfigMap := &corev1.ConfigMap{}

		err = clusterClient.Get(context.TODO(), types.NamespacedName{Name: "console-config", Namespace: "openshift-console"}, OSconsoleConfigMap)

		if err != nil {
			reqLogger.Error(err, "Failed to get console-config configmap from openshift-console namespace")
			return nil
		}

		var result map[interface{}]interface{}
		var apiaddr string
		if err := yaml.Unmarshal([]byte(OSconsoleConfigMap.Data["console-config.yaml"]), &result); err != nil {
			reqLogger.Error(err, "Failed to read console-config.yaml from console-config configmap")
			return nil
		}

		for k, v := range result {
			if k.(string) == "clusterInfo" {
				cinfo := v.(map[interface{}]interface{})
				for k1, v1 := range cinfo {
					if k1.(string) == "masterPublicURL" {
						apiaddr = v1.(string)
						apiaddr = strings.TrimPrefix(apiaddr, "https://")
						break
					}
				}
				break
			}
		}

		pos := strings.LastIndex(apiaddr, ":")

		newConfigMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ctrlcommon.IBMCloudClusterInfoCMName,
				Namespace: authCR.Namespace,
				Labels:    map[string]string{"app": "auth-idp"},
			},
			Data: map[string]string{
				ClusterAddr:          DomainName,
				ClusterEP:            "https://" + DomainName,
				RouteHTTPPort:        rhttpPort,
				RouteHTTPSPort:       rhttpsPort,
				ClusterName:          cname,
				ClusterAPIServerHost: apiaddr[0:pos],
				ClusterAPIServerPort: apiaddr[pos+1:],
				ProxyAddress:         ProxyDomainName,
				ProviderSVC:          "https://platform-identity-provider" + "." + authCR.Namespace + ".svc:4300",
				IDMgmtSVC:            "https://platform-identity-management" + "." + authCR.Namespace + ".svc:4500",
			},
		}

		// Set Authentication authCR as the owner and controller of the ConfigMap
		errset := controllerutil.SetControllerReference(authCR, newConfigMap, r.Scheme)

		if errset != nil {
			reqLogger.Error(err, "Failed to set owner for ConfigMap")
			return nil
		}
		return newConfigMap
	}

	reqLogger.Info("Failed to create ibmcloudClusterInfoConfigMap , can't determine the env type")
	return nil

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
func (r *AuthenticationReconciler) isHostedOnIBMCloud(ctx context.Context, namespace string) (isPublicCloud bool, err error) {
	reqLogger := logf.FromContext(ctx).V(1)
	cmName := ctrlcommon.IBMCloudClusterInfoCMName
	cm := &corev1.ConfigMap{}
	if err = r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: namespace}, cm); err != nil {
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
