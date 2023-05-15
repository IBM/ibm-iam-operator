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

package authentication

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	pkgCommon "github.com/IBM/ibm-iam-operator/pkg/common"
	osconfigv1 "github.com/openshift/api/config/v1"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *ReconcileAuthentication) handleConfigMap(instance *operatorv1alpha1.Authentication, wlpClientID string, wlpClientSecret string, currentConfigMap *corev1.ConfigMap, needToRequeue *bool) (err error) {

	var isOSEnv bool
	var domainName string
	var newConfigMap *corev1.ConfigMap

	configMapList := []string{"platform-auth-idp", "registration-script", "oauth-client-map", "registration-json"}
	functionList := []func(*operatorv1alpha1.Authentication, *runtime.Scheme) *corev1.ConfigMap{r.authIdpConfigMap, registrationScriptConfigMap}

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)

	// Check cluster type if CNCF or OCP
	globalConfigMapName := pkgCommon.GlobalConfigMapName
	globalConfigMap := &corev1.ConfigMap{}
	reqLogger.Info("Query global cm", "Configmap.Namespace", instance.Namespace, "ConfigMap.Name", globalConfigMapName)
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: globalConfigMapName, Namespace: instance.Namespace}, globalConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Error(err, "The configmap ", globalConfigMapName, " is not created yet")
			return
		}
		reqLogger.Error(err, "Failed to get ConfigMap", globalConfigMapName)
		return
	}

	pkgCommon.GetClusterType(context.Background(), pkgCommon.GlobalConfigMapName)

	if r.RunningOnCNCFCluster() {
		isOSEnv = false
		reqLogger.Info("Checked cluster type", "Configmap.Namespace", instance.Namespace, "ConfigMap.Name", globalConfigMapName, "clusterType", r.clusterType)
		domainName = globalConfigMap.Data["domain_name"]
		reqLogger.Info("Reading domainName from global cm", "Configmap.Namespace", instance.Namespace, "ConfigMap.Name", globalConfigMapName, "domainName", domainName)
	}

	// Reconcile ibmcloud-cluster-info configmap if not created already
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: instance.Namespace}, currentConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Configmap is not found ", "Configmap.Namespace", instance.Namespace, "ConfigMap.Name", "ibmcloud-cluster-info")
			reqLogger.Info("Going to create new ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", "ibmcloud-cluster-info")
			newConfigMap = r.ibmcloudClusterInfoConfigMap(r.client, instance, r.RunningOnOpenShiftCluster(), domainName, r.scheme)
			err = r.client.Create(context.TODO(), newConfigMap)
			if err != nil {
				reqLogger.Error(err, "Failed to create new ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", "ibmcloud-cluster-info")
				return
			} else {
				reqLogger.Info("Successfully created ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", "ibmcloud-cluster-info")
			}
		} else {
			reqLogger.Error(err, "Failed to get the ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", "ibmcloud-cluster-info")
		}
	} else {
		labels := currentConfigMap.Labels
		ownerRefs := currentConfigMap.OwnerReferences
		var ownRef string
		for _, ownRefs := range ownerRefs {
			ownRef = ownRefs.Kind
		}

		if labels != nil {
			value, ok := labels["app"]
			if ok && value == "auth-idp" && ownRef == "Authentication" {
				reqLogger.Info("ibmcloud-cluster-info Configmap is already created by IM operator", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", "ibmcloud-cluster-info")
			} else if ok && value == "management-ingress" && ownRef == "ManagementIngress" {
				reqLogger.Info("Configmap is already created by managementingress , IM installation may not proceed further until the configmap is removed", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", "ibmcloud-cluster-info")
				*needToRequeue = true
				return
			} else {
				reqLogger.Info("Can't determine the configmap ownership , IM installation may not proceed further until the configmap is removed", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", "ibmcloud-cluster-info")
				*needToRequeue = true
				return
			}
		}
	}

	// Public Cloud to be checked from ibmcloud-cluster-info
	isPublicCloud := isPublicCloud(r.client, instance.Namespace, "ibmcloud-cluster-info")

	//icpConsoleURL , icpProxyURL to be fetched from ibmcloud-cluster-info
	proxyConfigMapName := "ibmcloud-cluster-info"
	proxyConfigMap := &corev1.ConfigMap{}
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: proxyConfigMapName, Namespace: instance.Namespace}, proxyConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Error(err, "The configmap ", proxyConfigMapName, " is not created yet")
			return
		}
		reqLogger.Error(err, "Failed to get ConfigMap", proxyConfigMapName)
		*needToRequeue = true
		err = nil
		return
	}
	icpProxyURL, ok := proxyConfigMap.Data["proxy_address"]
	if !ok {
		reqLogger.Error(nil, "The configmap", proxyConfigMapName, "doesn't contain proxy address")
		*needToRequeue = true
		return
	}
	icpConsoleURL, ok := proxyConfigMap.Data["cluster_address"]

	if !ok {
		reqLogger.Error(nil, "The configmap", proxyConfigMapName, "doesn't contain cluster_address address")
		*needToRequeue = true
		return
	}

	// Creation the default configmaps
	for index, configMap := range configMapList {
		err = r.client.Get(context.TODO(), types.NamespacedName{Name: configMap, Namespace: instance.Namespace}, currentConfigMap)
		if err != nil {
			if errors.IsNotFound(err) {
				// Define a new ConfigMap
				if configMapList[index] == "registration-json" {
					newConfigMap = registrationJsonConfigMap(instance, wlpClientID, wlpClientSecret, icpConsoleURL, r.scheme)
				} else if configMapList[index] == "oauth-client-map" {
					newConfigMap = oauthClientConfigMap(instance, icpConsoleURL, icpProxyURL, r.scheme)
				} else {
					newConfigMap = functionList[index](instance, r.scheme)
					if configMapList[index] == "platform-auth-idp" {
						if instance.Spec.Config.ROKSEnabled && instance.Spec.Config.ROKSURL == "https://roks.domain.name:443" { //we enable it by default
							reqLogger.Info("Create platform-auth-idp Configmap roks settings", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
							issuer, err := readROKSURL(instance)
							if err != nil {
								reqLogger.Error(err, "Failed to get issuer URL", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", configMap)
								return err
							}
							newConfigMap.Data["ROKS_ENABLED"] = "true"
							newConfigMap.Data["ROKS_URL"] = issuer
							if instance.Spec.Config.ROKSUserPrefix == "changeme" { //we change it to empty prefix, that's the new default in 3.5
								if isPublicCloud {
									newConfigMap.Data["ROKS_USER_PREFIX"] = "IAM#"
								} else {
									newConfigMap.Data["ROKS_USER_PREFIX"] = ""
								}
							} else { // user specifies prefix but does not specify roksEnabled and roksURL we take the user provided prefix
								newConfigMap.Data["ROKS_USER_PREFIX"] = instance.Spec.Config.ROKSUserPrefix
							}
						} else {
							reqLogger.Info("Honor end user's setting", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
							//if user does not specify the prefix, we set it to IAM# to be consistent with previous release
							if instance.Spec.Config.ROKSEnabled && instance.Spec.Config.ROKSURL != "https://roks.domain.name:443" && instance.Spec.Config.ROKSUserPrefix == "changeme" {
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
						if instance.Spec.Config.ROKSEnabled && instance.Spec.Config.ROKSURL != "https://roks.domain.name:443" && instance.Spec.Config.ROKSUserPrefix == "changeme" {
							newConfigMap.Data["ROKS_USER_PREFIX"] = "IAM#"
						}
					}
				}
				reqLogger.Info("Creating a new ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", configMap)
				err = r.client.Create(context.TODO(), newConfigMap)
				if err != nil {
					reqLogger.Error(err, "Failed to create new ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", configMap)
					return
				}
				// ConfigMap created successfully - return and requeue
				*needToRequeue = true
			} else {
				reqLogger.Error(err, "Failed to get ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", configMap)
				return
			}
		} else {
			// @posriniv - find a more efficient solution
			if configMapList[index] == "platform-auth-idp" {
				cmUpdateRequired := false
				if _, keyExists := currentConfigMap.Data["LDAP_RECURSIVE_SEARCH"]; !keyExists {
					reqLogger.Info("Updating an existing Configmap", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					newConfigMap = functionList[index](instance, r.scheme)
					currentConfigMap.Data["LDAP_RECURSIVE_SEARCH"] = newConfigMap.Data["LDAP_RECURSIVE_SEARCH"]
					cmUpdateRequired = true
				}
				if _, keyExists := currentConfigMap.Data["CLAIMS_SUPPORTED"]; !keyExists {
					reqLogger.Info("Updating an existing Configmap", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					newConfigMap = functionList[index](instance, r.scheme)
					currentConfigMap.Data["CLAIMS_SUPPORTED"] = newConfigMap.Data["CLAIMS_SUPPORTED"]
					currentConfigMap.Data["CLAIMS_MAP"] = newConfigMap.Data["CLAIMS_MAP"]
					currentConfigMap.Data["SCOPE_CLAIM"] = newConfigMap.Data["SCOPE_CLAIM"]
					currentConfigMap.Data["BOOTSTRAP_USERID"] = newConfigMap.Data["BOOTSTRAP_USERID"]
					cmUpdateRequired = true
				}
				if _, keyExists := currentConfigMap.Data["PROVIDER_ISSUER_URL"]; !keyExists {
					reqLogger.Info("Updating an existing Configmap", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					newConfigMap = functionList[index](instance, r.scheme)
					currentConfigMap.Data["PROVIDER_ISSUER_URL"] = newConfigMap.Data["PROVIDER_ISSUER_URL"]
					cmUpdateRequired = true
				}
				if _, keyExists := currentConfigMap.Data["PREFERRED_LOGIN"]; !keyExists {
					reqLogger.Info("Updating an existing Configmap", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					newConfigMap = functionList[index](instance, r.scheme)
					currentConfigMap.Data["PREFERRED_LOGIN"] = newConfigMap.Data["PREFERRED_LOGIN"]
					cmUpdateRequired = true
				}
				if _, keyExists := currentConfigMap.Data["MONGO_READ_TIMEOUT"]; !keyExists {
					reqLogger.Info("Updating an existing Configmap", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					newConfigMap = functionList[index](instance, r.scheme)
					currentConfigMap.Data["MONGO_READ_TIMEOUT"] = newConfigMap.Data["MONGO_READ_TIMEOUT"]
					currentConfigMap.Data["MONGO_MAX_STALENESS"] = newConfigMap.Data["MONGO_MAX_STALENESS"]
					currentConfigMap.Data["MONGO_READ_PREFERENCE"] = newConfigMap.Data["MONGO_READ_PREFERENCE"]
					currentConfigMap.Data["MONGO_CONNECT_TIMEOUT"] = newConfigMap.Data["MONGO_CONNECT_TIMEOUT"]
					currentConfigMap.Data["MONGO_SELECTION_TIMEOUT"] = newConfigMap.Data["MONGO_SELECTION_TIMEOUT"]
					currentConfigMap.Data["MONGO_WAIT_TIME"] = newConfigMap.Data["MONGO_WAIT_TIME"]
					currentConfigMap.Data["MONGO_POOL_MIN_SIZE"] = newConfigMap.Data["MONGO_POOL_MIN_SIZE"]
					currentConfigMap.Data["MONGO_POOL_MAX_SIZE"] = newConfigMap.Data["MONGO_POOL_MAX_SIZE"]
					cmUpdateRequired = true
				}
				if _, keyExists := currentConfigMap.Data["OS_TOKEN_LENGTH"]; keyExists {
					if currentConfigMap.Data["OS_TOKEN_LENGTH"] == "45" {
						newConfigMap = functionList[index](instance, r.scheme)
						reqLogger.Info("Updating an existing Configmap", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
						reqLogger.Info("Updating OS token length", "New length is ", newConfigMap.Data["OS_TOKEN_LENGTH"])
						currentConfigMap.Data["OS_TOKEN_LENGTH"] = newConfigMap.Data["OS_TOKEN_LENGTH"]
						cmUpdateRequired = true
					}
				}
				if _, keyExists := currentConfigMap.Data["SCIM_LDAP_ATTRIBUTES_MAPPING"]; !keyExists {
					reqLogger.Info("Updating an existing Configmap to add new SCIM variables", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					newConfigMap = functionList[index](instance, r.scheme)
					currentConfigMap.Data["SCIM_LDAP_ATTRIBUTES_MAPPING"] = newConfigMap.Data["SCIM_LDAP_ATTRIBUTES_MAPPING"]
					currentConfigMap.Data["SCIM_LDAP_SEARCH_SIZE_LIMIT"] = newConfigMap.Data["SCIM_LDAP_SEARCH_SIZE_LIMIT"]
					currentConfigMap.Data["SCIM_LDAP_SEARCH_TIME_LIMIT"] = newConfigMap.Data["SCIM_LDAP_SEARCH_TIME_LIMIT"]
					currentConfigMap.Data["SCIM_ASYNC_PARALLEL_LIMIT"] = newConfigMap.Data["SCIM_ASYNC_PARALLEL_LIMIT"]
					currentConfigMap.Data["SCIM_GET_DISPLAY_FOR_GROUP_USERS"] = newConfigMap.Data["SCIM_GET_DISPLAY_FOR_GROUP_USERS"]
					cmUpdateRequired = true
				}
				if _, keyExists := currentConfigMap.Data["SCIM_AUTH_CACHE_MAX_SIZE"]; !keyExists {
					reqLogger.Info("Updating an existing Configmap to add new SCIM variables", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					newConfigMap = functionList[index](instance, r.scheme)
					currentConfigMap.Data["SCIM_AUTH_CACHE_MAX_SIZE"] = newConfigMap.Data["SCIM_AUTH_CACHE_MAX_SIZE"]
					cmUpdateRequired = true
				}
				if _, keyExists := currentConfigMap.Data["SCIM_AUTH_CACHE_TTL_VALUE"]; !keyExists {
					reqLogger.Info("Updating an existing Configmap to add new SCIM variables", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					newConfigMap = functionList[index](instance, r.scheme)
					currentConfigMap.Data["SCIM_AUTH_CACHE_TTL_VALUE"] = newConfigMap.Data["SCIM_AUTH_CACHE_TTL_VALUE"]
					cmUpdateRequired = true
				}
				if _, keyExists := currentConfigMap.Data["AUTH_SVC_LDAP_CONFIG_TIMEOUT"]; !keyExists {
					reqLogger.Info("Updating an existing Configmap to add new variable for auth-service LDAP configuration timeout", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					newConfigMap = functionList[index](instance, r.scheme)
					currentConfigMap.Data["AUTH_SVC_LDAP_CONFIG_TIMEOUT"] = newConfigMap.Data["AUTH_SVC_LDAP_CONFIG_TIMEOUT"]
					cmUpdateRequired = true
				}
				if _, keyExists := currentConfigMap.Data["IBM_CLOUD_SAAS"]; !keyExists {
					reqLogger.Info("Updating an existing Configmap", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					newConfigMap = functionList[index](instance, r.scheme)
					currentConfigMap.Data["IBM_CLOUD_SAAS"] = newConfigMap.Data["IBM_CLOUD_SAAS"]
					currentConfigMap.Data["SAAS_CLIENT_REDIRECT_URL"] = newConfigMap.Data["SAAS_CLIENT_REDIRECT_URL"]
					cmUpdateRequired = true
				}
				if _, keyExists := currentConfigMap.Data["ATTR_MAPPING_FROM_CONFIG"]; !keyExists {
					reqLogger.Info("Updating an existing Configmap to add new variable for attribute mapping resource", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					newConfigMap = functionList[index](instance, r.scheme)
					currentConfigMap.Data["ATTR_MAPPING_FROM_CONFIG"] = newConfigMap.Data["ATTR_MAPPING_FROM_CONFIG"]
					cmUpdateRequired = true
				}

				_, keyExists := currentConfigMap.Data["IS_OPENSHIFT_ENV"]
				if keyExists {
					reqLogger.Info("Current configmap", "Current Value", currentConfigMap.Data["IS_OPENSHIFT_ENV"])
					if currentConfigMap.Data["IS_OPENSHIFT_ENV"] != strconv.FormatBool(r.RunningOnOpenShiftCluster()) {
						currentConfigMap.Data["IS_OPENSHIFT_ENV"] = strconv.FormatBool(r.RunningOnOpenShiftCluster())
					}
				} else {
					currentConfigMap.Data["IS_OPENSHIFT_ENV"] = strconv.FormatBool(r.RunningOnOpenShiftCluster())
				}

				// This code would take care updating cp2 specific values into cp3 format
				idmgmtSVC, keyExists := currentConfigMap.Data["IDENTITY_MGMT_URL"]
				if keyExists && strings.Contains(idmgmtSVC, "127.0.0.1") {
					reqLogger.Info("Upgrade check : IDENTITY_MGMT_URL entry would be upgraded to CP3 format ", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					currentConfigMap.Data["IDENTITY_MGMT_URL"] = "https://platform-identity-management:4500"
					cmUpdateRequired = true
				}

				authSVC, keyExists := currentConfigMap.Data["BASE_OIDC_URL"]
				if keyExists && strings.Contains(authSVC, "127.0.0.1") {
					reqLogger.Info("Upgrade check : BASE_OIDC_URL entry would be upgraded to CP3 format ", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					currentConfigMap.Data["BASE_OIDC_URL"] = "https://platform-auth-service:9443/oidc/endpoint/OP"
					cmUpdateRequired = true
				}

				authdirSVC, keyExists := currentConfigMap.Data["IDENTITY_AUTH_DIRECTORY_URL"]
				if keyExists && strings.Contains(authdirSVC, "127.0.0.1") {
					reqLogger.Info("Upgrade check : IDENTITY_AUTH_DIRECTORY_URL entry would be upgraded to CP3 format ", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					currentConfigMap.Data["IDENTITY_AUTH_DIRECTORY_URL"] = "https://platform-auth-service:3100"
					cmUpdateRequired = true
				}

				idproviderSVC, keyExists := currentConfigMap.Data["IDENTITY_PROVIDER_URL"]
				if keyExists && strings.Contains(idproviderSVC, "127.0.0.1") {
					reqLogger.Info("Upgrade check : IDENTITY_PROVIDER_URL entry would be upgraded to CP3 format ", "Configmap.Namespace", currentConfigMap.Namespace, "ConfigMap.Name", currentConfigMap.Name)
					currentConfigMap.Data["IDENTITY_PROVIDER_URL"] = "https://platform-identity-provider:4300"
					cmUpdateRequired = true
				}

				cmUpdateRequired = true

				if cmUpdateRequired {
					err = r.client.Update(context.TODO(), currentConfigMap)
					if err != nil {
						reqLogger.Error(err, "Failed to update an existing Configmap", "Configmap.Namespace", currentConfigMap.Namespace, "Configmap.Name", currentConfigMap.Name)
						return
					}
				}
			}
		}

	}

	return nil

}

func (r *ReconcileAuthentication) authIdpConfigMap(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *corev1.ConfigMap {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	isPublicCloud := isPublicCloud(r.client, instance.Namespace, "ibmcloud-cluster-info")
	bootStrapUserId := instance.Spec.Config.BootstrapUserId
	roksUserPrefix := instance.Spec.Config.ROKSUserPrefix
	if len(bootStrapUserId) > 0 && strings.EqualFold(bootStrapUserId, "kubeadmin") && isPublicCloud {
		bootStrapUserId = ""
	}
	if isPublicCloud {
		roksUserPrefix = "IAM#"
	}
	newConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-auth-idp",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
		},
		Data: map[string]string{
			"BASE_AUTH_URL":                      "/v1",
			"BASE_OIDC_URL":                      "https://platform-auth-service:9443/oidc/endpoint/OP",
			"CLUSTER_NAME":                       instance.Spec.Config.ClusterName,
			"HTTP_ONLY":                          "false",
			"IDENTITY_AUTH_DIRECTORY_URL":        "https://platform-auth-service:3100",
			"IDENTITY_PROVIDER_URL":              "https://platform-identity-provider:4300",
			"IDENTITY_MGMT_URL":                  "https://platform-identity-management:4500",
			"MASTER_HOST":                        instance.Spec.Config.ClusterCADomain,
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
			"OIDC_ISSUER_URL":                    instance.Spec.Config.OIDCIssuerURL,
			"PDP_REDIS_CACHE_DEFAULT_TTL":        "600",
			"FIPS_ENABLED":                       strconv.FormatBool(instance.Spec.Config.FIPSEnabled),
			"NONCE_ENABLED":                      strconv.FormatBool(instance.Spec.Config.NONCEEnabled),
			"ROKS_ENABLED":                       strconv.FormatBool(instance.Spec.Config.ROKSEnabled),
			"IBM_CLOUD_SAAS":                     strconv.FormatBool(instance.Spec.Config.IBMCloudSaas),
			"ATTR_MAPPING_FROM_CONFIG":           strconv.FormatBool(instance.Spec.Config.AttrMappingFromConfig),
			"SAAS_CLIENT_REDIRECT_URL":           instance.Spec.Config.SaasClientRedirectUrl,
			"ROKS_URL":                           instance.Spec.Config.ROKSURL,
			"ROKS_USER_PREFIX":                   roksUserPrefix,
			"CLAIMS_SUPPORTED":                   instance.Spec.Config.ClaimsSupported,
			"CLAIMS_MAP":                         instance.Spec.Config.ClaimsMap,
			"SCOPE_CLAIM":                        instance.Spec.Config.ScopeClaim,
			"BOOTSTRAP_USERID":                   bootStrapUserId,
			"PROVIDER_ISSUER_URL":                instance.Spec.Config.ProviderIssuerURL,
			"PREFERRED_LOGIN":                    instance.Spec.Config.PreferredLogin,
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
			"LDAP_SEARCH_TIME_LIMIT":             "5",
			"LDAP_SEARCH_CN_ATTR_ONLY":           "false",
			"LDAP_SEARCH_ID_ATTR_ONLY":           "false",
			"IBMID_CLIENT_ID":                    "d3c8d1cf59a77cf73df35b073dfc1dc8",
			"IBMID_CLIENT_ISSUER":                "idaas.iam.ibm.com",
			"IBMID_PROFILE_URL":                  "https://w3-dev.api.ibm.com/profilemgmt/test/ibmidprofileait/v2/users",
			"IBMID_PROFILE_CLIENT_ID":            "1c36586c-cf48-4bce-9b9b-1a0480cc798b",
			"IBMID_PROFILE_FIELDS":               "displayName,name,emails",
			"SAML_NAMEID_FORMAT":                 "unspecified",
			"MONGO_READ_TIMEOUT":                 "40000",
			"MONGO_READ_PREFERENCE":              "primaryPreferred",
			"MONGO_CONNECT_TIMEOUT":              "30000",
			"MONGO_SELECTION_TIMEOUT":            "30000",
			"MONGO_WAIT_TIME":                    "20000",
			"MONGO_POOL_MIN_SIZE":                "5",
			"MONGO_POOL_MAX_SIZE":                "15",
			"MONGO_MAX_STALENESS":                "90",
			"SCIM_LDAP_SEARCH_SIZE_LIMIT":        "4500",
			"SCIM_LDAP_SEARCH_TIME_LIMIT":        "10",
			"SCIM_ASYNC_PARALLEL_LIMIT":          "100",
			"SCIM_GET_DISPLAY_FOR_GROUP_USERS":   "true",
			"SCIM_AUTH_CACHE_MAX_SIZE":           "1000",
			"SCIM_AUTH_CACHE_TTL_VALUE":          "60",
			"SCIM_LDAP_ATTRIBUTES_MAPPING":       scimLdapAttributesMapping,
		},
	}

	// Set Authentication instance as the owner and controller of the ConfigMap
	err := controllerutil.SetControllerReference(instance, newConfigMap, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
		return nil
	}
	return newConfigMap
}

func registrationJsonConfigMap(instance *operatorv1alpha1.Authentication, wlpClientID string, wlpClientSecret string, icpConsoleURL string, scheme *runtime.Scheme) *corev1.ConfigMap {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	tempRegistrationJson := registrationJson
	tempRegistrationJson = strings.ReplaceAll(tempRegistrationJson, "WLP_CLIENT_ID", wlpClientID)
	tempRegistrationJson = strings.ReplaceAll(tempRegistrationJson, "WLP_CLIENT_SECRET", wlpClientSecret)
	tempRegistrationJson = strings.ReplaceAll(tempRegistrationJson, "ICP_CONSOLE_URL", icpConsoleURL)

	//Logic to update registrationJson in constants.go based on icpConsoleURL has port 443 #55171
	//If icpConsoleURL has 443 in url (example : "cp-console.apps.tamil-dev.cp.fyre.ibm.com:443" need to update redirect url as below
	// "https://cp-console.apps.tamil-dev.cp.fyre.ibm.com/auth/liberty/callback","https://cp-console.apps.tamil-dev.cp.fyre.ibm.com:443/auth/liberty/callback"
	//else "https://cp-console.apps.tamil-dev.cp.fyre.ibm.com/auth/liberty/callback"

	var icpConsoleURLFinal string
	const apiRegistrationPath = "/auth/liberty/callback"
	reqLogger.Info("ICP console url for registrationJsonConfigMap ", icpConsoleURL)
	parseConsoleURL := strings.Split(icpConsoleURL, ":")
	if len(parseConsoleURL) > 1 {
		if parseConsoleURL[1] == "443" {
			icpConsoleURLFinal = "\"https://" + parseConsoleURL[0] + apiRegistrationPath + "\",\"https://" + icpConsoleURL + apiRegistrationPath + "\""
		} else {
			icpConsoleURLFinal = "\"https://" + icpConsoleURL + apiRegistrationPath + "\""
		}
	} else {
		icpConsoleURLFinal = "\"https://" + parseConsoleURL[0] + apiRegistrationPath + "\""
	}
	tempRegistrationJson = strings.ReplaceAll(tempRegistrationJson, "ICP_REGISTRATION_CONSOLE_URL", icpConsoleURLFinal)
	reqLogger.Info("Updated ICP console redirect url for registrationJson  ", icpConsoleURLFinal)
	newConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "registration-json",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
		},
		Data: map[string]string{
			"platform-oidc-registration.json": tempRegistrationJson,
		},
	}

	// Set Authentication instance as the owner and controller of the ConfigMap
	err := controllerutil.SetControllerReference(instance, newConfigMap, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
		return nil
	}
	return newConfigMap
}

func registrationScriptConfigMap(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *corev1.ConfigMap {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "registration-script",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
		},
		Data: map[string]string{
			"register-client.sh": registerClientScript,
		},
	}

	// Set Authentication instance as the owner and controller of the ConfigMap
	err := controllerutil.SetControllerReference(instance, newConfigMap, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
		return nil
	}
	return newConfigMap

}

func oauthClientConfigMap(instance *operatorv1alpha1.Authentication, icpConsoleURL string, icpProxyURL string, scheme *runtime.Scheme) *corev1.ConfigMap {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oauth-client-map",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
		},
		Data: map[string]string{
			"MASTER_IP":         icpConsoleURL,
			"PROXY_IP":          icpProxyURL,
			"CLUSTER_CA_DOMAIN": icpConsoleURL,
			"CLUSTER_NAME":      instance.Spec.Config.ClusterName,
		},
	}

	// Set Authentication instance as the owner and controller of the ConfigMap
	err := controllerutil.SetControllerReference(instance, newConfigMap, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
		return nil
	}
	return newConfigMap

}
func (r *ReconcileAuthentication) ibmcloudClusterInfoConfigMap(client client.Client, instance *operatorv1alpha1.Authentication, isOSEnv bool, domainName string, scheme *runtime.Scheme) *corev1.ConfigMap {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)

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

		ClusterAddress := strings.Join([]string{"cp-console", domainName}, ".")
		// to be checked for CNCF
		ep := "https://icp-management-ingress" + "." + instance.Namespace + ".svc:443"

		newConfigMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ibmcloud-cluster-info",
				Namespace: instance.Namespace,
				Labels:    map[string]string{"app": "auth-idp"},
			},
			Data: map[string]string{
				ClusterAddr:    ClusterAddress,
				ClusterEP:      ep,
				RouteHTTPPort:  rhttpPort,
				RouteHTTPSPort: rhttpsPort,
				ClusterName:    cname,
				ProxyAddress:   ClusterAddress,
				ProviderSVC:    "https://platform-identity-provider" + "." + instance.Namespace + ".svc:4300",
				IDMgmtSVC:      "https://platform-identity-management" + "." + instance.Namespace + ".svc:4500",
			},
		}

		// Set Authentication instance as the owner and controller of the ConfigMap
		err := controllerutil.SetControllerReference(instance, newConfigMap, scheme)
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
		clusterClient, err := createOrGetClusterClient()

		if err != nil {
			reqLogger.Error(err, "Failure creating or getting cluster client")
		}

		reqLogger.Info("Going to READ openshift ingress cluster config")
		errGet := clusterClient.Get(context.TODO(), types.NamespacedName{Name: ingressConfigName, Namespace: "openshift-authentication"}, ingressConfig)

		if errGet == nil {
			reqLogger.Info("Successfully READ openshift ingress cluster config")
			appsDomain := ingressConfig.Spec.AppsDomain
			if len(appsDomain) > 0 {
				reqLogger.Info("appsDomain has been configured", "appsDomain.value", appsDomain)

				if instance.Spec.Config.OnPremMultipleDeploy {
					multipleInstanceRouteName := strings.Join([]string{"cp-console", instance.Namespace}, "-")
					DomainName = strings.Join([]string{multipleInstanceRouteName, appsDomain}, ".")
					multipleInstanceProxyRouteName := strings.Join([]string{"cp-proxy", instance.Namespace}, "-")
					ProxyDomainName = strings.Join([]string{multipleInstanceProxyRouteName, appsDomain}, ".")
				} else {
					DomainName = strings.Join([]string{"cp-console", appsDomain}, ".")
					ProxyDomainName = strings.Join([]string{"cp-proxy", appsDomain}, ".")
				}
			} else {
				ingressDomain := ingressConfig.Spec.Domain
				reqLogger.Info("appsDomain is not configured , going to fetch default domain", "ingressDomain.value", ingressDomain)
				if instance.Spec.Config.OnPremMultipleDeploy {
					multipleInstanceRouteName := strings.Join([]string{"cp-console", instance.Namespace}, "-")
					DomainName = strings.Join([]string{multipleInstanceRouteName, ingressDomain}, ".")
					multipleInstanceProxyRouteName := strings.Join([]string{"cp-proxy", instance.Namespace}, "-")
					ProxyDomainName = strings.Join([]string{multipleInstanceProxyRouteName, ingressDomain}, ".")
				} else {
					DomainName = strings.Join([]string{"cp-console", ingressDomain}, ".")
					ProxyDomainName = strings.Join([]string{"cp-proxy", ingressDomain}, ".")
				}
			}
		} else {
			if !errors.IsNotFound(errGet) {
				reqLogger.Error(errGet, "Failed to READ openshift ingress cluster config")
			}
		}

		// get clusterApiServer Details cm console-config from openshift-console ns
		OSconsoleConfigMap := &corev1.ConfigMap{}

		err = clusterClient.Get(context.TODO(), types.NamespacedName{Name: "console-config", Namespace: "openshift-console"}, OSconsoleConfigMap)

		if err != nil {
			reqLogger.Error(err, "Failed to get console-config configmap from  openshift-console namespace")
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
				Name:      "ibmcloud-cluster-info",
				Namespace: instance.Namespace,
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
				ProviderSVC:          "https://platform-identity-provider" + "." + instance.Namespace + ".svc:4300",
				IDMgmtSVC:            "https://platform-identity-management" + "." + instance.Namespace + ".svc:4500",
			},
		}

		// Set Authentication instance as the owner and controller of the ConfigMap
		errset := controllerutil.SetControllerReference(instance, newConfigMap, scheme)

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
	scheme                      = runtime.NewScheme()
	ConfigMapSchemeGroupVersion = schema.GroupVersion{Group: "", Version: "v1"}
	ConfigSchemeGroupVersion    = schema.GroupVersion{Group: "config.openshift.io", Version: "v1"}
)

func createOrGetClusterClient() (client.Client, error) {
	// return if cluster client already exists
	if clusterClient != nil {
		return clusterClient, nil
	}
	// get a config to talk to the apiserver
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, err
	}

	scheme.AddKnownTypes(ConfigSchemeGroupVersion, &osconfigv1.Ingress{}, &osconfigv1.IngressList{})
	scheme.AddKnownTypes(ConfigMapSchemeGroupVersion, &corev1.ConfigMap{}, &corev1.ConfigMapList{})

	clusterClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	return clusterClient, nil
}

// Check if hosted on IBM Cloud
func isPublicCloud(client client.Client, namespace string, configMap string) bool {
	currentConfigMap := &corev1.ConfigMap{}
	err := client.Get(context.TODO(), types.NamespacedName{Name: configMap, Namespace: namespace}, currentConfigMap)
	if err != nil {
		log.Info("Error getting configmap", configMap)
		return false
	} else if err == nil {
		host := currentConfigMap.Data["cluster_kube_apiserver_host"]
		return strings.HasSuffix(host, "cloud.ibm.com")
	}
	return false
}

func readROKSURL(instance *operatorv1alpha1.Authentication) (string, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	wellknownURL := "https://kubernetes.default:443/.well-known/oauth-authorization-server"
	tokenFile := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caCert, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		reqLogger.Error(err, "Failed to read ca cert", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name")
		return "", err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	content, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		reqLogger.Error(err, "Failed to read default token", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name")
		return "", err
	}
	token := string(content)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caCertPool}}
	req, err := http.NewRequest("GET", wellknownURL, nil)
	if err != nil {
		reqLogger.Error(err, "Failed to get well known URL", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name")
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	client := &http.Client{Transport: transport}
	response, err := client.Do(req)

	if err != nil {
		reqLogger.Error(err, "Failed to get OpenShift server URL", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name")
		return "", err
	}
	var issuer string
	if response.Status == "200 OK" {
		defer response.Body.Close()
		body, err1 := ioutil.ReadAll(response.Body)
		if err1 != nil {
			reqLogger.Error(err, "Failed to readAll", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name")
			return "", err1
		}
		var result map[string]interface{}
		err = json.Unmarshal(body, &result)
		if err != nil {
			reqLogger.Error(err, "Failed to unmarshal", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name")
			return "", err
		}
		issuer = result["issuer"].(string)
	} else {
		reqLogger.Error(err, "Response status is not ok:"+response.Status, "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name")
		return "", err
	}
	return issuer, nil
}
