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
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"strconv"
	"strings"
)

func (r *ReconcileAuthentication) handleConfigMap(instance *operatorv1alpha1.Authentication, wlpClientID string, wlpClientSecret string, currentConfigMap *corev1.ConfigMap, requeueResult *bool) error {

	configMapList := []string{"platform-auth-idp", "registration-script", "oauth-client-map", "registration-json"}

	functionList := []func(*operatorv1alpha1.Authentication, *runtime.Scheme) *corev1.ConfigMap{authIdpConfigMap, registrationScriptConfigMap, oauthClientConfigMap}

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error
	var newConfigMap *corev1.ConfigMap

	for index, configMap := range configMapList {
		err = r.client.Get(context.TODO(), types.NamespacedName{Name: configMap, Namespace: instance.Namespace}, currentConfigMap)
		if err != nil && errors.IsNotFound(err) {
			// Define a new ConfigMap
			if configMapList[index] == "registration-json" {
				newConfigMap = registrationJsonConfigMap(instance, wlpClientID, wlpClientSecret, r.scheme)
			} else {
				newConfigMap = functionList[index](instance, r.scheme)
			}
			reqLogger.Info("Creating a new ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", configMap)
			err = r.client.Create(context.TODO(), newConfigMap)
			if err != nil {
				reqLogger.Error(err, "Failed to create new ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", configMap)
				return err
			}
			// ConfigMap created successfully - return and requeue
			*requeueResult = true
		} else if err != nil {
			reqLogger.Error(err, "Failed to get ConfigMap")
			return err
		}

	}

	return nil

}

func authIdpConfigMap(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *corev1.ConfigMap {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-auth-idp",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
		},
		Data: map[string]string{
			"BASE_AUTH_URL":               "/v1",
			"BASE_OIDC_URL":               "https://127.0.0.1:9443/oidc/endpoint/OP",
			"CLUSTER_NAME":                instance.Spec.Config.ClusterName,
			"HTTP_ONLY":                   "false",
			"IDENTITY_AUTH_DIRECTORY_URL": "https://127.0.0.1:3100",
			"IDENTITY_PROVIDER_URL":       "https://127.0.0.1:4300",
			"IDENTITY_MGMT_URL":           "https://127.0.0.1:4500",
			"MASTER_HOST":                 instance.Spec.Config.ClusterCADomain,
			"NODE_ENV":                    "production",
			"AUDIT_ENABLED_IDPROVIDER":    "false",
			"AUDIT_ENABLED_IDMGMT":        "false",
			"AUDIT_DETAIL":                "false",
			"LOG_LEVEL_IDPROVIDER":        "info",
			"LOG_LEVEL_AUTHSVC":           "info",
			"LOG_LEVEL_IDMGMT":            "info",
			"LOG_LEVEL_MW":                "info",
			"IDTOKEN_LIFETIME":            "12h",
			"JOURNAL_PATH":                instance.Spec.AuditService.JournalPath,
			"SESSION_TIMEOUT":             "43200",
			"OIDC_ISSUER_URL":             instance.Spec.Config.OIDCIssuerURL,
			"logrotate-conf": "\n # rotate log files weekly\ndaily\n\n# use the syslog group by" +
				" default, since this is the owning group # of /var/log/syslog.\n#su root syslog\n\n#" +
				" keep 4 weeks worth of backlogs\nrotate 4\n\n# create new (empty) log files after" +
				" rotating old ones \ncreate\n\n# uncomment this if you want your log files compressed\n" +
				" #compress\n\n# packages drop log rotation information into this directory\n include" +
				" /etc/logrotate.d\n# no packages own wtmp, or btmp -- we'll rotate them here\n",
			"logrotate":                          "/var/log/audit/*.log {\n copytruncate\n  rotate 24\n  hourly\n  missingok\n  notifempty\n}",
			"PDP_REDIS_CACHE_DEFAULT_TTL":        "600",
			"FIPS_ENABLED":                       strconv.FormatBool(instance.Spec.Config.FIPSEnabled),
			"NONCE_ENABLED":                      strconv.FormatBool(instance.Spec.Config.NONCEEnabled),
			"ROKS_ENABLED":                       strconv.FormatBool(instance.Spec.Config.ROKSEnabled),
			"ROKS_URL":                           instance.Spec.Config.ROKSURL,
			"ROKS_USER_PREFIX":                   instance.Spec.Config.ROKSUserPrefix,
			"LIBERTY_TOKEN_LENGTH":               "1024",
			"OS_TOKEN_LENGTH":                    "45",
			"LIBERTY_DEBUG_ENABLED":              "false",
			"LOGJAM_DHKEYSIZE_2048_BITS_ENABLED": "true",
			"LDAP_RECURSIVE_SEARCH":              "true",
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

func registrationJsonConfigMap(instance *operatorv1alpha1.Authentication, wlpClientID string, wlpClientSecret string, scheme *runtime.Scheme) *corev1.ConfigMap {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	icpConsoleURL := os.Getenv("ICP_CONSOLE_URL")
	tempRegistrationJson := registrationJson
	tempRegistrationJson = strings.ReplaceAll(tempRegistrationJson, "WLP_CLIENT_ID", wlpClientID)
	tempRegistrationJson = strings.ReplaceAll(tempRegistrationJson, "WLP_CLIENT_SECRET", wlpClientSecret)
	tempRegistrationJson = strings.ReplaceAll(tempRegistrationJson, "ICP_CONSOLE_URL", icpConsoleURL)

	newConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "registration-json",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
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
			Labels:    map[string]string{"app": "auth-idp"},
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

func oauthClientConfigMap(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *corev1.ConfigMap {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	icpConsoleURL := os.Getenv("ICP_CONSOLE_URL")
	icpProxyURL := os.Getenv("ICP_PROXY_URL")
	newConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oauth-client-map",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
		},
		Data: map[string]string{
			"MASTER_IP": icpConsoleURL,
			"PROXY_IP": icpProxyURL,
			"CLUSTER_CA_DOMAIN": icpConsoleURL,
			"CLUSTER_NAME": instance.Spec.Config.ClusterName,
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