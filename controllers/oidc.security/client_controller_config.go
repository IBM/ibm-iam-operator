//
// Copyright 2022 IBM Corporation
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

package oidcsecurity

import (
	"context"
	"fmt"
	"strings"

	ctrlCommon "github.com/IBM/ibm-iam-operator/controllers/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AuthenticationConfig collects relevant Authentication configuration from Secrets and ConfigMaps and provides that
// information through a single interface
type AuthenticationConfig map[string][]byte

const (
	// identityManagementURLKey is the key in the AuthenticationConfig corresponding to the Identity Management service URL value
	identityManagementURLKey string = "IDENTITY_MGMT_URL"
	// identityProviderURLKey is the key in the AuthenticationConfig corresponding to the Identity Provider service URL value
	identityProviderURLKey string = "IDENTITY_PROVIDER_URL"
	// authServiceURL is the key in the AuthenticationConfig corresponding to the OIDC URL value
	authServiceURLKey string = "BASE_OIDC_URL"
	// rOKSEnabledKey is the key in the AuthenticationConfig corresponding to a boolean string value that enables or
	// disables the automatic creation of an Openshift OAuthClients (legacy)
	rOKSEnabledKey string = "ROKS_ENABLED"
	// defaultAdminUserKey is the key in the AuthenticationConfig corresponding to the default admin username for the IAM API
	defaultAdminUserKey string = "admin_username"
	// defaultAdminPasswordKey is the key in the AuthenticationConfig corresponding to the default admin password for the IAM API
	defaultAdminPasswordKey string = "admin_password"
	// oauthAdminPasswordKey is the key in the AuthenticationConfig corresponding to the password for the oauthAdmin
	// account
	oAuthAdminPasswordKey string = "OAUTH2_CLIENT_REGISTRATION_SECRET"
	// authenticationNsKey is the key in the AuthenticationConfig corresponding to the namespace that the
	// Authentication CR is installed in, a.k.a. the services namespace
	authenticationNsKey string = "authenticationNamespace"
)

// ConfigValueNotFoundError is returned when a specific key is not available in the AuthenticationConfig
type ConfigValueNotFoundError struct {
	Key string
}

func (e *ConfigValueNotFoundError) Error() string {
	return fmt.Sprintf("unable to retrieve value for key %q from config", e.Key)
}

func NewConfigValueNotFoundError(key string) (err error) {
	return &ConfigValueNotFoundError{Key: key}
}

var ConfigNotSetError error = fmt.Errorf("config is not set")

type InvalidResourceError struct {
	Kind      string
	Name      string
	Namespace string
	Reason    string
}

func (e *InvalidResourceError) Error() string {
	return fmt.Sprintf("%s %s in namespace %s is invalid: %s", e.Kind, e.Name, e.Namespace, e.Reason)
}

func NewInvalidResourceError(kind, name, namespace, reason string) (err error) {
	return &InvalidResourceError{
		Kind:      kind,
		Name:      name,
		Namespace: namespace,
		Reason:    reason,
	}
}

type CP2ServiceURLFormatError struct{}

func (e *CP2ServiceURLFormatError) Error() string {
	return "found ConfigMap service data with cp2 format : 127.0.0.1"
}

func NewCP2ServiceURLFormatError() (err error) {
	return &CP2ServiceURLFormatError{}
}

// getClusterDomainNameForServiceURL converts the provided URL string from just a Service name to "<service
// name>.<namespace>.svc"
func getClusterDomainNameForServiceURL(url string, namespace string) string {
	suffix := ".svc"
	splitByColons := strings.Split(url, ":")
	port := splitByColons[len(splitByColons)-1]
	everythingBeforePort := strings.Join(splitByColons[:len(splitByColons)-1], ":")
	return everythingBeforePort + "." + namespace + suffix + ":" + port
}

// ApplyConfigMap takes the key value pairs found in a ConfigMap's Data field and sets the same keys and values in the
// AuthenticationConfig. Produces an error if the ConfigMap had an empty Data field.
func (c AuthenticationConfig) ApplyConfigMap(configMap *corev1.ConfigMap, keysList ...string) (err error) {
	if configMap.Data != nil || len(configMap.Data) == 0 {
		if len(keysList) != 0 {
			for _, k := range keysList {
				cKey := strings.Join([]string{configMap.Name, k}, "_")
				if (k == authServiceURLKey || k == identityProviderURLKey || k == identityManagementURLKey) && !strings.Contains(configMap.Data[k], "127.0.0.1") {
					c[cKey] = []byte(getClusterDomainNameForServiceURL(configMap.Data[k], configMap.Namespace))
				} else if !strings.Contains(configMap.Data[k], "127.0.0.1") {
					c[cKey] = []byte(configMap.Data[k])
				} else {
					return NewCP2ServiceURLFormatError()
				}
			}
		} else {
			for k, v := range configMap.Data {
				cKey := strings.Join([]string{configMap.Name, k}, "_")
				if (k == authServiceURLKey || k == identityProviderURLKey || k == identityManagementURLKey) && !strings.Contains(configMap.Data[k], "127.0.0.1") {
					c[cKey] = []byte(getClusterDomainNameForServiceURL(v, configMap.Namespace))
				} else if !strings.Contains(configMap.Data[k], "127.0.0.1") {
					c[cKey] = []byte(v)
				} else {
					return NewCP2ServiceURLFormatError()
				}
			}
		}
		return
	}
	return NewInvalidResourceError("ConfigMap", configMap.Name, configMap.Namespace, "missing valid \"Data\" field")
}

// ApplySecret takes the key value pairs found in a Secret's Data field and sets the same keys and values in the
// AuthenticationConfig after converting the values into strings from []byte. Produces an error if the Secret had an
// empty Data field.
func (c AuthenticationConfig) ApplySecret(secret *corev1.Secret, keysList ...string) (err error) {
	if secret.Data != nil || len(secret.Data) == 0 {
		if len(keysList) != 0 {
			for _, k := range keysList {
				cKey := strings.Join([]string{secret.Name, k}, "_")
				c[cKey] = secret.Data[k][:]
			}
		} else {
			for k, v := range secret.Data {
				cKey := strings.Join([]string{secret.Name, k}, "_")
				c[cKey] = v[:]
			}
		}
		return
	}
	return NewInvalidResourceError("Secret", secret.Name, secret.Namespace, "missing valid \"Data\" field")
}

func (c AuthenticationConfig) ApplyAuthenticationNamespace(namespace string) {
	c[authenticationNsKey] = []byte(namespace)
}

// getConfigValue retrieves the value stored at the provided key from the AuthenticationConfig. Produces an error if
// the AuthenticationConfig is empty or if the key is not present.
func (c AuthenticationConfig) getConfigValue(key string) (value []byte, err error) {
	if len(c) == 0 {
		return nil, ConfigNotSetError
	}
	value, ok := c[key]
	if !ok {
		err = NewConfigValueNotFoundError(key)
	}
	return
}

// IsConfigured returns whether all mandatory config fields are set.
func (c AuthenticationConfig) IsConfigured() bool {
	if c == nil || len(c) == 0 {
		return false
	}
	if value, err := c.GetIdentityManagementURL(); value != "" && err != nil && strings.Contains(value, "127.0.0.1") {
		return false
	}
	if value, err := c.GetIdentityProviderURL(); value != "" && err != nil && strings.Contains(value, "127.0.0.1") {
		return false
	}
	if _, err := c.GetROKSEnabled(); err != nil {
		return false
	}
	if value, err := c.GetAuthServiceURL(); value != "" && err != nil && strings.Contains(value, "127.0.0.1") {
		return false
	}
	if value, err := c.GetDefaultAdminUser(); value != "" && err != nil {
		return false
	}
	if value, err := c.GetDefaultAdminPassword(); value != "" && err != nil {
		return false
	}
	if value, err := c.GetOAuthAdminPassword(); value != "" && err != nil {
		return false
	}
	return true
}

// GetDefaultAdminUser gets the default admin user for the IAM API from the ClientReconciler's AuthenticationConfig.
// Produces an error if the AuthenticationConfig is empty or if the key is not present.
func (c AuthenticationConfig) GetDefaultAdminUser() (value string, err error) {
	key := strings.Join([]string{PlatformAuthIDPCredentialsSecretName, defaultAdminUserKey}, "_")
	bvalue, err := c.getConfigValue(key)
	return string(bvalue), err
}

// GetDefaultAdminPassword gets the default admin password for the IAM API from the ClientReconciler's
// AuthenticationConfig. Produces an error if the AuthenticationConfig is empty or if the key is not present.
func (c AuthenticationConfig) GetDefaultAdminPassword() (value string, err error) {
	key := strings.Join([]string{PlatformAuthIDPCredentialsSecretName, defaultAdminPasswordKey}, "_")
	bvalue, err := c.getConfigValue(key)
	return string(bvalue), err
}

// GetOauthAdminPassword gets the password for the OAuth Provider oauthadmin account from the ClientReconciler's
// AuthenticationConfig. Produces an error if the AuthenticationConfig is empty or if the key is not present.
func (c AuthenticationConfig) GetOAuthAdminPassword() (value string, err error) {
	key := strings.Join([]string{PlatformOIDCCredentialsSecretName, oAuthAdminPasswordKey}, "_")
	bvalue, err := c.getConfigValue(key)
	return string(bvalue), err
}

// GetROKSEnabled gets from the AuthenticationConfig whether the controller is enabled to use OpenShift OAuthClients
// for OIDC Client authentication via legacy configuration; creates and manages OAuthClient objects with names that
// match OIDC Client's clientId field. Produces an error if the AuthenticationConfig is empty or if the key is not
// present.
func (c AuthenticationConfig) GetROKSEnabled() (value bool, err error) {
	key := strings.Join([]string{PlatformAuthIDPConfigMapName, rOKSEnabledKey}, "_")
	valueByte, err := c.getConfigValue(key)
	if string(valueByte) == "true" {
		return true, nil
	}
	return
}

// GetIdentityProviderURL gets the Identity Provider URL from the ClientReconciler's AuthenticationConfig. Produces an
// error if the AuthenticationConfig is empty or if the key is not present.
func (c AuthenticationConfig) GetIdentityProviderURL() (value string, err error) {
	key := strings.Join([]string{PlatformAuthIDPConfigMapName, identityProviderURLKey}, "_")
	bvalue, err := c.getConfigValue(key)
	return string(bvalue), err
}

// GetIdentityManagementURL gets the Identity Management URL from the ClientReconciler's AuthenticationConfig. Produces
// an error if the AuthenticationConfig is empty or if the key is not present.
func (c AuthenticationConfig) GetIdentityManagementURL() (value string, err error) {
	key := strings.Join([]string{PlatformAuthIDPConfigMapName, identityManagementURLKey}, "_")
	bvalue, err := c.getConfigValue(key)
	return string(bvalue), err
}

// GetAuthServiceURL gets the IAM Auth Service URL from the ClientReconciler's AuthenticationConfig. Produces an error
// if the AuthenticationConfig is empty or if the key is not present.
func (c AuthenticationConfig) GetAuthServiceURL() (value string, err error) {
	key := strings.Join([]string{PlatformAuthIDPConfigMapName, authServiceURLKey}, "_")
	bvalue, err := c.getConfigValue(key)
	return string(bvalue), err
}

// GetAuthenticationNamespace gets the namespace in which the Authentication CR (and, in turn, the rest of the shared
// services) are installed.
func (c AuthenticationConfig) GetAuthenticationNamespace() (value string, err error) {
	bvalue, err := c.getConfigValue(authenticationNsKey)
	return string(bvalue), err
}

func (c AuthenticationConfig) GetCSCATLSKey() (value []byte, err error) {
	key := strings.Join([]string{CSCACertificateSecretName, corev1.TLSCertKey}, "_")
	return c.getConfigValue(key)
}

func GetConfig(ctx context.Context, k8sClient *client.Client, config *AuthenticationConfig) (err error) {
	servicesNamespace, err := ctrlCommon.GetServicesNamespace(ctx, k8sClient)
	if err != nil {
		return fmt.Errorf("failed to get ConfigMap: %w", err)
	}
	config.ApplyAuthenticationNamespace(servicesNamespace)

	configMap := &corev1.ConfigMap{}
	err = (*k8sClient).Get(ctx, types.NamespacedName{Name: PlatformAuthIDPConfigMapName, Namespace: servicesNamespace}, configMap)
	if err != nil {
		return fmt.Errorf("client failed to GET ConfigMap: %w", err)
	}
	err = config.ApplyConfigMap(configMap, identityManagementURLKey, identityProviderURLKey, rOKSEnabledKey, authServiceURLKey)
	if err != nil {
		return fmt.Errorf("failed to configure: %w", err)
	}

	platformAuthIDPCredentialsSecret := &corev1.Secret{}
	err = (*k8sClient).Get(ctx, types.NamespacedName{Name: PlatformAuthIDPCredentialsSecretName, Namespace: servicesNamespace}, platformAuthIDPCredentialsSecret)
	if err != nil {
		return
	}
	err = config.ApplySecret(platformAuthIDPCredentialsSecret, defaultAdminUserKey, defaultAdminPasswordKey)
	if err != nil {
		return fmt.Errorf("failed to configure: %w", err)
	}

	platformOIDCCredentialsSecret := &corev1.Secret{}
	err = (*k8sClient).Get(ctx, types.NamespacedName{Name: PlatformOIDCCredentialsSecretName, Namespace: servicesNamespace}, platformOIDCCredentialsSecret)
	if err != nil {
		return
	}
	err = config.ApplySecret(platformOIDCCredentialsSecret, oAuthAdminPasswordKey)
	if err != nil {
		return fmt.Errorf("failed to configure: %w", err)
	}

	csCACertificateSecret := &corev1.Secret{}
	err = (*k8sClient).Get(ctx, types.NamespacedName{Name: CSCACertificateSecretName, Namespace: servicesNamespace}, csCACertificateSecret)
	if err != nil {
		return
	}
	err = config.ApplySecret(csCACertificateSecret, corev1.TLSCertKey)
	if err != nil {
		return fmt.Errorf("failed to configure: %w", err)
	}
	return
}
