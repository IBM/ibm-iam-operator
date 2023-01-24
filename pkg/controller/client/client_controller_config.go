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

package client

import (
	"fmt"
	corev1 "k8s.io/api/core/v1"
)

// ClientControllerConfig maintains state used while reconciling OIDC Client objects
type ClientControllerConfig map[string]string

const (
  // identityManagementURLKey is the key in the ClientControllerConfig corresponding to the Identity Management service URL value
  identityManagementURLKey string = "IDENTITY_MGMT_URL"
  // identityProviderURLKey is the key in the ClientControllerConfig corresponding to the Identity Provider service URL value
  identityProviderURLKey string = "IDENTITY_PROVIDER_URL"
  // authServiceURL is the key in the ClientControllerConfig corresponding to the OIDC URL value
  authServiceURLKey string = "BASE_OIDC_URL"
  // rOKSEnabledKey is the key in the ClientControllerConfig corresponding to a boolean string value that enables or
  // disables the automatic creation of an Openshift OAuthClients (legacy)
  rOKSEnabledKey string = "ROKS_ENABLED"
  // osAuthEnabledKey is the key in the ClientControllerConfig corresponding to a boolean string value that enables or
  // disables OpenShift authentication using OAuthClients
  osAuthEnabledKey string = "OSAUTH_ENABLED"
  // defaultAdminUserKey is the key in the ClientControllerConfig corresponding to the default admin username for the IAM API
  defaultAdminUserKey string = "admin_username"
  // defaultAdminPasswordKey is the key in the ClientControllerConfig corresponding to the default admin password for the IAM API
  defaultAdminPasswordKey string = "admin_password"
  // oauthAdminPasswordKey is the key in the ClientControllerConfig corresponding to the password for the oauthAdmin
  // account
  oAuthAdminPasswordKey string = "OAUTH2_CLIENT_REGISTRATION_SECRET"
)

// ApplyConfigMap takes the key value pairs found in a ConfigMap's Data field and sets the same keys and values in the
// ClientControllerConfig. Produces an error if the ConfigMap had an empty Data field.
func (c ClientControllerConfig) ApplyConfigMap(configMap *corev1.ConfigMap, keysList ...string) (err error) {
  if configMap.Data != nil || len(configMap.Data) == 0 {
    if len(keysList) != 0 {
      for _, k := range keysList {
        c[k] = configMap.Data[k]
      }
    } else {
      for k, v := range configMap.Data {
        c[k] = v
      }
    }
    return
  }
  return fmt.Errorf("found ConfigMap had no \"Data\" field")
}

// ApplySecret takes the key value pairs found in a Secret's Data field and sets the same keys and values in the
// ClientControllerConfig after converting the values into strings from []byte. Produces an error if the Secret had an
// empty Data field.
func (c ClientControllerConfig) ApplySecret(secret *corev1.Secret, keysList ...string) (err error) {
  if secret.Data != nil || len(secret.Data) == 0 {
    if len(keysList) != 0 {
      for _, k := range keysList {
        c[k] = string(secret.Data[k][:])
      }
    } else {
      for k, v := range secret.Data {
        c[k] = string(v[:])
      }
    }
    return
  }
  return fmt.Errorf("found Secret had no \"Data\" field")
}

// IsConfigured returns whether all mandatory config fields are set.
func (r *ReconcileClient) IsConfigured() bool {
  if r.config == nil || len(r.config) == 0 {
    return false
  }
  if value, err := r.GetIdentityManagementURL(); value != "" && err != nil {
    return false
  }
  if value, err := r.GetIdentityProviderURL(); value != "" && err != nil {
    return false
  }
  if _, err := r.GetROKSEnabled(); err != nil {
    return false
  }
  if _, err := r.GetOSAuthEnabled(); err != nil {
    return false
  }
  if value, err := r.GetAuthServiceURL(); value != "" && err != nil {
    return false
  }
  if value, err := r.GetDefaultAdminUser(); value != "" && err != nil {
    return false
  }
  if value, err := r.GetDefaultAdminPassword(); value != "" && err != nil {
    return false
  }
  if value, err := r.GetOAuthAdminPassword(); value != "" && err != nil {
    return false
  }
  return true
}

// getConfigValue retrieves the value stored at the provided key from the ReconcileClient's config field. Produces an
// error if the ClientControllerConfig is empty or if the key is not present.
func (c ClientControllerConfig) getConfigValue(key string) (value string, err error) {
  if len(c) == 0 {
    return "", fmt.Errorf("config is not set")
  }
  value, ok := c[key]
  if !ok {
    err = fmt.Errorf("unable to retrieve value for key %q from config", key)
  }
  return
}

// GetDefaultAdminUser gets the default admin user for the IAM API from the ReconcileClient's ClientControllerConfig.
// Produces an error if the ClientControllerConfig is empty or if the key is not present.
func (r *ReconcileClient) GetDefaultAdminUser() (value string, err error) {
  value, err = r.config.getConfigValue(defaultAdminUserKey)
  return
}

// GetDefaultAdminPassword gets the default admin password for the IAM API from the ReconcileClient's
// ClientControllerConfig. Produces an error if the ClientControllerConfig is empty or if the key is not present.
func (r *ReconcileClient) GetDefaultAdminPassword() (value string, err error) {
  value, err = r.config.getConfigValue(defaultAdminPasswordKey)
  return
}

// GetOauthAdminPassword gets the password for the OAuth Provider oauthadmin account from the ReconcileClient's
// ClientControllerConfig. Produces an error if the ClientControllerConfig is empty or if the key is not present.
func (r *ReconcileClient) GetOAuthAdminPassword() (value string, err error) {
  value, err = r.config.getConfigValue(oAuthAdminPasswordKey)
  return
}

// GetROKSEnabled gets from the ClientControllerCOnfig whether the controller is enabled to use OpenShift OAuthClients
// for OIDC Client authentication via legacy configuration; creates and manages OAuthClient objects with names that
// match OIDC Client's clientId field. Produces an error if the ClientControllerConfig is empty or if the key is not
// present.
func (r *ReconcileClient) GetROKSEnabled() (value bool, err error) {
  valueStr, err := r.config.getConfigValue(rOKSEnabledKey)
  if valueStr == "true" {
    return true, nil
  }
  return
}

// GetOSAuthEnabled gets from the ClientControllerCOnfig whether the controller is enabled to use OpenShift OAuthClients
// for OIDC Client authentication; creates and manages OAuthClient objects with names that match OIDC Client's clientId
// field. Produces an error if the ClientControllerConfig is empty or if the key is not present.
func (r *ReconcileClient) GetOSAuthEnabled() (value bool, err error) {
  valueStr, err := r.config.getConfigValue(osAuthEnabledKey)
  if valueStr == "true" {
    return true, nil
  }
  return
}

// GetIdentityProviderURL gets the Identity Provider URL from the ReconcileClient's ClientControllerConfig. Produces an
// error if the ClientControllerConfig is empty or if the key is not present.
func (r *ReconcileClient) GetIdentityProviderURL() (value string, err error) {
  value, err = r.config.getConfigValue(identityProviderURLKey)
  return
}

// GetIdentityManagementURL gets the Identity Management URL from the ReconcileClient's ClientControllerConfig. Produces
// an error if the ClientControllerConfig is empty or if the key is not present.
func (r *ReconcileClient) GetIdentityManagementURL() (value string, err error) {
  value, err = r.config.getConfigValue(identityManagementURLKey)
  return
}

// GetAuthServiceURL gets the IAM Auth Service URL from the ReconcileClient's ClientControllerConfig. Produces an error
// if the ClientControllerConfig is empty or if the key is not present.
func (r *ReconcileClient) GetAuthServiceURL() (value string, err error) {
  value, err = r.config.getConfigValue(authServiceURLKey)
  return
}

