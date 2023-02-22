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

package client

import (
	"bytes"
	"context"

	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
	oidcv1 "github.com/IBM/ibm-iam-operator/pkg/apis/oidc/v1"
	regen "github.com/zach-klippenstein/goregen"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

type ClientCredentials struct {
	ClientID     string `json:"CLIENT_ID"`
	ClientSecret string `json:"CLIENT_SECRET"`
}

type OidcClientResponse struct {
	ClientIDIssuedAt        int           `json:"client_id_issued_at"`
	RegistrationClientURI   string        `json:"registration_client_uri"`
	ClientSecretExpiresAt   int           `json:"client_secret_expires_at"`
	TokenEndpointAuthMethod string        `json:"token_endpoint_auth_method"`
	Scope                   string        `json:"scope"`
	GrantTypes              []string      `json:"grant_types"`
	ResponseTypes           []string      `json:"response_types"`
	ApplicationType         string        `json:"application_type"`
	SubjectType             string        `json:"subject_type"`
	PostLogoutRedirectUris  []string      `json:"post_logout_redirect_uris"`
	PreauthorizedScope      string        `json:"preauthorized_scope"`
	IntrospectTokens        bool          `json:"introspect_tokens"`
	TrustedURIPrefixes      []string      `json:"trusted_uri_prefixes"`
	ResourceIds             []string      `json:"resource_ids"`
	FunctionalUserGroupIds  []string      `json:"functional_user_groupIds"`
  FunctionalUserID        string        `json:"functional_user_id"`
	AppPasswordAllowed      bool          `json:"appPasswordAllowed"`
	AppTokenAllowed         bool          `json:"appTokenAllowed"`
	ClientID                string        `json:"client_id"`
	ClientSecret            string        `json:"client_secret"`
	ClientName              string        `json:"client_name"`
	RedirectUris            []string      `json:"redirect_uris"`
	AllowRegexpRedirects    bool          `json:"allow_regexp_redirects"`
}

// ZenInstance represents the zen instance model (response from post, get)
type ZenInstance struct {
	ClientID       string `json:"clientId"`
	InstanceId     string `json:"instanceId"`
	ProductNameUrl string `json:"productNameUrl"`
	Namespace      string `json:"namespace"`
}

const (
	GetType    = "GET"
	PostType   = "POST"
	PutType    = "PUT"
	DeleteType = "DELETE"
)

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" // 52 possibilities
	letterIdxBits = 6                                                                // 6 bits to represent 64 possibilities / indexes
	letterIdxMask = 1<<letterIdxBits - 1                                             // All 1-bits, as many as letterIdxBits
)

// CreateClientRegistration registers a new OIDC Client on the OP using information provided in the provided Client CR.
func (r *ReconcileClient) CreateClientRegistration(ctx context.Context, client *oidcv1.Client, clientCreds *ClientCredentials) (response *http.Response, err error) {
  var url, identityProviderURL string
  identityProviderURL, err = r.GetIdentityProviderURL(client.Namespace)
  if err != nil {
    return
  }
  url = strings.Join([]string{identityProviderURL, "v1", "auth", "registration"}, "/")
	payload := r.generateClientRegistrationPayload(client, clientCreds)
	response, err = r.invokeClientRegistrationAPI(ctx, client, PostType, url, payload)
  if err == nil && response.Status != "201 Created" {
    err = NewOIDCClientError(response)
    return nil, err
  }
  return
}

// UpdateClientRegistration updates the OIDC Client registration represented by the Client CR to use the credentials
// stored in the provided Secret.
func (r *ReconcileClient) UpdateClientRegistration(ctx context.Context, client *oidcv1.Client, clientCreds *ClientCredentials) (response *http.Response, err error) {
  var url, identityProviderURL string
	payload := r.generateClientRegistrationPayload(client, clientCreds)
  identityProviderURL, err = r.GetIdentityProviderURL(client.Namespace)
  if err != nil {
    return
  }
  url = strings.Join([]string{identityProviderURL, "v1", "auth", "registration", clientCreds.ClientID}, "/")
	response, err = r.invokeClientRegistrationAPI(ctx, client, PutType, url, payload)
  if err == nil && response.Status != "200 OK" {
    return nil, NewOIDCClientError(response)
  }
  return
}

// DeleteClientRegistration deletes from the OP the OIDC Client registration represented by the Client CR.
func (r *ReconcileClient) DeleteClientRegistration(ctx context.Context, client *oidcv1.Client) (response *http.Response, err error) {
	clientId := client.Spec.ClientId
	if clientId == "" {
    return nil, fmt.Errorf("empty client ID")
  }

  var url, identityProviderURL string
  identityProviderURL, err = r.GetIdentityProviderURL(client.Namespace)
  if err != nil {
    return
  }
  url = strings.Join([]string{identityProviderURL, "v1", "auth", "registration", clientId}, "/")
  response, err = r.invokeClientRegistrationAPI(ctx, client, DeleteType, url, "")
  if err == nil && response.Status != "204 No Content" && response.Status != "404 Not Found" {
    return nil, NewOIDCClientError(response)
  }
  return
}

func (r *ReconcileClient) invokeClientRegistrationAPI(ctx context.Context, client *oidcv1.Client, requestType string, requestURL string, payload string) (response *http.Response, err error) {
  reqLogger := logf.FromContext(ctx).WithName("invokeClientRegistrationAPI")
  reqLogger.Info("params", "requestType", requestType, "requestURL", requestURL)
  oauthAdmin := "oauthadmin"
  var clientRegistrationSecret string
  clientRegistrationSecret, err = r.GetOAuthAdminPassword(client.Namespace)
  if err != nil {
    return
  }

	request, _ := http.NewRequest(requestType, requestURL, bytes.NewBuffer([]byte(payload)))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(oauthAdmin, clientRegistrationSecret)

  caCertSecret, err := r.getCSCACertificateSecret(ctx, client.Namespace)
  if err != nil {
    return
  }

  httpClient, err := createHTTPClient(caCertSecret.Data[corev1.TLSCertKey])
  if err != nil {
    return
  }

  response, err = httpClient.Do(request)
  if err != nil {
    return
  }
	return
}

// GetClientRegistration gets the registered Client from the OP, if it is there.
func (r *ReconcileClient) GetClientRegistration(ctx context.Context, client *oidcv1.Client) (response *http.Response, err error) {
  authServiceURL, err := r.GetIdentityProviderURL(client.Namespace)
  if err != nil {
    return
  }
	url := strings.Join([]string{authServiceURL, "v1", "auth", "registration", client.Spec.ClientId}, "/")
	response, err = r.invokeClientRegistrationAPI(ctx, client, GetType, url, "")
	if response == nil {
    err = fmt.Errorf("did not receive response from identity provider")
  } else if response.StatusCode >= 400 {
    err = NewOIDCClientError(response)
  } else if response.Status != "200 OK" {
    err = fmt.Errorf("did not get client successfully; received status %q", response.Status)
  }
  return
}

// setCSCACertificateSecret caches a copy of the Secret that contains the Common Services CA certificate for the
// provided namespace. If a Secret has already been cached for the namespace, this function replaces it with the new
// Secret.
func (r *ReconcileClient) setCSCACertificateSecret(ctx context.Context, namespace string, secret *corev1.Secret) (err error) {
  if secret == nil {
    return fmt.Errorf("provided Secret pointer was nil")
  }
  r.csCACertSecrets[namespace] = secret 
  return
}

// deleteCSCACertificateSecret deletes the cached copy of the Secret that contains the Common Services CA certificate
// for the provided namespace.
func (r *ReconcileClient) deleteCSCACertificateSecret(ctx context.Context, namespace string) {
  delete(r.csCACertSecrets, namespace)
}

// getCSCACertificateSecret gets the Secret that contains the Common Services CA certificate for the provided namespace.
// It will return the ReconcileClient's cached Secret for the namespace if it has one registered, or it will look up and
// return whatever matching Secret exists in the cluster and cache it for future use.
func (r *ReconcileClient) getCSCACertificateSecret(ctx context.Context, namespace string) (secret *corev1.Secret, err error) {
  logger := logf.FromContext(ctx, "namespace", namespace).WithName("getCSCACertificateSecret")
  var ok bool
  secret, ok = r.csCACertSecrets[namespace]
  // Have the secret locally; return it
  if ok {
    logger.Info("found CA certificate secret")
    return
  }
  logger.Info("CA certificate secret not found")
  secret = &corev1.Secret{}
  // Need to perform lookup of secret in the cluster
  csCACertificateSecretName := "cs-ca-certificate-secret"
  logger.Info("Attempt to get secret from namespace", "secretName", csCACertificateSecretName)
  err = r.client.Get(ctx, types.NamespacedName{Name: csCACertificateSecretName, Namespace: namespace}, secret)
  if err != nil {
    logger.Error(err, "failed to get secret", "secretName", csCACertificateSecretName)
    return nil, err
  } else {
    logger.Info("found secret on the cluster")
  }

  err = r.setCSCACertificateSecret(ctx, namespace, secret)
  if err != nil {
    logger.Error(err, "failed to set secret", "secretName", csCACertificateSecretName)
  } else {
    logger.Info("found CA certificate secret")
  }
  
  return
}

// GetClientCreds uses information from a Client to obtain the Client's credentials from the cluster.
// The Client must at a minimum have its ClientId, Secret, and namespace set.
func (r *ReconcileClient) GetClientCreds(ctx context.Context, client *oidcv1.Client) (clientCreds *ClientCredentials, err error) {
  if client == nil {
    return nil, fmt.Errorf("provided nil client")
  } else if client.Spec.ClientId == "" {
    return nil, fmt.Errorf("clientId was not set on Client")
  } 
  reqLogger := logf.FromContext(ctx).WithName("GetClientCreds").WithValues("clientId", client.Spec.ClientId)
  if client.Spec.Secret == "" {
    return nil, fmt.Errorf("secret was not set on Client")
  }
  secret := &corev1.Secret{}
  err = r.client.Get(ctx, types.NamespacedName{Name: client.Spec.Secret, Namespace: client.GetNamespace()}, secret)
  if err != nil {
    return
  }
  reqLogger.Info("successfully retrieved secret for Client", "secret", client.Spec.Secret)
  clientId := string(secret.Data["CLIENT_ID"][:])
  if clientId != client.Spec.ClientId {
    return nil, fmt.Errorf("secret %q with CLIENT_ID %q did not match .spec.clientId %q", client.Spec.Secret, clientId, client.Spec.ClientId)
  }
  clientCreds = &ClientCredentials{
    ClientID: clientId,
    ClientSecret: string(secret.Data["CLIENT_SECRET"][:]),
  }
  return
}

// getCredentialsFromResponse unmarshals the Client ID and Secret from an Authorization Service *http.Response into a
// *ClientCredentials struct.
func (r *ReconcileClient) unmarshalClientCreds(response *http.Response) (clientCreds *ClientCredentials, err error) {
  clientCreds = &ClientCredentials{}
  buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	defer response.Body.Close()
	registrationAPIResponse := buf.String()
	err = json.Unmarshal([]byte(registrationAPIResponse), clientCreds)
  return
}

func (r *ReconcileClient) generateClientCredentials(clientID string) *ClientCredentials {
	log.Info("OidcClient-Watcher, Generate ClientID & Secret")
	rule := `^([a-z0-9]){32,}$`
  // If clientID is empty, generate a new Client ID
  if len(clientID) == 0 {
    clientID = generateRandomString(rule)
  }
	clientSecret := generateRandomString(rule)
	return &ClientCredentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
}

func generateRandomString(rule string) string {
	generator, _ := regen.NewGenerator(rule, &regen.GeneratorArgs{
		RngSource:               rand.NewSource(time.Now().UnixNano()),
		MaxUnboundedRepeatCount: 1})
	randomString := generator.Generate()
	return randomString
}

func (r *ReconcileClient) generateClientRegistrationPayload(client *oidcv1.Client, clientCred *ClientCredentials) (payload string) {
	payloadJSON := map[string]interface{}{
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid profile email",
		"client_id":                  clientCred.ClientID,
		"client_secret":              clientCred.ClientSecret,
		"grant_types": []string{
			"authorization_code",
			"client_credentials",
			"password",
			"implicit",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
    },
		"response_types": []string{
			"code",
			"token",
			"id_token token",
    },
		"application_type":          "web",
		"subject_type":              "public",
		"post_logout_redirect_uris": client.Spec.OidcLibertyClient.LogoutUris,
		"preauthorized_scope":       "openid profile email general",
		"introspect_tokens":         true,
		"trusted_uri_prefixes":      client.Spec.OidcLibertyClient.TrustedUris,
		"redirect_uris":             client.Spec.OidcLibertyClient.RedirectUris,
  }

  if client.IsCPClientCredentialsEnabled() {
    grant_types, ok := payloadJSON["grant_types"].([]string)
    if !ok {
      goto marshal
    }
    payloadJSON["grant_types"] = append(grant_types, "cpclient_credentials")
    payloadJSON["functional_user_groupIds"] = client.Spec.Roles
  }
  marshal:
	payloadBytes, _ := json.Marshal(payloadJSON)
	payload = string(payloadBytes[:])
	return payload
}


// GetZenInstance returns the zen instance or nil if it does not exist
func (r *ReconcileClient) GetZenInstance(ctx context.Context, client *oidcv1.Client) (zenInstance *ZenInstance, err error) {

	if client.Spec.ZenInstanceId == "" {
		return nil, fmt.Errorf("Zen instance id is required to query a zen instance")
	}

  identityManagementURL, err := r.GetIdentityManagementURL(client.Namespace)
  if err != nil {
    return
  } 

  requestURLSplit := []string{identityManagementURL, "identity", "api", "v1", "zeninstance", client.Spec.ZenInstanceId}
	requestURL := strings.Join(requestURLSplit, "/")

	response, err := r.invokeIamApi(ctx, client, GetType, requestURL, "")

	if err != nil {
		return
	}
	if response != nil {
		if response.StatusCode == 404 {
			//zen instance not found
			return nil, nil
		}
		//Read response body
		buf := new(bytes.Buffer)
		buf.ReadFrom(response.Body)

		if response.StatusCode == 200 {
			zenInstance := &ZenInstance{}
			err := json.Unmarshal(buf.Bytes(), zenInstance)
			if err != nil {
				return nil, err
			}
			return zenInstance, nil
		}
		return nil, fmt.Errorf("An error occurred while querying the zen instance: Status:%s Msg:%s", response.Status, buf.String())
	}

	return nil, fmt.Errorf("No response was recieved from query of zen instance %s", client.Spec.ZenInstanceId)
}

// DeleteZenInstance deletes the requested zen instance
func (r *ReconcileClient) DeleteZenInstance(ctx context.Context, client *oidcv1.Client) (err error) {
	if client.Spec.ZenInstanceId == "" {
		return fmt.Errorf("Zen instance id is required to delete a zen instance")
	}

  // Get the platform-auth-idp ConfigMap to obtain constant values
  identityManagementURL, err := r.GetIdentityManagementURL(client.Namespace)
  if err != nil {
    return err
  } 
  requestURLSplit := []string{identityManagementURL, "identity", "api", "v1", "zeninstance", client.Spec.ZenInstanceId}
	requestURL := strings.Join(requestURLSplit, "/")
	response, err := r.invokeIamApi(ctx, client, DeleteType, requestURL, "")
	if err != nil {
		return
	}

	if err != nil {
		return 
	}
	if response != nil {
		if response.StatusCode == 200 {
			//zen instance deleted
			return
		}
		//Read response body
		buf := new(bytes.Buffer)
		buf.ReadFrom(response.Body)

		return fmt.Errorf("An error occurred while deleting the zen instance: Status:%s Msg:%s", response.Status, buf.String())
	}

	return fmt.Errorf("No response was received from query of zen instance %s", client.Spec.ZenInstanceId)
}

// CreateZenInstance registers the zen instance with the iam identity mgmt service
func (r *ReconcileClient) CreateZenInstance(ctx context.Context, client *oidcv1.Client, clientCreds *ClientCredentials) (err error) {
	payloadJSON := map[string]interface{}{
		"clientId":       client.Spec.ClientId,
    "clientSecret":   clientCreds.ClientSecret,
		"instanceId":     client.Spec.ZenInstanceId,
		"productNameUrl": client.Spec.ZenProductNameUrl,
		"namespace":      client.Namespace,
	}
	payloadBytes, _ := json.Marshal(payloadJSON)
	payload := string(payloadBytes[:])

  identityManagementURL, err := r.GetIdentityManagementURL(client.Namespace)
  if err != nil {
    return
  } 
  requestURLSplit := []string{identityManagementURL, "identity", "api", "v1", "zeninstance"}
	requestURL := strings.Join(requestURLSplit, "/")

	response, err := r.invokeIamApi(ctx, client, PostType, requestURL, payload)
	if response != nil && response.Status == "200 OK" {
		return nil
	}
	if err != nil {
		return
	}
	//Determine error and report
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	errorMsg := buf.String()
	err = fmt.Errorf("An error occurred while registering the zen instance: Status:%s Msg:%s", response.Status, errorMsg)
	return
}
