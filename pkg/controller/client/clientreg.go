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
	"net/http"
	"strings"

	oidcv1 "github.com/IBM/ibm-iam-operator/pkg/apis/oidc/v1"
	"github.com/IBM/ibm-iam-operator/pkg/controller/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type ClientCredentials struct {
	ClientID     string `json:"CLIENT_ID"`
	ClientSecret string `json:"CLIENT_SECRET"`
}

type OidcClientResponse struct {
	ClientIDIssuedAt        int      `json:"client_id_issued_at"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	ClientSecretExpiresAt   int      `json:"client_secret_expires_at"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ApplicationType         string   `json:"application_type"`
	SubjectType             string   `json:"subject_type"`
	PostLogoutRedirectUris  []string `json:"post_logout_redirect_uris"`
	PreauthorizedScope      string   `json:"preauthorized_scope"`
	IntrospectTokens        bool     `json:"introspect_tokens"`
	TrustedURIPrefixes      []string `json:"trusted_uri_prefixes"`
	ResourceIds             []string `json:"resource_ids"`
	FunctionalUserGroupIds  []string `json:"functional_user_groupIds"`
	FunctionalUserID        string   `json:"functional_user_id"`
	AppPasswordAllowed      bool     `json:"appPasswordAllowed"`
	AppTokenAllowed         bool     `json:"appTokenAllowed"`
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	ClientName              string   `json:"client_name"`
	RedirectUris            []string `json:"redirect_uris"`
	AllowRegexpRedirects    bool     `json:"allow_regexp_redirects"`
}

// ZenInstance represents the zen instance model (response from post, get)
type ZenInstance struct {
	ClientID       string `json:"clientId"`
	InstanceId     string `json:"instanceId"`
	ProductNameUrl string `json:"productNameUrl"`
	Namespace      string `json:"namespace"`
	ZenAuditUrl    string `json:"zenAuditUrl"`
}

// CreateClientRegistration registers a new OIDC Client on the OP using information provided in the provided Client CR.
func (r *ReconcileClient) CreateClientRegistration(ctx context.Context, client *oidcv1.Client) (response *http.Response, err error) {
	reqLogger := logf.FromContext(ctx).WithName("CreateClientRegistration")
	var url, identityProviderURL string
	identityProviderURL, err = r.GetIdentityProviderURL()
	if err != nil {
		reqLogger.Error(err, "Tried to get identity provider url but failed")
		return
	}
	url = strings.Join([]string{identityProviderURL, "v1", "auth", "registration"}, "/")
	clientCreds, err := r.GetClientCreds(ctx, client)
	if err != nil {
		return
	}
	payload := r.generateClientRegistrationPayload(client, clientCreds)
	response, err = r.invokeClientRegistrationAPI(ctx, client, http.MethodPost, url, payload)
	if err == nil && response.Status != "201 Created" {
		return nil, NewOIDCClientRegistrationError(
			client.Spec.ClientId,
			http.MethodPost,
			fmt.Sprintf("got status %s", response.Status),
			response,
		)
	} else if err != nil {
		return nil, NewOIDCClientRegistrationError(client.Spec.ClientId, http.MethodPost, err.Error(), response)
	}
	return
}

// UpdateClientRegistration updates the OIDC Client registration represented by the Client CR to use the credentials
// stored in the provided Secret.
func (r *ReconcileClient) UpdateClientRegistration(ctx context.Context, client *oidcv1.Client) (response *http.Response, err error) {
	logger := logf.FromContext(ctx).WithName("UpdateClientRegistration")
	var url, identityProviderURL string
	clientCreds, err := r.GetClientCreds(ctx, client)
	if err != nil {
		return
	}
	payload := r.generateClientRegistrationPayload(client, clientCreds)
	identityProviderURL, err = r.GetIdentityProviderURL()
	if err != nil {
		return
	}
	url = strings.Join([]string{identityProviderURL, "v1", "auth", "registration", clientCreds.ClientID}, "/")
	response, err = r.invokeClientRegistrationAPI(ctx, client, http.MethodPut, url, payload)
	if err == nil && response.Status != "200 OK" {
		return nil, NewOIDCClientRegistrationError(
			client.Spec.ClientId,
			http.MethodPut,
			fmt.Sprintf("got status %s", response.Status),
			response,
		)
	} else if err != nil {
		return nil, NewOIDCClientRegistrationError(
			client.Spec.ClientId,
			http.MethodPut,
			err.Error(),
			response,
		)
	}
	logger.Info("Client registration update successful")
	return
}

// DeleteClientRegistration deletes from the OP the OIDC Client registration represented by the Client CR.
func (r *ReconcileClient) DeleteClientRegistration(ctx context.Context, client *oidcv1.Client) (response *http.Response, err error) {
	clientId := client.Spec.ClientId
	if clientId == "" {
		return nil, fmt.Errorf("empty client ID")
	}

	var url, identityProviderURL string
	identityProviderURL, err = r.GetIdentityProviderURL()
	if err != nil {
		return
	}
	url = strings.Join([]string{identityProviderURL, "v1", "auth", "registration", clientId}, "/")
	response, err = r.invokeClientRegistrationAPI(ctx, client, http.MethodDelete, url, "")
	if err != nil {
		return nil, NewOIDCClientRegistrationError(client.Spec.ClientId, http.MethodDelete, err.Error(), response)
	}
	if err == nil && response.Status != "204 No Content" && response.Status != "404 Not Found" {
		return nil, NewOIDCClientRegistrationError(
			client.Spec.ClientId,
			http.MethodDelete,
			fmt.Sprintf("got status %s", response.Status),
			response,
		)
	}
	return
}

func (r *ReconcileClient) invokeClientRegistrationAPI(ctx context.Context, client *oidcv1.Client, requestType string, requestURL string, payload string) (response *http.Response, err error) {
	reqLogger := logf.FromContext(ctx).WithName("invokeClientRegistrationAPI")
	reqLogger.Info("params", "requestType", requestType, "requestURL", requestURL)
	oauthAdmin := "oauthadmin"
	var clientRegistrationSecret string
	clientRegistrationSecret, err = r.GetOAuthAdminPassword()
	if err != nil {
		return
	}

	request, _ := http.NewRequest(requestType, requestURL, bytes.NewBuffer([]byte(payload)))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(oauthAdmin, clientRegistrationSecret)

	caCertSecret, err := r.getCSCACertificateSecret(ctx)
	if err != nil {
		return
	}

	httpClient, err := createHTTPClient(caCertSecret.Data[corev1.TLSCertKey])
	if err != nil {
		return
	}

	response, err = httpClient.Do(request)
	if err != nil {
		reqLogger.Error(err, "Request failed")
		return
	}
	reqLogger.Info("Request complete", "headers", response.Request.Header)
	return
}

// GetClientRegistration gets the registered Client from the OP via the IdP, if that Client is there.
func (r *ReconcileClient) GetClientRegistration(ctx context.Context, client *oidcv1.Client) (response *http.Response, err error) {
	identityProviderURL, err := r.GetIdentityProviderURL()
	if err != nil {
		return
	}
	url := strings.Join([]string{identityProviderURL, "v1", "auth", "registration", client.Spec.ClientId}, "/")
	response, err = r.invokeClientRegistrationAPI(ctx, client, http.MethodGet, url, "")
	if err != nil {
		err = NewOIDCClientRegistrationError(
			client.Spec.ClientId,
			http.MethodGet,
			err.Error(),
			response,
		)
	} else if response.Status != "200 OK" {
		err = NewOIDCClientRegistrationError(
			client.Spec.ClientId,
			http.MethodGet,
			fmt.Sprintf("did not get client successfully; received status %q", response.Status),
			response,
		)
	}
	return
}

// getCSCACertificateSecret gets the Secret that contains the Common Services CA certificate for the provided namespace.
// It will return the ReconcileClient's cached Secret for the namespace if it has one registered, or it will look up and
// return whatever matching Secret exists in the cluster and cache it for future use.
func (r *ReconcileClient) getCSCACertificateSecret(ctx context.Context) (secret *corev1.Secret, err error) {
	logger := logf.FromContext(ctx).WithName("getCSCACertificateSecret").WithValues("secretName", CSCACertificateSecretName)
	secret = &corev1.Secret{}
	err = r.client.Get(ctx, types.NamespacedName{Name: CSCACertificateSecretName, Namespace: r.sharedServicesNamespace}, secret)
	if err != nil {
		logger.Error(err, "Failed to get secret")
		return nil, err
	} else {
		logger.Info("Got secret")
	}

	return
}

// GetClientCreds uses information from a Client to obtain the Client's credentials from the cluster.
// The Client must at a minimum have its ClientId, Secret, and namespace set.
func (r *ReconcileClient) GetClientCreds(ctx context.Context, client *oidcv1.Client) (clientCreds *ClientCredentials, err error) {
	if client == nil {
		return nil, fmt.Errorf("provided nil client")
	}
	secret, err := r.getSecretFromClient(ctx, client)
	reqLogger := logf.FromContext(ctx)
	if err != nil {
		reqLogger.Error(err, "Secret could not be retrieved for Client", "secretName", client.Spec.Secret)
		return
	}
	clientCreds, err = getClientCredsFromSecret(secret)
	if err != nil {
		reqLogger.Error(err, "Retrieved Secret did not have correct Client ID and Secret keys", "secretName", client.Spec.Secret)
		return nil, fmt.Errorf("could not create new ClientCredentials struct: %w", err)
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
	rule := `^([a-z0-9]){32,}$`
	// If clientID is empty, generate a new Client ID
	if len(clientID) == 0 {
		clientID = common.GenerateRandomString(rule)
	}
	clientSecret := common.GenerateRandomString(rule)
	return &ClientCredentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
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

	var response *http.Response
	if client.Spec.ZenInstanceId == "" {
		return nil, fmt.Errorf("Zen instance id is required to query a zen instance")
	}

	identityManagementURL, err := r.GetIdentityManagementURL()
	if err != nil {
		return
	}

	requestURLSplit := []string{identityManagementURL, "identity", "api", "v1", "zeninstance", client.Spec.ZenInstanceId}
	requestURL := strings.Join(requestURLSplit, "/")

	response, err = r.invokeIamApi(ctx, client, http.MethodGet, requestURL, "")

	if err != nil {
		return nil, NewZenClientRegistrationError(
			client.Spec.ClientId,
			http.MethodGet,
			client.Spec.ZenInstanceId,
			err.Error(),
			response,
		)
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
				return nil, NewZenClientRegistrationError(
					client.Spec.ClientId,
					http.MethodGet,
					client.Spec.ZenInstanceId,
					err.Error(),
					response,
				)
			}
			return zenInstance, nil
		}
		return nil, NewZenClientRegistrationError(
			client.Spec.ClientId,
			http.MethodGet,
			client.Spec.ZenInstanceId,
			fmt.Sprintf("An error occurred while querying the zen instance: Status:%s Msg:%s", response.Status, buf.String()),
			response,
		)
	}

	return nil, NewZenClientRegistrationError(
		client.Spec.ClientId,
		http.MethodGet,
		client.Spec.ZenInstanceId,
		fmt.Sprintf("no response was recieved from query of zen instance %s", client.Spec.ZenInstanceId),
		response,
	)
}

// DeleteZenInstance deletes the requested zen instance
func (r *ReconcileClient) DeleteZenInstance(ctx context.Context, client *oidcv1.Client) (err error) {
	if client.Spec.ZenInstanceId == "" {
		return fmt.Errorf("Zen instance id is required to delete a zen instance")
	}

	// Get the platform-auth-idp ConfigMap to obtain constant values
	identityManagementURL, err := r.GetIdentityManagementURL()
	if err != nil {
		return
	}
	requestURLSplit := []string{identityManagementURL, "identity", "api", "v1", "zeninstance", client.Spec.ZenInstanceId}
	requestURL := strings.Join(requestURLSplit, "/")
	response, err := r.invokeIamApi(ctx, client, http.MethodDelete, requestURL, "")
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

	return fmt.Errorf("no response was received from query of zen instance %s", client.Spec.ZenInstanceId)
}

// CreateZenInstance registers the zen instance with the iam identity mgmt service
func (r *ReconcileClient) CreateZenInstance(ctx context.Context, client *oidcv1.Client, clientCreds *ClientCredentials) (err error) {
	payloadJSON := map[string]interface{}{
		"clientId":       client.Spec.ClientId,
		"clientSecret":   clientCreds.ClientSecret,
		"instanceId":     client.Spec.ZenInstanceId,
		"productNameUrl": client.Spec.ZenProductNameUrl,
		"namespace":      client.Namespace,
		"zenAuditUrl":    client.Spec.ZenAuditUrl,
	}
	payloadBytes, _ := json.Marshal(payloadJSON)
	payload := string(payloadBytes[:])

	identityManagementURL, err := r.GetIdentityManagementURL()
	if err != nil {
		return
	}
	requestURLSplit := []string{identityManagementURL, "identity", "api", "v1", "zeninstance"}
	requestURL := strings.Join(requestURLSplit, "/")

	response, err := r.invokeIamApi(ctx, client, http.MethodPost, requestURL, payload)
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
