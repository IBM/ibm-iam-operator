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

package oidcsecurity

import (
	"bytes"
	"context"

	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/api/oidc.security/v1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type ClientCredentials struct {
	ClientID     []byte `json:"CLIENT_ID"`
	ClientSecret []byte `json:"CLIENT_SECRET"`
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

// CreateClientRegistration registers a new OIDC Client on the OP using information provided in the provided Client CR;
// it does so via a call to the IM Identity Provider service.
func (r *ClientReconciler) createClientRegistration(ctx context.Context, client *oidcsecurityv1.Client, servicesNamespace string) (response *http.Response, err error) {
	log := logf.FromContext(ctx).V(1)
	var url, identityProviderURL string
	identityProviderURL, err = r.getServiceURL(ctx, servicesNamespace, IdentityProviderURLKey)
	if err != nil {
		log.Error(err, "Tried to get identity provider url while getting client registration but failed")
		return
	}
	url = strings.Join([]string{identityProviderURL, "v1", "auth", "registration"}, "/")
	clientCreds, err := r.GetClientCreds(ctx, client)
	if err != nil {
		return
	}
	payload := r.generateClientRegistrationPayload(client, clientCreds)
	response, err = r.invokeClientRegistrationAPI(ctx, servicesNamespace, http.MethodPost, url, payload)
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

// GetClientRegistration gets the registered OIDC client from the OP, if it is there; it does so via a call to the IM
// Identity Provider service.
func (r *ClientReconciler) getClientRegistration(ctx context.Context, client *oidcsecurityv1.Client, servicesNamespace string) (response *http.Response, err error) {
	log := logf.FromContext(ctx).V(1)
	var url, identityProviderURL string
	identityProviderURL, err = r.getServiceURL(ctx, servicesNamespace, IdentityProviderURLKey)
	if err != nil {
		log.Error(err, "Tried to get identity provider url while getting client registration but failed")
		return
	}
	url = strings.Join([]string{identityProviderURL, "v1", "auth", "registration", client.Spec.ClientId}, "/")
	response, err = r.invokeClientRegistrationAPI(ctx, servicesNamespace, http.MethodGet, url, nil)
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

// UpdateClientRegistration updates a registered OIDC client's credentials to use those stored in the Client CR's
// Secret; it does so via a call to the IM Identity Provider service.
func (r *ClientReconciler) updateClientRegistration(ctx context.Context, client *oidcsecurityv1.Client, servicesNamespace string) (response *http.Response, err error) {
	log := logf.FromContext(ctx).V(1)
	var url, identityProviderURL string
	clientCreds, err := r.GetClientCreds(ctx, client)
	if err != nil {
		return
	}
	payload := r.generateClientRegistrationPayload(client, clientCreds)
	identityProviderURL, err = r.getServiceURL(ctx, servicesNamespace, IdentityProviderURLKey)
	if err != nil {
		log.Error(err, "Tried to get identity provider url while getting client registration but failed")
		return
	}
	url = strings.Join([]string{identityProviderURL, "v1", "auth", "registration", string(clientCreds.ClientID)}, "/")
	response, err = r.invokeClientRegistrationAPI(ctx, servicesNamespace, http.MethodPut, url, payload)
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
	log.Info("Client registration update successful")
	return
}

// DeleteClientRegistration deletes the OIDC client registration represented by the Client CR; it does so via a call to
// the IM Identity Provider service.
func (r *ClientReconciler) deleteClientRegistration(ctx context.Context, client *oidcsecurityv1.Client, servicesNamespace string) (response *http.Response, err error) {
	log := logf.FromContext(ctx).V(1)
	clientId := client.Spec.ClientId
	if clientId == "" {
		return nil, nil
	}

	var url, identityProviderURL string
	identityProviderURL, err = r.getServiceURL(ctx, servicesNamespace, IdentityProviderURLKey)
	if err != nil {
		log.Error(err, "Tried to get identity provider url while getting client registration but failed")
		return
	}
	url = strings.Join([]string{identityProviderURL, "v1", "auth", "registration", clientId}, "/")
	response, err = r.invokeClientRegistrationAPI(ctx, servicesNamespace, http.MethodDelete, url, nil)
	defer func() {
		response.Request = nil
	}()
	if err != nil {
		return nil, NewOIDCClientRegistrationError(client.Spec.ClientId, http.MethodDelete, err.Error(), response)
	}
	if response.Status != "204 No Content" && response.Status != "404 Not Found" {
		return nil, NewOIDCClientRegistrationError(
			client.Spec.ClientId,
			http.MethodDelete,
			fmt.Sprintf("got status %s", response.Status),
			response,
		)
	}
	return
}

func (r *ClientReconciler) invokeClientRegistrationAPI(ctx context.Context, servicesNamespace string, requestType string, requestURL string, payload []byte) (response *http.Response, err error) {
	reqLogger := logf.FromContext(ctx).V(1)
	username, password, err := GetOAuthAdminCredentials(r.Client, ctx, servicesNamespace)
	if err != nil {
		return
	}
	defer func() {
		common.Scrub(username)
		username = nil
		common.Scrub(password)
		password = nil
	}()

	request, err := http.NewRequest(requestType, requestURL, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(string(username), string(password))
	defer func() {
		request.Header.Del("Authorization")
	}()

	caCert, err := GetCommonServiceCATLSKey(r.Client, ctx, servicesNamespace)
	if err != nil {
		reqLogger.Error(err, "Failed to read certificate from Secret", "Secret.Name", CSCACertificateSecretName, "Secret.Namespace", servicesNamespace)
		return
	}
	reqLogger.Info("Read certificate from Secret", "Secret.Name", CSCACertificateSecretName, "Secret.Namespace", servicesNamespace)

	httpClient, err := createHTTPClient(caCert)
	if err != nil {
		return
	}

	response, err = httpClient.Do(request)
	if err != nil {
		reqLogger.Error(err, "OIDC registration request failed")
		return
	}
	reqLogger.Info("OIDC registration request complete")
	return
}

// GetClientCreds uses information from a Client to obtain the Client's credentials from the cluster.
// The Client must at a minimum have its ClientId, Secret, and namespace set.
func (r *ClientReconciler) GetClientCreds(ctx context.Context, client *oidcsecurityv1.Client) (clientCreds *ClientCredentials, err error) {
	if client == nil {
		return nil, fmt.Errorf("provided nil client")
	}
	secret, err := r.getSecretFromClient(ctx, client)
	reqLogger := logf.FromContext(ctx)
	if err != nil || secret == nil {
		reqLogger.Error(err, "Secret could not be retrieved for Client", "secretName", client.Spec.Secret)
		return
	}
	clientCreds, err = getClientCredsFromSecret(secret)
	if err != nil {
		reqLogger.Error(err, "Retrieved Secret did not have correct Client ID and Secret keys", "Secret.Name", client.Spec.Secret)
		return nil, fmt.Errorf("could not create new ClientCredentials struct: %w", err)
	}
	return
}

func (r *ClientReconciler) generateClientCredentials(clientID []byte) (creds *ClientCredentials, err error) {
	// If clientID is empty, generate a new Client ID
	if len(clientID) == 0 {
		clientID, err = r.GenerateBytes(common.LowerAlphaNum, 32)
	}
	if err != nil {
		return
	}
	clientSecret, err := r.GenerateBytes(common.LowerAlphaNum, 32)
	if err != nil {
		return
	}
	return &ClientCredentials{
		ClientID:     clientID[:],
		ClientSecret: clientSecret[:],
	}, nil
}

func (r *ClientReconciler) generateClientRegistrationPayload(client *oidcsecurityv1.Client, clientCred *ClientCredentials) (payload []byte) {
	payloadJSON := map[string]any{
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid profile email",
		"client_id":                  string(clientCred.ClientID[:]),
		"client_secret":              string(clientCred.ClientSecret[:]),
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
			payload, _ = json.Marshal(payloadJSON)
			return
		}
		payloadJSON["grant_types"] = append(grant_types, "cpclient_credentials")
		payloadJSON["functional_user_groupIds"] = client.Spec.Roles
	}
	payload, _ = json.Marshal(payloadJSON)
	return
}
