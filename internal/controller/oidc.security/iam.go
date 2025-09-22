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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/api/oidc.security/v1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type TokenInfo struct {
	AccessToken  []byte `json:"access_token"`
	TokenType    []byte `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        []byte `json:"scope"`
	RefreshToken []byte `json:"refresh_token"`
	IdToken      []byte `json:"id_token"`
}

func getTokenInfoFromResponse(ctx context.Context, response *http.Response) (tokenInfo *TokenInfo, err error) {
	log := logf.FromContext(ctx).V(1)
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("response body was not set")
	}
	defer response.Body.Close()
	tokenInfo = &TokenInfo{}
	buf := new(bytes.Buffer)
	numBytes, err := buf.ReadFrom(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read from response body due: %w", err)
	}
	if numBytes == 0 {
		return nil, fmt.Errorf("response body was not set")
	}
	bodyBytes := buf.Bytes()
	r, _ := utf8.DecodeRune(bodyBytes)
	log.Info("Decoded first character of body", "char", r, "char str", string(r))

	// If the first character is not a '{', we do not have a valid JSON response
	if r != '{' {
		return nil, fmt.Errorf("failed to get token info: %s", string(bodyBytes))
	}
	log.Info("Decoded body", "body", bodyBytes, "bodyString", string(bodyBytes), "byte 3", bodyBytes[2], "byte 3 str", string(bodyBytes[2]), "byte 4", bodyBytes[3], "byte 4 str", string(bodyBytes[3]), "byte 5", bodyBytes[4], "byte 5 str", string(bodyBytes[4]))
	tokenDecoder := json.NewDecoder(buf)
	if err = tokenDecoder.Decode(tokenInfo); err != nil {
		return nil, fmt.Errorf("failed to decode token info: %w", err)
	}
	//if err = json.Unmarshal(bodyBytes, tokenInfo); err != nil {
	//	return nil, fmt.Errorf("failed to unmarshal token info: %w", err)
	//}
	return tokenInfo, nil
}

// getAuthnTokens attempts to retrieve authentication tokens from the OP via the IM identity provider. If the Client is
// configured for the cpclient_credentials authorization grant type, the v1/auth/token endpoint is used with the
// Client's corresponding ClientCredentials. Otherwise, the password grant type is used with the OP admin credentials
// configured in platform-auth-idp-credentials.
func (r *ClientReconciler) getAuthnTokens(ctx context.Context, client *oidcsecurityv1.Client, servicesNamespace string) (tokenInfo *TokenInfo, err error) {
	log := logf.FromContext(ctx).V(1)
	var identityProviderURL string
	identityProviderURL, err = GetServiceURL(r.Client, ctx, servicesNamespace, IdentityProviderURLKey)
	if err != nil {
		log.Error(err, "Tried to get identity provider url while getting client registration but failed")
		return
	}
	var requestURL, grantType, tokenType string
	var defaultAdminUser, defaultAdminPassword []byte
	var clientCreds *ClientCredentials
	payload := []byte("scope=openid")
	requestURLSplit := []string{identityProviderURL, "v1", "auth"}
	if client.IsCPClientCredentialsEnabled() {
		tokenType = "token"
		grantType = "cpclient_credentials"
		clientCreds, err = r.GetClientCreds(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("failed to get Client credentials: %w", err)
		}
		defer func() {
			log.Info("Scrub client creds")
			common.Scrub(clientCreds.ClientID)
			common.Scrub(clientCreds.ClientSecret)
			clientCreds = nil
		}()
		log.Info("Retrieved client creds", "client_id", clientCreds.ClientID)
		payload = fmt.Appendf(payload, "&grant_type=%s&client_id=%s&client_secret=%s", grantType, clientCreds.ClientID, clientCreds.ClientSecret)
		log.Info("Constructed payload", "token_type", tokenType, "grant_type", grantType, "payload", payload)
		defer func() {
			payload = nil
		}()
	} else {
		tokenType = "identitytoken"
		grantType = "password"
		defaultAdminUser, defaultAdminPassword, err = GetDefaultAdminCredentials(r.Client, ctx, servicesNamespace)
		if err != nil {
			return
		}
		payload = fmt.Appendf(payload, "&grant_type=%s&username=%s&password=%s", grantType, defaultAdminUser, defaultAdminPassword)
		log.Info("Constructed payload", "token_type", tokenType, "grant_type", grantType, "payload", payload)
		defer func() {
			common.Scrub(defaultAdminUser)
			defaultAdminPassword = nil
			common.Scrub(defaultAdminPassword)
			defaultAdminPassword = nil
			common.Scrub(payload)
			payload = nil
		}()
	}
	requestURL = strings.Join(append(requestURLSplit, tokenType), "/")

	var tResp *http.Response
	var req *http.Request
	var httpClient *http.Client
	defer func() {
		tResp.Request = nil
		req = nil
		httpClient = nil
	}()
	username, password, err := GetOAuthAdminCredentials(r.Client, ctx, servicesNamespace)
	log.Info("OAuth admin credentials", "username", username, "password", password)
	if err != nil {
		return
	}
	defer func() {
		common.Scrub(username)
		username = nil
		common.Scrub(password)
		password = nil
	}()
	maxAttempts := 3
	for tIndex := range maxAttempts {
		err = nil
		log.Info("Attempt to retrieve token from id provider", "requestURL", requestURL, "tokenType", tokenType, "attempt", tIndex+1, "maxAttempts", maxAttempts)
		req, err = http.NewRequest("POST", requestURL, bytes.NewBuffer(payload))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
		if client.IsCPClientCredentialsEnabled() {
			req.SetBasicAuth(string(username), string(password))
			defer func() {
				req.Header.Del("Authorization")
			}()
		}

		var caCert []byte
		caCert, err = GetCommonServiceCATLSKey(r.Client, ctx, servicesNamespace)
		if err != nil {
			return
		}
		httpClient, err = createHTTPClient(caCert)
		if err != nil {
			return
		}
		tResp, err = httpClient.Do(req)
		if err != nil {
			log.Error(err, "Failed to request token from id provider")
			goto sleep
		}
		tokenInfo, err = getTokenInfoFromResponse(ctx, tResp)
		if err != nil {
			log.Error(err, "Failed to get token from id provider HTTP response")
		} else if tokenInfo != nil {
			return
		}

	sleep:
		if tIndex < maxAttempts-1 {
			time.Sleep(2 * time.Second)
		}
	}
	if err != nil {
		err = fmt.Errorf("failed to get access token: %w", err)
	} else {
		err = fmt.Errorf("failed to get access token")
	}
	return
}

// createHTTPClient handles boilerplate of creating an http.Client configured for TLS using the Common Services CA
// certificate.
func createHTTPClient(caCert []byte) (httpClient *http.Client, err error) {
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caCertPool}}
	httpClient = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	return
}

// Invoke an IAM API.  This function will obtain the required token before calling
func (r *ClientReconciler) invokeIamApi(ctx context.Context, client *oidcsecurityv1.Client, requestType string, requestURL string, payload string, servicesNamespace string) (response *http.Response, err error) {
	// First, check to see if OIDC client is registered before trying to get a token; if an issue is encountered,
	// bubble that up.
	if _, err = r.getClientRegistration(ctx, client, servicesNamespace); err != nil {
		return
	}

	tokenInfo, err := r.getAuthnTokens(ctx, client, servicesNamespace)
	if err != nil {
		return
	}
	bearer := strings.Join([]string{"Bearer ", string(tokenInfo.AccessToken)}, "")
	request, _ := http.NewRequest(requestType, requestURL, bytes.NewBuffer([]byte(payload)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", bearer)
	request.Header.Set("Accept", "application/json")
	defer func() {
		common.Scrub(tokenInfo.AccessToken)
		tokenInfo.AccessToken = nil
		common.Scrub(tokenInfo.IdToken)
		tokenInfo.IdToken = nil
		common.Scrub(tokenInfo.RefreshToken)
		tokenInfo.RefreshToken = nil
		common.Scrub(tokenInfo.Scope)
		tokenInfo.Scope = nil
		common.Scrub(tokenInfo.TokenType)
		tokenInfo.TokenType = nil
		request.Header.Del("Authorization")
	}()

	var caCert []byte
	if caCert, err = GetCommonServiceCATLSKey(r.Client, ctx, servicesNamespace); err != nil {
		return
	}

	httpClient, err := createHTTPClient(caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM API HTTP client: %w", err)
	}

	response, err = httpClient.Do(request)
	return
}
