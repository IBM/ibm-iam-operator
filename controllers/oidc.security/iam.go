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

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/apis/oidc.security/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type TokenInfo struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
}

func getTokenInfoFromResponse(response *http.Response) (tokenInfo *TokenInfo, err error) {
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

	// If the first character is not a '{', we do not have a valid JSON response
	if r != '{' {
		return nil, fmt.Errorf("failed to get token info: %s", string(bodyBytes))
	}

	if err = json.Unmarshal(bodyBytes, tokenInfo); err != nil {
		return nil, fmt.Errorf("%s", string(bodyBytes[:]))
	}
	return tokenInfo, nil
}

// getAuthnTokens attempts to retrieve authentication tokens from the OP via the IM identity provider. If the Client is
// configured for the cpclient_credentials authorization grant type, the v1/auth/token endpoint is used with the
// Client's corresponding ClientCredentials. Otherwise, the password grant type is used with the OP admin credentials
// configured in platform-auth-idp-credentials.
func (r *ClientReconciler) getAuthnTokens(ctx context.Context, client *oidcsecurityv1.Client, config *AuthenticationConfig) (tokenInfo *TokenInfo, err error) {
	reqLogger := logf.FromContext(ctx).V(1)
	identityProviderURL, err := config.GetIdentityProviderURL()
	if err != nil {
		return nil, err
	}
	var requestURL, grantType, tokenType, defaultAdminUser, defaultAdminPassword string
	var clientCreds *ClientCredentials
	payload := "scope=openid"
	requestURLSplit := []string{identityProviderURL, "v1", "auth"}
	if client.IsCPClientCredentialsEnabled() {
		tokenType = "token"
		grantType = "cpclient_credentials"
		clientCreds, err = r.GetClientCreds(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("failed to get Client credentials: %w", err)
		}
		reqLogger.Info("Retrieved client creds", "client_id", clientCreds.ClientID)
		payload = fmt.Sprintf("%s&grant_type=%s&client_id=%s&client_secret=%s", payload, grantType, clientCreds.ClientID, clientCreds.ClientSecret)
	} else {
		tokenType = "identitytoken"
		grantType = "password"
		defaultAdminUser, err = config.GetDefaultAdminUser()
		if err != nil {
			return
		}
		defaultAdminPassword, err = config.GetDefaultAdminPassword()
		if err != nil {
			return
		}
		payload = fmt.Sprintf("%s&grant_type=%s&username=%s&password=%s", payload, grantType, defaultAdminUser, defaultAdminPassword)
	}
	requestURL = strings.Join(append(requestURLSplit, tokenType), "/")

	var tResp *http.Response
	var req *http.Request
	var httpClient *http.Client
	oAuthAdminPassword, err := config.GetOAuthAdminPassword()
	if err != nil {
		return
	}
	maxAttempts := 3
	for tIndex := 0; tIndex < maxAttempts; tIndex++ {
		err = nil
		reqLogger.Info("Attempt to retrieve token from id provider", "requestURL", requestURL, "tokenType", tokenType, "attempt", tIndex+1, "maxAttempts", maxAttempts)
		req, err = http.NewRequest("POST", requestURL, bytes.NewBuffer([]byte(payload)))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
		if client.IsCPClientCredentialsEnabled() {
			req.SetBasicAuth("oauthadmin", oAuthAdminPassword)
		}

		var caCert []byte
		caCert, err = config.GetCSCATLSKey()
		if err != nil {
			return
		}
		httpClient, err = createHTTPClient(caCert)
		if err != nil {
			return
		}
		tResp, err = httpClient.Do(req)
		if err != nil {
			reqLogger.Error(err, "Failed to request token from id provider")
			goto sleep
		}
		tokenInfo, err = getTokenInfoFromResponse(tResp)
		if err != nil {
			reqLogger.Error(err, "Failed to get token from id provider HTTP response")
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
func (r *ClientReconciler) invokeIamApi(ctx context.Context, client *oidcsecurityv1.Client, requestType string, requestURL string, payload string, config *AuthenticationConfig) (response *http.Response, err error) {
	// First, check to see if OIDC client is registered before trying to get a token; if an issue is encountered,
	// bubble that up.
	if _, err = r.getClientRegistration(ctx, client, config); err != nil {
		return
	}

	tokenInfo, err := r.getAuthnTokens(ctx, client, config)
	if err != nil {
		return
	}

	bearer := strings.Join([]string{"Bearer ", tokenInfo.AccessToken}, "")
	request, _ := http.NewRequest(requestType, requestURL, bytes.NewBuffer([]byte(payload)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", bearer)
	request.Header.Set("Accept", "application/json")

	caCert, err := config.GetCSCATLSKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate Secret: %w", err)
	}

	httpClient, err := createHTTPClient(caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM API HTTP client: %w", err)
	}

	response, err = httpClient.Do(request)
	return
}
