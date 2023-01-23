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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	oidcv1 "github.com/IBM/ibm-iam-operator/pkg/apis/oidc/v1"
	"strings"
	"time"
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
  if response.Body != nil {
    defer response.Body.Close()
    tokenInfo = &TokenInfo{}
    buf := new(bytes.Buffer)
    buf.ReadFrom(response.Body)
    regResponse := buf.String()
    err = json.Unmarshal([]byte(regResponse), tokenInfo)
    if err != nil {
      return nil, fmt.Errorf("failed to get unmarshal response JSON %q: %w", regResponse, err)
    } 
    return tokenInfo, nil
  }
  return nil, fmt.Errorf("response body was not set")
}

// getAuthnTokens attempts to retrieve authentication tokens from the IAM identity provider. If the Client is configured
// for the cpclient_credentials authorization grant type, the v1/auth/token endpoint is used with the Client's
// corresponding ClientCredentials. Otherwise, the password grant type is used with the OP admin credentials configured
// in platform-auth-idp-credentials.
func (r *ReconcileClient) getAuthnTokens(ctx context.Context, client *oidcv1.Client) (tokenInfo *TokenInfo, err error) {
  reqLogger := logf.FromContext(ctx).WithName("getAuthnTokens")
  identityProviderURL, err := r.GetIdentityProviderURL()
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
    reqLogger.Info("check payload", "client_id", clientCreds.ClientID, "client_secret_set", clientCreds.ClientSecret != "")
  } else {
    tokenType = "identitytoken"
    grantType = "password"
    defaultAdminUser, err = r.GetDefaultAdminUser()
    if err != nil {
      return
    }
    defaultAdminPassword, err = r.GetDefaultAdminPassword()
    if err != nil {
      return
    }
    payload = fmt.Sprintf("%s&grant_type=%s&username=%s&password=%s", payload, grantType, defaultAdminUser, defaultAdminPassword)
  }
  requestURL = strings.Join(append(requestURLSplit, tokenType), "/")

	var tResp *http.Response
  var req *http.Request
  var httpClient *http.Client
  oAuthAdminPassword, err := r.GetOAuthAdminPassword()
  if err != nil {
    return
  }
  maxAttempts := 3
  for tIndex := 0; tIndex < maxAttempts; tIndex++ {
    err = nil
    reqLogger.Info("Attempt to retrieve token from id provider", "requestURL", requestURL, "tokenType", tokenType, "attempt", tIndex + 1, "maxAttempts", maxAttempts)
    req, err = http.NewRequest("POST", requestURL, bytes.NewBuffer([]byte(payload)))
    if err != nil {
      return
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
    if client.IsCPClientCredentialsEnabled() {
      req.SetBasicAuth("oauthadmin", oAuthAdminPassword)
    }
    httpClient, err = createHTTPClient()
    if err != nil {
      return
    }
		tResp, err = httpClient.Do(req)
		if err != nil {
      reqLogger.Error(err, "failed to request token from id provider")
			goto sleep
		}
    tokenInfo, err = getTokenInfoFromResponse(tResp)
    if err != nil {
      reqLogger.Error(err, "failed to get token from id provider HTTP response")
    } else if tokenInfo != nil {
      return
    }

    sleep:
    if tIndex < maxAttempts - 1 {
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
func createHTTPClient() (httpClient *http.Client, err error) {
	caCert, err := ioutil.ReadFile("/certs/ca.crt")
	if err != nil {
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caCertPool}}
	httpClient = &http.Client{Transport: transport}
  return
}

// Invoke an IAM API.  This function will obtain the required token before calling
func (r *ReconcileClient) invokeIamApi(ctx context.Context, client *oidcv1.Client, requestType string, requestURL string, payload string) (response *http.Response, err error) {
	tokenInfo, err := r.getAuthnTokens(ctx, client)
	if err != nil {
		return
	}
	bearer := strings.Join([]string{"Bearer ", tokenInfo.AccessToken}, "")
	request, _ := http.NewRequest(requestType, requestURL, bytes.NewBuffer([]byte(payload)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", bearer)
	request.Header.Set("Accept", "application/json")
  httpClient, err := createHTTPClient()
  if err != nil {
    return
  }
	response, err = httpClient.Do(request)
	return
}
