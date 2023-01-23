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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type TokenInfo struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
}

// generateAuthPayload generates the authentication payload used with the IAM API
func (r *ReconcileClient) generateAuthPayload() (payloadJSON string, err error) {
	defaultAdminUser, err := r.GetDefaultAdminUser()
  if err != nil {
    return
  }
  defaultAdminPassword, err := r.GetDefaultAdminPassword()
  if err != nil {
    return
  }
	payloadJSON = "grant_type=password&scope=openid&username=" + defaultAdminUser + "&password=" + defaultAdminPassword
	return
}

func getTokenInfoFromResponse(response *http.Response) (*TokenInfo, error) {
	responseObj := &TokenInfo{}
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	regRespone := buf.String()
	errParse := json.Unmarshal([]byte(regRespone), responseObj)
	if errParse == nil {
		return responseObj, nil
	} else {
		return nil, errParse
	}
}

// getAuthnTokens attempts to retrieve authentication tokens from the IAM API
func (r *ReconcileClient) getAuthnTokens() (tokenInfo *TokenInfo, err error) {
  identityProviderURL, err := r.GetIdentityProviderURL()
  if err != nil {
    return nil, err
  }
	requestURL := strings.Join([]string{identityProviderURL, "/v1/auth/identitytoken"}, "")
	payload, err := r.generateAuthPayload()
  if err != nil {
    return nil, err
  }
	req, _ := http.NewRequest("POST", requestURL, bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	caCert, err := ioutil.ReadFile("/certs/ca.crt")
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caCertPool}}
	client := &http.Client{Transport: transport}

	var tIndex = 0
	var tResp *http.Response
	for {
		tResp, err = client.Do(req)
		if err != nil {
			fmt.Println(err.Error())
		}
		if tResp != nil && tResp.StatusCode == 200 {
			defer tResp.Body.Close()

			tokenInfo, err = getTokenInfoFromResponse(tResp)
			if err != nil {
				fmt.Println(err.Error())
			}
			if tokenInfo != nil {
				return tokenInfo, nil
			}
		}
		if tIndex >= 2 {
			break
		}
		tIndex += 1
		time.Sleep(2 * time.Second)
		fmt.Println("Retrying identitytoken...")
	}
	if err != nil {
		return
	}

	err = fmt.Errorf("Failed to get access token")
	return
}

//Invoke an IAM API.  This function will obtain the required token before calling
func (r *ReconcileClient) invokeIamApi(requestType string, requestURL string, payload string) (resp *http.Response, err error) {
	tokenInfo, err := r.getAuthnTokens()
	if err != nil {
		return
	}
	bearer := strings.Join([]string{"Bearer ", tokenInfo.AccessToken}, "")
	req, _ := http.NewRequest(requestType, requestURL, bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Accept", "application/json")
	caCert, err := ioutil.ReadFile("/certs/ca.crt")
	if err != nil {
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caCertPool}}
	client := &http.Client{Transport: transport}
	resp, err = client.Do(req)
	if err != nil {
		return
	}
	return
}
