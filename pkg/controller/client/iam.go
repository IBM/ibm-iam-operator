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
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type TokenInfo struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
}

func generateAuthPayload() string {
  // TODO Figure out where this is set in a ConfigMap
	defaultAdmin := os.Getenv("DEFAULT_ADMIN_USER")
	defaultAdminPassword := os.Getenv("DEFAULT_ADMIN_PASSWORD")

	payloadJSON := "grant_type=password&scope=openid&username=" + defaultAdmin + "&password=" + defaultAdminPassword
	return payloadJSON
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

// getValueFromConfigMap returns the value stored at the provided key in the provided ConfigMap.
// If the ConfigMap's Data field is empty, the provided Kubernetes client will be used to query the cluster for a
// ConfigMap resource with a matching Name and Namespace. Produces an error if the ConfigMap's ObjectMeta has unset Name
// or Namespace values or if the key provided is not found in the ConfigMap's Data field.
func getValueFromConfigMap(k8sClient k8sclient.Client, configMap *corev1.ConfigMap, key string) (value string, err error) {
  if configMap.Data == nil {
    var (
      configMapName string
      configMapNamespace string
    )
    configMapName = configMap.GetName()
    configMapNamespace = configMap.GetNamespace()
    if configMapName == "" {
      err = fmt.Errorf("provided ConfigMap must have a name but did not have one")
      return
    } else if configMapNamespace == "" {
      err = fmt.Errorf("provided ConfigMap must have a namespace but did not have one")
      return
    } else {
      err = k8sClient.Get(context.TODO(), types.NamespacedName{Name: configMapName, Namespace: configMapNamespace}, configMap)
      if err != nil {
        return
      } 
    }
  }
  if value, ok := configMap.Data[key]; ok {
    return value, nil
  } else {
    err = fmt.Errorf("key %q not found in ConfigMap %q", key, configMap.GetName())
  }
  return
}

// Returns auth tokens to make IAM calls
func GetAuthnTokens(identityProviderURL string) (*TokenInfo, error) {
	requestUrl := strings.Join([]string{identityProviderURL, "/v1/auth/identitytoken"}, "")
	payload := generateAuthPayload()
	req, _ := http.NewRequest("POST", requestUrl, bytes.NewBuffer([]byte(payload)))
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
	var tErr error
	var tokenInfo *TokenInfo
	for {
		tResp, tErr = client.Do(req)
		if tErr != nil {
			fmt.Println(tErr.Error())
		}
		if tResp != nil && tResp.StatusCode == 200 {
			defer tResp.Body.Close()

			tokenInfo, tErr = getTokenInfoFromResponse(tResp)
			if tErr != nil {
				fmt.Println(tErr.Error())
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
	if tErr != nil {
		return nil, tErr
	}

	tErr = fmt.Errorf("Failed to get access token")
	return nil, tErr
}

//Invoke an IAM API.  This function will obtain the required token before calling
func InvokeIamApi(identityProviderURL string, requestType string, requestUrl string, payload string) (*http.Response, error) {
	tokenInfo, err2 := GetAuthnTokens(identityProviderURL)
	if err2 != nil {
		return nil, err2
	}
	bearer := strings.Join([]string{"Bearer ", tokenInfo.AccessToken}, "")
	req, _ := http.NewRequest(requestType, requestUrl, bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Accept", "application/json")
	caCert, err := ioutil.ReadFile("/certs/ca.crt")
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caCertPool}}
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
