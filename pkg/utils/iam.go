/*******************************************************************************
 * Licensed Materials - Property of IBM
 * (c) Copyright IBM Corporation 2021. All Rights Reserved.
 *
 * Note to U.S. Government Users Restricted Rights:
 * Use, duplication or disclosure restricted by GSA ADP Schedule
 * Contract with IBM Corp.
 *******************************************************************************/
package utils

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	GetType    = "GET"
	PostType   = "POST"
	PutType    = "PUT"
	DeleteType = "DELETE"
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

// Returns auth tokens to make IAM calls
func GetAuthnTokens() (*TokenInfo, error) {
	authProviderUrl := os.Getenv("IDENTITY_PROVIDER_URL")
	requestUrl := strings.Join([]string{authProviderUrl, "/v1/auth/identitytoken"}, "")
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
func InvokeIamApi(requestType string, requestUrl string, payload string) (*http.Response, error) {
	tokenInfo, err2 := GetAuthnTokens()
	if err2 != nil {
		return nil, err2
	}
	bearer := strings.Join([]string{"Bearer ", tokenInfo.AccessToken}, "")
	//log.Printf("GOT AUTH TOKEN bearer token: %s", bearer)
	//log.Printf("requestType:%s requestUrl:%s", requestType, requestUrl)

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
