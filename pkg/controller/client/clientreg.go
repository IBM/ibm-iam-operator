/*******************************************************************************
 * Licensed Materials - Property of IBM
 * (c) Copyright IBM Corporation 2018,2021. All Rights Reserved.
 *
 * Note to U.S. Government Users Restricted Rights:
 * Use, duplication or disclosure restricted by GSA ADP Schedule
 * Contract with IBM Corp.
 *******************************************************************************/
package client

import (
	"bytes"
	"context"
	//"crypto/rand"
	"crypto/tls"
	"crypto/x509"

	//"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	securityv1 "github.com/IBM/ibm-iam-operator/pkg/apis/oidc/v1"
	"k8s.io/apimachinery/pkg/types"
	utils "github.com/IBM/ibm-iam-operator/pkg/utils"
	regen "github.com/zach-klippenstein/goregen"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

type ClientCredentials struct {
	CLIENT_ID     string `json:"CLIENT_ID"`
	CLIENT_SECRET string `json:"CLIENT_SECRET"`
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
	ResourceIds             []interface{} `json:"resource_ids"`
	FunctionalUserGroupIds  []interface{} `json:"functional_user_groupIds"`
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

// The default auth service URL
const authServiceUrl = "https://platform-auth-service:9443"

func (r *ReconcileClient) CreateClientCredentials(client *securityv1.Client, recorder record.EventRecorder) (*ClientCredentials, error) {
	url := strings.Join([]string{authServiceUrl, "/oidc/endpoint/OP/registration"}, "")
	serviceName := client.Name
	clientCred := r.generateClientCredentials(serviceName)

	payload := r.generateClientRegistrationPayload(client, clientCred)
	response, err := r.invokeRegistration(client, PostType, url, payload)
	if response != nil && response.Status == "201 Created" {
		client.Spec.ClientId = clientCred.CLIENT_ID
		defer response.Body.Close()
		return clientCred, nil
	} else {
		handleOIDCClientError(client, response, err, PostType, recorder)
		err = fmt.Errorf("Error occurred during create oidc client regstration")
		return nil, err
	}

}

func (r *ReconcileClient) UpdateClientCredentials(client *securityv1.Client, secret *corev1.Secret, recorder record.EventRecorder) (*ClientCredentials, error) {
	secretData := secret.Data
	clientCred := &ClientCredentials{
		CLIENT_ID:     string(secretData["CLIENT_ID"]),
		CLIENT_SECRET: string(secretData["CLIENT_SECRET"]),
	}
	payload := r.generateClientRegistrationPayload(client, clientCred)
	url := strings.Join([]string{authServiceUrl, "/oidc/endpoint/OP/registration/", clientCred.CLIENT_ID}, "")
	response, err := r.invokeRegistration(client, PutType, url, payload)
	if response != nil && response.Status == "200 OK" {
		defer response.Body.Close()
		return clientCred, nil
	} else {
		handleOIDCClientError(client, response, err, PutType, recorder)
		err = fmt.Errorf("Error occurred during update oidc client regstration")
		return nil, err
	}
}

func (r *ReconcileClient) DeleteClientCredentials(client *securityv1.Client, recorder record.EventRecorder) error {
	clientId := client.Spec.ClientId
	if clientId != "" {
		url := strings.Join([]string{authServiceUrl, "/oidc/endpoint/OP/registration/", clientId}, "")
		response, err := r.invokeRegistration(client, DeleteType, url, "")
		if response != nil && (response.Status == "204 No Content" || response.Status == "404 Not Found") {
			defer response.Body.Close()
			return nil
		} else {
			handleOIDCClientError(client, response, err, DeleteType, recorder)
			err = fmt.Errorf("Error occurred during delete oidc client regstration")
			return err
		}
	} else {
		return nil
	}
}

func (r *ReconcileClient) invokeRegistration(oidcreg *securityv1.Client, requestType string, requestUrl string, payload string) (*http.Response, error) {
  clientRegistrationSecretName := "platform-oidc-credentials"
  secretObj := &corev1.Secret{}
  err := r.client.Get(context.TODO(), types.NamespacedName{Name: clientRegistrationSecretName, Namespace: oidcreg.GetNamespace()}, secretObj)
  if err != nil {
    log.Error(err, fmt.Sprintf("failed to get secret %q", clientRegistrationSecretName))
    return nil, err
  } 
  log.Info(fmt.Sprintf("Retrieved secret %q", clientRegistrationSecretName))
  oauthAdmin := "oauthadmin"
  clientRegistrationSecret := string(secretObj.Data["OAUTH2_CLIENT_REGISTRATION_SECRET"])

	req, _ := http.NewRequest(requestType, requestUrl, bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(oauthAdmin, clientRegistrationSecret)
	//caCert, err := ioutil.ReadFile("/certs/ca.crt")
	//if err != nil {
	//	return nil, err
	//}
	caCertPool := x509.NewCertPool()
	//caCertPool.AppendCertsFromPEM(caCert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caCertPool}}
	client := &http.Client{Transport: transport}
  resp, err := client.Do(req)
	if resp != nil && resp.StatusCode >= 400 {
		errorDetails, _ := ioutil.ReadAll(resp.Body)
		log.Error(err, fmt.Sprintf("Invoke registration has failed: %s", string(errorDetails)))
		err1 := errors.New(string(errorDetails))
		return nil, err1
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (r *ReconcileClient) getClientCredentials(oidcreg *securityv1.Client, recorder record.EventRecorder) (*http.Response, error) {
	clientId := oidcreg.Spec.ClientId
	url := strings.Join([]string{authServiceUrl, "/oidc/endpoint/OP/registration/", clientId}, "")
	response, err := r.invokeRegistration(oidcreg, GetType, url, "")
	if response != nil && response.Status == "200 OK" {
		return response, nil
	} else {
		handleOIDCClientError(oidcreg, response, err, GetType, recorder)
		err = fmt.Errorf("Error occurred while getting oidc client registration")
		return nil, err
	}
}

func (r *ReconcileClient) ClientIdExists(client *securityv1.Client, recorder record.EventRecorder) (bool, *ClientCredentials, error) {
	clientId := client.Spec.ClientId
	if clientId != "" {
		resp, err := r.getClientCredentials(client, recorder)
		if err != nil {
			return false, nil, err
		} else if clientId != "" && resp.Status == "200 OK" {
			clientCreds, errRes := r.getCredentialsFromResponse(resp)
			if errRes != nil {
				return false, nil, errRes
			} else {
				return true, clientCreds, nil
			}
		} else {
			return false, nil, nil
		}
	} else {
		return false, nil, nil
	}
}

func (r *ReconcileClient) getCredentialsFromResponse(response *http.Response) (*ClientCredentials, error) {
	responseObj := &OidcClientResponse{}
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	defer response.Body.Close()
	regRespone := buf.String()
	errParse := json.Unmarshal([]byte(regRespone), responseObj)
	if errParse == nil {
		clientCred := &ClientCredentials{
			CLIENT_ID:     responseObj.ClientID,
			CLIENT_SECRET: responseObj.ClientSecret,
		}
		return clientCred, nil
	} else {
		return nil, errParse
	}
}

func (r *ReconcileClient) generateClientCredentials(serviceName string) *ClientCredentials {
	log.Info("OidcClient-Watcher, Generate ClientID & Secret")
	rule := `^([a-z0-9]){32,}$`
	clientId := generateRandomString(rule)
	clientSecret := generateRandomString(rule)

	//masterNodesList := os.Getenv("MASTER_NODES_LIST")
	//randomString := string(SecureRandomAlphaString(30))
	//  clientIdData := []byte(strings.Join([]string{masterNodesList,serviceName,"id", randomString},""))
	//  clientIdHash := sha256.Sum256(clientIdData)
	//  clientId := hex.EncodeToString(clientIdHash[:])
	//  clientSecretData := []byte(strings.Join([]string{masterNodesList,serviceName,"secret", randomString},""))
	//  clientSecretHash := sha256.Sum256(clientSecretData)
	//  clientSecret := hex.EncodeToString(clientSecretHash[:])

	return &ClientCredentials{
		CLIENT_ID:     clientId,
		CLIENT_SECRET: clientSecret,
	}
}

func generateRandomString(rule string) string {

	generator, _ := regen.NewGenerator(rule, &regen.GeneratorArgs{
		RngSource:               rand.NewSource(time.Now().UnixNano()),
		MaxUnboundedRepeatCount: 1})
	randomString := generator.Generate()
	return randomString
}

func SecureRandomAlphaString(length int) string {

	result := make([]byte, length)
	bufferSize := int(float64(length) * 1.3)
	for i, j, randomBytes := 0, 0, []byte{}; i < length; j++ {
		if j%bufferSize == 0 {
			randomBytes = SecureRandomBytes(bufferSize)
		}
		if idx := int(randomBytes[j%length] & letterIdxMask); idx < len(letterBytes) {
			result[i] = letterBytes[idx]
			i++
		}
	}

	return string(result)
}

// SecureRandomBytes returns the requested number of bytes using crypto/rand
func SecureRandomBytes(length int) []byte {
	var randomBytes = make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		fmt.Println("Unable to generate random bytes")
	}
	return randomBytes
}

func (r *ReconcileClient) generateClientRegistrationPayload(oidcreg *securityv1.Client, clientCred *ClientCredentials) string {
	payloadJSON := map[string]interface{}{
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid profile email",
		"client_id":                  clientCred.CLIENT_ID,
		"client_secret":              clientCred.CLIENT_SECRET,
		"grant_types": []string{
			"authorization_code",
			"client_credentials",
			"password",
			"implicit",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"response_types": []string{
			"code",
			"token",
			"id_token token"},
		"application_type":          "web",
		"subject_type":              "public",
		"post_logout_redirect_uris": oidcreg.Spec.OidcLibertyClient.LogoutUris,
		"preauthorized_scope":       "openid profile email general",
		"introspect_tokens":         true,
		"trusted_uri_prefixes":      oidcreg.Spec.OidcLibertyClient.TrustedUris,
		"redirect_uris":             oidcreg.Spec.OidcLibertyClient.RedirectUris}
	payloadBytes, _ := json.Marshal(payloadJSON)
	payload := string(payloadBytes[:])
	return payload
}

// GetZenInstance returns the zen instance or nil if it does not exist
func (r *ReconcileClient) GetZenInstance(client *securityv1.Client) (*ZenInstance, error) {

	if client.Spec.ZenInstanceId == "" {
		return nil, fmt.Errorf("Zen instance id is required to query a zen instance")
	}

	idmgmtURL := os.Getenv("IDENTITY_MGMT_URL")
	requestURL := strings.Join([]string{idmgmtURL, "/identity/api/v1/zeninstance/", client.Spec.ZenInstanceId}, "")

	response, err := utils.InvokeIamApi(utils.GetType, requestURL, "")

	if err != nil {
		return nil, err
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
func (r *ReconcileClient) DeleteZenInstance(client *securityv1.Client) error {

	if client.Spec.ZenInstanceId == "" {
		return fmt.Errorf("Zen instance id is required to delete a zen instance")
	}

	idmgmtURL := os.Getenv("IDENTITY_MGMT_URL")
	requestURL := strings.Join([]string{idmgmtURL, "/identity/api/v1/zeninstance/", client.Spec.ZenInstanceId}, "")

	response, err := utils.InvokeIamApi(utils.DeleteType, requestURL, "")

	if err != nil {
		return err
	}
	if response != nil {
		if response.StatusCode == 200 {
			//zen instance deleted
			return nil
		}
		//Read response body
		buf := new(bytes.Buffer)
		buf.ReadFrom(response.Body)

		return fmt.Errorf("An error occurred while deleting the zen instance: Status:%s Msg:%s", response.Status, buf.String())
	}

	return fmt.Errorf("No response was received from query of zen instance %s", client.Spec.ZenInstanceId)
}

// CreateZenInstance registers the zen instance with the iam identity mgmt service
func (r *ReconcileClient) CreateZenInstance(client *securityv1.Client) error {
	payloadJSON := map[string]interface{}{
		"clientId":       client.Spec.ClientId,
		"instanceId":     client.Spec.ZenInstanceId,
		"productNameUrl": client.Spec.ZenProductNameUrl,
		"namespace":      client.Namespace,
	}
	payloadBytes, _ := json.Marshal(payloadJSON)
	payload := string(payloadBytes[:])

	idmgmtURL := os.Getenv("IDENTITY_MGMT_URL")
	requestURL := strings.Join([]string{idmgmtURL, "/identity/api/v1/zeninstance"}, "")

	response, err := utils.InvokeIamApi(utils.PostType, requestURL, payload)
	if response != nil && response.Status == "200 OK" {
		return nil
	}
	if err != nil {
		return err
	}
	//Determine error and report
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	errorMsg := buf.String()
	err = fmt.Errorf("An error occurred while registering the zen instance: Status:%s Msg:%s", response.Status, errorMsg)
	return err
}
