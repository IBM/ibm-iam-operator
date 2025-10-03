/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oidcsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/api/oidc.security/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ZenInstance represents the zen instance model (response from post, get)
type ZenInstance struct {
	ClientID       string `json:"clientId"`
	InstanceId     string `json:"instanceId"`
	ProductNameUrl string `json:"productNameUrl"`
	Namespace      string `json:"namespace"`
	ZenAuditUrl    string `json:"zenAuditUrl"`
}

// getZenInstanceRegistration gets the requested Zen instance registration using the ID Management API.
func (r *ClientReconciler) getZenInstanceRegistration(ctx context.Context, clientCR *oidcsecurityv1.Client, servicesNamespace string) (zenInstance *ZenInstance, err error) {
	log := logf.FromContext(ctx)
	var response *http.Response
	if clientCR.Spec.ZenInstanceId == "" {
		return nil, fmt.Errorf("Zen instance id is required to query a Zen instance")
	}

	var identityManagementURL string
	identityManagementURL, err = r.getServiceURL(ctx, servicesNamespace, IdentityManagementURLKey)
	if err != nil {
		log.Error(err, "Tried to get identity provider url while getting client registration but failed")
		return
	}
	requestURLSplit := []string{identityManagementURL, "identity", "api", "v1", "zeninstance", clientCR.Spec.ZenInstanceId}
	requestURL := strings.Join(requestURLSplit, "/")

	response, err = r.invokeIamApi(ctx, clientCR, http.MethodGet, requestURL, "", servicesNamespace)
	switch v := err.(type) {
	case *OIDCClientRegistrationError:
		// Return no response or error if the OIDC client isn't found given a token couldn't be retrieved
		if v.response != nil && v.response.StatusCode == 404 {
			return nil, nil
		}
		return
	case error:
		return nil, NewZenClientRegistrationError(
			clientCR.Spec.ClientId,
			http.MethodGet,
			clientCR.Spec.ZenInstanceId,
			v.Error(),
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
					clientCR.Spec.ClientId,
					http.MethodGet,
					clientCR.Spec.ZenInstanceId,
					err.Error(),
					response,
				)
			}
			return zenInstance, nil
		}
		return nil, NewZenClientRegistrationError(
			clientCR.Spec.ClientId,
			http.MethodGet,
			clientCR.Spec.ZenInstanceId,
			fmt.Sprintf("An error occurred while querying the zen instance: Status:%s Msg:%s", response.Status, buf.String()),
			response,
		)
	}

	return nil, NewZenClientRegistrationError(
		clientCR.Spec.ClientId,
		http.MethodGet,
		clientCR.Spec.ZenInstanceId,
		fmt.Sprintf("no response was recieved from query of Zen instance %s", clientCR.Spec.ZenInstanceId),
		response,
	)
}

// unregisterZenInstance deletes the requested zen instance registration using the ID Management API.
func (r *ClientReconciler) unregisterZenInstance(ctx context.Context, clientCR *oidcsecurityv1.Client, servicesNamespace string) (err error) {
	log := logf.FromContext(ctx)
	if clientCR.Spec.ZenInstanceId == "" {
		return fmt.Errorf("Zen instance id is required to delete a Zen instance registration")
	}

	var identityManagementURL string
	identityManagementURL, err = r.getServiceURL(ctx, servicesNamespace, IdentityManagementURLKey)
	if err != nil {
		log.Error(err, "Tried to get identity provider url while getting client registration but failed")
		return
	}
	requestURLSplit := []string{identityManagementURL, "identity", "api", "v1", "zeninstance", clientCR.Spec.ZenInstanceId}
	requestURL := strings.Join(requestURLSplit, "/")
	response, err := r.invokeIamApi(ctx, clientCR, http.MethodDelete, requestURL, "", servicesNamespace)
	switch v := err.(type) {
	case *OIDCClientRegistrationError:
		// Return no response or error if the OIDC client isn't found given a token couldn't be retrieved
		if v.response != nil && v.response.StatusCode == 404 {
			return nil
		}
		return
	case error:
		return NewZenClientRegistrationError(
			clientCR.Spec.ClientId,
			http.MethodGet,
			clientCR.Spec.ZenInstanceId,
			v.Error(),
			response,
		)
	}

	if response != nil {
		if response.StatusCode == 200 {
			//zen instance deleted
			return
		}
		//Read response body
		buf := new(bytes.Buffer)
		buf.ReadFrom(response.Body)

		return fmt.Errorf("an error occurred while deleting the Zen instance registration: Status:%s Msg:%s", response.Status, buf.String())
	}

	return fmt.Errorf("no response was received from query of Zen instance %s", clientCR.Spec.ZenInstanceId)
}

// registerZenInstance registers a Zen instance with the ID Management API.
func (r *ClientReconciler) registerZenInstance(ctx context.Context, clientCR *oidcsecurityv1.Client, clientCreds *ClientCredentials, servicesNamespace string) (err error) {
	log := logf.FromContext(ctx)
	payloadJSON := map[string]interface{}{
		"clientId":       clientCR.Spec.ClientId,
		"clientSecret":   string(clientCreds.ClientSecret),
		"instanceId":     clientCR.Spec.ZenInstanceId,
		"productNameUrl": clientCR.Spec.ZenProductNameUrl,
		"namespace":      clientCR.Namespace,
		"zenAuditUrl":    clientCR.Spec.ZenAuditUrl,
	}
	payloadBytes, _ := json.Marshal(payloadJSON)
	payload := string(payloadBytes[:])

	var identityManagementURL string
	identityManagementURL, err = r.getServiceURL(ctx, servicesNamespace, IdentityManagementURLKey)
	if err != nil {
		log.Error(err, "Tried to get identity provider url while getting client registration but failed")
		return
	}
	requestURLSplit := []string{identityManagementURL, "identity", "api", "v1", "zeninstance"}
	requestURL := strings.Join(requestURLSplit, "/")

	response, err := r.invokeIamApi(ctx, clientCR, http.MethodPost, requestURL, payload, servicesNamespace)
	switch v := err.(type) {
	case *OIDCClientRegistrationError:
		// Return no response or error if the OIDC client isn't found given a token couldn't be retrieved
		if v.response != nil && v.response.StatusCode == 404 {
			return nil
		}
		return
	case error:
		return NewZenClientRegistrationError(
			clientCR.Spec.ClientId,
			http.MethodGet,
			clientCR.Spec.ZenInstanceId,
			v.Error(),
			response,
		)
	}

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
	err = fmt.Errorf("an error occurred while registering the Zen instance: Status:%s Msg:%s", response.Status, errorMsg)
	return
}
