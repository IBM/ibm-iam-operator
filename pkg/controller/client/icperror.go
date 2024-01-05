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
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	oidcv1 "github.com/IBM/ibm-iam-operator/pkg/apis/oidc/v1"
	corev1 "k8s.io/api/core/v1"
)

type OIDCClientError struct {
	Description string `json:"error_description"`
}

func (e *OIDCClientError) Error() string {
	return e.Description
}

// ConditionStatus represents a condition's status.
//type EventType string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not. In the future, we could add other intermediate
// conditions, e.g. ConditionDegraded.
const (
	MessageCreateClientSuccessful             = "OIDC client registration create successful"
	MessageUpdateClientSuccessful             = "OIDC client registration update successful"
	MessageClientSuccessful                   = "OIDC client registration successful"
	MessageCreateClientFailed                 = "OIDC client registration create failed"
	MessageCreateZenRegistrationFailed        = "Registration of the Zen Instance failed"
	MessageUnknown                     string = "Unexpected error occurred while processing the request"

	ReasonCreateClientSuccessful             = "CreateClientSuccessful"
	ReasonCreateClientFailed                 = "CreateClientFailed"
	ReasonUpdateClientSuccessful             = "UpdateClientSuccessful"
	ReasonUpdateClientFailed                 = "UpdateClientFailed"
	ReasonGetClientFailed                    = "GetClientFailed"
	ReasonDeleteClientFailed                 = "DeleteClientFailed"
	ReasonCreateZenRegistrationFailed        = "CreateZenRegistrationFailed"
	ReasonUnknown                     string = "Unknown"
)

// NewOIDCClientError produces a new OIDCClientError by attempting to unmarshal the response body JSON into an
// OIDCClientError's Description field.
func NewOIDCClientError(response *http.Response) (oidcErr *OIDCClientError) {
	if response == nil || response.Body == nil {
		return nil
	}
	defer response.Body.Close()
	bodyBuffer, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return &OIDCClientError{
			Description: MessageUnknown,
		}
	}
	err = json.Unmarshal(bodyBuffer, oidcErr)
	if err != nil {
		return &OIDCClientError{
			Description: MessageUnknown,
		}
	}
	return
}

func (r *ReconcileClient) handleOIDCClientError(ctx context.Context, client *oidcv1.Client, err error, requestType string) {
	var errorMessage, reason string
	switch requestType {
	case PostType:
		reason = ReasonCreateClientFailed
	case PutType:
		reason = ReasonUpdateClientFailed
	case GetType:
		reason = ReasonGetClientFailed
	case DeleteType:
		reason = ReasonDeleteClientFailed
	default:
		reason = ReasonUnknown
	}

	errorMessage = err.Error()

	if requestType == PostType {
		SetClientCondition(client,
			oidcv1.ClientConditionReady,
			oidcv1.ConditionFalse,
			reason,
			MessageCreateClientFailed)
	}
	r.recorder.Event(client, corev1.EventTypeWarning, reason, errorMessage)
}
