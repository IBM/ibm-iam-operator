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
	"encoding/json"
	"net/http"

	condition "github.com/IBM/ibm-iam-operator/pkg/api/util"
	securityv1 "github.com/IBM/ibm-iam-operator/pkg/apis/oidc/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

type OidcClientError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
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

func handleOIDCClientError(oidcreg *securityv1.Client, response *http.Response, err error, requestType string, recorder record.EventRecorder) {
	var errorMessage, reason string
	errorObj := &OidcClientError{}

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

	if err == nil {
		buf := new(bytes.Buffer)
		buf.ReadFrom(response.Body)
		errorMsg := buf.String()
		errParse := json.Unmarshal([]byte(errorMsg), errorObj)
		if errParse == nil {
			errorMessage = errorObj.Description
		} else {
			errorMessage = MessageUnknown
		}
	} else {
		errorMessage = err.Error()
	}

	if requestType == PostType {
		condition.SetClientCondition(oidcreg,
			securityv1.ClientConditionReady,
			securityv1.ConditionFalse,
			reason,
			MessageCreateClientFailed)
	}
	recorder.Event(oidcreg, corev1.EventTypeWarning, reason, errorMessage)
  // If the response is non-nil and Body is non-nil, attempt to close
  if response != nil && response.Body != nil {
    defer response.Body.Close()
  }
}
