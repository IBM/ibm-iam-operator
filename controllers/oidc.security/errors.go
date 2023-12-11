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
	"encoding/json"
	"fmt"
	"net/http"
)

type clientIDed interface {
	ClientID() string
}
type httpTyped interface {
	RequestMethod() string
	Response() *http.Response
}
type zenInstanced interface {
	ZenInstanceId() string
}

// OIDCClientRegistrationError is an error for any issue that occurs while interacting with OIDC Client registrations.
type OIDCClientRegistrationError struct {
	Description   string `json:"error_description"`
	clientID      string
	requestMethod string
	response      *http.Response
}

// NewOIDCClientRegistrationError produces a new OIDCClientError by attempting to unmarshal the response body JSON into an
// OIDCClientRegistrationError's description field.
func NewOIDCClientRegistrationError(clientID, requestMethod, origErrMsg string, response *http.Response) (oidcErr *OIDCClientRegistrationError) {
	oidcErr = &OIDCClientRegistrationError{
		clientID:      clientID,
		Description:   MessageUnknown,
		requestMethod: requestMethod,
		response:      response,
	}
	if origErrMsg != "" {
		oidcErr.Description = origErrMsg
		return
	}
	if response == nil || response.Body == nil {
		return
	}
	defer response.Body.Close()

	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(response.Body)
	if err != nil {
		return
	}
	bodyBytes := buf.Bytes()
	err = json.Unmarshal(bodyBytes, oidcErr)
	// If unmarshal doesn't work, fail over to using the body directly
	if err != nil {
		oidcErr.Description = string(bodyBytes)
		return
	}
	return
}

func (e *OIDCClientRegistrationError) Error() string {
	var verb string
	switch e.requestMethod {
	case http.MethodPost:
		verb = "create"
	case http.MethodPut:
		verb = "update"
	case http.MethodDelete:
		verb = "delete"
	case http.MethodGet:
		verb = "get"
	}
	return fmt.Sprintf("failed to %s OIDC client %s: %s", verb, e.clientID, e.Description)
}

func (e *OIDCClientRegistrationError) ClientID() string {
	return e.clientID
}

func (e *OIDCClientRegistrationError) RequestMethod() string {
	return e.requestMethod
}

func (e *OIDCClientRegistrationError) Response() *http.Response {
	return e.response
}

// OIDCClientRegistrationError implements the following interfaces
var _ clientIDed = &OIDCClientRegistrationError{}
var _ httpTyped = &OIDCClientRegistrationError{}

// ZenClientRegistrationError is an error for any issue that occurs while interacting with a Zen instance.
type ZenClientRegistrationError struct {
	clientID      string
	Description   string
	requestMethod string // e.g. "GET"
	response      *http.Response
	zenInstanceId string
}

// NewZenClientRegistrationError produces a new ZenClientRegistrationError by attempting to unmarshal the response body
// JSON into an ZenClientRegistrationError's description field.
func NewZenClientRegistrationError(clientID, requestMethod, zenInstanceId, origErrMsg string, response *http.Response) (zenErr *ZenClientRegistrationError) {
	zenErr = &ZenClientRegistrationError{
		clientID:      clientID,
		requestMethod: requestMethod,
		response:      response,
		Description:   MessageUnknown,
		zenInstanceId: zenInstanceId,
	}
	if origErrMsg != "" {
		zenErr.Description = origErrMsg
		return
	}
	return
}

func (e *ZenClientRegistrationError) Error() string {
	var verb string
	switch e.requestMethod {
	case http.MethodPost:
		verb = "create"
	case http.MethodPut:
		verb = "update"
	case http.MethodDelete:
		verb = "delete"
	case http.MethodGet:
		verb = "get"
	}
	return fmt.Sprintf("failed to %s Zen registration for OIDC client %s on instance with ID %s: %s", verb, e.clientID, e.zenInstanceId, e.Description)
}

func (e *ZenClientRegistrationError) ClientID() string {
	return e.clientID
}

func (e *ZenClientRegistrationError) RequestMethod() string {
	return e.requestMethod
}

func (e *ZenClientRegistrationError) Response() *http.Response {
	return e.response
}

func (e *ZenClientRegistrationError) ZenInstanceId() string {
	return e.zenInstanceId
}

// ZenClientRegistrationError implements the following interfaces
var _ clientIDed = &ZenClientRegistrationError{}
var _ httpTyped = &ZenClientRegistrationError{}
var _ zenInstanced = &ZenClientRegistrationError{}

// IsOIDCError returns whether the error is related to an attempt to register OIDC Client or an existing OIDC Client
func IsOIDCError(err error) bool {
	if err == nil {
		return false
	}
	oidcErr, ok := err.(clientIDed)
	return ok && oidcErr.ClientID() != ""
}

// IsHTTPError returns whether the error is the result of an HTTP connection that has failed in some way
func IsHTTPError(err error) bool {
	if err == nil {
		return false
	}
	reqErr, ok := err.(httpTyped)
	return ok && reqErr.RequestMethod() != ""
}

// IsZenError returns whether the error relates to a failure received when interacting with Zen
func IsZenError(err error) bool {
	if err == nil {
		return false
	}
	zenErr, ok := err.(zenInstanced)
	return ok && zenErr.ZenInstanceId() != ""
}
