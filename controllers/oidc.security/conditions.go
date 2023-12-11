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
	"context"
	"net/http"

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/apis/oidc.security/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

// writeErrorConditionsAndEvents updates a Client CR's`.status.conditions` and writes an event related to the outcome.
// It is a no-op if err is nil.
func (r *ClientReconciler) writeErrorConditionsAndEvents(ctx context.Context, clientCR *oidcsecurityv1.Client, err error, requestMethod string) (statusUpdateErr error) {
	//reqLogger := logf.FromContext(ctx).WithValues("clientId", clientCR.Spec.ClientId, "namespace", clientCR.Namespace)
	var condition metav1.Condition
	if err == nil {
		return
	}

	// If the error doesn't relate to a failure of or transmitted by HTTP, this isn't a OIDC or Zen registration
	// problem
	httpErr, ok := err.(httpTyped)
	if !ok {
		condition = metav1.Condition{
			Type:    oidcsecurityv1.ClientConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  ReasonUnknown,
			Message: err.Error(),
		}
		meta.SetStatusCondition(&clientCR.Status.Conditions, condition)

		statusUpdateErr = r.Client.Status().Update(ctx, clientCR)
		return
	}

	// As for Zen, only report Zen client problems as registration creation issues
	if IsZenError(err) {
		condition = metav1.Condition{
			Type:    oidcsecurityv1.ClientConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  ReasonCreateZenRegistrationFailed,
			Message: MessageCreateZenRegistrationFailed,
		}
		meta.SetStatusCondition(&clientCR.Status.Conditions, condition)

		statusUpdateErr = r.Client.Status().Update(ctx, clientCR)
		r.Recorder.Event(clientCR, corev1.EventTypeWarning, ReasonCreateZenRegistrationFailed, err.Error())
		return
	}

	var reason string
	switch httpErr.RequestMethod() {
	case http.MethodPost:
		reason = ReasonCreateClientFailed
		condition = metav1.Condition{
			Type:    oidcsecurityv1.ClientConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: MessageCreateClientFailed,
		}
		meta.SetStatusCondition(&clientCR.Status.Conditions, condition)

		statusUpdateErr = r.Client.Status().Update(ctx, clientCR)
	case http.MethodPut:
		reason = ReasonUpdateClientFailed
	case http.MethodGet:
		reason = ReasonGetClientFailed
	case http.MethodDelete:
		reason = ReasonDeleteClientFailed
	default:
		reason = ReasonUnknown
	}

	r.Recorder.Event(clientCR, corev1.EventTypeWarning, reason, err.Error())
	return
}
