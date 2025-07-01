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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClientSpec defines the desired state of Client
type ClientSpec struct {
	OidcLibertyClient OidcLibertyClient `json:"oidcLibertyClient"`
	Secret            string            `json:"secret"`
	ClientId          string            `json:"clientId"`
	ZenAuditUrl       string            `json:"zenAuditUrl,omitempty"`
	ZenInstanceId     string            `json:"zenInstanceId,omitempty"`
	ZenProductNameUrl string            `json:"zenProductNameUrl,omitempty"`
	Roles             []string          `json:"roles,omitempty"`
}

type OidcLibertyClient struct {
	RedirectUris []string `json:"redirect_uris"`
	TrustedUris  []string `json:"trusted_uri_prefixes"`
	LogoutUris   []string `json:"post_logout_redirect_uris"`
}

// ClientStatus defines the observed state of Client
type ClientStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	LastFailureTime *metav1.Time `json:"lastFailureTime,omitempty"`
}

const (
	// ClientConditionReady indicates that a Client is ready for use.
	ClientConditionReady string = "Ready"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Client is the Schema for the clients API
type Client struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClientSpec   `json:"spec,omitempty"`
	Status ClientStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClientList contains a list of Client
type ClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Client `json:"items"`
}

// ConditionStatus represents a condition's status.
type ConditionStatus string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not. In the future, we could add other intermediate
// conditions, e.g. ConditionDegraded.
const (
	// ConditionTrue represents the fact that a given condition is true
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown
	ConditionUnknown ConditionStatus = "Unknown"
)

// IsCPClientCredentialsEnabled returns whether the fields required for a Client to be granted authentication tokens
// with a Client ID and Secret are set.
func (c *Client) IsCPClientCredentialsEnabled() bool {
	if len(c.Spec.ZenInstanceId) > 0 {
		return len(c.Spec.Roles) > 0 && len(c.Spec.ZenAuditUrl) > 0
	}
	return len(c.Spec.Roles) > 0
}

func init() {
	SchemeBuilder.Register(&Client{}, &ClientList{})
}
