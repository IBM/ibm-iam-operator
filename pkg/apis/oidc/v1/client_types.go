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
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ClientSpec defines the desired state of Client
// +k8s:openapi-gen=true
type ClientSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	OidcLibertyClient OidcLibertyClient `json:"oidcLibertyClient"`
	Secret            string            `json:"secret"`
	ClientId          string            `json:"clientId"`
	ZenAuditUrl       string            `json:"zenAuditUrl,omitempty"`
	ZenInstanceId     string            `json:"zenInstanceId,omitempty"`
	ZenProductNameUrl string            `json:"zenProductNameUrl,omitempty"`
	Roles             []string          `json:"roles,omitempty"`
}

type OidcLibertyClient struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	RedirectUris []string `json:"redirect_uris"`
	TrustedUris  []string `json:"trusted_uri_prefixes"`
	LogoutUris   []string `json:"post_logout_redirect_uris"`
}

// ClientStatus defines the observed state of Client
// +k8s:openapi-gen=true
type ClientStatus struct {
	Conditions []ClientCondition `json:"conditions,omitempty"`

	// +optional
	LastFailureTime *metav1.Time `json:"lastFailureTime,omitempty"`
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
}

// CertificateCondition contains condition information for an Certificate.
type ClientCondition struct {
	// Type of the condition, currently ('Ready').
	Type ClientConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	// +kubebuilder:validation:Enum=True;False;Unknown
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

// CertificateConditionType represents an Certificate condition value.
type ClientConditionType string

const (
	// CertificateConditionReady indicates that a certificate is ready for use.
	// This is defined as:
	// - The target secret exists
	// - The target secret contains a certificate that has not expired
	// - The target secret contains a private key valid for the certificate
	// - The commonName and dnsNames attributes match those specified on the Certificate
	ClientConditionReady ClientConditionType = "Ready"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Client is the Schema for the clients API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type Client struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClientSpec   `json:"spec,omitempty"`
	Status ClientStatus `json:"status,omitempty"`
}

// IsCPClientCredentialsEnabled returns whether the fields required for a Client to be granted authentication tokens
// with a Client ID and Secret are set.
func (c *Client) IsCPClientCredentialsEnabled() bool {
	if len(c.Spec.ZenInstanceId) > 0 {
		return len(c.Spec.Roles) > 0 && len(c.Spec.ZenAuditUrl) > 0
	}
	return len(c.Spec.Roles) > 0
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

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

func init() {
	SchemeBuilder.Register(&Client{}, &ClientList{})
}
