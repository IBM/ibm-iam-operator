/*
Copyright 2022.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CertificateSpec defines the desired state of Certificate
type CertificateSpec struct {
	// CommonName is a common name to be used on the Certificate.
	// If no CommonName is given, then the first entry in DNSNames is used as
	// the CommonName.
	// The CommonName should have a length of 64 characters or fewer to avoid
	// generating invalid CSRs; in order to have longer domain names, set the
	// CommonName (or first DNSNames entry) to have 64 characters or fewer,
	// and then add the longer domain name to DNSNames.
	// +optional
	CommonName string `json:"commonName,omitempty"`

	// Certificate default Duration
	// +optional
	Duration *metav1.Duration `json:"duration,omitempty"`

	// Certificate renew before expiration duration
	// +optional
	RenewBefore *metav1.Duration `json:"renewBefore,omitempty"`

	// DNSNames is a list of subject alt names to be used on the Certificate.
	// If no CommonName is given, then the first entry in DNSNames is used as
	// the CommonName and must have a length of 64 characters or fewer.
	// +optional
	// +nullable
	DNSNames []string `json:"dnsNames,omitempty"`

	// IPAddresses is a list of IP addresses to be used on the Certificate
	// +optional
	// +nullable
	IPAddresses []string `json:"ipAddresses,omitempty"`

	// SecretName is the name of the secret resource to store this secret in
	SecretName string `json:"secretName"`

	// IssuerRef is a reference to the issuer for this certificate.
	// If the 'kind' field is not set, or set to 'Issuer', an Issuer resource
	// with the given name in the same namespace as the Certificate will be used.
	// If the 'kind' field is set to 'ClusterIssuer', a ClusterIssuer with the
	// provided name will be used.
	// The 'name' field in this stanza is required at all times.
	IssuerRef ObjectReference `json:"issuerRef"`

	// IsCA will mark this Certificate as valid for signing.
	// This implies that the 'cert sign' usage is set
	// +optional
	IsCA bool `json:"isCA,omitempty"`
}

// CertificateStatus defines the observed state of Certificate
type CertificateStatus struct {
	// +optional
	Conditions []CertificateCondition `json:"conditions,omitempty"`

	// +optional
	LastFailureTime *metav1.Time `json:"lastFailureTime,omitempty"`

	// The expiration time of the certificate stored in the secret named
	// by this resource in spec.secretName.
	// +optional
	NotAfter *metav1.Time `json:"notAfter,omitempty"`
}

// CertificateCondition contains condition information for an Certificate.
type CertificateCondition struct {
	// Type of the condition, currently ('Ready').
	Type CertificateConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
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
type CertificateConditionType string

const (
	// CertificateConditionReady indicates that a certificate is ready for use.
	// This is defined as:
	// - The target secret exists
	// - The target secret contains a certificate that has not expired
	// - The target secret contains a private key valid for the certificate
	// - The commonName and dnsNames attributes match those specified on the Certificate
	CertificateConditionReady CertificateConditionType = "Ready"
)

//+kubebuilder:object:root=true

// Certificate is the Schema for the certificates API. Documentation For additional details regarding install parameters check: https://ibm.biz/icpfs39install. License By installing this product you accept the license terms https://ibm.biz/icpfs39license.
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Secret",type="string",JSONPath=".spec.secretName",description=""
// +kubebuilder:printcolumn:name="Issuer",type="string",JSONPath=".spec.issuerRef.name",description="",priority=1
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message",priority=1
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="CreationTimestamp is a timestamp representing the server time when this object was created. It is not guaranteed to be set in happens-before order across separate operations. Clients may not set this value. It is represented in RFC3339 form and is in UTC."
// +kubebuilder:printcolumn:name="Expiration",type="string",JSONPath=".status.notAfter"
// +kubebuilder:resource:path=certificates,shortName=cert;certs,scope=Namespaced
type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateSpec   `json:"spec,omitempty"`
	Status CertificateStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CertificateList contains a list of Certificate
type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Certificate `json:"items"`
}

// ConditionStatus represents a condition's status.
// +kubebuilder:validation:Enum=True;False;Unknown
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

// ObjectReference is a reference to an object with a given name, kind and group.
type ObjectReference struct {
	Name string `json:"name"`
	// +optional
	Kind string `json:"kind,omitempty"`
	// +optional
	Group string `json:"group,omitempty"`
}

const (
	CertificateKind = "Certificate"
)

var _ client.Object = &Certificate{}

func init() {
	SchemeBuilder.Register(
		&Certificate{},
		&CertificateList{},
	)
}