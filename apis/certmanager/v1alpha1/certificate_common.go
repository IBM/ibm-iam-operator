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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	ClusterIssuerKind      = "ClusterIssuer"
	IssuerKind             = "Issuer"
	CertificateKind        = "Certificate"
	CertificateRequestKind = "CertificateRequest"
	OrderKind              = "Order"
)

// KeyUsage specifies valid usage contexts for keys.
// See: https://tools.ietf.org/html/rfc5280#section-4.2.1.3
//
//	https://tools.ietf.org/html/rfc5280#section-4.2.1.12
//
// +kubebuilder:validation:Enum="signing";"digital signature";"content commitment";"key encipherment";"key agreement";
//
//	"data encipherment";"cert sign";"crl sign";"encipher only";"decipher only";"any";"server auth";"client auth";
//	"code signing";"email protection";"s/mime";"ipsec end system";"ipsec tunnel";"ipsec user";"timestamping";
//	"ocsp signing";"microsoft sgc";"netscape sgc"
type KeyUsage string

const (
	UsageSigning            KeyUsage = "signing"
	UsageDigitalSignature   KeyUsage = "digital signature"
	UsageContentCommittment KeyUsage = "content commitment"
	UsageKeyEncipherment    KeyUsage = "key encipherment"
	UsageKeyAgreement       KeyUsage = "key agreement"
	UsageDataEncipherment   KeyUsage = "data encipherment"
	UsageCertSign           KeyUsage = "cert sign"
	UsageCRLSign            KeyUsage = "crl sign"
	UsageEncipherOnly       KeyUsage = "encipher only"
	UsageDecipherOnly       KeyUsage = "decipher only"
	UsageAny                KeyUsage = "any"
	UsageServerAuth         KeyUsage = "server auth"
	UsageClientAuth         KeyUsage = "client auth"
	UsageCodeSigning        KeyUsage = "code signing"
	UsageEmailProtection    KeyUsage = "email protection"
	UsageSMIME              KeyUsage = "s/mime"
	UsageIPsecEndSystem     KeyUsage = "ipsec end system"
	UsageIPsecTunnel        KeyUsage = "ipsec tunnel"
	UsageIPsecUser          KeyUsage = "ipsec user"
	UsageTimestamping       KeyUsage = "timestamping"
	UsageOCSPSigning        KeyUsage = "ocsp signing"
	UsageMicrosoftSGC       KeyUsage = "microsoft sgc"
	UsageNetscapSGC         KeyUsage = "netscape sgc"
)

// DomainSolverConfig contains solver configuration for a set of domains.
type DomainSolverConfig struct {
	// Domains is the list of domains that this SolverConfig applies to.
	Domains []string `json:"domains"`

	// SolverConfig contains the actual solver configuration to use for the
	// provided set of domains.
	SolverConfig `json:",inline"`
}

// SolverConfig is a container type holding the configuration for either a
// HTTP01 or DNS01 challenge.
// Only one of HTTP01 or DNS01 should be non-nil.
type SolverConfig struct {
	// HTTP01 contains HTTP01 challenge solving configuration
	// +optional
	HTTP01 *HTTP01SolverConfig `json:"http01,omitempty"`

	// DNS01 contains DNS01 challenge solving configuration
	// +optional
	DNS01 *DNS01SolverConfig `json:"dns01,omitempty"`
}

// HTTP01SolverConfig contains solver configuration for HTTP01 challenges.
type HTTP01SolverConfig struct {
	// Ingress is the name of an Ingress resource that will be edited to include
	// the ACME HTTP01 'well-known' challenge path in order to solve HTTP01
	// challenges.
	// If this field is specified, 'ingressClass' **must not** be specified.
	// +optional
	Ingress string `json:"ingress,omitempty"`

	// IngressClass is the ingress class that should be set on new ingress
	// resources that are created in order to solve HTTP01 challenges.
	// This field should be used when using an ingress controller such as nginx,
	// which 'flattens' ingress configuration instead of maintaining a 1:1
	// mapping between loadbalancer IP:ingress resources.
	// If this field is not set, and 'ingress' is not set, then ingresses
	// without an ingress class set will be created to solve HTTP01 challenges.
	// If this field is specified, 'ingress' **must not** be specified.
	// +optional
	IngressClass *string `json:"ingressClass,omitempty"`
}

// DNS01SolverConfig contains solver configuration for DNS01 challenges.
type DNS01SolverConfig struct {
	// Provider is the name of the DNS01 challenge provider to use, as configure
	// on the referenced Issuer or ClusterIssuer resource.
	Provider string `json:"provider"`
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

// ACMECertificateConfig contains the configuration for the ACME certificate provider
type ACMECertificateConfig struct {
	Config []DomainSolverConfig `json:"config"`
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

// +kubebuilder:validation:Enum=rsa;ecdsa
type KeyAlgorithm string

const (
	RSAKeyAlgorithm   KeyAlgorithm = "rsa"
	ECDSAKeyAlgorithm KeyAlgorithm = "ecdsa"
)

// +kubebuilder:validation:Enum=pkcs1;pkcs8
type KeyEncoding string

const (
	PKCS1 KeyEncoding = "pkcs1"
	PKCS8 KeyEncoding = "pkcs8"
)
