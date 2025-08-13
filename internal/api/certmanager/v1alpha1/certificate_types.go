//
// Copyright 2025 IBM Corporation
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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Certificate is the Schema for the certificates API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=certificates,scope=Namespaced
type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateSpec   `json:"spec,omitempty"`
	Status CertificateStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CertificateList contains a list of Certificate
type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Certificate `json:"items"`
}

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

	// Organization is the organization to be used on the Certificate
	// +optional
	Organization []string `json:"organization,omitempty"`

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
	DNSNames []string `json:"dnsNames,omitempty"`

	// IPAddresses is a list of IP addresses to be used on the Certificate
	// +optional
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

	// Usages is the set of x509 actions that are enabled for a given key. Defaults are ('digital signature', 'key encipherment') if empty
	// +optional
	Usages []KeyUsage `json:"usages,omitempty"`

	// ACME contains configuration specific to ACME Certificates.
	// Notably, this contains details on how the domain names listed on this
	// Certificate resource should be 'solved', i.e. mapping HTTP01 and DNS01
	// providers to DNS names.
	// +optional
	ACME *ACMECertificateConfig `json:"acme,omitempty"`

	// KeySize is the key bit size of the corresponding private key for this certificate.
	// If provided, value must be between 2048 and 8192 inclusive when KeyAlgorithm is
	// empty or is set to "rsa", and value must be one of (256, 384, 521) when
	// KeyAlgorithm is set to "ecdsa".
	// +optional
	KeySize int `json:"keySize,omitempty"`

	// KeyAlgorithm is the private key algorithm of the corresponding private key
	// for this certificate. If provided, allowed values are either "rsa" or "ecdsa"
	// If KeyAlgorithm is specified and KeySize is not provided,
	// key size of 256 will be used for "ecdsa" key algorithm and
	// key size of 2048 will be used for "rsa" key algorithm.
	// +optional
	KeyAlgorithm KeyAlgorithm `json:"keyAlgorithm,omitempty"`

	// KeyEncoding is the private key cryptography standards (PKCS)
	// for this certificate's private key to be encoded in. If provided, allowed
	// values are "pkcs1" and "pkcs8" standing for PKCS#1 and PKCS#8, respectively.
	// If KeyEncoding is not specified, then PKCS#1 will be used by default.
	KeyEncoding KeyEncoding `json:"keyEncoding,omitempty"`
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

func init() {
	SchemeBuilder.Register(&Certificate{}, &CertificateList{})
}
