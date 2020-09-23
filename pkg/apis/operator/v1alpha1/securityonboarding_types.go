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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SecurityOnboardingSpec defines the desired state of SecurityOnboarding
type SecurityOnboardingSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	OperatorVersion      string                       `json:"operatorVersion"`
	Replicas             int32                        `json:"replicas"`
	ImageRegistry        string                       `json:"imageRegistry"`
	ImageName            string                       `json:"imageName"`
	ImageTag             string                       `json:"imageTag"`
	Resources            *corev1.ResourceRequirements `json:"resources,omitempty"`
	IAMOnboarding        IAMOnboardingSpec            `json:"iamOnboarding"`
	InitAuthService      InitAuthServiceSpec          `json:"initAuthService"`
	InitIdentityProvider InitIdentityProviderSpec     `json:"initIdentityProvider"`
	InitIdentityManager  InitIdentityManagerSpec      `json:"initIdentityManager"`
	InitTokenService     InitTokenServiceSpec         `json:"initTokenService"`
	InitPAP              InitPAPSpec                  `json:"initPAPSpec"`
	Config               ImpersonationSpec            `json:"impersonation"`
}

type IAMOnboardingSpec struct {
	ImageRegistry string                       `json:"imageRegistry"`
	ImageName     string                       `json:"imageName"`
	ImageTag      string                       `json:"imageTag"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type InitAuthServiceSpec struct {
	ImageRegistry string                       `json:"imageRegistry"`
	ImageName     string                       `json:"imageName"`
	ImageTag      string                       `json:"imageTag"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type InitIdentityProviderSpec struct {
	ImageRegistry string                       `json:"imageRegistry"`
	ImageName     string                       `json:"imageName"`
	ImageTag      string                       `json:"imageTag"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type InitIdentityManagerSpec struct {
	ImageRegistry string                       `json:"imageRegistry"`
	ImageName     string                       `json:"imageName"`
	ImageTag      string                       `json:"imageTag"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type InitTokenServiceSpec struct {
	ImageRegistry string                       `json:"imageRegistry"`
	ImageName     string                       `json:"imageName"`
	ImageTag      string                       `json:"imageTag"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type InitPAPSpec struct {
	ImageRegistry string                       `json:"imageRegistry"`
	ImageName     string                       `json:"imageName"`
	ImageTag      string                       `json:"imageTag"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type ImpersonationSpec struct {
	EnableImpersonation bool `json:"enableImpersonation"`
}

// SecurityOnboardingStatus defines the observed state of SecurityOnboarding
type SecurityOnboardingStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	PodNames []string `json:"podNames"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityOnboarding is the Schema for the securityonboardings API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=securityonboardings,scope=Namespaced
type SecurityOnboarding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecurityOnboardingSpec   `json:"spec,omitempty"`
	Status SecurityOnboardingStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityOnboardingList contains a list of SecurityOnboarding
type SecurityOnboardingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityOnboarding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecurityOnboarding{}, &SecurityOnboardingList{})
}
