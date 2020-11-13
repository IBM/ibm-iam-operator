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

// OIDCClientWatcherSpec defines the desired state of OIDCClientWatcher
type OIDCClientWatcherSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	OperatorVersion          string                       `json:"operatorVersion,omitempty"`
	Replicas                 int32                        `json:"replicas"`
	Resources                *corev1.ResourceRequirements `json:"resources,omitempty"`
	ImageRegistry            string                       `json:"imageRegistry,omitempty"`
	ImageTagPostfix          string                       `json:"imageTagPostfix,omitempty"`
	OidcInitAuthService      OidcInitAuthServiceSpec      `json:"oidcInitAuthService,omitempty"`
	OidcInitIdentityProvider OidcInitIdentityProviderSpec `json:"oidcInitIdentityProvider,omitempty"`
	OidcInitIdentityManager  OidcInitIdentityManagerSpec  `json:"oidcInitIdentityManager,omitempty"`
}

type OidcInitAuthServiceSpec struct {
	ImageRegistry string `json:"imageRegistry,omitempty"`
	ImageName     string `json:"imageName,omitempty"`
	ImageTag      string `json:"imageTag,omitempty"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type OidcInitIdentityProviderSpec struct {
	ImageRegistry string `json:"imageRegistry,omitempty"`
	ImageName     string `json:"imageName,omitempty"`
	ImageTag      string `json:"imageTag,omitempty"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type OidcInitIdentityManagerSpec struct {
	ImageRegistry string                       `json:"imageRegistry,omitempty"`
	ImageName     string                       `json:"imageName,omitempty"`
	ImageTag      string                       `json:"imageTag,omitempty"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

// OIDCClientWatcherStatus defines the observed state of OIDCClientWatcher
type OIDCClientWatcherStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Nodes []string `json:"nodes"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OIDCClientWatcher is the Schema for the oidcclientwatchers API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=oidcclientwatchers,scope=Namespaced
type OIDCClientWatcher struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OIDCClientWatcherSpec   `json:"spec,omitempty"`
	Status OIDCClientWatcherStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OIDCClientWatcherList contains a list of OIDCClientWatcher
type OIDCClientWatcherList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OIDCClientWatcher `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OIDCClientWatcher{}, &OIDCClientWatcherList{})
}
