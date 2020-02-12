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
	certmgr "github.com/IBM/ibm-iam-operator/pkg/apis/certmanager/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// PapSpec defines the desired state of Pap
type PapSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	OperatorVersion string           `json:"operatorVersion"`
	Replicas        int32            `json:"replicas"`
	PapService      PapServiceSpec   `json:"papService"`
	AuditService    AuditServiceSpec `json:"auditService"`
}

// PapServiceSpec defined the desired state of PapService Container
type PapServiceSpec struct {
	ImageRegistry string `json:"imageRegistry"`
	ImageName     string `json:"imageName"`
	ImageTag      string `json:"imageTag"`
}

// PapStatus defines the observed state of Pap
type PapStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Nodes []string `json:"nodes"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Pap is the Schema for the paps API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=paps,scope=Namespaced
type Pap struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PapSpec   `json:"spec,omitempty"`
	Status PapStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PapList contains a list of Pap
type PapList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Pap `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Pap{}, &PapList{})
	CertificateSchemeBuilder.Register(&certmgr.Certificate{}, &certmgr.CertificateList{})
}
