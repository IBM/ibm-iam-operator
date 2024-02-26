//
// Copyright 2022 IBM Corporation
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

// The following code is copied from the ODLM project at
// https://github.com/IBM/operand-deployment-lifecycle-manager
//
// Provides types needed to interact with the OperandRequest API.

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// The OperandRequestSpec identifies one or more specific operands (from a specific Registry) that should actually be installed.
type OperandRequestSpec struct {
	// Requests defines a list of operands installation.
	Requests []Request `json:"requests"`
}

// Bindable is a Kubernetes resources to be shared from one namespace to another.
// List of supported resources are Secrets, Configmaps, Services, and Routes.
// Secrets and Configmaps will be copied such that a new Secret/Configmap with
// exactly the same data will be created in the target namespace.
// Services and Routes data will be copied into a configmap in the target
// namespace.
type Bindable struct {
	// The secret identifies an existing secret. if it exists, the ODLM will share to the namespace of the OperandRequest.
	Secret string `json:"secret,omitempty"`
	// The configmap identifies an existing configmap object. if it exists, the ODLM will share to the namespace of the OperandRequest.
	Configmap string `json:"configmap,omitempty"`
	// Route data will be shared by copying it into a configmap which is then
	// created in the target namespace
	Route *Route `json:"route,omitempty"`
	// Service data will be shared by copying it into a configmap which is then
	// created in the target namespace
	Service *ServiceData `json:"service,omitempty"`
}

// Route represents the name and data inside an OpenShift route.
type Route struct {
	// Name is the name of the OpenShift Route resource
	Name string `json:"name"`
	// Data is a key-value pair where the value is a YAML path to a value in the
	// OpenShift Route, e.g. .spec.host or .spec.tls.termination
	Data map[string]string `json:"data"`
}

// ServiceData represents the name and data inside an Kubernetes Service.
type ServiceData struct {
	// Name is the name of the Kubernetes Service resource
	Name string `json:"name"`
	// Data is a key-value pair where the value is a YAML path to a value in the
	// Kubernetes Service, e.g. .spec.ports[0]port
	Data map[string]string `json:"data"`
}

// Request identifies a operand detail.
type Request struct {
	// Operands defines a list of the OperandRegistry entry for the operand to be deployed.
	Operands []Operand `json:"operands"`
	// Specifies the name in which the OperandRegistry reside.
	Registry string `json:"registry"`
	// Specifies the namespace in which the OperandRegistry reside.
	// The default is the current namespace in which the request is defined.
	RegistryNamespace string `json:"registryNamespace,omitempty"`
	// Description is an optional description for the request.
	Description string `json:"description,omitempty"`
}

// Operand defines the name and binding information for one operator.
type Operand struct {
	// Name of the operand to be deployed.
	Name string `json:"name"`
	// The bindings section is used to specify names of secret and/or configmap.
	Bindings map[string]Bindable `json:"bindings,omitempty"`
	// Kind is used when users want to deploy multiple custom resources.
	// Kind identifies the kind of the custom resource.
	Kind string `json:"kind,omitempty"`
	// APIVersion defines the versioned schema of this representation of an object.
	APIVersion string `json:"apiVersion,omitempty"`
	// InstanceName is used when users want to deploy multiple custom resources.
	// It is the name of the custom resource.
	InstanceName string `json:"instanceName,omitempty"`
	// Spec is used when users want to deploy multiple custom resources.
	// It is the configuration map of custom resource.
	Spec *runtime.RawExtension `json:"spec,omitempty"`
}

// ConditionType is the condition of a service.
type ConditionType string

// ClusterPhase is the phase of the installation.
type ClusterPhase string

// ResourceType is the type of condition use.
type ResourceType string

// OperatorPhase defines the operator status.
type OperatorPhase string

// Constants are used for state.
const (
	// RequestFinalizer is the name for the finalizer to allow for deletion.
	// when an OperandRequest is deleted.
	RequestFinalizer = "finalizer.request.ibm.com"

	ConditionCreating   ConditionType = "Creating"
	ConditionUpdating   ConditionType = "Updating"
	ConditionDeleting   ConditionType = "Deleting"
	ConditionNotFound   ConditionType = "NotFound"
	ConditionOutofScope ConditionType = "OutofScope"
	ConditionReady      ConditionType = "Ready"
	ConditionNoConflict ConditionType = "NoConflict"

	OperatorReady      OperatorPhase = "Ready for Deployment"
	OperatorRunning    OperatorPhase = "Running"
	OperatorInstalling OperatorPhase = "Installing"
	OperatorUpdating   OperatorPhase = "Updating"
	OperatorFailed     OperatorPhase = "Failed"
	OperatorInit       OperatorPhase = "Initialized"
	OperatorNotFound   OperatorPhase = "Not Found"
	OperatorNone       OperatorPhase = ""

	ClusterPhaseNone       ClusterPhase = "Pending"
	ClusterPhaseCreating   ClusterPhase = "Creating"
	ClusterPhaseInstalling ClusterPhase = "Installing"
	ClusterPhaseUpdating   ClusterPhase = "Updating"
	ClusterPhaseRunning    ClusterPhase = "Running"
	ClusterPhaseFailed     ClusterPhase = "Failed"

	ResourceTypeOperandRegistry ResourceType = "operandregistry"
	ResourceTypeCatalogSource   ResourceType = "catalogsource"
	ResourceTypeSub             ResourceType = "subscription"
	ResourceTypeCsv             ResourceType = "csv"
	ResourceTypeOperator        ResourceType = "operator"
	ResourceTypeOperand         ResourceType = "operands"
)

// Condition represents the current state of the Request Service.
// A condition might not show up if it is not happening.
type Condition struct {
	// Type of condition.
	Type ConditionType `json:"type"`
	// Status of the condition, one of True, False, Unknown.
	Status corev1.ConditionStatus `json:"status"`
	// The last time this condition was updated.
	LastUpdateTime string `json:"lastUpdateTime,omitempty"`
	// Last time the condition transitioned from one status to another.
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
	// The reason for the condition's last transition.
	Reason string `json:"reason,omitempty"`
	// A human readable message indicating details about the transition.
	Message string `json:"message,omitempty"`
}

type ResourceStatus struct { //Status of CRs not created by ODLM
	ObjectName string `json:"objectName,omitempty"`
	APIVersion string `json:"apiVersion,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Status     string `json:"status,omitempty"`
}
type OperandStatus struct { //Top level CR status ie the CR created by ODLM
	ObjectName       string           `json:"objectName,omitempty"`
	APIVersion       string           `json:"apiVersion,omitempty"`
	Namespace        string           `json:"namespace,omitempty"`
	Kind             string           `json:"kind,omitempty"`
	Status           string           `json:"status,omitempty"`
	ManagedResources []ResourceStatus `json:"managedResources,omitempty"`
}

type OpReqServiceStatus struct { //Top level service status
	OperatorName string          `json:"operatorName,omitempty"`
	Namespace    string          `json:"namespace,omitempty"`
	Status       string          `json:"status,omitempty"`
	Resources    []OperandStatus `json:"resources,omitempty"`
}

// OperandRequestStatus defines the observed state of OperandRequest.
type OperandRequestStatus struct {
	// Conditions represents the current state of the Request Service.
	Conditions []Condition `json:"conditions,omitempty"`
	// Members represnets the current operand status of the set.
	Members []MemberStatus `json:"members,omitempty"`
	// Phase is the cluster running phase.
	Phase ClusterPhase `json:"phase,omitempty"`
	//Services reflect the status of operands beyond whether they have been created
	Services []OpReqServiceStatus `json:"services,omitempty"`
}

// ServicePhase defines the service status.
type ServicePhase string

// Service status.
const (
	// ConfigFinalizer is the name for the finalizer to allow for deletion
	// when an OperandConfig is deleted.
	ConfigFinalizer = "finalizer.config.ibm.com"

	ServiceRunning  ServicePhase = "Running"
	ServiceFailed   ServicePhase = "Failed"
	ServiceInit     ServicePhase = "Initialized"
	ServiceCreating ServicePhase = "Creating"
	ServiceNotFound ServicePhase = "Not Found"
	ServiceNone     ServicePhase = ""
)

// MemberPhase shows the phase of the operator and operator instance.
type MemberPhase struct {
	// OperatorPhase shows the deploy phase of the operator.
	OperatorPhase OperatorPhase `json:"operatorPhase,omitempty"`
	// OperandPhase shows the deploy phase of the operator instance.
	OperandPhase ServicePhase `json:"operandPhase,omitempty"`
}

// OperandCRMember defines a custom resource created by OperandRequest.
type OperandCRMember struct {
	// Name is the name of the custom resource.
	Name string `json:"name,omitempty"`
	// Kind is the kind of the custom resource.
	Kind string `json:"kind,omitempty"`
	// APIVersion is the APIVersion of the custom resource.
	APIVersion string `json:"apiVersion,omitempty"`
}

// MemberStatus shows if the Operator is ready.
type MemberStatus struct {
	// The member name are the same as the subscription name.
	Name string `json:"name"`
	// The operand phase include None, Creating, Running, Failed.
	Phase MemberPhase `json:"phase,omitempty"`
	// OperandCRList shows the list of custom resource created by OperandRequest.
	OperandCRList []OperandCRMember `json:"operandCRList,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// OperandRequest is the Schema for the operandrequests API.
type OperandRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OperandRequestSpec   `json:"spec,omitempty"`
	Status OperandRequestStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// OperandRequestList contains a list of OperandRequest.
type OperandRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OperandRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OperandRequest{}, &OperandRequestList{})
}
