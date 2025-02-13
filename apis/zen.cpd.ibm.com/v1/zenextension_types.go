/*
Copyright 2023 IBM Corporation.

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

package zenv1

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:path=zenextensions,scope=Namespaced

// ZenExtension is the Schema for the zen extension API. The spec is omitted
// from this struct because the ZenExtension API does not have any guaranteed
// structure, which is incompatible with controller-gen code generation.
type ZenExtension struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:pruning:PreserveUnknownFields
	Status ZenExtensionStatus `json:"status,omitempty"`
}

func (z *ZenExtension) Ready() bool {
	return z.Status.AllExtensionsProcessed()
}

func (z *ZenExtension) NotReady() bool {
	return !z.Ready()
}

type ZenExtensionStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	Message    string             `json:"message,omitempty"`
	Status     string             `json:"zenExtensionStatus,omitempty"`
}

type ConditionType string

const ConditionTypeFailure string = "Failure"
const ConditionTypeSuccessful string = "Successful"
const ConditionTypeRunning string = "Running"
const ZenExtensionStatusCompleted string = "Completed"

func (z ZenExtensionStatus) AllExtensionsProcessed() bool {
	return meta.IsStatusConditionTrue(z.Conditions, ConditionTypeSuccessful) &&
		meta.IsStatusConditionFalse(z.Conditions, ConditionTypeFailure) &&
		meta.IsStatusConditionTrue(z.Conditions, ConditionTypeRunning) &&
		z.Status == ZenExtensionStatusCompleted
}

//+kubebuilder:object:root=true

// ZenExtensionList contains a list of ZenExtension
type ZenExtensionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ZenExtension `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ZenExtension{}, &ZenExtensionList{})
}
