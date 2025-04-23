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

package operator

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Deployment handling", func() {
	DescribeTable("hasDataField",
		func(b []byte, has bool) {
			fields := metav1.ManagedFieldsEntry{
				FieldsV1: &metav1.FieldsV1{
					Raw: b,
				},
			}
			Expect(hasDataField(fields)).To(Equal(has))
		},
		Entry("has a modified \"data\" field",
			[]byte(`{"manager": "ibm-iam-operator","operation": "Update", "apiVersion": "v1", "time": "2025-03-11T17:19:25Z", "fieldsType": "FieldsV1", "fieldsV1": {"f:data":{"f:proxy_address":{}}}}`),
			true,
		),
		Entry("is empty JSON",
			[]byte(`{}`),
			false,
		),
		Entry("is broken JSON",
			[]byte(`{`),
			false,
		),
		Entry("is empty slice",
			[]byte(``),
			false,
		),
	)
	DescribeTable("preserveObservedFields",
		func(observed, generated *appsv1.Deployment) {
			preserveObservedFields(observed, generated)
			for _, observedContainer := range observed.Spec.Template.Spec.Containers {
				for _, generatedContainer := range generated.Spec.Template.Spec.Containers {
					Expect(generatedContainer).To(Equal(observedContainer))
				}
			}
			for _, observedContainer := range observed.Spec.Template.Spec.InitContainers {
				for _, generatedContainer := range generated.Spec.Template.Spec.InitContainers {
					Expect(generatedContainer).To(Equal(observedContainer))
				}
			}
		},
		Entry("copies containers and initcontainers to generated from observed successfully",
			&appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
							Containers: []v1.Container{
								{
									Name: "platform-auth-service",
									LivenessProbe: &v1.Probe{
										FailureThreshold: 15,
										PeriodSeconds:    10,
										SuccessThreshold: 1,
									},
									ReadinessProbe: &v1.Probe{
										SuccessThreshold: 1,
									},
									TerminationMessagePath:   "/tmp/test",
									TerminationMessagePolicy: v1.TerminationMessageReadFile,
								},
							},
							InitContainers: []v1.Container{
								{
									Name:                     "init-db",
									TerminationMessagePath:   "/tmp/test",
									TerminationMessagePolicy: v1.TerminationMessageReadFile,
								},
							},
						},
					},
				},
			},
			&appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
							Containers: []v1.Container{
								{
									Name: "platform-auth-service",
								},
							},
							InitContainers: []v1.Container{
								{
									Name: "init-db",
								},
							},
						},
					},
				},
			},
		),
	)
})
