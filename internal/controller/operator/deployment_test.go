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
	Describe("preserveObservedFields", func() {
		It("should preserve TerminationMessagePath and TerminationMessagePolicy from observed containers", func() {
			observed := &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
							Containers: []v1.Container{
								{
									Name:                     "platform-auth-service",
									TerminationMessagePath:   "/dev/termination-log-observed",
									TerminationMessagePolicy: v1.TerminationMessageFallbackToLogsOnError,
								},
							},
						},
					},
				},
			}
			generated := &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
							Containers: []v1.Container{
								{
									Name:                     "platform-auth-service",
									TerminationMessagePath:   "/dev/termination-log-generated",
									TerminationMessagePolicy: v1.TerminationMessageReadFile,
								},
							},
						},
					},
				},
			}

			preserveObservedFields(observed, generated)

			Expect(generated.Spec.Template.Spec.Containers[0].TerminationMessagePath).To(Equal("/dev/termination-log-observed"))
			Expect(generated.Spec.Template.Spec.Containers[0].TerminationMessagePolicy).To(Equal(v1.TerminationMessageFallbackToLogsOnError))
		})

		It("should NOT preserve probe values from observed containers - generated probe values should remain", func() {
			observed := &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
							Containers: []v1.Container{
								{
									Name: "platform-identity-provider",
									LivenessProbe: &v1.Probe{
										InitialDelaySeconds: 10,
										PeriodSeconds:       5,
										TimeoutSeconds:      3,
										SuccessThreshold:    1,
										FailureThreshold:    2,
									},
									ReadinessProbe: &v1.Probe{
										InitialDelaySeconds: 15,
										PeriodSeconds:       8,
										TimeoutSeconds:      5,
										SuccessThreshold:    1,
										FailureThreshold:    3,
									},
								},
							},
						},
					},
				},
			}
			generated := &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
							Containers: []v1.Container{
								{
									Name: "platform-identity-provider",
									LivenessProbe: &v1.Probe{
										InitialDelaySeconds: 40,
										PeriodSeconds:       15,
										TimeoutSeconds:      10,
										SuccessThreshold:    1,
										FailureThreshold:    5,
									},
									ReadinessProbe: &v1.Probe{
										InitialDelaySeconds: 30,
										PeriodSeconds:       15,
										TimeoutSeconds:      10,
										SuccessThreshold:    1,
										FailureThreshold:    5,
									},
								},
							},
						},
					},
				},
			}

			preserveObservedFields(observed, generated)

			// Verify that generated probe values are NOT overwritten by observed values
			Expect(generated.Spec.Template.Spec.Containers[0].LivenessProbe.InitialDelaySeconds).To(Equal(int32(40)))
			Expect(generated.Spec.Template.Spec.Containers[0].LivenessProbe.PeriodSeconds).To(Equal(int32(15)))
			Expect(generated.Spec.Template.Spec.Containers[0].LivenessProbe.TimeoutSeconds).To(Equal(int32(10)))
			Expect(generated.Spec.Template.Spec.Containers[0].LivenessProbe.SuccessThreshold).To(Equal(int32(1)))
			Expect(generated.Spec.Template.Spec.Containers[0].LivenessProbe.FailureThreshold).To(Equal(int32(5)))

			Expect(generated.Spec.Template.Spec.Containers[0].ReadinessProbe.InitialDelaySeconds).To(Equal(int32(30)))
			Expect(generated.Spec.Template.Spec.Containers[0].ReadinessProbe.PeriodSeconds).To(Equal(int32(15)))
			Expect(generated.Spec.Template.Spec.Containers[0].ReadinessProbe.TimeoutSeconds).To(Equal(int32(10)))
			Expect(generated.Spec.Template.Spec.Containers[0].ReadinessProbe.SuccessThreshold).To(Equal(int32(1)))
			Expect(generated.Spec.Template.Spec.Containers[0].ReadinessProbe.FailureThreshold).To(Equal(int32(5)))
		})

		It("should preserve TerminationMessagePath and TerminationMessagePolicy from observed init containers", func() {
			observed := &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
							InitContainers: []v1.Container{
								{
									Name:                     "init-db",
									TerminationMessagePath:   "/dev/init-termination-log-observed",
									TerminationMessagePolicy: v1.TerminationMessageFallbackToLogsOnError,
								},
							},
						},
					},
				},
			}
			generated := &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
							InitContainers: []v1.Container{
								{
									Name:                     "init-db",
									TerminationMessagePath:   "/dev/init-termination-log-generated",
									TerminationMessagePolicy: v1.TerminationMessageReadFile,
								},
							},
						},
					},
				},
			}

			preserveObservedFields(observed, generated)

			Expect(generated.Spec.Template.Spec.InitContainers[0].TerminationMessagePath).To(Equal("/dev/init-termination-log-observed"))
			Expect(generated.Spec.Template.Spec.InitContainers[0].TerminationMessagePolicy).To(Equal(v1.TerminationMessageFallbackToLogsOnError))
		})

		It("should handle both probe values and termination fields correctly in the same container", func() {
			observed := &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
							Containers: []v1.Container{
								{
									Name: "platform-identity-management",
									LivenessProbe: &v1.Probe{
										InitialDelaySeconds: 20,
										PeriodSeconds:       10,
										TimeoutSeconds:      5,
										SuccessThreshold:    1,
										FailureThreshold:    3,
									},
									ReadinessProbe: &v1.Probe{
										InitialDelaySeconds: 25,
										PeriodSeconds:       12,
										TimeoutSeconds:      6,
										SuccessThreshold:    1,
										FailureThreshold:    4,
									},
									TerminationMessagePath:   "/dev/termination-log-observed",
									TerminationMessagePolicy: v1.TerminationMessageFallbackToLogsOnError,
								},
							},
						},
					},
				},
			}
			generated := &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
							Containers: []v1.Container{
								{
									Name: "platform-identity-management",
									LivenessProbe: &v1.Probe{
										InitialDelaySeconds: 40,
										PeriodSeconds:       15,
										TimeoutSeconds:      10,
										SuccessThreshold:    1,
										FailureThreshold:    5,
									},
									ReadinessProbe: &v1.Probe{
										InitialDelaySeconds: 30,
										PeriodSeconds:       15,
										TimeoutSeconds:      10,
										SuccessThreshold:    1,
										FailureThreshold:    5,
									},
									TerminationMessagePath:   "/dev/termination-log-generated",
									TerminationMessagePolicy: v1.TerminationMessageReadFile,
								},
							},
						},
					},
				},
			}

			preserveObservedFields(observed, generated)

			// Verify probe values remain from generated (NOT preserved from observed)
			Expect(generated.Spec.Template.Spec.Containers[0].LivenessProbe.InitialDelaySeconds).To(Equal(int32(40)))
			Expect(generated.Spec.Template.Spec.Containers[0].LivenessProbe.PeriodSeconds).To(Equal(int32(15)))
			Expect(generated.Spec.Template.Spec.Containers[0].LivenessProbe.TimeoutSeconds).To(Equal(int32(10)))
			Expect(generated.Spec.Template.Spec.Containers[0].LivenessProbe.FailureThreshold).To(Equal(int32(5)))

			Expect(generated.Spec.Template.Spec.Containers[0].ReadinessProbe.InitialDelaySeconds).To(Equal(int32(30)))
			Expect(generated.Spec.Template.Spec.Containers[0].ReadinessProbe.PeriodSeconds).To(Equal(int32(15)))
			Expect(generated.Spec.Template.Spec.Containers[0].ReadinessProbe.TimeoutSeconds).To(Equal(int32(10)))
			Expect(generated.Spec.Template.Spec.Containers[0].ReadinessProbe.FailureThreshold).To(Equal(int32(5)))

			// Verify termination fields ARE preserved from observed
			Expect(generated.Spec.Template.Spec.Containers[0].TerminationMessagePath).To(Equal("/dev/termination-log-observed"))
			Expect(generated.Spec.Template.Spec.Containers[0].TerminationMessagePolicy).To(Equal(v1.TerminationMessageFallbackToLogsOnError))
		})
	})
})
