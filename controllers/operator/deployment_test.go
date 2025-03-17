package operator

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
	//DescribeTable("preserveObservedFields",
	//	func(observed, generated *appsv1.Deployment) {
	//		preserveObservedFields(observed, generated)
	//		for _, observedContainer := range observed.Spec.Template.Spec.Containers {
	//			for _, generatedContainer := range generated.Spec.Template.Spec.Containers {
	//				Expect(observedContainer).To(Equal(generatedContainer))
	//			}
	//		}
	//		for _, observedContainer := range observed.Spec.Template.Spec.InitContainers {
	//			for _, generatedContainer := range generated.Spec.Template.Spec.InitContainers {
	//				Expect(observedContainer).To(Equal(generatedContainer))
	//			}
	//		}
	//	},
	//	Entry("",
	//		&appsv1.Deployment{
	//			Spec: appsv1.DeploymentSpec{
	//				Template: v1.PodTemplateSpec{
	//					Spec: v1.PodSpec{
	//						Containers: []v1.Container{
	//							{
	//								Name: "platform-auth-service",
	//								LivenessProbe: &v1.Probe{
	//									FailureThreshold: 15,
	//									PeriodSeconds:    10,
	//									SuccessThreshold: 1,
	//								},
	//								ReadinessProbe: &v1.Probe{
	//									SuccessThreshold: 1,
	//								},
	//								TerminationMessagePath:   "/tmp/test",
	//								TerminationMessagePolicy: v1.TerminationMessageReadFile,
	//							},
	//						},
	//						InitContainers: []v1.Container{
	//							{
	//								Name:                     "init-db",
	//								TerminationMessagePath:   "/tmp/test",
	//								TerminationMessagePolicy: v1.TerminationMessageReadFile,
	//							},
	//						},
	//					},
	//				},
	//			},
	//		},
	//		&appsv1.Deployment{
	//			Spec: appsv1.DeploymentSpec{
	//				Template: v1.PodTemplateSpec{
	//					Spec: v1.PodSpec{
	//						Containers: []v1.Container{
	//							{
	//								Name: "platform-auth-service",
	//							},
	//						},
	//						InitContainers: []v1.Container{
	//							{
	//								Name: "init-db",
	//							},
	//						},
	//					},
	//				},
	//			},
	//		},
	//	),
	//)
})
