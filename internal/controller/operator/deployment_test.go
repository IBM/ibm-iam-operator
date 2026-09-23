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
	"context"
	"reflect"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// deploymentSecondary is a minimal SecondaryReconciler used only in deployment
// generate-function tests. It satisfies the full interface with no-op stubs for
// methods not exercised by the generate functions under test.
type deploymentSecondary struct {
	name      string
	namespace string
	authCR    *operatorv1alpha1.Authentication
	client.Client
}

func (d deploymentSecondary) GetEmptyObject() client.Object {
	rType := reflect.TypeFor[*appsv1.Deployment]().Elem()
	return reflect.New(rType).Interface().(*appsv1.Deployment)
}
func (d deploymentSecondary) GetKind() string                                   { return "Deployment" }
func (d deploymentSecondary) GetName() string                                   { return d.name }
func (d deploymentSecondary) GetNamespace() string                              { return d.namespace }
func (d deploymentSecondary) GetPrimary() client.Object                         { return d.authCR }
func (d deploymentSecondary) GetClient() client.Client                          { return d.Client }
func (d deploymentSecondary) Reconcile(context.Context) (*ctrl.Result, error)   { return nil, nil }
func (d deploymentSecondary) Generate(_ context.Context, _ client.Object) error { return nil }
func (d deploymentSecondary) Modify(_ context.Context, _, _ client.Object) (bool, error) {
	return false, nil
}
func (d deploymentSecondary) OnWrite(context.Context) error                          { return nil }
func (d deploymentSecondary) OnFinished(_ context.Context, _, _ client.Object) error { return nil }

// newDeploymentSecondary builds a deploymentSecondary backed by a fake client
// that has the Authentication CR registered.
func newDeploymentSecondary(name string, authCR *operatorv1alpha1.Authentication) deploymentSecondary {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = operatorv1alpha1.AddToScheme(scheme)
	cl := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(authCR).Build()
	return deploymentSecondary{
		name:      name,
		namespace: authCR.Namespace,
		authCR:    authCR,
		Client:    cl,
	}
}

// builtInTolerationsWithEffect mirrors the default tolerations for auth-service and identity-provider
// (which include Effect: NoSchedule on the "dedicated" entry).
var builtInTolerationsWithEffect = []corev1.Toleration{
	{Key: "dedicated", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	{Key: "CriticalAddonsOnly", Operator: corev1.TolerationOpExists},
}

// builtInTolerationsNoEffect mirrors the default tolerations for identity-manager,
// which omits Effect on the "dedicated" entry (pre-existing inconsistency in the code).
var builtInTolerationsNoEffect = []corev1.Toleration{
	{Key: "dedicated", Operator: corev1.TolerationOpExists},
	{Key: "CriticalAddonsOnly", Operator: corev1.TolerationOpExists},
}

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

	Describe("NodeSelector and Tolerations propagation", func() {
		var ctx context.Context
		var authCR *operatorv1alpha1.Authentication
		var customToleration corev1.Toleration

		BeforeEach(func() {
			ctx = context.Background()
			customToleration = corev1.Toleration{
				Key:      "custom-taint",
				Operator: corev1.TolerationOpEqual,
				Value:    "custom-value",
				Effect:   corev1.TaintEffectNoSchedule,
			}
			authCR = &operatorv1alpha1.Authentication{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "operator.ibm.com/v1alpha1",
					Kind:       "Authentication",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "example-authentication",
					Namespace:       "data-ns",
					ResourceVersion: trackerAddResourceVersion,
				},
				Spec: operatorv1alpha1.AuthenticationSpec{
					OperatorVersion: "4.0.0",
					Replicas:        1,
					Config:          operatorv1alpha1.ConfigSpec{},
				},
			}
		})

		DescribeTable("generatePlatformAuthService propagates scheduling fields",
			func(nodeSelector map[string]string, tolerations []corev1.Toleration) {
				authCR.Spec.NodeSelector = nodeSelector
				authCR.Spec.Tolerations = tolerations
				s := newDeploymentSecondary("platform-auth-service", authCR)
				deploy := &appsv1.Deployment{}
				err := generatePlatformAuthService("", "", "", "")(s, ctx, deploy)
				Expect(err).NotTo(HaveOccurred())
				if len(nodeSelector) > 0 {
					Expect(deploy.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))
				} else {
					Expect(deploy.Spec.Template.Spec.NodeSelector).To(BeNil())
				}
				Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElements(builtInTolerationsWithEffect))
				for _, t := range tolerations {
					Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElement(t))
				}
			},
			Entry("sets nodeSelector and appends custom tolerations when both are specified",
				map[string]string{"node-role.kubernetes.io/worker": "true"},
				[]corev1.Toleration{customToleration},
			),
			Entry("leaves nodeSelector nil and only has built-in tolerations when neither field is set",
				map[string]string(nil),
				[]corev1.Toleration(nil),
			),
		)

		DescribeTable("generatePlatformIdentityManagement propagates scheduling fields",
			func(nodeSelector map[string]string, tolerations []corev1.Toleration) {
				authCR.Spec.NodeSelector = nodeSelector
				authCR.Spec.Tolerations = tolerations
				s := newDeploymentSecondary("platform-identity-management", authCR)
				deploy := &appsv1.Deployment{}
				err := generatePlatformIdentityManagement("", "", "", "", "")(s, ctx, deploy)
				Expect(err).NotTo(HaveOccurred())
				if len(nodeSelector) > 0 {
					Expect(deploy.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))
				} else {
					Expect(deploy.Spec.Template.Spec.NodeSelector).To(BeNil())
				}
				Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElements(builtInTolerationsNoEffect))
				for _, t := range tolerations {
					Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElement(t))
				}
			},
			Entry("sets nodeSelector and appends custom tolerations when both are specified",
				map[string]string{"node-role.kubernetes.io/worker": "true"},
				[]corev1.Toleration{customToleration},
			),
			Entry("leaves nodeSelector nil and only has built-in tolerations when neither field is set",
				map[string]string(nil),
				[]corev1.Toleration(nil),
			),
		)

		DescribeTable("generatePlatformIdentityProvider propagates scheduling fields",
			func(nodeSelector map[string]string, tolerations []corev1.Toleration) {
				authCR.Spec.NodeSelector = nodeSelector
				authCR.Spec.Tolerations = tolerations
				s := newDeploymentSecondary("platform-identity-provider", authCR)
				deploy := &appsv1.Deployment{}
				err := generatePlatformIdentityProvider("", "", "", "", "", "")(s, ctx, deploy)
				Expect(err).NotTo(HaveOccurred())
				if len(nodeSelector) > 0 {
					Expect(deploy.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))
				} else {
					Expect(deploy.Spec.Template.Spec.NodeSelector).To(BeNil())
				}
				Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElements(builtInTolerationsWithEffect))
				for _, t := range tolerations {
					Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElement(t))
				}
			},
			Entry("sets nodeSelector and appends custom tolerations when both are specified",
				map[string]string{"node-role.kubernetes.io/worker": "true"},
				[]corev1.Toleration{customToleration},
			),
			Entry("leaves nodeSelector nil and only has built-in tolerations when neither field is set",
				map[string]string(nil),
				[]corev1.Toleration(nil),
			),
		)
	})
})
