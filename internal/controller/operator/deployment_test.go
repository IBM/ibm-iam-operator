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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
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
	_ = v1.AddToScheme(scheme)
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
var builtInTolerationsWithEffect = []v1.Toleration{
	{Key: "dedicated", Operator: v1.TolerationOpExists, Effect: v1.TaintEffectNoSchedule},
	{Key: "CriticalAddonsOnly", Operator: v1.TolerationOpExists},
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
		var customToleration v1.Toleration

		BeforeEach(func() {
			ctx = context.Background()
			customToleration = v1.Toleration{
				Key:      "custom-taint",
				Operator: v1.TolerationOpEqual,
				Value:    "custom-value",
				Effect:   v1.TaintEffectNoSchedule,
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
			func(nodeSelector map[string]string, tolerations []v1.Toleration) {
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
				[]v1.Toleration{customToleration},
			),
			Entry("leaves nodeSelector nil and only has built-in tolerations when neither field is set",
				map[string]string(nil),
				[]v1.Toleration(nil),
			),
		)

		DescribeTable("generatePlatformIdentityManagement propagates scheduling fields",
			func(nodeSelector map[string]string, tolerations []v1.Toleration) {
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
				Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElements(builtInTolerationsWithEffect))
				for _, t := range tolerations {
					Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElement(t))
				}
			},
			Entry("sets nodeSelector and appends custom tolerations when both are specified",
				map[string]string{"node-role.kubernetes.io/worker": "true"},
				[]v1.Toleration{customToleration},
			),
			Entry("leaves nodeSelector nil and only has built-in tolerations when neither field is set",
				map[string]string(nil),
				[]v1.Toleration(nil),
			),
		)

		DescribeTable("generatePlatformIdentityProvider propagates scheduling fields",
			func(nodeSelector map[string]string, tolerations []v1.Toleration) {
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
				[]v1.Toleration{customToleration},
			),
			Entry("leaves nodeSelector nil and only has built-in tolerations when neither field is set",
				map[string]string(nil),
				[]v1.Toleration(nil),
			),
		)
	})
})

// Additional tests for §7.2.3 — generator replica counts, modifyDeployment replica handling,
// update lifecycle, MASTER_NODES_LIST sizing, and specsDiffer (Gap B).

var _ = Describe("Per-service replica behaviour", func() {
	const depNS = "deploy-test-ns"

	// baseAuthCR builds a minimal Authentication CR with the given global replicas.
	baseAuthCR := func(globalReplicas int32, autoScale bool) *operatorv1alpha1.Authentication {
		return &operatorv1alpha1.Authentication{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "operator.ibm.com/v1alpha1",
				Kind:       "Authentication",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "example-authentication",
				Namespace:       depNS,
				ResourceVersion: trackerAddResourceVersion,
			},
			Spec: operatorv1alpha1.AuthenticationSpec{
				OperatorVersion: "4.0.0",
				Replicas:        globalReplicas,
				AutoScaleConfig: autoScale,
			},
		}
	}

	// deployForCR builds a Deployment from the named generator, asserting no error.
	deployFromAuthService := func(authCR *operatorv1alpha1.Authentication) *appsv1.Deployment {
		s := newDeploymentSecondary("platform-auth-service", authCR)
		d := &appsv1.Deployment{}
		Expect(generatePlatformAuthService("", "", "", "")(s, context.Background(), d)).To(Succeed())
		return d
	}
	deployFromIdentityProvider := func(authCR *operatorv1alpha1.Authentication) *appsv1.Deployment {
		s := newDeploymentSecondary("platform-identity-provider", authCR)
		d := &appsv1.Deployment{}
		Expect(generatePlatformIdentityProvider("", "", "", "", "", "")(s, context.Background(), d)).To(Succeed())
		return d
	}
	deployFromIdentityManagement := func(authCR *operatorv1alpha1.Authentication) *appsv1.Deployment {
		s := newDeploymentSecondary("platform-identity-management", authCR)
		d := &appsv1.Deployment{}
		Expect(generatePlatformIdentityManagement("", "", "", "", "")(s, context.Background(), d)).To(Succeed())
		return d
	}

	Describe("§7.2.3 Generator replica counts", func() {

		DescribeTable("generatePlatformAuthService Spec.Replicas",
			func(globalReplicas int32, perSvc *int32, expected int32) {
				authCR := baseAuthCR(globalReplicas, false)
				authCR.Spec.AuthService.Replicas = perSvc
				d := deployFromAuthService(authCR)
				Expect(d.Spec.Replicas).NotTo(BeNil())
				Expect(*d.Spec.Replicas).To(Equal(expected))
			},
			Entry("perSvc nil → spec.Replicas", int32(3), (*int32)(nil), int32(3)),
			Entry("perSvc 1 < global 3 → 1", int32(3), ptr.To(int32(1)), int32(1)),
			Entry("perSvc 5 > global 2 → 5", int32(2), ptr.To(int32(5)), int32(5)),
			Entry("perSvc 1 (lower bound)", int32(2), ptr.To(int32(1)), int32(1)),
		)

		DescribeTable("generatePlatformIdentityProvider Spec.Replicas",
			func(globalReplicas int32, perSvc *int32, expected int32) {
				authCR := baseAuthCR(globalReplicas, false)
				authCR.Spec.IdentityProvider.Replicas = perSvc
				d := deployFromIdentityProvider(authCR)
				Expect(d.Spec.Replicas).NotTo(BeNil())
				Expect(*d.Spec.Replicas).To(Equal(expected))
			},
			Entry("perSvc nil → spec.Replicas", int32(3), (*int32)(nil), int32(3)),
			Entry("perSvc 1 < global 3 → 1", int32(3), ptr.To(int32(1)), int32(1)),
			Entry("perSvc 4 > global 2 → 4", int32(2), ptr.To(int32(4)), int32(4)),
			Entry("perSvc 1 (lower bound)", int32(2), ptr.To(int32(1)), int32(1)),
		)

		DescribeTable("generatePlatformIdentityManagement Spec.Replicas",
			func(globalReplicas int32, perSvc *int32, expected int32) {
				authCR := baseAuthCR(globalReplicas, false)
				authCR.Spec.IdentityManager.Replicas = perSvc
				d := deployFromIdentityManagement(authCR)
				Expect(d.Spec.Replicas).NotTo(BeNil())
				Expect(*d.Spec.Replicas).To(Equal(expected))
			},
			Entry("perSvc nil → spec.Replicas", int32(3), (*int32)(nil), int32(3)),
			Entry("perSvc 2 < global 3 → 2", int32(3), ptr.To(int32(2)), int32(2)),
			Entry("perSvc 5 > global 2 → 5", int32(2), ptr.To(int32(5)), int32(5)),
			Entry("perSvc 1 (lower bound)", int32(2), ptr.To(int32(1)), int32(1)),
		)

		It("a per-service override on one service does not alter the generated count of the other two (§6.5)", func() {
			authCR := baseAuthCR(2, false)
			authCR.Spec.AuthService.Replicas = ptr.To(int32(1)) // only authService pinned

			idpDeploy := deployFromIdentityProvider(authCR)
			idmDeploy := deployFromIdentityManagement(authCR)

			Expect(*idpDeploy.Spec.Replicas).To(Equal(int32(2)), "identityProvider should use global replicas")
			Expect(*idmDeploy.Spec.Replicas).To(Equal(int32(2)), "identityManager should use global replicas")
		})
	})

	Describe("§7.2.3 modifyDeployment replica handling (Gap A fix, §5.4)", func() {
		// callModifyDeployment runs modifyDeployment(false) with the given observed and generated
		// Deployments and the given AuthCR as the SecondaryReconciler's primary.
		callModifyDeployment := func(authCR *operatorv1alpha1.Authentication, deployName string, observed, generated *appsv1.Deployment) (modified bool, err error) {
			s := newDeploymentSecondary(deployName, authCR)
			return modifyDeployment(false)(s, context.Background(), observed, generated)
		}

		DescribeTable("observed replicas after modifyDeployment",
			func(deployName string, autoScale bool, perSvc *int32, globalReplicas, observedReplicas, expectedAfter int32, expectModified bool) {
				authCR := baseAuthCR(globalReplicas, autoScale)
				switch deployName {
				case "platform-auth-service":
					authCR.Spec.AuthService.Replicas = perSvc
				case "platform-identity-provider":
					authCR.Spec.IdentityProvider.Replicas = perSvc
				case "platform-identity-management":
					authCR.Spec.IdentityManager.Replicas = perSvc
				}

				// Build observed Deployment with the pre-existing live replica count.
				observed := makeTestDeployment(deployName, depNS, observedReplicas)
				// Build generated Deployment using the generator (which calls effectiveReplicas).
				var generated *appsv1.Deployment
				switch deployName {
				case "platform-auth-service":
					generated = deployFromAuthService(authCR)
				case "platform-identity-provider":
					generated = deployFromIdentityProvider(authCR)
				case "platform-identity-management":
					generated = deployFromIdentityManagement(authCR)
				}
				generated.Name = deployName
				generated.Namespace = depNS

				_, err := callModifyDeployment(authCR, deployName, observed, generated)
				Expect(err).NotTo(HaveOccurred())

				Expect(observed.Spec.Replicas).NotTo(BeNil())
				Expect(*observed.Spec.Replicas).To(Equal(expectedAfter), "for deployment %s", deployName)
			},
			// autoScale true, no pin → HPA owns scale; observed count preserved (Gap A branch unchanged for HPA-owned Deployments)
			Entry("auth-service: autoScale=true, no pin, HPA-scaled to 5 → 5 preserved",
				"platform-auth-service", true, (*int32)(nil), int32(2), int32(5), int32(5), false),
			// Gap A regression test: autoScale true, pin set → generated pin wins (must fail against old code)
			Entry("auth-service: autoScale=true, pin=1, observed=5 → 1 (Gap A fix)",
				"platform-auth-service", true, ptr.To(int32(1)), int32(2), int32(5), int32(1), true),
			Entry("auth-service: autoScale=true, pin=1, already at 1 → 1, no change",
				"platform-auth-service", true, ptr.To(int32(1)), int32(2), int32(1), int32(1), false),
			Entry("auth-service: autoScale=false, no pin, observed=2 → spec.Replicas=2",
				"platform-auth-service", false, (*int32)(nil), int32(2), int32(2), int32(2), false),
			Entry("auth-service: autoScale=false, pin=3, observed=2 → 3",
				"platform-auth-service", false, ptr.To(int32(3)), int32(2), int32(2), int32(3), true),
			Entry("auth-service: autoScale=true, pin=4, observed=2 (below pin) → 4",
				"platform-auth-service", true, ptr.To(int32(4)), int32(2), int32(2), int32(4), true),
			// Same Gap A rows for identity-provider
			Entry("idp: autoScale=true, pin=1, observed=5 → 1 (Gap A fix)",
				"platform-identity-provider", true, ptr.To(int32(1)), int32(2), int32(5), int32(1), true),
			Entry("idp: autoScale=true, no pin, HPA-scaled to 5 → 5 preserved",
				"platform-identity-provider", true, (*int32)(nil), int32(2), int32(5), int32(5), false),
			// Same Gap A rows for identity-management
			Entry("idm: autoScale=true, pin=1, observed=5 → 1 (Gap A fix)",
				"platform-identity-management", true, ptr.To(int32(1)), int32(2), int32(5), int32(1), true),
			Entry("idm: autoScale=true, no pin, HPA-scaled to 5 → 5 preserved",
				"platform-identity-management", true, (*int32)(nil), int32(2), int32(5), int32(5), false),
		)
	})

	Describe("§7.2.3 Update lifecycle tests (§6.5, §6.6)", func() {
		It("changing spec.Replicas only affects deployments without a per-service override", func() {
			authCR := baseAuthCR(2, false)
			authCR.Spec.AuthService.Replicas = ptr.To(int32(1)) // authService is pinned

			// Generate at global=2
			idpBefore := deployFromIdentityProvider(authCR)
			idmBefore := deployFromIdentityManagement(authCR)

			// Now change global replicas to 3
			authCR.Spec.Replicas = 3
			idpAfter := deployFromIdentityProvider(authCR)
			idmAfter := deployFromIdentityManagement(authCR)
			authServiceAfter := deployFromAuthService(authCR)

			// Non-pinned services should reflect the new global replicas
			Expect(*idpAfter.Spec.Replicas).To(Equal(int32(3)))
			Expect(*idmAfter.Spec.Replicas).To(Equal(int32(3)))
			// Pinned authService must not change
			Expect(*authServiceAfter.Spec.Replicas).To(Equal(int32(1)))

			// Sanity: idp was previously 2
			Expect(*idpBefore.Spec.Replicas).To(Equal(int32(2)))
			Expect(*idmBefore.Spec.Replicas).To(Equal(int32(2)))
		})

		It("removing a per-service override returns the Deployment to spec.Replicas on the next call (§6.6)", func() {
			authCR := baseAuthCR(3, false)
			authCR.Spec.AuthService.Replicas = ptr.To(int32(1)) // pinned

			pinned := deployFromAuthService(authCR)
			Expect(*pinned.Spec.Replicas).To(Equal(int32(1)))

			// Remove the override
			authCR.Spec.AuthService.Replicas = nil
			restored := deployFromAuthService(authCR)
			Expect(*restored.Spec.Replicas).To(Equal(int32(3)))
		})

		It("adding a per-service override where none existed takes effect on the first call", func() {
			authCR := baseAuthCR(2, true)

			before := deployFromAuthService(authCR)
			Expect(*before.Spec.Replicas).To(Equal(int32(2)))

			authCR.Spec.AuthService.Replicas = ptr.To(int32(1))
			after := deployFromAuthService(authCR)
			Expect(*after.Spec.Replicas).To(Equal(int32(1)))
		})
	})

	Describe("§7.2.3 MASTER_NODES_LIST sizing (§5.5)", func() {
		// masterNodeCount counts the space-separated entries in MASTER_NODES_LIST.
		masterNodeCount := func(authCR *operatorv1alpha1.Authentication) int {
			d := deployFromIdentityManagement(authCR)
			for _, c := range d.Spec.Template.Spec.Containers {
				for _, env := range c.Env {
					if env.Name == "MASTER_NODES_LIST" {
						if env.Value == "" {
							return 0
						}
						parts := 0
						for _, ch := range env.Value {
							if ch == ' ' {
								parts++
							}
						}
						return parts + 1
					}
				}
			}
			// Not found
			return -1
		}

		DescribeTable("MASTER_NODES_LIST entry count",
			func(globalReplicas int32, idmPerSvc *int32, expected int) {
				authCR := baseAuthCR(globalReplicas, false)
				authCR.Spec.IdentityManager.Replicas = idmPerSvc
				Expect(masterNodeCount(authCR)).To(Equal(expected))
			},
			Entry("perSvc nil, global 3 → 3 entries (backwards-compat)", int32(3), (*int32)(nil), 3),
			Entry("perSvc 1, global 3 → 1 entry", int32(3), ptr.To(int32(1)), 1),
			Entry("perSvc 5, global 2 → 5 entries", int32(2), ptr.To(int32(5)), 5),
		)

		It("setting authService or identityProvider replicas does not change the idm list length", func() {
			authCR := baseAuthCR(2, false)
			authCR.Spec.AuthService.Replicas = ptr.To(int32(10))
			authCR.Spec.IdentityProvider.Replicas = ptr.To(int32(10))
			Expect(masterNodeCount(authCR)).To(Equal(2), "should still use global replicas for idm")
		})

		It("autoScaleConfig true with no per-service override → list sized from spec.Replicas", func() {
			authCR := baseAuthCR(3, true)
			Expect(masterNodeCount(authCR)).To(Equal(3))
		})

		It("entry count equals generated Deployment Spec.Replicas when per-service value is set", func() {
			authCR := baseAuthCR(2, false)
			authCR.Spec.IdentityManager.Replicas = ptr.To(int32(4))
			d := deployFromIdentityManagement(authCR)
			Expect(*d.Spec.Replicas).To(Equal(int32(4)))
			Expect(masterNodeCount(authCR)).To(Equal(4))
		})
	})

	Describe("§7.2.3 specsDiffer (Gap B documentation)", func() {
		It("reports different when Spec.Replicas differ", func() {
			d1 := makeTestDeployment("platform-auth-service", depNS, 2)
			d2 := makeTestDeployment("platform-auth-service", depNS, 3)
			different, err := specsDiffer(d1, d2)
			Expect(err).NotTo(HaveOccurred())
			Expect(different).To(BeTrue())
		})

		It("reports not different when Spec.Replicas are equal", func() {
			d1 := makeTestDeployment("platform-auth-service", depNS, 2)
			d2 := makeTestDeployment("platform-auth-service", depNS, 2)
			different, err := specsDiffer(d1, d2)
			Expect(err).NotTo(HaveOccurred())
			Expect(different).To(BeFalse())
		})
	})
})
