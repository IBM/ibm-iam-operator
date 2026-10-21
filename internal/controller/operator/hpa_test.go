//
// Copyright 2026 IBM Corporation
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

package operator

import (
	"context"
	"fmt"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// Tests for §7.2.2 — unit tests for HPA handler and related helpers.

// newHPATestScheme builds a scheme that registers all types needed for HPA tests.
func newHPATestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	_ = autoscalingv2.AddToScheme(s)
	_ = operatorv1alpha1.AddToScheme(s)
	return s
}

// makeTestDeployment creates a minimal Deployment fixture for HPA tests.
func makeTestDeployment(name, namespace string, replicas int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      map[string]string{},
			Annotations: map[string]string{},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(replicas),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": name},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  name,
							Image: "test-image:latest",
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("500m"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
							},
						},
					},
				},
			},
		},
	}
}

// makeHPAFixture creates a minimal HPA fixture.
func makeHPAFixture(deployName, namespace string) *autoscalingv2.HorizontalPodAutoscaler {
	minReplicas := int32(1)
	return &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployName + "-hpa",
			Namespace: namespace,
		},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       deployName,
			},
			MinReplicas: &minReplicas,
			MaxReplicas: 3,
		},
	}
}

// makeAuthCRForHPA creates a minimal Authentication CR for HPA tests.
func makeAuthCRForHPA(namespace string, globalReplicas int32, autoScale bool) *operatorv1alpha1.Authentication {
	return &operatorv1alpha1.Authentication{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.ibm.com/v1alpha1",
			Kind:       "Authentication",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            "example-authentication",
			Namespace:       namespace,
			ResourceVersion: trackerAddResourceVersion,
		},
		Spec: operatorv1alpha1.AuthenticationSpec{
			OperatorVersion: "4.0.0",
			Replicas:        globalReplicas,
			AutoScaleConfig: autoScale,
		},
	}
}

// newHPAReconciler creates an AuthenticationReconciler backed by a fake client
// pre-seeded with the given objects.
func newHPAReconciler(scheme *runtime.Scheme, objs ...client.Object) *AuthenticationReconciler {
	cl := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		Build()
	return &AuthenticationReconciler{
		Client: cl,
	}
}

// hpaRequest builds a ctrl.Request for the given namespace/name.
func hpaRequest(namespace, name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: namespace}}
}

var _ = Describe("HPA helpers", func() {
	const hpaNS = "hpa-test-ns"

	Describe("deleteHPAIfPresent", func() {
		var (
			ctx    context.Context
			scheme *runtime.Scheme
		)

		BeforeEach(func() {
			ctx = context.Background()
			scheme = newHPATestScheme()
		})

		It("returns (true, nil) and removes the HPA when it exists", func() {
			hpa := makeHPAFixture("platform-auth-service", hpaNS)
			cl := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(hpa).Build()
			deleted, err := deleteHPAIfPresent(ctx, cl, hpa.Name, hpaNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(deleted).To(BeTrue())
			// Confirm it was actually removed.
			found := &autoscalingv2.HorizontalPodAutoscaler{}
			getErr := cl.Get(ctx, types.NamespacedName{Name: hpa.Name, Namespace: hpaNS}, found)
			Expect(errors.IsNotFound(getErr)).To(BeTrue())
		})

		It("returns (false, nil) when the HPA does not exist", func() {
			cl := fakeclient.NewClientBuilder().WithScheme(scheme).Build()
			deleted, err := deleteHPAIfPresent(ctx, cl, "nonexistent-hpa", hpaNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(deleted).To(BeFalse())
		})

		It("returns (false, err) when Get returns a non-NotFound error", func() {
			cl := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
						if _, ok := obj.(*autoscalingv2.HorizontalPodAutoscaler); ok {
							return fmt.Errorf("server unavailable")
						}
						return nil
					},
				}).
				Build()
			deleted, err := deleteHPAIfPresent(ctx, cl, "any-hpa", hpaNS)
			Expect(err).To(HaveOccurred())
			Expect(deleted).To(BeFalse())
		})

		It("returns (false, err) when Delete returns a non-NotFound error", func() {
			hpa := makeHPAFixture("platform-auth-service", hpaNS)
			cl := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(hpa).
				WithInterceptorFuncs(interceptor.Funcs{
					Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
						if _, ok := obj.(*autoscalingv2.HorizontalPodAutoscaler); ok {
							return fmt.Errorf("delete forbidden")
						}
						return nil
					},
				}).
				Build()
			deleted, err := deleteHPAIfPresent(ctx, cl, hpa.Name, hpaNS)
			Expect(err).To(HaveOccurred())
			Expect(deleted).To(BeFalse())
		})

		It("returns (true, nil) when Delete returns NotFound (HPA removed between Get and Delete)", func() {
			hpa := makeHPAFixture("platform-auth-service", hpaNS)
			cl := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(hpa).
				WithInterceptorFuncs(interceptor.Funcs{
					Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
						if _, ok := obj.(*autoscalingv2.HorizontalPodAutoscaler); ok {
							return errors.NewNotFound(
								schema.GroupResource{Group: "autoscaling", Resource: "horizontalpodautoscalers"},
								obj.GetName(),
							)
						}
						return nil
					},
				}).
				Build()
			deleted, err := deleteHPAIfPresent(ctx, cl, hpa.Name, hpaNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(deleted).To(BeTrue())
		})
	})

	Describe("buildHPAReconciler", func() {
		It("returns a reconciler with the correct name and namespace", func() {
			authCR := makeAuthCRForHPA(hpaNS, 2, true)
			scheme := newHPATestScheme()
			deploy := makeTestDeployment("platform-auth-service", hpaNS, 2)
			cl := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(authCR, deploy).Build()
			rec := buildHPAReconciler(authCR, "platform-auth-service", hpaNS, cl)
			Expect(rec.GetName()).To(Equal("platform-auth-service-hpa"))
			Expect(rec.GetNamespace()).To(Equal(hpaNS))
		})
	})

	Describe("generateHPAObject", func() {
		// Regression for §5.2.3: generateHPAObject uses spec.Replicas only and
		// is not affected when per-service fields are set on OTHER services.
		It("uses spec.Replicas for minReplicas and maxReplicas, regardless of per-service fields on other services", func() {
			authCR := makeAuthCRForHPA(hpaNS, 2, true)
			// Set per-service replicas on OTHER services — must not affect HPA for auth-service.
			authCR.Spec.IdentityProvider.Replicas = ptr.To(int32(5))
			authCR.Spec.IdentityManager.Replicas = ptr.To(int32(7))

			scheme := newHPATestScheme()
			deploy := makeTestDeployment("platform-auth-service", hpaNS, 2)
			cl := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(deploy).Build()

			s := deploymentSecondary{
				name:      "platform-auth-service",
				namespace: hpaNS,
				authCR:    authCR,
				Client:    cl,
			}
			hpa := &autoscalingv2.HorizontalPodAutoscaler{}
			Expect(generateHPAObject(authCR, "platform-auth-service")(s, context.Background(), hpa)).To(Succeed())

			expectedMin := int32(2)
			expectedMax := int32(2*2 + 1)
			Expect(hpa.Spec.MinReplicas).NotTo(BeNil())
			Expect(*hpa.Spec.MinReplicas).To(Equal(expectedMin))
			Expect(hpa.Spec.MaxReplicas).To(Equal(expectedMax))
		})
	})

	Describe("modifyHPA", func() {
		// Regression for §5.2.4: modifyHPA is unchanged and uses global spec.Replicas.
		// The observed HPA is pre-seeded with the correct owner reference so that
		// IsControllerOf returns true and SetControllerReference is not called.
		makeObservedHPA := func(authCR *operatorv1alpha1.Authentication, minR, maxR int32) *autoscalingv2.HorizontalPodAutoscaler {
			t := true
			return &autoscalingv2.HorizontalPodAutoscaler{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "platform-auth-service-hpa",
					Namespace: hpaNS,
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "operator.ibm.com/v1alpha1",
							Kind:       "Authentication",
							Name:       authCR.Name,
							UID:        authCR.UID,
							Controller: &t,
						},
					},
				},
				Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
					MinReplicas: &minR,
					MaxReplicas: maxR,
				},
			}
		}

		It("modifies the observed HPA when minReplicas do not match spec.Replicas", func() {
			authCR := makeAuthCRForHPA(hpaNS, 2, true)
			scheme := newHPATestScheme()
			cl := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(authCR).Build()

			s := deploymentSecondary{
				name:      "platform-auth-service-hpa",
				namespace: hpaNS,
				authCR:    authCR,
				Client:    cl,
			}
			observed := makeObservedHPA(authCR, int32(5), int32(11))
			generatedMin := int32(2)
			generated := &autoscalingv2.HorizontalPodAutoscaler{
				Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
					MinReplicas: &generatedMin,
					MaxReplicas: int32(2*2 + 1),
				},
			}
			modified, err := modifyHPA()(s, context.Background(), observed, generated)
			Expect(err).NotTo(HaveOccurred())
			Expect(modified).To(BeTrue())
		})

		It("does not modify when minReplicas and maxReplicas already match", func() {
			authCR := makeAuthCRForHPA(hpaNS, 2, true)
			scheme := newHPATestScheme()
			cl := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(authCR).Build()

			s := deploymentSecondary{
				name:      "platform-auth-service-hpa",
				namespace: hpaNS,
				authCR:    authCR,
				Client:    cl,
			}
			minReplicas := int32(2)
			maxReplicas := int32(2*2 + 1)
			observed := makeObservedHPA(authCR, minReplicas, maxReplicas)
			generated := &autoscalingv2.HorizontalPodAutoscaler{
				Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
					MinReplicas: &minReplicas,
					MaxReplicas: maxReplicas,
				},
			}
			modified, err := modifyHPA()(s, context.Background(), observed, generated)
			Expect(err).NotTo(HaveOccurred())
			Expect(modified).To(BeFalse())
		})
	})

	Describe("UpdateDeploymentReplicas", func() {
		var (
			ctx    context.Context
			scheme *runtime.Scheme
		)

		BeforeEach(func() {
			ctx = context.Background()
			scheme = newHPATestScheme()
		})

		It("updates the Deployment when observed replicas differ from desired", func() {
			deploy := makeTestDeployment("platform-auth-service", hpaNS, 3)
			r := newHPAReconciler(scheme, deploy)
			Expect(r.UpdateDeploymentReplicas(ctx, "platform-auth-service", hpaNS, int32(1))).To(Succeed())
			updated := &appsv1.Deployment{}
			Expect(r.Get(ctx, types.NamespacedName{Name: "platform-auth-service", Namespace: hpaNS}, updated)).To(Succeed())
			Expect(*updated.Spec.Replicas).To(Equal(int32(1)))
		})

		It("does not update when observed replicas already match", func() {
			deploy := makeTestDeployment("platform-auth-service", hpaNS, 2)
			r := newHPAReconciler(scheme, deploy)
			Expect(r.UpdateDeploymentReplicas(ctx, "platform-auth-service", hpaNS, int32(2))).To(Succeed())
			updated := &appsv1.Deployment{}
			Expect(r.Get(ctx, types.NamespacedName{Name: "platform-auth-service", Namespace: hpaNS}, updated)).To(Succeed())
			Expect(*updated.Spec.Replicas).To(Equal(int32(2)))
		})

		It("returns an error when the Deployment does not exist", func() {
			r := newHPAReconciler(scheme)
			err := r.UpdateDeploymentReplicas(ctx, "nonexistent", hpaNS, int32(1))
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("handleHPAs precedence table (§4.3)", func() {
		// These tests call handleHPAs and assert final HPA state.
		// handleHPAs uses r.getLatestAuthentication internally, which reads the
		// Authentication CR from the fake client by the request's NamespacedName.

		const globalReplicas = int32(2)

		deploymentNames := []string{
			"platform-auth-service",
			"platform-identity-provider",
			"platform-identity-management",
		}

		hpaNameFor := func(d string) string { return d + "-hpa" }

		allHPANames := []string{
			hpaNameFor("platform-auth-service"),
			hpaNameFor("platform-identity-provider"),
			hpaNameFor("platform-identity-management"),
		}

		type hpaScenario struct {
			description  string
			autoScale    bool
			perSvcSetter func(cr *operatorv1alpha1.Authentication)
			preExistHPAs []string // deployment names whose HPAs to pre-seed
			expectHPAs   []string // HPA names that must exist after reconcile
			expectNoHPAs []string // HPA names that must NOT exist after reconcile
		}

		scenarios := []hpaScenario{
			{
				description:  "Pin on authService, autoScale off, no stale HPA → no HPAs",
				autoScale:    false,
				perSvcSetter: func(cr *operatorv1alpha1.Authentication) { cr.Spec.AuthService.Replicas = ptr.To(int32(1)) },
				expectNoHPAs: allHPANames,
			},
			{
				description:  "Pin on authService, autoScale on, no stale HPA → no HPA for authService, HPAs for others",
				autoScale:    true,
				perSvcSetter: func(cr *operatorv1alpha1.Authentication) { cr.Spec.AuthService.Replicas = ptr.To(int32(1)) },
				expectHPAs:   []string{hpaNameFor("platform-identity-provider"), hpaNameFor("platform-identity-management")},
				expectNoHPAs: []string{hpaNameFor("platform-auth-service")},
			},
			{
				description:  "Pin on authService, autoScale on, stale HPA exists → stale HPA deleted, others created",
				autoScale:    true,
				perSvcSetter: func(cr *operatorv1alpha1.Authentication) { cr.Spec.AuthService.Replicas = ptr.To(int32(1)) },
				preExistHPAs: []string{"platform-auth-service"},
				expectHPAs:   []string{hpaNameFor("platform-identity-provider"), hpaNameFor("platform-identity-management")},
				expectNoHPAs: []string{hpaNameFor("platform-auth-service")},
			},
			{
				description:  "No pin, autoScale off → no HPAs",
				autoScale:    false,
				perSvcSetter: func(_ *operatorv1alpha1.Authentication) {},
				expectNoHPAs: allHPANames,
			},
			{
				description:  "No pin, autoScale off, stale HPA exists → stale HPA deleted",
				autoScale:    false,
				perSvcSetter: func(_ *operatorv1alpha1.Authentication) {},
				preExistHPAs: []string{"platform-auth-service"},
				expectNoHPAs: allHPANames,
			},
			{
				description:  "No pin, autoScale on → HPAs created for all services",
				autoScale:    true,
				perSvcSetter: func(_ *operatorv1alpha1.Authentication) {},
				expectHPAs:   allHPANames,
			},
			{
				description: "Mixed: pin on authService only, autoScale on → HPAs for idp and idm only",
				autoScale:   true,
				perSvcSetter: func(cr *operatorv1alpha1.Authentication) {
					cr.Spec.AuthService.Replicas = ptr.To(int32(1))
				},
				expectHPAs:   []string{hpaNameFor("platform-identity-provider"), hpaNameFor("platform-identity-management")},
				expectNoHPAs: []string{hpaNameFor("platform-auth-service")},
			},
			{
				description:  "Per-service value 1 (lower bound), autoScale on, stale HPA → deleted",
				autoScale:    true,
				perSvcSetter: func(cr *operatorv1alpha1.Authentication) { cr.Spec.AuthService.Replicas = ptr.To(int32(1)) },
				preExistHPAs: []string{"platform-auth-service"},
				expectNoHPAs: []string{hpaNameFor("platform-auth-service")},
				expectHPAs:   []string{hpaNameFor("platform-identity-provider"), hpaNameFor("platform-identity-management")},
			},
		}

		for _, sc := range scenarios {
			sc := sc // capture
			It(sc.description, func() {
				ctx := context.Background()
				scheme := newHPATestScheme()
				authCR := makeAuthCRForHPA(hpaNS, globalReplicas, sc.autoScale)
				sc.perSvcSetter(authCR)

				objects := []client.Object{authCR}
				for _, d := range deploymentNames {
					objects = append(objects, makeTestDeployment(d, hpaNS, globalReplicas))
				}
				for _, d := range sc.preExistHPAs {
					objects = append(objects, makeHPAFixture(d, hpaNS))
				}

				r := newHPAReconciler(scheme, objects...)
				req := hpaRequest(hpaNS, authCR.Name)
				_, err := r.handleHPAs(ctx, req)
				Expect(err).NotTo(HaveOccurred())

				for _, name := range sc.expectHPAs {
					found := &autoscalingv2.HorizontalPodAutoscaler{}
					Expect(r.Get(ctx, types.NamespacedName{Name: name, Namespace: hpaNS}, found)).
						To(Succeed(), "expected HPA %s to exist", name)
				}
				for _, name := range sc.expectNoHPAs {
					found := &autoscalingv2.HorizontalPodAutoscaler{}
					getErr := r.Get(ctx, types.NamespacedName{Name: name, Namespace: hpaNS}, found)
					Expect(errors.IsNotFound(getErr)).To(BeTrue(), "expected HPA %s to NOT exist, but got err: %v", name, getErr)
				}
			})
		}

		It("does not modify r.needsRollout (§5.2.2: assignment removed from handleHPAs)", func() {
			// needsRollout starts true; after handleHPAs it must still be true.
			ctx := context.Background()
			scheme := newHPATestScheme()
			authCR := makeAuthCRForHPA(hpaNS, globalReplicas, false)
			objects := []client.Object{authCR}
			for _, d := range deploymentNames {
				objects = append(objects, makeTestDeployment(d, hpaNS, globalReplicas))
			}
			r := newHPAReconciler(scheme, objects...)
			r.needsRollout = true
			req := hpaRequest(hpaNS, authCR.Name)
			_, err := r.handleHPAs(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.needsRollout).To(BeTrue())
		})
	})
})
