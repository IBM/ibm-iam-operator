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

package operator

import (
	"context"
	"net/http"
	"net/http/httptest"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	testutil "github.com/IBM/ibm-iam-operator/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	restclient "k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Service handling", func() {
	const (
		authCRName = "example-authentication"
		namespace  = "data-ns"
	)

	var (
		r      *AuthenticationReconciler
		authCR *operatorv1alpha1.Authentication
		cl     client.WithWatch
		scheme *runtime.Scheme
		ctx    context.Context
		req    ctrl.Request
		server *httptest.Server
	)

	// newAuthCR returns a minimal Authentication CR with the given zenFrontDoor value.
	newAuthCR := func(zenFrontDoor bool) *operatorv1alpha1.Authentication {
		return &operatorv1alpha1.Authentication{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "operator.ibm.com/v1alpha1",
				Kind:       "Authentication",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            authCRName,
				Namespace:       namespace,
				ResourceVersion: trackerAddResourceVersion,
			},
			Spec: operatorv1alpha1.AuthenticationSpec{
				Config: operatorv1alpha1.ConfigSpec{
					ZenFrontDoor: zenFrontDoor,
				},
			},
		}
	}

	// setupReconciler creates the fake client and reconciler for the given authCR and
	// any optional extra objects that should pre-exist in the store.
	// Uses an httptest server for the DiscoveryClient so no envtest binaries are needed.
	setupReconciler := func(cr *operatorv1alpha1.Authentication, extras ...client.Object) {
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())

		objs := []client.Object{cr}
		objs = append(objs, extras...)

		cb := fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(objs...)
		cl = cb.Build()

		// Use an httptest server instead of envtest so no kubebuilder binaries are needed.
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
		}))
		dc := discovery.NewDiscoveryClientForConfigOrDie(&restclient.Config{Host: server.URL})

		r = &AuthenticationReconciler{
			Client: &ctrlcommon.FallbackClient{
				Client: cl,
				Reader: cl,
			},
			DiscoveryClient: *dc,
		}
		ctx = context.Background()
		req = ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      authCRName,
				Namespace: namespace,
			},
		}
	}

	AfterEach(func() {
		if server != nil {
			server.Close()
			server = nil
		}
	})

	// getService fetches the named Service from the fake store.
	getService := func(name string) (*corev1.Service, error) {
		svc := &corev1.Service{}
		err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, svc)
		return svc, err
	}

	Describe("handleServices", func() {

		Describe("platform-auth-service", func() {

			Context("when zenFrontDoor is false", func() {
				BeforeEach(func() {
					authCR = newAuthCR(false)
					setupReconciler(authCR)
				})

				It("creates the service with a regular ClusterIP (not headless)", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService("platform-auth-service")
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.ClusterIP).NotTo(Equal("None"))
				})

				It("creates the service with SessionAffinity ClientIP", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService("platform-auth-service")
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.SessionAffinity).To(Equal(corev1.ServiceAffinityClientIP))
				})

				It("creates the service with only the p9443 port (no p3100)", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService("platform-auth-service")
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.Ports).To(HaveLen(1))
					Expect(svc.Spec.Ports[0].Name).To(Equal("p9443"))
					Expect(svc.Spec.Ports[0].Port).To(BeEquivalentTo(9443))
				})
			})

			Context("when zenFrontDoor is true", func() {
				BeforeEach(func() {
					authCR = newAuthCR(true)
					setupReconciler(authCR)
				})

				It("creates the service as headless (ClusterIP: None)", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService("platform-auth-service")
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.ClusterIP).To(Equal("None"))
				})

				It("creates the service with no SessionAffinity when headless", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService("platform-auth-service")
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.SessionAffinity).To(Equal(corev1.ServiceAffinityNone))
				})

				It("creates the service with only the p9443 port (no p3100)", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService("platform-auth-service")
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.Ports).To(HaveLen(1))
					Expect(svc.Spec.Ports[0].Name).To(Equal("p9443"))
					Expect(svc.Spec.Ports[0].Port).To(BeEquivalentTo(9443))
				})

				Context("when a non-headless platform-auth-service already exists (upgrade scenario)", func() {
					BeforeEach(func() {
						authCR = newAuthCR(true)
						// Pre-create a non-headless service to simulate an existing deployment
						// before zenFrontDoor was enabled.
						existingSvc := &corev1.Service{
							ObjectMeta: metav1.ObjectMeta{
								Name:            "platform-auth-service",
								Namespace:       namespace,
								ResourceVersion: trackerAddResourceVersion,
							},
							Spec: corev1.ServiceSpec{
								ClusterIP: "10.0.0.1",
								Ports: []corev1.ServicePort{
									{Name: "p9443", Port: 9443},
								},
								Selector:        map[string]string{"k8s-app": "platform-auth-service"},
								SessionAffinity: corev1.ServiceAffinityClientIP,
							},
						}
						setupReconciler(authCR, existingSvc)
					})

					It("deletes the non-headless service so it can be recreated as headless", func() {
						// First reconcile: deleteServiceIfNotHeadless fires and removes the
						// existing service; the secondary reconciler then creates it headless
						// (404 → create path), triggering a requeue.
						result, err := r.handleServices(ctx, req)
						testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

						// The old non-headless service must no longer exist after the first reconcile.
						_, err = getService("platform-auth-service")
						Expect(k8sErrors.IsNotFound(err)).To(BeTrue(),
							"expected the non-headless service to have been deleted")
					})

					It("creates a headless service on the second reconcile after deletion", func() {
						// First reconcile: deletes the non-headless service.
						_, _ = r.handleServices(ctx, req)

						// Second reconcile: service is absent, secondary reconciler creates it headless.
						result, err := r.handleServices(ctx, req)
						testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

						svc, err := getService("platform-auth-service")
						Expect(err).ToNot(HaveOccurred())
						Expect(svc.Spec.ClusterIP).To(Equal("None"))
					})
				})
			})
	
			Context("when zenFrontDoor is changed from true to false (headless → regular transition)", func() {
				BeforeEach(func() {
					authCR = newAuthCR(false) // zenFrontDoor now false
					// Pre-create a headless service left over from when zenFrontDoor was true.
					existingHeadlessSvc := &corev1.Service{
						ObjectMeta: metav1.ObjectMeta{
							Name:            "platform-auth-service",
							Namespace:       namespace,
							ResourceVersion: trackerAddResourceVersion,
						},
						Spec: corev1.ServiceSpec{
							ClusterIP: "None",
							Ports: []corev1.ServicePort{
								{Name: "p9443", Port: 9443},
							},
							Selector:        map[string]string{"k8s-app": "platform-auth-service"},
							SessionAffinity: corev1.ServiceAffinityNone,
						},
					}
					setupReconciler(authCR, existingHeadlessSvc)
				})
	
				It("deletes the headless service so it can be recreated as a regular ClusterIP service", func() {
					// First reconcile: deleteServiceIfHeadless fires and removes the
					// existing headless service; the secondary reconciler then creates
					// it as a regular service (404 → create path), triggering a requeue.
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
	
					// The headless service must no longer exist after the first reconcile.
					_, err = getService("platform-auth-service")
					Expect(k8sErrors.IsNotFound(err)).To(BeTrue(),
						"expected the headless service to have been deleted")
				})
	
				It("creates a regular ClusterIP service on the second reconcile after deletion", func() {
					// First reconcile: deletes the headless service.
					_, _ = r.handleServices(ctx, req)
	
					// Second reconcile: service is absent, secondary reconciler creates it as regular.
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
	
					svc, err := getService("platform-auth-service")
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.ClusterIP).NotTo(Equal("None"))
					Expect(svc.Spec.SessionAffinity).To(Equal(corev1.ServiceAffinityClientIP))
				})
			})
		})
	
		Describe("other services are not affected by zenFrontDoor", func() {
			BeforeEach(func() {
				authCR = newAuthCR(true)
				setupReconciler(authCR)
			})

			It("always creates platform-identity-management without headless ClusterIP", func() {
				result, err := r.handleServices(ctx, req)
				testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

				svc, err := getService("platform-identity-management")
				Expect(err).ToNot(HaveOccurred())
				Expect(svc.Spec.ClusterIP).NotTo(Equal("None"))
			})

			It("always creates platform-identity-provider without headless ClusterIP", func() {
				result, err := r.handleServices(ctx, req)
				testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

				svc, err := getService("platform-identity-provider")
				Expect(err).ToNot(HaveOccurred())
				Expect(svc.Spec.ClusterIP).NotTo(Equal("None"))
			})
		})
	})
})
