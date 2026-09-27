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
	"k8s.io/utils/ptr"
)

var _ = Describe("Service handling", func() {
	const (
		authCRName           = "example-authentication"
		namespace            = "data-ns"
		headlessServiceName  = "platform-auth-service-headless"
		gvkNone              = "none"
		gvkOCPRoute          = "openshift.io/v1/route"
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

	// newAuthCR returns an Authentication CR with the given zenFrontDoor value.
	// gvk may be nil (unset), gvkNone ("none"), or gvkOCPRoute ("openshift.io/v1/route").
	newAuthCR := func(zenFrontDoor bool, gvk *string) *operatorv1alpha1.Authentication {
		cr := &operatorv1alpha1.Authentication{
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
		if gvk != nil {
			cr.Spec.Config.Ingress = &operatorv1alpha1.IngressConfig{GVK: gvk}
		}
		return cr
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

		// ─────────────────────────────────────────────────────────────────
		// platform-auth-service: always a regular ClusterIP, never headless
		// ─────────────────────────────────────────────────────────────────
		Describe("platform-auth-service", func() {
			Context("when zenFrontDoor is false", func() {
				BeforeEach(func() {
					authCR = newAuthCR(false, nil)
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

				It("creates the service with both p9443 and p3100 ports", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService("platform-auth-service")
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.Ports).To(HaveLen(2))
					Expect(svc.Spec.Ports[0].Name).To(Equal("p9443"))
					Expect(svc.Spec.Ports[0].Port).To(BeEquivalentTo(9443))
					Expect(svc.Spec.Ports[1].Name).To(Equal("p3100"))
					Expect(svc.Spec.Ports[1].Port).To(BeEquivalentTo(3100))
				})
			})

			Context("when zenFrontDoor is true and gvk is none", func() {
				BeforeEach(func() {
					authCR = newAuthCR(true, ptr.To(gvkNone))
					setupReconciler(authCR)
				})

				It("still creates platform-auth-service as a regular ClusterIP (not headless)", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService("platform-auth-service")
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.ClusterIP).NotTo(Equal("None"),
						"platform-auth-service must never be made headless")
				})

				It("still creates platform-auth-service with SessionAffinity ClientIP", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService("platform-auth-service")
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.SessionAffinity).To(Equal(corev1.ServiceAffinityClientIP))
				})

				It("still creates platform-auth-service with both p9443 and p3100 ports", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService("platform-auth-service")
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.Ports).To(HaveLen(2))
				})
			})
		})

		// ─────────────────────────────────────────────────────────────────
		// platform-auth-service-headless: 4 cases
		// ─────────────────────────────────────────────────────────────────
		Describe("platform-auth-service-headless", func() {

			// Case 1: zenFrontDoor=true AND gvk=none → create headless service
			Context("Case 1: zenFrontDoor=true and gvk=none", func() {
				BeforeEach(func() {
					authCR = newAuthCR(true, ptr.To(gvkNone))
					setupReconciler(authCR)
				})

				It("creates platform-auth-service-headless with ClusterIP: None", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService(headlessServiceName)
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.ClusterIP).To(Equal("None"))
				})

				It("creates platform-auth-service-headless with selector targeting platform-auth-service pods", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService(headlessServiceName)
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.Selector).To(HaveKeyWithValue("k8s-app", "platform-auth-service"))
				})

				It("creates platform-auth-service-headless with port p9443", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					svc, err := getService(headlessServiceName)
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.Ports).To(HaveLen(1))
					Expect(svc.Spec.Ports[0].Name).To(Equal("p9443"))
					Expect(svc.Spec.Ports[0].Port).To(BeEquivalentTo(9443))
				})

				It("is idempotent: second reconcile succeeds without re-creating the service", func() {
					_, _ = r.handleServices(ctx, req) // first: creates
					_, err := r.handleServices(ctx, req) // second: no-op drift
					Expect(err).ToNot(HaveOccurred())

					svc, err := getService(headlessServiceName)
					Expect(err).ToNot(HaveOccurred())
					Expect(svc.Spec.ClusterIP).To(Equal("None"))
				})
			})

			// Case 2: zenFrontDoor=true BUT gvk removed/changed → delete headless service
			Context("Case 2: zenFrontDoor=true but gvk is unset (removed)", func() {
				BeforeEach(func() {
					// Pre-create the headless service as if it existed from Case 1.
					existingHeadless := &corev1.Service{
						ObjectMeta: metav1.ObjectMeta{
							Name:            headlessServiceName,
							Namespace:       namespace,
							ResourceVersion: trackerAddResourceVersion,
						},
						Spec: corev1.ServiceSpec{
							ClusterIP: "None",
							Selector:  map[string]string{"k8s-app": "platform-auth-service"},
							Ports:     []corev1.ServicePort{{Name: "p9443", Port: 9443}},
						},
					}
					// gvk is nil (not set) → ShouldRemoveRoutes() returns false
					authCR = newAuthCR(true, nil)
					setupReconciler(authCR, existingHeadless)
				})

				It("deletes platform-auth-service-headless", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					_, err = getService(headlessServiceName)
					Expect(k8sErrors.IsNotFound(err)).To(BeTrue(),
						"expected platform-auth-service-headless to have been deleted")
				})
			})

			// Case 3: zenFrontDoor=false AND gvk=none → delete headless service
			Context("Case 3: zenFrontDoor=false and gvk=none", func() {
				BeforeEach(func() {
					existingHeadless := &corev1.Service{
						ObjectMeta: metav1.ObjectMeta{
							Name:            headlessServiceName,
							Namespace:       namespace,
							ResourceVersion: trackerAddResourceVersion,
						},
						Spec: corev1.ServiceSpec{
							ClusterIP: "None",
							Selector:  map[string]string{"k8s-app": "platform-auth-service"},
							Ports:     []corev1.ServicePort{{Name: "p9443", Port: 9443}},
						},
					}
					authCR = newAuthCR(false, ptr.To(gvkNone))
					setupReconciler(authCR, existingHeadless)
				})

				It("deletes platform-auth-service-headless", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					_, err = getService(headlessServiceName)
					Expect(k8sErrors.IsNotFound(err)).To(BeTrue(),
						"expected platform-auth-service-headless to have been deleted")
				})
			})

			// Case 4: zenFrontDoor=false AND gvk=ocp route → delete headless service
			Context("Case 4: zenFrontDoor=false and gvk=ocp-route", func() {
				BeforeEach(func() {
					existingHeadless := &corev1.Service{
						ObjectMeta: metav1.ObjectMeta{
							Name:            headlessServiceName,
							Namespace:       namespace,
							ResourceVersion: trackerAddResourceVersion,
						},
						Spec: corev1.ServiceSpec{
							ClusterIP: "None",
							Selector:  map[string]string{"k8s-app": "platform-auth-service"},
							Ports:     []corev1.ServicePort{{Name: "p9443", Port: 9443}},
						},
					}
					authCR = newAuthCR(false, ptr.To(gvkOCPRoute))
					setupReconciler(authCR, existingHeadless)
				})

				It("deletes platform-auth-service-headless", func() {
					result, err := r.handleServices(ctx, req)
					testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

					_, err = getService(headlessServiceName)
					Expect(k8sErrors.IsNotFound(err)).To(BeTrue(),
						"expected platform-auth-service-headless to have been deleted")
				})
			})

			// Cleanup is a no-op when the headless service does not exist
			Context("when the headless service does not exist and condition is not met", func() {
				BeforeEach(func() {
					authCR = newAuthCR(false, nil)
					setupReconciler(authCR)
				})

				It("does not error when there is nothing to delete", func() {
					result, err := r.handleServices(ctx, req)
					Expect(err).ToNot(HaveOccurred())
					_ = result // may be nil or requeue depending on other services
				})
			})
		})

		// ─────────────────────────────────────────────────────────────────
		// Other services are unaffected by zenFrontDoor / gvk
		// ─────────────────────────────────────────────────────────────────
		Describe("platform-identity-management and platform-identity-provider", func() {
			BeforeEach(func() {
				authCR = newAuthCR(true, ptr.To(gvkNone))
				setupReconciler(authCR)
			})

			It("always creates platform-identity-management as a regular ClusterIP service", func() {
				result, err := r.handleServices(ctx, req)
				testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

				svc, err := getService("platform-identity-management")
				Expect(err).ToNot(HaveOccurred())
				Expect(svc.Spec.ClusterIP).NotTo(Equal("None"))
			})

			It("always creates platform-identity-provider as a regular ClusterIP service", func() {
				result, err := r.handleServices(ctx, req)
				testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

				svc, err := getService("platform-identity-provider")
				Expect(err).ToNot(HaveOccurred())
				Expect(svc.Spec.ClusterIP).NotTo(Equal("None"))
			})
		})
	})
})
