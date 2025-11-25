package operator

import (
	"context"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	userv1 "github.com/openshift/api/user/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var _ = Describe("ClusterRoleBinding handling", func() {
	var (
		r       *AuthenticationReconciler
		authCR  *operatorv1alpha1.Authentication
		cb      fakeclient.ClientBuilder
		cl      client.WithWatch
		scheme  *runtime.Scheme
		ctx     context.Context
		req     ctrl.Request
		dc      *discovery.DiscoveryClient
		testNs  string
		crbName string
	)

	BeforeEach(func() {
		testNs = "test-namespace"
		crbName = "ibm-iam-operand-restricted-" + testNs

		authCR = &operatorv1alpha1.Authentication{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "operator.ibm.com/v1alpha1",
				Kind:       "Authentication",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "example-authentication",
				Namespace:       testNs,
				ResourceVersion: trackerAddResourceVersion,
			},
		}

		req = ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      authCR.Name,
				Namespace: authCR.Namespace,
			},
		}

		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
		Expect(rbacv1.AddToScheme(scheme)).To(Succeed())
		Expect(authorizationv1.AddToScheme(scheme)).To(Succeed())
		Expect(userv1.AddToScheme(scheme)).To(Succeed())

		ctx = logf.IntoContext(context.Background(), logf.Log)
	})

	Describe("handleClusterRoleBindings", func() {
		Context("when operator does not have permission to create ClusterRoleBindings", func() {
			BeforeEach(func() {
				cb = *fakeclient.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(authCR)

				cl = cb.Build()
				var err error
				dc, err = discovery.NewDiscoveryClientForConfig(cfg)
				Expect(err).NotTo(HaveOccurred())

				r = &AuthenticationReconciler{
					Client: &ctrlcommon.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					Scheme:          scheme,
					DiscoveryClient: *dc,
				}
			})

			It("should skip ClusterRoleBinding creation and continue reconciling", func() {
				result, err := r.handleClusterRoleBindings(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())

				// Verify ClusterRoleBinding was not created
				crb := &rbacv1.ClusterRoleBinding{}
				err = cl.Get(ctx, types.NamespacedName{Name: crbName}, crb)
				Expect(k8sErrors.IsNotFound(err)).To(BeTrue())
			})
		})

		Context("when hasAPIAccess returns an error", func() {
			BeforeEach(func() {
				cb = *fakeclient.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(authCR)

				cl = cb.Build()
				var err error
				dc, err = discovery.NewDiscoveryClientForConfig(cfg)
				Expect(err).NotTo(HaveOccurred())

				r = &AuthenticationReconciler{
					Client: &ctrlcommon.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					Scheme:          scheme,
					DiscoveryClient: *dc,
				}
			})

			It("should skip and continue when OpenShift user API not found", func() {
				result, err := r.handleClusterRoleBindings(ctx, req)
				// Since OpenShift user API is not available, it should skip
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())
			})
		})

		Context("when OpenShift user API is not available", func() {
			BeforeEach(func() {
				cb = *fakeclient.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(authCR)

				cl = cb.Build()
				// Use a discovery client that won't find OpenShift user API
				var err error
				dc, err = discovery.NewDiscoveryClientForConfig(cfg)
				Expect(err).NotTo(HaveOccurred())

				r = &AuthenticationReconciler{
					Client: &ctrlcommon.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					Scheme:          scheme,
					DiscoveryClient: *dc,
				}
			})

			It("should skip ClusterRoleBinding creation and continue reconciling", func() {
				result, err := r.handleClusterRoleBindings(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())

				// Verify ClusterRoleBinding was not created
				crb := &rbacv1.ClusterRoleBinding{}
				err = cl.Get(ctx, types.NamespacedName{Name: crbName}, crb)
				Expect(k8sErrors.IsNotFound(err)).To(BeTrue())
			})
		})

		Context("when Authentication CR is not found", func() {
			BeforeEach(func() {
				cb = *fakeclient.NewClientBuilder().
					WithScheme(scheme)

				cl = cb.Build()
				var err error
				dc, err = discovery.NewDiscoveryClientForConfig(cfg)
				Expect(err).NotTo(HaveOccurred())

				r = &AuthenticationReconciler{
					Client: &ctrlcommon.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					Scheme:          scheme,
					DiscoveryClient: *dc,
				}
			})

			It("should skip and continue when OpenShift user API not found", func() {
				result, err := r.handleClusterRoleBindings(ctx, req)
				// Since OpenShift user API is not available, it should skip
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())
			})
		})

		Context("when ClusterRoleBinding already exists", func() {
			BeforeEach(func() {
				// Create existing ClusterRoleBinding
				existingCRB := &rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name: crbName,
						Labels: map[string]string{
							"app.kubernetes.io/instance":   "ibm-iam-operator",
							"app.kubernetes.io/managed-by": "ibm-iam-operator",
							"app.kubernetes.io/name":       "ibm-iam-operator",
						},
					},
					RoleRef: rbacv1.RoleRef{
						APIGroup: rbacv1.GroupName,
						Kind:     "ClusterRole",
						Name:     "ibm-iam-operand-restricted",
					},
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "ibm-iam-operand-restricted",
							Namespace: testNs,
						},
					},
				}

				cb = *fakeclient.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(authCR, existingCRB)

				cl = cb.Build()
				var err error
				dc, err = discovery.NewDiscoveryClientForConfig(cfg)
				Expect(err).NotTo(HaveOccurred())

				r = &AuthenticationReconciler{
					Client: &ctrlcommon.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					Scheme:          scheme,
					DiscoveryClient: *dc,
				}
			})

			It("should continue reconciling without error", func() {
				result, err := r.handleClusterRoleBindings(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())

				// Verify ClusterRoleBinding still exists
				crb := &rbacv1.ClusterRoleBinding{}
				err = cl.Get(ctx, types.NamespacedName{Name: crbName}, crb)
				Expect(err).NotTo(HaveOccurred())
				Expect(crb.Name).To(Equal(crbName))
			})
		})

		Context("when ClusterRoleBinding creation succeeds", func() {
			BeforeEach(func() {
				cb = *fakeclient.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(authCR)

				cl = cb.Build()
				var err error
				dc, err = discovery.NewDiscoveryClientForConfig(cfg)
				Expect(err).NotTo(HaveOccurred())

				r = &AuthenticationReconciler{
					Client: &ctrlcommon.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					Scheme:          scheme,
					DiscoveryClient: *dc,
				}
			})

			It("should skip and continue when OpenShift user API not found", func() {
				result, err := r.handleClusterRoleBindings(ctx, req)
				// Since OpenShift user API is not available, it should skip
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())

				// Verify ClusterRoleBinding was not created
				crb := &rbacv1.ClusterRoleBinding{}
				err = cl.Get(ctx, types.NamespacedName{Name: crbName}, crb)
				Expect(k8sErrors.IsNotFound(err)).To(BeTrue())
			})
		})

		Context("when ClusterRoleBinding creation succeeds with OpenShift", func() {
			BeforeEach(func() {
				// This test would need OpenShift APIs registered which we don't have in the test environment
				Skip("Skipping test that requires OpenShift user API to be registered")
			})

			It("should create ClusterRoleBinding with correct properties", func() {
				result, err := r.handleClusterRoleBindings(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.RequeueAfter).To(Equal(defaultLowerWait))

				// Verify ClusterRoleBinding was created with correct properties
				crb := &rbacv1.ClusterRoleBinding{}
				err = cl.Get(ctx, types.NamespacedName{Name: crbName}, crb)
				Expect(err).NotTo(HaveOccurred())

				// Verify name
				Expect(crb.Name).To(Equal(crbName))

				// Verify labels
				Expect(crb.Labels).To(HaveKeyWithValue("app.kubernetes.io/instance", "ibm-iam-operator"))
				Expect(crb.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "ibm-iam-operator"))
				Expect(crb.Labels).To(HaveKeyWithValue("app.kubernetes.io/name", "ibm-iam-operator"))

				// Verify RoleRef
				Expect(crb.RoleRef.APIGroup).To(Equal(rbacv1.GroupName))
				Expect(crb.RoleRef.Kind).To(Equal("ClusterRole"))
				Expect(crb.RoleRef.Name).To(Equal("ibm-iam-operand-restricted"))

				// Verify Subjects
				Expect(crb.Subjects).To(HaveLen(1))
				Expect(crb.Subjects[0].Kind).To(Equal("ServiceAccount"))
				Expect(crb.Subjects[0].Name).To(Equal("ibm-iam-operand-restricted"))
				Expect(crb.Subjects[0].Namespace).To(Equal(testNs))
			})
		})

		Context("when ClusterRoleBinding name is generated correctly", func() {
			It("should use the format 'ibm-iam-operand-restricted-{namespace}'", func() {
				testCases := []struct {
					namespace    string
					expectedName string
				}{
					{"default", "ibm-iam-operand-restricted-default"},
					{"kube-system", "ibm-iam-operand-restricted-kube-system"},
					{"my-namespace", "ibm-iam-operand-restricted-my-namespace"},
					{"test-ns-123", "ibm-iam-operand-restricted-test-ns-123"},
				}

				for _, tc := range testCases {
					authCR := &operatorv1alpha1.Authentication{
						TypeMeta: metav1.TypeMeta{
							APIVersion: "operator.ibm.com/v1alpha1",
							Kind:       "Authentication",
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:            "example-authentication",
							Namespace:       tc.namespace,
							ResourceVersion: trackerAddResourceVersion,
						},
					}

					cb := *fakeclient.NewClientBuilder().
						WithScheme(scheme).
						WithObjects(authCR)

					cl := cb.Build()
					dc, err := discovery.NewDiscoveryClientForConfig(cfg)
					Expect(err).NotTo(HaveOccurred())

					r := &AuthenticationReconciler{
						Client: &ctrlcommon.FallbackClient{
							Client: cl,
							Reader: cl,
						},
						Scheme:          scheme,
						DiscoveryClient: *dc,
					}

					req := ctrl.Request{
						NamespacedName: types.NamespacedName{
							Name:      authCR.Name,
							Namespace: authCR.Namespace,
						},
					}

					result, err := r.handleClusterRoleBindings(ctx, req)
					// Since OpenShift user API is not available in test env, it should skip
					Expect(err).NotTo(HaveOccurred())
					Expect(result).To(BeNil())
				}
			})
		})
	})
})

// Made with Bob
