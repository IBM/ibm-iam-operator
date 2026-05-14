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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("RBAC Cleanup", func() {
	var (
		ctx       context.Context
		namespace string
		authCR    *operatorv1alpha1.Authentication
		req       ctrl.Request
		scheme    *runtime.Scheme
	)

	BeforeEach(func() {
		ctx = context.Background()
		namespace = "test-namespace"

		authCR = &operatorv1alpha1.Authentication{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "operator.ibm.com/v1alpha1",
				Kind:       "Authentication",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "example-authentication",
				Namespace: namespace,
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
		Expect(rbacv1.AddToScheme(scheme)).To(Succeed())
		Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
		Expect(authorizationv1.AddToScheme(scheme)).To(Succeed())
	})

	Describe("cleanupOldRBAC", func() {
		var (
			r              *AuthenticationReconciler
			crbName        string
			existingObjs   []client.Object
			fakeClientSSAR *fakeClientWithSSAR
		)

		BeforeEach(func() {
			crbName = "ibm-iam-operand-restricted-" + namespace
			existingObjs = []client.Object{authCR}
			fakeClientSSAR = nil
		})

		JustBeforeEach(func() {
			baseClient := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(existingObjs...).
				Build()

			var cl client.Client
			if fakeClientSSAR != nil {
				fakeClientSSAR.Client = baseClient
				cl = fakeClientSSAR
			} else {
				cl = &fakeClientWithSSAR{
					Client:   baseClient,
					allowAll: true,
				}
			}

			r = &AuthenticationReconciler{
				Client: cl,
				Scheme: scheme,
			}
		})

		Context("when all resources exist and operator has full permissions", func() {
			BeforeEach(func() {
				existingObjs = append(existingObjs,
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "ibm-iam-operand-restricted",
							Namespace: namespace,
						},
					},
					&rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "ibm-iam-operand-restricted",
							Namespace: namespace,
						},
					},
					&corev1.ServiceAccount{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "ibm-iam-operand-restricted",
							Namespace: namespace,
						},
					},
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name: crbName,
							Labels: map[string]string{
								"app.kubernetes.io/managed-by": "ibm-iam-operator",
							},
						},
						RoleRef: rbacv1.RoleRef{
							Kind: "ClusterRole",
							Name: "ibm-iam-operand-restricted",
						},
					},
					&rbacv1.ClusterRole{
						ObjectMeta: metav1.ObjectMeta{
							Name: "ibm-iam-operand-restricted",
						},
					},
				)
			})

			It("should delete all resources successfully", func() {
				result, err := r.cleanupOldRBAC(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())

				By("verifying RoleBinding is deleted")
				rb := &rbacv1.RoleBinding{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted", Namespace: namespace}, rb)
				Expect(k8sErrors.IsNotFound(err)).To(BeTrue())

				By("verifying Role is deleted")
				role := &rbacv1.Role{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted", Namespace: namespace}, role)
				Expect(k8sErrors.IsNotFound(err)).To(BeTrue())

				By("verifying ServiceAccount is deleted")
				sa := &corev1.ServiceAccount{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted", Namespace: namespace}, sa)
				Expect(k8sErrors.IsNotFound(err)).To(BeTrue())

				By("verifying ClusterRoleBinding is deleted")
				crb := &rbacv1.ClusterRoleBinding{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: crbName}, crb)
				Expect(k8sErrors.IsNotFound(err)).To(BeTrue())

				By("verifying ClusterRole is deleted")
				cr := &rbacv1.ClusterRole{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted"}, cr)
				Expect(k8sErrors.IsNotFound(err)).To(BeTrue())
			})
		})

		Context("when operator lacks ClusterRoleBinding delete permission", func() {
			BeforeEach(func() {
				existingObjs = append(existingObjs,
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name: crbName,
						},
					},
					&rbacv1.ClusterRole{
						ObjectMeta: metav1.ObjectMeta{
							Name: "ibm-iam-operand-restricted",
						},
					},
				)

				fakeClientSSAR = &fakeClientWithSSAR{
					denyResources: map[string]map[string]bool{
						"clusterrolebindings": {"delete": true},
					},
				}
			})

			It("should skip ClusterRoleBinding deletion", func() {
				result, err := r.cleanupOldRBAC(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())

				By("verifying ClusterRoleBinding still exists")
				crb := &rbacv1.ClusterRoleBinding{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: crbName}, crb)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when multiple ClusterRoleBindings reference the ClusterRole", func() {
			BeforeEach(func() {
				existingObjs = append(existingObjs,
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name: crbName,
							Labels: map[string]string{
								"app.kubernetes.io/managed-by": "ibm-iam-operator",
							},
						},
						RoleRef: rbacv1.RoleRef{
							Kind: "ClusterRole",
							Name: "ibm-iam-operand-restricted",
						},
					},
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name: "ibm-iam-operand-restricted-other-namespace",
							Labels: map[string]string{
								"app.kubernetes.io/managed-by": "ibm-iam-operator",
							},
						},
						RoleRef: rbacv1.RoleRef{
							Kind: "ClusterRole",
							Name: "ibm-iam-operand-restricted",
						},
					},
					&rbacv1.ClusterRole{
						ObjectMeta: metav1.ObjectMeta{
							Name: "ibm-iam-operand-restricted",
						},
					},
				)
			})

			It("should delete the namespace-specific ClusterRoleBinding but preserve the ClusterRole", func() {
				result, err := r.cleanupOldRBAC(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())

				By("verifying ClusterRole still exists")
				cr := &rbacv1.ClusterRole{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted"}, cr)
				Expect(err).NotTo(HaveOccurred())

				By("verifying the namespace-specific ClusterRoleBinding is deleted")
				crb := &rbacv1.ClusterRoleBinding{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: crbName}, crb)
				Expect(k8sErrors.IsNotFound(err)).To(BeTrue())

				By("verifying the other ClusterRoleBinding still exists")
				otherCrb := &rbacv1.ClusterRoleBinding{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted-other-namespace"}, otherCrb)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when only one ClusterRoleBinding exists but for a different namespace", func() {
			BeforeEach(func() {
				existingObjs = append(existingObjs,
					&rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name: "ibm-iam-operand-restricted-other-namespace",
							Labels: map[string]string{
								"app.kubernetes.io/managed-by": "ibm-iam-operator",
							},
						},
						RoleRef: rbacv1.RoleRef{
							Kind: "ClusterRole",
							Name: "ibm-iam-operand-restricted",
						},
					},
					&rbacv1.ClusterRole{
						ObjectMeta: metav1.ObjectMeta{
							Name: "ibm-iam-operand-restricted",
						},
					},
				)
			})

			It("should preserve the ClusterRole since the single ClusterRoleBinding doesn't match current namespace", func() {
				result, err := r.cleanupOldRBAC(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())

				By("verifying ClusterRole still exists")
				cr := &rbacv1.ClusterRole{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted"}, cr)
				Expect(err).NotTo(HaveOccurred())

				By("verifying the other namespace's ClusterRoleBinding still exists")
				otherCrb := &rbacv1.ClusterRoleBinding{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted-other-namespace"}, otherCrb)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when operator lacks list permission for ClusterRoleBindings", func() {
			BeforeEach(func() {
				existingObjs = append(existingObjs,
					&rbacv1.ClusterRole{
						ObjectMeta: metav1.ObjectMeta{
							Name: "ibm-iam-operand-restricted",
						},
					},
				)

				fakeClientSSAR = &fakeClientWithSSAR{
					denyResources: map[string]map[string]bool{
						"clusterrolebindings": {"list": true},
					},
				}
			})

			It("should skip ClusterRole deletion to avoid potential conflicts", func() {
				result, err := r.cleanupOldRBAC(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())

				By("verifying ClusterRole still exists")
				cr := &rbacv1.ClusterRole{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted"}, cr)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when no ClusterRoleBindings reference the ClusterRole", func() {
			BeforeEach(func() {
				existingObjs = append(existingObjs,
					&rbacv1.ClusterRole{
						ObjectMeta: metav1.ObjectMeta{
							Name: "ibm-iam-operand-restricted",
						},
					},
				)
			})

			It("should skip ClusterRole deletion when count is zero", func() {
				result, err := r.cleanupOldRBAC(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())

				By("verifying ClusterRole still exists")
				cr := &rbacv1.ClusterRole{}
				err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted"}, cr)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when resources do not exist", func() {
			It("should complete successfully without errors", func() {
				result, err := r.cleanupOldRBAC(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())
			})
		})
	})
})

// fakeClientWithSSAR wraps a fake client and intercepts SelfSubjectAccessReview creation
type fakeClientWithSSAR struct {
	client.Client
	allowAll      bool
	denyResources map[string]map[string]bool // resource -> verb -> deny
}

func (f *fakeClientWithSSAR) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if ssar, ok := obj.(*authorizationv1.SelfSubjectAccessReview); ok {
		resource := ssar.Spec.ResourceAttributes.Resource
		verb := ssar.Spec.ResourceAttributes.Verb

		// Default to allowed
		ssar.Status.Allowed = true

		// Check if we should deny this specific resource/verb combination
		if !f.allowAll && f.denyResources != nil {
			if verbs, exists := f.denyResources[resource]; exists {
				if deny, verbExists := verbs[verb]; verbExists && deny {
					ssar.Status.Allowed = false
					ssar.Status.Denied = true
					ssar.Status.Reason = "Denied by test"
				}
			}
		}

		return nil
	}
	return f.Client.Create(ctx, obj, opts...)
}

// Made with Bob
