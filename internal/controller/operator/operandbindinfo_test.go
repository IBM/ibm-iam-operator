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
	"path/filepath"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	testutil "github.com/IBM/ibm-iam-operator/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

var _ = Describe("OperandBindInfo handling", func() {

	Describe("creation of OperandBindInfo", func() {
		var r *AuthenticationReconciler
		var authCR *operatorv1alpha1.Authentication
		var cb fakeclient.ClientBuilder
		var cl client.WithWatch
		var scheme *runtime.Scheme
		var ctx context.Context
		BeforeEach(func() {
			crds, err := envtest.InstallCRDs(cfg, envtest.CRDInstallOptions{
				Paths: []string{filepath.Join(".", "testdata", "crds", "odlm")},
			})
			Expect(crds).To(HaveLen(1))
			Expect(err).ToNot(HaveOccurred())

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
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddODLMEnabledToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(authCR)
			cl = cb.Build()
			dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			Expect(err).NotTo(HaveOccurred())

			r = &AuthenticationReconciler{
				Client: &ctrlcommon.FallbackClient{
					Client: cl,
					Reader: cl,
				},
				DiscoveryClient: *dc,
			}
			ctx = context.Background()
		})

		It("should create a new OperandBindInfo", func() {
			result, err := r.handleOperandBindInfo(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      authCR.Name,
						Namespace: authCR.Namespace,
					},
				},
			)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			observed := &operatorv1alpha1.OperandBindInfo{}
			bindInfoKey := types.NamespacedName{Name: bindInfoName, Namespace: authCR.Namespace}
			err = r.Get(ctx, bindInfoKey, observed)
			Expect(err).ToNot(HaveOccurred())
			generated := &operatorv1alpha1.OperandBindInfo{}
			Expect(generateOperandBindInfo(authCR, r.Client.Scheme(), generated)).To(Succeed())
			Expect(observed.Spec).To(Equal(generated.Spec))
			Expect(ctrlcommon.IsOwnerOf(r.Client.Scheme(), authCR, observed)).To(BeTrue())
		})

		It("should continue reconciling if the OperandBindInfo is already there", func() {
			By("creating an OperandBindInfo ahead of time")
			generated := &operatorv1alpha1.OperandBindInfo{}
			Expect(generateOperandBindInfo(authCR, r.Client.Scheme(), generated)).To(Succeed())
			Expect(r.Create(ctx, generated)).To(Succeed())

			result, err := r.handleOperandBindInfo(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      authCR.Name,
						Namespace: authCR.Namespace,
					},
				},
			)
			testutil.ConfirmThatItContinuesReconciling(result, err)
		})

		It("should update the OperandBindInfo if it has incorrect owner references", func() {
			By("creating an OperandBindInfo without owner references ahead of time")
			generated := &operatorv1alpha1.OperandBindInfo{}
			Expect(generateOperandBindInfo(authCR, r.Client.Scheme(), generated)).To(Succeed())
			generated.OwnerReferences = []metav1.OwnerReference{}
			Expect(r.Create(ctx, generated)).To(Succeed())

			result, err := r.handleOperandBindInfo(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      authCR.Name,
						Namespace: authCR.Namespace,
					},
				},
			)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

			observed := &operatorv1alpha1.OperandBindInfo{}
			bindInfoKey := types.NamespacedName{Name: bindInfoName, Namespace: authCR.Namespace}
			err = r.Get(ctx, bindInfoKey, observed)
			Expect(err).ToNot(HaveOccurred())
			Expect(ctrlcommon.IsOwnerOf(r.Client.Scheme(), authCR, observed)).To(BeTrue())
		})

		It("should update the OperandBindInfo if the spec differs", func() {
			By("creating an OperandBindInfo without owner references ahead of time")
			faultyBindInfo := &operatorv1alpha1.OperandBindInfo{}
			Expect(generateOperandBindInfo(authCR, r.Client.Scheme(), faultyBindInfo)).To(Succeed())
			faultyBindInfo.Spec.Bindings = map[string]operatorv1alpha1.Bindable{}
			faultyBindInfo.Spec.Description = "Some other description"
			faultyBindInfo.Spec.Registry = "Some other registry"
			faultyBindInfo.Spec.Operand = "Some other operand"

			Expect(r.Create(ctx, faultyBindInfo)).To(Succeed())

			result, err := r.handleOperandBindInfo(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      authCR.Name,
						Namespace: authCR.Namespace,
					},
				},
			)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)

			generated := &operatorv1alpha1.OperandBindInfo{}
			Expect(generateOperandBindInfo(authCR, r.Client.Scheme(), generated)).To(Succeed())
			observed := &operatorv1alpha1.OperandBindInfo{}
			bindInfoKey := types.NamespacedName{Name: bindInfoName, Namespace: authCR.Namespace}
			err = r.Get(ctx, bindInfoKey, observed)
			Expect(err).ToNot(HaveOccurred())
			Expect(observed.Spec).To(Equal(generated.Spec))
			Expect(ctrlcommon.IsOwnerOf(r.Client.Scheme(), authCR, observed)).To(BeTrue())
		})
	})
})
