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

package operator

import (
	"context"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// Tests for §7.2.5 — CRD schema validation of the minimum: 1 constraint.
//
// These tests run against the envtest API server (k8sClient from suite_test.go),
// which loads the CRD from config/crd/bases. They verify that:
//   - Values >= 1 are accepted
//   - Values of 0 or negative are rejected with an Invalid error
//   - Omitting the field is accepted (backwards compatibility)
//
// The tests will fail until the CRD has been regenerated with `make generate manifests`
// to include the new `replicas` field with `minimum: 1` on each service spec.

// minimalAuthenticationCR returns a bare-minimum Authentication CR sufficient for CRD
// validation tests. The caller must set per-service fields before submitting.
func minimalAuthenticationCR(name, namespace string) *operatorv1alpha1.Authentication {
	return &operatorv1alpha1.Authentication{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.ibm.com/v1alpha1",
			Kind:       "Authentication",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: operatorv1alpha1.AuthenticationSpec{
			OperatorVersion: "4.0.0",
			Replicas:        1,
			Config:          operatorv1alpha1.ConfigSpec{},
		},
	}
}

var _ = Describe("Authentication CRD per-service replica validation (§7.2.5)", func() {
	const crdNS = "default"

	// Each sub-test creates a uniquely-named CR so that tests are independent.
	It("accepts authService.replicas = 1 (minimum allowed)", func() {
		cr := minimalAuthenticationCR("crd-val-auth-1", crdNS)
		cr.Spec.AuthService.Replicas = ptr.To[int32](1)
		Expect(k8sClient.Create(context.Background(), cr)).To(Succeed())
		_ = k8sClient.Delete(context.Background(), cr)
	})

	It("rejects authService.replicas = 0 (below minimum)", func() {
		cr := minimalAuthenticationCR("crd-val-auth-0", crdNS)
		cr.Spec.AuthService.Replicas = ptr.To[int32](0)
		err := k8sClient.Create(context.Background(), cr)
		Expect(errors.IsInvalid(err)).To(BeTrue(), "expected Invalid error but got: %v", err)
	})

	It("rejects authService.replicas = -1 (negative)", func() {
		cr := minimalAuthenticationCR("crd-val-auth-neg1", crdNS)
		cr.Spec.AuthService.Replicas = ptr.To[int32](-1)
		err := k8sClient.Create(context.Background(), cr)
		Expect(errors.IsInvalid(err)).To(BeTrue(), "expected Invalid error but got: %v", err)
	})

	It("rejects identityProvider.replicas = 0 (below minimum)", func() {
		cr := minimalAuthenticationCR("crd-val-idp-0", crdNS)
		cr.Spec.IdentityProvider.Replicas = ptr.To[int32](0)
		err := k8sClient.Create(context.Background(), cr)
		Expect(errors.IsInvalid(err)).To(BeTrue(), "expected Invalid error but got: %v", err)
	})

	It("rejects identityManager.replicas = 0 (below minimum)", func() {
		cr := minimalAuthenticationCR("crd-val-idm-0", crdNS)
		cr.Spec.IdentityManager.Replicas = ptr.To[int32](0)
		err := k8sClient.Create(context.Background(), cr)
		Expect(errors.IsInvalid(err)).To(BeTrue(), "expected Invalid error but got: %v", err)
	})

	It("accepts all per-service fields omitted (backwards compatibility, §6.1)", func() {
		cr := minimalAuthenticationCR("crd-val-no-persvc", crdNS)
		// No per-service replicas set — this is the backwards-compatible case.
		Expect(k8sClient.Create(context.Background(), cr)).To(Succeed())
		_ = k8sClient.Delete(context.Background(), cr)
	})
})
