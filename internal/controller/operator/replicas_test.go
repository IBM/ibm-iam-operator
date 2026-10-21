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
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"
)

// Tests for §7.2.1 — pure helper unit tests for effectiveReplicas, hpaEnabled,
// and perSvcReplicasForDeployment.

var _ = Describe("Replica helpers", func() {

	Describe("effectiveReplicas", func() {
		DescribeTable("returns the correct effective replica count",
			func(global int32, perService *int32, expected int32) {
				Expect(effectiveReplicas(global, perService)).To(Equal(expected))
			},
			// per-service nil → falls back to global
			Entry("perService nil falls back to global", int32(3), (*int32)(nil), int32(3)),
			// per-service < global → per-service wins
			Entry("perService 1 with global 3 → 1", int32(3), ptr.To(int32(1)), int32(1)),
			// per-service > global → per-service wins
			Entry("perService 5 with global 2 → 5", int32(2), ptr.To(int32(5)), int32(5)),
			// per-service == global
			Entry("perService equals global → same value", int32(2), ptr.To(int32(2)), int32(2)),
			// lower bound: per-service = 1 (CRD minimum)
			Entry("per-service 1 is the minimum allowed value", int32(1), ptr.To(int32(1)), int32(1)),
		)
	})

	Describe("hpaEnabled", func() {
		DescribeTable("returns correct HPA enable/disable decision",
			func(autoScaleConfig bool, perService *int32, expected bool) {
				Expect(hpaEnabled(autoScaleConfig, perService)).To(Equal(expected))
			},
			// autoscaling off, no per-service → no HPA
			Entry("(false, nil) → false", false, (*int32)(nil), false),
			// autoscaling on, no per-service → HPA created
			Entry("(true, nil) → true", true, (*int32)(nil), true),
			// autoscaling on, per-service set → HPA suppressed
			Entry("(true, &1) → false", true, ptr.To(int32(1)), false),
			// autoscaling off, per-service set → still no HPA
			Entry("(false, &1) → false", false, ptr.To(int32(1)), false),
			// autoscaling on, per-service set to high value → still suppressed
			Entry("(true, &5) → false", true, ptr.To(int32(5)), false),
		)
	})

	Describe("perSvcReplicasForDeployment", func() {
		var authCR *operatorv1alpha1.Authentication

		BeforeEach(func() {
			authCR = &operatorv1alpha1.Authentication{}
		})

		Context("when no per-service fields are set", func() {
			It("returns nil for platform-auth-service", func() {
				Expect(perSvcReplicasForDeployment(authCR, "platform-auth-service")).To(BeNil())
			})
			It("returns nil for platform-identity-provider", func() {
				Expect(perSvcReplicasForDeployment(authCR, "platform-identity-provider")).To(BeNil())
			})
			It("returns nil for platform-identity-management", func() {
				Expect(perSvcReplicasForDeployment(authCR, "platform-identity-management")).To(BeNil())
			})
			It("returns nil for an unknown deployment name", func() {
				Expect(perSvcReplicasForDeployment(authCR, "some-other-deployment")).To(BeNil())
			})
		})

		Context("when per-service fields are set", func() {
			BeforeEach(func() {
				authCR.Spec.AuthService.Replicas = ptr.To(int32(1))
				authCR.Spec.IdentityProvider.Replicas = ptr.To(int32(3))
				authCR.Spec.IdentityManager.Replicas = ptr.To(int32(5))
			})

			It("returns authService.Replicas for platform-auth-service", func() {
				result := perSvcReplicasForDeployment(authCR, "platform-auth-service")
				Expect(result).NotTo(BeNil())
				Expect(*result).To(Equal(int32(1)))
			})
			It("returns identityProvider.Replicas for platform-identity-provider", func() {
				result := perSvcReplicasForDeployment(authCR, "platform-identity-provider")
				Expect(result).NotTo(BeNil())
				Expect(*result).To(Equal(int32(3)))
			})
			It("returns identityManager.Replicas for platform-identity-management", func() {
				result := perSvcReplicasForDeployment(authCR, "platform-identity-management")
				Expect(result).NotTo(BeNil())
				Expect(*result).To(Equal(int32(5)))
			})
			It("returns nil for an unknown deployment name even when fields are set", func() {
				Expect(perSvcReplicasForDeployment(authCR, "platform-unknown")).To(BeNil())
			})
		})

		Context("when only one per-service field is set", func() {
			BeforeEach(func() {
				authCR.Spec.IdentityProvider.Replicas = ptr.To(int32(2))
			})
			It("returns the set value for that service", func() {
				result := perSvcReplicasForDeployment(authCR, "platform-identity-provider")
				Expect(result).NotTo(BeNil())
				Expect(*result).To(Equal(int32(2)))
			})
			It("returns nil for unset services", func() {
				Expect(perSvcReplicasForDeployment(authCR, "platform-auth-service")).To(BeNil())
				Expect(perSvcReplicasForDeployment(authCR, "platform-identity-management")).To(BeNil())
			})
		})
	})
})
