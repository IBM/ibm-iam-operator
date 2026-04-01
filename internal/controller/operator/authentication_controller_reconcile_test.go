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
//

package operator

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/IBM/ibm-iam-operator/internal/controller/common"
)

var _ = Describe("Authentication Controller Reconcile", func() {
	var ctx context.Context

	BeforeEach(func() {
		log := zap.New(zap.UseDevMode(true))
		ctx = logf.IntoContext(context.Background(), log)
	})

	Describe("Reconciliation Strategy", func() {
		Context("when using NewLazySubreconcilers for status updates", func() {
			It("should collect all results before returning", func() {
				// Test that lazy reconcilers continue even after errors
				sub1 := common.SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					return &ctrl.Result{RequeueAfter: 10 * time.Second}, nil
				})
				sub2 := common.SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					return &ctrl.Result{RequeueAfter: 30 * time.Second}, nil
				})

				subs := common.NewLazySubreconcilers(sub1, sub2)
				result, err := subs.Reconcile(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				// Should use the longest requeue time
				Expect(result.RequeueAfter).To(Equal(30 * time.Second))
			})
		})

		Context("when using NewStrictSubreconcilers for main reconciliation", func() {
			It("should halt on first error or requeue", func() {
				count := 0
				sub1 := common.SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return &ctrl.Result{Requeue: true}, nil
				})
				sub2 := common.SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return nil, nil
				})

				subs := common.NewStrictSubreconcilers(sub1, sub2)
				result, err := subs.Reconcile(ctx)

				// Should halt after first subreconciler
				Expect(count).To(Equal(1))
				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Requeue).To(BeTrue())
			})
		})
	})

	Describe("Requeue Behavior", func() {
		Context("when subreconcilers request different requeue times", func() {
			It("should use the longest requeue time without errors", func() {
				sub1 := common.SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					return &ctrl.Result{RequeueAfter: 5 * time.Second}, nil
				})
				sub2 := common.SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					return &ctrl.Result{RequeueAfter: 15 * time.Second}, nil
				})
				sub3 := common.SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					return &ctrl.Result{RequeueAfter: 10 * time.Second}, nil
				})

				subs := common.NewLazySubreconcilers(sub1, sub2, sub3)
				result, err := subs.Reconcile(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.RequeueAfter).To(Equal(15 * time.Second))
			})

			It("should use exponential backoff when errors occur", func() {
				testErr := errors.New("test error")
				sub1 := common.SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					return &ctrl.Result{RequeueAfter: 10 * time.Second}, nil
				})
				sub2 := common.SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					return &ctrl.Result{RequeueAfter: 20 * time.Second}, testErr
				})

				subs := common.NewLazySubreconcilers(sub1, sub2)
				result, err := subs.Reconcile(ctx)

				Expect(err).To(HaveOccurred())
				Expect(result).NotTo(BeNil())
				// Should reset to 0 for exponential backoff
				Expect(result.RequeueAfter).To(Equal(time.Duration(0)))
			})
		})
	})
})

// Made with Bob
