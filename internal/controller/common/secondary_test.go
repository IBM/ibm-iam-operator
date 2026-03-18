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

package common

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/opdev/subreconciler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var _ = Describe("Secondary Reconciler Functions", func() {
	var ctx context.Context

	BeforeEach(func() {
		log := zap.New(zap.UseDevMode(true))
		ctx = logf.IntoContext(context.Background(), log)
	})

	Describe("ReduceSubreconcilerResultsAndErrors", func() {
		Context("when given empty slices", func() {
			It("should return nil result and nil error", func() {
				result, err := ReduceSubreconcilerResultsAndErrors([]*ctrl.Result{}, []error{})
				Expect(result).To(BeNil())
				Expect(err).To(BeNil())
			})
		})

		Context("when given only nil results", func() {
			It("should return nil result and nil error", func() {
				result, err := ReduceSubreconcilerResultsAndErrors([]*ctrl.Result{nil, nil}, []error{nil, nil})
				Expect(result).To(BeNil())
				Expect(err).To(BeNil())
			})
		})

		Context("when given a single result with Requeue=true", func() {
			It("should return result with Requeue=true", func() {
				inputResult := &ctrl.Result{Requeue: true}
				result, err := ReduceSubreconcilerResultsAndErrors([]*ctrl.Result{inputResult}, []error{nil})
				Expect(result).NotTo(BeNil())
				Expect(result.Requeue).To(BeTrue())
				Expect(err).To(BeNil())
			})
		})

		Context("when given multiple results with different RequeueAfter values", func() {
			It("should return the longest RequeueAfter duration", func() {
				result1 := &ctrl.Result{RequeueAfter: 10 * time.Second}
				result2 := &ctrl.Result{RequeueAfter: 30 * time.Second}
				result3 := &ctrl.Result{RequeueAfter: 20 * time.Second}
				result, err := ReduceSubreconcilerResultsAndErrors([]*ctrl.Result{result1, result2, result3}, []error{nil, nil, nil})
				Expect(result).NotTo(BeNil())
				Expect(result.RequeueAfter).To(Equal(30 * time.Second))
				Expect(err).To(BeNil())
			})
		})

		Context("when given results with errors", func() {
			It("should set RequeueAfter to 0 for exponential backoff", func() {
				result1 := &ctrl.Result{RequeueAfter: 10 * time.Second}
				result2 := &ctrl.Result{RequeueAfter: 30 * time.Second}
				err1 := errors.New("test error")
				result, err := ReduceSubreconcilerResultsAndErrors([]*ctrl.Result{result1, result2}, []error{nil, err1})
				Expect(result).NotTo(BeNil())
				Expect(result.RequeueAfter).To(Equal(time.Duration(0)))
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("test error"))
			})
		})

		Context("when given multiple results with Requeue=true", func() {
			It("should preserve Requeue=true", func() {
				result1 := &ctrl.Result{Requeue: false}
				result2 := &ctrl.Result{Requeue: true}
				result3 := &ctrl.Result{Requeue: false}
				result, err := ReduceSubreconcilerResultsAndErrors([]*ctrl.Result{result1, result2, result3}, []error{nil, nil, nil})
				Expect(result).NotTo(BeNil())
				Expect(result.Requeue).To(BeTrue())
				Expect(err).To(BeNil())
			})
		})

		Context("when given multiple errors", func() {
			It("should join all errors", func() {
				err1 := errors.New("error 1")
				err2 := errors.New("error 2")
				err3 := errors.New("error 3")
				result, err := ReduceSubreconcilerResultsAndErrors([]*ctrl.Result{nil, nil, nil}, []error{err1, err2, err3})
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("error 1"))
				Expect(err.Error()).To(ContainSubstring("error 2"))
				Expect(err.Error()).To(ContainSubstring("error 3"))
				Expect(result).To(BeNil())
			})
		})

		Context("when given mixed nil and non-nil results", func() {
			It("should handle them correctly", func() {
				result1 := &ctrl.Result{RequeueAfter: 10 * time.Second}
				result, err := ReduceSubreconcilerResultsAndErrors([]*ctrl.Result{nil, result1, nil}, []error{nil, nil, nil})
				Expect(result).NotTo(BeNil())
				Expect(result.RequeueAfter).To(Equal(10 * time.Second))
				Expect(err).To(BeNil())
			})
		})
	})

	Describe("SubreconcilerFn", func() {
		Context("when created and reconciled", func() {
			It("should execute the function", func() {
				executed := false
				fn := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					executed = true
					return subreconciler.ContinueReconciling()
				})
				result, err := fn.Reconcile(ctx)
				Expect(executed).To(BeTrue())
				Expect(result).To(BeNil())
				Expect(err).To(BeNil())
			})

			It("should return the function's result and error", func() {
				expectedErr := errors.New("test error")
				expectedResult := &ctrl.Result{Requeue: true}
				fn := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					return expectedResult, expectedErr
				})
				result, err := fn.Reconcile(ctx)
				Expect(result).To(Equal(expectedResult))
				Expect(err).To(Equal(expectedErr))
			})
		})
	})

	Describe("NewSubreconcilers", func() {
		Context("when given multiple functions", func() {
			It("should create a Subreconcilers slice", func() {
				req := ctrl.Request{}
				fn1 := func(ctx context.Context, req ctrl.Request) (*ctrl.Result, error) {
					return subreconciler.ContinueReconciling()
				}
				fn2 := func(ctx context.Context, req ctrl.Request) (*ctrl.Result, error) {
					return subreconciler.ContinueReconciling()
				}
				subs := NewSubreconcilers(req, fn1, fn2)
				Expect(subs).To(HaveLen(2))
			})

			It("should execute all functions when reconciled", func() {
				req := ctrl.Request{}
				count := 0
				fn1 := func(ctx context.Context, req ctrl.Request) (*ctrl.Result, error) {
					count++
					return subreconciler.ContinueReconciling()
				}
				fn2 := func(ctx context.Context, req ctrl.Request) (*ctrl.Result, error) {
					count++
					return subreconciler.ContinueReconciling()
				}
				subs := NewSubreconcilers(req, fn1, fn2)
				result, err := subs.Reconcile(ctx)
				Expect(count).To(Equal(2))
				Expect(result).To(BeNil())
				Expect(err).To(BeNil())
			})
		})

		Context("when given no functions", func() {
			It("should create an empty Subreconcilers slice", func() {
				req := ctrl.Request{}
				subs := NewSubreconcilers(req)
				Expect(subs).To(HaveLen(0))
			})
		})
	})

	Describe("NewSubreconcilersWithResultLog", func() {
		Context("when given functions", func() {
			It("should create subreconcilers with logging", func() {
				req := ctrl.Request{}
				fn := func(ctx context.Context, req ctrl.Request) (*ctrl.Result, error) {
					return subreconciler.ContinueReconciling()
				}
				subs := NewSubreconcilersWithResultLog(req, fn)
				Expect(subs).To(HaveLen(1))
			})

			It("should execute functions and log results", func() {
				req := ctrl.Request{}
				executed := false
				fn := func(ctx context.Context, req ctrl.Request) (*ctrl.Result, error) {
					executed = true
					return subreconciler.ContinueReconciling()
				}
				subs := NewSubreconcilersWithResultLog(req, fn)
				result, err := subs.Reconcile(ctx)
				Expect(executed).To(BeTrue())
				Expect(result).To(BeNil())
				Expect(err).To(BeNil())
			})
		})
	})

	Describe("NewStrictSubreconcilers", func() {
		Context("when all subreconcilers succeed", func() {
			It("should execute all subreconcilers", func() {
				count := 0
				sub1 := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return subreconciler.ContinueReconciling()
				})
				sub2 := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return subreconciler.ContinueReconciling()
				})
				subs := NewStrictSubreconcilers(sub1, sub2)
				result, err := subs.Reconcile(ctx)
				Expect(count).To(Equal(2))
				Expect(result).To(BeNil())
				Expect(err).To(BeNil())
			})
		})

		Context("when a subreconciler returns an error", func() {
			It("should halt execution and return the error", func() {
				count := 0
				expectedErr := errors.New("test error")
				sub1 := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return subreconciler.RequeueWithError(expectedErr)
				})
				sub2 := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return subreconciler.ContinueReconciling()
				})
				subs := NewStrictSubreconcilers(sub1, sub2)
				result, err := subs.Reconcile(ctx)
				Expect(count).To(Equal(1))
				Expect(err).To(Equal(expectedErr))
				Expect(result).NotTo(BeNil())
			})
		})

		Context("when a subreconciler requests requeue", func() {
			It("should halt execution and return the requeue result", func() {
				count := 0
				sub1 := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return subreconciler.Requeue()
				})
				sub2 := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return subreconciler.ContinueReconciling()
				})
				subs := NewStrictSubreconcilers(sub1, sub2)
				result, err := subs.Reconcile(ctx)
				Expect(count).To(Equal(1))
				Expect(result).NotTo(BeNil())
				Expect(result.Requeue).To(BeTrue())
				Expect(err).To(BeNil())
			})
		})
	})

	Describe("NewLazySubreconcilers", func() {
		Context("when all subreconcilers succeed", func() {
			It("should execute all subreconcilers", func() {
				count := 0
				sub1 := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return subreconciler.ContinueReconciling()
				})
				sub2 := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return subreconciler.ContinueReconciling()
				})
				subs := NewLazySubreconcilers(sub1, sub2)
				result, err := subs.Reconcile(ctx)
				Expect(count).To(Equal(2))
				Expect(result).To(BeNil())
				Expect(err).To(BeNil())
			})
		})

		Context("when a subreconciler returns an error", func() {
			It("should continue execution and collect all results", func() {
				count := 0
				expectedErr := errors.New("test error")
				sub1 := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return subreconciler.RequeueWithError(expectedErr)
				})
				sub2 := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return subreconciler.ContinueReconciling()
				})
				subs := NewLazySubreconcilers(sub1, sub2)
				_, err := subs.Reconcile(ctx)
				Expect(count).To(Equal(2))
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("test error"))
			})
		})

		Context("when multiple subreconcilers request requeue", func() {
			It("should collect all requeue requests", func() {
				count := 0
				sub1 := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return subreconciler.RequeueWithDelay(10 * time.Second)
				})
				sub2 := SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
					count++
					return subreconciler.RequeueWithDelay(30 * time.Second)
				})
				subs := NewLazySubreconcilers(sub1, sub2)
				result, err := subs.Reconcile(ctx)
				Expect(count).To(Equal(2))
				Expect(result).NotTo(BeNil())
				Expect(result.RequeueAfter).To(Equal(30 * time.Second))
				Expect(err).To(BeNil())
			})
		})
	})

	Describe("Subreconcilers.Reconcile", func() {
		Context("when reconciling multiple subreconcilers", func() {
			It("should execute all and reduce results", func() {
				count := 0
				subs := Subreconcilers{
					SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
						count++
						return subreconciler.ContinueReconciling()
					}),
					SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
						count++
						return subreconciler.ContinueReconciling()
					}),
				}
				result, err := subs.Reconcile(ctx)
				Expect(count).To(Equal(2))
				Expect(result).To(BeNil())
				Expect(err).To(BeNil())
			})

			It("should collect all errors and results", func() {
				err1 := errors.New("error 1")
				err2 := errors.New("error 2")
				subs := Subreconcilers{
					SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
						return subreconciler.RequeueWithError(err1)
					}),
					SubreconcilerFn(func(ctx context.Context) (*ctrl.Result, error) {
						return subreconciler.RequeueWithError(err2)
					}),
				}
				result, err := subs.Reconcile(ctx)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("error 1"))
				Expect(err.Error()).To(ContainSubstring("error 2"))
				Expect(result).NotTo(BeNil())
			})
		})
	})

	Describe("StrategicSubreconcilers interface", func() {
		Context("when using NewStrictSubreconcilers", func() {
			It("should implement StrategicSubreconcilers interface", func() {
				subs := NewStrictSubreconcilers()
				var _ StrategicSubreconcilers = subs
				Expect(subs.GetStrategy()).NotTo(BeNil())
			})
		})

		Context("when using NewLazySubreconcilers", func() {
			It("should implement StrategicSubreconcilers interface", func() {
				subs := NewLazySubreconcilers()
				var _ StrategicSubreconcilers = subs
				Expect(subs.GetStrategy()).NotTo(BeNil())
			})
		})
	})
})

// Made with Bob
