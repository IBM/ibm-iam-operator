/*
Copyright 2026 IBM Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package operator

import (
	"context"
	"errors"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	ctrl "sigs.k8s.io/controller-runtime"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
)

var _ = Describe("progress", func() {
	var authCR *operatorv1alpha1.Authentication

	BeforeEach(func() {
		authCR = &operatorv1alpha1.Authentication{}
	})

	It("has checkpoints that increase strictly from 0% to 100%", func() {
		cs := progressCheckpoints
		ordered := []checkpoint{cs.Start, cs.RBACDone, cs.DBRequested, cs.DBReady,
			cs.MigrationDone, cs.ResourcesDone, cs.OIDCDone, cs.RoutesHPAsDone, cs.Complete}

		Expect(ordered[0].pct).To(Equal(0))
		Expect(ordered[len(ordered)-1].pct).To(Equal(100))
		for i := 1; i < len(ordered); i++ {
			Expect(ordered[i].pct).To(BeNumerically(">", ordered[i-1].pct), ordered[i].msg)
		}
	})

	DescribeTable("parseProgress",
		func(s string, expected int, expectedOK bool) {
			v, ok := parseProgress(s)
			Expect(ok).To(Equal(expectedOK))
			if expectedOK {
				Expect(v).To(Equal(expected))
			}
		},
		Entry("a percentage", "40%", 40, true),
		Entry("surrounding whitespace", " 40% ", 40, true),
		Entry("no percent sign", "40", 40, true),
		Entry("empty", "", 0, false),
		Entry("not a number", "abc%", 0, false),
	)

	DescribeTable("startProgress resets to 0% only when a new operation begins",
		func(current string, expectChanged bool, expected string) {
			authCR.Status.Progress = current
			Expect(startProgress(authCR)).To(Equal(expectChanged))
			Expect(authCR.Status.Progress).To(Equal(expected))
		},
		Entry("never set", "", true, "0%"),
		Entry("previous operation completed", "100%", true, "0%"),
		Entry("mid-operation, e.g. after an operator restart", "40%", false, "40%"),
		Entry("already started", "0%", false, "0%"),
	)

	Describe("advanceProgress", func() {
		It("moves forward and shows the checkpoint's message", func() {
			authCR.Status.Progress = "10%"
			Expect(advanceProgress(authCR, progressCheckpoints.DBRequested)).To(BeTrue())
			Expect(authCR.Status.Progress).To(Equal("20%"))
			Expect(authCR.Status.ProgressMessage).To(Equal(progressCheckpoints.DBRequested.msg))
		})

		It("never moves backwards when a later pass stops earlier", func() {
			authCR.Status.Progress = "55%"
			Expect(advanceProgress(authCR, progressCheckpoints.RBACDone)).To(BeFalse())
			Expect(authCR.Status.Progress).To(Equal("55%"))
		})

		It("reports no change when the same checkpoint is reached again", func() {
			advanceProgress(authCR, progressCheckpoints.DBRequested)
			Expect(advanceProgress(authCR, progressCheckpoints.DBRequested)).To(BeFalse())
		})
	})

	It("reports no change when completing an already completed operation", func() {
		Expect(completeProgress(authCR)).To(BeTrue())
		Expect(authCR.Status.Progress).To(Equal("100%"))
		Expect(completeProgress(authCR)).To(BeFalse())
	})
})

var _ = Describe("pass progress", func() {
	It("has no checkpoint until one is reached", func() {
		Expect(reachedCheckpoint(withPassProgress(context.Background()))).To(BeNil())
	})

	It("remembers the latest checkpoint of the pass", func() {
		ctx := withPassProgress(context.Background())
		reachCheckpoint(ctx, progressCheckpoints.RBACDone)
		reachCheckpoint(ctx, progressCheckpoints.DBRequested)
		Expect(*reachedCheckpoint(ctx)).To(Equal(progressCheckpoints.DBRequested))
	})

	It("keeps separate passes apart", func() {
		a := withPassProgress(context.Background())
		b := withPassProgress(context.Background())
		reachCheckpoint(a, progressCheckpoints.RBACDone)
		Expect(reachedCheckpoint(b)).To(BeNil())
	})

	It("ignores checkpoints on a context without pass progress", func() {
		ctx := context.Background()
		Expect(func() { reachCheckpoint(ctx, progressCheckpoints.RBACDone) }).NotTo(Panic())
		Expect(reachedCheckpoint(ctx)).To(BeNil())
	})

	It("counts a pass as completed only once it reaches the last checkpoint", func() {
		ctx := withPassProgress(context.Background())
		Expect(passCompleted(ctx)).To(BeFalse())
		reachCheckpoint(ctx, progressCheckpoints.OIDCDone)
		Expect(passCompleted(ctx)).To(BeFalse())
		reachCheckpoint(ctx, progressCheckpoints.RoutesHPAsDone)
		Expect(passCompleted(ctx)).To(BeTrue())
	})

	It("is recorded by progressSubreconciler without halting the pass", func() {
		ctx := withPassProgress(context.Background())
		result, err := progressSubreconciler(progressCheckpoints.OIDCDone)(ctx, ctrl.Request{})

		Expect(result).To(BeNil())
		Expect(err).NotTo(HaveOccurred())
		Expect(*reachedCheckpoint(ctx)).To(Equal(progressCheckpoints.OIDCDone))
	})
})

var _ = Describe("reconcileHistory", func() {
	var (
		authCR *operatorv1alpha1.Authentication
		t0     time.Time
	)

	BeforeEach(func() {
		authCR = &operatorv1alpha1.Authentication{}
		t0 = time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	})

	It("prefixes each entry with an RFC 3339 UTC timestamp", func() {
		local := t0.In(time.FixedZone("IST", 5*60*60+30*60))
		appendReconcileHistory(authCR, "something went wrong", local)
		Expect(authCR.Status.ReconcileHistory).To(Equal([]string{"2026-09-29T10:00:00Z something went wrong"}))
	})

	It("keeps the newest maxReconcileHistoryEntries entries, newest first", func() {
		for i := 1; i <= maxReconcileHistoryEntries+1; i++ {
			appendReconcileHistory(authCR, fmt.Sprintf("msg %d", i), t0.Add(time.Duration(i)*time.Minute))
		}

		Expect(authCR.Status.ReconcileHistory).To(Equal([]string{
			"2026-09-29T10:04:00Z msg 4",
			"2026-09-29T10:03:00Z msg 3",
			"2026-09-29T10:02:00Z msg 2",
		}))
	})

	Describe("appendReconcileHistoryIfNew", func() {
		It("skips a repeat of the latest message, whatever its timestamp", func() {
			authCR.Status.ReconcileHistory = []string{"2026-09-28T10:00:00Z " + reconcileFailurePrefix + "x"}

			Expect(appendReconcileHistoryIfNew(authCR, reconcileFailurePrefix+"x", t0)).To(BeFalse())
			Expect(authCR.Status.ReconcileHistory).To(HaveLen(1))
		})

		It("records a repeated message when something else happened in between", func() {
			appendReconcileHistory(authCR, reconcileFailurePrefix+"x", t0)
			markReconcileSuccess(authCR, t0)

			Expect(appendReconcileHistoryIfNew(authCR, reconcileFailurePrefix+"x", t0)).To(BeTrue())
			Expect(authCR.Status.ReconcileHistory).To(HaveLen(3))
		})
	})

	It("writes joined errors on one line", func() {
		err := errors.Join(errors.New("a"), errors.New("b"))
		Expect(reconcileFailureMessage(err)).To(Equal(reconcileFailurePrefix + "a; b"))
	})

	It("knows whether the latest entry is a failure", func() {
		Expect(lastReconcileFailed(authCR)).To(BeFalse())

		appendReconcileHistory(authCR, reconcileFailureMessage(errors.New("boom")), t0)
		Expect(lastReconcileFailed(authCR)).To(BeTrue())

		markReconcileSuccess(authCR, t0)
		Expect(lastReconcileFailed(authCR)).To(BeFalse())
	})
})
