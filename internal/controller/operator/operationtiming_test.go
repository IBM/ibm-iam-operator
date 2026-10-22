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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
)

// drainEvents returns the events recorded so far by rec, emptying its channel.
func drainEvents(rec *record.FakeRecorder) []string {
	var events []string
	for {
		select {
		case e := <-rec.Events:
			events = append(events, e)
		default:
			return events
		}
	}
}

var _ = Describe("formatDuration", func() {
	DescribeTable("formats durations to whole seconds as shown in status",
		func(d time.Duration, expected string) {
			Expect(formatDuration(d)).To(Equal(expected))
		},
		Entry("seconds", 45*time.Second, "45s"),
		Entry("minutes and seconds", 12*time.Minute+30*time.Second, "12m30s"),
		Entry("hours, minutes and seconds", time.Hour+5*time.Minute+3*time.Second, "1h5m3s"),
		Entry("rounds sub-second remainders", 1500*time.Millisecond, "2s"),
		Entry("zero", time.Duration(0), "0s"),
	)
})

var _ = Describe("operation", func() {
	var (
		t0 metav1.Time
		op *operation
	)

	at := func(d time.Duration) metav1.Time { return metav1.NewTime(t0.Add(d)) }

	BeforeEach(func() {
		t0 = metav1.NewTime(time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC))
		op = &operation{start: t0}
	})

	It("keeps the first wait start when a dependency is reported waiting again", func() {
		Expect(op.waitStarted(embeddedDBDependency, at(4*time.Second))).To(BeTrue())
		Expect(op.waitStarted(embeddedDBDependency, at(time.Minute))).To(BeFalse())

		Expect(op.deps).To(HaveLen(1))
		Expect(op.deps[0].StartTime).To(Equal(at(4 * time.Second)))
	})

	It("measures a dependency's wait from its first wait to when it became ready", func() {
		op.waitStarted(embeddedDBDependency, at(4*time.Second))

		wait, ok := op.ready(embeddedDBDependency, at(12*time.Minute+34*time.Second))
		Expect(ok).To(BeTrue())
		Expect(wait).To(Equal(12*time.Minute + 30*time.Second))
		Expect(op.deps[0].ReadyTime).To(Equal(at(12*time.Minute + 34*time.Second)))
		Expect(op.deps[0].DependencyDuration).To(Equal("12m30s"))
	})

	It("keeps the first ready time when a dependency is reported ready again", func() {
		op.waitStarted(embeddedDBDependency, at(0))
		op.ready(embeddedDBDependency, at(time.Minute))

		_, ok := op.ready(embeddedDBDependency, at(time.Hour))
		Expect(ok).To(BeFalse())
		Expect(op.deps[0].DependencyDuration).To(Equal("1m0s"))
	})

	It("does not record a dependency that was ready without being waited on", func() {
		_, ok := op.ready(embeddedDBDependency, at(time.Minute))
		Expect(ok).To(BeFalse())
		Expect(op.deps).To(BeEmpty())
	})

	It("drops a pending dependency but keeps one that already became ready", func() {
		op.waitStarted(embeddedDBDependency, at(0))
		op.waitStarted(MigrationJobName, at(0))
		op.ready(MigrationJobName, at(time.Minute))

		Expect(op.drop(embeddedDBDependency)).To(BeTrue())
		Expect(op.drop(MigrationJobName)).To(BeFalse())
		Expect(op.deps).To(HaveExactElements(HaveField("Component", MigrationJobName)))
	})

	It("has pending dependencies until every waited-on one is ready or dropped", func() {
		Expect(op.hasPendingDependencies()).To(BeFalse())

		op.waitStarted(embeddedDBDependency, at(0))
		op.waitStarted(MigrationJobName, at(0))
		Expect(op.hasPendingDependencies()).To(BeTrue())

		op.ready(embeddedDBDependency, at(time.Minute))
		Expect(op.hasPendingDependencies()).To(BeTrue())

		op.drop(MigrationJobName)
		Expect(op.hasPendingDependencies()).To(BeFalse())
	})

	Describe("entry", func() {
		It("covers the whole operation and each dependency waited on", func() {
			op.waitStarted(embeddedDBDependency, at(4*time.Second))
			op.ready(embeddedDBDependency, at(12*time.Minute+34*time.Second))

			e := op.entry(at(22*time.Minute + 30*time.Second))
			Expect(e.StartTime).To(Equal(t0))
			Expect(e.EndTime).To(Equal(at(22*time.Minute + 30*time.Second)))
			Expect(e.TotalDuration).To(Equal("22m30s"))
			Expect(e.Phase).To(Equal(operationPhaseCompleted))
			Expect(e.DependencyTime).To(HaveExactElements(And(
				HaveField("Component", embeddedDBDependency),
				HaveField("DependencyDuration", "12m30s"),
			)))
		})

		It("has no dependencyTime when nothing was waited on", func() {
			Expect(op.entry(at(time.Minute)).DependencyTime).To(BeNil())
		})

		It("is not affected by later changes to the operation", func() {
			op.waitStarted(embeddedDBDependency, at(0))
			e := op.entry(at(time.Minute))

			op.ready(embeddedDBDependency, at(2*time.Minute))
			Expect(e.DependencyTime[0].ReadyTime.IsZero()).To(BeTrue())
		})
	})
})

var _ = Describe("prependOperationTiming", func() {
	It("puts the newest entry first and keeps at most maxOperationTimingEntries", func() {
		authCR := &operatorv1alpha1.Authentication{}
		for i := 0; i < maxOperationTimingEntries+2; i++ {
			prependOperationTiming(authCR, operatorv1alpha1.OperationTimingEntry{TotalDuration: formatDuration(time.Duration(i) * time.Second)})
		}

		Expect(authCR.Status.OperationTiming).To(HaveLen(maxOperationTimingEntries))
		Expect(authCR.Status.OperationTiming[0].TotalDuration).To(Equal("6s"))
		Expect(authCR.Status.OperationTiming[maxOperationTimingEntries-1].TotalDuration).To(Equal("2s"))
	})
})

var _ = Describe("AuthenticationReconciler operation tracking", func() {
	var (
		ctx     context.Context
		rec     *record.FakeRecorder
		r       *AuthenticationReconciler
		authCR  *operatorv1alpha1.Authentication
		key     types.NamespacedName
		created metav1.Time
	)

	BeforeEach(func() {
		ctx = logf.IntoContext(context.Background(), zap.New(zap.UseDevMode(true)))
		rec = record.NewFakeRecorder(100)
		r = &AuthenticationReconciler{Recorder: rec}
		created = metav1.NewTime(time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC))
		authCR = &operatorv1alpha1.Authentication{
			ObjectMeta: metav1.ObjectMeta{Name: "example-authentication", Namespace: "test-ns", CreationTimestamp: created},
		}
		key = types.NamespacedName{Namespace: "test-ns", Name: "example-authentication"}
	})

	Describe("startOperation", func() {
		It("dates a fresh install from the CR's creation", func() {
			op := r.startOperation(ctx, authCR, true)
			Expect(op.start).To(Equal(created))
		})

		It("dates any other operation from when it starts", func() {
			before := time.Now().Add(-time.Second)
			op := r.startOperation(ctx, authCR, false)
			Expect(op.start.Time).To(BeTemporally(">", before))
		})

		It("returns the operation already in flight and announces it only once", func() {
			first := r.startOperation(ctx, authCR, true)
			second := r.startOperation(ctx, authCR, false)

			Expect(second).To(BeIdenticalTo(first))
			Expect(drainEvents(rec)).To(HaveExactElements(ContainSubstring(EventReasonOperationStarted)))
		})

		It("keeps operations of different CRs separate", func() {
			other := authCR.DeepCopy()
			other.Namespace = "other-ns"

			Expect(r.startOperation(ctx, authCR, true)).NotTo(BeIdenticalTo(r.startOperation(ctx, other, true)))
			Expect(r.operations).To(HaveLen(2))
		})
	})

	Describe("dependencyWaiting", func() {
		It("starts an operation for a fresh install's first wait", func() {
			r.dependencyWaiting(ctx, authCR, embeddedDBDependency)

			Expect(r.operations[key]).NotTo(BeNil())
			Expect(r.operations[key].start).To(Equal(created))
			Expect(r.operations[key].hasPendingDependencies()).To(BeTrue())
		})

		It("announces each wait once however many passes report it", func() {
			for i := 0; i < 3; i++ {
				r.dependencyWaiting(ctx, authCR, embeddedDBDependency)
			}

			Expect(drainEvents(rec)).To(HaveExactElements(
				ContainSubstring(EventReasonOperationStarted),
				ContainSubstring(EventReasonDependencyWaitStarted),
			))
		})
	})

	Describe("dependencyReady", func() {
		It("does nothing when no operation is in flight", func() {
			r.dependencyReady(ctx, authCR, embeddedDBDependency)

			Expect(r.operations).To(BeEmpty())
			Expect(drainEvents(rec)).To(BeEmpty())
		})

		It("does not list a dependency the operation did not wait on", func() {
			authCR.Status.Service.Status = ResourceNotReadyState
			r.startOperation(ctx, authCR, false)
			drainEvents(rec)

			r.dependencyReady(ctx, authCR, embeddedDBDependency)
			Expect(r.operations[key].deps).To(BeEmpty())
			Expect(drainEvents(rec)).To(BeEmpty())
		})

		It("records a waited-on dependency as ready once", func() {
			r.dependencyWaiting(ctx, authCR, embeddedDBDependency)
			drainEvents(rec)

			r.dependencyReady(ctx, authCR, embeddedDBDependency)
			r.dependencyReady(ctx, authCR, embeddedDBDependency)

			Expect(r.operations[key].hasPendingDependencies()).To(BeFalse())
			Expect(drainEvents(rec)).To(HaveExactElements(ContainSubstring(EventReasonDependencyReady)))
		})
	})

	Describe("finishOperation", func() {
		BeforeEach(func() {
			r.dependencyWaiting(ctx, authCR, embeddedDBDependency)
			drainEvents(rec)
		})

		It("adds nothing while the CR is not Ready", func() {
			r.dependencyReady(ctx, authCR, embeddedDBDependency)
			authCR.Status.Service.Status = ResourceNotReadyState

			added, _ := r.finishOperation(ctx, authCR)
			Expect(added).To(BeFalse())
			Expect(authCR.Status.OperationTiming).To(BeEmpty())
		})

		It("adds nothing while a dependency is still pending", func() {
			authCR.Status.Service.Status = ResourceReadyState

			added, _ := r.finishOperation(ctx, authCR)
			Expect(added).To(BeFalse())
			Expect(authCR.Status.OperationTiming).To(BeEmpty())
		})

		It("adds nothing when no operation is in flight", func() {
			delete(r.operations, key)
			authCR.Status.Service.Status = ResourceReadyState

			added, onPersisted := r.finishOperation(ctx, authCR)
			Expect(added).To(BeFalse())
			Expect(onPersisted).NotTo(Panic())
			Expect(drainEvents(rec)).To(BeEmpty())
		})

		It("keeps the operation until the status carrying the entry is persisted", func() {
			r.dependencyReady(ctx, authCR, embeddedDBDependency)
			drainEvents(rec)
			authCR.Status.Service.Status = ResourceReadyState

			added, onPersisted := r.finishOperation(ctx, authCR)
			Expect(added).To(BeTrue())
			Expect(authCR.Status.OperationTiming).To(HaveLen(1))
			Expect(r.operations).To(HaveKey(key))
			Expect(drainEvents(rec)).To(BeEmpty())

			onPersisted()
			Expect(r.operations).NotTo(HaveKey(key))
			Expect(drainEvents(rec)).To(HaveExactElements(ContainSubstring(EventReasonOperationEnded)))
		})

		It("finishes once a pending dependency is no longer needed", func() {
			authCR.Status.Service.Status = ResourceReadyState
			r.dependencyNotNeeded(ctx, authCR, embeddedDBDependency)

			added, _ := r.finishOperation(ctx, authCR)
			Expect(added).To(BeTrue())
			Expect(authCR.Status.OperationTiming[0].DependencyTime).To(BeEmpty())
		})
	})
})
