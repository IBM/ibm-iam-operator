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
	"fmt"
	"runtime"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
)

// testRecorder is a minimal record.EventRecorder for use in tests.
type testRecorder struct {
	events []string
}

func (t *testRecorder) Event(object k8sruntime.Object, eventtype, reason, message string) {
	t.events = append(t.events, fmt.Sprintf("%s: %s", reason, message))
}

func (t *testRecorder) Eventf(object k8sruntime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	t.events = append(t.events, fmt.Sprintf("%s: %s", reason, fmt.Sprintf(messageFmt, args...)))
}

func (t *testRecorder) AnnotatedEventf(object k8sruntime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
	t.events = append(t.events, fmt.Sprintf("%s: %s", reason, fmt.Sprintf(messageFmt, args...)))
}

var _ record.EventRecorder = &testRecorder{}

// newTestReconciler builds a minimal AuthenticationReconciler wired with the
// given recorder for use in unit tests that do not need a live API server.
func newTestReconciler(rec *testRecorder, enforceLeastPrivilege bool) *AuthenticationReconciler {
	return &AuthenticationReconciler{
		Recorder:              rec,
		EnforceLeastPrivilege: enforceLeastPrivilege,
	}
}

var _ = Describe("formatDuration", func() {
	DescribeTable("formats durations correctly",
		func(d time.Duration, expected string) {
			Expect(formatDuration(d)).To(Equal(expected))
		},
		Entry("seconds only", 45*time.Second, "45s"),
		Entry("minutes and seconds", 22*time.Minute+30*time.Second, "22m30s"),
		Entry("hours minutes seconds", 1*time.Hour+5*time.Minute+3*time.Second, "1h5m3s"),
		Entry("zero duration", 0*time.Second, "0s"),
		Entry("one minute exactly", 60*time.Second, "1m0s"),
	)
})

var _ = Describe("OperationTiming", func() {
	var (
		ctx      context.Context
		instance *operatorv1alpha1.Authentication
	)

	BeforeEach(func() {
		log := zap.New(zap.UseDevMode(true))
		ctx = logf.IntoContext(context.Background(), log)

		instance = &operatorv1alpha1.Authentication{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-auth",
				Namespace: "test-ns",
			},
		}
	})

	Describe("RecordOperationStart", func() {
		It("returns a non-nil state with a populated startTime", func() {
			r := newTestReconciler(nil, false)
			r.Recorder = nil

			before := metav1.Now()
			state := r.RecordOperationStart(ctx, instance, "test start")
			after := metav1.Now()

			Expect(state).NotTo(BeNil())
			Expect(state.startTime.Time).To(BeTemporally(">=", before.Time))
			Expect(state.startTime.Time).To(BeTemporally("<=", after.Time))
			Expect(state.depStartTimes).NotTo(BeNil())
			Expect(state.dependencyTimes).To(BeEmpty())
		})

		It("does not panic when Recorder is nil", func() {
			r := &AuthenticationReconciler{Recorder: nil}
			Expect(func() {
				r.RecordOperationStart(ctx, instance, "msg")
			}).NotTo(Panic())
		})

		It("does not emit an event when EnforceLeastPrivilege is true", func() {
			rec := &testRecorder{}
			r := newTestReconciler(rec, true)

			r.RecordOperationStart(ctx, instance, "msg")
			Expect(rec.events).To(BeEmpty())
		})

		It("emits OperationStarted event when allowed", func() {
			rec := &testRecorder{}
			r := newTestReconciler(rec, false)

			r.RecordOperationStart(ctx, instance, "install started")
			Expect(rec.events).To(HaveLen(1))
			Expect(rec.events[0]).To(ContainSubstring(EventReasonOperationStarted))
			Expect(rec.events[0]).To(ContainSubstring("install started"))
		})
	})

	Describe("RecordDependencyWaitStart", func() {
		It("stores the start time for the component", func() {
			r := newTestReconciler(nil, false)
			r.Recorder = nil
			state := r.RecordOperationStart(ctx, instance, "start")
			before := metav1.Now()
			r.RecordDependencyWaitStart(ctx, instance, state, "ccs")
			after := metav1.Now()

			Expect(state.depStartTimes).To(HaveKey("ccs"))
			Expect(state.depStartTimes["ccs"].Time).To(BeTemporally(">=", before.Time))
			Expect(state.depStartTimes["ccs"].Time).To(BeTemporally("<=", after.Time))
		})

		It("is a no-op when state is nil", func() {
			r := &AuthenticationReconciler{}
			Expect(func() {
				r.RecordDependencyWaitStart(ctx, instance, nil, "ccs")
			}).NotTo(Panic())
		})

		It("does not emit an event when EnforceLeastPrivilege is true", func() {
			rec := &testRecorder{}
			r := newTestReconciler(rec, true)
			state := r.RecordOperationStart(ctx, instance, "start")
			rec.events = nil // clear OperationStarted

			r.RecordDependencyWaitStart(ctx, instance, state, "ccs")
			Expect(rec.events).To(BeEmpty())
		})

		It("emits DependencyWaitStarted event when allowed", func() {
			rec := &testRecorder{}
			r := newTestReconciler(rec, false)
			state := r.RecordOperationStart(ctx, instance, "start")
			rec.events = nil

			r.RecordDependencyWaitStart(ctx, instance, state, "ws")
			Expect(rec.events).To(HaveLen(1))
			Expect(rec.events[0]).To(ContainSubstring(EventReasonDependencyWaitStarted))
			Expect(rec.events[0]).To(ContainSubstring("ws"))
		})
	})

	Describe("RecordDependencyReady", func() {
		It("appends a DependencyTime entry with correct fields", func() {
			r := newTestReconciler(nil, false)
			r.Recorder = nil
			state := r.RecordOperationStart(ctx, instance, "start")
			r.RecordDependencyWaitStart(ctx, instance, state, "ccs")
			runtime.Gosched() // yield to ensure measurable elapsed time
			time.Sleep(2 * time.Millisecond)
			r.RecordDependencyReady(ctx, instance, state, "ccs")

			Expect(state.dependencyTimes).To(HaveLen(1))
			dt := state.dependencyTimes[0]
			Expect(dt.Component).To(Equal("ccs"))
			Expect(dt.DependencyDuration).NotTo(BeEmpty())
			Expect(dt.ReadyTime.Time).To(BeTemporally(">=", dt.StartTime.Time))
		})

		It("handles missing start time gracefully", func() {
			r := newTestReconciler(nil, false)
			r.Recorder = nil
			state := r.RecordOperationStart(ctx, instance, "start")
			// Deliberately skip RecordDependencyWaitStart
			r.RecordDependencyReady(ctx, instance, state, "orphan")

			Expect(state.dependencyTimes).To(HaveLen(1))
			Expect(state.dependencyTimes[0].DependencyDuration).To(Equal("0s"))
		})

		It("is a no-op when state is nil", func() {
			r := &AuthenticationReconciler{}
			Expect(func() {
				r.RecordDependencyReady(ctx, instance, nil, "ccs")
			}).NotTo(Panic())
		})

		It("does not emit an event when EnforceLeastPrivilege is true", func() {
			rec := &testRecorder{}
			r := newTestReconciler(rec, true)
			state := r.RecordOperationStart(ctx, instance, "start")
			r.RecordDependencyWaitStart(ctx, instance, state, "analytics")
			rec.events = nil

			r.RecordDependencyReady(ctx, instance, state, "analytics")
			Expect(rec.events).To(BeEmpty())
		})

		It("emits DependencyReady event when allowed", func() {
			rec := &testRecorder{}
			r := newTestReconciler(rec, false)
			state := r.RecordOperationStart(ctx, instance, "start")
			r.RecordDependencyWaitStart(ctx, instance, state, "analytics")
			rec.events = nil

			r.RecordDependencyReady(ctx, instance, state, "analytics")
			Expect(rec.events).To(HaveLen(1))
			Expect(rec.events[0]).To(ContainSubstring(EventReasonDependencyReady))
			Expect(rec.events[0]).To(ContainSubstring("analytics"))
		})

		It("records multiple dependencies independently", func() {
			r := newTestReconciler(nil, false)
			r.Recorder = nil
			state := r.RecordOperationStart(ctx, instance, "start")

			r.RecordDependencyWaitStart(ctx, instance, state, "ws")
			r.RecordDependencyWaitStart(ctx, instance, state, "ccs")
			r.RecordDependencyReady(ctx, instance, state, "ws")
			r.RecordDependencyReady(ctx, instance, state, "ccs")

			Expect(state.dependencyTimes).To(HaveLen(2))
			components := []string{
				state.dependencyTimes[0].Component,
				state.dependencyTimes[1].Component,
			}
			Expect(components).To(ContainElements("ws", "ccs"))
		})
	})

	Describe("operationTiming rolling window", func() {
		It("keeps at most maxOperationTimingEntries entries when a 6th is added", func() {
			existing := make([]operatorv1alpha1.OperationTimingEntry, maxOperationTimingEntries)
			for i := range existing {
				existing[i] = operatorv1alpha1.OperationTimingEntry{Phase: "Completed"}
			}

			newEntry := operatorv1alpha1.OperationTimingEntry{Phase: "Failed"}
			updated := append([]operatorv1alpha1.OperationTimingEntry{newEntry}, existing...)
			if len(updated) > maxOperationTimingEntries {
				updated = updated[:maxOperationTimingEntries]
			}

			Expect(updated).To(HaveLen(maxOperationTimingEntries))
			Expect(updated[0].Phase).To(Equal("Failed"))
		})

		It("does not truncate when the list is below the limit", func() {
			existing := []operatorv1alpha1.OperationTimingEntry{
				{Phase: "Completed"},
			}
			newEntry := operatorv1alpha1.OperationTimingEntry{Phase: "Completed"}
			updated := append([]operatorv1alpha1.OperationTimingEntry{newEntry}, existing...)
			if len(updated) > maxOperationTimingEntries {
				updated = updated[:maxOperationTimingEntries]
			}
			Expect(updated).To(HaveLen(2))
		})

		It("preserves insertion order (most recent first)", func() {
			existing := []operatorv1alpha1.OperationTimingEntry{
				{Phase: "old"},
			}
			newEntry := operatorv1alpha1.OperationTimingEntry{Phase: "newest"}
			updated := append([]operatorv1alpha1.OperationTimingEntry{newEntry}, existing...)
			Expect(updated[0].Phase).To(Equal("newest"))
			Expect(updated[1].Phase).To(Equal("old"))
		})
	})

	Describe("OperationEnded event type selection", func() {
		It("uses Normal for Completed phase", func() {
			phase := "Completed"
			eventType := corev1.EventTypeNormal
			if phase != "Completed" {
				eventType = corev1.EventTypeWarning
			}
			Expect(eventType).To(Equal(corev1.EventTypeNormal))
		})

		It("uses Warning for Failed phase", func() {
			phase := "Failed"
			eventType := corev1.EventTypeNormal
			if phase != "Completed" {
				eventType = corev1.EventTypeWarning
			}
			Expect(eventType).To(Equal(corev1.EventTypeWarning))
		})

		It("uses Warning for Timeout phase", func() {
			phase := "Timeout"
			eventType := corev1.EventTypeNormal
			if phase != "Completed" {
				eventType = corev1.EventTypeWarning
			}
			Expect(eventType).To(Equal(corev1.EventTypeWarning))
		})
	})

	Describe("DeepCopy for new types", func() {
		It("deep copies OperationTimingEntry without aliasing", func() {
			dep := operatorv1alpha1.DependencyTime{
				Component:          "ccs",
				StartTime:          metav1.Now(),
				ReadyTime:          metav1.Now(),
				DependencyDuration: "5m0s",
			}
			entry := operatorv1alpha1.OperationTimingEntry{
				StartTime:      metav1.Now(),
				EndTime:        metav1.Now(),
				TotalDuration:  "10m0s",
				Phase:          "Completed",
				DependencyTime: []operatorv1alpha1.DependencyTime{dep},
			}

			copied := entry.DeepCopy()
			Expect(copied).NotTo(BeNil())
			Expect(copied.Phase).To(Equal(entry.Phase))
			Expect(copied.TotalDuration).To(Equal(entry.TotalDuration))
			Expect(copied.DependencyTime).To(HaveLen(1))

			// Mutate original — copy must be unaffected.
			entry.Phase = "Mutated"
			entry.DependencyTime[0].Component = "mutated"
			Expect(copied.Phase).To(Equal("Completed"))
			Expect(copied.DependencyTime[0].Component).To(Equal("ccs"))
		})

		It("deep copies AuthenticationStatus.OperationTiming without aliasing", func() {
			status := operatorv1alpha1.AuthenticationStatus{
				OperationTiming: []operatorv1alpha1.OperationTimingEntry{
					{Phase: "Completed", TotalDuration: "5m0s"},
				},
			}
			copied := status.DeepCopy()
			Expect(copied.OperationTiming).To(HaveLen(1))

			status.OperationTiming[0].Phase = "Mutated"
			Expect(copied.OperationTiming[0].Phase).To(Equal("Completed"))
		})

		It("returns nil when DeepCopy is called on a nil OperationTimingEntry", func() {
			var entry *operatorv1alpha1.OperationTimingEntry
			Expect(entry.DeepCopy()).To(BeNil())
		})

		It("returns nil when DeepCopy is called on a nil DependencyTime", func() {
			var dt *operatorv1alpha1.DependencyTime
			Expect(dt.DeepCopy()).To(BeNil())
		})
	})
})
