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
	"slices"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
)

const (
	maxOperationTimingEntries = 5

	operationPhaseCompleted = "Completed"

	EventReasonOperationStarted      = "OperationStarted"
	EventReasonDependencyWaitStarted = "DependencyWaitStarted"
	EventReasonDependencyReady       = "DependencyReady"
	EventReasonOperationEnded        = "OperationEnded"
)

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// operation is an in-flight operation for one Authentication CR: when it
// started and the external dependencies it has waited on.
type operation struct {
	start metav1.Time
	// deps has one entry per dependency waited on, in the order the waits
	// began. A zero ReadyTime means the dependency is still pending.
	deps []operatorv1alpha1.DependencyTime
}

func (o *operation) dep(component string) *operatorv1alpha1.DependencyTime {
	for i := range o.deps {
		if o.deps[i].Component == component {
			return &o.deps[i]
		}
	}
	return nil
}

// waitStarted records that the operation began waiting on component at now.
// It returns false if component was already waited on in this operation.
func (o *operation) waitStarted(component string, now metav1.Time) bool {
	if o.dep(component) != nil {
		return false
	}
	o.deps = append(o.deps, operatorv1alpha1.DependencyTime{Component: component, StartTime: now})
	return true
}

// ready records that component became ready at now and returns how long it
// was waited on. It returns false if component was never waited on or is
// already ready.
func (o *operation) ready(component string, now metav1.Time) (time.Duration, bool) {
	d := o.dep(component)
	if d == nil || !d.ReadyTime.IsZero() {
		return 0, false
	}
	wait := now.Sub(d.StartTime.Time)
	d.ReadyTime = now
	d.DependencyDuration = formatDuration(wait)
	return wait, true
}

// pending reports whether any dependency waited on is not ready yet.
func (o *operation) pending() bool {
	for _, d := range o.deps {
		if d.ReadyTime.IsZero() {
			return true
		}
	}
	return false
}

// entry returns the operationTiming entry for the operation ending at end.
func (o *operation) entry(end metav1.Time) operatorv1alpha1.OperationTimingEntry {
	e := operatorv1alpha1.OperationTimingEntry{
		StartTime:     o.start,
		EndTime:       end,
		TotalDuration: formatDuration(end.Sub(o.start.Time)),
		Phase:         operationPhaseCompleted,
	}
	if len(o.deps) > 0 {
		e.DependencyTime = slices.Clone(o.deps)
	}
	return e
}

// operationTracker holds the in-flight operation of each Authentication CR.
// It is kept in memory across requeues so dependency waits can span multiple
// reconcile passes. The mutex guards only the map: controller-runtime never
// reconciles the same CR concurrently, so an operation is only ever touched by
// one goroutine at a time.
type operationTracker struct {
	mu  sync.Mutex
	ops map[types.NamespacedName]*operation
}

func (t *operationTracker) get(key types.NamespacedName) *operation {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ops[key]
}

// getOrStart returns the operation for key, starting one at start if none is
// in flight. started reports whether a new operation was started.
func (t *operationTracker) getOrStart(key types.NamespacedName, start metav1.Time) (op *operation, started bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if op = t.ops[key]; op != nil {
		return op, false
	}
	if t.ops == nil {
		t.ops = make(map[types.NamespacedName]*operation)
	}
	op = &operation{start: start}
	t.ops[key] = op
	return op, true
}

func (t *operationTracker) remove(key types.NamespacedName) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.ops, key)
}

// dependencyWaiting records that component is not ready for authCR, starting
// an operation for it if none is in flight. It is safe to call on every
// reconcile pass while waiting; only the first call per operation counts.
func (r *AuthenticationReconciler) dependencyWaiting(ctx context.Context, authCR *operatorv1alpha1.Authentication, component string) {
	log := logf.FromContext(ctx)
	now := metav1.Now()
	start := now
	// A CR that has never had a service status is a fresh install, which began
	// when the CR was created rather than when the wait was noticed.
	if authCR.Status.Service.Status == "" && !authCR.CreationTimestamp.IsZero() {
		start = authCR.CreationTimestamp
	}
	op, started := r.operations.getOrStart(client.ObjectKeyFromObject(authCR), start)
	if started {
		log.Info("Operation started", "startTime", start)
		r.event(authCR, corev1.EventTypeNormal, EventReasonOperationStarted,
			fmt.Sprintf("Waiting on external dependencies for %s/%s", authCR.Namespace, authCR.Name))
	}
	if op.waitStarted(component, now) {
		log.Info("Waiting for dependency", "component", component)
		r.event(authCR, corev1.EventTypeNormal, EventReasonDependencyWaitStarted,
			fmt.Sprintf("Waiting for dependency: %s", component))
	}
}

// dependencyReady records that component is ready for authCR. It has no
// effect unless the in-flight operation was waiting on component.
func (r *AuthenticationReconciler) dependencyReady(ctx context.Context, authCR *operatorv1alpha1.Authentication, component string) {
	op := r.operations.get(client.ObjectKeyFromObject(authCR))
	if op == nil {
		return
	}
	wait, ok := op.ready(component, metav1.Now())
	if !ok {
		return
	}
	logf.FromContext(ctx).Info("Dependency ready", "component", component, "duration", formatDuration(wait))
	r.event(authCR, corev1.EventTypeNormal, EventReasonDependencyReady,
		fmt.Sprintf("Dependency %s is ready", component))
}

// finishOperation adds the operationTiming entry for authCR's operation to its
// status once the operation is complete: the CR is Ready and no dependency the
// operation waited on is still pending. It reports whether an entry was added.
//
// onPersisted must be called after the status update carrying the entry
// succeeds; only then is the operation forgotten, so a failed update is retried
// with the same operation on the next pass. It is a no-op if nothing was added.
func (r *AuthenticationReconciler) finishOperation(ctx context.Context, authCR *operatorv1alpha1.Authentication) (added bool, onPersisted func()) {
	key := client.ObjectKeyFromObject(authCR)
	op := r.operations.get(key)
	if op == nil || authCR.Status.Service.Status != ResourceReadyState || op.pending() {
		return false, func() {}
	}
	entry := op.entry(metav1.Now())
	prependOperationTiming(authCR, entry)
	return true, func() {
		r.operations.remove(key)
		logf.FromContext(ctx).Info("Recorded operationTiming", "totalDuration", entry.TotalDuration)
		r.event(authCR, corev1.EventTypeNormal, EventReasonOperationEnded,
			fmt.Sprintf("Operation completed for %s/%s in %s", authCR.Namespace, authCR.Name, entry.TotalDuration))
	}
}

func (r *AuthenticationReconciler) event(authCR *operatorv1alpha1.Authentication, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(authCR, eventType, reason, message)
	}
}

// prependOperationTiming adds entry as the most recent operation, keeping at
// most maxOperationTimingEntries.
func prependOperationTiming(authCR *operatorv1alpha1.Authentication, entry operatorv1alpha1.OperationTimingEntry) {
	updated := append([]operatorv1alpha1.OperationTimingEntry{entry}, authCR.Status.OperationTiming...)
	if len(updated) > maxOperationTimingEntries {
		updated = updated[:maxOperationTimingEntries]
	}
	authCR.Status.OperationTiming = updated
}
