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

// formatDuration formats d to whole seconds, e.g. 45s, 22m30s or 1h5m3s.
func formatDuration(d time.Duration) string {
	return d.Round(time.Second).String()
}

// operation is an in-flight operation for one Authentication CR.
type operation struct {
	start metav1.Time
	// deps are the external dependencies waited on, in wait order.
	// A zero ReadyTime means the dependency is still pending.
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

// waitStarted records that the operation began waiting on component.
// Returns false if already waiting on component.
func (o *operation) waitStarted(component string, now metav1.Time) bool {
	if o.dep(component) != nil {
		return false
	}
	o.deps = append(o.deps, operatorv1alpha1.DependencyTime{Component: component, StartTime: now})
	return true
}

// ready records that component became ready and returns the wait duration.
// Returns false if component was never waited on or is already ready.
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

// drop removes a still-pending wait on component. Reports whether one was removed.
func (o *operation) drop(component string) bool {
	for i, d := range o.deps {
		if d.Component == component {
			if !d.ReadyTime.IsZero() {
				return false
			}
			o.deps = slices.Delete(o.deps, i, i+1)
			return true
		}
	}
	return false
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

// operationTracker holds in-flight operations keyed by CR. Kept in memory
// across requeues so dependency waits span multiple passes. The mutex guards
// the map only; controller-runtime serialises reconciles per CR.
type operationTracker struct {
	mu  sync.Mutex
	ops map[types.NamespacedName]*operation
}

func (t *operationTracker) get(key types.NamespacedName) *operation {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ops[key]
}

// getOrStart returns the operation for key, starting one at start if none is in flight.
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

// startOperation returns authCR's in-flight operation, starting one if none exists.
// For a fresh install (no prior service status) the start time is the CR's creation time.
func (r *AuthenticationReconciler) startOperation(ctx context.Context, authCR *operatorv1alpha1.Authentication, freshInstall bool) *operation {
	start := metav1.Now()
	if freshInstall && !authCR.CreationTimestamp.IsZero() {
		start = authCR.CreationTimestamp
	}
	op, started := r.operations.getOrStart(client.ObjectKeyFromObject(authCR), start)
	if started {
		logf.FromContext(ctx).Info("Operation started", "startTime", start)
		r.event(authCR, corev1.EventTypeNormal, EventReasonOperationStarted,
			fmt.Sprintf("Operation started for %s/%s", authCR.Namespace, authCR.Name))
	}
	return op
}

// dependencyWaiting records that component is not yet ready, starting an operation
// if none is in flight. Safe to call every pass; only the first call per operation counts.
func (r *AuthenticationReconciler) dependencyWaiting(ctx context.Context, authCR *operatorv1alpha1.Authentication, component string) {
	// authCR is as fetched this pass, so an empty service status means the CR
	// has never had one: a fresh install.
	op := r.startOperation(ctx, authCR, authCR.Status.Service.Status == "")
	if op.waitStarted(component, metav1.Now()) {
		logf.FromContext(ctx).Info("Waiting for dependency", "component", component)
		r.event(authCR, corev1.EventTypeNormal, EventReasonDependencyWaitStarted,
			fmt.Sprintf("Waiting for dependency: %s", component))
	}
}

// dependencyReady records that component became ready. No-op if not being waited on.
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

// dependencyNotNeeded drops a pending wait on component (e.g. config changed),
// so the operation is not blocked by a dependency that no longer applies.
func (r *AuthenticationReconciler) dependencyNotNeeded(ctx context.Context, authCR *operatorv1alpha1.Authentication, component string) {
	op := r.operations.get(client.ObjectKeyFromObject(authCR))
	if op != nil && op.drop(component) {
		logf.FromContext(ctx).Info("No longer waiting for dependency", "component", component)
	}
}

// finishOperation adds an operationTiming entry when the CR is Ready and all
// waited dependencies are resolved. Reports whether an entry was added.
// Call onPersisted after the status update succeeds to forget the operation;
// a failed update will retry with the same operation on the next pass.
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

// prependOperationTiming prepends entry, capping the list at maxOperationTimingEntries.
func prependOperationTiming(authCR *operatorv1alpha1.Authentication, entry operatorv1alpha1.OperationTimingEntry) {
	updated := append([]operatorv1alpha1.OperationTimingEntry{entry}, authCR.Status.OperationTiming...)
	if len(updated) > maxOperationTimingEntries {
		updated = updated[:maxOperationTimingEntries]
	}
	authCR.Status.OperationTiming = updated
}
