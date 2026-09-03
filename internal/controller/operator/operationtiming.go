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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/opdev/subreconciler"
)

const (
	// maxOperationTimingEntries is the maximum number of operationTiming entries retained.
	maxOperationTimingEntries = 5

	// Event reasons as specified in section 5.5 of the standardized-status spec.
	EventReasonOperationStarted      = "OperationStarted"
	EventReasonDependencyWaitStarted = "DependencyWaitStarted"
	EventReasonDependencyReady       = "DependencyReady"
	EventReasonOperationEnded        = "OperationEnded"
)

// formatDuration formats a time.Duration as a human-readable string matching
// the spec examples (e.g. "22m30s", "45s", "8m45s").
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

// operationState holds the in-flight timing data for the current reconcile
// pass. It is populated by RecordOperationStart and consumed by
// WriteOperationTiming. Each AuthenticationReconciler instance owns one.
type operationState struct {
	startTime       metav1.Time
	dependencyTimes []operatorv1alpha1.DependencyTime
	// depStartTimes tracks the start time keyed by component name while the
	// dependency is still being waited on.
	depStartTimes map[string]metav1.Time
}

// RecordOperationStart captures the operation start time, emits the
// OperationStarted event, and initialises per-dependency tracking state.
// Call this at the very top of a reconcile pass, before any dependency checks.
func (r *AuthenticationReconciler) RecordOperationStart(ctx context.Context, instance *operatorv1alpha1.Authentication, message string) *operationState {
	log := logf.FromContext(ctx)
	state := &operationState{
		startTime:     metav1.Now(),
		depStartTimes: make(map[string]metav1.Time),
	}
	log.Info("Operation started", "message", message)
	if !r.EnforceLeastPrivilege && r.Recorder != nil {
		r.Recorder.Event(instance, corev1.EventTypeNormal, EventReasonOperationStarted, message)
	}
	return state
}

// RecordDependencyWaitStart marks the moment the operator begins waiting for a
// named dependency. Call this immediately before entering any wait loop.
func (r *AuthenticationReconciler) RecordDependencyWaitStart(ctx context.Context, instance *operatorv1alpha1.Authentication, state *operationState, component string) {
	if state == nil {
		return
	}
	log := logf.FromContext(ctx)
	now := metav1.Now()
	state.depStartTimes[component] = now
	log.Info("Waiting for dependency", "component", component)
	if !r.EnforceLeastPrivilege && r.Recorder != nil {
		r.Recorder.Event(instance, corev1.EventTypeNormal, EventReasonDependencyWaitStarted,
			fmt.Sprintf("Waiting for dependency: %s", component))
	}
}

// RecordDependencyReady marks the moment a named dependency became ready.
// Call this immediately after a dependency transitions to the ready state.
func (r *AuthenticationReconciler) RecordDependencyReady(ctx context.Context, instance *operatorv1alpha1.Authentication, state *operationState, component string) {
	if state == nil {
		return
	}
	log := logf.FromContext(ctx)
	readyTime := metav1.Now()
	depEntry := operatorv1alpha1.DependencyTime{
		Component: component,
		ReadyTime: readyTime,
	}
	if start, ok := state.depStartTimes[component]; ok {
		depEntry.StartTime = start
		depEntry.DependencyDuration = formatDuration(readyTime.Sub(start.Time))
	} else {
		depEntry.StartTime = readyTime
		depEntry.DependencyDuration = "0s"
	}
	state.dependencyTimes = append(state.dependencyTimes, depEntry)
	log.Info("Dependency ready", "component", component, "duration", depEntry.DependencyDuration)
	if !r.EnforceLeastPrivilege && r.Recorder != nil {
		r.Recorder.Event(instance, corev1.EventTypeNormal, EventReasonDependencyReady,
			fmt.Sprintf("Dependency %s is ready", component))
	}
}

// WriteOperationTiming finalises the current operation's timing entry, prepends
// it to .status.operationTiming (keeping at most maxOperationTimingEntries),
// emits the OperationEnded event, and persists the status update to the API
// server. Returns a subreconciler result; callers should propagate it.
func (r *AuthenticationReconciler) WriteOperationTiming(ctx context.Context, req ctrl.Request, state *operationState, phase string, message string) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	if state == nil {
		return subreconciler.ContinueReconciling()
	}

	endTime := metav1.Now()
	totalDuration := formatDuration(endTime.Sub(state.startTime.Time))

	entry := operatorv1alpha1.OperationTimingEntry{
		StartTime:     state.startTime,
		EndTime:       endTime,
		TotalDuration: totalDuration,
		Phase:         phase,
	}
	if len(state.dependencyTimes) > 0 {
		entry.DependencyTime = state.dependencyTimes
	}

	// Fetch the latest Authentication CR first so we have a valid object to
	// attach the event to and a current resourceVersion for the status update.
	observed := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, observed); subreconciler.ShouldHaltOrRequeue(result, err) {
		// ShouldHaltOrRequeue is true for both errors and pure requeues (err==nil).
		if err != nil {
			log.Error(err, "Could not fetch Authentication before writing operationTiming")
		}
		return
	}

	// Emit OperationEnded event against the fetched CR so involvedObject is
	// correctly populated with Name, Namespace, and UID.
	if !r.EnforceLeastPrivilege && r.Recorder != nil {
		eventType := corev1.EventTypeNormal
		if phase != "Completed" {
			eventType = corev1.EventTypeWarning
		}
		r.Recorder.Event(observed, eventType, EventReasonOperationEnded,
			fmt.Sprintf("phase=%s: %s", phase, message))
	}

	updated := append([]operatorv1alpha1.OperationTimingEntry{entry}, observed.Status.OperationTiming...)
	if len(updated) > maxOperationTimingEntries {
		updated = updated[:maxOperationTimingEntries]
	}
	observed.Status.OperationTiming = updated

	if err = r.Client.Status().Update(ctx, observed); err != nil {
		log.Error(err, "Failed to update operationTiming status")
		return subreconciler.RequeueWithError(err)
	}
	log.Info("Updated operationTiming", "phase", phase, "totalDuration", totalDuration)
	return subreconciler.ContinueReconciling()
}
