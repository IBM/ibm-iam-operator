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
	"k8s.io/apimachinery/pkg/types"
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

type operationState struct {
	startTime       metav1.Time
	dependencyTimes []operatorv1alpha1.DependencyTime
	depStartTimes   map[string]metav1.Time
	depReady        map[string]bool
}

// getOperationState returns the in-flight operation for the given
// Authentication CR, or nil if none is being tracked
func (r *AuthenticationReconciler) getOperationState(key types.NamespacedName) *operationState {
	r.opStatesMu.Lock()
	defer r.opStatesMu.Unlock()
	return r.opStates[key]
}

func (r *AuthenticationReconciler) setOperationState(key types.NamespacedName, state *operationState) {
	r.opStatesMu.Lock()
	defer r.opStatesMu.Unlock()
	if r.opStates == nil {
		r.opStates = make(map[types.NamespacedName]*operationState)
	}
	r.opStates[key] = state
}

func (r *AuthenticationReconciler) clearOperationState(key types.NamespacedName) {
	r.opStatesMu.Lock()
	defer r.opStatesMu.Unlock()
	delete(r.opStates, key)
}

func (r *AuthenticationReconciler) RecordOperationStart(ctx context.Context, instance *operatorv1alpha1.Authentication, message string) *operationState {
	log := logf.FromContext(ctx)
	state := &operationState{
		startTime:     metav1.Now(),
		depStartTimes: make(map[string]metav1.Time),
		depReady:      make(map[string]bool),
	}
	log.Info("Operation started", "message", message)
	r.event(instance, corev1.EventTypeNormal, EventReasonOperationStarted, message)
	return state
}

func (r *AuthenticationReconciler) RecordDependencyWaitStart(ctx context.Context, instance *operatorv1alpha1.Authentication, state *operationState, component string) {
	if state == nil {
		return
	}
	if _, alreadyWaiting := state.depStartTimes[component]; alreadyWaiting {
		return
	}
	log := logf.FromContext(ctx)
	state.depStartTimes[component] = metav1.Now()
	log.Info("Waiting for dependency", "component", component)
	r.event(instance, corev1.EventTypeNormal, EventReasonDependencyWaitStarted, fmt.Sprintf("Waiting for dependency: %s", component))
}

func (r *AuthenticationReconciler) RecordDependencyReady(ctx context.Context, instance *operatorv1alpha1.Authentication, state *operationState, component string) {
	if state == nil || state.depReady[component] {
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
		// No matching WaitStart was recorded; treat duration as zero.
		depEntry.StartTime = readyTime
		depEntry.DependencyDuration = "0s"
	}
	state.dependencyTimes = append(state.dependencyTimes, depEntry)
	state.depReady[component] = true
	log.Info("Dependency ready", "component", component, "duration", depEntry.DependencyDuration)
	r.event(instance, corev1.EventTypeNormal, EventReasonDependencyReady, fmt.Sprintf("Dependency %s is ready", component))
}

// BuildOperationTimingEntry constructs the OperationTimingEntry for a finished
// operation. It neither writes to the API server nor emits an event; call
// RecordOperationEnded once the status update carrying the entry is succeeds.
func (r *AuthenticationReconciler) BuildOperationTimingEntry(ctx context.Context, instance *operatorv1alpha1.Authentication, state *operationState, phase string, message string) *operatorv1alpha1.OperationTimingEntry {
	if state == nil {
		return nil
	}
	endTime := metav1.Now()
	entry := &operatorv1alpha1.OperationTimingEntry{
		StartTime:     state.startTime,
		EndTime:       endTime,
		TotalDuration: formatDuration(endTime.Sub(state.startTime.Time)),
		Phase:         phase,
	}
	if len(state.dependencyTimes) > 0 {
		entry.DependencyTime = state.dependencyTimes
	}
	return entry
}

func (r *AuthenticationReconciler) RecordOperationEnded(instance *operatorv1alpha1.Authentication, phase string, message string) {
	eventType := corev1.EventTypeNormal
	if phase != operationPhaseCompleted {
		eventType = corev1.EventTypeWarning
	}
	r.event(instance, eventType, EventReasonOperationEnded, fmt.Sprintf("phase=%s: $s", phase, message))
}

func (r *AuthenticationReconciler) event(instance *operatorv1alpha1.Authentication, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(instance, eventType, reason, message)
	}
}

func prependOperationTiming(authCR *operatorv1alpha1.Authentication, entry operatorv1alpha1.OperationTimingEntry) {
	updated := append([]operatorv1alpha1.OperationTimingEntry{entry}, authCR.Status.OperationTiming...)
	if len(updated) > maxOperationTimingEntries {
		updated = updated[:maxOperationTimingEntries]
	}
	authCR.Status.OperationTiming = updated
}
