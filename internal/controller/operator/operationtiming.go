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
	maxOperationTimingEntries = 5

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
}

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
		// No matching WaitStart was recorded; treat duration as zero.
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

func (r *AuthenticationReconciler) WriteOperationTiming(ctx context.Context, req ctrl.Request, state *operationState, phase string, message string) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	if state == nil {
		return subreconciler.ContinueReconciling()
	}

	endTime := metav1.Now()
	entry := operatorv1alpha1.OperationTimingEntry{
		StartTime:     state.startTime,
		EndTime:       endTime,
		TotalDuration: formatDuration(endTime.Sub(state.startTime.Time)),
		Phase:         phase,
	}
	if len(state.dependencyTimes) > 0 {
		entry.DependencyTime = state.dependencyTimes
	}

	// Fetch before emitting the event so involvedObject has Name/Namespace/UID.
	observed := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, observed); subreconciler.ShouldHaltOrRequeue(result, err) {
		// ShouldHaltOrRequeue is true for both errors and pure requeues (err==nil).
		if err != nil {
			log.Error(err, "Could not fetch Authentication before writing operationTiming")
		}
		return
	}

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
	log.Info("Updated operationTiming", "phase", phase, "totalDuration", entry.TotalDuration)
	return subreconciler.ContinueReconciling()
}
