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
	"strconv"
	"strings"
	"time"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
)

const (
	maxReconcileHistoryEntries = 3

	reconcileSuccessMessage = "The last reconciliation was completed successfully."
	reconcileFailurePrefix  = "Reconciliation failed: "
)

type checkpoint struct {
	pct int
	msg string
}

// progressCheckpoints are the stages of a reconcile pass, in order. Each is
// named for the step just finished; its message describes what the operator
// is doing next, so a CR that stops at a checkpoint shows what it waits on.
var progressCheckpoints = struct {
	Start          checkpoint
	RBACDone       checkpoint
	DBRequested    checkpoint
	DBReady        checkpoint
	MigrationDone  checkpoint
	ResourcesDone  checkpoint
	OIDCDone       checkpoint
	RoutesHPAsDone checkpoint
	Complete       checkpoint
}{
	Start:          checkpoint{0, "Setting up RBAC"},
	RBACDone:       checkpoint{10, "Configuring database"},
	DBRequested:    checkpoint{20, "Waiting for database"},
	DBReady:        checkpoint{40, "Running database migration"},
	MigrationDone:  checkpoint{55, "Deploying services"},
	ResourcesDone:  checkpoint{70, "Registering OIDC client"},
	OIDCDone:       checkpoint{85, "Configuring routes and autoscaling"},
	RoutesHPAsDone: checkpoint{95, "Waiting for services to become ready"},
	Complete:       checkpoint{100, "Completed"},
}

func parseProgress(s string) (int, bool) {
	s = strings.TrimSuffix(strings.TrimSpace(s), "%")
	if s == "" {
		return 0, false
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return v, true
}

// setProgress writes c to authCR and reports whether anything changed.
func setProgress(authCR *operatorv1alpha1.Authentication, c checkpoint) bool {
	progress := fmt.Sprintf("%d%%", c.pct)
	if authCR.Status.Progress == progress && authCR.Status.ProgressMessage == c.msg {
		return false
	}
	authCR.Status.Progress = progress
	authCR.Status.ProgressMessage = c.msg
	return true
}

// startProgress resets progress to 0% when a new operation begins: the
// previous one completed (100%) or progress was never set. Mid-operation it
// does nothing.
func startProgress(authCR *operatorv1alpha1.Authentication) bool {
	if current, ok := parseProgress(authCR.Status.Progress); ok && current != progressCheckpoints.Complete.pct {
		return false
	}
	return setProgress(authCR, progressCheckpoints.Start)
}

// advanceProgress moves progress forward to c. It never moves backwards,
// because a pass that requeues early reaches fewer checkpoints than an
// earlier pass did.
func advanceProgress(authCR *operatorv1alpha1.Authentication, c checkpoint) bool {
	if current, ok := parseProgress(authCR.Status.Progress); ok && c.pct <= current {
		return false
	}
	return setProgress(authCR, c)
}

func completeProgress(authCR *operatorv1alpha1.Authentication) bool {
	return setProgress(authCR, progressCheckpoints.Complete)
}

// passProgress records the last checkpoint reached during one reconcile pass.
// It lives in the pass's context rather than on the reconciler, so concurrent
// reconciles of different CRs cannot see each other's checkpoints.
type passProgress struct {
	reached *checkpoint
}

type passProgressKey struct{}

func withPassProgress(ctx context.Context) context.Context {
	return context.WithValue(ctx, passProgressKey{}, &passProgress{})
}

// reachCheckpoint records c as the latest checkpoint of the current pass.
func reachCheckpoint(ctx context.Context, c checkpoint) {
	if p, ok := ctx.Value(passProgressKey{}).(*passProgress); ok {
		p.reached = &c
	}
}

// reachedCheckpoint returns the latest checkpoint of the current pass, or nil
// if none was reached.
func reachedCheckpoint(ctx context.Context) *checkpoint {
	if p, ok := ctx.Value(passProgressKey{}).(*passProgress); ok {
		return p.reached
	}
	return nil
}

// passCompleted reports whether the current pass got through every
// non-status step, i.e. reached the last checkpoint without halting.
func passCompleted(ctx context.Context) bool {
	c := reachedCheckpoint(ctx)
	return c != nil && *c == progressCheckpoints.RoutesHPAsDone
}

func appendReconcileHistory(authCR *operatorv1alpha1.Authentication, message string, now time.Time) {
	entry := fmt.Sprintf("%s %s", now.UTC().Format(time.RFC3339), message)
	updated := append([]string{entry}, authCR.Status.ReconcileHistory...)
	if len(updated) > maxReconcileHistoryEntries {
		updated = updated[:maxReconcileHistoryEntries]
	}
	authCR.Status.ReconcileHistory = updated
}

// appendReconcileHistoryIfNew appends message unless it matches the most
// recent entry (ignoring its timestamp). It returns whether an entry was added.
func appendReconcileHistoryIfNew(authCR *operatorv1alpha1.Authentication, message string, now time.Time) bool {
	if len(authCR.Status.ReconcileHistory) > 0 {
		if _, latest, ok := strings.Cut(authCR.Status.ReconcileHistory[0], " "); ok && latest == message {
			return false
		}
	}
	appendReconcileHistory(authCR, message, now)
	return true
}

func markReconcileSuccess(authCR *operatorv1alpha1.Authentication, now time.Time) {
	appendReconcileHistory(authCR, reconcileSuccessMessage, now)
}

// reconcileFailureMessage is the reconcileHistory message for err, on one line
// even when err joins several errors.
func reconcileFailureMessage(err error) string {
	return reconcileFailurePrefix + strings.ReplaceAll(err.Error(), "\n", "; ")
}

// lastReconcileFailed reports whether the most recent reconcileHistory entry
// records a failure.
func lastReconcileFailed(authCR *operatorv1alpha1.Authentication) bool {
	if len(authCR.Status.ReconcileHistory) == 0 {
		return false
	}
	_, latest, _ := strings.Cut(authCR.Status.ReconcileHistory[0], " ")
	return strings.HasPrefix(latest, reconcileFailurePrefix)
}
