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

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/opdev/subreconciler"
)

const (
	maxReconcileHistoryEntries = 3

	progressCompleteValue   = 100
	progressCompleteMessage = "The Current Operation Is Completed"
)

// checkpoint defines a single progress percentage and its associated message.
type checkpoint struct {
	pct int
	msg string
}

// progressCheckpoints lists the ordered checkpoints for an Authentication
// reconcile pass. The percentages are pre-defined; each one is only written to
// the CR when the reconciler actually reaches that point in the chain.
//
// Mapping to runNonStatusSubreconcilers positions:
//
//	 0%  — fresh reconcile loop begins
//	10%  — RBAC (SA, Roles, RoleBindings, ClusterRoles, ClusterRoleBindings) complete
//	20%  — database OperandRequest created / EDB migration steps initiated
//	40%  — embedded DB ready (ensureCommonServiceDBIsReady passed)
//	55%  — DB schema migration Job has succeeded
//	70%  — core resources (Certs, Services, Secrets, ConfigMaps, Deployments) applied
//	85%  — OIDC client registration Job complete
//	95%  — Zen front-door and UI OperandRequest handled; Routes/HPAs applied
//
// 100%  — all resources Ready (set in updateAuthenticationStatus)
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
	Start:          checkpoint{0, "New Reconcile Loop Begin"},
	RBACDone:       checkpoint{10, "Finished RBAC Setup"},
	DBRequested:    checkpoint{20, "Finished Database OperandRequest"},
	DBReady:        checkpoint{40, "Finished Waiting for Embedded Database"},
	MigrationDone:  checkpoint{55, "Finished Database Schema Migration"},
	ResourcesDone:  checkpoint{70, "Finished Deploying Core Resources"},
	OIDCDone:       checkpoint{85, "Finished OIDC Client Registration"},
	RoutesHPAsDone: checkpoint{95, "Finished Routes and HPAs"},
	Complete:       checkpoint{progressCompleteValue, progressCompleteMessage},
}

// parseProgress extracts the integer percentage from a string like "42%".
// Returns 0 and false if the string is empty, missing, or not parseable.
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

// SetProgress updates .status.progress and .status.progressMessage on authCR
// according to the spec rules:
//   - Only advance if incoming % >= current %; never go backwards mid-operation.
//   - Reset to 0% when current is 100% (new operation starting) or blank (first run).
//
// Returns true when the field was actually changed, false when the call was a
// no-op. The caller is responsible for persisting the CR after calling this.
func SetProgress(authCR *operatorv1alpha1.Authentication, c checkpoint) bool {
	incoming := c.pct
	current, ok := parseProgress(authCR.Status.Progress)

	// Reset condition: current is 100% or not yet set (blank / unparseable).
	// In either case only a 0% incoming is accepted — this enforces the spec
	// requirement that every new loop starts at 0 before advancing.
	if !ok || current == progressCompleteValue {
		if incoming != 0 {
			// Non-zero checkpoint arrived before the loop reset to 0%; no-op.
			return false
		}
		authCR.Status.Progress = "0%"
		authCR.Status.ProgressMessage = c.msg
		return true
	}

	// Normal mid-operation case: only advance, never retreat.
	if incoming < current {
		return false
	}

	authCR.Status.Progress = fmt.Sprintf("%d%%", incoming)
	authCR.Status.ProgressMessage = c.msg
	return true
}

// AppendReconcileHistory prepends a timestamped message to
// .status.reconcileHistory, keeping at most maxReconcileHistoryEntries entries.
// The caller is responsible for persisting the CR.
func AppendReconcileHistory(authCR *operatorv1alpha1.Authentication, message string) {
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	entry := fmt.Sprintf("%s %s", ts, message)
	updated := append([]string{entry}, authCR.Status.ReconcileHistory...)
	if len(updated) > maxReconcileHistoryEntries {
		updated = updated[:maxReconcileHistoryEntries]
	}
	authCR.Status.ReconcileHistory = updated
}

// MarkReconcileSuccess updates .status.reconcileHistory after a successful
// reconcile loop. It prepends a success entry (capped at maxReconcileHistoryEntries)
// so that recent failures remain visible below it, giving operators a clear
// history of the last few outcomes.
func MarkReconcileSuccess(authCR *operatorv1alpha1.Authentication) {
	AppendReconcileHistory(authCR, "The last reconciliation was completed successfully.")
}

// WriteProgress fetches the latest Authentication CR, applies the given
// checkpoint, and — only if the progress value actually changed — persists the
// status update. Returns a subreconciler result; callers must propagate it.
func (r *AuthenticationReconciler) WriteProgress(ctx context.Context, req ctrl.Request, c checkpoint) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		// ShouldHaltOrRequeue is true for pure requeues (err == nil) as well as
		// real errors; only log when there is an actual error to report.
		if err != nil {
			log.Error(err, "Could not fetch Authentication before writing progress")
		}
		return
	}
	if !SetProgress(authCR, c) {
		// Progress did not change — skip the status write entirely.
		return subreconciler.ContinueReconciling()
	}
	if err = r.Client.Status().Update(ctx, authCR); err != nil {
		log.Error(err, "Failed to update progress status")
		return subreconciler.RequeueWithError(err)
	}
	log.V(1).Info("Progress updated", "progress", authCR.Status.Progress, "message", authCR.Status.ProgressMessage)
	return subreconciler.ContinueReconciling()
}
