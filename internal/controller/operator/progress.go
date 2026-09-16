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

type checkpoint struct {
	pct int
	msg string
}

// Checkpoint percentages and messages for each stage of a reconcile pass.
// 100% is set separately in updateAuthenticationStatus on Ready transition.
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

// SetProgress returns true when the field changed, false when it was a no-op.
// Three cases:
//   - current == 100%: only 0% (loop reset) is accepted to avoid overwriting a
//     completed state with a mid-operation value from the new pass.
//   - blank/unparseable: accept any checkpoint so progress recovers if the
//     initial 0% write was ever missed.
//   - otherwise: only advance, never retreat.
func SetProgress(authCR *operatorv1alpha1.Authentication, c checkpoint) bool {
	incoming := c.pct
	current, ok := parseProgress(authCR.Status.Progress)

	if ok && current == progressCompleteValue {
		if incoming != 0 {
			return false
		}
		authCR.Status.Progress = "0%"
		authCR.Status.ProgressMessage = c.msg
		return true
	}

	if !ok {
		authCR.Status.Progress = fmt.Sprintf("%d%%", incoming)
		authCR.Status.ProgressMessage = c.msg
		return true
	}

	if incoming < current {
		return false
	}

	authCR.Status.Progress = fmt.Sprintf("%d%%", incoming)
	authCR.Status.ProgressMessage = c.msg
	return true
}

func AppendReconcileHistory(authCR *operatorv1alpha1.Authentication, message string) {
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	entry := fmt.Sprintf("%s %s", ts, message)
	updated := append([]string{entry}, authCR.Status.ReconcileHistory...)
	if len(updated) > maxReconcileHistoryEntries {
		updated = updated[:maxReconcileHistoryEntries]
	}
	authCR.Status.ReconcileHistory = updated
}

func MarkReconcileSuccess(authCR *operatorv1alpha1.Authentication) {
	AppendReconcileHistory(authCR, "The last reconciliation was completed successfully.")
}

func (r *AuthenticationReconciler) WriteProgress(ctx context.Context, req ctrl.Request, c checkpoint) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		// ShouldHaltOrRequeue is true for both errors and pure requeues (err==nil).
		if err != nil {
			log.Error(err, "Could not fetch Authentication before writing progress")
		}
		return
	}
	if !SetProgress(authCR, c) {
		return subreconciler.ContinueReconciling()
	}
	if err = r.Client.Status().Update(ctx, authCR); err != nil {
		log.Error(err, "Failed to update progress status")
		return subreconciler.RequeueWithError(err)
	}
	log.V(1).Info("Progress updated", "progress", authCR.Status.Progress, "message", authCR.Status.ProgressMessage)
	return subreconciler.ContinueReconciling()
}
