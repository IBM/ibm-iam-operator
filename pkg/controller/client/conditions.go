//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package client

import (
	"fmt"

	oidcv1 "github.com/IBM/ibm-iam-operator/pkg/apis/oidc/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClientHasCondition will return true if the given Client has a
// condition matching the provided ClientCondition.
// Only the Type and Status field will be used in the comparison, meaning that
// this function will return 'true' even if the Reason, Message and
// LastTransitionTime fields do not match.
func ClientHasCondition(client *oidcv1.Client, c oidcv1.ClientCondition) bool {
	if client == nil {
		return false
	}
	existingConditions := client.Status.Conditions
	for _, cond := range existingConditions {
		if c.Type == cond.Type && c.Status == cond.Status {
			return true
		}
	}
	return false
}

// SetClientCondition will set a 'condition' on the given Client.
// - If no condition of the same type already exists, the condition will be
//   inserted with the LastTransitionTime set to the current time.
// - If a condition of the same type and state already exists, the condition
//   will be updated but the LastTransitionTime will not be modified.
// - If a condition of the same type and different state already exists, the
//   condition will be updated and the LastTransitionTime set to the current
//   time.
func SetClientCondition(client *oidcv1.Client, conditionType oidcv1.ClientConditionType, status oidcv1.ConditionStatus, reason, message string) {
	newCondition := oidcv1.ClientCondition{
		Type:    conditionType,
		Status:  status,
		Reason:  reason,
		Message: message,
	}

	nowTime := metav1.NewTime(Clock.Now())
	newCondition.LastTransitionTime = &nowTime
	// Search through existing conditions
	for idx, cond := range client.Status.Conditions {
		// Skip unrelated conditions
		if cond.Type != conditionType {
			continue
		}

		// If this update doesn't contain a state transition, we don't update
		// the conditions LastTransitionTime to Now()
		if cond.Status == status {
			newCondition.LastTransitionTime = cond.LastTransitionTime
		} else {
			fmt.Printf("Found status change for Client %q condition %q: %q -> %q; setting lastTransitionTime to %v\n", client.Name, conditionType, cond.Status, status, nowTime.Time)
		}
		// Overwrite the existing condition
		client.Status.Conditions[idx] = newCondition
		return
	}

	// If we've not found an existing condition of this type, we simply insert
	// the new condition into the slice.
	client.Status.Conditions = append(client.Status.Conditions, newCondition)
	fmt.Printf("Setting lastTransitionTime for Client %q condition %q to %v\n", client.Name, conditionType, nowTime.Time)
}
