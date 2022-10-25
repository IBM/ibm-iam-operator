/*******************************************************************************
 * Licensed Materials - Property of IBM
 * (c) Copyright IBM Corporation 2018. All Rights Reserved.
 *
 * Note to U.S. Government Users Restricted Rights:
 * Use, duplication or disclosure restricted by GSA ADP Schedule
 * Contract with IBM Corp.
 *******************************************************************************/

package util

import (
	"fmt"

	securityv1 "github.com/IBM/ibm-iam-operator/pkg/apis/oidc/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/clock"
)

// Clock is defined as a package var so it can be stubbed out during tests.
var Clock clock.Clock = clock.RealClock{}

// ClientHasCondition will return true if the given Client has a
// condition matching the provided ClientCondition.
// Only the Type and Status field will be used in the comparison, meaning that
// this function will return 'true' even if the Reason, Message and
// LastTransitionTime fields do not match.
func ClientHasCondition(client *securityv1.Client, c securityv1.ClientCondition) bool {
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
func SetClientCondition(client *securityv1.Client, conditionType securityv1.ClientConditionType, status securityv1.ConditionStatus, reason, message string) {
	newCondition := securityv1.ClientCondition{
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
