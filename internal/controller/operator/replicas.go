//
// Copyright 2026 IBM Corporation
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

package operator

import operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"

// effectiveReplicas returns the per-service replica count if set,
// falling back to the global spec.Replicas.
func effectiveReplicas(global int32, perService *int32) int32 {
	if perService != nil {
		return *perService
	}
	return global
}

// hpaEnabled returns true only when autoscaling is globally on AND
// the operator has not pinned this service's replica count.
func hpaEnabled(autoScaleConfig bool, perServiceReplicas *int32) bool {
	return autoScaleConfig && perServiceReplicas == nil
}

// perSvcReplicasForDeployment maps a Deployment name to the per-service
// Replicas override field on the Authentication CR. It returns nil when
// the deployment name is not one of the three stateless service Deployments
// or when the field is unset.
func perSvcReplicasForDeployment(authCR *operatorv1alpha1.Authentication, name string) *int32 {
	switch name {
	case "platform-auth-service":
		return authCR.Spec.AuthService.Replicas
	case "platform-identity-provider":
		return authCR.Spec.IdentityProvider.Replicas
	case "platform-identity-management":
		return authCR.Spec.IdentityManager.Replicas
	}
	return nil
}
