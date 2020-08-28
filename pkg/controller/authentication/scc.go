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

package authentication

import (
	"context"
	"strings"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	sccv1 "github.com/openshift/api/security/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"	
	"k8s.io/apimachinery/pkg/types"
)

func generateSCCObject(serviceaccount, name, namespace string) *sccv1.SecurityContextConstraints {
	user := strings.Join([]string{"system:serviceaccount", namespace, serviceaccount}, ":")
	privilegeEscalation := true

	return &sccv1.SecurityContextConstraints{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SecurityContextConstraint",
			APIVersion: sccv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
		},
		AllowHostDirVolumePlugin:		 true,
		AllowHostIPC:                    false,
		AllowHostNetwork:                false,
		AllowHostPID:                    false,
		AllowHostPorts:					 false,
		AllowPrivilegeEscalation:        &privilegeEscalation,
		AllowPrivilegedContainer:        false,
		AllowedCapabilities:             []core.Capability{},
		DefaultAddCapabilities:          []core.Capability{},
		FSGroup:                         sccv1.FSGroupStrategyOptions{Type: sccv1.FSGroupStrategyMustRunAs},
		Groups:                          []string{},
		ReadOnlyRootFilesystem:          false,
		RunAsUser:                       sccv1.RunAsUserStrategyOptions{Type: sccv1.RunAsUserStrategyRunAsAny},
		SELinuxContext:                  sccv1.SELinuxContextStrategyOptions{Type: sccv1.SELinuxStrategyRunAsAny},
		SupplementalGroups:              sccv1.SupplementalGroupsStrategyOptions{Type: sccv1.SupplementalGroupsStrategyRunAsAny},
		Users:                           []string{user},
		Volumes:                         []sccv1.FSType{sccv1.FSTypeConfigMap, sccv1.FSTypeDownwardAPI, sccv1.FSTypeEmptyDir, sccv1.FSTypeHostPath, sccv1.FSTypeNFS, sccv1.FSTypePersistentVolumeClaim, sccv1.FSProjected, sccv1.FSTypeSecret},
	}

}

func (r *ReconcileAuthentication) handleSCC(instance *operatorv1alpha1.Authentication, currentSCC *sccv1.SecurityContextConstraints, requeueResult *bool) error {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: instance.Name, Namespace: ""}, currentSCC)
	if err != nil && errors.IsNotFound(err) {
		newScc := generateSCCObject(serviceAccountName, instance.Name, instance.Namespace)
		reqLogger.Info("Creating a new SecurityContextConstraints", "SecurityContextConstraints.Name", instance.Name)
		err = r.client.Create(context.TODO(), newScc)
		if err != nil {
			reqLogger.Error(err, "Failed to create new SecurityContextConstraints", "SecurityContextConstraints.Name", instance.Name)
			return err
		}
		// SecurityContextConstraints created successfully - return and requeue
		*requeueResult = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get SecurityContextConstraints")
		return err
	}
	return nil
}
