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
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type SubjectData struct {
	Name string
	Kind string
}

type CRBData struct {
	Subject  []SubjectData
	RoleName string
}

func generateCRBData(defaultAdminUser string, oidcIssuerURL string) map[string]CRBData {

	return map[string]CRBData{
		"icp:default:accountadmin": CRBData{
			Subject: []SubjectData{
				{
					Name: "icp:default:accountadmin",
					Kind: "Group",
				},
			},
			RoleName: "icp:accountadmin",
		},
		"icp:default:member": CRBData{
			Subject: []SubjectData{
				{
					Name: "icp:default:member",
					Kind: "Group",
				},
			},
			RoleName: "extension",
		},
		"icp:default:teamadmin": CRBData{
			Subject: []SubjectData{
				{
					Name: "icp:default:teamadmin",
					Kind: "Group",
				},
			},
			RoleName: "icp:teamadmin",
		},
		"icp::editors": CRBData{
			Subject: []SubjectData{
				{
					Name: "icp::editor",
					Kind: "Group",
				},
			},
			RoleName: "icp-clusterservicestatus-reader",
		},
		"icp::operators": CRBData{
			Subject: []SubjectData{
				{
					Name: "icp::operator",
					Kind: "Group",
				},
			},
			RoleName: "icp-clusterservicestatus-reader",
		},
		"oidc-admin-binding": CRBData{
			Subject: []SubjectData{
				{
					Name: oidcIssuerURL + "#" + defaultAdminUser,
					Kind: "User",
				},
				{
					Name: defaultAdminUser,
					Kind: "User",
				},
			},
			RoleName: "cluster-admin",
		},
	}

}

func (r *ReconcileAuthentication) handleClusterRoleBinding(instance *operatorv1alpha1.Authentication, currentClusterRoleBinding *rbacv1.ClusterRoleBinding, requeueResult *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error
	defaultAdminUser := instance.Spec.Config.DefaultAdminUser
	oidcIssuerURL := instance.Spec.Config.OIDCIssuerURL

	crbData := generateCRBData(defaultAdminUser, oidcIssuerURL)

	for clusterRoleBinding, crbValue := range crbData {
		err = r.client.Get(context.TODO(), types.NamespacedName{Name: clusterRoleBinding, Namespace: instance.Namespace}, currentClusterRoleBinding)
		if err != nil && errors.IsNotFound(err) {
			// Define a new clusterRoleBinding
			newClusterRoleBinding := createClusterRoleBinding(clusterRoleBinding, crbValue)
			reqLogger.Info("Creating a new clusterRoleBinding", "clusterRoleBinding.Name", clusterRoleBinding)
			err = r.client.Create(context.TODO(), newClusterRoleBinding)
			if err != nil {
				reqLogger.Error(err, "Failed to create new clusterRoleBinding", "clusterRoleBinding.Name", clusterRoleBinding)
				return err
			}
			// clusterRoleBinding created successfully - return and requeue
			*requeueResult = true
		} else if err != nil {
			reqLogger.Error(err, "Failed to get clusterRoleBinding")
			return err
		}

	}

	return nil
}

func createClusterRoleBinding(clusterRoleBinding string, data CRBData) *rbacv1.ClusterRoleBinding {
	newClusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterRoleBinding,
			Labels: map[string]string{
				"app": "auth-idp",
			},
		},
		Subjects: getSubjects(data.Subject),
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     data.RoleName,
		},
	}

	return newClusterRoleBinding
}

func getSubjects(subjectDataList []SubjectData) []rbacv1.Subject {

	var subjects []rbacv1.Subject
	var newSubject rbacv1.Subject
	for _, subjectData := range subjectDataList {

		newSubject = rbacv1.Subject{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     subjectData.Kind,
			Name:     subjectData.Name,
		}
		subjects = append(subjects, newSubject)
	}
	return subjects
}
