//
// Copyright 2020, 2021 IBM Corporation
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
	"k8s.io/klog"
)

type CRData struct {
	Labels      map[string]string
	MatchLabels map[string]string
	Rules       []rbacv1.PolicyRule
}

func generateCRData() map[string]CRData {
	viewerVerbs := []string{"get", "list", "watch"}
	adminVerbs := []string{"get", "list", "watch", "create", "delete", "deletecollection", "patch", "update"}

	return map[string]CRData{
		"icp:teamadmin": {
			Labels:      nil,
			MatchLabels: nil,
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"rbac.authorization.k8s.io"},
					Resources: []string{"clusterrolebindings"},
					Verbs:     adminVerbs,
				},
				{
					APIGroups: []string{"clusterhealth.ibm.com"},
					Resources: []string{"clusterservicestatuses"},
					Verbs:     viewerVerbs,
				},
			},
		},
		"icp:cloudpakadmin": {
			Labels: map[string]string{
				"app": "auth-idp",
			},
			MatchLabels: nil,
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"namespaces"},
					Verbs:     adminVerbs,
				},
				{
					APIGroups: []string{"rbac.authorization.k8s.io"},
					Resources: []string{"clusterrolebindings"},
					Verbs:     adminVerbs,
				},
				{
					APIGroups: []string{"operator.ibm.com"},
					Resources: []string{"mustgatherjobs"},
					Verbs:     adminVerbs,
				},
				{
					APIGroups: []string{"clusterhealth.ibm.com"},
					Resources: []string{"clusterservicestatuses"},
					Verbs:     viewerVerbs,
				},
				{
					APIGroups: []string{"user.openshift.io"},
					Resources: []string{"users"},
					Verbs:     adminVerbs,
				},
				{
					APIGroups: []string{"user.openshift.io"},
					Resources: []string{"groups"},
					Verbs:     adminVerbs,
				},
			},
		},
		"icp:accountadmin": {
			Labels: map[string]string{
				"app": "auth-idp",
			},
			MatchLabels: nil,
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"namespaces"},
					Verbs:     adminVerbs,
				},
				{
					APIGroups: []string{"rbac.authorization.k8s.io"},
					Resources: []string{"clusterrolebindings"},
					Verbs:     adminVerbs,
				},
				{
					APIGroups: []string{"clusterhealth.ibm.com"},
					Resources: []string{"clusterservicestatuses"},
					Verbs:     viewerVerbs,
				},
				{
					APIGroups: []string{"user.openshift.io"},
					Resources: []string{"users"},
					Verbs:     adminVerbs,
				},
				{
					APIGroups: []string{"user.openshift.io"},
					Resources: []string{"groups"},
					Verbs:     adminVerbs,
				},
			},
		},
		"icp-clusterservicestatus-reader": {
			Labels: map[string]string{
				"app": "auth-idp",
			},
			MatchLabels: nil,
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"clusterhealth.ibm.com"},
					Resources: []string{"clusterservicestatuses"},
					Verbs:     viewerVerbs,
				},
			},
		},
		"cloudpak-switchers": {
			Labels:      nil,
			MatchLabels: nil,
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"operators.ibm.com"},
					Resources: []string{"switcheritems"},
					Verbs:     viewerVerbs,
				},
			},
		},
	}
}

func getPolicyRules(verbs []string) []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods", "pods/attach", "pods/exec", "pods/portforward", "pods/proxy"},
			Verbs:     verbs,
		},
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps", "endpoints", "persistentvolumeclaims", "replicationcontrollers", "replicationcontrollers/scale", "serviceaccounts", "services", "services/proxy"},
			Verbs:     verbs,
		},
		{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     verbs,
		},
		{
			APIGroups: []string{""},
			Resources: []string{"bindings", "events", "limitranges", "namespaces/status", "pods/log", "pods/status", "replicationcontrollers/status", "resourcequotas", "resourcequotas/status"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"impersonate"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"daemonsets", "deployments", "deployments/rollback", "deployments/scale", "replicasets", "replicasets/scale", "statefulsets"},
			Verbs:     verbs,
		},
		{
			APIGroups: []string{"autoscaling"},
			Resources: []string{"horizontalpodautoscalers"},
			Verbs:     verbs,
		},
		{
			APIGroups: []string{"batch"},
			Resources: []string{"cronjobs", "jobs"},
			Verbs:     verbs,
		},
		{
			APIGroups: []string{"extensions"},
			Resources: []string{"daemonsets", "deployments", "deployments/rollback", "deployments/scale", "ingresses", "networkpolicies", "replicasets", "replicasets/scale", "replicationcontrollers/scale"},
			Verbs:     verbs,
		},
		{
			APIGroups: []string{"icp.ibm.com"},
			Resources: []string{"images"},
			Verbs:     verbs,
		},
		{
			APIGroups: []string{"securityenforcement.admission.cloud.ibm.com"},
			Resources: []string{"imagepolicies"},
			Verbs:     verbs,
		},
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs:     verbs,
		},
		{
			APIGroups: []string{"servicecatalog.k8s.io"},
			Resources: []string{"servicebindings", "serviceinstances", "servicebindings/status", "serviceinstances/status"},
			Verbs:     verbs,
		},
		{
			APIGroups: []string{"servicecatalog.k8s.io"},
			Resources: []string{"servicebrokers", "serviceclasses", "serviceplans"},
			Verbs:     verbs,
		},
	}
}

func (r *ReconcileAuthentication) handleClusterRole(instance *operatorv1alpha1.Authentication, currentClusterRole *rbacv1.ClusterRole, requeueResult *bool) error {

	//	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	crData := generateCRData()

	for clusterRole := range crData {
		err = r.client.Get(context.Background(), types.NamespacedName{Name: clusterRole, Namespace: ""}, currentClusterRole)
		if err != nil && errors.IsNotFound(err) {
			// Define a new ClusterRole
			newClusterRole := createClusterRole(clusterRole, crData[clusterRole])
			klog.Info("Creating a new ClusterRole", "ClusterRole.Name", clusterRole)
			err = r.client.Create(context.TODO(), newClusterRole)
			if err != nil {
				klog.Error(err, "Failed to create new ClusterRole", "ClusterRole.Name", clusterRole)
				return err
			}
			// ClusterRole created successfully - return and requeue
			*requeueResult = true
		} else if err != nil {
			klog.Error(err, "Failed to get ClusterRole")
			return err
		}

	}

	return nil
}

func createClusterRole(clusterRole string, data CRData) *rbacv1.ClusterRole {
	newClusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterRole,
		},
		Rules: data.Rules,
	}
	if data.MatchLabels != nil {
		newClusterRole.AggregationRule = &rbacv1.AggregationRule{
			ClusterRoleSelectors: []metav1.LabelSelector{
				{
					MatchLabels: data.MatchLabels,
				},
			},
		}
	}
	if data.Labels != nil {
		newClusterRole.ObjectMeta.Labels = data.Labels
	}

	return newClusterRole
}
