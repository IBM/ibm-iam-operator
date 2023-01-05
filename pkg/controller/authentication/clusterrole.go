package authentication

import (
	"context"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (r *ReconcileAuthentication) handleClusterRole(instance *operatorv1alpha1.Authentication, clusterRole *rbacv1.ClusterRole, requeueResult *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "ibm-iam-oauthclient", Namespace: ""}, clusterRole)
	if err != nil && errors.IsNotFound(err) {
		// Define a new service
		iamOauthClient := r.iamOauthClientClusterRole(instance)
		reqLogger.Info("Creating a new TMLRoleNew", "ibm-iam-oauthclient")
		err = r.client.Create(context.TODO(), iamOauthClient)
		if err != nil {
			reqLogger.Error(err, "Failed to create new TMLRole", "ibm-iam-oauthclient")
			return err
		}
		// Service created successfully - return and requeue
		*requeueResult = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get ClusterRole")
		return err
	}
	return nil
}
func (r *ReconcileAuthentication) iamOauthClientClusterRole(instance *operatorv1alpha1.Authentication) *rbacv1.Role {

	// reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	iamOauthClientClusterRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ibm-iam-oauthclient",
			Labels:    map[string]string{"app.kubernetes.io/instance": "ibm-iam-operator", "app.kubernetes.io/managed-by": "ibm-iam-operator", "app.kubernetes.io/name": "ibm-iam-operator"},
			Namespace: "ibm-common-services",
		},
		Rules: []rbacv1.PolicyRule{
			{
				// APIGroups: []string{"oauth.openshift.io"},
				// Resources: []string{"oauthclients"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"create", "get", "list", "update", "delete", "watch"},
			},
		},
	}
	// "error":"cluster-scoped resource must not have a namespace-scoped owner, owner's namespace ibm-common-services"
	// Set Authentication instance as the owner and controller of the ClusterRole
	// err := controllerutil.SetControllerReference(instance, iamOauthClientClusterRole, r.scheme)
	// if err != nil {
	// 	reqLogger.Error(err, "Failed to set owner for ClusterRole")
	// 	return nil
	// }
	return iamOauthClientClusterRole

}
