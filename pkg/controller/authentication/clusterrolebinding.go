package authentication

import (
	"context"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (r *ReconcileAuthentication) handleClusterRoleBinding(instance *operatorv1alpha1.Authentication, clusterRoleBinding *rbacv1.ClusterRoleBinding, requeueResult *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "ibm-iam-oauthclient", Namespace: ""}, clusterRoleBinding)
	if err != nil && errors.IsNotFound(err) {
		// Define a new service
		iamOauthClient := r.iamOauthClientCRB(instance)
		reqLogger.Info("Creating a new ClusterRoleBinding", "ClusterRoleBinding.Name", "ibm-iam-oauthclient")
		err = r.client.Create(context.TODO(), iamOauthClient)
		if err != nil {
			reqLogger.Error(err, "Failed to create new ClusterRoleBinding", "ibm-iam-oauthclient")
			return err
		}
		// Service created successfully - return and requeue
		*requeueResult = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get ClusterRoleBinding")
		return err
	}
	return nil
}
func (r *ReconcileAuthentication) iamOauthClientCRB(instance *operatorv1alpha1.Authentication) *rbacv1.ClusterRoleBinding {

	// reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	iamOauthClientCRB := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ibm-iam-oauthclient",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app.kubernetes.io/instance": "ibm-iam-operator", "app.kubernetes.io/managed-by": "ibm-iam-operator", "app.kubernetes.io/name": "ibm-iam-operator"},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "ibm-iam-oauthclient",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "ServiceAccount",
				Name: "ibm-iam-operator",
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Service
	// err := controllerutil.SetControllerReference(instance, iamOauthClientCRB, r.scheme)
	// if err != nil {
	// 	reqLogger.Error(err, "Failed to set owner for ClusterRoleBinding")
	// 	return nil
	// }
	return iamOauthClientCRB

}
