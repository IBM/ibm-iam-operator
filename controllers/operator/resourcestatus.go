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

package operator

import (
	"context"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	zenv1 "github.com/IBM/ibm-iam-operator/apis/zen.cpd.ibm.com/v1"
	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type statusRetrievalFunc func(context.Context, client.Client, []string, string) []operatorv1alpha1.ManagedResourceStatus

const (
	UnknownAPIVersion     string = "Unknown"
	ResourceReadyState    string = "Ready"
	ResourceNotReadyState string = "NotReady"
)

func getServiceStatus(ctx context.Context, k8sClient client.Client, namespacedName types.NamespacedName) (status operatorv1alpha1.ManagedResourceStatus) {
	reqLogger := logf.FromContext(ctx).WithName("getServiceStatus").V(1)
	kind := "Service"
	status = operatorv1alpha1.ManagedResourceStatus{
		ObjectName: namespacedName.Name,
		APIVersion: UnknownAPIVersion,
		Namespace:  namespacedName.Namespace,
		Kind:       kind,
		Status:     ResourceNotReadyState,
	}
	service := &corev1.Service{}
	err := k8sClient.Get(ctx, namespacedName, service)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Could not find resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
		} else {
			reqLogger.Error(err, "Error reading resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
		}
		return
	}
	status.APIVersion = service.APIVersion
	status.Status = ResourceReadyState
	return
}

func getAllServiceStatus(ctx context.Context, k8sClient client.Client, names []string, namespace string) (statuses []operatorv1alpha1.ManagedResourceStatus) {
	reqLogger := logf.FromContext(ctx).WithName("getAllServiceStatus").V(1)
	for _, name := range names {
		nsn := types.NamespacedName{Name: name, Namespace: namespace}
		statuses = append(statuses, getServiceStatus(ctx, k8sClient, nsn))
	}
	reqLogger.Info("New statuses", "statuses", statuses)
	return
}

func getDeploymentStatus(ctx context.Context, k8sClient client.Client, namespacedName types.NamespacedName) (status operatorv1alpha1.ManagedResourceStatus) {
	reqLogger := logf.FromContext(ctx).WithName("getDeploymentStatus").V(1)
	kind := "Deployment"
	status = operatorv1alpha1.ManagedResourceStatus{
		ObjectName: namespacedName.Name,
		APIVersion: UnknownAPIVersion,
		Namespace:  namespacedName.Namespace,
		Kind:       kind,
		Status:     ResourceNotReadyState,
	}
	deployment := &appsv1.Deployment{}
	err := k8sClient.Get(ctx, namespacedName, deployment)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Could not find resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
		} else {
			reqLogger.Error(err, "Error reading resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
		}
		return
	}
	status.APIVersion = deployment.APIVersion
	for _, condition := range deployment.Status.Conditions {
		if condition.Type == appsv1.DeploymentAvailable && condition.Status == corev1.ConditionTrue {
			status.Status = ResourceReadyState
			return
		}
	}
	return
}

func getAllDeploymentStatus(ctx context.Context, k8sClient client.Client, names []string, namespace string) (statuses []operatorv1alpha1.ManagedResourceStatus) {
	reqLogger := logf.FromContext(ctx).WithName("getAllDeploymentStatus").V(1)
	for _, name := range names {
		nsn := types.NamespacedName{Name: name, Namespace: namespace}
		statuses = append(statuses, getDeploymentStatus(ctx, k8sClient, nsn))
	}
	reqLogger.Info("New statuses", "statuses", statuses)
	return
}

func getJobStatus(ctx context.Context, k8sClient client.Client, namespacedName types.NamespacedName) (status operatorv1alpha1.ManagedResourceStatus) {
	reqLogger := logf.FromContext(ctx).WithName("getJobStatus").V(1)
	kind := "Job"
	status = operatorv1alpha1.ManagedResourceStatus{
		ObjectName: namespacedName.Name,
		APIVersion: UnknownAPIVersion,
		Namespace:  namespacedName.Namespace,
		Kind:       kind,
		Status:     ResourceNotReadyState,
	}
	job := &batchv1.Job{}
	err := k8sClient.Get(ctx, namespacedName, job)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Could not find resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
		} else {
			reqLogger.Error(err, "Error reading resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
		}
		return
	}
	status.APIVersion = job.APIVersion
	for _, condition := range job.Status.Conditions {
		if condition.Type == batchv1.JobComplete && condition.Status == corev1.ConditionTrue {
			status.Status = ResourceReadyState
			return
		}
	}
	return
}

func getAllJobStatus(ctx context.Context, k8sClient client.Client, names []string, namespace string) (statuses []operatorv1alpha1.ManagedResourceStatus) {
	reqLogger := logf.FromContext(ctx).WithName("getAllJobStatus").V(1)
	for _, name := range names {
		nsn := types.NamespacedName{Name: name, Namespace: namespace}
		statuses = append(statuses, getJobStatus(ctx, k8sClient, nsn))
	}
	reqLogger.Info("New statuses", "statuses", statuses)
	return
}

func getRouteStatus(ctx context.Context, k8sClient client.Client, namespacedName types.NamespacedName) (status operatorv1alpha1.ManagedResourceStatus) {
	reqLogger := logf.FromContext(ctx).WithName("getRouteStatus").V(1)
	kind := "Route"
	status = operatorv1alpha1.ManagedResourceStatus{
		ObjectName: namespacedName.Name,
		APIVersion: UnknownAPIVersion,
		Namespace:  namespacedName.Namespace,
		Kind:       kind,
		Status:     ResourceNotReadyState,
	}
	route := &routev1.Route{}
	err := k8sClient.Get(ctx, namespacedName, route)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Could not find resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
		} else {
			reqLogger.Error(err, "Error reading resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
		}
		return
	}
	status.APIVersion = route.APIVersion
	for _, routeIngress := range route.Status.Ingress {
		for _, condition := range routeIngress.Conditions {
			if condition.Type == routev1.RouteAdmitted && condition.Status != corev1.ConditionTrue {
				return
			}
		}
	}
	status.Status = ResourceReadyState
	return
}

func getAllRouteStatus(ctx context.Context, k8sClient client.Client, names []string, namespace string) (statuses []operatorv1alpha1.ManagedResourceStatus) {
	reqLogger := logf.FromContext(ctx).WithName("getAllRouteStatus").V(1)
	for _, name := range names {
		nsn := types.NamespacedName{Name: name, Namespace: namespace}
		statuses = append(statuses, getRouteStatus(ctx, k8sClient, nsn))
	}
	reqLogger.Info("New statuses", "statuses", statuses)
	return
}

func getZenExtensionStatus(ctx context.Context, k8sClient client.Client, namespacedName types.NamespacedName) (status operatorv1alpha1.ManagedResourceStatus) {
	reqLogger := logf.FromContext(ctx).WithName("getRouteStatus").V(1)
	kind := "ZenExtension"
	status = operatorv1alpha1.ManagedResourceStatus{
		ObjectName: namespacedName.Name,
		APIVersion: UnknownAPIVersion,
		Namespace:  namespacedName.Namespace,
		Kind:       kind,
		Status:     ResourceNotReadyState,
	}
	zenExtension := &zenv1.ZenExtension{}
	err := k8sClient.Get(ctx, namespacedName, zenExtension)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Could not find resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
		} else {
			reqLogger.Error(err, "Error reading resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
		}
		return
	}

	status.APIVersion = zenExtension.APIVersion
	if zenExtension.NotReady() {
		return
	}
	status.Status = ResourceReadyState
	return
}

func getAllZenExtensionStatus(ctx context.Context, k8sClient client.Client, names []string, namespace string) (statuses []operatorv1alpha1.ManagedResourceStatus) {
	reqLogger := logf.FromContext(ctx).WithName("getAllZenExtensionStatus").V(1)
	for _, name := range names {
		nsn := types.NamespacedName{Name: name, Namespace: namespace}
		statuses = append(statuses, getZenExtensionStatus(ctx, k8sClient, nsn))
	}
	reqLogger.Info("New statuses", "statuses", statuses)
	return
}

func (r *AuthenticationReconciler) getCurrentServiceStatus(ctx context.Context, k8sClient client.Client, authentication *operatorv1alpha1.Authentication) (status operatorv1alpha1.ServiceStatus) {
	reqLogger := logf.FromContext(ctx).WithName("getCurrentServiceStatus").V(1)
	type statusRetrieval struct {
		names []string
		f     statusRetrievalFunc
	}

	statusRetrievals := []statusRetrieval{
		{
			names: []string{
				"platform-auth-service",
				"platform-identity-management",
				"platform-identity-provider",
			},
			f: getAllServiceStatus,
		},
		{
			names: []string{
				"platform-auth-service",
				"platform-identity-management",
				"platform-identity-provider",
			},
			f: getAllDeploymentStatus,
		},
		{
			names: []string{"oidc-client-registration"},
			f:     getAllJobStatus,
		},
	}

	zenExtensionStatusRetrieval := statusRetrieval{
		names: []string{
			ImZenExtName,
		},
		f: getAllZenExtensionStatus,
	}

	routeStatusRetrieval := statusRetrieval{
		names: []string{
			"id-mgmt",
			"platform-auth",
			"platform-id-provider",
			"platform-login",
			"platform-oidc",
			"saml-ui-callback",
			"social-login-callback",
		},
		f: getAllRouteStatus,
	}

	if authentication.Spec.Config.ZenFrontDoor {
		reqLogger.Info("Zen Front Door is enabled; will check ZenExtension status and skip checking Route status")
		statusRetrievals = append(statusRetrievals, zenExtensionStatusRetrieval)
	} else if r.RunningOnOpenShiftCluster() {
		reqLogger.Info("Is running on OpenShift; will check Route status")
		statusRetrievals = append(statusRetrievals, routeStatusRetrieval)
	} else {
		reqLogger.Info("Is not running on OpenShift; will skip checking Route status")
	}

	kind := "Authentication"
	status = operatorv1alpha1.ServiceStatus{
		ObjectName:       authentication.Name,
		Namespace:        authentication.Namespace,
		APIVersion:       authentication.APIVersion,
		Kind:             kind,
		ManagedResources: []operatorv1alpha1.ManagedResourceStatus{},
		Status:           ResourceNotReadyState,
	}

	reqLogger.Info("Getting statuses")
	for _, getStatuses := range statusRetrievals {
		status.ManagedResources = append(status.ManagedResources, getStatuses.f(ctx, k8sClient, getStatuses.names, status.Namespace)...)
	}

	for _, managedResourceStatus := range status.ManagedResources {
		if managedResourceStatus.Status == ResourceNotReadyState {
			return
		}
	}

	// If planned migrations have not been completed, return Authentication as not ready
	if meta.IsStatusConditionFalse(authentication.Status.Conditions, operatorv1alpha1.ConditionMigrated) {
		return
	}
	status.Status = ResourceReadyState
	return
}
