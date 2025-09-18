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
	"reflect"
	"slices"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func (r *AuthenticationReconciler) setAuthenticationStatus(ctx context.Context, authCR *operatorv1alpha1.Authentication) (modified bool, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Set Authentication status")
	authCRCopy := authCR.DeepCopy()
	var nodes []string
	debugLog.Info("Set nodes status")
	nodes, err = r.getNodesStatus(debugCtx, authCR)
	if err != nil {
		return
	}
	if len(authCR.Status.Nodes) == 0 || !slices.Equal(authCR.Status.Nodes, nodes) {
		authCR.Status.Nodes = nodes
	}

	debugLog.Info("Set migration status")
	err = r.setMigrationStatusConditions(debugCtx, authCR)
	if err != nil {
		return
	}

	debugLog.Info("Set service status")
	authCR.Status.Service = r.getCurrentServiceStatus(debugCtx, r.Client, authCR)
	expectedPodCount := int(authCR.Spec.Replicas) * 3
	if len(nodes) != expectedPodCount {
		debugLog.Info("Number of nodes did not match expected count", "expected", expectedPodCount)
		authCR.Status.Service.Status = ResourceNotReadyState
	}
	if !reflect.DeepEqual(authCR.Status, authCRCopy.Status) {
		log.Info("Status has changed since previous reconciliation")
		modified = true
	}
	return
}

// setMigrationStatusConditions sets the appropriate MigrationsPerformed and
// MigrationsRunning metav1.Condition values within the Authentication CR's
// status conditions.
func (r *AuthenticationReconciler) setMigrationStatusConditions(ctx context.Context, authCR *operatorv1alpha1.Authentication) (err error) {
	objKey := types.NamespacedName{Name: MigrationJobName, Namespace: authCR.Namespace}
	job := &batchv1.Job{}
	err = r.Client.Get(ctx, objKey, job)
	if k8sErrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}
	setMigratedStatus(authCR, job)
	setMigrationsRunningStatus(authCR, job)
	return
}

// jobHasCompleted flags whether the Job has completed successfully
func jobHasCompleted(job *batchv1.Job) (running bool) {
	return job.Status.CompletionTime != nil
}

// jobHasFailed flags whether any Pod associated with the Job has failed.
func jobHasFailed(job *batchv1.Job) (hasFailed bool) {
	return job.Status.Failed > 0
}

// jobHasCompletelyFailed flags whether the Job has failed to the point of
// hitting its BackoffLimit.
func jobHasCompletelyFailed(job *batchv1.Job) (hasFailed bool) {
	if job.Spec.BackoffLimit == nil {
		return job.Status.Failed >= 6
	}
	return job.Status.Failed >= *job.Spec.BackoffLimit
}

// setMigrationsRunningStatus sets the appropriate metav1.Condition of type
// MigrationsRunning given the current state of the migration Job and the
// Authentication CR.
func setMigrationsRunningStatus(authCR *operatorv1alpha1.Authentication, job *batchv1.Job) {
	if jobHasCompletelyFailed(job) || jobHasCompleted(job) {
		meta.SetStatusCondition(&authCR.Status.Conditions, *operatorv1alpha1.NewMigrationFinishedCondition())
		return
	}
	currentCondition := meta.FindStatusCondition(
		authCR.Status.Conditions,
		operatorv1alpha1.ConditionMigrationsRunning)
	if currentCondition == nil || currentCondition.Status == metav1.ConditionFalse {
		meta.SetStatusCondition(&authCR.Status.Conditions, *operatorv1alpha1.NewMigrationInProgressCondition())
		return
	}
}

// setMigratedStatus sets the appropriate metav1.Condition of type
// MigrationsPerformed given the current state of the migration Job and the
// Authentication CR.
func setMigratedStatus(authCR *operatorv1alpha1.Authentication, job *batchv1.Job) {
	if jobHasCompleted(job) {
		meta.SetStatusCondition(&authCR.Status.Conditions, *operatorv1alpha1.NewMigrationCompleteCondition())
		return
	}
	if jobHasFailed(job) {
		meta.SetStatusCondition(&authCR.Status.Conditions, *operatorv1alpha1.NewMigrationFailureCondition(MigrationJobName))
		return
	}
	currentCondition := meta.FindStatusCondition(
		authCR.Status.Conditions,
		operatorv1alpha1.ConditionMigrated)
	if currentCondition == nil || currentCondition.Status == metav1.ConditionTrue {
		meta.SetStatusCondition(&authCR.Status.Conditions, *operatorv1alpha1.NewMigrationYetToBeCompleteCondition(MigrationJobName))
		return
	}
}

// getNodesStatus returns a sorted list of IM Pods that is written to the Authentication CR's .status.nodes.
func (r *AuthenticationReconciler) getNodesStatus(ctx context.Context, authCR *operatorv1alpha1.Authentication) (nodes []string, err error) {
	log := logf.FromContext(ctx)
	appNames := []string{"platform-auth-service", "platform-identity-management", "platform-identity-provider"}
	nodes = []string{}
	for _, appName := range appNames {
		podList := &corev1.PodList{}
		listOptsProv := []client.ListOption{
			client.InNamespace(authCR.Namespace),
			client.MatchingLabels(map[string]string{"k8s-app": appName}),
		}
		if err = r.Client.List(ctx, podList, listOptsProv...); err != nil {
			log.Info("Failed to list pods by label and namespace", "k8s-app", appName, "namespace", authCR.Namespace)
			return
		}
		nodes = append(nodes, getPodNames(ctx, podList.Items)...)
	}
	slices.Sort(nodes)
	return
}

func getPodNames(ctx context.Context, pods []corev1.Pod) []string {
	reqLogger := logf.FromContext(ctx)
	var podNames []string
	for _, pod := range pods {
		podNames = append(podNames, pod.Name)
		reqLogger.Info("Found Pod", "Pod.Name", pod.Name)
	}
	return podNames
}

func getServiceStatus(ctx context.Context, k8sClient client.Client, namespacedName types.NamespacedName) (status operatorv1alpha1.ManagedResourceStatus) {
	reqLogger := logf.FromContext(ctx)
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
	if err == nil {
		status.APIVersion = service.APIVersion
		status.Status = ResourceReadyState
		return
	} else if k8sErrors.IsNotFound(err) {
		reqLogger.Info("Could not find resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
	} else {
		reqLogger.Error(err, "Error reading resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
	}
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
	if k8sErrors.IsNotFound(err) {
		reqLogger.Info("Could not find resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
		return
	} else if err != nil {
		reqLogger.Error(err, "Error reading resource for status update", "kind", kind, "name", namespacedName.Name, "namespace", namespacedName.Namespace)
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
		if k8sErrors.IsNotFound(err) {
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
		if k8sErrors.IsNotFound(err) {
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
			names: []string{"oidc-client-registration", MigrationJobName},
			f:     getAllJobStatus,
		},
	}

	routeStatusRetrieval := statusRetrieval{
		names: []string{
			"id-mgmt",
			"platform-auth",
			"platform-id-auth",
			"platform-id-provider",
			"platform-login",
			"platform-oidc",
			"saml-ui-callback",
			"social-login-callback",
			IMCrtAuthRouteName,
		},
		f: getAllRouteStatus,
	}

	if ctrlcommon.ClusterHasRouteGroupVersion(&r.DiscoveryClient) {
		reqLogger.Info("Is running on OpenShift; will check Route status")
		statusRetrievals = append(statusRetrievals, routeStatusRetrieval)
	} else {
		reqLogger.Info("Routes are not available; assuming ingress will be configured manually")
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
