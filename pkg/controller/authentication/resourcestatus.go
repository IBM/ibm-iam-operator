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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func getServiceStatus(s *corev1.Service) (status operatorv1alpha1.ManagedResourceStatus) {
  status = operatorv1alpha1.ManagedResourceStatus{
    ObjectName: s.Name,
    APIVersion: s.APIVersion,
    Namespace: s.Namespace,
    Kind: "Service",
    Status: "NotReady",
  }
  if s == nil {
    return
  }
  status.Status = "Ready"
  return
}

func getDeploymentStatus(d *appsv1.Deployment) (status operatorv1alpha1.ManagedResourceStatus) {
  status = operatorv1alpha1.ManagedResourceStatus{
    ObjectName: d.Name,
    APIVersion: d.APIVersion,
    Namespace: d.Namespace,
    Kind: "Deployment",
    Status: "NotReady",
  }
  for _, condition := range d.Status.Conditions {
    if condition.Type == appsv1.DeploymentAvailable && condition.Status == corev1.ConditionTrue {
      status.Status = "Ready"
      return
    }
  }
  return
}

func getJobStatus(j *batchv1.Job) (status operatorv1alpha1.ManagedResourceStatus) {
  status = operatorv1alpha1.ManagedResourceStatus{
    ObjectName: j.Name,
    APIVersion: j.APIVersion,
    Namespace: j.Namespace,
    Kind: "Job",
    Status: "NotReady",
  }
  if j == nil {
    return
  }

  for _, condition := range j.Status.Conditions {
    if condition.Type == batchv1.JobComplete && condition.Status == corev1.ConditionTrue {
      status.Status = "Ready"
      return
    }
  }
  return
}

func getRouteStatus(r *routev1.Route) (status operatorv1alpha1.ManagedResourceStatus) {
  status = operatorv1alpha1.ManagedResourceStatus{
    ObjectName: r.Name,
    APIVersion: r.APIVersion,
    Namespace: r.Namespace,
    Kind: "Route",
    Status: "NotReady",
  }
  for _, routeIngress := range r.Status.Ingress {
    for _, condition := range routeIngress.Conditions {
      if condition.Type == routev1.RouteAdmitted && condition.Status != corev1.ConditionTrue {
        return
      }
    }
  }
  status.Status = "Ready"
  return
}

type statusRetrievalFunc func(context.Context, client.Client, []string, string) []operatorv1alpha1.ManagedResourceStatus

func getAllServiceStatus(ctx context.Context, k8sClient client.Client, names []string, namespace string) (statuses []operatorv1alpha1.ManagedResourceStatus) {
  reqLogger := logf.FromContext(ctx).WithName("getAllServiceStatus").V(3)
  for _, name := range names {
    s := &corev1.Service{}
    nsn := types.NamespacedName{ Name: name, Namespace: namespace }
    _ = k8sClient.Get(ctx, nsn, s)
    statuses = append(statuses, getServiceStatus(s))
  }
  reqLogger.Info("New statuses", "statuses", statuses)
  return
}

func getAllDeploymentStatus(ctx context.Context, k8sClient client.Client, names []string, namespace string) (statuses []operatorv1alpha1.ManagedResourceStatus) {
  reqLogger := logf.FromContext(ctx).WithName("getAllDeploymentStatus").V(3)
  for _, name := range names {
    d := &appsv1.Deployment{}
    nsn := types.NamespacedName{ Name: name, Namespace: namespace }
    _ = k8sClient.Get(ctx, nsn, d)
    statuses = append(statuses, getDeploymentStatus(d))
  }
  reqLogger.Info("New statuses", "statuses", statuses)
  return
}

func getAllJobStatus(ctx context.Context, k8sClient client.Client, names []string, namespace string) (statuses []operatorv1alpha1.ManagedResourceStatus) {
  reqLogger := logf.FromContext(ctx).WithName("getAllJobStatus").V(3)
  for _, name := range names {
    j := &batchv1.Job{}
    nsn := types.NamespacedName{ Name: name, Namespace: namespace }
    _ = k8sClient.Get(ctx, nsn, j)
    statuses = append(statuses, getJobStatus(j))
  }
  reqLogger.Info("New statuses", "statuses", statuses)
  return
}

func getAllRouteStatus(ctx context.Context, k8sClient client.Client, names []string, namespace string) (statuses []operatorv1alpha1.ManagedResourceStatus) {
  reqLogger := logf.FromContext(ctx).WithName("getAllRouteStatus").V(3)
  for _, name := range names {
    r := &routev1.Route{}
    nsn := types.NamespacedName{ Name: name, Namespace: namespace }
    _ = k8sClient.Get(ctx, nsn, r)
    statuses = append(statuses, getRouteStatus(r))
  }
  reqLogger.Info("New statuses", "statuses", statuses)
  return
}

func getCurrentServiceStatus(ctx context.Context, k8sClient client.Client, authentication *operatorv1alpha1.Authentication) (status operatorv1alpha1.ServiceStatus) {
  reqLogger := logf.FromContext(ctx).WithName("getCurrentServiceStatus").V(3)
  type statusRetrieval struct {
    names []string
    f statusRetrievalFunc
  }

  // 
  statusRetrievals := []statusRetrieval {
    {
      names: []string {
        "iam-token-service",
        "platform-auth-service",
        "platform-identity-management",
        "platform-identity-provider",
      },
      f: getAllServiceStatus,
    },
    {
      names: []string {
        "platform-auth-service",
        "platform-identity-management",
        "platform-identity-provider",
      },
      f: getAllDeploymentStatus,
    },
    {
      names: []string { "oidc-client-registration" },
      f: getAllJobStatus,
    },
    {
      names: []string {
        "id-mgmt",
        "platform-auth",
        "platform-id-auth",
        "platform-id-provider",
        "platform-login",
        "platform-oidc",
        "saml-ui-callback",
        "social-login-callback",
      },
      f: getAllRouteStatus,
    },
  }

  status = operatorv1alpha1.ServiceStatus{
    ObjectName: authentication.Name,
    Namespace: authentication.Namespace,
    APIVersion: authentication.APIVersion,
    Kind: "Authentication",
    ManagedResources: []operatorv1alpha1.ManagedResourceStatus{},
    Status: "NotReady",
  }

  reqLogger.Info("Getting statuses")
  for _, getStatuses := range statusRetrievals {
    status.ManagedResources = append(status.ManagedResources, getStatuses.f(ctx, k8sClient, getStatuses.names, status.Namespace)...)
  }

  for _, managedResourceStatus := range status.ManagedResources {
    if managedResourceStatus.Status == "NotReady" {
      return
    }
  }
  status.Status = "Ready"
  return
}
