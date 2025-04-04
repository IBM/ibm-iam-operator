//
// Copyright 2025 IBM Corporation
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

import (
	"context"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	"github.com/opdev/subreconciler"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	"k8s.io/apimachinery/pkg/api/errors"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *AuthenticationReconciler) handleHPA(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {

	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "handleHPA")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	deployments := []string{"platform-auth-service", "platform-identity-provider", "platform-identity-management"}
	// Fetch CommonService CR
	gvk := schema.GroupVersionKind{
		Group:   "operator.ibm.com",
		Version: "v3",
		Kind:    "CommonService",
	}
	commonService := &unstructured.Unstructured{}
	commonService.SetGroupVersionKind(gvk)
	namespace := authCR.Namespace
	err = r.Get(ctx, types.NamespacedName{Name: "common-service", Namespace: namespace}, commonService)
	if err != nil {
		return
	}
	autoScaleEnabled, _, err := unstructured.NestedBool(commonService.Object, "spec", "autoScaleConfig")
	if err != nil {
		return
	}
	size, found, err := unstructured.NestedString(commonService.Object, "spec", "size")
	if err != nil || !found {
		return
	}
	if autoScaleEnabled {
		// Creating HPA - remove replicas from Deployment
		for _, deployName := range deployments {
			if err := r.UpdateDeploymentReplicas(ctx, deployName, namespace, true, 0); err == nil {
				var minReplicas int32
				if size == "small" || size == "starterset" {
					minReplicas = 1
				} else {
					minReplicas = 2
				}
				if err = r.createHPA(authCR, ctx, authCR.Namespace, deployName, minReplicas); k8sErrors.IsAlreadyExists(err) {
					reqLogger.Info("HPA already exists; continuing")
					return subreconciler.ContinueReconciling()
				} else if err != nil {
					reqLogger.Info("Encountered an unexpected error while trying to create HPA", "error", err.Error())
					return subreconciler.RequeueWithError(err)
				}
			}
		}
	} else {
		// HPA is disabled - delete any existing HPA and set fixed replicas
		for _, deployName := range deployments {
			hpa := &autoscalingv2.HorizontalPodAutoscaler{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deployName + "-hpa",
					Namespace: namespace,
				},
			}
			err := r.Get(ctx, types.NamespacedName{Name: deployName + "-hpa", Namespace: namespace}, hpa)
			if err == nil {
				reqLogger.Info("Deleting existing HPAs")
				if err := r.Delete(ctx, hpa); err == nil {
					var fixedReplicas int32
					if size == "small" || size == "starterset" {
						fixedReplicas = 1
					} else {
						fixedReplicas = 3
					}
					// Update Deployment with fixed replicas
					if err := r.UpdateDeploymentReplicas(ctx, deployName, namespace, false, fixedReplicas); err != nil {
						return subreconciler.RequeueWithError(err)
					}
				}
			} else if !errors.IsNotFound(err) {
				return subreconciler.RequeueWithDelay(defaultLowerWait)
			}
		}
	}
	return
}

func (r *AuthenticationReconciler) createHPA(instance *operatorv1alpha1.Authentication, ctx context.Context, namespace string, deploymentName string, minReplicas int32) (err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "createHPA")
	// Fetch Deployment
	deploy := &appsv1.Deployment{}
	err = r.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: namespace}, deploy)
	if err != nil {
		return
	}

	// Extract memory and CPU requests and limits
	containers := deploy.Spec.Template.Spec.Containers
	currentReplicas := deploy.Spec.Replicas
	maxReplicas := 2*(*currentReplicas) + 1

	// get existing memory requests and limits
	memRequest := containers[0].Resources.Requests.Memory().Value() // Bytes
	memLimit := containers[0].Resources.Limits.Memory().Value()

	// get existing cpu requests and limits
	cpuRequest := containers[0].Resources.Requests.Cpu().MilliValue()
	cpuLimit := containers[0].Resources.Limits.Cpu().MilliValue()

	// Compute averageUtilization for memory
	avgUtilMem := calculateUtilization(memRequest, memLimit)
	// Compute averageUtilization for CPU
	avgUtilCPU := calculateUtilization(cpuRequest, cpuLimit)

	// Define HPA
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName + "-hpa",
			Namespace: namespace,
		},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       deploymentName,
			},
			MinReplicas: &minReplicas,
			MaxReplicas: maxReplicas,
			Metrics: []autoscalingv2.MetricSpec{
				{
					Type: autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{
						Name: "memory",
						Target: autoscalingv2.MetricTarget{
							Type:               autoscalingv2.UtilizationMetricType,
							AverageUtilization: &avgUtilMem,
						},
					},
				},
				{
					Type: autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{
						Name: "cpu",
						Target: autoscalingv2.MetricTarget{
							Type:               autoscalingv2.UtilizationMetricType,
							AverageUtilization: &avgUtilCPU,
						},
					},
				},
			},
		},
	}
	reqLogger = reqLogger.WithValues("HPA.Name", hpa.Name)
	errHPA := r.Create(ctx, hpa)
	if errHPA == nil {
		reqLogger.Info("HPA created")
		err = controllerutil.SetControllerReference(instance, hpa, r.Scheme)
		if err != nil {
			reqLogger.Error(err, "Failed to set owner for hpa")
			return
		}
	}
	return errHPA

}

func calculateUtilization(request int64, limit int64) int32 {
	utilizationRatio := (float64(limit) / float64(request)) * 100

	if utilizationRatio < 130 {
		return 90
	}
	return int32((float64(limit) * 0.7 / float64(request)) * 100)
}

func (r *AuthenticationReconciler) UpdateDeploymentReplicas(ctx context.Context, deploymentName, namespace string, autoScaleEnabled bool, fixedReplicas int32) error {

	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "UpdateDeploymentReplicas")
	deploy := &appsv1.Deployment{}
	err := r.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: namespace}, deploy)
	if err != nil {
		return err
	}

	if autoScaleEnabled {
		// Remove `.spec.replicas` to let HPA control scaling
		if deploy.Spec.Replicas != nil {
			deploy.Spec.Replicas = nil
			if err := r.Update(ctx, deploy); err != nil {
				reqLogger.Error(err, "failed to update deployment to remove replicas")
				return err
			}
		}
	} else {
		// Update only if the existing replica count is different
		if deploy.Spec.Replicas == nil || *deploy.Spec.Replicas != fixedReplicas {
			deploy.Spec.Replicas = &fixedReplicas
			if err := r.Update(ctx, deploy); err != nil {
				reqLogger.Error(err, "failed to update deployment with fixed replicas")
				return err
			}
		} else {
			reqLogger.Info("Deployment already has the correct replicas")
		}
	}

	return nil
}
