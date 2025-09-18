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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *AuthenticationReconciler) handleHPAs(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure HPAs are present when requested")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	deployments := []string{"platform-auth-service", "platform-identity-provider", "platform-identity-management"}

	authCRNS := authCR.Namespace
	autoScaleEnabled := authCR.Spec.AutoScaleConfig
	replicas := authCR.Spec.Replicas
	if autoScaleEnabled {
		log.Info("Autoscaling is enabled; HPAs should be present")
		subRecs := []common.SecondaryReconciler{}
		results := []*ctrl.Result{}
		errs := []error{}

		for _, deployName := range deployments {
			// Build the HPA reconciler
			builder := common.NewSecondaryReconcilerBuilder[*autoscalingv2.HorizontalPodAutoscaler]().
				WithName(deployName + "-hpa").
				WithGenerateFns(generateHPAObject(authCR, deployName)).
				WithModifyFns(modifyHPA())

			subRecs = append(subRecs, builder.
				WithNamespace(authCRNS).
				WithPrimary(authCR).
				WithClient(r.Client).
				MustBuild())
		}

		for _, subRec := range subRecs {
			subResult, subErr := subRec.Reconcile(debugCtx)
			results = append(results, subResult)
			errs = append(errs, subErr)
		}

		result, err = common.ReduceSubreconcilerResultsAndErrors(results, errs)
		if err == nil {
			debugLog.Info("Cancel any pending rollouts of Deployments")
			r.needsRollout = false
		}
		if subreconciler.ShouldRequeue(result, err) {
			log.Info("Cluster state has been modified; requeueing")
			return
		}
		return subreconciler.ContinueReconciling()
	} else {
		// HPA is disabled - delete any existing HPA and set fixed replicas
		log.Info("Autoscaling not enabled; remove any existing HPAs")
		for _, deployName := range deployments {
			hpa := &autoscalingv2.HorizontalPodAutoscaler{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deployName + "-hpa",
					Namespace: authCRNS,
				},
			}
			err := r.Get(debugCtx, types.NamespacedName{Name: deployName + "-hpa", Namespace: authCRNS}, hpa)
			if err == nil {
				log.Info("HPA is disabled, Deleting existing HPAs")
				if err := r.Delete(debugCtx, hpa); err == nil {
					r.UpdateDeploymentReplicas(debugCtx, deployName, authCRNS, replicas)
				}
			} else if !errors.IsNotFound(err) {
				return subreconciler.RequeueWithDelay(defaultLowerWait)
			}
		}
	}
	return
}

func generateHPAObject(instance *operatorv1alpha1.Authentication, deploymentName string) common.GenerateFn[*autoscalingv2.HorizontalPodAutoscaler] {
	return func(s common.SecondaryReconciler, ctx context.Context, hpa *autoscalingv2.HorizontalPodAutoscaler) (err error) {

		// Fetch Deployment
		reqLogger := logf.FromContext(ctx)
		deploy := &appsv1.Deployment{}
		minReplicas := instance.Spec.Replicas
		// set min replicas to 2 for large profile as well
		if minReplicas > 2 {
			minReplicas = 2
		}
		err = s.GetClient().Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: instance.Namespace}, deploy)
		if err != nil {
			reqLogger.Error(err, "Failed to fetch Deployment", "DeploymentName", deploymentName)
			return
		}
		// Extract memory and CPU requests and limits
		if len(deploy.Spec.Template.Spec.Containers) == 0 {
			reqLogger.Error(err, "Deployment has no containers")
			return
		}

		container := deploy.Spec.Template.Spec.Containers[0]
		maxReplicas := 2*(instance.Spec.Replicas) + 1

		memRequest := container.Resources.Requests.Memory().Value()
		memLimit := container.Resources.Limits.Memory().Value()
		cpuRequest := container.Resources.Requests.Cpu().MilliValue()
		cpuLimit := container.Resources.Limits.Cpu().MilliValue()

		// Compute average utilization
		avgUtilMem := calculateUtilization(memRequest, memLimit)
		avgUtilCPU := calculateUtilization(cpuRequest, cpuLimit)

		// Define HPA
		*hpa = autoscalingv2.HorizontalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{
				Name:      deploymentName + "-hpa",
				Namespace: instance.Namespace,
				Labels:    instance.Labels,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: instance.APIVersion,
						Kind:       instance.Kind,
						Name:       instance.Name,
						UID:        instance.UID,
					},
				},
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

		// Set owner reference for garbage collection
		err = controllerutil.SetControllerReference(instance, hpa, s.GetClient().Scheme())
		if err != nil {
			reqLogger.Error(err, "Failed to set owner reference for HPA")
			return
		}

		return nil
	}
}

func calculateUtilization(request int64, limit int64) int32 {
	utilizationRatio := (float64(limit) / float64(request)) * 100

	if utilizationRatio < 130 {
		return 90
	}
	return int32((float64(limit) * 0.7 / float64(request)) * 100)
}

func (r *AuthenticationReconciler) UpdateDeploymentReplicas(ctx context.Context, deploymentName, namespace string, fixedReplicas int32) error {

	reqLogger := logf.FromContext(ctx)
	deploy := &appsv1.Deployment{}
	err := r.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: namespace}, deploy)
	if err != nil {
		return err
	}
	// Update only if the existing replica count is different
	if deploy.Spec.Replicas == nil || *deploy.Spec.Replicas != fixedReplicas {
		replicas := fixedReplicas
		deploy.Spec.Replicas = &replicas
		if err := r.Update(ctx, deploy); err != nil {
			reqLogger.Error(err, "failed to update deployment replicas", "deployment", deploy.Name, "desiredReplicas", replicas)
			return err
		}
	} else {
		reqLogger.Info("Deployment already has the correct replicas")
	}

	return nil
}

// modifyHPA looks for relevant differences between the observed and
// generated HPAs and makes modifications to the observed HPA when
// such differences are found. Returns a boolean representing whether a
// modification was made and an error if the operation could not be completed.
func modifyHPA() common.ModifyFn[*autoscalingv2.HorizontalPodAutoscaler] {
	return func(s common.SecondaryReconciler, ctx context.Context, observed, generated *autoscalingv2.HorizontalPodAutoscaler) (modified bool, err error) {
		authCR, ok := s.GetPrimary().(*operatorv1alpha1.Authentication)
		if !ok {
			return
		}
		desiredMax := 2*(authCR.Spec.Replicas) + 1
		if *observed.Spec.MinReplicas > 2 {
			observed.Spec = generated.Spec
			modified = true
		} else if *observed.Spec.MinReplicas != authCR.Spec.Replicas || observed.Spec.MaxReplicas != desiredMax {
			observed.Spec = generated.Spec
			modified = true
		}
		if !common.IsControllerOf(s.GetClient().Scheme(), s.GetPrimary(), observed) {
			if err = controllerutil.SetControllerReference(s.GetPrimary(), observed, s.GetClient().Scheme()); err != nil {
				return false, err
			}
			modified = true
		}

		return
	}
}
