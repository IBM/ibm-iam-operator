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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *AuthenticationReconciler) handleServices(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure Services are created")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	zenFrontDoor := authCR.Spec.Config.ZenFrontDoor

	platformAuthServiceBuilder := common.NewSecondaryReconcilerBuilder[*corev1.Service]().
		WithName("platform-auth-service")

	if zenFrontDoor {
		// When zenFrontDoor is enabled the service must be headless (ClusterIP: "None").
		// If an existing non-headless service is present, delete it first so it can be
		// recreated as headless on the next reconcile (ClusterIP is immutable).
		platformAuthServiceBuilder = platformAuthServiceBuilder.
			WithGenerateFns(
				deleteServiceIfNotHeadless,
				generateService(false, true,
					corev1.ServicePort{
						Name: "p9443",
						Port: 9443,
					},
				),
			).
			WithModifyFns(validateCP3PodSelectorAndLabel, ensureHeadlessClusterIP)
	} else {
		// When zenFrontDoor is disabled the service must be a regular ClusterIP service.
		// If an existing headless service is present (e.g. zenFrontDoor was just disabled),
		// delete it first so it can be recreated as a regular service on the next reconcile.
		platformAuthServiceBuilder = platformAuthServiceBuilder.
			WithGenerateFns(
				deleteServiceIfHeadless,
				generateService(
					true, false,
					corev1.ServicePort{
						Name: "p9443",
						Port: 9443,
					},
				),
			).
			WithModifyFns(validateCP3PodSelectorAndLabel, updateSessionAffinity, ensureNonHeadlessClusterIP)
	}

	builders := []*common.SecondaryReconcilerBuilder[*corev1.Service]{
		platformAuthServiceBuilder,
		common.NewSecondaryReconcilerBuilder[*corev1.Service]().
			WithName("platform-identity-management").
			WithGenerateFns(generateService(
				false, false,
				corev1.ServicePort{
					Name: "p4500",
					Port: 4500,
				},
				corev1.ServicePort{
					Name:     "p443",
					Port:     443,
					Protocol: corev1.ProtocolTCP,
					TargetPort: intstr.IntOrString{
						IntVal: 4500,
					},
				},
			)).
			WithModifyFns(validateCP3PodSelectorAndLabel, updateSessionAffinity),
		common.NewSecondaryReconcilerBuilder[*corev1.Service]().
			WithName("platform-identity-provider").
			WithGenerateFns(generateService(
				true, false,
				corev1.ServicePort{
					Name: "p4300",
					Port: 4300,
				},
			)).
			WithModifyFns(validateCP3PodSelectorAndLabel, updateSessionAffinity),
	}

	subRecs := []common.SecondaryReconciler{}
	for i := range builders {
		subRecs = append(subRecs, builders[i].
			WithNamespace(authCR.Namespace).
			WithPrimary(authCR).
			WithClient(r.Client).
			MustBuild())
	}

	results := []*ctrl.Result{}
	errs := []error{}
	for _, reconciler := range subRecs {
		result, err = reconciler.Reconcile(debugCtx)
		results = append(results, result)
		errs = append(errs, err)
	}

	return common.ReduceSubreconcilerResultsAndErrors(results, errs)
}

func updateSessionAffinity(s common.SecondaryReconciler, ctx context.Context, observed, generated *corev1.Service) (modified bool, err error) {
	log := logf.FromContext(ctx)
	if observed.Spec.SessionAffinity != generated.Spec.SessionAffinity {
		log.Info("Session affinity differs; updating", "current", observed.Spec.SessionAffinity, "desired", generated.Spec.SessionAffinity)
		observed.Spec.SessionAffinity = generated.Spec.SessionAffinity
		modified = true
	}
	return
}

// generateService returns a GenerateFn that creates IM's Services. Takes a
// variable number of corev1.ServicePort structs. When headless is true the
// generated service has ClusterIP set to "None" (headless service).
func generateService(useSessionAffinity bool, headless bool, ports ...corev1.ServicePort) common.GenerateFn[*corev1.Service] {
	return func(s common.SecondaryReconciler, ctx context.Context, service *corev1.Service) (err error) {
		spec := corev1.ServiceSpec{
			Ports: ports,
			Selector: map[string]string{
				"k8s-app": s.GetName(),
			},
			Type:            "ClusterIP",
			SessionAffinity: corev1.ServiceAffinityNone,
		}
		if useSessionAffinity {
			spec.SessionAffinity = corev1.ServiceAffinityClientIP
		}
		if headless {
			spec.ClusterIP = "None"
		}
		*service = corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.GetName(),
				Namespace: s.GetNamespace(),
				Labels:    map[string]string{"app": s.GetName()},
			},
			Spec: spec,
		}

		// Set Authentication instance as the owner and controller of the Service
		err = controllerutil.SetControllerReference(s.GetPrimary(), service, s.GetClient().Scheme())
		return
	}
}

// deleteServiceIfNotHeadless is a GenerateFn that deletes the existing
// platform-auth-service if it is not already a headless service (ClusterIP != "None").
// Since ClusterIP is immutable, the service must be deleted and recreated.
// On the next reconcile the secondary reconciler will create it as headless.
func deleteServiceIfNotHeadless(s common.SecondaryReconciler, ctx context.Context, _ *corev1.Service) (err error) {
	log := logf.FromContext(ctx)
	existing := &corev1.Service{}
	objKey := types.NamespacedName{Name: s.GetName(), Namespace: s.GetNamespace()}
	if err = s.GetClient().Get(ctx, objKey, existing); k8sErrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return
	}
	if existing.Spec.ClusterIP == "None" {
		// Already headless – nothing to do.
		return nil
	}
	log.Info("Deleting non-headless platform-auth-service so it can be recreated as headless")
	if err = s.GetClient().Delete(ctx, existing); k8sErrors.IsNotFound(err) {
		return nil
	}
	return
}

// ensureHeadlessClusterIP is a ModifyFn for platform-auth-service when zenFrontDoor
// is enabled. It is a safety-net that sets ClusterIP to "None" on the observed
// service if for any reason it differs from the generated spec.
// In practice deleteServiceIfNotHeadless handles the transition; this covers any
// race conditions or edge cases.
func ensureHeadlessClusterIP(s common.SecondaryReconciler, ctx context.Context, observed, generated *corev1.Service) (modified bool, err error) {
	log := logf.FromContext(ctx)
	if observed.Spec.ClusterIP != "None" {
		log.Info("Service ClusterIP is not headless; will delete to trigger recreation", "current", observed.Spec.ClusterIP)
		// ClusterIP is immutable – delete so the next reconcile recreates it.
		if err = s.GetClient().Delete(ctx, observed); k8sErrors.IsNotFound(err) {
			err = nil
		}
		// Return modified=false so the secondary reconciler does not attempt an Update.
		return false, err
	}
	return
}

// deleteServiceIfHeadless is a GenerateFn that deletes the existing
// platform-auth-service if it is currently a headless service (ClusterIP == "None").
// This handles the zenFrontDoor true→false transition: since ClusterIP is immutable
// the service must be deleted and recreated as a regular ClusterIP service.
func deleteServiceIfHeadless(s common.SecondaryReconciler, ctx context.Context, _ *corev1.Service) (err error) {
	log := logf.FromContext(ctx)
	existing := &corev1.Service{}
	objKey := types.NamespacedName{Name: s.GetName(), Namespace: s.GetNamespace()}
	if err = s.GetClient().Get(ctx, objKey, existing); k8sErrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return
	}
	if existing.Spec.ClusterIP != "None" {
		// Already a regular ClusterIP service – nothing to do.
		return nil
	}
	log.Info("Deleting headless platform-auth-service so it can be recreated as a regular ClusterIP service")
	if err = s.GetClient().Delete(ctx, existing); k8sErrors.IsNotFound(err) {
		return nil
	}
	return
}

// ensureNonHeadlessClusterIP is a ModifyFn for platform-auth-service when zenFrontDoor
// is disabled. It is a safety-net that deletes the observed service if it is still
// headless (ClusterIP == "None"), triggering recreation as a regular ClusterIP service.
// In practice deleteServiceIfHeadless handles the transition; this covers any
// race conditions or edge cases.
func ensureNonHeadlessClusterIP(s common.SecondaryReconciler, ctx context.Context, observed, generated *corev1.Service) (modified bool, err error) {
	log := logf.FromContext(ctx)
	if observed.Spec.ClusterIP == "None" {
		log.Info("Service is headless but zenFrontDoor is disabled; will delete to trigger recreation")
		// ClusterIP is immutable – delete so the next reconcile recreates it as regular.
		if err = s.GetClient().Delete(ctx, observed); k8sErrors.IsNotFound(err) {
			err = nil
		}
		// Return modified=false so the secondary reconciler does not attempt an Update.
		return false, err
	}
	return
}

// validateCP3ServicePodSelectorAndLabel is a ModifyFn that ensures that the
// Selector for the Service as well as its label match the values for CP3.
func validateCP3PodSelectorAndLabel(s common.SecondaryReconciler, _ context.Context, observed, _ *corev1.Service) (modified bool, err error) {
	podSelector := observed.Spec.Selector
	value, ok := podSelector["k8s-app"]
	if ok && value != observed.Name {
		observed.Spec.Selector = map[string]string{"k8s-app": s.GetName()}
		modified = true
	}
	// Going to validate label for CP3 upgrade
	label := observed.Labels
	value, ok = label["app"]
	if ok && value != observed.Name {
		observed.Labels = map[string]string{"app": s.GetName()}
		modified = true
	}
	return
}
