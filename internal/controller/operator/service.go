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
	"sigs.k8s.io/controller-runtime/pkg/client"
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

	// platform-auth-service is always a regular ClusterIP service with session
	// affinity. It is never made headless regardless of zenFrontDoor or gvk settings.
	builders := []*common.SecondaryReconcilerBuilder[*corev1.Service]{
		common.NewSecondaryReconcilerBuilder[*corev1.Service]().
			WithName("platform-auth-service").
			WithGenerateFns(generateService(
				true,
				corev1.ServicePort{
					Name: "p9443",
					Port: 9443,
				},
				corev1.ServicePort{
					Name: "p3100",
					Port: 3100,
				},
			)).
			WithModifyFns(validateCP3PodSelectorAndLabel, updateSessionAffinity),
		common.NewSecondaryReconcilerBuilder[*corev1.Service]().
			WithName("platform-identity-management").
			WithGenerateFns(generateService(
				false,
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
				true,
				corev1.ServicePort{
					Name: "p4300",
					Port: 4300,
				},
			)).
			WithModifyFns(validateCP3PodSelectorAndLabel, updateSessionAffinity),
	}

	// platform-auth-service-headless is an additional headless service required
	// only when BOTH conditions hold simultaneously:
	//   - spec.config.zenFrontDoor: true
	//   - spec.config.ingress.gvk: "none"  (i.e. ShouldRemoveRoutes() == true)
	//
	// In all other cases (any one condition is absent or toggled off) the headless
	// service must be removed if it exists:
	//   Case 2: zenFrontDoor=true  but gvk removed/changed → delete
	//   Case 3: zenFrontDoor=false and gvk=none             → delete
	//   Case 4: zenFrontDoor=false and gvk=ocp-route        → delete
	if authCR.Spec.Config.ZenFrontDoor && authCR.ShouldRemoveRoutes() {
		// Case 1: both conditions met → add the headless service to the builders list
		// so it is reconciled through the same loop as all other services.
		builders = append(builders, common.NewSecondaryReconcilerBuilder[*corev1.Service]().
			WithName("platform-auth-service-headless").
			WithGenerateFns(generateHeadlessService(
				"platform-auth-service", // selector: target pods of platform-auth-service
				corev1.ServicePort{
					Name: "p9443",
					Port: 9443,
				},
			)).
			WithModifyFns(validateCP3PodSelectorAndLabel))
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

	// Cases 2, 3, 4: condition no longer holds → delete headless service if present.
	if !authCR.Spec.Config.ZenFrontDoor || !authCR.ShouldRemoveRoutes() {
		if cleanupErr := deleteHeadlessAuthServiceIfExists(debugCtx, r.Client, authCR.Namespace); cleanupErr != nil {
			log.Error(cleanupErr, "Failed to delete platform-auth-service-headless during cleanup")
			errs = append(errs, cleanupErr)
		}
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
// variable number of corev1.ServicePort structs.
func generateService(useSessionAffinity bool, ports ...corev1.ServicePort) common.GenerateFn[*corev1.Service] {
	return func(s common.SecondaryReconciler, ctx context.Context, service *corev1.Service) (err error) {
		*service = corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.GetName(),
				Namespace: s.GetNamespace(),
				Labels:    map[string]string{"app": s.GetName()},
			},
			Spec: corev1.ServiceSpec{
				Ports: ports,
				Selector: map[string]string{
					"k8s-app": s.GetName(),
				},
				Type:            "ClusterIP",
				SessionAffinity: corev1.ServiceAffinityNone,
			},
		}
		if useSessionAffinity {
			service.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
		}

		// Set Authentication instance as the owner and controller of the Service
		err = controllerutil.SetControllerReference(s.GetPrimary(), service, s.GetClient().Scheme())
		return
	}
}

// generateHeadlessService returns a GenerateFn that creates a headless ClusterIP
// service (ClusterIP: "None"). The selector is set to the provided podSelectorName
// rather than the service's own name, allowing the headless service to target a
// different set of pods (e.g. platform-auth-service-headless targeting the pods
// of platform-auth-service). Takes a variable number of corev1.ServicePort structs.
func generateHeadlessService(podSelectorName string, ports ...corev1.ServicePort) common.GenerateFn[*corev1.Service] {
	return func(s common.SecondaryReconciler, ctx context.Context, service *corev1.Service) (err error) {
		*service = corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.GetName(),
				Namespace: s.GetNamespace(),
				Labels:    map[string]string{"app": s.GetName()},
			},
			Spec: corev1.ServiceSpec{
				Ports: ports,
				Selector: map[string]string{
					"k8s-app": podSelectorName,
				},
				Type:      "ClusterIP",
				ClusterIP: "None", // headless: no virtual IP, DNS returns individual pod IPs
			},
		}

		// Set Authentication instance as the owner and controller of the Service
		err = controllerutil.SetControllerReference(s.GetPrimary(), service, s.GetClient().Scheme())
		return
	}
}

// deleteHeadlessAuthServiceIfExists deletes platform-auth-service-headless when
// the condition that requires it (zenFrontDoor=true AND gvk=none) no longer holds.
// It is safe to call when the service does not exist.
func deleteHeadlessAuthServiceIfExists(ctx context.Context, cl client.Client, namespace string) error {
	log := logf.FromContext(ctx)
	svc := &corev1.Service{}
	objKey := types.NamespacedName{Name: "platform-auth-service-headless", Namespace: namespace}
	if err := cl.Get(ctx, objKey, svc); k8sErrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}
	log.Info("Deleting platform-auth-service-headless: condition (zenFrontDoor=true AND gvk=none) no longer holds")
	if err := cl.Delete(ctx, svc); k8sErrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}
	return nil
}

var headlessServiceSelectorMap = map[string]string{
	"platform-auth-service-headless": "platform-auth-service",
}

// validateCP3ServicePodSelectorAndLabel is a ModifyFn that ensures that the
// Selector for the Service as well as its label match the values for CP3.
func validateCP3PodSelectorAndLabel(s common.SecondaryReconciler, _ context.Context, observed, _ *corev1.Service) (modified bool, err error) {
	podSelector := observed.Spec.Selector
	value, ok := podSelector["k8s-app"]

	expectedK8sAppValue, isHeadlessService := headlessServiceSelectorMap[observed.Name]
	if !isHeadlessService {
		expectedK8sAppValue = s.GetName()
	}

	if ok && value != observed.Name {
		observed.Spec.Selector = map[string]string{"k8s-app": expectedK8sAppValue}
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
