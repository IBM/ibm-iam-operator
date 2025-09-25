/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package operator

import (
	"context"
	"reflect"
	"runtime"
	"strings"

	"fmt"
	"sync"
	"time"

	certmgr "github.com/IBM/ibm-iam-operator/internal/api/certmanager/v1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/IBM/ibm-iam-operator/internal/version"
	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	handler "sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	sscsidriverv1 "sigs.k8s.io/secrets-store-csi-driver/apis/v1"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/opdev/subreconciler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var fullAccess int32 = 0777
var trueVar bool = true
var falseVar bool = false
var seconds60 int64 = 60
var partialAccess int32 = 420
var authServicePort int32 = 9443
var authHealthCheckPort int32 = 9080
var identityProviderPort int32 = 4300
var identityManagerPort int32 = 4500
var serviceAccountName string = "ibm-iam-operand-restricted"

var cpu50 = resource.NewMilliQuantity(50, resource.DecimalSI)            // 50m
var cpu100 = resource.NewMilliQuantity(100, resource.DecimalSI)          // 100m
var cpu1000 = resource.NewMilliQuantity(1000, resource.DecimalSI)        // 1000m
var memory128 = resource.NewQuantity(128*1024*1024, resource.BinarySI)   // 128Mi
var memory150 = resource.NewQuantity(150*1024*1024, resource.BinarySI)   // 150Mi
var memory178 = resource.NewQuantity(178*1024*1024, resource.BinarySI)   // 178Mi
var memory300 = resource.NewQuantity(300*1024*1024, resource.BinarySI)   // 300Mi
var memory350 = resource.NewQuantity(350*1024*1024, resource.BinarySI)   // 350Mi
var memory400 = resource.NewQuantity(400*1024*1024, resource.BinarySI)   // 400Mi
var memory550 = resource.NewQuantity(550*1024*1024, resource.BinarySI)   // 550Mi
var memory650 = resource.NewQuantity(650*1024*1024, resource.BinarySI)   // 650Mi
var memory1024 = resource.NewQuantity(1024*1024*1024, resource.BinarySI) // 1024Mi

// opreqWait is used for the resources that interact with and originate from OperandRequests
var opreqWait time.Duration = 100 * time.Millisecond

// defaultLowerWait is used in instances where a requeue is needed quickly, regardless of previous requeues
var defaultLowerWait time.Duration = 5 * time.Millisecond

// finalizerName is the finalizer appended to the Authentication CR
var finalizerName = "authentication.operator.ibm.com"

func (r *AuthenticationReconciler) getLatestAuthentication(ctx context.Context, req ctrl.Request, authentication *operatorv1alpha1.Authentication) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)
	if err := r.Get(ctx, req.NamespacedName, authentication); err != nil {
		if k8sErrors.IsNotFound(err) {
			reqLogger.Info("Authentication not found; skipping reconciliation")
			return subreconciler.DoNotRequeue()
		}
		reqLogger.Error(err, "Failed to get Authentication")
		return subreconciler.RequeueWithError(err)
	}
	return subreconciler.ContinueReconciling()
}

// RunningOnOpenShiftCluster returns whether the Operator is running on an OpenShift cluster
func (r *AuthenticationReconciler) RunningOnOpenShiftCluster() bool {
	return common.ClusterHasOpenShiftConfigGroupVerison(&r.DiscoveryClient) && common.ClusterHasRouteGroupVersion(&r.DiscoveryClient)
}

// RunningOnCNCFCluster returns whether the Operator is running on a CNCF cluster
func (r *AuthenticationReconciler) RunningOnCNCFCluster() bool {
	return !common.ClusterHasOpenShiftConfigGroupVerison(&r.DiscoveryClient) || !common.ClusterHasRouteGroupVersion(&r.DiscoveryClient)

}

// RunningOnUnknownCluster returns whether the Operator is running on an unknown cluster type
func (r *AuthenticationReconciler) RunningOnUnknownCluster() bool {
	return r.clusterType == common.Unknown
}

func (r *AuthenticationReconciler) addFinalizer(ctx context.Context, finalizerName string, instance *operatorv1alpha1.Authentication) (err error) {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	if !common.ContainsString(instance.Finalizers, finalizerName) {
		instance.Finalizers = append(instance.Finalizers, finalizerName)
		err = r.Update(ctx, instance)
	}
	return
}

// removeFinalizer removes the provided finalizer from the Authentication instance.
func (r *AuthenticationReconciler) removeFinalizer(ctx context.Context, finalizerName string, instance *operatorv1alpha1.Authentication) (err error) {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	if common.ContainsString(instance.Finalizers, finalizerName) {
		instance.Finalizers = common.RemoveString(instance.Finalizers, finalizerName)
		err = r.Update(ctx, instance)
		if err != nil {
			return fmt.Errorf("error updating the CR to remove the finalizer: %w", err)
		}
	}
	return
}

// AuthenticationReconciler reconciles a Authentication object
type AuthenticationReconciler struct {
	client.Client
	Scheme          *k8sRuntime.Scheme
	DiscoveryClient discovery.DiscoveryClient
	Mutex           sync.Mutex
	clusterType     common.ClusterType
	needsRollout    bool
	common.ByteGenerator
}

func GetFunctionName(fn any) string {
	fnStrs := strings.Split(runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name(), ".")
	return strings.Split(fnStrs[len(fnStrs)-1], "-")[0]
}

// withResultLog is a helper function that logs the result of a subreconciler
func withResultLog(fn subreconciler.FnWithRequest) func(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	return func(rootCtx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
		fnName := GetFunctionName(fn)
		log := logf.FromContext(rootCtx, "subreconciler", fnName)
		ctx := logf.IntoContext(rootCtx, log)
		log.V(1).Info("Running subreconciler")
		if result, err = fn(ctx, req); subreconciler.ShouldHaltOrRequeue(result, err) {
			log.V(1).Info("Result: should halt or requeue ", "result", result, "err", err)
			return
		}
		log.V(1).Info("Result: no requeue necessary", "result", result, "err", err)
		return
	}
}

func (r *AuthenticationReconciler) updateAuthenticationStatus(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	observed := &operatorv1alpha1.Authentication{}
	modified := false
	if result, err = r.getLatestAuthentication(ctx, req, observed); subreconciler.ShouldHaltOrRequeue(result, err) {
		log.Info("Could not get Authentication before service status update")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	modified, err = r.setAuthenticationStatus(ctx, observed)
	if err != nil {
		log.Error(err, "Failed to set Authentication status")
		return subreconciler.RequeueWithError(err)
	} else if !modified && observed.Status.Service.Status == ResourceReadyState {
		log.Info("No new status changes needed")
		return subreconciler.DoNotRequeue()
	} else if !modified {
		log.Info("Not ready yet; requeue")
		return subreconciler.Requeue()
	}

	log.Info("Status updates found; update status before finishing loop.")
	if err = r.Client.Status().Update(ctx, observed); err != nil {
		log.Error(err, "Failed to update status")
		return subreconciler.RequeueWithError(err)
	}
	log.Info("Updated status")
	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

func (r *AuthenticationReconciler) handleAuthenticationFinalizer(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	// Determine if the Authentication CR is going to be deleted
	if authCR.DeletionTimestamp.IsZero() {
		log.Info("Authentication is not being deleted; add finalizer if not present")
		// Object not being deleted, but add our finalizer so we know to remove this object later when it is going to be deleted
		beforeFinalizerCount := len(authCR.GetFinalizers())
		err = r.addFinalizer(ctx, finalizerName, authCR)
		if err != nil {
			log.Info("Failed to add finalizer")
			return subreconciler.RequeueWithError(err)
		}
		afterFinalizerCount := len(authCR.GetFinalizers())
		if afterFinalizerCount > beforeFinalizerCount {
			log.Info("Finalizer added successfully")
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		}
		log.Info("Finalizer already present")
		return subreconciler.ContinueReconciling()
	}
	log.Info("Authentication is being deleted")

	// Object scheduled to be deleted
	if err = r.removeFinalizer(ctx, finalizerName, authCR); err != nil {
		log.Info("Failed to remove finalizer")
		return subreconciler.RequeueWithError(err)
	}

	log.Info("Removed finalizer successfully")

	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *AuthenticationReconciler) Reconcile(rootCtx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := logf.FromContext(rootCtx).WithName("controller_authentication")
	ctx := logf.IntoContext(rootCtx, log)
	log.Info("Reconciling Authentication CR")

	// Fetch the Authentication instance
	authCR := &operatorv1alpha1.Authentication{}
	err = r.Get(ctx, req.NamespacedName, authCR)
	if k8sErrors.IsNotFound(err) {
		return result, nil
	} else if err != nil {
		return
	}

	if !common.ClusterHasCSIGroupVersion(&r.DiscoveryClient) && authCR.SecretsStoreCSIEnabled() {
		log.Info("useSecretsStoreCSI is enabled, but the API is not available on this cluster. Ignoring setting until Secrets Store CSI driver is installed.")
	}

	var subResult *ctrl.Result

	fns := []subreconciler.FnWithRequest{
		r.handleAuthenticationFinalizer,
		r.createSA,
		r.createRole,
		r.createRoleBinding,
		r.handleClusterRoles,
		r.handleClusterRoleBindings,
		r.addMongoMigrationFinalizers,
		r.overrideMongoDBBootstrap,
		r.handleOperandRequest,
		r.createEDBShareClaim,
		r.ensureDatastoreSecretAndCM,
		r.ensureCommonServiceDBIsReady,
		r.ensureMigrationJobRuns,
		r.checkSAMLPresence,
		r.handleCertificates,
		r.handleServices,
		r.handleOperandBindInfo,
		r.handleSecrets,
		r.handleConfigMaps,
		r.removeIngresses,
		r.handleServiceAccount,
		r.ensureMigrationJobSucceeded,
		r.handleDeployments,
		r.ensureOIDCClientRegistrationJobRuns,
		r.handleZenFrontDoor,
		r.handleRoutes,
		r.handleHPAs,
		r.syncClientHostnames,
		r.handleMongoDBCleanup,
	}

	for _, fn := range fns {
		if subResult, err = withResultLog(fn)(ctx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
			break
		}
	}

	subResult, err = r.updateAuthenticationStatus(ctx, req)
	if subreconciler.ShouldRequeue(subResult, err) {
		log.Info("Reconciliation for Authentication CR spec incomplete; requeueing")
	} else if subreconciler.ShouldContinue(subResult, err) {
		log.Info("Reconciliation for Authentication CR spec complete")
	} else {
		log.Info("Reconciling Authentication CR complete")
	}

	result, err = subreconciler.Evaluate(subResult, err)
	log.V(1).Info("Reconciliation return", "result", result, "err", err)
	return
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthenticationReconciler) SetupWithManager(mgr ctrl.Manager) error {

	authCtrl := ctrl.NewControllerManagedBy(mgr).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1alpha1.Authentication{}, handler.OnlyControllerOwner())).
		Watches(&corev1.Secret{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1alpha1.Authentication{}, handler.OnlyControllerOwner())).
		Watches(&certmgr.Certificate{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1alpha1.Authentication{}, handler.OnlyControllerOwner())).
		Watches(&batchv1.Job{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1alpha1.Authentication{}, handler.OnlyControllerOwner())).
		Watches(&corev1.Service{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1alpha1.Authentication{}, handler.OnlyControllerOwner())).
		Watches(&netv1.Ingress{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1alpha1.Authentication{}, handler.OnlyControllerOwner())).
		Watches(&appsv1.Deployment{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1alpha1.Authentication{}, handler.OnlyControllerOwner())).
		Watches(&autoscalingv2.HorizontalPodAutoscaler{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1alpha1.Authentication{}, handler.OnlyControllerOwner()))

	//Add routes
	if common.ClusterHasOpenShiftConfigGroupVerison(&r.DiscoveryClient) {
		authCtrl.Watches(&routev1.Route{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1alpha1.Authentication{}, handler.OnlyControllerOwner()))
	}
	if common.ClusterHasOperandRequestAPIResource(&r.DiscoveryClient) {
		authCtrl.Watches(&operatorv1alpha1.OperandRequest{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1alpha1.Authentication{}, handler.OnlyControllerOwner()))
	}
	if common.ClusterHasOperandBindInfoAPIResource(&r.DiscoveryClient) {
		authCtrl.Watches(&operatorv1alpha1.OperandBindInfo{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1alpha1.Authentication{}, handler.OnlyControllerOwner()))
	}
	if common.ClusterHasCSIGroupVersion(&r.DiscoveryClient) {
		authCtrl.Watches(&sscsidriverv1.SecretProviderClass{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1alpha1.Authentication{}, handler.OnlyControllerOwner()))
		spcLabelSelector := metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "app.kubernetes.io/part-of",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"im"},
				},
				{
					Key:      SecretProviderClassAsVolumeLabel,
					Operator: metav1.LabelSelectorOpExists,
				},
			},
		}
		spcLabelPredicate, err := predicate.LabelSelectorPredicate(spcLabelSelector)
		if err != nil {
			return err
		}
		authCtrl.Watches(&sscsidriverv1.SecretProviderClass{},

			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) (requests []reconcile.Request) {
				authCR, _ := common.GetAuthentication(ctx, r.Client)
				if authCR == nil {
					return
				}
				return []reconcile.Request{
					{NamespacedName: types.NamespacedName{
						Name:      authCR.Name,
						Namespace: authCR.Namespace,
					}},
				}
			}), builder.WithPredicates(spcLabelPredicate),
		)
	}

	productCMPred := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldObj := e.ObjectOld.(*corev1.ConfigMap)
			newObj := e.ObjectNew.(*corev1.ConfigMap)

			return oldObj.Name == ZenProductConfigmapName && oldObj.Data[URL_PREFIX] != newObj.Data[URL_PREFIX]
		},

		// Allow create events
		CreateFunc: func(e event.CreateEvent) bool {
			obj := e.Object.(*corev1.ConfigMap)
			return obj.Name == ZenProductConfigmapName
		},

		// Allow delete events
		DeleteFunc: func(e event.DeleteEvent) bool {
			obj := e.Object.(*corev1.ConfigMap)
			return obj.Name == ZenProductConfigmapName
		},

		// Allow generic events (e.g., external triggers)
		GenericFunc: func(e event.GenericEvent) bool {
			obj := e.Object.(*corev1.ConfigMap)
			return obj.Name == ZenProductConfigmapName
		},
	}

	globalCMPred := predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetName() == common.GlobalConfigMapName
	})

	authCtrl.Watches(&corev1.ConfigMap{},
		handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) (requests []reconcile.Request) {
			authCR, _ := common.GetAuthentication(ctx, r.Client)
			if authCR == nil {
				return
			}
			return []reconcile.Request{
				{NamespacedName: types.NamespacedName{
					Name:      authCR.Name,
					Namespace: authCR.Namespace,
				}},
			}
		}), builder.WithPredicates(predicate.Or(globalCMPred, productCMPred)),
	)
	bootstrappedPred := predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetLabels()[common.ManagerVersionLabel] == version.Version
	})

	authCtrl.Watches(&operatorv1alpha1.Authentication{}, &handler.EnqueueRequestForObject{}, builder.WithPredicates(bootstrappedPred))
	return authCtrl.Named("controller_authentication").
		Complete(r)
}

// hasAPIAccess uses SelfSubjectAccessReviews to confirm whether the Opertor's ServiceAccount has authorization to use a
// list of verbs on a given apiversion and kind.
func (r *AuthenticationReconciler) hasAPIAccess(ctx context.Context, namespace string, group string, resource string, verbs []string) (hasAccess bool, err error) {
	reqLogger := logf.FromContext(ctx).V(1).WithValues("namespace", namespace, "group", group, "resource", resource, "verbs", verbs)
	for _, verb := range verbs {
		ssar := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: namespace,
					Verb:      verb,
					Group:     group,
					Resource:  resource,
				},
			},
		}
		reqLogger.Info("Creating SSAR", "namespace", namespace, "verb", verb, "group", group, "resource", resource)
		if err = r.Create(ctx, ssar); err != nil {
			reqLogger.Error(err, "Failed to make access check query")
			return false, fmt.Errorf("failed to make access check query: %w", err)
		}
		if !ssar.Status.Allowed {
			reqLogger.Info("Operator ServiceAccount is not authorized", "allowed", ssar.Status.Allowed, "denied", ssar.Status.Denied, "reason", ssar.Status.Reason)
			return
		}
	}

	reqLogger.Info("Operator ServiceAccount is authorized")
	return true, nil
}
