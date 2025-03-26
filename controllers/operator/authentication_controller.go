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

	"fmt"
	"reflect"
	"sync"
	"time"

	certmgr "github.com/IBM/ibm-iam-operator/apis/certmanager/v1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/controllers/common"
	"github.com/IBM/ibm-iam-operator/database/migration"
	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	net "k8s.io/api/networking/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	handler "sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	zenv1 "github.com/IBM/ibm-iam-operator/apis/zen.cpd.ibm.com/v1"
	"github.com/opdev/subreconciler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("controller_authentication")
var fullAccess int32 = 0777
var trueVar bool = true
var falseVar bool = false
var seconds60 int64 = 60
var partialAccess int32 = 420
var authServicePort int32 = 9443
var identityProviderPort int32 = 4300
var identityManagerPort int32 = 4500
var serviceAccountName string = "ibm-iam-operand-restricted"

var cpu10 = resource.NewMilliQuantity(10, resource.DecimalSI)            // 10m
var cpu50 = resource.NewMilliQuantity(50, resource.DecimalSI)            // 50m
var cpu100 = resource.NewMilliQuantity(100, resource.DecimalSI)          // 100m
var cpu1000 = resource.NewMilliQuantity(1000, resource.DecimalSI)        // 1000m
var memory32 = resource.NewQuantity(100*1024*1024, resource.BinarySI)    // 32Mi
var memory128 = resource.NewQuantity(128*1024*1024, resource.BinarySI)   // 128Mi
var memory150 = resource.NewQuantity(150*1024*1024, resource.BinarySI)   // 150Mi
var memory178 = resource.NewQuantity(178*1024*1024, resource.BinarySI)   // 178Mi
var memory300 = resource.NewQuantity(300*1024*1024, resource.BinarySI)   // 300Mi
var memory350 = resource.NewQuantity(350*1024*1024, resource.BinarySI)   // 350Mi
var memory400 = resource.NewQuantity(400*1024*1024, resource.BinarySI)   // 400Mi
var memory550 = resource.NewQuantity(550*1024*1024, resource.BinarySI)   // 550Mi
var memory650 = resource.NewQuantity(650*1024*1024, resource.BinarySI)   // 650Mi
var memory1024 = resource.NewQuantity(1024*1024*1024, resource.BinarySI) // 1024Mi

// migrationWait is used when still waiting on a result to be produced by the migration worker
var migrationWait time.Duration = 10 * time.Second

// opreqWait is used for the resources that interact with and originate from OperandRequests
var opreqWait time.Duration = 100 * time.Millisecond

// defaultLowerWait is used in instances where a requeue is needed quickly, regardless of previous requeues
var defaultLowerWait time.Duration = 5 * time.Millisecond

var rule = `^([a-z0-9]){32,}$`
var wlpClientID = ctrlcommon.GenerateRandomString(rule)
var wlpClientSecret = ctrlcommon.GenerateRandomString(rule)

// finalizerName is the finalizer appended to the Authentication CR
var finalizerName = "authentication.operator.ibm.com"

func (r *AuthenticationReconciler) loopUntilConditionsSet(ctx context.Context, req ctrl.Request, conditions ...*metav1.Condition) {
	reqLogger := logf.FromContext(ctx)
	conditionsSet := false
	for !conditionsSet {
		authCR := &operatorv1alpha1.Authentication{}
		if result, err := r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
			reqLogger.Info("Failed to retrieve Authentication CR for status update; retrying")
			continue
		}
		for _, condition := range conditions {
			if condition == nil {
				continue
			}
			meta.SetStatusCondition(&authCR.Status.Conditions, *condition)
		}
		if err := r.Client.Status().Update(ctx, authCR); err != nil {
			reqLogger.Error(err, "Failed to set conditions on Authentication; retrying", "conditions", conditions)
			continue
		}
		conditionsSet = true
	}
}

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
	return ctrlcommon.ClusterHasOpenShiftConfigGroupVerison(&r.DiscoveryClient) && ctrlcommon.ClusterHasRouteGroupVersion(&r.DiscoveryClient)
}

// RunningOnCNCFCluster returns whether the Operator is running on a CNCF cluster
func (r *AuthenticationReconciler) RunningOnCNCFCluster() bool {
	return !ctrlcommon.ClusterHasOpenShiftConfigGroupVerison(&r.DiscoveryClient) || !ctrlcommon.ClusterHasRouteGroupVersion(&r.DiscoveryClient)

}

// RunningOnUnknownCluster returns whether the Operator is running on an unknown cluster type
func (r *AuthenticationReconciler) RunningOnUnknownCluster() bool {
	return r.clusterType == ctrlcommon.Unknown
}

func (r *AuthenticationReconciler) addFinalizer(ctx context.Context, finalizerName string, instance *operatorv1alpha1.Authentication) (err error) {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	if !ctrlcommon.ContainsString(instance.Finalizers, finalizerName) {
		instance.Finalizers = append(instance.Finalizers, finalizerName)
		err = r.Update(ctx, instance)
	}
	return
}

// removeFinalizer removes the provided finalizer from the Authentication instance.
func (r *AuthenticationReconciler) removeFinalizer(ctx context.Context, finalizerName string, instance *operatorv1alpha1.Authentication) (err error) {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	if ctrlcommon.ContainsString(instance.Finalizers, finalizerName) {
		instance.Finalizers = ctrlcommon.RemoveString(instance.Finalizers, finalizerName)
		err = r.Update(ctx, instance)
		if err != nil {
			return fmt.Errorf("error updating the CR to remove the finalizer: %w", err)
		}
	}
	return
}

// needsAuditServiceDummyDataReset compares the state in an Authentication's .spec.auditService and returns whether it
// needs to be overwritten with dummy data.
func needsAuditServiceDummyDataReset(a *operatorv1alpha1.Authentication) bool {
	return a.Spec.AuditService.ImageName != operatorv1alpha1.AuditServiceIgnoreString ||
		a.Spec.AuditService.ImageRegistry != operatorv1alpha1.AuditServiceIgnoreString ||
		a.Spec.AuditService.ImageTag != operatorv1alpha1.AuditServiceIgnoreString ||
		a.Spec.AuditService.SyslogTlsPath != "" ||
		a.Spec.AuditService.Resources != nil
}

// AuthenticationReconciler reconciles a Authentication object
type AuthenticationReconciler struct {
	client.Client
	Reader          client.Reader
	Scheme          *runtime.Scheme
	DiscoveryClient discovery.DiscoveryClient
	Mutex           sync.Mutex
	clusterType     ctrlcommon.ClusterType
	dbSetupChan     chan *migration.Result
}

// GetFromCacheOrAPI first tries to GET the object from the cache; if this
// fails, it attempts a GET from the API server directly.
func (r *AuthenticationReconciler) Get(ctx context.Context, objkey client.ObjectKey, obj client.Object) (err error) {
	if err = r.Client.Get(ctx, objkey, obj); k8sErrors.IsNotFound(err) {
		return r.Reader.Get(ctx, objkey, obj)
	}
	return
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Authentication object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *AuthenticationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	reqLogger := log.WithValues("Request.Namespace", req.Namespace, "Request.Name", req.Name)

	needToRequeue := false

	reconcileCtx := logf.IntoContext(ctx, reqLogger)
	// Set default result
	result = ctrl.Result{}
	// Set Requeue to true if requeue is needed at end of reconcile loop
	defer func() {
		if needToRequeue {
			result.Requeue = true
		}
	}()

	reqLogger.Info("Reconciling Authentication")

	// Fetch the Authentication instance
	instance := &operatorv1alpha1.Authentication{}
	err = r.Get(reconcileCtx, req.NamespacedName, instance)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Set err to nil to signal the error has been handled
			err = nil
		}
		// Return without requeueing
		return
	}

	// Determine if the Authentication CR  is going to be deleted
	if instance.DeletionTimestamp.IsZero() {
		// Object not being deleted, but add our finalizer so we know to remove this object later when it is going to be deleted
		beforeFinalizerCount := len(instance.GetFinalizers())
		err = r.addFinalizer(reconcileCtx, finalizerName, instance)
		if err != nil {
			return
		}
		afterFinalizerCount := len(instance.GetFinalizers())
		if afterFinalizerCount > beforeFinalizerCount {
			needToRequeue = true
			return
		}
	} else {
		// Object scheduled to be deleted
		err = r.removeFinalizer(reconcileCtx, finalizerName, instance)
		return
	}

	// Be sure to update status before returning if Authentication is found (but only if the Authentication hasn't
	// already been updated, e.g. finalizer update
	defer func() {
		reqLogger.Info("Update status before finishing loop.")
		if reflect.DeepEqual(instance.Status, operatorv1alpha1.AuthenticationStatus{}) {
			instance.Status = operatorv1alpha1.AuthenticationStatus{
				Nodes: []string{},
			}
		}
		currentServiceStatus := r.getCurrentServiceStatus(ctx, r.Client, instance)
		if !reflect.DeepEqual(currentServiceStatus, instance.Status.Service) {
			instance.Status.Service = currentServiceStatus
			reqLogger.Info("Current status does not reflect current state; updating")
		}
		statusUpdateErr := r.Client.Status().Update(ctx, instance)
		if statusUpdateErr != nil {
			reqLogger.Error(statusUpdateErr, "Failed to update status; trying again")
			currentInstance := &operatorv1alpha1.Authentication{}
			r.Client.Get(ctx, req.NamespacedName, currentInstance)
			currentInstance.Status.Service = currentServiceStatus
			statusUpdateErr = r.Client.Status().Update(ctx, currentInstance)
			if statusUpdateErr != nil {
				reqLogger.Error(statusUpdateErr, "Retry failed; returning error")
				return
			}
		} else {
			reqLogger.Info("Updated status")
		}
		reqLogger.V(1).Info("Final result", "result", result, "err", err)
	}()

	var subResult *ctrl.Result
	if subResult, err = r.addMongoMigrationFinalizers(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		reqLogger.V(1).Info("Should halt or requeue after addMongoMigrationFinalizers", "result", result, "err", err)
		result, err = subreconciler.Evaluate(subResult, err)
		return
	}

	if subResult, err = r.overrideMongoDBBootstrap(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		reqLogger.V(1).Info("Should halt or requeue after overrideMongoDBBootstrap", "result", result, "err", err)
		result, err = subreconciler.Evaluate(subResult, err)
		return
	}

	if subResult, err = r.handleOperandRequest(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		reqLogger.V(1).Info("Should halt or requeue after handleOperandRequest", "result", result, "err", err)
		result, err = subreconciler.Evaluate(subResult, err)
		return
	}

	if subResult, err = r.createEDBShareClaim(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		reqLogger.V(1).Info("Should halt or requeue after createEDBShareClaim", "result", result, "err", err)
		result, err = subreconciler.Evaluate(subResult, err)
		return
	}

	// Check if this Certificate already exists and create it if it doesn't
	reqLogger.Info("Creating ibm-iam-operand-restricted serviceaccount")
	currentSA := &corev1.ServiceAccount{}
	err = r.createSA(instance, currentSA, &needToRequeue)
	if err != nil {
		return
	}
	// create operand role and role-binding
	r.createRole(instance)
	r.createRoleBinding(instance)

	// Check if this Certificate already exists and create it if it doesn't
	if subResult, err := r.handleCertificates(ctx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	// Check if this Service already exists and create it if it doesn't
	currentService := &corev1.Service{}
	err = r.handleService(instance, currentService, &needToRequeue)
	if err != nil {
		return
	}

	// Check if this Secret already exists and create it if it doesn't
	currentSecret := &corev1.Secret{}
	err = r.handleSecret(instance, wlpClientID, wlpClientSecret, currentSecret, &needToRequeue)
	if err != nil {
		return
	}

	if subResult, err := r.handleConfigMaps(ctx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	if subResult, err := r.handleOperandBindInfo(ctx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	// Check if this Job already exists and create it if it doesn't
	currentJob := &batchv1.Job{}
	err = r.handleJob(instance, currentJob, &needToRequeue)
	if err != nil {
		return
	}
	// create clusterrole and clusterrolebinding
	if subResult, err := r.handleClusterRoles(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	if subResult, err := r.handleClusterRoleBindings(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	r.ReconcileRemoveIngresses(ctx, instance, &needToRequeue)
	// updates redirecturi annotations to serviceaccount
	r.handleServiceAccount(instance, &needToRequeue)

	if subResult, err := r.ensureDatastoreSecretAndCM(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	// perform any migrations that may be needed before Deployments run
	if subResult, err := r.handleMigrations(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	if subResult, err := r.setMigrationCompleteStatus(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	if result, err := r.handleMongoDBCleanup(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(result, err) {
		reqLogger.V(1).Info("Should halt or requeue after handleMongoDBCleanup", "result", result, "err", err)
		return subreconciler.Evaluate(result, err)
	}

	// Check if this Deployment already exists and create it if it doesn't
	currentDeployment := &appsv1.Deployment{}
	currentProviderDeployment := &appsv1.Deployment{}
	currentManagerDeployment := &appsv1.Deployment{}
	err = r.handleDeployment(instance, currentDeployment, currentProviderDeployment, currentManagerDeployment, &needToRequeue)
	if err != nil {
		return
	}

	if needsAuditServiceDummyDataReset(instance) {
		instance.SetRequiredDummyData()
		err = r.Update(ctx, instance)
		if err != nil {
			return
		}
	}

	if subResult, err := r.handleZenFrontDoor(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	if subResult, err := r.handleRoutes(ctx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	return
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthenticationReconciler) SetupWithManager(mgr ctrl.Manager) error {

	authCtrl := ctrl.NewControllerManagedBy(mgr).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&certmgr.Certificate{}).
		Owns(&batchv1.Job{}).
		Owns(&corev1.Service{}).
		Owns(&net.Ingress{}).
		Owns(&appsv1.Deployment{})

	//Add routes
	if ctrlcommon.ClusterHasOpenShiftConfigGroupVerison(&r.DiscoveryClient) {
		authCtrl.Owns(&routev1.Route{})
	}
	if ctrlcommon.ClusterHasZenExtensionGroupVersion(&r.DiscoveryClient) {
		authCtrl.Owns(&zenv1.ZenExtension{})
	}
	if ctrlcommon.ClusterHasOperandRequestAPIResource(&r.DiscoveryClient) {
		authCtrl.Owns(&operatorv1alpha1.OperandRequest{})
	}
	if ctrlcommon.ClusterHasOperandBindInfoAPIResource(&r.DiscoveryClient) {
		authCtrl.Owns(&operatorv1alpha1.OperandBindInfo{})
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
		return o.GetName() == ctrlcommon.GlobalConfigMapName
	})

	authCtrl.Watches(&corev1.ConfigMap{},
		handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) (requests []reconcile.Request) {
			authCR, _ := ctrlcommon.GetAuthentication(ctx, &r.Client)
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
	return authCtrl.For(&operatorv1alpha1.Authentication{}).
		Complete(r)
}

func apiResourceIsNamespaced(gvk schema.GroupVersionKind, apiLists []*metav1.APIResourceList) (isNamespaced bool) {
	for _, apiList := range apiLists {
		if apiList.GroupVersion != gvk.GroupVersion().String() {
			continue
		}
		for _, r := range apiList.APIResources {
			if r.Kind == gvk.Kind {
				return r.Namespaced
			}
		}
	}
	return false
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
