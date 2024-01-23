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
	ctrlCommon "github.com/IBM/ibm-iam-operator/controllers/common"
	certmgr "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	net "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"reflect"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sync"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
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

var rule = `^([a-z0-9]){32,}$`
var wlpClientID = ctrlCommon.GenerateRandomString(rule)
var wlpClientSecret = ctrlCommon.GenerateRandomString(rule)

// RunningOnOpenShiftCluster returns whether the Operator is running on an OpenShift cluster
func (r *AuthenticationReconciler) RunningOnOpenShiftCluster() bool {
	return ctrlCommon.ClusterHasOpenShiftConfigGroupVerison() && ctrlCommon.ClusterHasRouteGroupVersion()
}

// RunningOnCNCFCluster returns whether the Operator is running on a CNCF cluster
func (r *AuthenticationReconciler) RunningOnCNCFCluster() bool {
	return !ctrlCommon.ClusterHasOpenShiftConfigGroupVerison() || !ctrlCommon.ClusterHasRouteGroupVersion()

}

// RunningOnUnknownCluster returns whether the Operator is running on an unknown cluster type
func (r *AuthenticationReconciler) RunningOnUnknownCluster() bool {
	return r.clusterType == ctrlCommon.Unknown
}

func (r *AuthenticationReconciler) addFinalizer(ctx context.Context, finalizerName string, instance *operatorv1alpha1.Authentication) (err error) {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	if !containsString(instance.Finalizers, finalizerName) {
		instance.Finalizers = append(instance.Finalizers, finalizerName)
		err = r.Client.Update(ctx, instance)
	}
	return
}

// removeFinalizer removes the provided finalizer from the Authentication instance.
func (r *AuthenticationReconciler) removeFinalizer(ctx context.Context, finalizerName string, instance *operatorv1alpha1.Authentication) (err error) {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	if containsString(instance.Finalizers, finalizerName) {
		instance.Finalizers = removeString(instance.Finalizers, finalizerName)
		err = r.Client.Update(ctx, instance)
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
	Client      client.Client
	Scheme      *runtime.Scheme
	Mutex       sync.Mutex
	clusterType ctrlCommon.ClusterType
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
	err = r.Client.Get(reconcileCtx, req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Set err to nil to signal the error has been handled
			err = nil
		}
		// Return without requeueing
		return
	}

	// Credit: kubebuilder book
	finalizerName := "authentication.operator.ibm.com"
	// Determine if the Authentication CR  is going to be deleted
	if instance.ObjectMeta.DeletionTimestamp.IsZero() {
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
	}()

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
	currentCertificate := &certmgr.Certificate{}
	err = r.handleCertificate(instance, currentCertificate, &needToRequeue)
	if err != nil {
		return
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

	//Check if this ConfigMap already exists and create it if it doesn't
	currentConfigMap := &corev1.ConfigMap{}
	err = r.handleConfigMap(instance, wlpClientID, wlpClientSecret, currentConfigMap, &needToRequeue)
	if err != nil {
		return
	}

	// Check if this Job already exists and create it if it doesn't
	currentJob := &batchv1.Job{}
	err = r.handleJob(instance, currentJob, &needToRequeue)
	if err != nil {
		return
	}
	// create clusterrole and clusterrolebinding
	r.createClusterRole(instance)
	r.createClusterRoleBinding(instance)

	r.ReconcileRemoveIngresses(ctx, instance, &needToRequeue)
	// updates redirecturi annotations to serviceaccount
	r.handleServiceAccount(instance, &needToRequeue)

	if ctrlCommon.ClusterHasRouteGroupVersion() {
		err = r.handleRoutes(ctx, instance, &needToRequeue)
		if err != nil && !errors.IsNotFound(err) {
			return
		}
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
		err = r.Client.Update(ctx, instance)
		if err != nil {
			return
		}
	}

	return
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthenticationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if ctrlCommon.ClusterHasOpenShiftConfigGroupVerison() {
		return ctrl.NewControllerManagedBy(mgr).
			Owns(&corev1.ConfigMap{}).
			Owns(&corev1.Secret{}).
			Owns(&certmgr.Certificate{}).
			Owns(&batchv1.Job{}).
			Owns(&corev1.Service{}).
			Owns(&net.Ingress{}).
			Owns(&appsv1.Deployment{}).
			Owns(&routev1.Route{}).
			For(&operatorv1alpha1.Authentication{}).
			Complete(r)
	}
	return ctrl.NewControllerManagedBy(mgr).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&certmgr.Certificate{}).
		Owns(&batchv1.Job{}).
		Owns(&corev1.Service{}).
		Owns(&net.Ingress{}).
		Owns(&appsv1.Deployment{}).
		For(&operatorv1alpha1.Authentication{}).
		Complete(r)
}

// Helper functions to check and remove string from a slice of strings.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}
