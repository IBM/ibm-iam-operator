//
// Copyright 2023 IBM Corporation
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
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// addEmbeddedDBIfNeeded appends the common-service-cnpg Operand to the list of
// Operands when the IM install is configured to use an embedded IBM CNPG. If there
// is an error while trying to obtain the relevant IM configuration for IBM
// CNPG, it will skip adding the Operand and return the encountered error.
func (r *AuthenticationReconciler) addEmbeddedDBIfNeeded(ctx context.Context, authCR *operatorv1alpha1.Authentication,
	operands *[]operatorv1alpha1.Operand) (err error) {
	var usingExternal bool
	if usingExternal, err = r.isConfiguredForExternalDB(ctx, authCR); err != nil || usingExternal {
		return
	}
	name := "common-service-cnpg"
	*operands = append(*operands, operatorv1alpha1.Operand{
		Name: name,
		Bindings: map[string]operatorv1alpha1.Bindable{
			"protected-im-db": {
				Secret:    ctrlcommon.DatastoreEDBSecretName,
				Configmap: ctrlcommon.DatastoreEDBCMName,
			},
		},
	})
	return
}

// addEmbeddedEDBIfNeeded appends the common-service-postgresql Operand to the list of Operands when the IM install is
// configured to use an embedded EDB. If there is an error while trying to obtain the relevant IM configuration for EDB,
// it will skip adding the Operand and return the encountered error.
func (r *AuthenticationReconciler) addEmbeddedEDBIfNeeded(ctx context.Context, authCR *operatorv1alpha1.Authentication,
	operands *[]operatorv1alpha1.Operand) (err error) {
	var usingExternal bool
	if usingExternal, err = r.isConfiguredForExternalDB(ctx, authCR); err != nil || usingExternal {
		return
	}
	name := "common-service-postgresql"
	*operands = append(*operands, operatorv1alpha1.Operand{
		Name: name,
		Bindings: map[string]operatorv1alpha1.Bindable{
			"protected-im-db": {
				Secret:    ctrlcommon.DatastoreEDBSecretName,
				Configmap: ctrlcommon.DatastoreEDBCMName,
			},
		},
	})
	return
}

// handleOperandRequest manages the OperandRequest for database operands. For backward compatibility,
// it uses "ibm-iam-request" if it already exists, otherwise creates "im-needs-database".
// The UI Operator is now managed by a separate OperandRequest (im-needs-ui).
func (r *AuthenticationReconciler) handleDatabaseOperandRequest(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	opReqName := "im-needs-database"
	log := logf.FromContext(ctx, "OperandRequest.Name", opReqName)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure OperandRequest is present when supported by cluster and contains correct Operands")

	if !ctrlcommon.ClusterHasOperandRequestAPIResource(&r.DiscoveryClient) {
		log.Info("The OperandRequest API resource is not supported by this cluster; assuming EDB connection will be configured manually", "Secret", ctrlcommon.DatastoreEDBSecretName, "ConfigMap", ctrlcommon.DatastoreEDBCMName, "Namespace", req.Namespace)
		return subreconciler.ContinueReconciling()
	}

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	desiredOperands := []operatorv1alpha1.Operand{}

	if err = r.addEmbeddedDBIfNeeded(debugCtx, authCR, &desiredOperands); err != nil {
		log.Error(err, "Unexpected error was encountered while attempting to determine whether IBM PG needed")
		return subreconciler.RequeueWithError(err)
	}

	observedOpReq := &operatorv1alpha1.OperandRequest{}
	err = r.Get(debugCtx, types.NamespacedName{Name: opReqName, Namespace: authCR.Namespace}, observedOpReq)

	if k8sErrors.IsNotFound(err) {
		debugLog.Info("OperandRequest not found, creating")
		desiredRequests := []operatorv1alpha1.Request{
			{Registry: "common-service", RegistryNamespace: authCR.Namespace, Operands: desiredOperands},
		}

		desiredOperandSpec := operatorv1alpha1.OperandRequestSpec{
			Requests: desiredRequests,
		}

		desiredObjectMeta := metav1.ObjectMeta{
			Name:      opReqName,
			Namespace: authCR.Namespace,
		}

		desiredOpReq := &operatorv1alpha1.OperandRequest{
			ObjectMeta: desiredObjectMeta,
			Spec:       desiredOperandSpec,
		}

		if err = controllerutil.SetControllerReference(authCR, desiredOpReq, r.Scheme); err != nil {
			log.Error(err, "Failed to set controller reference on OperandRequest")
			return subreconciler.RequeueWithError(err)
		}

		if err = r.Create(debugCtx, desiredOpReq); k8sErrors.IsAlreadyExists(err) {
			log.Info("OperandRequest already exists; continuing")
			return subreconciler.ContinueReconciling()
		} else if err != nil {
			log.Error(err, "Failed to create OperandRequest")
			return subreconciler.RequeueWithError(err)
		}

		log.Info("Created OperandRequest")
		return subreconciler.RequeueWithDelay(opreqWait)
	} else if err != nil {
		log.Error(err, "Failed to get OperandRequest")
		return subreconciler.RequeueWithError(err)
	}

	changed := false

	if len(observedOpReq.Spec.Requests) == 0 {
		observedOpReq.Spec.Requests = []operatorv1alpha1.Request{
			{Registry: "common-service", RegistryNamespace: authCR.Namespace, Operands: desiredOperands},
		}
		changed = true
	} else {
		observedOperands := observedOpReq.Spec.Requests[0].Operands

		log.Info("List Operands", "observedOperands", observedOperands, "desiredOperands", desiredOperands)
		if !operandsAreEqual(observedOperands, desiredOperands) {
			debugLog.Info("Operands are different, set to desired")
			observedOpReq.Spec.Requests[0].Operands = desiredOperands
			changed = true
		}

		if observedOpReq.Spec.Requests[0].RegistryNamespace != authCR.Namespace {
			observedOpReq.Spec.Requests[0].RegistryNamespace = authCR.Namespace
			changed = true
		}
	}

	if !changed {
		log.Info("No changes to OperandRequest; continue")
		return subreconciler.ContinueReconciling()
	}

	if err = controllerutil.SetControllerReference(authCR, observedOpReq, r.Scheme); err != nil {
		log.Error(err, "Failed to set controller reference on OperandRequest")
		return subreconciler.RequeueWithError(err)
	}
	if err = r.Update(debugCtx, observedOpReq); err != nil {
		log.Error(err, "Failed to update OperandRequest")
		return subreconciler.RequeueWithError(err)
	}
	log.Info("Updated OperandRequest successfully")
	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

// operandsAreEqual compares two lists of Operands and returns whether the lists contain the same elements.
func operandsAreEqual(operandsA, operandsB []operatorv1alpha1.Operand) bool {
	if len(operandsA) != len(operandsB) {
		return false
	}
	for _, a := range operandsA {
		found := false
		for _, b := range operandsB {
			if reflect.DeepEqual(a, b) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// configuredForExternalDB returns whether an Authentication is configured for connecting to an external EDB.
// This is determined by obtaining the `im-datastore-edb-cm` ConfigMap and reading its `IS_EMBEDDED` field.
// If this value is set to "false", then the IM instance needs to use the connection details contained within this
// ConfigMap.
func (r *AuthenticationReconciler) isConfiguredForExternalDB(ctx context.Context, authCR *operatorv1alpha1.Authentication) (isConfigured bool, err error) {
	// stubbed until external EDB is supported
	log := logf.FromContext(ctx)
	cm := &corev1.ConfigMap{}

	err = r.Get(ctx, types.NamespacedName{Name: ctrlcommon.DatastoreEDBCMName, Namespace: authCR.Namespace}, cm)
	if err != nil && k8sErrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		log.Error(err, "Failed to get ConfigMap from services namespace", "name", ctrlcommon.DatastoreEDBCMName)
		return false, err
	}

	return cm.Data["IS_EMBEDDED"] == "false", nil
}

// needsExternalEDB returns whether the IM install needs an external EDB configured.
func (r *AuthenticationReconciler) needsExternalEDB(ctx context.Context, authCR *operatorv1alpha1.Authentication) (needsExternal bool, err error) {
	if !ctrlcommon.ClusterHasOperandRequestAPIResource(&r.DiscoveryClient) {
		return true, nil
	}
	isConfiguredForExternal, err := r.isConfiguredForExternalDB(ctx, authCR)
	return isConfiguredForExternal, err
}

func isIBMMongoDBOperator(name string) bool {
	const earlierMongoDBOperatorName string = "ibm-mongodb-operator"
	const newerMongoDBOperatorName string = "ibm-im-mongodb-operator"
	return name == earlierMongoDBOperatorName || name == newerMongoDBOperatorName
}

func getMongoDBOperandFromOpReq(opReq *operatorv1alpha1.OperandRequest) *operatorv1alpha1.Operand {
	if len(opReq.Spec.Requests) == 0 {
		return nil
	}
	for _, request := range opReq.Spec.Requests {
		if request.Registry != "common-service" {
			continue
		}
		o := getMongoDBOperandFromOperands(request.Operands)
		if o != nil {
			return o
		}
	}
	return nil
}

func getMongoDBOperandFromOperands(operands []operatorv1alpha1.Operand) *operatorv1alpha1.Operand {
	for _, operand := range operands {
		if isIBMMongoDBOperator(operand.Name) {
			return &operand
		}
	}
	return nil
}

func hasMongoDBOperandFromOperands(operands []operatorv1alpha1.Operand) bool {
	return getMongoDBOperandFromOperands(operands) != nil
}

// createEDBShareClaim requests a share of the embedded EDB Common Service via the creation of a CommonService object.
func (r *AuthenticationReconciler) createEDBShareClaim(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	csCRName := "im-common-service"
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Create a CommonService CR for shared EDB claim")

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	if needsExternal, err := r.needsExternalEDB(debugCtx, authCR); err == nil && needsExternal {
		log.Info("External EDB configuration details to be set up; skipping creation of CommonService CR for EDB share")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		log.Error(err, "Unexpected error occurred while trying to determine whether external EDB is to be configured")
		return subreconciler.RequeueWithError(err)
	}

	log = log.WithValues("CommonService.Name", csCRName)
	unstructuredCS := map[string]any{
		"kind":       "CommonService",
		"apiVersion": "operator.ibm.com/v3",
		"metadata": map[string]any{
			"name":      csCRName,
			"namespace": authCR.Namespace,
		},
		"spec": map[string]any{
			"sharedDBServices": "IM",
		},
	}
	unstructuredObj := &unstructured.Unstructured{Object: unstructuredCS}
	if err = controllerutil.SetControllerReference(authCR, unstructuredObj, r.Client.Scheme()); err != nil {
		log.Error(err, "Failed to set owner for ConfigMap")
		return subreconciler.RequeueWithError(err)
	}

	if err = r.Create(ctx, unstructuredObj); k8sErrors.IsAlreadyExists(err) {
		// CommonService already exists from a previous reconcile
		log.Info("CommonService CR for shared EDB claim already exists")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		log.Error(err, "Failed to create CommonService CR for shared EDB claim")
		return subreconciler.RequeueWithError(err)
	}
	log.Info("Created CommonService CR for shared EDB claim successfully")
	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

// handleEDBToIBMPGMigration orchestrates the migration from EDB to IBM PG
// This should be called before ensureMigrationJobRuns as it handles the database
// service migration, which is distinct from data migration between running services.
func (r *AuthenticationReconciler) handleEDBToIBMPGMigration(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Checking if EDB to IBM PG migration is needed")

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	if needsExternal, err := r.needsExternalEDB(debugCtx, authCR); err == nil && needsExternal {
		log.Info("Configured to connect to external database; skipping migration check")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		log.Error(err, "Unexpected error occurred while trying to determine whether external EDB is to be configured")
		return subreconciler.RequeueWithError(err)
	}

	if !ctrlcommon.ClusterHasOperandRequestAPIResource(&r.DiscoveryClient) {
		log.Info("The OperandRequest API resource is not supported by this cluster; skipping migration")
		return subreconciler.ContinueReconciling()
	}

	// Check if legacy OperandRequest exists
	legacyOpReqName := "ibm-iam-request"
	newOpReqName := "im-needs-database"

	legacyOpReq := &operatorv1alpha1.OperandRequest{}
	if err = r.Get(debugCtx, types.NamespacedName{Name: legacyOpReqName, Namespace: authCR.Namespace}, legacyOpReq); k8sErrors.IsNotFound(err) {
		log.Info("EDB operand not present in legacy OperandRequest; migration not needed")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		log.Error(err, "Failed to check for legacy OperandRequest")
		return subreconciler.RequeueWithError(err)
	}

	log.Info("Found legacy OperandRequest; checking migration status")

	// Get or create the new OperandRequest for migration operands
	newOpReq := &operatorv1alpha1.OperandRequest{}
	if err = r.Get(debugCtx, types.NamespacedName{Name: newOpReqName, Namespace: authCR.Namespace}, newOpReq); err == nil {
		log.Info("Database OperandRequest exists; continuing", "OperandRequest.Name", newOpReqName)
		return subreconciler.ContinueReconciling()
	} else if err != nil && !k8sErrors.IsNotFound(err) {
		log.Error(err, "Failed to get new OperandRequest")
		return subreconciler.RequeueWithError(err)
	}

	// Check migration state in new OperandRequest
	hasMigrator := false
	if len(legacyOpReq.Spec.Requests) == 0 {
		err = fmt.Errorf("failed to locate migrator request: OperandRequest %s does not have at least one entry in .spec.requests", legacyOpReqName)
		return subreconciler.RequeueWithError(err)
	}

	for _, operand := range legacyOpReq.Spec.Requests[0].Operands {
		if operand.Name == "common-service-pg-migrator" {
			hasMigrator = true
		}
	}

	log.Info("Migration state", "hasMigrator", hasMigrator)

	// Verify EDB Cluster CR is present and healthy
	if !hasMigrator {
		log.Info("Verifying EDB Cluster is healthy")
		if result, err = r.checkEDBClusterHealth(debugCtx, authCR.Namespace); subreconciler.ShouldHaltOrRequeue(result, err) {
			return
		}

		// Create/update im-needs-database with common-service-pg-migrator
		log.Info("Adding common-service-pg-migrator to ibm-iam-request OperandRequest")
		legacyOpReq.Spec.Requests[0].Operands = append(legacyOpReq.Spec.Requests[0].Operands, operatorv1alpha1.Operand{
			Name: "common-service-pg-migrator",
		})

		// Create new OperandRequest with migrator
		if err = r.Update(debugCtx, legacyOpReq); err != nil {
			log.Error(err, "Failed to update legacy OperandRequest with migrator")
			return subreconciler.RequeueWithError(err)
		}
		log.Info("Added common-service-pg-migrator to ibm-iam-request OperandRequest")
		return subreconciler.RequeueWithDelay(30 * time.Second)
	}

	log.Info("Waiting for migration job to complete")
	if result, err = r.checkMigrationJobComplete(debugCtx, authCR.Namespace); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	// Wait for IBM PG Cluster to be ready
	log.Info("Waiting for IBM PG Cluster to be ready")
	if result, err = r.checkIBMPGClusterHealth(debugCtx, authCR.Namespace); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	log.Info("Data successfully migrated to IBM PG Cluster")
	return subreconciler.ContinueReconciling()
}

// checkEDBClusterHealth verifies that the EDB Cluster CR is present and in healthy state
func (r *AuthenticationReconciler) checkEDBClusterHealth(ctx context.Context, namespace string) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)

	edbClusterAPIVersion := "postgresql.k8s.enterprisedb.io/v1"
	u := &unstructured.Unstructured{
		Object: map[string]any{
			"kind":       "Cluster",
			"apiVersion": edbClusterAPIVersion,
		},
	}

	if err = r.Get(ctx, types.NamespacedName{Name: "common-service-db", Namespace: namespace}, u); k8sErrors.IsNotFound(err) {
		log.Info("EDB Cluster not found; waiting for it to be created")
		return subreconciler.RequeueWithDelay(30 * time.Second)
	} else if err != nil {
		log.Error(err, "Failed to get EDB Cluster")
		return subreconciler.RequeueWithError(err)
	}

	// Check cluster status
	type cluster struct {
		metav1.ObjectMeta
		metav1.TypeMeta
		Status struct {
			Instances      int                `json:"instances,omitempty"`
			ReadyInstances int                `json:"readyInstances,omitempty"`
			Phase          string             `json:"phase,omitempty"`
			Conditions     []metav1.Condition `json:"conditions,omitempty"`
		} `json:"status"`
	}

	obj := &cluster{}
	var objJSON []byte
	if objJSON, err = u.MarshalJSON(); err != nil {
		log.Error(err, "Failed to marshal EDB Cluster")
		return subreconciler.RequeueWithError(err)
	}
	if err = json.Unmarshal(objJSON, obj); err != nil {
		log.Error(err, "Failed to unmarshal EDB Cluster status")
		return subreconciler.RequeueWithError(err)
	}

	// Check if cluster is ready using conditions or phase
	isReady := false
	if obj.Status.Conditions != nil && meta.IsStatusConditionPresentAndEqual(obj.Status.Conditions, "Ready", metav1.ConditionTrue) {
		isReady = true
	} else if obj.Status.Phase == "Cluster in healthy state" && obj.Status.ReadyInstances == obj.Status.Instances && obj.Status.Instances > 0 {
		isReady = true
	}

	if isReady {
		log.Info("IBM PG Cluster is healthy", "instances", obj.Status.Instances, "readyInstances", obj.Status.ReadyInstances)
		return subreconciler.ContinueReconciling()
	}

	log.Info("EDB Cluster not yet healthy; waiting", "phase", obj.Status.Phase, "instances", obj.Status.Instances, "readyInstances", obj.Status.ReadyInstances)
	return subreconciler.RequeueWithDelay(30 * time.Second)
}

// checkMigrationJobComplete verifies that the migration job has completed successfully
func (r *AuthenticationReconciler) checkMigrationJobComplete(ctx context.Context, namespace string) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)

	jobName := "common-service-db-pg-migration-job"
	u := &unstructured.Unstructured{
		Object: map[string]any{
			"kind":       "Job",
			"apiVersion": "batch/v1",
		},
	}

	if err = r.Get(ctx, types.NamespacedName{Name: jobName, Namespace: namespace}, u); k8sErrors.IsNotFound(err) {
		log.Info("Migration job not found; waiting for it to be created")
		return subreconciler.RequeueWithDelay(30 * time.Second)
	} else if err != nil {
		log.Error(err, "Failed to get migration job")
		return subreconciler.RequeueWithError(err)
	}

	// Check job status
	type job struct {
		metav1.ObjectMeta
		metav1.TypeMeta
		Status struct {
			Succeeded int `json:"succeeded,omitempty"`
			Failed    int `json:"failed,omitempty"`
		} `json:"status"`
	}

	obj := &job{}
	var objJSON []byte
	if objJSON, err = u.MarshalJSON(); err != nil {
		log.Error(err, "Failed to marshal migration job")
		return subreconciler.RequeueWithError(err)
	}
	if err = json.Unmarshal(objJSON, obj); err != nil {
		log.Error(err, "Failed to unmarshal migration job status")
		return subreconciler.RequeueWithError(err)
	}

	if obj.Status.Succeeded > 0 {
		log.Info("Migration job completed successfully")
		return subreconciler.ContinueReconciling()
	}

	if obj.Status.Failed > 0 {
		log.Error(fmt.Errorf("migration job failed"), "Migration job failed")
		return subreconciler.RequeueWithError(fmt.Errorf("migration job failed"))
	}

	log.Info("Migration job still running; waiting")
	return subreconciler.RequeueWithDelay(30 * time.Second)
}

// checkIBMPGClusterHealth verifies that the IBM PG Cluster CR is present and in healthy state
func (r *AuthenticationReconciler) checkIBMPGClusterHealth(ctx context.Context, namespace string) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)

	ibmPGClusterAPIVersion := "pg.ibm.com/v1"
	u := &unstructured.Unstructured{
		Object: map[string]any{
			"kind":       "Cluster",
			"apiVersion": ibmPGClusterAPIVersion,
		},
	}

	if err = r.Get(ctx, types.NamespacedName{Name: "common-service-db", Namespace: namespace}, u); k8sErrors.IsNotFound(err) {
		log.Info("IBM PG Cluster not found; waiting for it to be created")
		return subreconciler.RequeueWithDelay(30 * time.Second)
	} else if err != nil {
		log.Error(err, "Failed to get IBM PG Cluster")
		return subreconciler.RequeueWithError(err)
	}

	// Check cluster status
	type cluster struct {
		metav1.ObjectMeta
		metav1.TypeMeta
		Status struct {
			Instances      int                `json:"instances,omitempty"`
			ReadyInstances int                `json:"readyInstances,omitempty"`
			Phase          string             `json:"phase,omitempty"`
			Conditions     []metav1.Condition `json:"conditions,omitempty"`
		} `json:"status"`
	}

	obj := &cluster{}
	var objJSON []byte
	if objJSON, err = u.MarshalJSON(); err != nil {
		log.Error(err, "Failed to marshal IBM PG Cluster")
		return subreconciler.RequeueWithError(err)
	}
	if err = json.Unmarshal(objJSON, obj); err != nil {
		log.Error(err, "Failed to unmarshal IBM PG Cluster status")
		return subreconciler.RequeueWithError(err)
	}

	// Check if cluster is ready using conditions or phase
	isReady := false
	if obj.Status.Conditions != nil && meta.IsStatusConditionPresentAndEqual(obj.Status.Conditions, "Ready", metav1.ConditionTrue) {
		isReady = true
	} else if obj.Status.Phase == "Cluster in healthy state" && obj.Status.ReadyInstances == obj.Status.Instances && obj.Status.Instances > 0 {
		isReady = true
	}

	if isReady {
		log.Info("IBM PG Cluster is healthy", "instances", obj.Status.Instances, "readyInstances", obj.Status.ReadyInstances)
		return subreconciler.ContinueReconciling()
	}

	log.Info("IBM PG Cluster not yet healthy; waiting", "phase", obj.Status.Phase, "instances", obj.Status.Instances, "readyInstances", obj.Status.ReadyInstances)
	return subreconciler.RequeueWithDelay(30 * time.Second)
}

func (r *AuthenticationReconciler) ensureCommonServiceDBIsReady(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure Cluster is present and available before connecting")

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	// Skip if cluster doesn't support OperandRequest API
	if !ctrlcommon.ClusterHasOperandRequestAPIResource(&r.DiscoveryClient) {
		log.Info("The OperandRequest API resource is not supported by this cluster; skipping wait")
		return subreconciler.ContinueReconciling()
	}

	if needsExternal, err := r.needsExternalEDB(debugCtx, authCR); err == nil && needsExternal {
		log.Info("Configured to connect to external database; skipping this check")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		log.Error(err, "Unexpected error occurred while trying to determine whether external EDB is to be configured")
		return subreconciler.RequeueWithError(err)
	}

	opReqName := "im-needs-database"
	// Get the OperandRequest
	opReq := &operatorv1alpha1.OperandRequest{}
	if err = r.Get(debugCtx, types.NamespacedName{Name: opReqName, Namespace: authCR.Namespace}, opReq); k8sErrors.IsNotFound(err) {
		log.Info("Database OperandRequest not found; waiting for it to be created")
		return subreconciler.RequeueWithDelay(30 * time.Second)
	} else if err != nil {
		log.Error(err, "Failed to get database OperandRequest")
		return subreconciler.RequeueWithError(err)
	}

	// Check if OperandRequest has reached Running phase
	if opReq.Status.Phase != operatorv1alpha1.ClusterPhaseRunning {
		log.Info("Database OperandRequest not yet in Running phase; waiting",
			"currentPhase", opReq.Status.Phase,
			"desiredPhase", operatorv1alpha1.ClusterPhaseRunning)
		return subreconciler.RequeueWithDelay(30 * time.Second)
	}

	log.Info("Database OperandRequest is in Running phase")

	// Log current phase and requeue
	return r.checkIBMPGClusterHealth(debugCtx, req.Namespace)
}

// handleUIOperandRequest manages the UI OperandRequest using a SecondaryReconciler
func (r *AuthenticationReconciler) handleUIOperandRequest(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)
	log.Info("Ensure UI OperandRequest is present when supported by cluster")

	if !ctrlcommon.ClusterHasOperandRequestAPIResource(&r.DiscoveryClient) {
		log.Info("The OperandRequest API resource is not supported by this cluster; skipping UI OperandRequest creation")
		return subreconciler.ContinueReconciling()
	}

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	if !authCR.Status.Service.DeploymentsReady() {
		log.Info("IM Deployments are not Ready yet; requeueing")
		return subreconciler.RequeueWithDelay(10 * time.Second)
	}

	if result, err = r.getUIOperandRequestSubreconciler(authCR).Reconcile(debugCtx); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	legacyOpReq := &operatorv1alpha1.OperandRequest{}
	if err = r.Get(debugCtx, types.NamespacedName{Name: "ibm-iam-request", Namespace: authCR.Namespace}, legacyOpReq); k8sErrors.IsNotFound(err) {
		log.Info("No legacy OperandRequest to remove; continuing")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		log.Error(err, "Failed to get legacy OperandRequest")
		return subreconciler.RequeueWithError(err)
	}

	log.Info("Found legacy OperandRequest ibm-iam-request; removing if current OperandRequests running")

	uiOpReqName := "im-needs-ui"
	// Get the OperandRequest
	uiOpReq := &operatorv1alpha1.OperandRequest{}
	if err = r.Get(debugCtx, types.NamespacedName{Name: uiOpReqName, Namespace: authCR.Namespace}, uiOpReq); k8sErrors.IsNotFound(err) {
		log.Info("UI OperandRequest not found; waiting for it to be created")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	} else if err != nil {
		log.Error(err, "Failed to get UI OperandRequest")
		return subreconciler.RequeueWithError(err)
	}

	// Check if OperandRequest has reached Running phase
	if uiOpReq.Status.Phase != operatorv1alpha1.ClusterPhaseRunning {
		log.Info("UI OperandRequest not yet in Running phase; waiting",
			"currentPhase", uiOpReq.Status.Phase,
			"desiredPhase", operatorv1alpha1.ClusterPhaseRunning)
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	log.Info("UI OperandRequest is in Running phase")

	usingExternalPostgres := false
	if usingExternalPostgres, err = r.needsExternalEDB(debugCtx, authCR); err != nil {
		log.Error(err, "Unexpected error occurred while trying to determine whether external EDB is to be configured")
		return subreconciler.RequeueWithError(err)
	}

	if !usingExternalPostgres {
		dbOpReqName := "im-needs-database"
		// Get the OperandRequest
		dbOpReq := &operatorv1alpha1.OperandRequest{}
		if err = r.Get(debugCtx, types.NamespacedName{Name: dbOpReqName, Namespace: authCR.Namespace}, dbOpReq); k8sErrors.IsNotFound(err) {
			log.Info("Database OperandRequest not found; waiting for it to be created")
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		} else if err != nil {
			log.Error(err, "Failed to get database OperandRequest")
			return subreconciler.RequeueWithError(err)
		}

		// Check if OperandRequest has reached Running phase
		if dbOpReq.Status.Phase != operatorv1alpha1.ClusterPhaseRunning {
			log.Info("Database OperandRequest not yet in Running phase; waiting",
				"currentPhase", dbOpReq.Status.Phase,
				"desiredPhase", operatorv1alpha1.ClusterPhaseRunning)
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		}

		log.Info("Database OperandRequest is in Running phase")
		log.Info("Confirm Cluster CR health before proceeding with legacy OperandRequest removal")
		if result, err = r.checkIBMPGClusterHealth(debugCtx, req.Namespace); subreconciler.ShouldHaltOrRequeue(result, err) {
			return
		}
	} else {
		log.Info("Using external Postgres; skipping check for OperandRequest im-needs-database")
	}

	log.Info("Removing legacy OperandRequest", "OperandRequest.Name", legacyOpReq.Name)

	if err = r.Delete(debugCtx, legacyOpReq); err != nil && !k8sErrors.IsNotFound(err) {
		log.Error(err, "Failed to delete legacy OperandRequest")
		return subreconciler.RequeueWithError(err)
	}

	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

// getUIOperandRequestSubreconciler creates a subreconciler for managing the UI OperandRequest
func (r *AuthenticationReconciler) getUIOperandRequestSubreconciler(authCR *operatorv1alpha1.Authentication) (subRec ctrlcommon.Subreconciler) {
	return ctrlcommon.NewSecondaryReconcilerBuilder[*operatorv1alpha1.OperandRequest]().
		WithName("im-needs-ui").
		WithGenerateFns(generateUIOperandRequest).
		WithClient(r.Client).
		WithNamespace(authCR.Namespace).
		WithPrimary(authCR).MustBuild()
}

// generateUIOperandRequest creates the OperandRequest for the UI operator
func generateUIOperandRequest(s ctrlcommon.SecondaryReconciler, ctx context.Context, opReq *operatorv1alpha1.OperandRequest) error {
	log := logf.FromContext(ctx)

	primary := s.GetPrimary()
	authCR, ok := primary.(*operatorv1alpha1.Authentication)
	if !ok {
		log.Error(nil, "Primary is not an Authentication CR")
		return fmt.Errorf("primary is not an Authentication CR")
	}

	opReq.SetName(s.GetName())
	opReq.SetNamespace(s.GetNamespace())

	desiredOperands := []operatorv1alpha1.Operand{
		{Name: "ibm-idp-config-ui-operator"},
	}

	desiredRequests := []operatorv1alpha1.Request{
		{
			Registry:          "common-service",
			RegistryNamespace: authCR.Namespace,
			Operands:          desiredOperands,
		},
	}

	opReq.Spec = operatorv1alpha1.OperandRequestSpec{
		Requests: desiredRequests,
	}

	if err := controllerutil.SetControllerReference(authCR, opReq, s.GetClient().Scheme()); err != nil {
		log.Error(err, "Failed to set controller reference on OperandRequest")
		return err
	}

	return nil
}
