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

// addEmbeddedEDBIfNeeded appends the common-service-postgresql Operand to the list of Operands when the IM install is
// configured to use an embedded EDB. If there is an error while trying to obtain the relevant IM configuration for EDB,
// it will skip adding the Operand and return the encountered error.
func (r *AuthenticationReconciler) addEmbeddedEDBIfNeeded(ctx context.Context, authCR *operatorv1alpha1.Authentication,
	operands *[]operatorv1alpha1.Operand) (err error) {
	var usingExternal bool
	if usingExternal, err = r.isConfiguredForExternalEDB(ctx, authCR); err == nil && !usingExternal {
		*operands = append(*operands, operatorv1alpha1.Operand{
			Name: "common-service-postgresql",
			Bindings: map[string]operatorv1alpha1.Bindable{
				"protected-im-db": {
					Secret:    ctrlcommon.DatastoreEDBSecretName,
					Configmap: ctrlcommon.DatastoreEDBCMName,
				},
			},
		})
	}
	return
}

// handleOperandRequest manages the ibm-iam-request OperandRequest and adds or removes Operand entries from it depending
// upon what the IM install needs. At a minimum, the UI Operator is included.
func (r *AuthenticationReconciler) handleOperandRequest(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	opReqName := "ibm-iam-request"
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure OperandRequest is present when supported by cluster and contains correct Operands")

	log = logf.FromContext(ctx, "OperandRequest.Name", opReqName)
	if !ctrlcommon.ClusterHasOperandRequestAPIResource(&r.DiscoveryClient) {
		log.Info("The OperandRequest API resource is not supported by this cluster; assuming EDB connection will be configured manually", "Secret", ctrlcommon.DatastoreEDBSecretName, "ConfigMap", ctrlcommon.DatastoreEDBCMName, "Namespace", req.Namespace)
		return subreconciler.ContinueReconciling()
	}

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	desiredOperands := []operatorv1alpha1.Operand{
		{Name: "ibm-idp-config-ui-operator"},
	}

	if err = r.addEmbeddedEDBIfNeeded(debugCtx, authCR, &desiredOperands); err != nil {
		log.Error(err, "Unexpected error was encountered while attempting to determine whether EDB needed")
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

		if err = controllerutil.SetOwnerReference(authCR, desiredOpReq, r.Scheme); err != nil {
			log.Error(err, "Failed to set owner reference on OperandRequest")
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
	// Previously, the IM Operator used a feature of ODLM to deploy a default Authentication CR that was defined in
	// its alm-examples on the CSV. Now that the Operator needs to be able to control the Operators it requires
	// during its runtime instead of between Operator installs or upgrades, it needs to remove the
	// operator.ibm.com/opreq-control label from the OperandRequest in order to signal that ODLM is no longer
	// controlling the contents of this OperandRequest.
	if _, ok := observedOpReq.Labels["operator.ibm.com/opreq-control"]; ok {
		delete(observedOpReq.Labels, "operator.ibm.com/opreq-control")
		changed = true
	}

	observedOperands := observedOpReq.Spec.Requests[0].Operands
	observedMongoDBOperand := getMongoDBOperandFromOpReq(observedOpReq)

	// If MongoDB is still needed, and observed OpReq has MongoDB, and the list of desired Operands does not have
	// MongoDB listed

	needToMigrate, err := mongoIsPresent(r.Client, debugCtx, authCR)
	if err != nil {
		log.Info("Failed to determine whether there is a need to migrate from MongoDB", "err", err.Error())
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	if needToMigrate && observedMongoDBOperand != nil &&
		!hasMongoDBOperandFromOperands(desiredOperands) {
		desiredOperands = append(desiredOperands, *observedMongoDBOperand)
	}

	log.V(1).Info("List Operands", "observedOperands", observedOperands, "desiredOperands", desiredOperands)
	if !operandsAreEqual(observedOperands, desiredOperands) {
		debugLog.Info("Operands are different, set to desired")
		observedOpReq.Spec.Requests[0].Operands = desiredOperands
		changed = true
	}

	if observedOpReq.Spec.Requests[0].RegistryNamespace != authCR.Namespace {
		observedOpReq.Spec.Requests[0].RegistryNamespace = authCR.Namespace
		changed = true
	}

	if !changed {
		log.Info("No changes to OperandRequest; continue")
		return subreconciler.ContinueReconciling()
	}

	if err = controllerutil.SetOwnerReference(authCR, observedOpReq, r.Scheme); err != nil {
		log.Error(err, "Failed to set owner reference on OperandRequest")
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

// configuredForExternalEDB returns whether an Authentication is configured for connecting to an external EDB.
// This is determined by obtaining the `im-datastore-edb-cm` ConfigMap and reading its `IS_EMBEDDED` field.
// If this value is set to "false", then the IM instance needs to use the connection details contained within this
// ConfigMap.
func (r *AuthenticationReconciler) isConfiguredForExternalEDB(ctx context.Context, authCR *operatorv1alpha1.Authentication) (isConfigured bool, err error) {
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
	isConfiguredForExternal, err := r.isConfiguredForExternalEDB(ctx, authCR)
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

func (r *AuthenticationReconciler) ensureCommonServiceDBIsReady(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure Cluster is present and available before connecting")

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	if needsExternal, err := r.needsExternalEDB(debugCtx, authCR); err == nil && needsExternal {
		log.Info("Configured to connect to external database; skipping this check")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		log.Error(err, "Unexpected error occurred while trying to determine whether external EDB is to be configured")
		return subreconciler.RequeueWithError(err)
	}

	log = log.WithValues("Object.Name", "common-service-db", "Object.Kind", "Cluster", "Object.APIVersion", "postgresql.k8s.enterprisedb.io/v1")

	u := &unstructured.Unstructured{
		Object: map[string]any{
			"kind":       "Cluster",
			"apiVersion": "postgresql.k8s.enterprisedb.io/v1",
		},
	}
	if err = r.Get(ctx, types.NamespacedName{Name: "common-service-db", Namespace: req.Namespace}, u); k8sErrors.IsNotFound(err) {
		log.Info("Cluster not found")
		return subreconciler.Requeue()
	} else if err != nil {
		log.Error(err, "Cluster could not be retrieved")
		return subreconciler.RequeueWithError(err)
	}
	type cluster struct {
		metav1.ObjectMeta
		metav1.TypeMeta
		Status struct {
			Conditions []metav1.Condition `json:"conditions,omitempty"`
		} `json:"status"`
	}
	obj := &cluster{}
	var objJSON []byte
	if objJSON, err = u.MarshalJSON(); err != nil {
		log.Error(err, "Failed to marshal unstructured Cluster into JSON")
		return subreconciler.RequeueWithError(err)
	}
	if err = json.Unmarshal(objJSON, obj); err != nil {
		log.Error(err, "Failed to unmarshal JSON into Cluster status")
		return subreconciler.RequeueWithError(err)
	}
	if obj.Status.Conditions != nil && meta.IsStatusConditionPresentAndEqual(obj.Status.Conditions, "Ready", metav1.ConditionTrue) {
		log.Info("Cluster is Ready")
		return subreconciler.ContinueReconciling()
	}
	log.Info("Cluster is not Ready")
	return subreconciler.RequeueWithDelay(30 * time.Second)
}
