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
	"reflect"
	"strings"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	ctrlCommon "github.com/IBM/ibm-iam-operator/controllers/common"
	"github.com/opdev/subreconciler"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
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
					Secret:    ctrlCommon.DatastoreEDBSecretName,
					Configmap: ctrlCommon.DatastoreEDBCMName,
				},
			},
		})
	}
	return
}

// handleOperandRequest manages the ibm-iam-request OperandRequest and adds or removes Operand entries from it depending
// upon what the IM install needs. At a minimum, the UI Operator is included.
func (r *AuthenticationReconciler) handleOperandRequest(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "handleOperandRequest")

	opReqName := "ibm-iam-request"

	reqLogger.Info("Ensure that OperandRequest is updated with correct Operands", "OperandRequestName", opReqName)
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	desiredOperands := []operatorv1alpha1.Operand{
		{Name: "ibm-idp-config-ui-operator"},
	}

	if err = r.addEmbeddedEDBIfNeeded(ctx, authCR, &desiredOperands); err != nil {
		return subreconciler.RequeueWithError(err)
	}

	observedOpReq := &operatorv1alpha1.OperandRequest{}
	err = r.Get(ctx, types.NamespacedName{Name: opReqName, Namespace: authCR.Namespace}, observedOpReq)

	if k8sErrors.IsNotFound(err) {
		if r.needToMigrateMongoDB(ctx, authCR) {
			desiredOperands = append(desiredOperands, operatorv1alpha1.Operand{Name: "ibm-im-mongodb-operator"})
		}

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

		if err = r.Create(ctx, desiredOpReq); k8sErrors.IsAlreadyExists(err) {
			reqLogger.Info("OperandRequest already exists", "OperandRequestName", opReqName)
		} else if err != nil {
			reqLogger.Error(err, "Failed to create OperandRequest", "OperandRequestName", opReqName)
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("Created OperandRequest", "OperandRequestName", opReqName)
		return subreconciler.Requeue()
	} else if err != nil {
		reqLogger.Error(err, "Failed to get OperandRequest", "OperandRequestName", opReqName)
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
	observedMongoDBOperand := getMongoDBOperatorOperand(observedOpReq)

	if r.needToPreserveMongoDBInOpReq(ctx, authCR) {
		if observedMongoDBOperand != nil {
			desiredOperands = append(desiredOperands, *observedMongoDBOperand)
		}
	}

	if !operandsAreEqual(observedOperands, desiredOperands) {
		observedOpReq.Spec.Requests[0].Operands = desiredOperands
		changed = true
	}

	if observedOpReq.Spec.Requests[0].RegistryNamespace != authCR.Namespace {
		observedOpReq.Spec.Requests[0].RegistryNamespace = authCR.Namespace
		changed = true
	}

	if changed {
		if err = controllerutil.SetOwnerReference(authCR, observedOpReq, r.Scheme); err != nil {
			reqLogger.Error(err, "Failed to set owner reference on OperandRequest", "OperandRequestName", opReqName)
			return subreconciler.RequeueWithError(err)
		}
		if err = r.Update(ctx, observedOpReq); err != nil {
			reqLogger.Error(err, "Failed to update OperandRequest", "OperandRequestName", opReqName)
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("Updated OperandRequest successfully", "OperandRequestName", opReqName)
		return subreconciler.Requeue()
	}

	reqLogger.Info("No changes to OperandRequest; continue", "OperandRequestName", opReqName)
	return subreconciler.ContinueReconciling()
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
	reqLogger := logf.FromContext(ctx)
	cm := &corev1.ConfigMap{}

	err = r.Get(ctx, types.NamespacedName{Name: ctrlCommon.DatastoreEDBCMName, Namespace: authCR.Namespace}, cm)
	if err != nil && k8sErrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get ConfigMap from services namespace", "name", ctrlCommon.DatastoreEDBCMName)
		return false, err
	}

	return cm.Data["IS_EMBEDDED"] == "false", nil
}

// needsEmbeddedEDB is the inverse of isConfiguredForExternalEDB, save for passthrough of any error encountered that is
// not an IsNotFound.
func (r *AuthenticationReconciler) needsEmbeddedEDB(ctx context.Context, authCR *operatorv1alpha1.Authentication) (needsEmbedded bool, err error) {
	isConfiguredForExternal, err := r.isConfiguredForExternalEDB(ctx, authCR)
	return !isConfiguredForExternal, err
}

func (r *AuthenticationReconciler) servicesNamespaceHasMongoDBService(ctx context.Context, authCR *operatorv1alpha1.Authentication) bool {
	reqLogger := logf.FromContext(ctx)
	service := &corev1.Service{}
	mongoDBServiceName := "mongodb"
	err := r.Get(ctx, types.NamespacedName{Name: mongoDBServiceName, Namespace: authCR.Namespace}, service)
	if err != nil {
		reqLogger.Error(err, "Failed to get MongoDB Service")
		return false
	}

	return true
}

func isIBMMongoDBOperator(name string) bool {
	return strings.HasPrefix(name, "ibm-") && strings.HasSuffix(name, "-mongodb-operator")
}

// needToMigrateMongoDB indicates whether the reconciler should prepare for migrating data from MongoDB
func (r *AuthenticationReconciler) needToMigrateMongoDB(ctx context.Context, authCR *operatorv1alpha1.Authentication) bool {
	return authCR.HasNotBeenMigrated() && r.servicesNamespaceHasMongoDBService(ctx, authCR)
}

// needToPreserveMongoDBInOpReq indicates whether the reconciler should keep the requirement for MongoDB in its
// OperandRequest
func (r *AuthenticationReconciler) needToPreserveMongoDBInOpReq(ctx context.Context, authCR *operatorv1alpha1.Authentication) bool {
	return r.needToMigrateMongoDB(ctx, authCR) || authCR.IsRetainingArtifacts()
}

func getOperandByName(opReq *operatorv1alpha1.OperandRequest, name string) *operatorv1alpha1.Operand {
	if len(opReq.Spec.Requests) == 0 {
		return nil
	}
	for _, request := range opReq.Spec.Requests {
		if request.Registry != "common-service" {
			continue
		}
		for _, operand := range request.Operands {
			if operand.Name == name {
				return &operand
			}
		}
	}
	return nil
}

func getMongoDBOperatorOperand(opReq *operatorv1alpha1.OperandRequest) *operatorv1alpha1.Operand {
	if len(opReq.Spec.Requests) == 0 {
		return nil
	}
	for _, request := range opReq.Spec.Requests {
		if request.Registry != "common-service" {
			continue
		}
		for _, operand := range request.Operands {
			if isIBMMongoDBOperator(operand.Name) {
				return &operand
			}
		}
	}
	return nil
}

// createEDBShareClaim requests a share of the embedded EDB Common Service via the creation of a CommonService object.
func (r *AuthenticationReconciler) createEDBShareClaim(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := log.WithValues("Instance.Namespace", req.Namespace, "Instance.Name", req.Name)
	reqLogger.Info("Create a CommonService CR for shared EDB claim")

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	if usingExternal, err := r.isConfiguredForExternalEDB(ctx, authCR); err == nil && usingExternal {
		reqLogger.Info("Configured for connecting external EDB; skipping CommonService CR creation")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		return subreconciler.RequeueWithError(err)
	}

	csCRName := "im-common-service"
	unstructuredCS := map[string]interface{}{
		"kind":       "CommonService",
		"apiVersion": "operator.ibm.com/v3",
		"metadata": map[string]interface{}{
			"name":      csCRName,
			"namespace": authCR.Namespace,
		},
		"spec": map[string]interface{}{
			"sharedDBServices": "IM",
		},
	}
	unstructuredObj := &unstructured.Unstructured{Object: unstructuredCS}

	if err = r.Create(context.TODO(), unstructuredObj); k8sErrors.IsAlreadyExists(err) {
		// CommonService already exists from a previous reconcile
		reqLogger.Info("CommonService CR for shared EDB claim already exists", "CommonServiceName", csCRName)
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		reqLogger.Error(err, "Failed to create CommonService CR for shared EDB claim", "CommonServiceName", csCRName)
		return subreconciler.RequeueWithError(err)
	}
	reqLogger.Info("Created CommonService CR for shared EDB claim successfully")
	return subreconciler.Requeue()
}
