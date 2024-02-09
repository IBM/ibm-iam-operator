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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/controllers/common"
	ctrlCommon "github.com/IBM/ibm-iam-operator/controllers/common"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
)

func (r *AuthenticationReconciler) checkforCSEDB(instance *operatorv1alpha1.Authentication, needToRequeue *bool) (err error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	edbConfiMapName := ctrlCommon.IMDatasourceCMName
	cfgmap, exists := r.checkIfConfigmapExists(instance, edbConfiMapName)

	if exists {
		// im-datastore-edb-cm exist, check if DB is embedded or not
		is_embedded := cfgmap.Data["IS_EMBEDDED"]
		reqLogger.Info("EMBEDDED: " + is_embedded)
		if is_embedded == "true" {
			// create operandrequst as well as commonservice CRs
			r.createOprReqAndCS(instance, needToRequeue)

		} else {
			reqLogger.Info("Embedded edb is FALSE, External Db is being used")
		}
	} else {
		// create operandrequst as well as commonservice CRs
		r.createOprReqAndCS(instance, needToRequeue)
	}

	return
}

func (r *AuthenticationReconciler) checkIfConfigmapExists(instance *operatorv1alpha1.Authentication, edbConfiMapName string) (configmap *corev1.ConfigMap, exist bool) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	csEDBConfigmap := &corev1.ConfigMap{}
	reqLogger.Info("Query CS EDB cm", "Configmap.Namespace", instance.Namespace, "ConfigMap.Name", edbConfiMapName)
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: edbConfiMapName, Namespace: instance.Namespace}, csEDBConfigmap)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("The configmap " + edbConfiMapName + " is not present")
			return nil, false
		}
		reqLogger.Info("Failed to get ConfigMap " + edbConfiMapName)
		return nil, false
	}
	reqLogger.Info("configmap " + edbConfiMapName + " is present")
	return csEDBConfigmap, true
}

func (r *AuthenticationReconciler) createOpendRequest(instance *operatorv1alpha1.Authentication) (err error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	reqLogger.Info("EDB:: inside operandrequest creation")

	// Define the YAML content as a map[string]interface{}
	yamlContent := map[string]interface{}{
		"kind":       "OperandRequest",
		"apiVersion": "operator.ibm.com/v1alpha1",
		"metadata": map[string]interface{}{
			"name":      ctrlCommon.IMEDBOprName,
			"namespace": instance.Namespace,
		},
		"spec": map[string]interface{}{
			"requests": []map[string]interface{}{
				{
					"operands": []map[string]interface{}{
						{
							"name": "common-service-postgresql",
							"bindings": map[string]interface{}{
								"protected-im-db": map[string]interface{}{
									"secret":    "im-datastore-edb-secret",
									"configmap": "im-datastore-edb-cm",
								},
							},
						},
					},
					"registry":          "common-service",
					"registryNamespace": instance.Namespace,
				},
			},
		},
	}

	// Create an Unstructured object from the YAML content
	unstructuredObj := &unstructured.Unstructured{Object: yamlContent}

	err = r.Client.Create(context.TODO(), unstructuredObj)
	if err != nil {
		if errors.IsAlreadyExists(err) {
			reqLogger.Info("OperandRequest" + ctrlCommon.IMEDBOprName + " already exists")
		} else {
			reqLogger.Error(err, "Error creating OperandRequest "+ctrlCommon.IMEDBOprName)
		}
		return err
	}
	return nil
}

// IM operator creates CommonService CR, to claim the usage on shared embedded database
func (r *AuthenticationReconciler) createCommonService(instance *operatorv1alpha1.Authentication) (err error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	// Define the YAML content as a map[string]interface{}
	yamlContent := map[string]interface{}{
		"kind":       "CommonService",
		"apiVersion": "operator.ibm.com/v3",
		"metadata": map[string]interface{}{
			"name":      ctrlCommon.IMEDBCSName,
			"namespace": instance.Namespace,
		},
		"spec": map[string]interface{}{
			"sharedDBServices": "IM",
		},
	}

	unstructuredObj := &unstructured.Unstructured{Object: yamlContent}
	err = r.Client.Create(context.TODO(), unstructuredObj)
	if err != nil {
		if errors.IsAlreadyExists(err) {
			// Route already exists from a previous reconcile
			reqLogger.Info("CommonService CR im-common-service already exists")
		} else {
			reqLogger.Error(err, "Error creating commonservice "+ctrlCommon.IMEDBCSName)
			return err
		}
	}
	return nil
}

func (r *AuthenticationReconciler) checkOperandRequestExists(instance *operatorv1alpha1.Authentication) (exist bool) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	reqLogger.Info("Query IM EDB OperandRequest", "OperandRequest.Namespace", instance.Namespace, "OperandRequest.Name", common.IMEDBOprName)

	key := types.NamespacedName{Name: ctrlCommon.IMEDBOprName, Namespace: instance.Namespace}

	gvk := schema.GroupVersionKind{
		Group:   "operator.ibm.com",
		Version: "v1alpha1",
		Kind:    "OperandRequest",
	}

	unstrCert := &unstructured.Unstructured{}
	unstrCert.SetGroupVersionKind(gvk)

	err := r.Client.Get(context.TODO(), key, unstrCert)

	if err != nil {
		if !errors.IsNotFound(err) {
			reqLogger.Info(ctrlCommon.IMEDBOprName + " OperandRequest Not Found")
			return false
		}
		reqLogger.Info("Failed to get OperandRequest " + ctrlCommon.IMEDBOprName)
		return false
	}
	reqLogger.Info("OperandRequest " + ctrlCommon.IMEDBOprName + " is present")

	return true
}

func (r *AuthenticationReconciler) checkCommonServiceExists(instance *operatorv1alpha1.Authentication) (exist bool) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	reqLogger.Info("Query IM EDB CommonService", "OperandRequest.Namespace", instance.Namespace, "OperandRequest.Name", common.IMEDBOprName)

	key := types.NamespacedName{Name: ctrlCommon.IMEDBCSName, Namespace: instance.Namespace}

	gvk := schema.GroupVersionKind{
		Group:   "operator.ibm.com",
		Version: "v3",
		Kind:    "CommonService",
	}

	unstrCert := &unstructured.Unstructured{}
	unstrCert.SetGroupVersionKind(gvk)

	err := r.Client.Get(context.TODO(), key, unstrCert)

	if err != nil {
		if !errors.IsNotFound(err) {
			reqLogger.Info(ctrlCommon.IMEDBCSName + " CommonService Not Found")
			return false
		}
		reqLogger.Info("Failed to get CommonService " + ctrlCommon.IMEDBCSName)
		return false
	}
	reqLogger.Info("CommonService " + ctrlCommon.IMEDBCSName + " is present")

	return true
}

// creates operandrequest and commonservice cr
func (r *AuthenticationReconciler) createOprReqAndCS(instance *operatorv1alpha1.Authentication, needToRequeue *bool) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	// check if ibm-iam-request-csedb operandrequest is already present or not
	oprExist := r.checkOperandRequestExists(instance)
	// create  ibm-iam-request-csedb operandrequest if not present
	if !oprExist {
		// create postgresql operandrequest
		reqLogger.Info("Creating OperandRequest: " + ctrlCommon.IMEDBOprName)
		err := r.createOpendRequest(instance)
		if err != nil {
			*needToRequeue = true
		}
	}
	// create Commonservice CR
	csCRExist := r.checkCommonServiceExists(instance)
	if !csCRExist {
		// create postgresql commonservice CR
		reqLogger.Info("Creating CommonService: " + ctrlCommon.IMEDBCSName)
		err := r.createCommonService(instance)
		if err != nil {
			*needToRequeue = true
		}
	}

}
