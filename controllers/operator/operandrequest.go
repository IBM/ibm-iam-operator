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
	"fmt"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	ctrlCommon "github.com/IBM/ibm-iam-operator/controllers/common"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
)

func (r *AuthenticationReconciler) checkforCSEDB(instance *operatorv1alpha1.Authentication, needToRequeue *bool) (err error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	edbConfiMapName := ctrlCommon.IMDatasourceCMName
	cfgmap, exists := r.checkIfConfigmapExists(instance, edbConfiMapName)

	if exists {
		is_embedded := cfgmap.Data["IS_EMBEDDED"]
		reqLogger.Info("EMBEDDED ??" + is_embedded)
		if is_embedded == "true" {
			// create postgresql operandrequest
			reqLogger.Info("Embedded edb is TRUE, Creating ibm-iam-request-csedb operandrequest")
			err := r.createOpendRequest(instance)
			if err != nil {
				*needToRequeue = true
			}
			// create Commonservice CR

		} else {
			reqLogger.Info("Embedded edb is FALSE, Creating ibm-iam-request-csedb operandrequest")
		}
	} else {
		reqLogger.Info("ELSE BLOCK EMBEDDED ??")
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
			reqLogger.Error(err, "The configmap ", edbConfiMapName, " is not created yet")
			reqLogger.Info("Creating ibm-iam-request-csedb operandrequest")
			// create postgresql operandrequest
			r.createOpendRequest(instance)
			return nil, false
		} else {
			reqLogger.Info("EDB CONFIGMAP present or what ")
		}
		reqLogger.Error(err, "Failed to get ConfigMap", edbConfiMapName)
		return nil, false
	} else {
		reqLogger.Info("configmap " + edbConfiMapName + " is already present")
		// edbConfiMapName exist, read the data
		return csEDBConfigmap, true
	}
}

func (r *AuthenticationReconciler) createOpendRequest(instance *operatorv1alpha1.Authentication) (err error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	reqLogger.Info("EDB:: inside operandrequest creation")

	// Define the YAML content as a map[string]interface{}
	operandRequestName := "ibm-iam-request-csedb"
	yamlContent := map[string]interface{}{
		"kind":       "OperandRequest",
		"apiVersion": "operator.ibm.com/v1alpha1",
		"metadata": map[string]interface{}{
			"name":      operandRequestName,
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
			// Route already exists from a previous reconcile
			reqLogger.Info("OperandRequest ibm-iam-request-csedb  already exists")
		} else {
			fmt.Printf("Error creating custom resource: %v\n", err)
		}
		return err
	}
	return nil
}

// IM operator creates CommonService CR, to claim the usage on shared embedded database
func (r *AuthenticationReconciler) createCommonService(instance *operatorv1alpha1.Authentication) (err error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	// Define the YAML content as a map[string]interface{}
	csCRName := "im-common-service"
	yamlContent := map[string]interface{}{
		"kind":       "CommonService",
		"apiVersion": "operator.ibm.com/v3",
		"metadata": map[string]interface{}{
			"name": csCRName,
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
			fmt.Printf("Error creating custom resource: %v\n", err)
			return err
		}
	}
	return nil
}
