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
	"os"
	"time"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	ctrlCommon "github.com/IBM/ibm-iam-operator/controllers/common"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
)

func (r *AuthenticationReconciler) checkforCSEDB(instance *operatorv1alpha1.Authentication, needToRequeue *bool) (err error) {

	edbConfiMapName := ctrlCommon.IMDatasourceCMName
	cfgmap, exists := r.checkIfConfigmapExists(instance, edbConfiMapName)

	if exists {
		is_embedded := cfgmap.Data["IS_EMBEDDED"]
		if is_embedded == "true" {
			// create postgresql operandrequest
			err := createOpendRequest(instance)
			if err != nil {
				*needToRequeue = true
			}
			// create Commonservice CR

		}
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
			// create postgresql operandrequest
			createOpendRequest(instance)
			return nil, false
		}
		reqLogger.Error(err, "Failed to get ConfigMap", edbConfiMapName)
		return nil, false
	} else {
		// edbConfiMapName exist, read the data
		return csEDBConfigmap, true
	}
}

func createOpendRequest(instance *operatorv1alpha1.Authentication) (err error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	cfg, err := config.GetConfig()
	if err != nil {
		// Create a dynamic client
		dynamicClient, err := dynamic.NewForConfig(cfg)
		if err != nil {
			fmt.Printf("Error creating dynamic client: %v\n", err)
			os.Exit(1)
		}
		gvr := schema.GroupVersionResource{
			Group:    "operator.ibm.com", // Update with the actual API group of your CRD
			Version:  "v1alpha1",         // Update with the actual API version of your CRD
			Resource: "OperandRequest",   // Update with the actual resource name of your CRD
		}

		// Define the YAML content as a map[string]interface{}
		operandRequestName := "ibm-iam-request-csedb"
		yamlContent := map[string]interface{}{
			"kind":       "OperandRequest",
			"apiVersion": "operator.ibm.com/v1alpha1",
			"metadata": map[string]interface{}{
				"name": operandRequestName,
			},
			"spec": map[string]interface{}{
				"requests": []map[string]interface{}{
					{
						"operands": []map[string]interface{}{
							{
								"name": "common-service-postgresql",
								"bindings": map[string]interface{}{
									"protected-cloudpak-db": map[string]interface{}{
										"secret": "common-service-db-cpadmin",
									},
									"private-superuser-db": map[string]interface{}{
										"secret": "common-service-db-superuser",
									},
								},
							},
						},
						"registry":          "common-service",
						"registryNamespace": "ibm-common-services",
					},
				},
			},
		}

		// Create an Unstructured object from the YAML content
		unstructuredObj := &unstructured.Unstructured{Object: yamlContent}

		// Now you can use unstructuredObj as needed
		_, err = dynamicClient.Resource(gvr).
			Namespace(instance.Namespace).
			Create(context.Background(), unstructuredObj, metav1.CreateOptions{})

		if err != nil {
			if errors.IsAlreadyExists(err) {
				// Route already exists from a previous reconcile
				reqLogger.Info("OperandRequest ibm-iam-request-csedb  already exists")
			} else {
				fmt.Printf("Error creating custom resource: %v\n", err)
			}
			return err
		}
		// Rest of your code...

		// Wait for the resource to become ready (for demonstration purposes, adjust the timeout and polling intervals as needed)
		for {
			time.Sleep(5 * time.Second) // Adjust the polling interval
			customResource, err := dynamicClient.Resource(gvr).
				Namespace(instance.Namespace).
				Get(context.Background(), "example-custom-resource", metav1.GetOptions{})
			if err != nil {
				panic(err.Error())
			}

			// Check if the resource is ready (you need to define the specific conditions for readiness)
			ready := checkCustomResourceReady(customResource)
			if ready {
				fmt.Println("Custom resource is ready for use!")
				break
			}

			fmt.Println("Custom resource is not yet ready. Waiting...")
			// Add a timeout check or other condition to exit the loop if needed
		}
	}
	return nil
}

func checkCustomResourceReady(cr *unstructured.Unstructured) bool {
	cr.GetCreationTimestamp()
	fmt.Println("Custom resource creation timestamp is ", cr.GetCreationTimestamp())
	// Implement your own logic to check if the custom resource is ready for use
	// For demonstration purposes, this function returns true always
	return true
}

func createCommonService(instance *operatorv1alpha1.Authentication) (err error) {

	cfg, err := config.GetConfig()
	if err != nil {
		// Create a dynamic client
		dynamicClient, err := dynamic.NewForConfig(cfg)
		if err != nil {
			fmt.Printf("Error creating dynamic client: %v\n", err)
			os.Exit(1)
		}
		gvr := schema.GroupVersionResource{
			Group:    "operator.ibm.com", // Update with the actual API group of your CRD
			Version:  "v3",               // Update with the actual API version of your CRD
			Resource: "CommonService",    // Update with the actual resource name of your CRD
		}

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

		// Create an Unstructured object from the YAML content
		unstructuredObj := &unstructured.Unstructured{Object: yamlContent}

		// Now you can use unstructuredObj as needed
		_, err = dynamicClient.Resource(gvr).
			Namespace(instance.Namespace).
			Create(context.Background(), unstructuredObj, metav1.CreateOptions{})

		if err != nil {
			fmt.Printf("Error creating custom resource: %v\n", err)
			return err
		}
	}
	return nil
}
