//
// Copyright 2021 IBM Corporation
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

package common

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/operator-framework/operator-sdk/pkg/k8sutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type ClusterType int64

const (
	Unknown ClusterType = iota
	OpenShift
	CNCF
)

func (ct ClusterType) String() string {
	switch ct {
	case OpenShift:
		return "OpenShift"
	case CNCF:
		return "CNCF"
	default:
		return "Unknown"
	}
}

var _ fmt.Stringer = OpenShift

// GetClusterType attempts to determine whether the Operator is running on Openshift versus a CNCF cluster. Exits in the
// event that the cluster config can't be obtained to make queries or if the watch namespace can't be obtained.
func GetClusterType(ctx context.Context, cmName string) (clusterType ClusterType, err error) {
	logger := logf.FromContext(ctx).WithName("GetClusterType")
	logger.Info("Get cluster config")
	// Assume OpenShift as the default
	cfg, err := config.GetConfig()
	if err != nil {
		logger.Error(err, "Could not obtain cluster config")
		return
	}

	// Attempt o get services namespace from the default CommonService
	var namespaces []string
	servicesNamespace, err := GetSharedServicesNamespace(ctx, CommonServiceName)
	if err != nil {
		logger.Error(err, "Could not get services namespace from CommonService", "name", CommonServiceName)
		err = nil
	}
	logger.Info("Got shared service namespace", "namespace", servicesNamespace)
	namespaces = []string{servicesNamespace}

	// In the event that getting the services namespace in the previuos method doesn't work out, get all watch
	// namespaces - one of them will contain the ConfigMap that this function needs
	if len(namespaces) == 0 {
		logger.Info("Get watch namespace(s)")
		var watchNamespace string
		watchNamespace, err = k8sutil.GetWatchNamespace()
		if err != nil {
			logger.Error(err, "Failed to get watch namespace")
			return
		}
		logger.Info("Got watch namespace(s)", "namespaces", watchNamespace)
		namespaces = strings.Split(watchNamespace, ",")
	}

	logger.Info("Create client to query for ConfigMap")
	osDetectClient, err := client.New(cfg, client.Options{})
	if err != nil {
		logger.Error(err, "Failed to create client")
		return
	}
	cm := &corev1.ConfigMap{}
	for _, namespace := range namespaces {
		logger.Info("Try to find ConfigMap", "name", cmName, "namespace", namespace)
		err = osDetectClient.Get(ctx, types.NamespacedName{Name: cmName, Namespace: namespace}, cm)
		if err != nil {
			logger.Info("Did not find it", "namespace", namespace)
			continue
		}
		logger.Info("Found ConfigMap", "name", cmName, "namespace", namespace)
		clusterTypeValue, ok := cm.Data["kubernetes_cluster_type"]
		// Only assume CNCF cluster if the field is set and it case-insensitively matches "cncf"
		if ok && strings.EqualFold(clusterTypeValue, "cncf") {
			clusterType = CNCF
		} else {
			clusterType = OpenShift
		}
		logger.Info("Looked for kubernetes_cluster_type", "ok", ok, "value", clusterTypeValue, "clusterType", clusterType)
		return
	}
	logger.Info("Could not find ConfigMap", "name", cmName, "isOSEnv", Unknown)
	return
}

// GetSharedServicesNamespace returns the name of the shared services namespace for the Common Services instance that
// this Operator is a part of. Fails if the CommonService CR by the name provided cannot be found in the namespace this
// Operator is running in.
func GetSharedServicesNamespace(ctx context.Context, name string) (namespace string, err error) {
	logger := logf.FromContext(ctx).WithName("GetSharedServicesNamespace")
	cfg, err := config.GetConfig()
	if err != nil {
		logger.Error(err, "Could not obtain cluster config")
		os.Exit(1)
	}
	operatorNamespace, err := k8sutil.GetOperatorNamespace()
	if err != nil {
		logger.Error(err, "Failed to get operator namespace")
		return
	}

	getCSClient, err := client.New(cfg, client.Options{})
	if err != nil {
		logger.Error(err, "Failed to create client")
		return
	}

	key := types.NamespacedName{Name: name, Namespace: operatorNamespace}

	logger = logger.WithValues("name", name, "namespace", operatorNamespace)

	gvk := schema.GroupVersionKind{
		Group:   "operator.ibm.com",
		Version: "v3",
		Kind:    "CommonService",
	}

	unstrCS := &unstructured.Unstructured{}
	unstrCS.SetGroupVersionKind(gvk)

	err = getCSClient.Get(ctx, key, unstrCS)
	if err != nil {
		logger.Error(err, "Failed to get CommonService as unstructured object")
		return
	}

	spec, ok := unstrCS.Object["spec"].(map[string]interface{})
	if !ok {
		logger.Error(nil, "Failed to convert CommonService spec into map[string]interface{}")
		err = fmt.Errorf(".spec of CommonService %s in namespace %s is not a map[string]interface{}", name, operatorNamespace)
		return
	}
	namespace, ok = spec["servicesNamespace"].(string)
	if !ok {
		logger.Error(nil, "Failed to get string servicesNamespace from CommonService spec")
		err = fmt.Errorf(".spec.servicesNamespace of CommonService %s in namespace %s is not a string", name, operatorNamespace)
	}
	return
}
