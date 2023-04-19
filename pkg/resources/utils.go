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

package resources

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	v1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	"github.com/operator-framework/operator-sdk/pkg/k8sutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var CsConfigAnnotationSuffix = "common-service/config"
var CsDefaultNamespace = "ibm-common-services"

// GetCsConfigAnnotation returns '<namespace>.common-service/config' annotation name for given namespace
func GetCsConfigAnnotation(namespace string) string {
	if len(namespace) == 0 {
		return CsDefaultNamespace + "." + CsConfigAnnotationSuffix
	}

	return namespace + "." + CsConfigAnnotationSuffix
}

// IsCsConfigAnnotationExists checks if '<namespace>.common-service/config' annotation name exists in the given annotations map or not
func IsCsConfigAnnotationExists(annotations map[string]string) bool {
	if len(annotations) == 0 {
		return false
	}
	csAnnotationFound := false
	reg, _ := regexp.Compile(`^(.*)\.common-service\/config`)
	for anno := range annotations {
		if reg.MatchString(anno) {
			csAnnotationFound = true
			break
		}
	}
	if csAnnotationFound {
		return true
	}
	return false
}

func IsOAuthAnnotationExists(annotations map[string]string) bool {
	if len(annotations) == 0 {
		return false
	}
	csOauthAnnotationFound := false
	reg, _ := regexp.Compile(`^(.*)\/oauth-redirectreference`)
	for anno := range annotations {
		if reg.MatchString(anno) {
			csOauthAnnotationFound = true
			break
		}
	}
	if csOauthAnnotationFound {
		return true
	}
	return false
}

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
func GetClusterType(ctx context.Context) (clusterType ClusterType, err error) {
	logger := logf.FromContext(ctx).WithName("OnOpenShift")
	logger.Info("Get cluster config")
	// Assume OpenShift as the default
	cfg, err := config.GetConfig()
	if err != nil {
		logger.Error(err, "Could not obtain cluster config")
		return
	}

	// Attempt o get services namespace from the default CommonService
	const CSName string = "common-service"
	var namespaces []string
	servicesNamespace, err := getSharedServicesNamespaceFromCommonService(ctx, CSName)
	if err != nil {
		logger.Error(err, "Could not get services namespace from CommonService", "name", CSName)
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
		logger.Info("Try to find ibm-cpp-config ConfigMap", "namespace", namespace)
		err = osDetectClient.Get(ctx, types.NamespacedName{Name: "ibm-cpp-config", Namespace: namespace}, cm)
		if err != nil {
			logger.Info("Did not find it", "namespace", namespace)
			continue
		}
		logger.Info("Found ibm-cpp-config ConfigMap", "namespace", namespace)
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
	logger.Info("Could not find ibm-cpp-config ConfigMap", "isOSEnv", Unknown)
	return
}

func getSharedServicesNamespaceFromCommonService(ctx context.Context, name string) (namespace string, err error) {
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

	gvk := schema.GroupVersionKind {
		Group: "operator.ibm.com",
		Version: "v3", 
		Kind: "CommonService",
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

// getSharedServicesNamespace determines the namespace that contains the shared services by listing all Authentications
// in all namespaces where the Operator has visibility. There should only ever be one Authentication CR for a given
// IM Operator instance, so wherever that one Authentication CR is found is assumed to be where the other Operands are.
// If no or more than one Authentication CR is found, an error is reported as this is an unsupported usage of the CR.
func GetSharedServicesNamespace(ctx context.Context, k8sClient client.Client) (namespace string, err error) {
	reqLogger := logf.FromContext(ctx).WithName("getSharedServicesNamespace")
	authenticationList := &v1alpha1.AuthenticationList{}
	err = k8sClient.List(ctx, authenticationList)
	if err != nil {
		reqLogger.Error(err, "Error encountered while trying to determine shared services namespace")
		return
	}
	if len(authenticationList.Items) != 1 {
		err = fmt.Errorf("expected to find 1 Authentication but found %d", len(authenticationList.Items))
		var namespacedNames []types.NamespacedName
		for _, item := range authenticationList.Items {
			nsn := types.NamespacedName{Name: item.Name, Namespace: item.Namespace}
			namespacedNames = append(namespacedNames, nsn)
		}
		reqLogger.Error(err, "Error encountered while trying to determine shared services namespace", "AuthenticationList", namespacedNames)
		return
	}
	return authenticationList.Items[0].Namespace, nil
}
