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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	osconfigv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	discovery "k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	zenv1 "github.com/IBM/ibm-iam-operator/apis/zen.cpd.ibm.com/v1"
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
func GetClusterType(ctx context.Context, k8sClient *client.Client, cmName string) (clusterType ClusterType, err error) {
	logger := logf.FromContext(ctx)
	logger.Info("Get cluster config")

	var namespaces []string
	// TODO Clean this up for switch back to using Authentication CR
	servicesNamespace, err := GetServicesNamespace(ctx, k8sClient)
	if err != nil {
		logger.Error(err, "Could not get services namespace from CommonService", "name", CommonServiceName)
		err = nil
	} else {
		logger.Info("Got services namespace", "namespace", servicesNamespace)
		namespaces = []string{servicesNamespace}
	}

	// In the event that getting the services namespace in the previous method doesn't work out, get all watch
	// namespaces - one of them will contain the ConfigMap that this function needs
	if len(namespaces) == 0 {
		logger.Info("Get watch namespace(s)")
		var watchNamespace string
		watchNamespace, err = GetWatchNamespace()
		if err != nil {
			logger.Error(err, "Failed to get watch namespace")
			return
		}
		logger.Info("Got watch namespace(s)", "namespaces", watchNamespace)
		namespaces = strings.Split(watchNamespace, ",")
	}

	logger.Info("Create client to query for ConfigMap")

	cm := &corev1.ConfigMap{}
	for _, namespace := range namespaces {
		logger.Info("Try to find ConfigMap", "name", cmName, "namespace", namespace)
		err = (*k8sClient).Get(ctx, types.NamespacedName{Name: cmName, Namespace: namespace}, cm)
		if err != nil {
			logger.Error(err, "Failed to get ConfigMap")
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

func clusterHasGroupVersion(dc *discovery.DiscoveryClient, gv schema.GroupVersion) (apiPresent bool, err error) {
	if dc == nil {
		var cfg *rest.Config
		if cfg, err = config.GetConfig(); err != nil {
			return
		}

		if dc, err = discovery.NewDiscoveryClientForConfig(cfg); err != nil {
			return
		}
	}

	groupVersion := strings.Join([]string{gv.Group, gv.Version}, "/")
	resources, err := dc.ServerResourcesForGroupVersion(groupVersion)
	if err != nil || resources == nil {
		return false, err
	}

	return true, nil
}

func ClusterHasRouteGroupVersion(dc *discovery.DiscoveryClient) (found bool) {
	found, _ = clusterHasGroupVersion(dc, routev1.GroupVersion)
	return
}

func ClusterHasOpenShiftConfigGroupVerison(dc *discovery.DiscoveryClient) (found bool) {
	found, _ = clusterHasGroupVersion(dc, osconfigv1.GroupVersion)
	return
}

func ClusterHasZenExtensionGroupVersion(dc *discovery.DiscoveryClient) (found bool) {
	found, _ = clusterHasGroupVersion(dc, zenv1.GroupVersion)
	return
}

// The following is brought over from earlier versions of the operator-sdk

// GetWatchNamespace returns the Namespace the operator should be watching for changes
func GetWatchNamespace() (string, error) {
	// WatchNamespaceEnvVar is the constant for env variable WATCH_NAMESPACE
	// which specifies the Namespace to watch.
	// An empty value means the operator is running with cluster scope.
	var watchNamespaceEnvVar = "WATCH_NAMESPACE"

	ns, found := os.LookupEnv(watchNamespaceEnvVar)
	if !found {
		return "", fmt.Errorf("%s must be set", watchNamespaceEnvVar)
	}
	return ns, nil
}

const (
	// ForceRunModeEnv indicates if the operator should be forced to run in either local
	// or cluster mode (currently only used for local mode)
	ForceRunModeEnv string = "OSDK_FORCE_RUN_MODE"
	// ForceOperatorNsEnv provides an override value to indicate which namespace the Operator is running in; this is
	// largely meant for testing purposes (e.g. with envtest)
	ForceOperatorNsEnv string = "FORCE_OPERATOR_NS"
)

type RunModeType string

const (
	LocalRunMode   RunModeType = "local"
	ClusterRunMode RunModeType = "cluster"
)

func isRunModeLocal() bool {
	return os.Getenv(ForceRunModeEnv) == string(LocalRunMode)
}

func isOperatorNsForced() (string, bool) {
	value := os.Getenv(ForceOperatorNsEnv)
	return value, value != ""
}

// ErrNoNamespace indicates that a namespace could not be found for the current
// environment
var ErrNoNamespace = fmt.Errorf("namespace not found for current environment")

// ErrRunLocal indicates that the operator is set to run in local mode (this error
// is returned by functions that only work on operators running in cluster mode)
var ErrRunLocal = fmt.Errorf("operator run mode forced to local")

// GetOperatorNamespace returns the namespace the Operator should be running in.
func GetOperatorNamespace() (string, error) {
	if ns, isNsForced := isOperatorNsForced(); isRunModeLocal() && isNsForced {
		return ns, nil
	} else if isRunModeLocal() {
		return "", ErrRunLocal
	}
	nsBytes, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNoNamespace
		}
		return "", err
	}
	ns := strings.TrimSpace(string(nsBytes))
	return ns, nil
}

// End k8sutil "ports"

// GetAuthentication finds the Authentication for this install of the Cloud Pak Foundational Services. It does this by
// listing all Authentications in all namespaces where the Operator has visibility. There should only ever be one
// Authentication CR for a given IM Operator instance, so wherever that one Authentication CR is found is assumed to be
// where the other Operands are. If no or more than one Authentication CR is found, an error is reported as this is an
// unsupported usage of the CR.
func GetAuthentication(ctx context.Context, k8sClient *client.Client) (authCR *operatorv1alpha1.Authentication, err error) {
	authenticationList := &operatorv1alpha1.AuthenticationList{}
	err = (*k8sClient).List(ctx, authenticationList)
	if err != nil {
		return
	}
	if len(authenticationList.Items) != 1 {
		err = fmt.Errorf("expected to find 1 Authentication but found %d", len(authenticationList.Items))
		return
	}
	return &authenticationList.Items[0], nil
}

// GetServicesNamespace finds the namespace that contains the shared services deriving from the Authentication CR for
// this IM install. Returns an error when
func GetServicesNamespace(ctx context.Context, k8sClient *client.Client) (namespace string, err error) {
	authCR, err := GetAuthentication(ctx, k8sClient)
	if err != nil {
		return
	}
	return authCR.Namespace, nil
}

func MergeMap(in map[string]string, mergeMap map[string]string) map[string]string {
	if mergeMap == nil {
		mergeMap = make(map[string]string)
	}
	if in == nil {
		return mergeMap
	}
	for k, v := range in {
		mergeMap[k] = v
	}
	return mergeMap
}

func GetBindInfoRefreshMap() map[string]string {
	return map[string]string{
		"bindinfoRefresh/configmap": DatastoreEDBCMName,
		"bindinfoRefresh/secret":    DatastoreEDBSecretName,
	}
}

// ReduceSubreconcilerResultsAndErrors takes a slice of Result pointers and a slice of errors and reduces them to a
// single Result pointer and error to be used in a subreconciler.Evaluate call.
func ReduceSubreconcilerResultsAndErrors(results []*ctrl.Result, errs []error) (result *ctrl.Result, err error) {
	err = errors.Join(errs...)
	for _, r := range results {
		if r == nil {
			continue
		}
		if result == nil {
			result = &ctrl.Result{}
			*result = *r
			continue
		}
		if r.Requeue {
			result.Requeue = true
		}
		// Always use exponential back off for results that have errors
		if err != nil {
			result.RequeueAfter = 0
		} else if r.RequeueAfter > result.RequeueAfter {
			result.RequeueAfter = r.RequeueAfter
		}
	}

	return
}
