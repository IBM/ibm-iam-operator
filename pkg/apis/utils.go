package apis

import (
	"context"
	"github.com/IBM/ibm-iam-operator/pkg/common"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// addAPIsIfOnOpenShift adds the provided AddToScheme functions to the AddToSchemes SchemeBuilder only if the cluster
// this Operator is running on is an OpenShift cluster. This is done to avoid issues where OpenShift-specific CRDs are
// not installed on the cluster, which lead to failures to start the controller.
func addAPIsIfOnOpenShift(ctx context.Context, addToSchemeFuncs ...func(s *runtime.Scheme) error) (err error) {
	logger := logf.FromContext(ctx).WithName("addAPIsIfOnOpenShift")
	clusterType, err := common.GetClusterType(ctx, common.GlobalConfigMapName)
	if err != nil {
		logger.Error(err, "Failed to detect cluster type")
		return
	}
	if clusterType == common.OpenShift {
		logger.Info("Running on OpenShift - adding relevant schemes")
		AddToSchemes = append(AddToSchemes, addToSchemeFuncs...)
	} else {
		logger.Info("Not running on OpenShift - skipping OpenShift-specific schemes")
	}
	return
}
