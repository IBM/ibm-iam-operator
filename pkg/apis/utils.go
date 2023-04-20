//
// Copyright 2022 IBM Corporation
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
