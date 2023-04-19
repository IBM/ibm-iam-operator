//
// Copyright 2020 IBM Corporation
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
	certmgr "github.com/IBM/ibm-iam-operator/pkg/apis/certmanager/v1alpha1"
	"github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	certmgrv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"github.com/operator-framework/operator-sdk/pkg/log/zap"
	"os"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"github.com/IBM/ibm-iam-operator/pkg/resources"
)

func init() {
	// Register the types with the Scheme so the components can map objects to GroupVersionKinds and back
	AddToSchemes = append(AddToSchemes, v1alpha1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, certmgr.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, certmgrv1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, v1alpha1.CertificateSchemeBuilder.AddToScheme)

	// This code races with cmd's main function, so attempt to set the logger here, just in case
	logf.SetLogger(zap.Logger())
	logger := logf.Log.WithName("operator_v1alpha1_init")
	ctx := logf.IntoContext(context.Background(), logger)
	err := addAPIsIfOnOpenShift(ctx, configv1.AddToScheme, routev1.AddToScheme)
	if err != nil {
		logger.Error(nil, "Exiting due to failure to detect cluster type")
		os.Exit(1)
	}
}

func addAPIsIfOnOpenShift(ctx context.Context, addToSchemeFuncs ...func(s *runtime.Scheme) error) (err error) {
	logger := logf.FromContext(ctx).WithName("addAPIsIfOnOpenShift")
	clusterType, err := resources.GetClusterType(ctx)
	if err != nil {
		logger.Error(err, "Failed to detect cluster type")
		return
	}
	if clusterType == resources.OpenShift {
		logger.Info("Running on OpenShift - adding relevant schemes")
		AddToSchemes = append(AddToSchemes, addToSchemeFuncs...)
	} else {
		logger.Info("Not running on OpenShift - skipping OpenShift-specific schemes")
	}
	return
}

