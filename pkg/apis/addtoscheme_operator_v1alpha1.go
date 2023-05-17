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
	routev1 "github.com/openshift/api/route/v1"
	"github.com/operator-framework/operator-sdk/pkg/log/zap"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
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
	routeAddToSchemeTest := &addToSchemeTest{
		AddToScheme:  routev1.AddToScheme,
		ListType:     &routev1.RouteList{},
		GroupVersion: routev1.GroupVersion,
	}
	err := addAPIfRegistered(ctx, routeAddToSchemeTest)
	if err != nil {
		logger.Error(err, "Some or all OpenShift-specific schemes were not added")
		err = nil
	}
}
