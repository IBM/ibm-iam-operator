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
	certmgr "github.com/IBM/ibm-iam-operator/pkg/apis/certmanager/v1alpha1"
	"github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	certmgrv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	routev1 "github.com/openshift/api/route/v1"
)

func init() {
	// Register the types with the Scheme so the components can map objects to GroupVersionKinds and back
	AddToSchemes = append(AddToSchemes, v1alpha1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, certmgr.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, certmgrv1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, v1alpha1.CertificateSchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, routev1.AddToScheme)
}
