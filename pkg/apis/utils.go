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
	"fmt"

	"github.com/operator-framework/operator-sdk/pkg/k8sutil"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// addToSchemeTest structs contain an AddToScheme function for SchemeBuilders as well as list of types to test client
// calls on.
type addToSchemeTest struct {
	AddToScheme  func(s *runtime.Scheme) error
	ListType     client.ObjectList
	GroupVersion schema.GroupVersion
}

// addAPIfRegistered adds the provided API's AddToScheme function to the AddToSchemes SchemeBuilder only if the cluster
// this Operator is running on has the API registered. This is done to avoid issues where OpenShift-specific kinds are
// not installed on the cluster, which lead to failures to start the controller.
func addAPIfRegistered(ctx context.Context, addToSchemeTests ...*addToSchemeTest) (err error) {
	logger := logf.FromContext(ctx).WithName("addRouteV1APIfRegistered")
	cfg, err := config.GetConfig()
	if err != nil {
		err = fmt.Errorf("could not obtain cluster config: %w", err)
		return
	}
	addToSchemes := []func(s *runtime.Scheme) error{}
	for _, test := range addToSchemeTests {
		addToSchemes = append(addToSchemes, test.AddToScheme)
	}
	sb := runtime.NewSchemeBuilder(addToSchemes...)
	scheme := runtime.NewScheme()
	err = sb.AddToScheme(scheme)
	if err != nil {
		err = fmt.Errorf("failed to construct test schema: %w", err)
		return
	}

	apiDetectClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		err = fmt.Errorf("failed to create test client: %w", err)
		return
	}

	operatorNs, _ := k8sutil.GetOperatorNamespace()
	opts := []client.ListOption{
		client.InNamespace(operatorNs),
	}
	for _, test := range addToSchemeTests {
		err = apiDetectClient.List(ctx, test.ListType, opts...)
		if err != nil {
			logger.Info("API group could not be retrieved from the cluster; skipping scheme", "groupversion", test.GroupVersion)
			err = nil
			continue
		}
		logger.Info("API group found on the cluster", "groupversion", test.GroupVersion)
		AddToSchemes = append(AddToSchemes, test.AddToScheme)
	}

	return
}
