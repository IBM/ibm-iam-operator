package authentication

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

import (
	"context"
	"fmt"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"
)

const pgsqlCluster = `
apiVersion: postgresql.k8s.enterprisedb.io/v1
kind: Cluster
metadata:
  name: im-store-edb
spec:
  instances: 2
  logLevel: info
  primaryUpdateStrategy: unsupervised
  storage:
    size: 20Gi
  certificates:
    serverCASecret: im-ca-cert-secret
    serverTLSSecret: im-store-edb-server
    clientCASecret: im-ca-cert-secret
    replicationTLSSecret: im-store-edb-replica-client
`

func (r *ReconcileAuthentication) createUpdateFromYaml(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, yamlContent []byte) error {
	obj := &unstructured.Unstructured{}
	jsonSpec, err := yaml.YAMLToJSON(yamlContent)
	if err != nil {
		return fmt.Errorf("could not convert yaml to json: %v", err)
	}

	if err := obj.UnmarshalJSON(jsonSpec); err != nil {
		return fmt.Errorf("could not unmarshal resource: %v", err)
	}

	obj.SetNamespace(instance.Namespace)

	// Set CommonServiceConfig instance as the owner and controller
	if err := controllerutil.SetControllerReference(instance, obj, scheme); err != nil {
		return err
	}

	err = r.client.Create(context.TODO(), obj)
	if err != nil {
		if errors.IsAlreadyExists(err) {
			if err := r.client.Update(context.TODO(), obj); err != nil {
				return fmt.Errorf("could not Update resource: %v", err)
			}
			return nil
		}
		return fmt.Errorf("could not Create resource: %v", err)
	}

	return nil
}
