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
	"github.com/IBM/ibm-iam-operator/pkg/controller/shatag"
	storagev1 "k8s.io/api/storage/v1"
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
  imageName: {{ .ImageName }}
  instances: 2
  logLevel: info
  primaryUpdateStrategy: unsupervised
  startDelay: 120
  stopDelay: 90
  storage:
    resizeInUseVolumes: true
    size: 20Gi
    storageClass: {{ .StorageClass }}
  bootstrap:
    initdb:
      database: iam
      owner: iam_user
      dataChecksums: true
      postInitApplicationSQL:
        - GRANT CONNECT ON DATABASE iam TO public
        - GRANT ALL PRIVILEGES ON DATABASE iam TO iam_user
        - CREATE SCHEMA platformdb
        - ALTER SCHEMA platformdb OWNER TO iam_user
        - GRANT ALL ON SCHEMA platformdb TO iam_user
  postgresql:
    parameters:
      max_connections: '500'
  certificates:
    serverCASecret: im-pgsql-server-cert
    serverTLSSecret: im-pgsql-server-cert
    clientCASecret: im-pgsql-client-cert
    replicationTLSSecret: im-pgsql-client-cert
  resources:
    limits:
      cpu: {{ .CpuLim }}
      ephemeral-storage: {{ .ESLim }}
      memory: {{ .MemLim }}
    requests:
      cpu: {{ .CpuReq }}
      ephemeral-storage: {{ .ESReq }}
      memory: {{ .MemReq }}
`

// Create Postgresql Cluster CR
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

func (r *ReconcileAuthentication) newPgsqlServiceSpec(instance *operatorv1alpha1.Authentication) *operatorv1alpha1.PgsqlServiceSpec {
	storageClass := instance.Spec.PgsqlService.StorageClass

	if storageClass == "" {
		storageclass, err := r.getStorageClass()
		if err != nil {
			return nil
		} else {
			instance.Spec.PgsqlService.StorageClass = storageclass

		}
	} else {
		scExist := r.storageClassAvailable(storageClass)
		if !scExist {
			storageclass, err := r.getStorageClass()
			if err != nil {
				return nil
			}
			instance.Spec.PgsqlService.StorageClass = storageclass

		}
	}
	if instance.Spec.PgsqlService.LogLevel == "" {
		instance.Spec.PgsqlService.LogLevel = "info"
	}
	cpuReq := instance.Spec.PgsqlService.Resources.Requests.Cpu().String()
	if cpuReq == "" {
		cpuReq = "75m"
	}
	memReq := instance.Spec.PgsqlService.Resources.Requests.Memory().String()
	if memReq == "" {
		memReq = "256Mi"
	}
	esReq := instance.Spec.PgsqlService.Resources.Requests.StorageEphemeral().String()
	if esReq == "" {
		esReq = "128Mi"
	}
	cpuLim := instance.Spec.PgsqlService.Resources.Limits.Cpu().String()
	if cpuLim == "" {
		cpuLim = "200m"
	}
	memLim := instance.Spec.PgsqlService.Resources.Limits.Memory().String()
	if memLim == "" {
		memLim = "768Mi"
	}
	esLim := instance.Spec.PgsqlService.Resources.Limits.StorageEphemeral().String()
	if esLim == "" {
		esLim = "512Mi"

	}
	return &operatorv1alpha1.PgsqlServiceSpec{LogLevel: instance.Spec.PgsqlService.LogLevel, StorageClass: instance.Spec.PgsqlService.StorageClass, ImageName: shatag.GetImageRef("POSTGRESQL_IMAGE"), CpuReq: cpuReq, MemReq: memReq, ESReq: esReq, CpuLim: cpuLim, MemLim: memLim, ESLim: esLim}
}

func (r *ReconcileAuthentication) getStorageClass() (string, error) {
	scList := &storagev1.StorageClassList{}
	err := r.Reader.List(context.TODO(), scList)
	if err != nil {
		return "", err
	}
	if len(scList.Items) == 0 {
		return "", fmt.Errorf("could not find storage class in the cluster")
	}

	for _, sc := range scList.Items {
		if sc.GetAnnotations()["storageclass.kubernetes.io/is-default-class"] == "true" || sc.GetAnnotations()["storageclass.beta.kubernetes.io/is-default-class"] == "true" {
			return sc.GetName(), nil
		}
		if sc.Provisioner == "kubernetes.io/no-provisioner" {
			return sc.GetName(), nil
		}
	}

	return "", fmt.Errorf("could not find dynamic provisioner storage class in the cluster nor is there a default storage class")
}

func (r *ReconcileAuthentication) storageClassAvailable(storageClass string) bool {
	var scExist bool
	scList := &storagev1.StorageClassList{}
	err := r.Reader.List(context.TODO(), scList)
	if err != nil {
		return false
	}
	if len(scList.Items) == 0 {
		return false
	}

	for _, sc := range scList.Items {
		if sc.ObjectMeta.Name == storageClass {
			scExist = true
			break
		}
	}

	return scExist
}
