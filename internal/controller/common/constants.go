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

package common

const GlobalConfigMapName string = "ibm-cpp-config"
const CommonServiceName string = "common-service"

// Name of ConfigMap that configures IBM Cloud cluster information
const IBMCloudClusterInfoCMName string = "ibmcloud-cluster-info"

// Name of ConfigMap that configures external or embedded EDB for IM
const DatastoreEDBCMName string = "im-datastore-edb-cm"

// Name of Secret containing certificates for connecting to EDB
const DatastoreEDBSecretName string = "im-datastore-edb-secret"

// Name of the mongodb operator deployment name
const MongoOprDeploymentName string = "ibm-mongodb-operator"

// Name of the mongodb statefulset name
const MongoStatefulsetName string = "icp-mongodb"

// Name of CommonService created by IM Operator to provision EDB share
const DatastoreEDBCSName string = "im-common-service"

type DeploymentName string

// The current names of Deployments managed by this Operator
const (
	PlatformIdentityProvider   DeploymentName = "platform-identity-provider"
	PlatformIdentityManagement DeploymentName = "platform-identity-management"
	PlatformAuthService        DeploymentName = "platform-auth-service"
)
