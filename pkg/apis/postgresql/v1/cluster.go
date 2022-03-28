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
package v1

import (
	certmgr "github.com/IBM/ibm-iam-operator/pkg/apis/certmanager/v1alpha1"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Cluster is the Schema for the Clusters API
type Cluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterSpec  `json:"spec,omitempty"`
	Status ClientStatus `json:"status,omitempty"`
}

// ClientSpec defines the desired state of Client
type ClusterSpec struct {
	Bootstrap             *Bootstrap         `json:"bootstrap"`
	Postgresql            *Postgresql        `json:"postgresql"`
	Storage               *Storage           `json:"storage"`
	PrimaryUpdateStrategy string             `json:"primaryUpdateStrategy"`
	Instances             int                `json:"instances"`
	Resources             *Resources         `json:"resources"`
	Certificates          *Certificates      `json:"certificates"`
	ImageName             string             `json:"imageName"`
	Backup                *Backup            `json:"backup,omitempty"`
	ExternalClusters      []ExternalClusters `json:"externalClusters,omitempty"`
}

// ClientStatus defines the observed state of Client
type ClientStatus struct {
	Instances       int              `json:"instances"`
	InstancesStatus *InstancesStatus `json:"instancesStatus"`
	Phase           string           `json:"phase"`
	PvcCount        int              `json:"pvcCount"`
	ReadyInstances  int              `json:"readyInstances"`
	TargetPrimary   string           `json:"targetPrimary"`
	WriteService    string           `json:"writeService"`
	CurrentPrimary  string           `json:"currentPrimary"`
}

// Bootstrap
type Bootstrap struct {
	Initdb   *Initdb   `json:"initdb,omitempty"`
	Recovery *Recovery `json:"recovery,omitempty"`
}

// Initdb
type Initdb struct {
	Database string `json:"database"`
	Owner    string `json:"owner"`
}

// Parameters
type Parameters struct {
	WorkMem                       string `json:"work_mem"`
	MaintenanceWorkMem            string `json:"maintenance_work_mem"`
	LogTempFiles                  string `json:"log_temp_files"`
	LoggingCollector              string `json:"logging_collector"`
	AutovacuumVacuumScaleFactor   string `json:"autovacuum_vacuum_scale_factor"`
	EffectiveCacheSize            string `json:"effective_cache_size"`
	AutovacuumVacuumCostLimit     string `json:"autovacuum_vacuum_cost_limit"`
	MaxParallelWorkers            string `json:"max_parallel_workers"`
	MaxWalSenders                 string `json:"max_wal_senders"`
	MaxReplicationSlots           string `json:"max_replication_slots"`
	MaxSyncWorkersPerSubscription string `json:"max_sync_workers_per_subscription"`
	LogStatement                  string `json:"log_statement"`
	MaxWorkerProcesses            string `json:"max_worker_processes"`
	SharedBuffers                 string `json:"shared_buffers"`
	LogLinePrefix                 string `json:"log_line_prefix"`
	LogDuration                   string `json:"log_duration"`
	MaxLogicalReplicationWorkers  string `json:"max_logical_replication_workers"`
	MaxConnections                string `json:"max_connections"`
	WalKeepSegments               string `json:"wal_keep_segments"`
}

// Postgresql
type Postgresql struct {
	PgHba      []string    `json:"pg_hba"`
	Parameters *Parameters `json:"parameters"`
}

// Storage
type Storage struct {
	Size         string       `json:"size"`
	StorageClass string       `json:"storageClass"`
	PvcTemplate  *PvcTemplate `json:"pvcTemplate"`
}

// PvcTemplate
type PvcTemplate struct {
	AccessModes []string `json:"accessModes"`
}

// Requests
type Requests struct {
	Memory string `json:"memory"`
	Cpu    string `json:"cpu"`
}

// Limits
type Limits struct {
	Memory string `json:"memory"`
	Cpu    string `json:"cpu"`
}

// InstancesStatus
type InstancesStatus struct {
	Healthy []string `json:"healthy"`
}

type Resources struct {
	Requests *Requests `json:"requests"`
	Limits   *Limits   `json:"limits"`
}

type Certificates struct {
	ServerCASecret       string `json:"serverCASecret"`
	ServerTLSSecret      string `json:"serverTLSSecret"`
	ClientCASecret       string `json:"clientCASecret"`
	ReplicationTLSSecret string `json:"replicationTLSSecret"`
}

// Backup
type Backup struct {
	BarmanObjectStore *BarmanObjectStore `json:"barmanObjectStore"`
}

// BarmanObjectStore
type BarmanObjectStore struct {
	DestinationPath string         `json:"destinationPath"`
	EndpointURL     string         `json:"endpointURL"`
	ServerName      string         `json:"serverName,omitempty"`
	S3Credentials   *S3Credentials `json:"s3Credentials"`
}

// S3Credentials
type S3Credentials struct {
	AccessKeyId     *AccessKeyId     `json:"accessKeyId"`
	SecretAccessKey *SecretAccessKey `json:"secretAccessKey"`
}

// AccessKeyId
type AccessKeyId struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// SecretAccessKey
type SecretAccessKey struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type Recovery struct {
	Backup         *RecoveryBackup `json:"backup,omitempty"`
	Source         string          `json:"source,omitempty"`
	RecoveryTarget *RecoveryTarget `json:"recoveryTarget,omitempty"`
}

type RecoveryBackup struct {
	Name string `json:"name"`
}

type RecoveryTarget struct {
	TargetImmediate bool `json:"targetImmediate"`
}

type ExternalClusters struct {
	Name              string             `json:"name"`
	BarmanObjectStore *BarmanObjectStore `json:"barmanObjectStore"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterList contains a list of Clusters
type ClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Cluster `json:"items"`
}

func init() {
	PostgresSchemeBuilder.Register(&Cluster{}, &ClusterList{})
	operatorv1alpha1.CertificateSchemeBuilder.Register(&certmgr.Certificate{}, &certmgr.CertificateList{})
}
