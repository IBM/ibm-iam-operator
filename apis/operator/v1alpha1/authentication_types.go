/*
Copyright 2023 IBM Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// AuthenticationSpec defines the desired state of Authentication
type AuthenticationSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of Authentication. Edit authentication_types.go to remove/update
	OperatorVersion               string                 `json:"operatorVersion"`
	Replicas                      int32                  `json:"replicas"`
	Labels                        map[string]string      `json:"labels,omitempty"`
	AuditService                  AuditServiceSpec       `json:"auditService"`
	AuthService                   AuthServiceSpec        `json:"authService"`
	IdentityProvider              IdentityProviderSpec   `json:"identityProvider"`
	IdentityManager               IdentityManagerSpec    `json:"identityManager"`
	InitMongodb                   InitMongodbSpec        `json:"initMongodb"`
	ClientRegistration            ClientRegistrationSpec `json:"clientRegistration"`
	Config                        ConfigSpec             `json:"config"`
	EnableInstanaMetricCollection bool                   `json:"enableInstanaMetricCollection,omitempty"`
}

type AuditServiceSpec struct {
	ImageRegistry string                       `json:"imageRegistry"`
	ImageName     string                       `json:"imageName"`
	ImageTag      string                       `json:"imageTag"`
	SyslogTlsPath string                       `json:"syslogTlsPath,omitempty"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

const AuditServiceIgnoreString string = "auditService no longer used - ignore"

// setRequiredDummyData writes dummy AuditServiceSpec data to an Authentication in order to maintain backwards- and
// forwards-compatibility with previous Authentication CRD releases. Running this function ensures that, if an earlier
// version of the Authentication CRD is installed on a cluster where this version's CRD was previously, the CRs created
// based upon this version's CRD will not break in a multi-tenancy scenario.
func (a *Authentication) SetRequiredDummyData() {
	if a == nil {
		return
	}

	a.Spec.AuditService = AuditServiceSpec{
		ImageRegistry: AuditServiceIgnoreString,
		ImageName:     AuditServiceIgnoreString,
		ImageTag:      AuditServiceIgnoreString,
	}
}

type AuthServiceSpec struct {
	ImageRegistry    string                       `json:"imageRegistry"`
	ImageName        string                       `json:"imageName"`
	ImageTag         string                       `json:"imageTag"`
	RouterCertSecret string                       `json:"routerCertSecret"`
	Resources        *corev1.ResourceRequirements `json:"resources,omitempty"`
	LdapsCACert      string                       `json:"ldapsCACert"`
}

type IdentityProviderSpec struct {
	ImageRegistry string                       `json:"imageRegistry"`
	ImageName     string                       `json:"imageName"`
	ImageTag      string                       `json:"imageTag"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type IdentityManagerSpec struct {
	ImageRegistry   string                       `json:"imageRegistry"`
	ImageName       string                       `json:"imageName"`
	ImageTag        string                       `json:"imageTag"`
	MasterNodesList string                       `json:"masterNodesList"`
	Resources       *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type InitMongodbSpec struct {
	ImageRegistry string                       `json:"imageRegistry"`
	ImageName     string                       `json:"imageName"`
	ImageTag      string                       `json:"imageTag"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type ClientRegistrationSpec struct {
	ImageRegistry string                       `json:"imageRegistry"`
	ImageName     string                       `json:"imageName"`
	ImageTag      string                       `json:"imageTag"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type ConfigSpec struct {
	ClusterCADomain             string `json:"clusterCADomain"`
	DefaultAdminUser            string `json:"defaultAdminUser"`
	DefaultAdminPassword        string `json:"defaultAdminPassword"`
	ScimAdminUser               string `json:"scimAdminUser"`
	ScimAdminPassword           string `json:"scimAdminPassword"`
	ClusterName                 string `json:"clusterName"`
	ClusterInternalAddress      string `json:"clusterInternalAddress"`
	ClusterExternalAddress      string `json:"clusterExternalAddress"`
	WLPClientID                 string `json:"wlpClientID"`
	WLPClientSecret             string `json:"wlpClientSecret"`
	AuthUniqueHosts             string `json:"authUniqueHosts"`
	WLPClientRegistrationSecret string `json:"wlpClientRegistrationSecret"`
	InstallType                 string `json:"installType"`
	IsOpenshiftEnv              bool   `json:"isOpenshiftEnv"`
	OpenshiftPort               int32  `json:"openshiftPort"`
	ICPPort                     int32  `json:"icpPort"`
	FIPSEnabled                 bool   `json:"fipsEnabled"`
	ROKSEnabled                 bool   `json:"roksEnabled"`
	IBMCloudSaas                bool   `json:"ibmCloudSaas,omitempty"`
	OnPremMultipleDeploy        bool   `json:"onPremMultipleDeploy,omitempty"`
	SaasClientRedirectUrl       string `json:"saasClientRedirectUrl,omitempty"`
	NONCEEnabled                bool   `json:"nonceEnabled"`
	XFrameDomain                string `json:"xframeDomain,omitempty"`
	PreferredLogin              string `json:"preferredLogin,omitempty"`
	DefaultLogin                string `json:"defaultLogin,omitempty"`
	ROKSURL                     string `json:"roksURL"`
	ROKSUserPrefix              string `json:"roksUserPrefix"`
	EnableImpersonation         bool   `json:"enableImpersonation"`
	BootstrapUserId             string `json:"bootstrapUserId,omitempty"`
	ProviderIssuerURL           string `json:"providerIssuerURL,omitempty"`
	ClaimsSupported             string `json:"claimsSupported,omitempty"`
	ClaimsMap                   string `json:"claimsMap,omitempty"`
	ScopeClaim                  string `json:"scopeClaim,omitempty"`
	OIDCIssuerURL               string `json:"oidcIssuerURL"`
	AttrMappingFromConfig       bool   `json:"attrMappingFromConfig,omitempty"`
	ZenFrontDoor                bool   `json:"zenFrontDoor,omitempty"`
}

type ManagedResourceStatus struct {
	ObjectName string `json:"objectName,omitempty"`
	APIVersion string `json:"apiVersion,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Status     string `json:"status,omitempty"`
}

type ServiceStatus struct {
	ObjectName       string                  `json:"objectName,omitempty"`
	APIVersion       string                  `json:"apiVersion,omitempty"`
	Namespace        string                  `json:"namespace,omitempty"`
	Kind             string                  `json:"kind,omitempty"`
	Status           string                  `json:"status,omitempty"`
	ManagedResources []ManagedResourceStatus `json:"managedResources,omitempty"`
}

func (a *Authentication) SetService(ctx context.Context, service ServiceStatus, statusClient client.StatusClient, mu sync.Locker) (err error) {
	reqLogger := logf.FromContext(ctx)
	mu.Lock()
	defer mu.Unlock()

	updatedServiceStatus := false
	if !reflect.DeepEqual(service, a.Status.Service) {
		a.Status.Service = service
		updatedServiceStatus = true
	}

	if updatedServiceStatus {
		reqLogger.Info("Status has changed; performing update")
		err = statusClient.Status().Update(ctx, a)
	} else {
		reqLogger.Info("Status is the same; skipping update")
	}
	if err != nil {
		reqLogger.Error(err, "Attempt to update failed")
	}
	return nil
}

// AuthenticationStatus defines the observed state of Authentication
type AuthenticationStatus struct {
	Nodes      []string           `json:"nodes"`
	Service    ServiceStatus      `json:"service,omitempty"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

const ConditionMigrationsRunning = "MigrationsRunning"

const ConditionMigrated string = "MigrationsPerformed"
const MessageMigrationSuccess string = "All migrations completed successfully"
const MessageMigrationInProgress string = "Migrations are currently being performed; monitor progress in the IM Operator \"migration_worker\" logs"
const MessageMigrationFinished string = "Migration attempt finished"
const ReasonMigrationComplete string = "Complete"
const ReasonMigrationsInProgress string = "InProgress"
const ReasonMigrationsDone string = "Done"
const ReasonMigrationFailure string = "Failed"

func NewMigrationCompleteCondition() *metav1.Condition {
	return &metav1.Condition{
		Type:    ConditionMigrated,
		Status:  metav1.ConditionTrue,
		Reason:  ReasonMigrationComplete,
		Message: MessageMigrationSuccess,
	}
}

func NewMigrationInProgressCondition() *metav1.Condition {
	return &metav1.Condition{
		Type:    ConditionMigrationsRunning,
		Status:  metav1.ConditionTrue,
		Reason:  ReasonMigrationsInProgress,
		Message: MessageMigrationInProgress,
	}
}

func NewMigrationFinishedCondition() *metav1.Condition {
	return &metav1.Condition{
		Type:    ConditionMigrationsRunning,
		Status:  metav1.ConditionFalse,
		Reason:  ReasonMigrationsDone,
		Message: MessageMigrationFinished,
	}
}

func NewMigrationFailureCondition(name string) *metav1.Condition {
	message := fmt.Sprintf("Migration %q failed; review the IM Operator \"migration_worker\" logs for more information", name)
	return &metav1.Condition{
		Type:    ConditionMigrated,
		Status:  metav1.ConditionFalse,
		Reason:  ReasonMigrationFailure,
		Message: message,
	}
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:path=authentications,scope=Namespaced

// Authentication is the Schema for the authentications API
type Authentication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:pruning:PreserveUnknownFields
	Spec AuthenticationSpec `json:"spec,omitempty"`
	// +kubebuilder:pruning:PreserveUnknownFields
	Status AuthenticationStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AuthenticationList contains a list of Authentication
type AuthenticationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Authentication `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Authentication{}, &AuthenticationList{})
}

const AnnotationAuthMigrationComplete string = "authentication.operator.ibm.com/migration-complete"
const AnnotationAuthRetainMigrationArtifacts string = "authentication.operator.ibm.com/retain-migration-artifacts"
const AnnotationAuthDBSchemaVersion string = "authentication.operator.ibm.com/db-schema-version"

func (a *Authentication) HasBeenMigrated() bool {
	return meta.IsStatusConditionPresentAndEqual(a.Status.Conditions, ConditionMigrated, metav1.ConditionTrue)
}

func (a *Authentication) HasNotBeenMigrated() bool {
	return !a.HasBeenMigrated()
}

func (a *Authentication) IsRetainingArtifacts() bool {
	annotations := a.GetAnnotations()
	if value, ok := annotations[AnnotationAuthRetainMigrationArtifacts]; !ok || value == "true" {
		return true
	}
	return false
}

func (a *Authentication) IsNotRetainingArtifacts() bool {
	return !a.IsRetainingArtifacts()
}

func (a *Authentication) HasDBSchemaVersion() bool {
	annotations := a.GetAnnotations()
	if _, ok := annotations[AnnotationAuthDBSchemaVersion]; ok {
		return true
	}
	return false
}

func (a *Authentication) HasNoDBSchemaVersion() bool {
	return !a.HasDBSchemaVersion()
}

func (a *Authentication) GetDBSchemaVersion() string {
	annotations := a.GetAnnotations()
	if version, ok := annotations[AnnotationAuthDBSchemaVersion]; ok {
		return version
	}
	return ""
}

func (s ServiceStatus) IsReady() bool {
	return s.Status == "Ready"
}

func (s ServiceStatus) GVKReady(gvk schema.GroupVersionKind) bool {
	apiVersion, kind := gvk.ToAPIVersionAndKind()
	var found, ready int
	for _, resource := range s.ManagedResources {
		if resource.APIVersion != apiVersion || resource.Kind != kind {
			continue
		}
		found++
		if resource.Status != "Ready" {
			return false
		}
		ready++
	}
	return found > 0 && found == ready
}

func (s ServiceStatus) DeploymentsReady() bool {
	gvk := appsv1.SchemeGroupVersion.WithKind("Deployment")
	return s.GVKReady(gvk)
}

func (s ServiceStatus) ServicesReady() bool {
	gvk := corev1.SchemeGroupVersion.WithKind("Service")
	return s.GVKReady(gvk)
}
