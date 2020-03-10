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

package v1alpha1

import (
	userv1 "github.com/openshift/api/user/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AuthenticationSpec defines the desired state of Authentication
type AuthenticationSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	OperatorVersion    string                 `json:"operatorVersion"`
	Replicas           int32                  `json:"replicas"`
	AuditService       AuditServiceSpec       `json:"auditService"`
	AuthService        AuthServiceSpec        `json:"authService"`
	IdentityProvider   IdentityProviderSpec   `json:"identityProvider"`
	IdentityManager    IdentityManagerSpec    `json:"identityManager"`
	InitMongodb        InitMongodbSpec        `json:"initMongodb"`
	ClientRegistration ClientRegistrationSpec `json:"clientRegistration"`
	Config             ConfigSpec             `json:"config"`
}

type AuditServiceSpec struct {
	ImageRegistry string `json:"imageRegistry"`
	ImageName     string `json:"imageName"`
	ImageTag      string `json:"imageTag"`
	JournalPath   string `json:"journalPath"`
}

type AuthServiceSpec struct {
	ImageRegistry    string `json:"imageRegistry"`
	ImageName        string `json:"imageName"`
	ImageTag         string `json:"imageTag"`
	RouterCertSecret string `json:"routerCertSecret"`
	LdapsCACert      string `json:"ldapsCACert"`
}

type IdentityProviderSpec struct {
	ImageRegistry string `json:"imageRegistry"`
	ImageName     string `json:"imageName"`
	ImageTag      string `json:"imageTag"`
}

type IdentityManagerSpec struct {
	ImageRegistry   string `json:"imageRegistry"`
	ImageName       string `json:"imageName"`
	ImageTag        string `json:"imageTag"`
	MasterNodesList string `json:"masterNodesList"`
}

type InitMongodbSpec struct {
	ImageRegistry string `json:"imageRegistry"`
	ImageName     string `json:"imageName"`
	ImageTag      string `json:"imageTag"`
}

type ClientRegistrationSpec struct {
	ImageRegistry string `json:"imageRegistry"`
	ImageName     string `json:"imageName"`
	ImageTag      string `json:"imageTag"`
}

type ConfigSpec struct {
	ClusterCADomain             string `json:"clusterCADomain"`
	DefaultAdminUser            string `json:"defaultAdminUser"`
	DefaultAdminPassword        string `json:"defaultAdminPassword"`
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
	NONCEEnabled                bool   `json:"nonceEnabled"`
	ROKSURL                     string `json:"roksURL"`
	ROKSUserPrefix              string `json:"roksUserPrefix"`
	EnableImpersonation         bool   `json:"enableImpersonation"`
	OIDCIssuerURL               string `json:"oidcIssuerURL"`
}

// AuthenticationStatus defines the observed state of Authentication
type AuthenticationStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Nodes []string `json:"nodes"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Authentication is the Schema for the authentications API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=authentications,scope=Namespaced
type Authentication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthenticationSpec   `json:"spec,omitempty"`
	Status AuthenticationStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthenticationList contains a list of Authentication
type AuthenticationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Authentication `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Authentication{}, &AuthenticationList{})
	UserBuilder.Register(&userv1.User{}, &userv1.UserList{})
}
