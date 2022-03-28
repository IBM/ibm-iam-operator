package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// IAMDatabaseClusterSpec defines the desired state of IAMDatabaseCluster
type IAMDatabaseClusterSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	ImageRegistry string                       `json:"imageRegistry"`
	ImageName     string                       `json:"imageName"`
	ImageTag      string                       `json:"imageTag"`
	Resources     *corev1.ResourceRequirements `json:"resources,omitempty"`
	Instances     int                          `json:"instances"`
	LogLevel      string                       `json:"logLevel"`
	Storage       *DBStorage                   `json:"storage"`
}

// IAMDatabaseClusterStatus defines the observed state of IAMDatabaseCluster
type IAMDatabaseClusterStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	ReadyInstances int    `json:"readyInstances"`
	CurrentPrimary string `json:"currentPrimary"`
	Phase          string `json:"phase"`
	Message        string `json:"message"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IAMDatabaseCluster is the Schema for the iamdatabaseclusters API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=iamdatabaseclusters,scope=Namespaced
type IAMDatabaseCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IAMDatabaseClusterSpec   `json:"spec,omitempty"`
	Status IAMDatabaseClusterStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IAMDatabaseClusterList contains a list of IAMDatabaseCluster
type IAMDatabaseClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IAMDatabaseCluster `json:"items"`
}

type DBStorage struct {
	Size         string `json:"volumeSize"`
	StorageClass string `json:"storageClass"`
}

func init() {
	SchemeBuilder.Register(&IAMDatabaseCluster{}, &IAMDatabaseClusterList{})
}
