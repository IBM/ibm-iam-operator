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

package oidcclientwatcher

import (
	"context"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const oidcClientWatcherDeploymentName = "oidcclient-watcher"

var trueVar bool = true
var falseVar bool = false
var defaultMode int32 = 420
var seconds60 int64 = 60
var runAsUser int64 = 21000
var fsGroup int64 = 21000
var cpu10 = resource.NewMilliQuantity(10, resource.DecimalSI)          // 10m
var cpu200 = resource.NewMilliQuantity(200, resource.DecimalSI)        // 200m
var memory16 = resource.NewQuantity(16*1024*1024, resource.BinarySI)   // 16Mi
var memory128 = resource.NewQuantity(128*1024*1024, resource.BinarySI) // 128Mi
var serviceAccountName string = "ibm-iam-operator"

var log = logf.Log.WithName("controller_oidcclientwatcher")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new OIDCClientWatcher Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileOIDCClientWatcher{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("oidcclientwatcher-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource OIDCClientWatcher
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.OIDCClientWatcher{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner OIDCClientWatcher
	err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.OIDCClientWatcher{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileOIDCClientWatcher implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileOIDCClientWatcher{}

// ReconcileOIDCClientWatcher reconciles a OIDCClientWatcher object
type ReconcileOIDCClientWatcher struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a OIDCClientWatcher object and makes changes based on the state read
// and what is in the OIDCClientWatcher.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a OIDCClientWatcher Deployment for each OIDCClientWatcher CR
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileOIDCClientWatcher) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling OIDCClientWatcher")

	// Fetch the OIDCClientWatcher instance
	instance := &operatorv1alpha1.OIDCClientWatcher{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not instance, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("OIDCClientWatcher resource not instance. Ignoring since object must be deleted")
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		reqLogger.Error(err, "Failed to get OIDCClientWatcher")
		return reconcile.Result{}, err
	}

	// Credit: kubebuilder book
	finalizerName := "oidclientwatcher.operator.ibm.com"
	// Determine if the OIDC ClientWatcher is going to be deleted
	if instance.ObjectMeta.DeletionTimestamp.IsZero() {
		// Object not being deleted, but add our finalizer so we know to remove this object later when it is going to be deleted
		if !containsString(instance.ObjectMeta.Finalizers, finalizerName) {
			instance.ObjectMeta.Finalizers = append(instance.ObjectMeta.Finalizers, finalizerName)
			if err := r.client.Update(context.Background(), instance); err != nil {
				log.Error(err, "Error adding the finalizer to the CR")
				return reconcile.Result{}, err
			}
		}
	} else {
		// Object scheduled to be deleted
		if containsString(instance.ObjectMeta.Finalizers, finalizerName) {
			if err := r.deleteExternalResources(instance); err != nil {
				log.Error(err, "Error deleting resources created by this operator")

				return reconcile.Result{}, err
			}

			instance.ObjectMeta.Finalizers = removeString(instance.ObjectMeta.Finalizers, finalizerName)
			if err := r.client.Update(context.Background(), instance); err != nil {
				log.Error(err, "Error updating the CR to remove the finalizer")
				return reconcile.Result{}, err
			}

		}
		return reconcile.Result{}, nil
	}

	// Check if this Deployment already exists and create it if it doesn't
	currentDeployment := &appsv1.Deployment{}
	recResult, err := r.handleDeployment(instance, currentDeployment)
	if err != nil {
		return recResult, err
	}

	currentClusterRole := &rbacv1.ClusterRole{}
	recResult, err = r.handleClusterRole(instance, currentClusterRole)
	if err != nil {
		return recResult, err
	}

	currentCRD := &extv1.CustomResourceDefinition{}
	recResult, err = r.handleCRD(instance, currentCRD)
	if err != nil {
		return recResult, err
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileOIDCClientWatcher) handleClusterRole(instance *operatorv1alpha1.OIDCClientWatcher, currentClusterRole *rbacv1.ClusterRole) (reconcile.Result, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "icp-oidc-client-admin-aggregate", Namespace: ""}, currentClusterRole)
	if err != nil && errors.IsNotFound(err) {
		// Define admin cluster role
		adminClusterRole := r.adminClusterRoleForOIDCClientWatcher(instance)
		reqLogger.Info("Creating a new ClusterRole", "ClusterRole.Namespace", instance.Namespace, "ClusterRole.Name", "icp-oidc-client-admin-aggregate")
		err = r.client.Create(context.TODO(), adminClusterRole)
		if err != nil {
			reqLogger.Error(err, "Failed to create new ClusterRole", "ClusterRole.Namespace", instance.Namespace, "ClusterRole.Name", "icp-oidc-client-admin-aggregate")
			return reconcile.Result{}, err
		}

	} else if err != nil {
		reqLogger.Error(err, "Failed to get ClusterRole")
		return reconcile.Result{}, err
	}

	err = r.client.Get(context.TODO(), types.NamespacedName{Name: "icp-oidc-client-operate-aggregate", Namespace: ""}, currentClusterRole)
	if err != nil && errors.IsNotFound(err) {
		// Define operator cluster role
		operatorClusterRole := r.operatorClusterRoleForOIDCClientWatcher(instance)
		reqLogger.Info("Creating a new ClusterRole", "ClusterRole.Namespace", instance.Namespace, "ClusterRole.Name", "icp-oidc-client-admin-aggregate")
		err = r.client.Create(context.TODO(), operatorClusterRole)
		if err != nil {
			reqLogger.Error(err, "Failed to create new ClusterRole", "ClusterRole.Namespace", instance.Namespace, "ClusterRole.Name", "icp-oidc-client-admin-aggregate")
			return reconcile.Result{}, err
		}
	} else if err != nil {
		reqLogger.Error(err, "Failed to get ClusterRole")
		return reconcile.Result{}, err
	}
	//admin roles created successfully
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileOIDCClientWatcher) handleCRD(instance *operatorv1alpha1.OIDCClientWatcher, currentCRD *extv1.CustomResourceDefinition) (reconcile.Result, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "clients.oidc.security.ibm.com", Namespace: ""}, currentCRD)
	if err != nil && errors.IsNotFound(err) {
		// Define CRD
		newCRD := r.crdForOIDCClientWatcher(instance)
		reqLogger.Info("Creating a new CRD", "CRD.Namespace", instance.Namespace, "CRD.Name", "clients.oidc.security.ibm.com")
		err = r.client.Create(context.TODO(), newCRD)
		if err != nil {
			reqLogger.Error(err, "Failed to create new CRD", "CRD.Namespace", instance.Namespace, "CRD.Name", "clients.oidc.security.ibm.com")
			return reconcile.Result{}, err
		}
		// new CRD created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get CRD")
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileOIDCClientWatcher) handleDeployment(instance *operatorv1alpha1.OIDCClientWatcher, currentDeployment *appsv1.Deployment) (reconcile.Result, error) {

	// Check if this Deployment already exists
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "oidcclient-watcher", Namespace: instance.Namespace}, currentDeployment)
	if err != nil && errors.IsNotFound(err) {
		// Define a new deployment
		ocwDep := r.deploymentForOIDCClientWatcher(instance)
		reqLogger.Info("Creating a new Deployment", "Deployment.Namespace", ocwDep.Namespace, "Deployment.Name", ocwDep.Name)
		err = r.client.Create(context.TODO(), ocwDep)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Deployment", "Deployment.Namespace", ocwDep.Namespace, "Deployment.Name", ocwDep.Name)
			return reconcile.Result{}, err
		}
		// Deployment created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Deployment")
		return reconcile.Result{}, err
	}

	// Ensure the deployment replicas is the same as the spec
	replicas := instance.Spec.Replicas
	if *currentDeployment.Spec.Replicas != replicas {
		currentDeployment.Spec.Replicas = &replicas
		err = r.client.Update(context.TODO(), instance)
		if err != nil {
			reqLogger.Error(err, "Failed to update Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", instance.Name)
			return reconcile.Result{}, err
		}
		// Spec updated - return and requeue
		return reconcile.Result{Requeue: true}, nil
	}

	// Update the OIDCClientWatcher status with the pod names
	// List the pods for this OIDCClientWatcher's deployment
	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels(map[string]string{"app": "oidcclient-watcher"}),
	}
	if err = r.client.List(context.TODO(), podList, listOpts...); err != nil {
		reqLogger.Error(err, "Failed to list pods", "OIDCClientWatcher.Namespace", instance.Namespace, "OIDCClientWatcher.Name", instance.Name)
		return reconcile.Result{}, err
	}
	podNames := getPodNames(podList.Items)

	// Update status.Nodes if needed
	if !reflect.DeepEqual(podNames, instance.Status.Nodes) {
		instance.Status.Nodes = podNames
		err := r.client.Status().Update(context.TODO(), instance)
		if err != nil {
			reqLogger.Error(err, "Failed to update OIDCClientWatcher status")
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil

}

func (r *ReconcileOIDCClientWatcher) adminClusterRoleForOIDCClientWatcher(instance *operatorv1alpha1.OIDCClientWatcher) *rbacv1.ClusterRole {
	//reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	adminClusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "icp-oidc-client-admin-aggregate",
			Labels: map[string]string{
				"kubernetes.io/bootstrapping":                  "rbac-defaults",
				"rbac.icp.com/aggregate-to-icp-admin":          "true",
				"rbac.authorization.k8s.io/aggregate-to-admin": "true",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"oidc.security.ibm.com"},
				Resources: []string{"clients"},
				Verbs:     []string{"create", "get", "list", "patch", "update", "watch", "delete"},
			},
		},
	}

	// Set OIDCClientWatcher instance as the owner and controller of the admin cluster role
	/*err := controllerutil.SetControllerReference(instance, adminClusterRole, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for admin Cluster Role")
		return nil
	}*/
	return adminClusterRole
}

func (r *ReconcileOIDCClientWatcher) operatorClusterRoleForOIDCClientWatcher(instance *operatorv1alpha1.OIDCClientWatcher) *rbacv1.ClusterRole {
	//reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	operatorClusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "icp-oidc-client-operate-aggregate",
			Labels: map[string]string{
				"kubernetes.io/bootstrapping":                 "rbac-defaults",
				"rbac.icp.com/aggregate-to-icp-operate":       "true",
				"rbac.authorization.k8s.io/aggregate-to-edit": "true",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"oidc.security.ibm.com"},
				Resources: []string{"clients"},
				Verbs:     []string{"create", "get", "list", "patch", "update", "watch", "delete"},
			},
		},
	}

	// Set OIDCClientWatcher instance as the owner and controller of the cluster role
	/*err := controllerutil.SetControllerReference(instance, operatorClusterRole, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for operator Cluster Role")
		return nil
	}*/
	return operatorClusterRole
}

func (r *ReconcileOIDCClientWatcher) crdForOIDCClientWatcher(instance *operatorv1alpha1.OIDCClientWatcher) *extv1.CustomResourceDefinition {
	//reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newCRD := &extv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "clients.oidc.security.ibm.com",
			Labels: map[string]string{
				"app": "oidcclient-watcher",
			},
			Namespace: "ibm-common-services",
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Scope:   "Namespaced",
			Group:   "oidc.security.ibm.com",
			Version: "v1",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:       "Client",
				Singular:   "client",
				Plural:     "clients",
				ShortNames: []string{"or"},
			},
			Validation: &extv1.CustomResourceValidation{
				OpenAPIV3Schema: &extv1.JSONSchemaProps{
					Properties: map[string]extv1.JSONSchemaProps{
						"apiVersion": extv1.JSONSchemaProps{
							Description: `APIVersion defines the versioned schema of this representation
							of an object. Servers should convert recognized schemas to the latest
							internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources`,
							Type: "string",
						},
						"kind": extv1.JSONSchemaProps{
							Description: `Kind is a string value representing the REST resource this
							object represents. Servers may infer this from the endpoint the client
							submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds`,
							Type: "string",
						},
						"metadata": extv1.JSONSchemaProps{
							Type: "object",
						},
						"spec": extv1.JSONSchemaProps{
							Type: "object",
						},
						"status": extv1.JSONSchemaProps{
							Type: "object",
						},
					},
				},
			},
			AdditionalPrinterColumns: []extv1.CustomResourceColumnDefinition{
				{
					Name:     "Secret",
					Type:     "string",
					JSONPath: ".spec.secret",
				},
				{
					Name:     "Ready",
					Type:     "string",
					JSONPath: `.status.conditions[?(@.type=="Ready")].status`,
				},
				{
					Name:     "Status",
					Type:     "string",
					JSONPath: `.status.conditions[?(@.type=="Ready")].message`,
					Priority: 1,
				},
				{
					Name:     "Age",
					Type:     "date",
					JSONPath: ".metadata.creationTimestamp",
					Description: `CreationTimestamp is a timestamp representing the server time when this object was created. It is not guaranteed to be set in happens-before order across separate operations. Clients may not set this value. It is represented in RFC3339 form and is in UTC.
					\nPopulated by the system. Read-only. Null for lists. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata`,
				},
			},
		},
	}

	return newCRD
}

// deploymentForOIDCClientWatcher returns a OIDCClientWatcher Deployment object
func (r *ReconcileOIDCClientWatcher) deploymentForOIDCClientWatcher(instance *operatorv1alpha1.OIDCClientWatcher) *appsv1.Deployment {
	reqLogger := log.WithValues("deploymentForOIDCClientWatcher", "Entry", "instance.Name", instance.Name)
	image := instance.Spec.ImageRegistry + ":" + instance.Spec.ImageTagPostfix
	replicas := instance.Spec.Replicas

	ocwDep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      oidcClientWatcherDeploymentName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app": "oidcclient-watcher",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "oidcclient-watcher",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":                        "oidcclient-watcher",
						"app.kubernetes.io/instance": "oidcclient-watcher",
					},
					Annotations: map[string]string{
						"scheduler.alpha.kubernetes.io/critical-pod": "",
						"productName":                        "IBM Cloud Platform Common Services",
						"productID":                          "068a62892a1e4db39641342e592daa25",
						"productVersion":                     "3.3.0",
						"productMetric":                      "FREE",
						"clusterhealth.ibm.com/dependencies": "cert-manager, common-mongodb, icp-management-ingress",
						"seccomp.security.alpha.kubernetes.io/pod": "docker/default",
					},
				},
				Spec: corev1.PodSpec{
					TerminationGracePeriodSeconds: &seconds60,
					ServiceAccountName:            serviceAccountName,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser: &runAsUser,
						FSGroup:   &fsGroup,
					},
					HostIPC: false,
					HostPID: false,
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
								NodeSelectorTerms: []corev1.NodeSelectorTerm{
									{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{
												Key:      "beta.kubernetes.io/arch",
												Operator: corev1.NodeSelectorOpIn,
												Values:   []string{gorun.GOARCH},
											},
										},
									},
								},
							},
						},
					},
					Tolerations: []corev1.Toleration{
						{
							Key:      "dedicated",
							Operator: corev1.TolerationOpExists,
							Effect:   corev1.TaintEffectNoSchedule,
						},
						{
							Key:      "CriticalAddonsOnly",
							Operator: corev1.TolerationOpExists,
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "tmp",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "oidcclient-watcher",
							Image:           image,
							ImagePullPolicy: corev1.PullAlways,
							Resources: corev1.ResourceRequirements{
								Limits: map[corev1.ResourceName]resource.Quantity{
									corev1.ResourceCPU:    *cpu200,
									corev1.ResourceMemory: *memory128},
								Requests: map[corev1.ResourceName]resource.Quantity{
									corev1.ResourceCPU:    *cpu10,
									corev1.ResourceMemory: *memory16},
							},
							Env: []corev1.EnvVar{
								{
									Name: "CLUSTER_NAME",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "platform-auth-idp",
											},
											Key: "CLUSTER_NAME",
										},
									},
								},
								{
									Name: "DEFAULT_ADMIN_USER",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "platform-auth-idp-credentials",
											},
											Key: "admin_username",
										},
									},
								},
								{
									Name: "DEFAULT_ADMIN_PASSWORD",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "platform-auth-idp-credentials",
											},
											Key: "admin_password",
										},
									},
								},
								{
									Name:  "IDENTITY_PROVIDER_URL",
									Value: "https://platform-identity-provider:4300",
								},
								{
									Name:  "IAM_AUTH_SERVICE_URL",
									Value: "https://platform-auth-service:9443",
								},
								{
									Name: "ROKS_URL",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "platform-auth-idp",
											},
											Key: "ROKS_URL",
										},
									},
								},
								{
									Name: "ROKS_ENABLED",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "platform-auth-idp",
											},
											Key: "ROKS_ENABLED",
										},
									},
								},
								{
									Name:  "IDENTITY_MGMT_URL",
									Value: "https://platform-identity-management:4500",
								},
								{
									Name:  "OPERATOR_NAME",
									Value: "icp-oidcclient-watcher",
								},
								{
									Name:  "OAUTH_ADMIN",
									Value: "oauthadmin",
								},
								{
									Name: "OAUTH2_CLIENT_REGISTRATION_SECRET",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "platform-oidc-credentials",
											},
											Key: "OAUTH2_CLIENT_REGISTRATION_SECRET",
										},
									},
								},
								{
									Name: "POD_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath:  "metadata.name",
										},
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "tmp",
									MountPath: "/tmp",
								},
							},
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{"ls"},
									},
								},
								InitialDelaySeconds: 30,
								PeriodSeconds:       15,
							},
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{"ls"},
									},
								},
								InitialDelaySeconds: 15,
								PeriodSeconds:       15,
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged:               &falseVar,
								RunAsNonRoot:             &trueVar,
								ReadOnlyRootFilesystem:   &trueVar,
								AllowPrivilegeEscalation: &falseVar,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
							},
						},
					},
				},
			},
		},
	}
	// Set OIDCClientWatcher instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, ocwDep, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Deployment")
		return nil
	}
	return ocwDep
}

// getPodNames returns the pod names of the array of pods passed in
func getPodNames(pods []corev1.Pod) []string {
	reqLogger := log.WithValues("Request.Namespace", "CS??? namespace", "Request.Name", "CS???")
	var podNames []string
	for _, pod := range pods {
		podNames = append(podNames, pod.Name)
		reqLogger.Info("CS??? pod name=" + pod.Name)
	}
	return podNames
}

// Removes some of the resources created by this controller for the CR including
// The clusterrole and custom resource definitions created by OIDC Client Watcher
func (r *ReconcileOIDCClientWatcher) deleteExternalResources(instance *operatorv1alpha1.OIDCClientWatcher) error {

	crList := []string{"icp-oidc-client-operate-aggregate", "icp-oidc-client-admin-aggregate"}
	crdList := []string{"clients.oidc.security.ibm.com"}
	// Remove Cluster Role

	for _, cr := range crList {
		if err := removeCR(r.client, cr); err != nil {
			return err
		}
	}

	// Remove CustomResourceDefinition

	for _, crd := range crdList {
		if err := removeCRD(r.client, crd); err != nil {
			return err
		}
	}

	return nil
}

// Helper functions to check and remove string from a slice of strings.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}

// Functions to remove cluster scoped resources

func removeCR(client client.Client, crName string) error {
	// Delete Clusterrole
	clusterRole := &rbacv1.ClusterRole{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: crName, Namespace: ""}, clusterRole); err != nil && errors.IsNotFound(err) {
		log.V(1).Info("Error getting cluster role", crName, err)
		return nil
	} else if err == nil {
		if err = client.Delete(context.Background(), clusterRole); err != nil {
			log.V(1).Info("Error deleting cluster role", "name", crName, "error message", err)
			return err
		}
	} else {
		return err
	}
	return nil
}

func removeCRD(client client.Client, crdName string) error {
	// Delete CustomResourceDefinition
	customResourceDefinition := &extv1.CustomResourceDefinition{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: crdName, Namespace: ""}, customResourceDefinition); err != nil && errors.IsNotFound(err) {
		log.V(1).Info("Error getting custome resource definition", "msg", err)
		return nil
	} else if err == nil {
		if err = client.Delete(context.Background(), customResourceDefinition); err != nil {
			log.V(1).Info("Error deleting custom resource definition", "name", crdName, "error message", err)
			return err
		}
	} else {
		return err
	}
	return nil
}
