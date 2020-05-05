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

package secretwatcher

import (
	"context"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	gorun "runtime"
	"github.com/IBM/ibm-iam-operator/pkg/controller/shas"
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
	"github.com/IBM/ibm-iam-operator/pkg/apis/controller/shas"
)

const secretWatcherDeploymentName = "secret-watcher"

var trueVar bool = true
var falseVar bool = false
var defaultMode int32 = 420
var seconds60 int64 = 60
var serviceAccountName string = "ibm-iam-operand-restricted"
var cpu50 = resource.NewMilliQuantity(50, resource.DecimalSI)          // 50m
var cpu200 = resource.NewMilliQuantity(200, resource.DecimalSI)        // 200m
var memory64 = resource.NewQuantity(64*1024*1024, resource.BinarySI)   // 64Mi
var memory256 = resource.NewQuantity(256*1024*1024, resource.BinarySI) // 256Mi

var log = logf.Log.WithName("controller_secretwatcher")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new SecretWatcher Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileSecretWatcher{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("secretwatcher-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource SecretWatcher
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.SecretWatcher{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner SecretWatcher
	err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.SecretWatcher{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileSecretWatcher implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileSecretWatcher{}

// ReconcileSecretWatcher reconciles a SecretWatcher object
type ReconcileSecretWatcher struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a SecretWatcher object and makes changes based on the state read
// and what is in the SecretWatcher.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a SecretWatcher Deployment for each SecretWatcher CR
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileSecretWatcher) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling SecretWatcher")

	// Fetch the SecretWatcher instance
	SecretWatcher := &operatorv1alpha1.SecretWatcher{}
	err := r.client.Get(context.TODO(), request.NamespacedName, SecretWatcher)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not instance, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("SecretWatcher resource not instance. Ignoring since object must be deleted")
			return reconcile.Result{}, nil
		} else {
			// Error reading the object - requeue the request.
			reqLogger.Error(err, "Failed to get SecretWatcher")
			return reconcile.Result{}, err
		}
	}

	// Check if the deployment already exists, if not create a new one
	instance := &appsv1.Deployment{}
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: "secret-watcher", Namespace: SecretWatcher.Namespace}, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Define a new deployment
			swDep := r.deploymentForSecretWatcher(SecretWatcher)
			reqLogger.Info("Creating a new Deployment", "Deployment.Namespace", swDep.Namespace, "Deployment.Name", swDep.Name)
			err = r.client.Create(context.TODO(), swDep)
			if err != nil {
				reqLogger.Error(err, "Failed to create new Deployment", "Deployment.Namespace", swDep.Namespace, "Deployment.Name", swDep.Name)
				return reconcile.Result{}, err
			}
			// Deployment created successfully - return and requeue
			return reconcile.Result{Requeue: true}, nil
		} else {
			reqLogger.Error(err, "Failed to get Deployment")
			return reconcile.Result{}, err
		}
	} else {
		reqLogger.Info("Updating an existing Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", instance.Name)
		newDeployment := r.deploymentForSecretWatcher(SecretWatcher)
		instance.Spec = newDeployment.Spec
		err = r.client.Update(context.TODO(), instance)
		if err != nil {
			reqLogger.Error(err, "Failed to update an existing Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", instance.Name)
			return reconcile.Result{}, err
		}
	}

	// Ensure the deployment replicas is the same as the spec
	replicas := SecretWatcher.Spec.Replicas
	if *instance.Spec.Replicas != replicas {
		instance.Spec.Replicas = &replicas
		err = r.client.Update(context.TODO(), instance)
		if err != nil {
			reqLogger.Error(err, "Failed to update Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", instance.Name)
			return reconcile.Result{}, err
		}
		// Spec updated - return and requeue
		return reconcile.Result{Requeue: true}, nil
	}

	// Update the SecretWatcher status with the pod names
	// List the pods for this SecretWatcher's deployment
	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(SecretWatcher.Namespace),
		client.MatchingLabels(labelsForSecretWatcherSelect(SecretWatcher.Name, instance.Name)),
	}
	if err = r.client.List(context.TODO(), podList, listOpts...); err != nil {
		reqLogger.Error(err, "Failed to list pods", "SecretWatcher.Namespace", SecretWatcher.Namespace, "SecretWatcher.Name", SecretWatcher.Name)
		return reconcile.Result{}, err
	}
	podNames := getPodNames(podList.Items)

	// Update status.Nodes if needed
	if !reflect.DeepEqual(podNames, SecretWatcher.Status.Nodes) {
		SecretWatcher.Status.Nodes = podNames
		err := r.client.Status().Update(context.TODO(), SecretWatcher)
		if err != nil {
			reqLogger.Error(err, "Failed to update SecretWatcher status")
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

// deploymentForSecretWatcher returns a SecretWatcher Deployment object
func (r *ReconcileSecretWatcher) deploymentForSecretWatcher(instance *operatorv1alpha1.SecretWatcher) *appsv1.Deployment {
	reqLogger := log.WithValues("deploymentForSecretWatcher", "Entry", "instance.Name", instance.Name)
	labels1 := labelsForSecretWatcherMeta(secretWatcherDeploymentName)
	labels2 := labelsForSecretWatcherSelect(instance.Name, secretWatcherDeploymentName)
	labels3 := labelsForSecretWatcherPod(instance.Name, secretWatcherDeploymentName)
	arch := gorun.GOARCH
	image := instance.Spec.ImageRegistry + "/" + instance.Spec.ImageName + "@" + shas.SecretWatcherSHA[arch]
	replicas := instance.Spec.Replicas

	swDep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretWatcherDeploymentName,
			Namespace: instance.Namespace,
			Labels:    labels1,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels2,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels3,
					Annotations: map[string]string{
						"scheduler.alpha.kubernetes.io/critical-pod": "",
						"productName":                        "IBM Cloud Platform Common Services",
						"productID":                          "068a62892a1e4db39641342e592daa25",
						"productVersion":                     "3.3.0",
						"productMetric":                      "FREE",
						"clusterhealth.ibm.com/dependencies": "cert-manager, common-mongodb, icp-management-ingress",
					},
				},
				Spec: corev1.PodSpec{
					TerminationGracePeriodSeconds: &seconds60, 
					HostIPC:            false,
					HostPID:            false,
					ServiceAccountName: serviceAccountName,
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
						{
							Name: "cluster-ca",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "cs-ca-certificate-secret",
									Items: []corev1.KeyToPath{
										{
											Key:  "tls.key",
											Path: "ca.key",
										},
										{
											Key:  "tls.crt",
											Path: "ca.crt",
										},
									},
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "secret-watcher",
							Image:           image,
							ImagePullPolicy: corev1.PullAlways,
							Env: []corev1.EnvVar{
								{
									Name: "ICP_API_KEY",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "icp-serviceid-apikey-secret",
											},
											Key: "ICP_API_KEY",
										},
									},
								},
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
									Name: "POD_NAMESPACE",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath:  "metadata.namespace",
										},
									},
								},
								{
									Name:  "IDENTITY_PROVIDER_URL",
									Value: "https://platform-identity-provider:4300",
								},
								{
									Name:  "IAM_TOKEN_SERVICE_URL",
									Value: "https://platform-auth-service:9443",
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: map[corev1.ResourceName]resource.Quantity{
									corev1.ResourceCPU:    *cpu200,
									corev1.ResourceMemory: *memory256},
								Requests: map[corev1.ResourceName]resource.Quantity{
									corev1.ResourceCPU:    *cpu50,
									corev1.ResourceMemory: *memory64},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "tmp",
									MountPath: "/tmp",
								},
								{
									Name:      "cluster-ca",
									MountPath: "/certs/cluster-ca",
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
	// Set SecretWatcher instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, swDep, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Deployment")
		return nil
	}
	return swDep
}

// labelsForSecretWatcher returns the labels for selecting the resources
// belonging to the given secret watcher CR name.
//CS??? need separate func for each image to set "instanceName"???
func labelsForSecretWatcherPod(instanceName string, deploymentName string) map[string]string {
	return map[string]string{"app": deploymentName, "component": "secret-watcher", "secretwatcher_cr": instanceName,
		"app.kubernetes.io/name": deploymentName, "app.kubernetes.io/component": "secret-watcher", "app.kubernetes.io/instance": "secret-watcher", "release": "secret-watcher"}
}

//CS??? need separate func for each image to set "app"???
func labelsForSecretWatcherSelect(instanceName string, deploymentName string) map[string]string {
	return map[string]string{"app": deploymentName, "component": "secret-watcher", "secretwatcher_cr": instanceName}
}

//CS???
func labelsForSecretWatcherMeta(deploymentName string) map[string]string {
	return map[string]string{"app.kubernetes.io/name": deploymentName, "app.kubernetes.io/component": "secret-watcher", "release": "secret-watcher"}
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
