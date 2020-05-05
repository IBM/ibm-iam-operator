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

package policycontroller

import (
	"context"
	"reflect"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	gorun "runtime"
	"github.com/IBM/ibm-iam-operator/pkg/controller/shas"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const iamPolicyControllerDepName = "iam-policy-controller"

var trueVar bool = true
var falseVar bool = false
var defaultMode int32 = 420
var seconds60 int64 = 60
var cpu100 = resource.NewMilliQuantity(100, resource.DecimalSI)        // 100m
var cpu200 = resource.NewMilliQuantity(200, resource.DecimalSI)        // 200m
var memory256 = resource.NewQuantity(256*1024*1024, resource.BinarySI) // 256Mi
var memory128 = resource.NewQuantity(128*1024*1024, resource.BinarySI) // 128Mi
var serviceAccountName string = "ibm-iam-operand-restricted"

var log = logf.Log.WithName("controller_policycontroller")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new PolicyController Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcilePolicyController{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("policycontroller-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource PolicyController
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.PolicyController{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner PolicyController
	err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.PolicyController{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcilePolicyController implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcilePolicyController{}

// ReconcilePolicyController reconciles a PolicyController object
type ReconcilePolicyController struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a PolicyController object and makes changes based on the state read
// and what is in the PolicyController.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcilePolicyController) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling PolicyController")

	// Fetch the PolicyController instance
	instance := &operatorv1alpha1.PolicyController{}
	recErr := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if recErr != nil {
		if errors.IsNotFound(recErr) {
			// Request object not instance, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("PolicyController resource instance not found. Ignoring since object must be deleted")
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		reqLogger.Error(recErr, "Failed to get deploymentForPolicyController")
		return reconcile.Result{}, recErr
	}

	// Credit: kubebuilder book
	finalizerName := "policycontroller.operator.ibm.com"
	// Determine if the Policy Controller CR is going to be deleted
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

	// If the Deployment does not exist, create it
	iamPolControllerDeployment := &appsv1.Deployment{}
	recResult, recErr := r.handleDeployment(instance, iamPolControllerDeployment)
	if recErr != nil {
		return recResult, recErr
	}

	// If the CustomResourceDefinition does not exist, create it
	iamPolControllerCRD := &extv1.CustomResourceDefinition{}
	recResult, recErr = r.handleCRD(instance, iamPolControllerCRD)
	if recErr != nil {
		return recResult, recErr
	}

	// If the ClusterRole does not exist, create it
	iamPolControllerClusterRole := &rbacv1.ClusterRole{}
	recResult, recErr = r.handleClusterRole(instance, iamPolControllerClusterRole)
	if recErr != nil {
		return recResult, recErr
	}

	// If the ClusterRoleBinding does not exist, create it
	iamPolControllerClusterRoleBinding := &rbacv1.ClusterRoleBinding{}
	recResult, recErr = r.handleClusterRoleBinding(instance, iamPolControllerClusterRoleBinding)
	if recErr != nil {
		return recResult, recErr
	}

	return reconcile.Result{}, nil
}

func (r *ReconcilePolicyController) handleClusterRoleBinding(instance *operatorv1alpha1.PolicyController, currentClusterRoleBinding *rbacv1.ClusterRoleBinding) (reconcile.Result, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "iam-policy-controller-rolebinding", Namespace: ""}, currentClusterRoleBinding)
	if err != nil && errors.IsNotFound(err) {
		// Define  Cluster Rolebinding
		clusterRoleBinding := r.clusterRoleBindingForPolicyController(instance)
		reqLogger.Info("Creating ClusterRoleBinding", "ClusterRoleBinding.Namespace", instance.Namespace, "ClusterRoleBinding.Name", "iam-policy-controller-rolebinding")
		err = r.client.Create(context.TODO(), clusterRoleBinding)
		if err != nil {
			reqLogger.Error(err, "Failed to create ClusterRoleBinding", "ClusterRoleBinding.Namespace", instance.Namespace, "ClusterRoleBinding.Name", "iam-policy-controller-rolebinding")
			return reconcile.Result{}, err
		}

	} else if err != nil {
		reqLogger.Error(err, "Failed to get ClusterRoleBinding")
		return reconcile.Result{}, err
	}
	//Cluster rolebinding has created successfully
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcilePolicyController) handleClusterRole(instance *operatorv1alpha1.PolicyController, currentClusterRole *rbacv1.ClusterRole) (reconcile.Result, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "iam-policy-controller-role", Namespace: ""}, currentClusterRole)
	if err != nil && errors.IsNotFound(err) {
		// Define cluster role
		clusterRole := r.clusterRoleForPolicyController(instance)
		reqLogger.Info("Creating ClusterRole", "ClusterRole.Namespace", instance.Namespace, "ClusterRole.Name", "iam-policy-controller-role")
		err = r.client.Create(context.TODO(), clusterRole)
		if err != nil {
			reqLogger.Error(err, "Failed to create ClusterRole", "ClusterRole.Namespace", instance.Namespace, "ClusterRole.Name", "iam-policy-controller-role")
			return reconcile.Result{}, err
		}

	} else if err != nil {
		reqLogger.Error(err, "Failed to get ClusterRole")
		return reconcile.Result{}, err
	}
	//Cluster Adminstrator roles created successfully
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcilePolicyController) handleCRD(instance *operatorv1alpha1.PolicyController, currentCRD *extv1.CustomResourceDefinition) (reconcile.Result, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "iampolicies.iam.policies.ibm.com", Namespace: ""}, currentCRD)
	if err != nil && errors.IsNotFound(err) {
		// Define CustomResourceDefinition
		newCRD := r.custResourceDefinitionForPolicyController(instance)
		reqLogger.Info("Creating CustomResourceDefinition", "newCRD.Namespace", instance.Namespace, "newCRD.Name", "iampolicies.iam.policies.ibm.com")
		err = r.client.Create(context.TODO(), newCRD)
		if err != nil {
			reqLogger.Error(err, "Failed to create CustomResourceDefinition", "newCRD.Namespace", instance.Namespace, "newCRD.Name", "iampolicies.iam.policies.ibm.com")
			return reconcile.Result{}, err
		}
		// new CustomResourceDefinition created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get CustomResourceDefinition")
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func (r *ReconcilePolicyController) handleDeployment(instance *operatorv1alpha1.PolicyController, currentDeployment *appsv1.Deployment) (reconcile.Result, error) {

	// Check if this Deployment already exists
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: iamPolicyControllerDepName, Namespace: instance.Namespace}, currentDeployment)
	if err != nil {
		if errors.IsNotFound(err) {
			// Define a new deployment
			ocwDep := r.deploymentForPolicyController(instance)
			reqLogger.Info("Creating Deployment", "Deployment.Namespace", ocwDep.Namespace, "Deployment.Name", ocwDep.Name)
			err = r.client.Create(context.TODO(), ocwDep)
			if err != nil {
				reqLogger.Error(err, "Failed to create Deployment", "Deployment.Namespace", ocwDep.Namespace, "Deployment.Name", ocwDep.Name)
				return reconcile.Result{}, err
			}
			// Deployment created successfully - return and requeue
			return reconcile.Result{Requeue: true}, nil
		} else {
			reqLogger.Error(err, "Failed to get Deployment")
			return reconcile.Result{}, err
		}
	} else {
		newDeployment := r.deploymentForPolicyController(instance)
		currentDeployment.Spec = newDeployment.Spec
		reqLogger.Info("Updating an existing Deployment", "Deployment.Namespace", currentDeployment.Namespace, "Deployment.Name", currentDeployment.Name)
		err = r.client.Update(context.TODO(), currentDeployment)
		if err != nil {
			reqLogger.Error(err, "Failed to update an existing Deployment", "Deployment.Namespace", currentDeployment.Namespace, "Deployment.Name", currentDeployment.Name)
			return reconcile.Result{}, err
		}
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

	// Update the PolicyController status with the pod names
	// List the pods for this PolicyController deployment
	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels(map[string]string{"app": "iam-policy-controller"}),
	}
	if err = r.client.List(context.TODO(), podList, listOpts...); err != nil {
		reqLogger.Error(err, "Failed to list pods", "PolicyController", instance.Namespace, "PolicyController.Name", instance.Name)
		return reconcile.Result{}, err
	}
	podNames := getPodNames(podList.Items)

	// Update status.Nodes if needed
	if !reflect.DeepEqual(podNames, instance.Status.Nodes) {
		instance.Status.Nodes = podNames
		err := r.client.Status().Update(context.TODO(), instance)
		if err != nil {
			reqLogger.Error(err, "Failed to update PolicyController status")
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil

}

func (r *ReconcilePolicyController) clusterRoleForPolicyController(instance *operatorv1alpha1.PolicyController) *rbacv1.ClusterRole {
	//reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "iam-policy-controller-role",
			Labels: map[string]string{
				"app": "iam-policy-controller",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"grc-mcmpolicy.ibm.com"},
				Resources: []string{"Iampolicies", "namespaces"},
				Verbs:     []string{"create", "get", "list", "patch", "update", "watch", "delete"},
			},
		},
	}

	// Set PolicyController instance as the owner and controller of the Cluster Role
	/*err := controllerutil.SetControllerReference(instance, clusterRole, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for ClusterRole")
		return nil
	}*/
	return clusterRole
}

func (r *ReconcilePolicyController) clusterRoleBindingForPolicyController(instance *operatorv1alpha1.PolicyController) *rbacv1.ClusterRoleBinding {
	//reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	clusRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "iam-policy-controller-rolebinding",
			Labels: map[string]string{
				"app": "iam-policy-controller",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "iam-policy-controller-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "default",
				Namespace: "system",
			},
		},
	}
	// Set PolicyController instance as the owner and controller of the ClusterRoleBinding
	/*err := controllerutil.SetControllerReference(instance, clusRoleBinding, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for ClusterRoleBinding")
		return nil
	}*/
	return clusRoleBinding
}

func (r *ReconcilePolicyController) custResourceDefinitionForPolicyController(instance *operatorv1alpha1.PolicyController) *extv1.CustomResourceDefinition {
	//reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newCRD := &extv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "iampolicies.iam.policies.ibm.com",
			Labels: map[string]string{
				"app": "iam-policy-controller",
			},
			Namespace: instance.Namespace,
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Scope:   "Namespaced",
			Group:   "iam.policies.ibm.com",
			Version: "v1alpha1",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:       "IamPolicy",
				Singular:   "iampolicy",
				Plural:     "iampolicies",
				ShortNames: []string{"or"},
			},
			Validation: &extv1.CustomResourceValidation{
				OpenAPIV3Schema: &extv1.JSONSchemaProps{
					Properties: map[string]extv1.JSONSchemaProps{
						"labelSelector": extv1.JSONSchemaProps{
							Description: `selecting a list of namespaces where the policy applies`,
							Type:        "object",
						},
						"maxClusterRoleBindingUsers": extv1.JSONSchemaProps{
							Description: `selecting a list of namespaces where the policy applies`,
							Type:        "integer",
							Format:      "int64",
						},
						"maxRoleBindingViolationsPerNamespace": extv1.JSONSchemaProps{
							Type:   "integer",
							Format: "int64",
						},
						"namespaceSelector": extv1.JSONSchemaProps{
							Description: `enforce, inform`,
							Type:        "string",
						},
						"remediationAction": extv1.JSONSchemaProps{
							Type: "string",
						},
					},
				},
			},
			AdditionalPrinterColumns: []extv1.CustomResourceColumnDefinition{
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

// deploymentForPolicyController returns a IAM PolicyController Deployment object
func (r *ReconcilePolicyController) deploymentForPolicyController(instance *operatorv1alpha1.PolicyController) *appsv1.Deployment {
	reqLogger := log.WithValues("deploymentForPolicyController", "Entry", "instance.Name", instance.Name)
	arch := gorun.GOARCH
	image := instance.Spec.ImageRegistry + "/" + instance.Spec.ImageName + "@" + shas.PolicyControllerSHA[arch]
	replicas := instance.Spec.Replicas

	iamPolicyDep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      iamPolicyControllerDepName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app": "iam-policy-controller",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "iam-policy-controller",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":                        "iam-policy-controller",
						"app.kubernetes.io/instance": "iam-policy-controller",
					},
					Annotations: map[string]string{
						"productName":                        "IBM Cloud Platform Common Services",
						"productID":                          "068a62892a1e4db39641342e592daa25",
						"productVersion":                     "3.3.0",
						"productMetric":                      "FREE",
						"clusterhealth.ibm.com/dependencies": "cert-manager, common-mongodb, icp-management-ingress",
					},
				},
				Spec: corev1.PodSpec{
					TerminationGracePeriodSeconds: &seconds60,
					ServiceAccountName: serviceAccountName,
					HostNetwork:        false,
					HostIPC:            false,
					HostPID:            false,
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
							Name:            iamPolicyControllerDepName,
							Image:           image,
							ImagePullPolicy: corev1.PullAlways,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "tmp",
									MountPath: "/tmp",
								},
							},
							Args: []string{"--v=0", "--update-frequency=60"},
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{"sh", "-c", "pgrep iam-policy -l"},
									},
								},
								InitialDelaySeconds: 30,
								TimeoutSeconds:      5,
							},
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{"sh", "-c", "exec echo start iam-policy-controller"},
									},
								},
								InitialDelaySeconds: 10,
								TimeoutSeconds:      2,
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
							Resources: corev1.ResourceRequirements{
								Limits: map[corev1.ResourceName]resource.Quantity{
									corev1.ResourceCPU:    *cpu200,
									corev1.ResourceMemory: *memory256},
								Requests: map[corev1.ResourceName]resource.Quantity{
									corev1.ResourceCPU:    *cpu100,
									corev1.ResourceMemory: *memory128},
							},
						},
					},
				},
			},
		},
	}
	// Set PolicyController  instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, iamPolicyDep, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Deployment")
		return nil
	}
	return iamPolicyDep
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
// The clusterrole, clusterrolebinding custom resource definition created by Policy Controller
func (r *ReconcilePolicyController) deleteExternalResources(instance *operatorv1alpha1.PolicyController) error {

	crName := "iam-policy-controller-role"
	crbName := "iam-policy-controller-rolebinding"
	crdName := "iampolicies.iam.policies.ibm.com"

	// Remove Cluster Role

	if err := removeCR(r.client, crName); err != nil {
		return err
	}

	// Remove Cluster Role Binding

	if err := removeCRB(r.client, crbName); err != nil {
		return err
	}

	// Remove CustomResourceDefinition

	if err := removeCRD(r.client, crdName); err != nil {
		return err
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

func removeCRB(client client.Client, crbName string) error {
	// Delete ClusterRoleBinding
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: crbName, Namespace: ""}, clusterRoleBinding); err != nil && errors.IsNotFound(err) {
		log.V(1).Info("Error getting cluster role binding", crbName, err)
		return nil
	} else if err == nil {
		if err = client.Delete(context.Background(), clusterRoleBinding); err != nil {
			log.V(1).Info("Error deleting cluster role binding", "name", crbName, "error message", err)
			return err
		}
	} else {
		return err
	}
	return nil
}

func removeCRD(client client.Client, crdName string) error {
	// Delete CustomResourceDefintion
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
