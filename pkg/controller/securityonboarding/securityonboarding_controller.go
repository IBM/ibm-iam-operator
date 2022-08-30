//
// Copyright 2020, 2021 IBM Corporation
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

package securityonboarding

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"reflect"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/pkg/controller/shatag"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_securityonboarding")
var cpu20 = resource.NewMilliQuantity(20, resource.DecimalSI)            // 20m
var cpu100 = resource.NewMilliQuantity(100, resource.DecimalSI)          // 100m
var cpu200 = resource.NewMilliQuantity(200, resource.DecimalSI)          // 200m
var memory256 = resource.NewQuantity(256*1024*1024, resource.BinarySI)   // 256Mi
var memory128 = resource.NewQuantity(128*1024*1024, resource.BinarySI)   // 128Mi
var memory64 = resource.NewQuantity(64*1024*1024, resource.BinarySI)     // 64Mi
var memory512 = resource.NewQuantity(512*1024*1024, resource.BinarySI)   // 512Mi
var memory1024 = resource.NewQuantity(1024*1024*1024, resource.BinarySI) // 1024Mi
var trueVar bool = true
var falseVar bool = false
var serviceAccountName string = "ibm-iam-operand-restricted"

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new SecurityOnboarding Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileSecurityOnboarding{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("securityonboarding-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource SecurityOnboarding
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.SecurityOnboarding{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner SecurityOnboarding
	err = c.Watch(&source.Kind{Type: &corev1.Pod{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.SecurityOnboarding{},
	})
	if err != nil {
		return err
	}

	//watch for configMap creation.
	err = c.Watch(&source.Kind{Type: &corev1.ConfigMap{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.SecurityOnboarding{},
	})
	if err != nil {
		return err
	}

	//watch for JobCreation creation.
	err = c.Watch(&source.Kind{Type: &batchv1.Job{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.SecurityOnboarding{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileSecurityOnboarding implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileSecurityOnboarding{}

// ReconcileSecurityOnboarding reconciles a SecurityOnboarding object
type ReconcileSecurityOnboarding struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a SecurityOnboarding object and makes changes based on the state read
// and what is in the SecurityOnboarding.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileSecurityOnboarding) Reconcile(context context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling SecurityOnboarding")

	// Fetch the SecurityOnboarding instance
	instance := &operatorv1alpha1.SecurityOnboarding{}
	err := r.client.Get(context, request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	recResult, err := r.handleConfigMap(instance)
	if err != nil {
		return recResult, err
	}

	reqLogger.Info("Complete - handleConfigMap")

	recResult, err = r.handleJob(instance)
	if err != nil {
		return recResult, err
	}

	reqLogger.Info("Complete - handleConfigMap")
	// Update the SecurityOnboarding status with the pod names
	// List the pods for this SecurityOnboarding's job
	jobList := &batchv1.JobList{}
	listOpts := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels(map[string]string{"app": "security-onboarding"}),
	}
	reqLogger.Info("Complete - got job list")
	if err = r.client.List(context, jobList, listOpts...); err != nil {
		reqLogger.Error(err, "Failed to list jobs", "SecurityOnboarding.Namespace", instance.Namespace, "SecurityOnboarding.Name", instance.Name)
		return reconcile.Result{}, err
	}
	jobNames := getJobNames(jobList.Items)
	// Update status.Nodes if needed
	if !reflect.DeepEqual(jobNames, instance.Status.PodNames) {
		instance.Status.PodNames = jobNames
		err := r.client.Status().Update(context, instance)
		if err != nil {
			reqLogger.Error(err, "Failed to update SecurityOnboarding status")
			return reconcile.Result{}, err
		}
	}
	return reconcile.Result{}, nil
}

// getJobNames returns the pod names of the array of pods passed in
func getJobNames(jobs []batchv1.Job) []string {
	reqLogger := log.WithValues("Request.Namespace", "CS??? namespace", "Request.Name", "CS???")
	var jobNames []string
	for _, job := range jobs {
		jobNames = append(jobNames, job.Name)
		reqLogger.Info("CS??? pod name=" + job.Name)
	}
	return jobNames
}

func (r *ReconcileSecurityOnboarding) handleConfigMap(instance *operatorv1alpha1.SecurityOnboarding) (reconcile.Result, error) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	m := []string{"ElasticSearch", "HelmApi", "HelmRepo", "Kms", "Monitoring", "TillerService", "Tiller_Serviceid_Policies", "Onboard_Script", "Onboard_Py3_Script"}

	foundErr := false
	for _, ele := range m {
		configExists := false
		reqLogger.Info("Creating a new ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", ele)
		newConfigMap, err := createConfigMap(instance, r, ele)
		if err != nil {
			//			reqLogger.Error(err, "Failed to create new ConfigMap -1, exists already ", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", ele)
			reqLogger.Info("Failed to create new ConfigMap -1, exists already ", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", ele)
			configExists = true
		}

		if !configExists {
			err = r.client.Create(context.TODO(), newConfigMap)
			if err != nil {
				reqLogger.Error(err, "Failed to create new ConfigMap - 2", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", ele)
				foundErr = true
			} else {
				reqLogger.Info("Successfully created ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", ele)
			}
		}
	}

	if foundErr {
		return reconcile.Result{}, nil
	} else {
		return reconcile.Result{Requeue: true}, nil
	}
}

/*
 * Generic method to create a ConfigMap given a Access Policy file.
 */
func createConfigMap(instance *operatorv1alpha1.SecurityOnboarding, r *ReconcileSecurityOnboarding, configName string) (*corev1.ConfigMap, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)

	err0, accessPolicy := getAccessPolicy(configName)
	if err0 != nil {
		return nil, err0
	}

	dataKey, val0, tmpStr := "", "", ""
	tmpStr = strings.ReplaceAll(strings.ToLower(configName), "_", "-")
	//tmpStr = strings.ToLower(configName)
	if strings.HasSuffix(tmpStr, "-script") {
		dataKey = tmpStr + ".py"
		val0 = tmpStr
	} else if tmpStr == "tiller-serviceid-policies" {
		dataKey = "tiller_serviceid_policies" + ".json"
		val0 = tmpStr
	} else {
		dataKey = "action_role_" + tmpStr + ".json"
		val0 = tmpStr + "-json"
	}

	//Check if the config map is already created, if exists throw error
	currentConfigMap := &corev1.ConfigMap{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: val0, Namespace: instance.Namespace}, currentConfigMap)
	if err == nil {
		return currentConfigMap, fmt.Errorf("Config Map %v already exists.", val0)
	}

	accessPolicy = strings.ReplaceAll(accessPolicy, "NAMESPACE", instance.Namespace)

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      val0,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "security-onboarding"},
		},
		Data: map[string]string{
			dataKey: accessPolicy,
		},
	}

	// Set SecurityOnboarding instance as the owner and controller of the ConfigMap
	err1 := controllerutil.SetControllerReference(instance, configMap, r.scheme)

	if err1 != nil {
		reqLogger.Error(err1, "Failed to set owner for ConfigMap")
		return configMap, err1
	}

	return configMap, nil
}

/*
 * Generic method to return Access Policy json file as a 'string'.
 */
func getAccessPolicy(label string) (error, string) {

	if label == "ElasticSearch" {
		return nil, operatorv1alpha1.ElasticSearch
	} else if label == "HelmApi" {
		return nil, operatorv1alpha1.HelmApi
	} else if label == "HelmRepo" {
		return nil, operatorv1alpha1.HelmRepo
	} else if label == "Kms" {
		return nil, operatorv1alpha1.Kms
	} else if label == "Monitoring" {
		return nil, operatorv1alpha1.Monitoring
	} else if label == "TillerService" {
		return nil, operatorv1alpha1.TillerService
	} else if label == "Tiller_Serviceid_Policies" {
		return nil, operatorv1alpha1.Tiller_Serviceid_Policies
	} else if label == "Onboard_Script" {
		return nil, operatorv1alpha1.Onboard_Script
	} else if label == "Onboard_Py3_Script" {
		return nil, operatorv1alpha1.Onboard_Py3_Script
	} else {
		return fmt.Errorf("Unknown label %s", label), ""
	}
}

func (r *ReconcileSecurityOnboarding) handleJob(instance *operatorv1alpha1.SecurityOnboarding) (reconcile.Result, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	//Create security-onboarding job
	securityOnboardJob, restartRequired, err := getSecurityOnboardJob(instance, r)

	secJobExists := false
	foundErr1 := false
	if err != nil {
		reqLogger.Info("Failed to create security-onboarding Job, exists already ", "Job.Namespace", instance.Namespace, "Job.Name", "security-onboarding")
		secJobExists = true
	}

	if !secJobExists {
		err = r.client.Create(context.TODO(), securityOnboardJob)
		if err != nil {
			reqLogger.Error(err, "Failed to create job", "Job.Namespace", instance.Namespace, "Job.Name", "security-onboarding")
			foundErr1 = true
		} else {
			reqLogger.Info("Successfully created Job", "Job.Namespace", instance.Namespace, "Job.Name", "security-onboarding")
		}
	} else if restartRequired {
		reqLogger.Info("Restart required for securityOnboardJob")
		err = r.client.Delete(context.TODO(), securityOnboardJob)
		if err != nil {
			reqLogger.Error(err, "Failed to delete job", "Job.Namespace", instance.Namespace, "Job.Name", "security-onboarding")
			foundErr1 = true
		} else {
			reqLogger.Info("Successfully deleted Job", "Job.Namespace", instance.Namespace, "Job.Name", "security-onboarding")
		}
	}

	//Create security-onboarding job
	iamOnboardJob, restartRequired, err := getIAMOnboardJob(instance, r)
	foundErr2 := false
	iamJobExists := false
	if err != nil {
		reqLogger.Info("Failed to create iam-onboarding Job, ", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
		reqLogger.Info("The err from IAMOnboardJob is ", err.Error())
		iamJobExists = true
	}

	if !iamJobExists {
		err = r.client.Create(context.TODO(), iamOnboardJob)
		if err != nil {
			reqLogger.Error(err, "Failed to create job", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
			foundErr2 = true
		} else {
			reqLogger.Info("Successfully created Job", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
		}
	} else if restartRequired {
		reqLogger.Info("Restart required for iamOnboardJob ", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
		err = r.client.Delete(context.TODO(), iamOnboardJob)
		if err != nil {
			reqLogger.Error(err, "Failed to delete job", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
			foundErr2 = true
		} else {
			reqLogger.Info("Successfully deleted Job", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
		}
	}

	if foundErr1 && foundErr2 {
		return reconcile.Result{}, nil
	} else {
		return reconcile.Result{Requeue: true}, nil
	}

}

func getSecurityOnboardJob(instance *operatorv1alpha1.SecurityOnboarding, r *ReconcileSecurityOnboarding) (*batchv1.Job, bool, error) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	//Create all the Volumes
	strVolName := []string{"onboard-script", "onboard-py3-script", "elasticsearch-json", "monitoring-json", "helmapi-json", "helmrepo-json",
		"tillerservice-json", "tiller-serviceid-policies", "kms-json"}
	resources := instance.Spec.Resources
	if resources == nil {
		resources = &corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    *cpu200,
				corev1.ResourceMemory: *memory512},
			Requests: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    *cpu20,
				corev1.ResourceMemory: *memory64},
		}
	}
	tmpInitContainers := []corev1.Container{
		{
			Name:            "init-auth-service",
			Command:         []string{"sh", "-c", "sleep 75; until curl -k -i -fsS https://platform-auth-service:9443/oidc/endpoint/OP/.well-known/openid-configuration | grep '200 OK'; do sleep 3; done;"},
			Image:           shatag.GetImageRef("ICP_PLATFORM_AUTH_IMAGE"),
			ImagePullPolicy: corev1.PullPolicy("Always"),
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
	}
	tmpVolumes := []corev1.Volume{}
	for _, ele := range strVolName {
		var mode int32 = 0744

		t := corev1.Volume{
			Name: ele,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: ele,
					},
					DefaultMode: &mode,
				},
			},
		}
		tmpVolumes = append(tmpVolumes, t)
	}

	t1 := corev1.Volume{
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
	}
	tmpVolumes = append(tmpVolumes, t1)

	tmpMounts := []corev1.VolumeMount{}
	//Create all the VolumeMounts
	volMounts := map[string]string{
		"onboard-py3-script":        "/app/scripts",
		"elasticsearch-json":        "/app/elasticsearch",
		"monitoring-json":           "/app/monitoring",
		"helmapi-json":              "/app/helmapi",
		"helmrepo-json":             "/app/helmrepo",
		"tillerservice-json":        "/app/tillerservice",
		"tiller-serviceid-policies": "/app/tiller_serviceid_policies",
		"cluster-ca":                "/app/cluster-ca",
		"kms-json":                  "/app/kms",
	}

	for k, v := range volMounts {
		t2 := corev1.VolumeMount{
			Name:      k,
			MountPath: v,
		}
		tmpMounts = append(tmpMounts, t2)
	}

	podSpec := corev1.PodSpec{
		RestartPolicy:      "OnFailure",
		ServiceAccountName: serviceAccountName,
		TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
			{
				MaxSkew:           1,
				TopologyKey:       "topology.kubernetes.io/zone",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "security-onboarding",
					},
				},
			},
			{
				MaxSkew:           1,
				TopologyKey:       "topology.kubernetes.io/region",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "security-onboarding",
					},
				},
			},
		},
		InitContainers: tmpInitContainers,
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
		Containers: []corev1.Container{
			{
				Name:            "security-onboarding",
				Image:           shatag.GetImageRef("ICP_IAM_ONBOARDING_IMAGE"),
				ImagePullPolicy: corev1.PullPolicy("Always"),
				//				Command:         []string{"python", "/app/scripts/onboard-script.py"},
				Command: []string{"python", "/app/scripts/onboard-py3-script.py"},
				SecurityContext: &corev1.SecurityContext{
					Privileged:               &falseVar,
					RunAsNonRoot:             &trueVar,
					ReadOnlyRootFilesystem:   &trueVar,
					AllowPrivilegeEscalation: &falseVar,
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				},
				Resources: *resources,
				Env: []corev1.EnvVar{
					{
						Name: "ICP_API_KEY",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								Key:                  "ICP_API_KEY",
								LocalObjectReference: corev1.LocalObjectReference{Name: "icp-serviceid-apikey-secret"},
							},
						},
					},
					{
						Name: "CLUSTER_NAME",
						ValueFrom: &corev1.EnvVarSource{
							ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
								Key:                  "CLUSTER_NAME",
								LocalObjectReference: corev1.LocalObjectReference{Name: "platform-auth-idp"},
							},
						},
					},
				},
				VolumeMounts: tmpMounts,
			},
		},
		Volumes: tmpVolumes,
	}

	//Check if the Job is already created, if exists throw error
	currentJob := &batchv1.Job{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "security-onboarding", Namespace: instance.Namespace}, currentJob)
	if err == nil {
		if currentJob.Spec.Template.Spec.Containers[0].Image != shatag.GetImageRef("ICP_IAM_ONBOARDING_IMAGE") {
			return currentJob, true, fmt.Errorf("Job %v already exists.", "security-onboarding")
		}
		return currentJob, false, fmt.Errorf("Job %v already exists.", "security-onboarding")
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "security-onboarding",
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app":                        "security-onboarding",
				"app.kubernetes.io/instance": "security-onboarding",
			},
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: "security-onboarding",
					Annotations: map[string]string{
						"scheduler.alpha.kubernetes.io/critical-pod": "",
						"productName":                        "IBM Cloud Platform Common Services",
						"productID":                          "068a62892a1e4db39641342e592daa25",
						"productMetric":                      "FREE",
						"clusterhealth.ibm.com/dependencies": "cert-manager, common-mongodb, icp-management-ingress",
					},
				},
				Spec: podSpec,
			},
		},
	}

	// Set SecurityOnboarding instance as the owner and controller of the Job
	err1 := controllerutil.SetControllerReference(instance, job, r.scheme)

	if err1 != nil {
		reqLogger.Error(err1, "Failed to set owner for security-onboarding Job")
		return job, false, err1
	}

	return job, false, nil

}

func getIAMOnboardJob(instance *operatorv1alpha1.SecurityOnboarding, r *ReconcileSecurityOnboarding) (*batchv1.Job, bool, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)

	resources := instance.Spec.IAMOnboarding.Resources

	if resources == nil {
		resources = &corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    *cpu200,
				corev1.ResourceMemory: *memory1024},
			Requests: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    *cpu20,
				corev1.ResourceMemory: *memory64},
		}
	}

	tmpEnvs := []corev1.EnvVar{
		{
			Name: "DEFAULT_ADMIN_USER",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key:                  "admin_username",
					LocalObjectReference: corev1.LocalObjectReference{Name: "platform-auth-idp-credentials"},
				},
			},
		},
		{
			Name: "AUDIT_ENABLED",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					Key:                  "AUDIT_ENABLED",
					LocalObjectReference: corev1.LocalObjectReference{Name: "auth-pdp"},
				},
			},
		},
		{
			Name: "DEFAULT_ADMIN_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key:                  "admin_password",
					LocalObjectReference: corev1.LocalObjectReference{Name: "platform-auth-idp-credentials"},
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
			Name: "CLUSTER_NAME",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					Key:                  "CLUSTER_NAME",
					LocalObjectReference: corev1.LocalObjectReference{Name: "platform-auth-idp"},
				},
			},
		},
		{
			Name: "IBM_CLOUD_SAAS",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					Key:                  "IBM_CLOUD_SAAS",
					LocalObjectReference: corev1.LocalObjectReference{Name: "platform-auth-idp"},
				},
			},
		},
		{
			Name:  "MONGO_DB",
			Value: "platform-db",
		},
		{
			Name:  "MONGO_COLLECTION",
			Value: "iam",
		},
		{
			Name: "MONGO_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key:                  "user",
					LocalObjectReference: corev1.LocalObjectReference{Name: "icp-mongodb-admin"},
				},
			},
		},
		{
			Name: "MONGO_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key:                  "password",
					LocalObjectReference: corev1.LocalObjectReference{Name: "icp-mongodb-admin"},
				},
			},
		},
		{
			Name:  "MONGO_HOST",
			Value: "mongodb",
		},
		{
			Name:  "MONGO_PORT",
			Value: "27017",
		},
		{
			Name:  "MONGO_AUTHSOURCE",
			Value: "admin",
		},
		{
			Name:  "CF_DB_NAME",
			Value: "security-data",
		},
		{
			Name:  "DB_NAME",
			Value: "platform-db",
		},
		{
			Name:  "CAMS_PDP_URL",
			Value: "https://iam-pdp:7998",
		},
		{
			Name:  "IAM_TOKEN_SERVICE_URL",
			Value: "https://platform-auth-service:9443",
		},
		{
			Name:  "IDENTITY_PROVIDER_URL",
			Value: "https://platform-identity-provider:4300",
		},
		{
			Name:  "IAM_PAP_URL",
			Value: "https://iam-pap:39001",
		},
		{
			Name: "NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "metadata.namespace",
				},
			},
		},
		{
			Name: "DEFAULT_TTL",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					Key:                  "PDP_REDIS_CACHE_DEFAULT_TTL",
					LocalObjectReference: corev1.LocalObjectReference{Name: "platform-auth-idp"},
				},
			},
		},
		{
			Name:  "WORKERS",
			Value: "15",
		},
	}

	tmpInitContainers := []corev1.Container{
		{
			Name:            "init-auth-service",
			Command:         []string{"sh", "-c", "sleep 75; until curl -k -i -fsS https://platform-auth-service:9443/oidc/endpoint/OP/.well-known/openid-configuration | grep '200 OK'; do sleep 3; done;"},
			Image:           shatag.GetImageRef("ICP_PLATFORM_AUTH_IMAGE"),
			ImagePullPolicy: corev1.PullPolicy("Always"),
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
		{
			Name:            "init-identity-provider",
			Command:         []string{"sh", "-c", "until curl -k -i -fsS https://platform-identity-provider:4300 | grep '200 OK'; do sleep 3; done;"},
			Image:           shatag.GetImageRef("ICP_PLATFORM_AUTH_IMAGE"),
			ImagePullPolicy: corev1.PullPolicy("Always"),
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "cluster-ca",
					MountPath: "/certs",
				},
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
		{
			Name:            "init-identity-manager",
			Command:         []string{"sh", "-c", "until curl -k -i -fsS https://platform-identity-management:4500 | grep '200 OK'; do sleep 3; done;"},
			Image:           shatag.GetImageRef("ICP_PLATFORM_AUTH_IMAGE"),
			ImagePullPolicy: corev1.PullPolicy("Always"),
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "cluster-ca",
					MountPath: "/certs",
				},
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
		{
			Name:            "init-token-service",
			Command:         []string{"sh", "-c", "until curl -k -i -fsS https://platform-auth-service:9443/iam/oidc/keys | grep '200 OK'; do sleep 3; done;"},
			Image:           shatag.GetImageRef("ICP_PLATFORM_AUTH_IMAGE"),
			ImagePullPolicy: corev1.PullPolicy("Always"),
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
		{
			Name:            "init-pap",
			Command:         []string{"sh", "-c", "until curl -k -i -fsS https://iam-pap:39001/v1/health | grep '200 OK'; do sleep 3; done;"},
			Image:           shatag.GetImageRef("ICP_PLATFORM_AUTH_IMAGE"),
			ImagePullPolicy: corev1.PullPolicy("Always"),
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "cluster-ca",
					MountPath: "/certs",
				},
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
		{
			Name:            "init-token-validation",
			Command:         []string{"python", "/app/acs_utils/build/init_token_validation.py"},
			Image:           shatag.GetImageRef("ICP_IAM_ONBOARDING_IMAGE"),
			ImagePullPolicy: corev1.PullPolicy("Always"),
			SecurityContext: &corev1.SecurityContext{
				Privileged:               &falseVar,
				RunAsNonRoot:             &trueVar,
				ReadOnlyRootFilesystem:   &trueVar,
				AllowPrivilegeEscalation: &falseVar,
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			},
			Resources: *resources,
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "mongodb-ca-cert",
					MountPath: "/certs/mongodb-ca",
				},
				{
					Name:      "auth-pdp-secret",
					MountPath: "/certs/auth-pdp",
				},
				{
					Name:      "cluster-ca",
					MountPath: "/certs",
				},
				{
					Name:      "shared",
					MountPath: "/app/logs/audit",
				},
				{
					Name:      "mongodb-client-cert",
					MountPath: "/certs/mongodb-client",
				},
			},
			Env: tmpEnvs,
		},
	}
	var mode1, mode2, mode3, mode4 int32 = 420, 420, 420, 420
	tmpVolumes := []corev1.Volume{
		{
			Name: "mongodb-ca-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "mongodb-root-ca-cert",
				},
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
					DefaultMode: &mode1,
				},
			},
		},
		{
			Name: "auth-pdp-secret",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "auth-pdp-secret",
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
					DefaultMode: &mode2,
				},
			},
		},
		{
			Name: "shared",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: "",
				},
			},
		},
		{
			Name: "logrotate",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "auth-pdp",
					},
					DefaultMode: &mode3,
					Items: []corev1.KeyToPath{
						{
							Key:  "logrotate",
							Path: "audit",
						},
					},
				},
			},
		},
		{
			Name: "logrotate-conf",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "auth-pdp",
					},
					DefaultMode: &mode4,
					Items: []corev1.KeyToPath{
						{
							Key:  "logrotate-conf",
							Path: "logrotate.conf",
						},
					},
				},
			},
		},
		{
			Name: "mongodb-client-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "icp-mongodb-client-cert",
				},
			},
		},
	}

	if instance.Spec.Config.EnableImpersonation {
		tmpEnvs = append(tmpEnvs, corev1.EnvVar{
			Name:  "ENABLE_IMPERSONATION",
			Value: "true",
		})
		tmpEnvs = append(tmpEnvs, corev1.EnvVar{
			Name:  "KUBE_APISERVER_HOST",
			Value: "icp-management-ingress",
		})
		tmpEnvs = append(tmpEnvs, corev1.EnvVar{
			Name:  "KUBERNETES_SERVICE_HOST",
			Value: "icp-management-ingress",
		})
	}

	podSpec := corev1.PodSpec{
		RestartPolicy:      "OnFailure",
		InitContainers:     tmpInitContainers,
		Volumes:            tmpVolumes,
		ServiceAccountName: serviceAccountName,
		TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
			{
				MaxSkew:           1,
				TopologyKey:       "topology.kubernetes.io/zone",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "iam-onboarding",
					},
				},
			},
			{
				MaxSkew:           1,
				TopologyKey:       "topology.kubernetes.io/region",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "iam-onboarding",
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
		Containers: []corev1.Container{
			{
				Name:            "iam-onboarding",
				Command:         []string{"python", "/app/acs_utils/build/icp_iam_am_bootstrap.py"},
				Image:           shatag.GetImageRef("ICP_IAM_ONBOARDING_IMAGE"),
				ImagePullPolicy: corev1.PullPolicy("Always"),
				SecurityContext: &corev1.SecurityContext{
					Privileged:               &falseVar,
					RunAsNonRoot:             &trueVar,
					ReadOnlyRootFilesystem:   &trueVar,
					AllowPrivilegeEscalation: &falseVar,
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				},
				Resources: *resources,
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "mongodb-ca-cert",
						MountPath: "/certs/mongodb-ca",
					},
					{
						Name:      "auth-pdp-secret",
						MountPath: "/certs/auth-pdp",
					},
					{
						Name:      "cluster-ca",
						MountPath: "/certs",
					},
					{
						Name:      "shared",
						MountPath: "/app/logs/audit",
					},
					{
						Name:      "mongodb-client-cert",
						MountPath: "/certs/mongodb-client",
					},
				},
				Env: tmpEnvs,
			},
		},
	}

	//Check if the Job is already created, if exists throw error
	currentJob := &batchv1.Job{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "iam-onboarding", Namespace: instance.Namespace}, currentJob)
	if err == nil {
		if currentJob.Status.Conditions != nil && currentJob.Status.Conditions[0].Type == "Failed" {
			reqLogger.Info("Inside job failed condition ", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
			config, err := rest.InClusterConfig()
			if err == nil {
				clientset, err := kubernetes.NewForConfig(config)
				if err == nil {
					events, err := clientset.CoreV1().Events(instance.Namespace).List(context.TODO(), metav1.ListOptions{FieldSelector: "involvedObject.name=iam-onboarding", TypeMeta: metav1.TypeMeta{Kind: "Job"}})
					if err == nil {
						if len(events.Items) > 2 {
							reqLogger.Info("The event from failed iam-onboarding job is ", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
							reqLogger.Info(events.Items[len(events.Items)-3].Message)
							r, _ := regexp.Compile(":\\s?(.*)")
							matches := r.FindAllString(events.Items[len(events.Items)-3].Message, -1)
							if len(matches) > 0 {
								pod_name := strings.TrimSpace(strings.Split(matches[0], ":")[1])
								reqLogger.Info("IAM Onboarding failed pod name is ", pod_name, "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
								_, err = clientset.CoreV1().Pods(instance.Namespace).Get(context.TODO(), pod_name, metav1.GetOptions{})
								if errors.IsNotFound(err) {
									reqLogger.Info("Pod iam-onboarding not found in %v namespace\n", instance.Namespace, "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
								} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
									reqLogger.Info("Error getting pod %v\n", statusError.ErrStatus.Message, "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
								} else if err != nil {
									reqLogger.Info("The error getting pod ", err.Error(), "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
								} else {
									reqLogger.Info("Found iam-onboarding pod in %v namespace\n", instance.Namespace)
									count := int64(50)
									podLogOpts := corev1.PodLogOptions{
										Follow:    true,
										TailLines: &count,
									}
									req := clientset.CoreV1().Pods(instance.Namespace).GetLogs(pod_name, &podLogOpts)
									podLogs, err2 := req.Stream(context.TODO())
									if err2 != nil {
										reqLogger.Info("error in opening stream ", err2.Error(), "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
									} else {
										defer podLogs.Close()
										reqLogger.Info("Get logs for the iam-onboarding pod ", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
										buf := new(bytes.Buffer)
										_, err2 = io.Copy(buf, podLogs)
										if err2 != nil {
											reqLogger.Info("error in copy information from podLogs to buf")
										}
										pod_logs := strings.Split(buf.String(), "\n")
										reqLogger.Info(" The last few lines are ")
										start_index := 0
										end_index := len(pod_logs)
										if end_index > 10 {
											start_index = end_index - 10
										}
										for i := start_index; i < end_index; i++ {
											reqLogger.Info(pod_logs[i])
										}
									}
									reqLogger.Info("Done reading iam-onboarding logs ", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
								}
							} else {
								reqLogger.Info("Couldn't get pod's name from iam-onboarding job's event ", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
							}
						} else {
							reqLogger.Info("Couldn't fetch event from failed iam-onboarding job ", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
						}
					}
				}

			}

			return currentJob, true, fmt.Errorf("Job %v Failed thus restart.", "iam-onboarding")
		}
		if currentJob.Spec.Template.Spec.Containers[0].Image != shatag.GetImageRef("ICP_IAM_ONBOARDING_IMAGE") {
			return currentJob, true, fmt.Errorf("Job %v already exists.", "iam-onboarding")
		}
		return currentJob, false, fmt.Errorf("Job %v already exists.", "iam-onboarding")
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "iam-onboarding",
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app":                        "iam-onboarding",
				"app.kubernetes.io/instance": "iam-onboarding",
			},
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: "iam-onboarding",
					Annotations: map[string]string{
						"scheduler.alpha.kubernetes.io/critical-pod": "",
						"productName":                        "IBM Cloud Platform Common Services",
						"productID":                          "068a62892a1e4db39641342e592daa25",
						"productMetric":                      "FREE",
						"clusterhealth.ibm.com/dependencies": "cert-manager, common-mongodb, icp-management-ingress",
					},
				},
				Spec: podSpec,
			},
		},
	}

	// Set SecurityOnboarding instance as the owner and controller of the Job
	err1 := controllerutil.SetControllerReference(instance, job, r.scheme)

	if err1 != nil {
		reqLogger.Error(err1, "Failed to set owner for iam-onboarding Job")
		return job, false, err1
	}

	return job, false, nil
}
