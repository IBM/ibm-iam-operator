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

package securityonboarding

import (
	"context"
	"fmt"
	"strings"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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

var log = logf.Log.WithName("controller_securityonboarding")
var serviceAccountName string = "ibm-iam-operator"

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
func (r *ReconcileSecurityOnboarding) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling SecurityOnboarding")

	// Fetch the SecurityOnboarding instance
	instance := &operatorv1alpha1.SecurityOnboarding{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
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

	return reconcile.Result{}, nil
}

func (r *ReconcileSecurityOnboarding) handleConfigMap(instance *operatorv1alpha1.SecurityOnboarding) (reconcile.Result, error) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	m := []string{"ElasticSearch", "HelmApi", "HelmRepo", "Kms", "MgmtRepo", "Monitoring", "TillerService", "Tiller_Serviceid_Policies", "Onboard_Script"}

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
	} else if label == "MgmtRepo" {
		return nil, operatorv1alpha1.MgmtRepo
	} else if label == "Monitoring" {
		return nil, operatorv1alpha1.Monitoring
	} else if label == "TillerService" {
		return nil, operatorv1alpha1.TillerService
	} else if label == "Tiller_Serviceid_Policies" {
		return nil, operatorv1alpha1.Tiller_Serviceid_Policies
	} else if label == "Onboard_Script" {
		return nil, operatorv1alpha1.Onboard_Script
	} else {
		return fmt.Errorf("Unknown label %s", label), ""
	}
}

func (r *ReconcileSecurityOnboarding) handleJob(instance *operatorv1alpha1.SecurityOnboarding) (reconcile.Result, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	//Create security-onboarding job
	securityOnboardJob, err := getSecurityOnboardJob(instance, r)

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
	}

	//Create security-onboarding job
	iamOnboardJob, err := getIAMOnboardJob(instance, r)
	foundErr2 := false
	iamJobExists := false
	if err != nil {
		reqLogger.Info("Failed to create iam-onboarding Job, exists already ", "Job.Namespace", instance.Namespace, "Job.Name", "iam-onboarding")
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
	}

	if foundErr1 && foundErr2 {
		return reconcile.Result{}, nil
	} else {
		return reconcile.Result{Requeue: true}, nil
	}

}

func getSecurityOnboardJob(instance *operatorv1alpha1.SecurityOnboarding, r *ReconcileSecurityOnboarding) (*batchv1.Job, error) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	//Create all the Volumes
	strVolName := []string{"onboard-script", "elasticsearch-json", "monitoring-json", "helmapi-json", "helmrepo-json", "mgmtrepo-json",
		"tillerservice-json", "tiller-serviceid-policies", "kms-json"}
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
				SecretName: "cluster-ca-cert",
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
		"onboard-script":            "/app/scripts",
		"elasticsearch-json":        "/app/elasticsearch",
		"monitoring-json":           "/app/monitoring",
		"helmapi-json":              "/app/helmapi",
		"helmrepo-json":             "/app/helmrepo",
		"mgmtrepo-json":             "/app/mgmtrepo",
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
		Containers: []corev1.Container{
			{
				Name:            "security-onboarding",
				Image:           instance.Spec.ImageRegistry + "/" + instance.Spec.ImageName + ":" + instance.Spec.ImageTag,
				ImagePullPolicy: corev1.PullPolicy("Always"),
				Command:         []string{"python", "/app/scripts/onboard-script.py"},
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
		return currentJob, fmt.Errorf("Job %v already exists.", "security-onboarding")
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "security-onboarding",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "security-onboarding"},
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: "security-onboarding",
				},
				Spec: podSpec,
			},
		},
	}

	// Set SecurityOnboarding instance as the owner and controller of the Job
	err1 := controllerutil.SetControllerReference(instance, job, r.scheme)

	if err1 != nil {
		reqLogger.Error(err1, "Failed to set owner for security-onboarding Job")
		return job, err1
	}

	return job, nil

}

func getIAMOnboardJob(instance *operatorv1alpha1.SecurityOnboarding, r *ReconcileSecurityOnboarding) (*batchv1.Job, error) {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)

	tmpInitContainers := []corev1.Container{
		{
			Name:            "init-auth-service",
			Command:         []string{"sh", "-c", "sleep 75; until curl -k -i -fsS https://platform-auth-service:9443/oidc/endpoint/OP/.well-known/openid-configuration | grep '200 OK'; do sleep 3; done;"},
			Image:           instance.Spec.InitAuthService.ImageRegistry + "/" + instance.Spec.InitAuthService.ImageName + ":" + instance.Spec.InitAuthService.ImageTag,
			ImagePullPolicy: corev1.PullPolicy("Always"),
		},
		{
			Name:            "init-identity-provider",
			Command:         []string{"sh", "-c", "until curl --cacert /certs/ca.crt -i -fsS https://platform-identity-provider:4300 | grep '200 OK'; do sleep 3; done;"},
			Image:           instance.Spec.InitIdentityProvider.ImageRegistry + "/" + instance.Spec.InitIdentityProvider.ImageName + ":" + instance.Spec.InitIdentityProvider.ImageTag,
			ImagePullPolicy: corev1.PullPolicy("Always"),
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "cluster-ca",
					MountPath: "/certs",
				},
			},
		},
		{
			Name:            "init-identity-manager",
			Command:         []string{"sh", "-c", "until curl -k-i -fsS https://platform-identity-management:4500 | grep '200 OK'; do sleep 3; done;"},
			Image:           instance.Spec.InitIdentityManager.ImageRegistry + "/" + instance.Spec.InitIdentityManager.ImageName + ":" + instance.Spec.InitIdentityManager.ImageTag,
			ImagePullPolicy: corev1.PullPolicy("Always"),
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "cluster-ca",
					MountPath: "/certs",
				},
			},
		},
		{
			Name:            "init-token-service",
			Command:         []string{"sh", "-c", "until curl -k -i -fsS https://platform-auth-service:9443/iam/oidc/keys | grep '200 OK'; do sleep 3; done;"},
			Image:           instance.Spec.InitTokenService.ImageRegistry + "/" + instance.Spec.InitTokenService.ImageName + ":" + instance.Spec.InitTokenService.ImageTag,
			ImagePullPolicy: corev1.PullPolicy("Always"),
		},
		{
			Name:            "init-pap",
			Command:         []string{"sh", "-c", "until curl --cacert /certs/ca.crt -i -fsS https://iam-pap:39001/v1/health | grep '200 OK'; do sleep 3; done;"},
			Image:           instance.Spec.InitPAP.ImageRegistry + "/" + instance.Spec.InitPAP.ImageName + ":" + instance.Spec.InitPAP.ImageTag,
			ImagePullPolicy: corev1.PullPolicy("Always"),
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "cluster-ca",
					MountPath: "/certs",
				},
			},
		},
	}
	var mode1, mode2, mode3, mode4 int32 = 420, 420, 420, 420
	tmpVolumes := []corev1.Volume{
		{
			Name: "mongodb-ca-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "cluster-ca-cert",
				},
			},
		},
		{
			Name: "cluster-ca",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "cluster-ca-cert",
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
			Value: "https://platform-auth-service:9443/iam",
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
		Containers: []corev1.Container{
			{
				Name:            "iam-onboarding",
				Command:         []string{"python", "/app/acs_utils/build/icp_iam_am_bootstrap.py"},
				Image:           instance.Spec.IAMOnboarding.ImageRegistry + "/" + instance.Spec.IAMOnboarding.ImageName + ":" + instance.Spec.IAMOnboarding.ImageTag,
				ImagePullPolicy: corev1.PullPolicy("Always"),
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
		return currentJob, fmt.Errorf("Job %v already exists.", "iam-onboarding")
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "iam-onboarding",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "iam-onboarding"},
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: "iam-onboarding",
				},
				Spec: podSpec,
			},
		},
	}

	// Set SecurityOnboarding instance as the owner and controller of the Job
	err1 := controllerutil.SetControllerReference(instance, job, r.scheme)

	if err1 != nil {
		reqLogger.Error(err1, "Failed to set owner for iam-onboarding Job")
		return job, err1
	}

	return job, nil
}
