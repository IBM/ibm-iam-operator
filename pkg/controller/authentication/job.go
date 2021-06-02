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

package authentication

import (
	"context"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/pkg/controller/shatag"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *ReconcileAuthentication) handleJob(instance *operatorv1alpha1.Authentication, currentJob *batchv1.Job, requeueResult *bool) error {

	//	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	job := "oidc-client-registration"
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: job, Namespace: instance.Namespace}, currentJob)
	if err != nil && errors.IsNotFound(err) {
		// Define a new Job
		newJob := generateJobObject(instance, r.scheme, job)
		klog.Info("Creating a new Job", "Job.Namespace", instance.Namespace, "Job.Name", job)
		err = r.client.Create(context.TODO(), newJob)
		if err != nil {
			klog.Error(err, "Failed to create new Job", "Job.Namespace", instance.Namespace, "Job.Name", job)
			return err
		}
		// Job created successfully - return and requeue
		*requeueResult = true
	} else if err != nil {
		klog.Error(err, "Failed to get Job")
		return err
	}

	return nil

}

func generateJobObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, jobName string) *batchv1.Job {
	//reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	image := shatag.GetImageRef("ICP_PLATFORM_AUTH_IMAGE")
	resources := instance.Spec.ClientRegistration.Resources
	if resources == nil {
		resources = &corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    *cpu1000,
				corev1.ResourceMemory: *memory1024},
			Requests: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    *cpu100,
				corev1.ResourceMemory: *memory128},
		}
	}

	newJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": jobName},
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: jobName,
					Labels: map[string]string{
						"app":                        jobName,
						"app.kubernetes.io/instance": "oidc-client-registration",
					},
					Annotations: map[string]string{
						"scheduler.alpha.kubernetes.io/critical-pod": "",
						"productName":                        "IBM Cloud Platform Common Services",
						"productID":                          "068a62892a1e4db39641342e592daa25",
						"productMetric":                      "FREE",
						"clusterhealth.ibm.com/dependencies": "cert-manager, common-mongodb, icp-management-ingress",
					},
				},
				Spec: corev1.PodSpec{
					HostIPC: false,
					HostPID: false,
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/zone",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": jobName,
								},
							},
						},
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/region",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": jobName,
								},
							},
						},
					},
					ServiceAccountName: serviceAccountName,
					RestartPolicy:      corev1.RestartPolicyOnFailure,
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
					Volumes:    buildVolumes(),
					Containers: buildContainer(jobName, image, resources),
				},
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Job
	err := controllerutil.SetControllerReference(instance, newJob, scheme)
	if err != nil {
		klog.Error(err, "Failed to set owner for Job")
		return nil
	}
	return newJob
}

func buildVolumes() []corev1.Volume {
	return []corev1.Volume{

		{
			Name: "registration-script",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "registration-script",
					},
					DefaultMode: &fullAccess,
				},
			},
		},
		{
			Name: "registration-json",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "registration-json",
					},
					DefaultMode: &fullAccess,
				},
			},
		},
	}
}

func buildContainer(jobName string, image string, resources *corev1.ResourceRequirements) []corev1.Container {
	return []corev1.Container{
		{
			Name:            jobName,
			Image:           image,
			ImagePullPolicy: corev1.PullAlways,
			SecurityContext: &corev1.SecurityContext{
				Privileged:               &falseVar,
				RunAsNonRoot:             &trueVar,
				ReadOnlyRootFilesystem:   &falseVar,
				AllowPrivilegeEscalation: &falseVar,
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			},
			Resources: *resources,
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "registration-script",
					MountPath: "/scripts",
				},
				{
					Name:      "registration-json",
					MountPath: "/jsons",
				},
			},
			Command: []string{"/scripts/register-client.sh"},
			Env: []corev1.EnvVar{
				{
					Name: "WLP_CLIENT_REGISTRATION_SECRET",
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
					Name: "WLP_CLIENT_ID",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "platform-oidc-credentials",
							},
							Key: "WLP_CLIENT_ID",
						},
					},
				},
				{
					Name: "WLP_CLIENT_SECRET",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "platform-oidc-credentials",
							},
							Key: "WLP_CLIENT_SECRET",
						},
					},
				},
				{
					Name: "ICP_CONSOLE_URL",
					ValueFrom: &corev1.EnvVarSource{
						ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "management-ingress-info",
							},
							Key: "MANAGEMENT_INGRESS_ROUTE_HOST",
						},
					},
				},
			},
		},
	}

}
