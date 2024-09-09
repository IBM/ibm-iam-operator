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

package operator

import (
	"context"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/controllers/common"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *AuthenticationReconciler) handleJob(instance *operatorv1alpha1.Authentication, currentJob *batchv1.Job, needToRequeue *bool) (err error) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)

	job := "oidc-client-registration"
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: job, Namespace: instance.Namespace}, currentJob)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Job not found", "name", job, "namespace", instance.Namespace)
		// Confirm that configmap ibmcloud-cluster-info is created by IM-Operator before further usage
		consoleConfigMapName := "ibmcloud-cluster-info"
		consoleConfigMap := &corev1.ConfigMap{}
		err = r.Client.Get(context.TODO(), types.NamespacedName{Name: consoleConfigMapName, Namespace: instance.Namespace}, consoleConfigMap)
		if err != nil {
			if errors.IsNotFound(err) {
				reqLogger.Error(err, "The configmap is not created yet", "ConfigMap.Name", consoleConfigMapName)
				return
			} else {
				reqLogger.Error(err, "Failed to get ConfigMap", "ConfigMap.Name", consoleConfigMapName)
				return
			}
		}
		// Idempotently assign controller reference to Job and return a failure in the event that it cannot be
		// done (e.g. Controller reference already set)
		if err = controllerutil.SetControllerReference(instance, consoleConfigMap, r.Client.Scheme()); err != nil {
			reqLogger.Error(err, "ConfigMap is not owned by this Authentication instance; setting controller reference by force", "ConfigMap.Name", consoleConfigMapName, "Instance.UID", instance.UID)
			for _, ownerRef := range consoleConfigMap.OwnerReferences {
				if *ownerRef.Controller {
					*ownerRef.Controller = false
					break
				}
			}
			if err = controllerutil.SetControllerReference(instance, consoleConfigMap, r.Client.Scheme()); err != nil {
				reqLogger.Error(err, "Could not force setting controller reference", "ConfigMap.Name", consoleConfigMapName, "Instance.UID", instance.UID)
				return
			}
		}

		// Define a new Job
		newJob := generateJobObject(instance, r.Scheme, job)
		reqLogger.Info("Creating a new Job", "Job.Namespace", instance.Namespace, "Job.Name", job)
		err = r.Client.Create(context.TODO(), newJob)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Job", "Job.Namespace", instance.Namespace, "Job.Name", job)
			return
		}
		// Job created successfully - return and requeue
		*needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Job")
		return
	}

	return

}

func generateJobObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, jobName string) *batchv1.Job {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	image := common.GetImageRef("IM_INITCONTAINER_IMAGE")
	resources := instance.Spec.ClientRegistration.Resources

	metaLabels := common.MergeMap(map[string]string{"app": jobName}, instance.Spec.Labels)
	podMetaLabels := map[string]string{
		"app":                        jobName,
		"app.kubernetes.io/instance": "oidc-client-registration",
	}
	podLabels := common.MergeMap(podMetaLabels, instance.Spec.Labels)
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
			Labels:    metaLabels,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   jobName,
					Labels: podLabels,
					Annotations: map[string]string{
						"scheduler.alpha.kubernetes.io/critical-pod": "",
						"productName":                        "IBM Cloud Platform Common Services",
						"productID":                          "068a62892a1e4db39641342e592daa25",
						"productMetric":                      "FREE",
						"clusterhealth.ibm.com/dependencies": "cert-manager",
					},
				},
				Spec: corev1.PodSpec{
					HostIPC: false,
					HostPID: false,
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
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
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
								NodeSelectorTerms: []corev1.NodeSelectorTerm{
									{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{
												Key:      "kubernetes.io/arch",
												Operator: corev1.NodeSelectorOpIn,
												Values:   ArchList,
											},
										},
									},
								},
							},
						},
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
								{
									Weight: 100,
									PodAffinityTerm: corev1.PodAffinityTerm{
										TopologyKey: "kubernetes.io/hostname",
										LabelSelector: &metav1.LabelSelector{
											MatchExpressions: []metav1.LabelSelectorRequirement{
												{
													Key:      "app",
													Operator: metav1.LabelSelectorOpIn,
													Values:   []string{"oidc-client-registration"},
												},
											},
										},
									},
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
		reqLogger.Error(err, "Failed to set owner for Job")
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
			ImagePullPolicy: corev1.PullIfNotPresent,
			SecurityContext: &corev1.SecurityContext{
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
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
								Name: "ibmcloud-cluster-info",
							},
							Key: "cluster_address",
						},
					},
				},
			},
		},
	}

}
