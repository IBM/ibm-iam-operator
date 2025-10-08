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
	"fmt"
	"os"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	sscsidriverv1 "sigs.k8s.io/secrets-store-csi-driver/apis/v1"
)

const MigrationJobName string = "ibm-im-db-migration"

func (r *AuthenticationReconciler) ensureMigrationJobRuns(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)
	authCR := &operatorv1alpha1.Authentication{}
	log.Info("Make sure that any new migrations are executed")
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		log.Info("Failed to retrieve Authentication CR for status update")
		return
	}
	return r.getMigrationJobSubreconciler(authCR).Reconcile(debugCtx)
}

func (r *AuthenticationReconciler) checkSAMLPresence(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)
	authCR := &operatorv1alpha1.Authentication{}
	cmName := "platform-auth-idp"
	jobName := "im-has-saml"
	log.Info("Make sure that MASTER_PATH is set in ConfigMap", "ConfigMap.Name", cmName)
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		log.Info("Failed to retrieve Authentication CR for status update; retrying")
		return
	}
	cm := &corev1.ConfigMap{}
	objKey := types.NamespacedName{Name: cmName, Namespace: req.Namespace}
	if err = r.Get(debugCtx, objKey, cm); k8sErrors.IsNotFound(err) {
		log.Info("ConfigMap not found; creating Job to determine correct value", "ConfigMap.Name", cmName, "Job.Name", jobName)
		return r.getSAMLQueryJob(authCR).Reconcile(debugCtx)
	} else if err != nil {
		log.Error(err, "Unexpected error was encountered while trying to get ConfigMap", "ConfigMap.Name", cmName)
		return subreconciler.RequeueWithError(err)
	}
	if _, ok := cm.Data["MASTER_PATH"]; !ok {
		log.Info("MASTER_PATH not found; creating Job to determine correct value", "ConfigMap.Name", cmName, "Job.Name", jobName)
		return r.getSAMLQueryJob(authCR).Reconcile(debugCtx)
	}

	log.Info("MASTER_PATH is set; delete the Job, if present", "ConfigMap.Name", cmName)
	return removeIMHasSAMLJob(r.Client, debugCtx, req)
}

func (r *AuthenticationReconciler) ensureOIDCClientRegistrationJobRuns(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		log.Info("Failed to retrieve Authentication CR for status update; retrying")
		return
	}
	log = log.WithValues("Deployment.Name", "platform-auth-service")
	log.Info("Confirm that Deployment is available before handling default OIDC client")
	deploy := &appsv1.Deployment{}
	objKey := types.NamespacedName{Name: "platform-auth-service", Namespace: req.Namespace}
	err = r.Get(ctx, objKey, deploy)
	if err == nil &&
		((deploy.Spec.Replicas != nil && deploy.Status.AvailableReplicas == *deploy.Spec.Replicas) ||
			(deploy.Spec.Replicas == nil && deploy.Status.AvailableReplicas == 1)) {
		log.Info("Deployment is available; ensure default OIDC client is registered")
		return r.getOIDCClientRegistrationSubreconciler(authCR).Reconcile(ctx)
	}
	log.Info("Deployment is not available yet, requeueing")
	if err != nil {
		return subreconciler.RequeueWithError(fmt.Errorf("failed to verify availability of Deployment %s in namespace %s: %w", objKey.Name, objKey.Namespace, err))
	}
	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

func (r *AuthenticationReconciler) ensureMigrationJobSucceeded(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)
	authCR := &operatorv1alpha1.Authentication{}
	log.Info("Make sure that migration Job has succeeded", "Job.Name", MigrationJobName)
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		log.Info("Failed to retrieve Authentication CR for status update; retrying")
		return
	}
	job := &batchv1.Job{}
	log = log.WithValues("Job.Name", MigrationJobName)
	if err = r.Get(debugCtx, types.NamespacedName{Name: MigrationJobName, Namespace: authCR.Namespace}, job); err != nil {
		log.Error(err, "Unexpected error while getting Job")
		return subreconciler.RequeueWithError(err)
	}

	if job.Status.Succeeded == 1 {
		log.Info("Job succeeded")
		return subreconciler.ContinueReconciling()
	}

	log.Info("Job has not succeeded yet")
	return subreconciler.Requeue()
}

func (r *AuthenticationReconciler) getMigrationJobSubreconciler(authCR *operatorv1alpha1.Authentication) (subRec common.Subreconciler) {
	return common.NewSecondaryReconcilerBuilder[*batchv1.Job]().
		WithName(MigrationJobName).
		WithGenerateFns(removeJobIfFailedOrImageDifferent("IM_DB_MIGRATOR_IMAGE"),
			generateMigratorJobObject).
		WithClient(r.Client).
		WithNamespace(authCR.Namespace).
		WithPrimary(authCR).MustBuild()
}

func (r *AuthenticationReconciler) getSAMLQueryJob(authCR *operatorv1alpha1.Authentication) (subRec common.Subreconciler) {
	return common.NewSecondaryReconcilerBuilder[*batchv1.Job]().
		WithName("im-has-saml").
		WithGenerateFns(deleteJobIfFailedWithGreaterThan1, generateSAMLQueryJobObject).
		WithClient(r.Client).
		WithNamespace(authCR.Namespace).
		WithPrimary(authCR).MustBuild()
}

func deleteJobIfFailedWithGreaterThan1(s common.SecondaryReconciler, ctx context.Context, job *batchv1.Job) (err error) {
	jobName := s.GetName()
	log := logf.FromContext(ctx, "Job.Name", jobName)
	namespace := s.GetNamespace()
	objKey := types.NamespacedName{Name: jobName, Namespace: namespace}
	cl := s.GetClient()
	if err = cl.Get(ctx, objKey, job); k8sErrors.IsNotFound(err) {
		log.Info("Job not found; skipping")
		return nil
	} else if err != nil {
		err = fmt.Errorf("failed to get Job: %w", err)
		log.Error(err, "Encountered unexpected error while getting Object")
		return
	}
	if !jobFailedConditionIsTrue(job) {
		return nil
	}
	exitCode, _ := getSAMLJobResult(cl, ctx, namespace)
	if exitCode == 0 || exitCode == 1 {
		return nil
	}
	log.Info("Removing Job with failing exit code", "exitCode", exitCode)
	_, err = removeIMHasSAMLJob(cl, ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: s.GetPrimary().GetName(), Namespace: namespace}})
	if err != nil {
		log.Error(err, "Failed to remove Job")
	}
	log.Info("Successfully removed Job")
	return
}

func removeIMHasSAMLJob(cl client.Client, ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	jobName := "im-has-saml"
	log := logf.FromContext(ctx, "Object.Name", jobName)
	job := &batchv1.Job{}
	objKey := types.NamespacedName{Name: jobName, Namespace: req.Namespace}
	if err = cl.Get(ctx, objKey, job); k8sErrors.IsNotFound(err) {
		log.Info("No Job to delete; skipping")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		err = fmt.Errorf("failed to get Job %s in namespace %s for removal: %w", objKey.Name, objKey.Namespace, err)
		log.Error(err, "Encountered unexpected error while getting Job")
		return subreconciler.RequeueWithError(err)
	}

	deletionsMade := false

	jobUID := job.ObjectMeta.UID

	podList := &corev1.PodList{}

	podListOpts := []client.ListOption{
		client.InNamespace(req.Namespace),
		client.MatchingLabels(map[string]string{
			"batch.kubernetes.io/controller-uid": string(jobUID),
			"batch.kubernetes.io/job-name":       jobName,
		}),
	}

	depPodListOpts := []client.ListOption{
		client.InNamespace(req.Namespace),
		client.MatchingLabels(map[string]string{
			"controller-uid": string(jobUID),
			"job-name":       jobName,
		}),
	}

	if err = cl.Delete(ctx, job); k8sErrors.IsNotFound(err) {
		log.Info("Job not found; continuing")
	} else if err != nil {
		err = fmt.Errorf("failed to delete Job %s in namespace %s after getting MASTER_PATH: %w", objKey.Name, req.Namespace, err)
		log.Error(err, "Failed to delete Job")
		return subreconciler.RequeueWithError(err)
	} else {
		log.Info("Job deleted")
		deletionsMade = true
	}

	if err = cl.List(ctx, podList, podListOpts...); err != nil {
		log.Error(err, "Failed to list Job Pods")
		return subreconciler.RequeueWithError(err)
	} else if len(podList.Items) == 0 {
		log.Info("No Pods were found using prefixed Job labels; trying list with deprecated, non-prefixed Job labels")
		if err = cl.List(ctx, podList, depPodListOpts...); err != nil {
			log.Error(err, "Failed to list Job Pods with deprecated Job labels")
			return subreconciler.RequeueWithError(err)
		}
	}

	if len(podList.Items) == 0 && deletionsMade {
		log.Info("Job and Pods cleaned up; requeueing")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	} else if len(podList.Items) == 0 && !deletionsMade {
		log.Info("Job and Pods not found; continuing")
		return subreconciler.ContinueReconciling()
	}

	podDeleteOpts := []client.DeleteOption{
		client.GracePeriodSeconds(0),
	}

	log.Info("Deleting found Pods")
	for _, po := range podList.Items {
		if err = cl.Delete(ctx, &po, podDeleteOpts...); k8sErrors.IsNotFound(err) {
			log.Info("Pod not found", "Pod.Name", po.Name)
		} else if err != nil {
			log.Error(err, "Failed to delete Pod", "Pod.Name", po.Name)
			return subreconciler.RequeueWithError(err)
		} else {
			log.Info("Pod deleted", "Pod.Name", po.Name)
			deletionsMade = true
		}
	}

	if !deletionsMade {
		log.Info("No deletions needed for Job or Pods; continuing")
		return subreconciler.ContinueReconciling()
	}

	log.Info("Deletions of Job or Pods made; requeueing")
	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

func (r *AuthenticationReconciler) getOIDCClientRegistrationSubreconciler(authCR *operatorv1alpha1.Authentication) (subRec common.Subreconciler) {
	return common.NewSecondaryReconcilerBuilder[*batchv1.Job]().
		WithName("oidc-client-registration").
		WithGenerateFns(removeJobIfFailedOrImageDifferent("IM_INITCONTAINER_IMAGE"),
			generateJobObject).
		WithClient(r.Client).
		WithNamespace(authCR.Namespace).
		WithPrimary(authCR).MustBuild()
}

func getJobCondition(conditions []batchv1.JobCondition, conditionType batchv1.JobConditionType) (c *batchv1.JobCondition) {
	if conditions == nil {
		return
	}
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return &condition
		}
	}
	return
}

func jobFailedConditionIsTrue(job *batchv1.Job) bool {
	condition := getJobCondition(job.Status.Conditions, batchv1.JobFailed)
	if condition == nil {
		return false
	}
	if condition.Status == corev1.ConditionTrue {
		return true
	}
	return false
}

func removeJobIfFailedOrImageDifferent(imageRef string) common.GenerateFn[*batchv1.Job] {
	return func(s common.SecondaryReconciler, ctx context.Context, job *batchv1.Job) (err error) {
		log := logf.FromContext(ctx)
		log.Info("Determine whether Job needs to be replaced")
		if err = s.GetClient().Get(ctx, common.GetObjectKey(s), job); k8sErrors.IsNotFound(err) {
			log.Info("Job not found, nothing to remove")
			return nil
		} else if err != nil {
			log.Error(err, "Attempt to find Job failed")
			return
		}

		// Leave the Job alone if the image refs haven't changed and the Job hasn't failed
		if job.Spec.Template.Spec.Containers[0].Image == common.GetImageRef(imageRef) && !jobFailedConditionIsTrue(job) {
			log.Info("No changes found that warrant replacing the Job")
			return
		}

		log.Info("Job needs to be replaced; deleting first")
		deleteOpts := []client.DeleteOption{
			client.PropagationPolicy(metav1.DeletePropagationForeground),
		}
		if err = s.GetClient().Delete(ctx, job, deleteOpts...); k8sErrors.IsNotFound(err) {
			log.Info("No Job to delete")
			return nil
		} else if err != nil {
			log.Error(err, "Failed to delete Job")
		} else {
			log.Info("Deleted Job")
		}
		return
	}
}

func generateJobObject(s common.SecondaryReconciler, ctx context.Context, job *batchv1.Job) (err error) {
	log := logf.FromContext(ctx)
	authCR, ok := s.GetPrimary().(*operatorv1alpha1.Authentication)
	if !ok {
		return fmt.Errorf("received non-Authentication")
	}
	image := common.GetImageRef("IM_INITCONTAINER_IMAGE")
	resources := authCR.Spec.ClientRegistration.Resources

	metaLabels := common.MergeMaps(nil,
		authCR.Spec.Labels,
		map[string]string{"app": s.GetName()},
		common.GetCommonLabels())
	podMetaLabels := map[string]string{
		"app":                        s.GetName(),
		"app.kubernetes.io/instance": s.GetName(),
	}
	podLabels := common.MergeMaps(nil, authCR.Spec.Labels, podMetaLabels, common.GetCommonLabels())
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

	imagePullSecret := os.Getenv("IMAGE_PULL_SECRET")

	*job = batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.GetName(),
			Namespace: s.GetNamespace(),
			Labels:    metaLabels,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   s.GetName(),
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
									"app": s.GetName(),
								},
							},
						},
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/region",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": s.GetName(),
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
													Values:   []string{s.GetName()},
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
					Containers: buildContainer(s.GetName(), image, resources),
				},
			},
		},
	}

	if imagePullSecret != "" {
		job.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: imagePullSecret}}

	}

	// Set Authentication instance as the owner and controller of the Job
	err = controllerutil.SetControllerReference(authCR, job, s.GetClient().Scheme())
	if err != nil {
		log.Error(err, "Failed to set owner for Job")
		return nil
	}
	return
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
		{
			Name: "oidc-registration-secrets",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "platform-oidc-credentials",
					Items: []corev1.KeyToPath{
						{Key: "WLP_CLIENT_ID", Path: "client_id"},
						{Key: "OAUTH2_CLIENT_REGISTRATION_SECRET", Path: "oauthadmin_passwd"},
					},
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
				ReadOnlyRootFilesystem:   ptr.To(true),
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
					ReadOnly:  true,
				},
				{
					Name:      "oidc-registration-secrets",
					MountPath: "/etc/register",
					ReadOnly:  true,
				},
			},
			Command: []string{"/scripts/register-client.sh"},
		},
	}

}

func generateSAMLQueryJobObject(s common.SecondaryReconciler, ctx context.Context, job *batchv1.Job) (err error) {
	log := logf.FromContext(ctx)
	if err = generateMigratorJobObject(s, ctx, job); err != nil {
		return
	}
	log.Info("Set command for query job")
	job.Spec.Template.Spec.Containers[0].Command = []string{"/usr/local/bin/migrator", "query", "--postgres-config", "/etc/postgres"}
	job.Spec.Template.Spec.Containers[0].Name = s.GetName()
	job.Spec.Template.Spec.RestartPolicy = corev1.RestartPolicyNever
	job.Spec.Template.Spec.Containers[0].Env = nil
	job.Spec.BackoffLimit = ptr.To(int32(1))
	return
}

func generateMigratorJobObject(s common.SecondaryReconciler, ctx context.Context, job *batchv1.Job) (err error) {
	log := logf.FromContext(ctx)
	authCR, ok := s.GetPrimary().(*operatorv1alpha1.Authentication)
	if !ok {
		return fmt.Errorf("received non-Authentication")
	}
	image := common.GetImageRef("IM_DB_MIGRATOR_IMAGE")
	resources := authCR.Spec.ClientRegistration.Resources

	metaLabels := common.MergeMaps(nil,
		authCR.Spec.Labels,
		map[string]string{"app": s.GetName()},
		common.GetCommonLabels())
	podMetaLabels := map[string]string{
		"app": s.GetName(),
	}
	podLabels := common.MergeMaps(nil, authCR.Spec.Labels, podMetaLabels, common.GetCommonLabels())
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

	imagePullSecret := os.Getenv("IMAGE_PULL_SECRET")

	var mongoHost string
	var needsMongoDBMigration bool
	if needsMongoDBMigration, err = mongoIsPresent(s.GetClient(), ctx, authCR); err != nil {
		return
	} else if needsMongoDBMigration {
		if mongoHost, err = getMongoHost(s.GetClient(), ctx, s.GetNamespace()); err != nil {
			return
		}
	}

	edbspc := &sscsidriverv1.SecretProviderClass{}
	if authCR.SecretsStoreCSIEnabled() {
		if err = getSecretProviderClassForVolume(s.GetClient(), ctx, authCR.Namespace, "pgsql-certs", edbspc); IsLabelConflictError(err) {
			log.Error(err, "Multiple SecretProviderClasses are labeled to be mounted as the same volume; ensure that only one is labeled for the given volume name", "volumeName", common.IMLdapBindPwdVolume)
		} else if err != nil {
			log.Error(err, "Unexpected error occurred while trying to get SecretProviderClass")
		}
		if err != nil {
			return
		}
	}

	*job = batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.GetName(),
			Namespace: s.GetNamespace(),
			Labels:    metaLabels,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   s.GetName(),
					Labels: podLabels,
					Annotations: map[string]string{
						"scheduler.alpha.kubernetes.io/critical-pod": "",
						"productName":   "IBM Cloud Platform Common Services",
						"productID":     "068a62892a1e4db39641342e592daa25",
						"productMetric": "FREE",
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
									"app": s.GetName(),
								},
							},
						},
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/region",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": s.GetName(),
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
													Values:   []string{s.GetName()},
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
					Volumes:    buildMigratorVolumes(needsMongoDBMigration, edbspc.Name),
					Containers: buildMigratorContainer(s, image, resources, mongoHost),
				},
			},
		},
	}

	if imagePullSecret != "" {
		job.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: imagePullSecret}}

	}

	// Set Authentication instance as the owner and controller of the Job
	err = controllerutil.SetControllerReference(authCR, job, s.GetClient().Scheme())
	if err != nil {
		log.Error(err, "Failed to set owner for Job")
		return
	}
	return
}

func buildMigratorContainer(s common.SecondaryReconciler, image string, resources *corev1.ResourceRequirements, mongoHost string) (containers []corev1.Container) {
	container := corev1.Container{
		Name:            s.GetName(),
		Image:           image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		SecurityContext: &corev1.SecurityContext{
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
			Privileged:               ptr.To(false),
			RunAsNonRoot:             ptr.To(true),
			ReadOnlyRootFilesystem:   ptr.To(true),
			AllowPrivilegeEscalation: ptr.To(false),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		},
		Resources: *resources,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "postgres-config",
				MountPath: "/etc/postgres/config",
				ReadOnly:  true,
			},
			{
				Name:      "pgsql-certs",
				MountPath: "/etc/postgres/certs",
				ReadOnly:  true,
			},
		},
		Command: []string{"/usr/local/bin/migrator", "migrate", "--postgres-config", "/etc/postgres"},
	}

	if mongoHost == "" {
		return []corev1.Container{container}
	}

	container.Command = append(container.Command, "--mongodb-config", "/etc/mongodb")
	container.Env = []corev1.EnvVar{
		{Name: "MONGODB_HOST", Value: mongoHost},
		{Name: "MONGODB_PORT", Value: "27017"},
		{Name: "MONGODB_NAME", Value: "platform-db"},
		{Name: "POD_NAMESPACE", Value: s.GetNamespace()},
	}
	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
		Name:      "mongodb-admin-creds",
		MountPath: "/etc/mongodb/config",
		ReadOnly:  true,
	}, corev1.VolumeMount{
		Name:      "mongodb-certs",
		MountPath: "/etc/mongodb/certs",
		ReadOnly:  true,
	})

	return []corev1.Container{container}
}

func buildMigratorVolumes(needsMongoDBMigration bool, edbSPCName string) (volumes []corev1.Volume) {
	volumes = []corev1.Volume{
		{
			Name: "postgres-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: common.DatastoreEDBCMName,
					},
					DefaultMode: ptr.To(int32(420)),
				},
			},
		},
	}

	if edbSPCName != "" {
		volumes = append(volumes, corev1.Volume{
			Name: "pgsql-certs",
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{
					Driver:   "secrets-store.csi.k8s.io",
					ReadOnly: ptr.To(true),
					VolumeAttributes: map[string]string{
						"secretProviderClass": edbSPCName,
					},
				},
			},
		})
	} else {
		volumes = append(volumes, corev1.Volume{
			Name: "pgsql-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: common.DatastoreEDBSecretName,
					Items: []corev1.KeyToPath{
						{
							Key:  "ca.crt",
							Path: "ca.crt",
							Mode: ptr.To(int32(420)),
						},
						{
							Key:  "tls.crt",
							Path: "tls.crt",
							Mode: ptr.To(int32(420)),
						},
						{
							Key:  "tls.key",
							Path: "tls.key",
							Mode: ptr.To(int32(420)),
						},
					},
					DefaultMode: ptr.To(int32(420)),
				},
			},
		})
	}

	if !needsMongoDBMigration {
		return
	}

	mongoDBCertsVol := corev1.Volume{
		Name: "mongodb-certs",
		VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{
					{
						Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "mongodb-root-ca-cert",
							},
							Items: []corev1.KeyToPath{
								{Key: "ca.crt", Path: "ca.crt"},
							},
						},
					},
					{
						Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "icp-mongodb-client-cert",
							},
							Items: []corev1.KeyToPath{
								{Key: "tls.crt", Path: "tls.crt"},
								{Key: "tls.key", Path: "tls.key"},
							},
						},
					},
				},
			},
		},
	}

	mongoDBAdminCredsVol := corev1.Volume{
		Name: "mongodb-admin-creds",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: "icp-mongodb-admin",
				Items: []corev1.KeyToPath{
					{Key: "user", Path: "user"},
					{Key: "password", Path: "password"},
				},
			},
		},
	}

	return append(volumes, mongoDBCertsVol, mongoDBAdminCredsVol)
}
