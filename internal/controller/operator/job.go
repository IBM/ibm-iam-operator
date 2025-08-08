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
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *AuthenticationReconciler) getMigrationJobSubreconciler(authCR *operatorv1alpha1.Authentication) (subRec common.Subreconciler) {
	return common.NewSecondaryReconcilerBuilder[*batchv1.Job]().
		WithName("ibm-im-db-migration").
		WithGenerateFns(removeJobIfFailedOrImageDifferent("IM_DB_MIGRATOR_IMAGE"),
			generateMigratorJobObject).
		WithClient(r.Client).
		WithNamespace(authCR.Namespace).
		WithPrimary(authCR).MustBuild()
}

func (r *AuthenticationReconciler) getSAMLQueryJob(authCR *operatorv1alpha1.Authentication) (subRec common.Subreconciler) {
	return common.NewSecondaryReconcilerBuilder[*batchv1.Job]().
		WithName("im-has-saml").
		WithGenerateFns(generateSAMLQueryJobObject).
		WithClient(r.Client).
		WithNamespace(authCR.Namespace).
		WithPrimary(authCR).MustBuild()
}

func (r *AuthenticationReconciler) ensureMigrationJobRuns(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	authCR := &operatorv1alpha1.Authentication{}
	if result, err := r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		log.Info("Failed to retrieve Authentication CR for status update; retrying")
	}
	return r.getMigrationJobSubreconciler(authCR).Reconcile(ctx)
}

func (r *AuthenticationReconciler) checkSAMLPresence(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	authCR := &operatorv1alpha1.Authentication{}
	if result, err := r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		log.Info("Failed to retrieve Authentication CR for status update; retrying")
	}
	cm := &corev1.ConfigMap{}
	objKey := types.NamespacedName{Name: "platform-auth-idp", Namespace: req.Namespace}
	if err = r.Get(ctx, objKey, cm); err != nil && !k8sErrors.IsNotFound(err) {
		return subreconciler.RequeueWithError(err)
	} else if err == nil {
		// If MASTER_PATH set, skip creating this Job
		if _, ok := cm.Data["MASTER_PATH"]; ok {
			return subreconciler.ContinueReconciling()
		}
	}

	return r.getSAMLQueryJob(authCR).Reconcile(ctx)
}

func (r *AuthenticationReconciler) ensureOIDCClientRegistrationJobRuns(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	authCR := &operatorv1alpha1.Authentication{}
	if result, err := r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		log.Info("Failed to retrieve Authentication CR for status update; retrying")
	}
	return r.getOIDCClientRegistrationSubreconciler(authCR).Reconcile(ctx)
}

func (r *AuthenticationReconciler) ensureMigrationJobSucceeded(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	authCR := &operatorv1alpha1.Authentication{}
	if result, err := r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		log.Info("Failed to retrieve Authentication CR for status update; retrying")
	}
	job := &batchv1.Job{}
	if err = r.Get(ctx, types.NamespacedName{Name: "ibm-im-db-migration", Namespace: authCR.Namespace}, job); err != nil {
		return subreconciler.RequeueWithError(err)
	}

	if job.Status.Succeeded == 1 {
		return subreconciler.ContinueReconciling()
	}

	return subreconciler.Requeue()
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

func removeJobIfFailedOrImageDifferent(imageRef string) common.GenerateFn[*batchv1.Job] {
	return func(s common.SecondaryReconciler, ctx context.Context, job *batchv1.Job) (err error) {
		if err = s.GetClient().Get(ctx, common.GetObjectKey(s), job); k8sErrors.IsNotFound(err) {
			return nil
		} else if err != nil {
			return
		}

		if job.Spec.Template.Spec.Containers[0].Image == common.GetImageRef(imageRef) || job.Status.Failed != 1 {
			return
		}
		if err = s.GetClient().Delete(ctx, job); k8sErrors.IsNotFound(err) {
			return nil
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
					Volumes:    buildMigratorVolumes(needsMongoDBMigration),
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
				Name:      "postgres-tls",
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

func buildMigratorVolumes(needsMongoDBMigration bool) (volumes []corev1.Volume) {
	volumes = []corev1.Volume{
		{
			Name: "postgres-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "im-datastore-edb-cm",
					},
					DefaultMode: ptr.To(int32(400)),
				},
			},
		},
		{
			Name: "postgres-tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "im-datastore-edb-secret",
					Items: []corev1.KeyToPath{
						{
							Key:  "ca.crt",
							Path: "ca.crt",
							Mode: ptr.To(int32(400)),
						},
						{
							Key:  "tls.crt",
							Path: "tls.crt",
							Mode: ptr.To(int32(400)),
						},
						{
							Key:  "tls.key",
							Path: "tls.key",
							Mode: ptr.To(int32(400)),
						},
					},
					DefaultMode: ptr.To(int32(400)),
				},
			},
		},
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
								Name: "mongo-root-ca-cert",
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
		Name: "mongo-admin-creds",
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
