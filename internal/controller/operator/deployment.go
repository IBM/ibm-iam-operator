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

package operator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"time"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const RestartAnnotation string = "authentications.operator.ibm.com/restartedAt"

// Name of Secret containing certificates for Common Audit Logging
const AuditTLSSecretName string = "audit-tls"
const IMAuditTLSVolume string = "audit-volume"

func (r *AuthenticationReconciler) handleDeployments(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "handleDeployments")
	deployCtx := logf.IntoContext(ctx, reqLogger)

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(deployCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	if result, err = r.removeCP2Deployments(deployCtx, req); subreconciler.ShouldHaltOrRequeue(result, err) && err != nil {
		return
	}

	// Check for the presence of dependencies
	consoleConfigMap := &corev1.ConfigMap{}
	ibmCloudClusterInfoKey := types.NamespacedName{Name: common.IBMCloudClusterInfoCMName, Namespace: req.Namespace}
	err = r.Client.Get(deployCtx, ibmCloudClusterInfoKey, consoleConfigMap)
	if k8sErrors.IsNotFound(err) {
		reqLogger.Error(err, "The ConfigMap has not been created yet", "ConfigMap.Name", common.IBMCloudClusterInfoCMName)
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	} else if err != nil {
		reqLogger.Error(err, "Failed to get ConfigMap", common.IBMCloudClusterInfoCMName)
		return subreconciler.RequeueWithError(err)
	}

	// Check if the ibmcloud-cluster-info created by IM-Operator
	if !common.IsOwnerOf(r.Client.Scheme(), authCR, consoleConfigMap) {
		reqLogger.Info("Reconcile Deployment : Can't find ibmcloud-cluster-info Configmap created by IM operator, IM deployment may not proceed", "Configmap.Namespace", consoleConfigMap.Namespace, "ConfigMap.Name", common.IBMCloudClusterInfoCMName)
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	icpConsoleURL := consoleConfigMap.Data["cluster_address"]
	samlConsoleURL, ok := consoleConfigMap.Data["cluster_address_auth"]
	if !ok {
		samlConsoleURL = icpConsoleURL
	}

	auditSecretName, err := r.getAuditSecretNameIfExists(context.TODO(), authCR)
	if err != nil {
		return subreconciler.RequeueWithError(err)
	}
	auditSecretName = authCR.Spec.Config.AuditSecret

	reqLogger.Info("Does audit-tls secret exist?", "Deployment.Namespace", req.Namespace, "Secret exists", auditSecretName)

	// Check for the presence of dependencies, for SAAS
	reqLogger.Info("Is SAAS enabled?", "Instance spec config value", authCR.Spec.Config.IBMCloudSaas)
	var saasServiceIdCrn string = ""
	saasTenantConfigMapName := "cs-saas-tenant-config"
	saasTenantConfigMap := &corev1.ConfigMap{}
	if authCR.Spec.Config.IBMCloudSaas {
		err := r.Client.Get(deployCtx, types.NamespacedName{Name: saasTenantConfigMapName, Namespace: authCR.Namespace}, saasTenantConfigMap)
		if k8sErrors.IsNotFound(err) {
			reqLogger.Error(err, "SAAS is enabled, waiting for the configmap to be created", "ConfigMap.Name", saasTenantConfigMapName)
			return subreconciler.RequeueWithError(err)
		} else if err != nil {
			reqLogger.Error(err, "Failed to get ConfigMap", saasTenantConfigMapName)
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("SAAS tenant configmap was created; updating service_crn_id from configmap", "ConfigMap.Name", saasTenantConfigMapName)
		saasServiceIdCrn = saasTenantConfigMap.Data["service_crn_id"]
	}

	imagePullSecret := os.Getenv("IMAGE_PULL_SECRET")
	builders := []*common.SecondaryReconcilerBuilder[*appsv1.Deployment]{
		common.NewSecondaryReconcilerBuilder[*appsv1.Deployment]().
			WithName("platform-auth-service").
			WithGenerateFns(generatePlatformAuthService(imagePullSecret, icpConsoleURL, saasServiceIdCrn)).
			WithModifyFns(modifyDeployment(r.needsRollout)),
		common.NewSecondaryReconcilerBuilder[*appsv1.Deployment]().
			WithName("platform-identity-management").
			WithGenerateFns(generatePlatformIdentityManagement(imagePullSecret, icpConsoleURL, saasServiceIdCrn, auditSecretName)).
			WithModifyFns(modifyDeployment(r.needsRollout)),
		common.NewSecondaryReconcilerBuilder[*appsv1.Deployment]().
			WithName("platform-identity-provider").
			WithGenerateFns(generatePlatformIdentityProvider(imagePullSecret, samlConsoleURL, saasServiceIdCrn, auditSecretName)).
			WithModifyFns(modifyDeployment(r.needsRollout)),
	}

	subRecs := []common.SecondaryReconciler{}
	for i := range builders {
		subRecs = append(subRecs, builders[i].
			WithNamespace(authCR.Namespace).
			WithPrimary(authCR).
			WithClient(r.Client).
			MustBuild())
	}

	results := []*ctrl.Result{}
	errs := []error{}
	for _, subRec := range subRecs {
		subResult, subErr := subRec.Reconcile(deployCtx)
		results = append(results, subResult)
		errs = append(errs, subErr)
	}
	result, err = common.ReduceSubreconcilerResultsAndErrors(results, errs)
	if err == nil {
		r.needsRollout = false
	}
	if subreconciler.ShouldRequeue(result, err) {
		reqLogger.Info("Cluster state has been modified; requeueing")
		return
	}

	// Deployment already exists - don't requeue
	return subreconciler.ContinueReconciling()
}

func (r *AuthenticationReconciler) removeCP2Deployments(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)
	// We need to cleanup existing CP2 deployment before the CP3 installation
	cp2DeploymentNames := [6]string{"auth-idp", "auth-pdp", "auth-pap", "secret-watcher", "oidcclient-watcher", "iam-policy-controller"}

	deleted := false
	// Check for existing CP2 Deployments , Delete those if found
	for _, name := range cp2DeploymentNames {
		deploy := &appsv1.Deployment{}
		if err = r.Client.Get(ctx, types.NamespacedName{Name: name, Namespace: req.Namespace}, deploy); k8sErrors.IsNotFound(err) {
			continue
		} else if err != nil {
			reqLogger.Info("Upgrade check: Error while getting deployment.", "Deployment.Namespace", req.Namespace, "Deployment.Name", name, "reason", err.Error())
			return subreconciler.RequeueWithError(err)
		}
		if err = r.Client.Delete(ctx, deploy); k8sErrors.IsNotFound(err) {
			continue
		} else if err != nil {
			reqLogger.Info("Upgrade check: Error while deleting deployment.", "Deployment.Namespace", req.Namespace, "Deployment.Name", name, "reason", err.Error())
			return subreconciler.RequeueWithError(err)
		}
		deleted = true
		reqLogger.Info("Upgrade check: Deleted deployment", "Deployment.Namespace", req.Namespace, "Deployment.Name", name)
	}
	if deleted {
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
	reqLogger.Info("No cleanup required; continuing")
	return subreconciler.ContinueReconciling()
}

// getAuditSecretNameIfExists determines whether an audit service has been
// configured with TLS. Returns the name of the Secret used to store the TLS
// certificates if a Secret has been identified by the user and found on the
// cluster, or an empty string when the Secret isn't found or cannot otherwise
// be retrieved. If an error other than NotFound is received when trying to get
// the Secret, that is returned as well.
func (r *AuthenticationReconciler) getAuditSecretNameIfExists(ctx context.Context, authCR *operatorv1alpha1.Authentication) (*string, error) {
	//var auditSecretName string
	//var auditURL string
	reqLogger := logf.FromContext(ctx)

	if authCR.Spec.Config.AuditUrl == nil || authCR.Spec.Config.AuditSecret == nil {
		reqLogger.Info("Audit URL or Audit Secret is not specified in Authentication CR", "key", "AUDIT_URL")
		return nil, nil
	}

	reqLogger.Info("Fetched audit URL and audit Secret from Authentication CR", "AUDIT_SECRET", authCR.Spec.Config.AuditSecret, "AUDIT_URL", authCR.Spec.Config.AuditUrl)
	if authCR.Spec.Config.AuditSecret != nil {
		auditTLSSecret := &corev1.Secret{}
		auditTLSSecretStruct := types.NamespacedName{Name: *authCR.Spec.Config.AuditSecret, Namespace: authCR.Namespace}
		reqLogger.Info("Checking for audit Secret", "Audit secret", authCR.Spec.Config.AuditSecret, "Namespace", authCR.Namespace)
		err1 := r.Get(ctx, auditTLSSecretStruct, auditTLSSecret)
		if k8sErrors.IsNotFound(err1) {
			reqLogger.Info("Secret for audit configuration not found")
			return nil, nil
		} else if err1 != nil {
			reqLogger.Error(err1, "Failed to retrieve Secret for audit configuration")
			return nil, err1
		}
	}
	reqLogger.Info("Secret found for audit configuration")
	return authCR.Spec.Config.AuditSecret, nil
}

func generatePlatformAuthService(imagePullSecret, icpConsoleURL, _ string) common.GenerateFn[*appsv1.Deployment] {
	return func(s common.SecondaryReconciler, ctx context.Context, deploy *appsv1.Deployment) (err error) {
		reqLogger := logf.FromContext(ctx)
		authServiceImage := common.GetImageRef("ICP_PLATFORM_AUTH_IMAGE")
		initContainerImage := common.GetImageRef("IM_INITCONTAINER_IMAGE")
		authCR, ok := s.GetPrimary().(*operatorv1alpha1.Authentication)
		if !ok {
			return fmt.Errorf("received non-Authentication")
		}
		replicas := authCR.Spec.Replicas
		ldapCACert := authCR.Spec.AuthService.LdapsCACert
		routerCertSecret := authCR.Spec.AuthService.RouterCertSecret

		deployLabels := common.MergeMaps(nil,
			authCR.Spec.Labels,
			map[string]string{
				"app":                              s.GetName(),
				"operator.ibm.com/bindinfoRefresh": "enabled",
			},
			common.GetCommonLabels())

		podLabels := common.MergeMaps(nil,
			authCR.Spec.Labels,
			map[string]string{
				"app":                        s.GetName(),
				"k8s-app":                    s.GetName(),
				"component":                  s.GetName(),
				"app.kubernetes.io/instance": s.GetName(),
				"intent":                     "projected",
			},
			common.GetCommonLabels())

		*deploy = appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.GetName(),
				Namespace: authCR.Namespace,
				Labels:    deployLabels,
				Annotations: map[string]string{
					"bindinfoRefresh/configmap": common.DatastoreEDBCMName,
					"bindinfoRefresh/secret":    common.DatastoreEDBSecretName,
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app":       s.GetName(),
						"k8s-app":   s.GetName(),
						"component": s.GetName(),
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
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
						TerminationGracePeriodSeconds: &seconds60,
						ServiceAccountName:            serviceAccountName,
						HostIPC:                       falseVar,
						HostPID:                       falseVar,
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
									{
										Weight: 100,
										PodAffinityTerm: corev1.PodAffinityTerm{
											TopologyKey: "topology.kubernetes.io/zone",
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
						Volumes:        buildIdpVolumes(ldapCACert, routerCertSecret, nil),
						Containers:     buildContainers(authCR, authServiceImage, icpConsoleURL),
						InitContainers: buildInitContainers(initContainerImage),
					},
				},
			},
		}
		if imagePullSecret != "" {
			deploy.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: imagePullSecret}}
		}
		// Set SecretWatcher instance as the owner and controller
		err = controllerutil.SetControllerReference(authCR, deploy, s.GetClient().Scheme())
		if err != nil {
			reqLogger.Error(err, "Failed to set owner for Deployment")
			return nil
		}
		return
	}
}

func generatePlatformIdentityManagement(imagePullSecret, icpConsoleURL, _ string, auditSecretName *string) common.GenerateFn[*appsv1.Deployment] {
	return func(s common.SecondaryReconciler, ctx context.Context, deploy *appsv1.Deployment) (err error) {
		reqLogger := logf.FromContext(ctx)
		identityManagerImage := common.GetImageRef("ICP_IDENTITY_MANAGER_IMAGE")
		initContainerImage := common.GetImageRef("IM_INITCONTAINER_IMAGE")
		authCR, ok := s.GetPrimary().(*operatorv1alpha1.Authentication)
		if !ok {
			return fmt.Errorf("received non-Authentication")
		}
		replicas := authCR.Spec.Replicas
		ldapCACert := authCR.Spec.AuthService.LdapsCACert
		routerCertSecret := authCR.Spec.AuthService.RouterCertSecret

		deployLabels := common.MergeMaps(nil,
			authCR.Spec.Labels,
			map[string]string{
				"app":                              s.GetName(),
				"operator.ibm.com/bindinfoRefresh": "enabled",
			},
			common.GetCommonLabels())

		podLabels := common.MergeMaps(nil,
			authCR.Spec.Labels,
			map[string]string{
				"app":                        s.GetName(),
				"k8s-app":                    s.GetName(),
				"component":                  s.GetName(),
				"app.kubernetes.io/instance": s.GetName(),
				"intent":                     "projected",
			},
			common.GetCommonLabels())

		*deploy = appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.GetName(),
				Namespace: authCR.Namespace,
				Labels:    deployLabels,
				Annotations: map[string]string{
					"bindinfoRefresh/configmap": common.DatastoreEDBCMName,
					"bindinfoRefresh/secret":    common.DatastoreEDBSecretName,
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app":       s.GetName(),
						"k8s-app":   s.GetName(),
						"component": s.GetName(),
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
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
						TerminationGracePeriodSeconds: &seconds60,
						ServiceAccountName:            serviceAccountName,
						HostIPC:                       falseVar,
						HostPID:                       falseVar,
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
									{
										Weight: 100,
										PodAffinityTerm: corev1.PodAffinityTerm{
											TopologyKey: "topology.kubernetes.io/zone",
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
						Tolerations: []corev1.Toleration{
							{
								Key:      "dedicated",
								Operator: corev1.TolerationOpExists,
							},
							{
								Key:      "CriticalAddonsOnly",
								Operator: corev1.TolerationOpExists,
							},
						},
						Volumes:        buildIdpVolumes(ldapCACert, routerCertSecret, auditSecretName),
						Containers:     buildManagerContainers(authCR, identityManagerImage, icpConsoleURL),
						InitContainers: buildInitForMngrAndProvider(initContainerImage),
					},
				},
			},
		}
		if imagePullSecret != "" {
			deploy.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: imagePullSecret}}
		}
		// Set SecretWatcher instance as the owner and controller
		err = controllerutil.SetControllerReference(authCR, deploy, s.GetClient().Scheme())
		if err != nil {
			reqLogger.Error(err, "Failed to set owner for Deployment")
		}
		return
	}
}

func generatePlatformIdentityProvider(imagePullSecret, icpConsoleURL, saasServiceIdCrn string, auditSecretName *string) common.GenerateFn[*appsv1.Deployment] {
	return func(s common.SecondaryReconciler, ctx context.Context, deploy *appsv1.Deployment) (err error) {
		reqLogger := logf.FromContext(ctx)
		identityProviderImage := common.GetImageRef("ICP_IDENTITY_PROVIDER_IMAGE")
		initContainerImage := common.GetImageRef("IM_INITCONTAINER_IMAGE")
		authCR, ok := s.GetPrimary().(*operatorv1alpha1.Authentication)
		if !ok {
			return fmt.Errorf("unexpected non-Authentication")
		}
		replicas := authCR.Spec.Replicas
		ldapCACert := authCR.Spec.AuthService.LdapsCACert
		routerCertSecret := authCR.Spec.AuthService.RouterCertSecret

		deployLabels := common.MergeMaps(nil,
			authCR.Spec.Labels,
			map[string]string{
				"app":                              s.GetName(),
				"operator.ibm.com/bindinfoRefresh": "enabled",
			},
			common.GetCommonLabels())

		podLabels := common.MergeMaps(nil,
			authCR.Spec.Labels,
			map[string]string{
				"app":                        s.GetName(),
				"k8s-app":                    s.GetName(),
				"component":                  s.GetName(),
				"app.kubernetes.io/instance": s.GetName(),
				"intent":                     "projected",
			},
			common.GetCommonLabels())

		*deploy = appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.GetName(),
				Namespace: s.GetNamespace(),
				Labels:    deployLabels,
				Annotations: map[string]string{
					"bindinfoRefresh/configmap": common.DatastoreEDBCMName,
					"bindinfoRefresh/secret":    common.DatastoreEDBSecretName,
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app":       s.GetName(),
						"k8s-app":   s.GetName(),
						"component": s.GetName(),
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
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
						TerminationGracePeriodSeconds: &seconds60,
						ServiceAccountName:            serviceAccountName,
						HostIPC:                       falseVar,
						HostPID:                       falseVar,
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
									{
										Weight: 100,
										PodAffinityTerm: corev1.PodAffinityTerm{
											TopologyKey: "topology.kubernetes.io/zone",
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
						Volumes:        buildIdpVolumes(ldapCACert, routerCertSecret, auditSecretName),
						Containers:     buildProviderContainers(authCR, identityProviderImage, icpConsoleURL, saasServiceIdCrn),
						InitContainers: buildInitForMngrAndProvider(initContainerImage),
					},
				},
			},
		}

		if imagePullSecret != "" {
			deploy.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: imagePullSecret}}
		}

		err = controllerutil.SetControllerReference(authCR, deploy, s.GetClient().Scheme())
		if err != nil {
			reqLogger.Error(err, "Failed to set owner for Deployment")
		}
		return
	}
}

// preserveObservedFields sets specific labels, annotations, and spec values
// from the observed Deployment on the generated Deployment.
func preserveObservedFields(observed, generated *appsv1.Deployment) {
	certmanagerLabel := "certmanager.k8s.io/time-restarted"
	if val, ok := observed.Spec.Template.ObjectMeta.Labels[certmanagerLabel]; ok {
		generated.Spec.Template.ObjectMeta.Labels[certmanagerLabel] = val
	}
	annotationsToPreserve := []string{
		"nss.ibm.com/namespaceList",
		"bindinfo/restartTime",
		RestartAnnotation,
	}
	for _, annotation := range annotationsToPreserve {
		if val, ok := observed.Spec.Template.ObjectMeta.Annotations[annotation]; ok {
			generated.Spec.Template.ObjectMeta.Annotations[annotation] = val
		}
	}
	generated.Spec.ProgressDeadlineSeconds = observed.Spec.ProgressDeadlineSeconds
	generated.Spec.RevisionHistoryLimit = observed.Spec.RevisionHistoryLimit
	generated.Spec.Strategy = observed.Spec.Strategy
	generated.Spec.Template.Spec.DNSPolicy = observed.Spec.Template.Spec.DNSPolicy
	generated.Spec.Template.Spec.RestartPolicy = observed.Spec.Template.Spec.RestartPolicy
	generated.Spec.Template.Spec.SchedulerName = observed.Spec.Template.Spec.SchedulerName
	generated.Spec.Template.Spec.DeprecatedServiceAccount = observed.Spec.Template.Spec.DeprecatedServiceAccount
	for _, observedContainer := range observed.Spec.Template.Spec.Containers {
		for i, generatedContainer := range generated.Spec.Template.Spec.Containers {
			if observedContainer.Name != generatedContainer.Name {
				continue
			}

			if generatedContainer.LivenessProbe == nil {
				generated.Spec.Template.Spec.Containers[i].LivenessProbe = &corev1.Probe{}
			}
			if observedContainer.LivenessProbe != nil {
				generated.Spec.Template.Spec.Containers[i].LivenessProbe.FailureThreshold = observedContainer.LivenessProbe.FailureThreshold
				generated.Spec.Template.Spec.Containers[i].LivenessProbe.PeriodSeconds = observedContainer.LivenessProbe.PeriodSeconds
				generated.Spec.Template.Spec.Containers[i].LivenessProbe.SuccessThreshold = observedContainer.LivenessProbe.SuccessThreshold
			}

			if generatedContainer.ReadinessProbe == nil {
				generated.Spec.Template.Spec.Containers[i].ReadinessProbe = &corev1.Probe{}
			}
			if observedContainer.ReadinessProbe != nil {
				generated.Spec.Template.Spec.Containers[i].ReadinessProbe.SuccessThreshold = observedContainer.ReadinessProbe.SuccessThreshold
				generated.Spec.Template.Spec.Containers[i].TerminationMessagePath = observedContainer.TerminationMessagePath
				generated.Spec.Template.Spec.Containers[i].TerminationMessagePolicy = observedContainer.TerminationMessagePolicy
			}
		}
	}
	for _, observedContainer := range observed.Spec.Template.Spec.InitContainers {
		for i, generatedContainer := range generated.Spec.Template.Spec.InitContainers {
			if observedContainer.Name != generatedContainer.Name {
				continue
			}
			generated.Spec.Template.Spec.InitContainers[i].TerminationMessagePath = observedContainer.TerminationMessagePath
			generated.Spec.Template.Spec.InitContainers[i].TerminationMessagePolicy = observedContainer.TerminationMessagePolicy
		}
	}
}

// specsDiffer compares the hashes of two Deployments' specs to determine
// whether they are meaningfully different.
func specsDiffer(observed, generated *appsv1.Deployment) (different bool, err error) {
	observedBytes, err := observed.Spec.Marshal()
	if err != nil {
		return
	}
	generatedBytes, err := generated.Spec.Marshal()
	if err != nil {
		return
	}
	observedSHA := sha256.Sum256(observedBytes[:])
	generatedSHA := sha256.Sum256(generatedBytes[:])
	return !bytes.Equal(observedSHA[:], generatedSHA[:]), nil
}

// modifyDeployment looks for relevant differences between the observed and
// generated Deployments and makes modifications to the observed Deployment when
// such differences are found. Returns a boolean representing whether a
// modification was made and an error if the operation could not be completed.
func modifyDeployment(needsRollout bool) common.ModifyFn[*appsv1.Deployment] {
	return func(s common.SecondaryReconciler, ctx context.Context, observed, generated *appsv1.Deployment) (modified bool, err error) {
		preserveObservedFields(observed, generated)
		authCR, ok := s.GetPrimary().(*operatorv1alpha1.Authentication)
		if !ok {
			return
		}
		if authCR.Spec.AutoScaleConfig {
			generated.Spec.Replicas = observed.Spec.Replicas
		}
		if val, ok := observed.Labels["operator.ibm.com/bindinfoRefresh"]; !ok || val != "enabled" {
			observed.Labels["operator.ibm.com/bindinfoRefresh"] = "enabled"
			modified = true
		}
		metaAnnotations := common.MergeMap(common.GetBindInfoRefreshMap(), observed.Annotations)
		if !reflect.DeepEqual(observed.Annotations, metaAnnotations) {
			observed.Annotations = metaAnnotations
			modified = true
		}

		if specModified, err := specsDiffer(observed, generated); err != nil {
			return false, err
		} else if specModified {
			observed.Spec = generated.Spec
			modified = true
		}

		if !common.IsControllerOf(s.GetClient().Scheme(), s.GetPrimary(), observed) {
			if err = controllerutil.SetControllerReference(s.GetPrimary(), observed, s.GetClient().Scheme()); err != nil {
				return false, err
			}
			modified = true
		}

		if !needsRollout {
			return
		}

		timestampNow := time.Now().UTC().Format(time.RFC3339)
		if observed.Spec.Template.Annotations[RestartAnnotation] != timestampNow {
			observed.Spec.Template.Annotations[RestartAnnotation] = timestampNow
			modified = true
		}

		return
	}
}

func signalNeedRolloutFn[T client.Object](r *AuthenticationReconciler) common.OnWriteFn[T] {
	return func(s common.SecondaryReconciler, ctx context.Context) (_ error) {
		reqLogger := logf.FromContext(ctx)
		reqLogger.Info("Signal need for Deployment rollout")
		r.needsRollout = true
		return
	}
}

func hasDataField(fields metav1.ManagedFieldsEntry) bool {
	type Entry struct {
		FieldsV1 struct {
			Data map[string]any `json:"f:data,omitempty"`
		} `json:"fieldsV1"`
	}
	data := &Entry{}
	if err := json.Unmarshal(fields.FieldsV1.Raw, data); err == nil && len(data.FieldsV1.Data) > 0 {
		return true
	}
	return false
}

func buildIdpVolumes(ldapCACert string, routerCertSecret string, auditSecretName *string) []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: "platform-identity-management",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "platform-identity-management",
					Items: []corev1.KeyToPath{
						{
							Key:  "tls.key",
							Path: "tls.key",
						},
						{
							Key:  "tls.crt",
							Path: "tls.crt",
						},
					},
					DefaultMode: &partialAccess,
				},
			},
		},
		{
			Name: "auth-key",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "platform-auth-secret",
					Items: []corev1.KeyToPath{
						{
							Key:  "tls.key",
							Path: "platformauth-key.crt",
						},
						{
							Key:  "tls.crt",
							Path: "platformauth.crt",
						},
					},
					DefaultMode: &partialAccess,
				},
			},
		},
		{
			Name: "identity-provider-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "identity-provider-secret",
					Items: []corev1.KeyToPath{
						{
							Key:  "ca.crt",
							Path: "ca.crt",
						},
						{
							Key:  "tls.key",
							Path: "tls.key",
						},
						{
							Key:  "tls.crt",
							Path: "tls.crt",
						},
					},
					DefaultMode: &partialAccess,
				},
			},
		},
		{
			Name: "ldaps-ca-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: ldapCACert,
					Items: []corev1.KeyToPath{
						{
							Key:  "certificate",
							Path: "ldaps-ca.crt",
						},
					},
					DefaultMode: &partialAccess,
				},
			},
		},
		{
			Name: "ibmid-jwk-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "platform-auth-ibmid-jwk",
					Items: []corev1.KeyToPath{
						{
							Key:  "cert",
							Path: "ibmid-jwk.crt",
						},
					},
					DefaultMode: &partialAccess,
				},
			},
		},
		{
			Name: "ibmid-ssl-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "platform-auth-ibmid-ssl-chain",
					Items: []corev1.KeyToPath{
						{
							Key:  "cert",
							Path: "ibmid-ssl.crt",
						},
					},
					DefaultMode: &partialAccess,
				},
			},
		},
		{
			Name: "saml-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: routerCertSecret,
					Items: []corev1.KeyToPath{
						{
							Key:  "tls.crt",
							Path: "saml-auth.crt",
						},
						{
							Key:  "tls.key",
							Path: "saml-auth.key",
						},
					},
					DefaultMode: &partialAccess,
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
					DefaultMode: &partialAccess,
				},
			},
		},
		{
			Name: "pgsql-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  common.DatastoreEDBSecretName,
					DefaultMode: &partialAccess,
				},
			},
		},
		{
			Name: "pgsql-client-cred",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: common.DatastoreEDBCMName,
					},
					DefaultMode: &partialAccess,
				},
			},
		},
		{
			Name: "scim-ldap-attributes-mapping",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp",
					},
					Items: []corev1.KeyToPath{
						{
							Key:  "SCIM_LDAP_ATTRIBUTES_MAPPING",
							Path: "scim_ldap_attributes_mapping.json",
						},
					},
					DefaultMode: &partialAccess,
				},
			},
		},
	}
	if auditSecretName != nil && *auditSecretName != "" {
		auditVolume := corev1.Volume{
			Name: IMAuditTLSVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: *auditSecretName,
					Items: []corev1.KeyToPath{
						{
							Key:  "tls.crt",
							Path: "tls.crt",
						},
						{
							Key:  "tls.key",
							Path: "tls.key",
						},
						{
							Key:  "ca.crt",
							Path: "ca.crt",
						},
					},
					DefaultMode: &partialAccess,
				},
			},
		}
		volumes = append(volumes, auditVolume)
	}
	return volumes
}
