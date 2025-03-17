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

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/controllers/common"
	ctrlCommon "github.com/IBM/ibm-iam-operator/controllers/common"
	ctrlcommon "github.com/IBM/ibm-iam-operator/controllers/common"
	"github.com/opdev/subreconciler"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const RestartAnnotation string = "authentications.operator.ibm.com/restartedAt"

func (r *AuthenticationReconciler) handleDeployments(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "handleDeployments")
	deployCtx := logf.IntoContext(ctx, reqLogger)

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(deployCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	if subResult, err := r.removeCP2Deployments(deployCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) && err != nil {
		return subreconciler.RequeueWithError(err)
	}

	// Check for the presence of dependencies
	consoleConfigMap := &corev1.ConfigMap{}
	ibmCloudClusterInfoKey := types.NamespacedName{Name: ctrlcommon.IBMCloudClusterInfoCMName, Namespace: req.Namespace}
	err = r.Client.Get(deployCtx, ibmCloudClusterInfoKey, consoleConfigMap)
	if errors.IsNotFound(err) {
		reqLogger.Error(err, "The ConfigMap has not been created yet", "ConfigMap.Name", ctrlcommon.IBMCloudClusterInfoCMName)
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	} else if err != nil {
		reqLogger.Error(err, "Failed to get ConfigMap", ctrlcommon.IBMCloudClusterInfoCMName)
		return subreconciler.RequeueWithError(err)
	}

	// Check if the ibmcloud-cluster-info created by IM-Operator
	gvk := schema.GroupVersionKind{
		Kind:    "Authentication",
		Group:   "operator.ibm.com",
		Version: "v1alpha1",
	}
	if !ctrlcommon.IsOwnerOf(gvk, authCR, consoleConfigMap) {
		reqLogger.Info("Reconcile Deployment : Can't find ibmcloud-cluster-info Configmap created by IM operator, IM deployment may not proceed", "Configmap.Namespace", consoleConfigMap.Namespace, "ConfigMap.Name", ctrlcommon.IBMCloudClusterInfoCMName)
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	icpConsoleURL := consoleConfigMap.Data["cluster_address"]
	samlConsoleURL, ok := consoleConfigMap.Data["cluster_address_auth"]
	if !ok {
		samlConsoleURL = icpConsoleURL
	}

	// Check for the presence of dependencies, for SAAS
	reqLogger.Info("Is SAAS enabled?", "Instance spec config value", authCR.Spec.Config.IBMCloudSaas)
	var saasServiceIdCrn string = ""
	saasTenantConfigMapName := "cs-saas-tenant-config"
	saasTenantConfigMap := &corev1.ConfigMap{}
	if authCR.Spec.Config.IBMCloudSaas {
		err := r.Client.Get(deployCtx, types.NamespacedName{Name: saasTenantConfigMapName, Namespace: authCR.Namespace}, saasTenantConfigMap)
		if errors.IsNotFound(err) {
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

	updaters := []common.ObjectUpdater{
		&deployUpdater{
			Name:             "platform-auth-service",
			Client:           r.Client,
			authCR:           authCR,
			imagePullSecret:  imagePullSecret,
			icpConsoleURL:    icpConsoleURL,
			saasServiceIdCrn: saasServiceIdCrn,
			generate:         generatePlatformAuthService,
			modify:           modifyDeployment,
		},
		&deployUpdater{
			Name:             "platform-identity-management",
			Client:           r.Client,
			authCR:           authCR,
			imagePullSecret:  imagePullSecret,
			icpConsoleURL:    icpConsoleURL,
			saasServiceIdCrn: saasServiceIdCrn,
			generate:         generatePlatformIdentityManagement,
			modify:           modifyDeployment,
		},
		&deployUpdater{
			Name:             "platform-identity-provider",
			Client:           r.Client,
			authCR:           authCR,
			imagePullSecret:  imagePullSecret,
			icpConsoleURL:    samlConsoleURL,
			saasServiceIdCrn: saasServiceIdCrn,
			generate:         generatePlatformIdentityProvider,
			modify:           modifyDeployment,
		},
	}

	results := []*ctrl.Result{}
	errs := []error{}
	podNames := []string{}
	for _, u := range updaters {
		subResult, subErr := common.CreateOrUpdate(deployCtx, u)
		results = append(results, subResult)
		errs = append(errs, subErr)
		podList := &corev1.PodList{}
		listOpts := []client.ListOption{
			client.InNamespace(u.ObjectNamespace()),
			client.MatchingLabels(map[string]string{"k8s-app": u.ObjectName()}),
		}
		if err = r.Client.List(ctx, podList, listOpts...); err != nil {
			reqLogger.Error(err, "Failed to list pods")
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("CS??? get pod names")
		podNames = append(podNames, getPodNames(podList.Items)...)
	}
	result, err = common.ReduceSubreconcilerResultsAndErrors(results, errs)
	if subreconciler.ShouldRequeue(result, err) {
		reqLogger.Info("Cluster state has been modified; requeueing")
		return
	}

	// Deployment already exists - don't requeue
	reqLogger.Info("Final pod names", "Pod names:", podNames)
	// Update status.Nodes if needed
	if !reflect.DeepEqual(podNames, authCR.Status.Nodes) {
		authCR.Status.Nodes = podNames
		reqLogger.Info("CS??? put pod names in status")
		err := r.Client.Status().Update(deployCtx, authCR)
		if err != nil {
			reqLogger.Error(err, "Failed to update Authentication status")
			return subreconciler.RequeueWithError(err)
		}
		return subreconciler.RequeueWithDelay(defaultLowerWait)
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

type deployUpdater struct {
	Name             string                                                                     // name of the Deployment to create/update
	authCR           *operatorv1alpha1.Authentication                                           // Authentication CR being reconciled
	client.Client                                                                               // Kubernetes client
	imagePullSecret  string                                                                     // name of the Secret containing the image pull secret
	icpConsoleURL    string                                                                     // URL for cp-console
	saasServiceIdCrn string                                                                     // cloud resource name (CRN) for SaaS service
	generate         func(context.Context, *deployUpdater, *appsv1.Deployment) error            // function that generates Deployment
	modify           func(*deployUpdater, *appsv1.Deployment, *appsv1.Deployment) (bool, error) // function that modifies one Deployment based upon the contents of another
	onChange         func(context.Context) error                                                // function that runs operations required after a create or update of the object
}

var _ common.ObjectUpdater = &deployUpdater{}

func (u *deployUpdater) ObjectKind() string {
	return "Deployment"
}

func (u *deployUpdater) ObjectName() string {
	return u.Name
}

func (u *deployUpdater) ObjectNamespace() string {
	return u.authCR.Namespace
}

func (u *deployUpdater) GetEmptyObject() client.Object {
	return &appsv1.Deployment{}
}

func (u *deployUpdater) Generate(ctx context.Context, obj client.Object) (err error) {
	if u.generate == nil {
		return nil
	}
	deploy, ok := obj.(*appsv1.Deployment)
	if !ok || deploy == nil {
		panic("received a client.Object other than *appsv1.Deployment")
	}
	return u.generate(ctx, u, deploy)
}

func (u *deployUpdater) Modify(observed, generated client.Object) (updated bool, err error) {
	if u.modify == nil {
		return
	}
	observedDeploy, ok := observed.(*appsv1.Deployment)
	if !ok || observedDeploy == nil {
		panic("received a client.Object for observed other than *appsv1.Deployment")
	}
	generatedDeploy, ok := generated.(*appsv1.Deployment)
	if !ok || generatedDeploy == nil {
		panic("received a client.Object for generated other than *appsv1.Deployment")
	}
	return u.modify(u, observedDeploy, generatedDeploy)
}

func (u *deployUpdater) OnChange(ctx context.Context) (err error) {
	if u.onChange == nil {
		return nil
	}
	return u.onChange(ctx)
}

func (u *deployUpdater) Validate() (err error) {
	if u == nil || u.authCR == nil {
		return fmt.Errorf("ConfigMap updater does not have all mandatory fields set")
	}
	return
}

func hasSameReplicas(observed, generated *appsv1.Deployment) bool {
	return *(observed.Spec.Replicas) == *(generated.Spec.Replicas)
}

func hasSameSelector(observed, generated *appsv1.Deployment) bool {
	return reflect.DeepEqual(*(observed.Spec.Selector), *(generated.Spec.Selector))
}

func generatePlatformAuthService(ctx context.Context, u *deployUpdater, deploy *appsv1.Deployment) (err error) {
	reqLogger := logf.FromContext(ctx)
	authServiceImage := common.GetImageRef("ICP_PLATFORM_AUTH_IMAGE")
	initContainerImage := common.GetImageRef("IM_INITCONTAINER_IMAGE")
	replicas := u.authCR.Spec.Replicas
	ldapCACert := u.authCR.Spec.AuthService.LdapsCACert
	routerCertSecret := u.authCR.Spec.AuthService.RouterCertSecret

	deployLabels := common.MergeMaps(nil,
		u.authCR.Spec.Labels,
		map[string]string{
			"app":                              u.Name,
			"operator.ibm.com/bindinfoRefresh": "enabled",
		},
		ctrlCommon.GetCommonLabels())

	podLabels := common.MergeMaps(nil,
		u.authCR.Spec.Labels,
		map[string]string{
			"app":                        u.Name,
			"k8s-app":                    u.Name,
			"component":                  u.Name,
			"app.kubernetes.io/instance": u.Name,
			"intent":                     "projected",
		},
		ctrlCommon.GetCommonLabels())

	*deploy = appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      u.Name,
			Namespace: u.authCR.Namespace,
			Labels:    deployLabels,
			Annotations: map[string]string{
				"bindinfoRefresh/configmap": ctrlcommon.DatastoreEDBCMName,
				"bindinfoRefresh/secret":    ctrlcommon.DatastoreEDBSecretName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":       u.Name,
					"k8s-app":   u.Name,
					"component": u.Name,
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
									"app": u.Name,
								},
							},
						},
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/region",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": u.Name,
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
													Values:   []string{u.Name},
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
													Values:   []string{u.Name},
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
					Volumes:        buildIdpVolumes(ldapCACert, routerCertSecret),
					Containers:     buildContainers(u.authCR, authServiceImage, u.icpConsoleURL),
					InitContainers: buildInitContainers(initContainerImage),
				},
			},
		},
	}
	if u.imagePullSecret != "" {
		deploy.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: u.imagePullSecret}}
	}
	// Set SecretWatcher instance as the owner and controller
	err = controllerutil.SetControllerReference(u.authCR, deploy, u.Scheme())
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Deployment")
		return nil
	}
	return
}

func generatePlatformIdentityManagement(ctx context.Context, u *deployUpdater, deploy *appsv1.Deployment) (err error) {
	reqLogger := logf.FromContext(ctx)
	identityManagerImage := common.GetImageRef("ICP_IDENTITY_MANAGER_IMAGE")
	initContainerImage := common.GetImageRef("IM_INITCONTAINER_IMAGE")
	replicas := u.authCR.Spec.Replicas
	ldapCACert := u.authCR.Spec.AuthService.LdapsCACert
	routerCertSecret := u.authCR.Spec.AuthService.RouterCertSecret

	deployLabels := common.MergeMaps(nil,
		u.authCR.Spec.Labels,
		map[string]string{
			"app":                              u.Name,
			"operator.ibm.com/bindinfoRefresh": "enabled",
		},
		ctrlCommon.GetCommonLabels())

	podLabels := common.MergeMaps(nil,
		u.authCR.Spec.Labels,
		map[string]string{
			"app":                        u.Name,
			"k8s-app":                    u.Name,
			"component":                  u.Name,
			"app.kubernetes.io/instance": u.Name,
			"intent":                     "projected",
		},
		ctrlCommon.GetCommonLabels())

	*deploy = appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      u.Name,
			Namespace: u.authCR.Namespace,
			Labels:    deployLabels,
			Annotations: map[string]string{
				"bindinfoRefresh/configmap": ctrlcommon.DatastoreEDBCMName,
				"bindinfoRefresh/secret":    ctrlcommon.DatastoreEDBSecretName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":       u.Name,
					"k8s-app":   u.Name,
					"component": u.Name,
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
									"app": u.Name,
								},
							},
						},
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/region",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": u.Name,
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
													Values:   []string{u.Name},
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
													Values:   []string{u.Name},
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
					Volumes:        buildIdpVolumes(ldapCACert, routerCertSecret),
					Containers:     buildManagerContainers(u.authCR, identityManagerImage, u.icpConsoleURL),
					InitContainers: buildInitForMngrAndProvider(initContainerImage),
				},
			},
		},
	}
	if u.imagePullSecret != "" {
		deploy.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: u.imagePullSecret}}
	}
	// Set SecretWatcher instance as the owner and controller
	err = controllerutil.SetControllerReference(u.authCR, deploy, u.Scheme())
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Deployment")
	}
	return
}

func generatePlatformIdentityProvider(ctx context.Context, u *deployUpdater, deploy *appsv1.Deployment) (err error) {
	reqLogger := logf.FromContext(ctx)
	identityProviderImage := common.GetImageRef("ICP_IDENTITY_PROVIDER_IMAGE")
	initContainerImage := common.GetImageRef("IM_INITCONTAINER_IMAGE")
	replicas := u.authCR.Spec.Replicas
	ldapCACert := u.authCR.Spec.AuthService.LdapsCACert
	routerCertSecret := u.authCR.Spec.AuthService.RouterCertSecret

	deployLabels := common.MergeMaps(nil,
		u.authCR.Spec.Labels,
		map[string]string{
			"app":                              u.Name,
			"operator.ibm.com/bindinfoRefresh": "enabled",
		},
		ctrlCommon.GetCommonLabels())

	podLabels := common.MergeMaps(nil,
		u.authCR.Spec.Labels,
		map[string]string{
			"app":                        u.Name,
			"k8s-app":                    u.Name,
			"component":                  u.Name,
			"app.kubernetes.io/instance": u.Name,
			"intent":                     "projected",
		},
		ctrlCommon.GetCommonLabels())

	*deploy = appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      u.Name,
			Namespace: u.authCR.Namespace,
			Labels:    deployLabels,
			Annotations: map[string]string{
				"bindinfoRefresh/configmap": ctrlcommon.DatastoreEDBCMName,
				"bindinfoRefresh/secret":    ctrlcommon.DatastoreEDBSecretName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":       u.Name,
					"k8s-app":   u.Name,
					"component": u.Name,
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
									"app": u.Name,
								},
							},
						},
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/region",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": u.Name,
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
													Values:   []string{u.Name},
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
													Values:   []string{u.Name},
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
					Volumes:        buildIdpVolumes(ldapCACert, routerCertSecret),
					Containers:     buildProviderContainers(u.authCR, identityProviderImage, u.icpConsoleURL, u.saasServiceIdCrn),
					InitContainers: buildInitForMngrAndProvider(initContainerImage),
				},
			},
		},
	}

	if u.imagePullSecret != "" {
		deploy.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: u.imagePullSecret}}
	}

	err = controllerutil.SetControllerReference(u.authCR, deploy, u.Scheme())
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Deployment")
	}
	return
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
			generated.Spec.Template.Spec.Containers[i].LivenessProbe.FailureThreshold = observedContainer.LivenessProbe.FailureThreshold
			generated.Spec.Template.Spec.Containers[i].LivenessProbe.PeriodSeconds = observedContainer.LivenessProbe.PeriodSeconds
			generated.Spec.Template.Spec.Containers[i].LivenessProbe.SuccessThreshold = observedContainer.LivenessProbe.SuccessThreshold
			if generatedContainer.ReadinessProbe == nil {
				generated.Spec.Template.Spec.Containers[i].ReadinessProbe = &corev1.Probe{}
			}
			generated.Spec.Template.Spec.Containers[i].ReadinessProbe.SuccessThreshold = observedContainer.ReadinessProbe.SuccessThreshold
			generated.Spec.Template.Spec.Containers[i].TerminationMessagePath = observedContainer.TerminationMessagePath
			generated.Spec.Template.Spec.Containers[i].TerminationMessagePolicy = observedContainer.TerminationMessagePolicy
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
	return bytes.Compare(observedSHA[:], generatedSHA[:]) != 0, nil
}

// modifyDeployment looks for relevant differences between the observed and
// generated Deployments and makes modifications to the observed Deployment when
// such differences are found. Returns a boolean representing whether a
// modification was made and an error if the operation could not be completed.
func modifyDeployment(u *deployUpdater, observed, generated *appsv1.Deployment) (modified bool, err error) {
	preserveObservedFields(observed, generated)

	if val, ok := observed.Labels["operator.ibm.com/bindinfoRefresh"]; !ok || val != "enabled" {
		observed.Labels["operator.ibm.com/bindinfoRefresh"] = "enabled"
		modified = true
	}
	metaAnnotations := ctrlcommon.MergeMap(ctrlcommon.GetBindInfoRefreshMap(), observed.Annotations)
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

	gvk := schema.GroupVersionKind{
		Kind:    "Authentication",
		Group:   "operator.ibm.com",
		Version: "v1alpha1",
	}
	if !ctrlcommon.IsControllerOf(gvk, u.authCR, observed) {
		if err = controllerutil.SetControllerReference(u.authCR, observed, u.Scheme()); err != nil {
			return false, err
		}
		modified = true
	}
	return
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

func (r *AuthenticationReconciler) configurationHasChangedSinceLastUpdate(ctx context.Context, namespace string, timestamp *metav1.Time) (changed bool, err error) {
	objects := map[string]client.Object{
		"platform-auth-idp-credentials":  &corev1.Secret{},
		"platform-auth-scim-credentials": &corev1.Secret{},
		"platform-auth-idp-encryption":   &corev1.Secret{},
		"platform-oidc-credentials":      &corev1.Secret{},
		"platform-auth-ibmid-jwk":        &corev1.Secret{},
		"platform-auth-ibmid-ssl-chain":  &corev1.Secret{},
		"platform-auth-idp":              &corev1.ConfigMap{},
	}
	for name, obj := range objects {
		objKey := types.NamespacedName{Name: name, Namespace: namespace}
		if err = r.Get(ctx, objKey, obj); err != nil {
			return
		}
		objEventTime := obj.GetCreationTimestamp()
		if objEventTime.After(timestamp.Time) {
			return true, nil
		}
		managedFieldsList := obj.GetManagedFields()
		for _, field := range managedFieldsList {
			if !hasDataField(field) {
				continue
			}
			objEventTime = *field.Time
			if objEventTime.After(timestamp.Time) {
				return true, nil
			}
		}
	}
	return false, nil

}

// RolloutDeployments triggers rollouts for the IM Deployments
func RolloutDeployments(ctx context.Context, u common.ObjectUpdater) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("Object.Namespace", u.ObjectNamespace(), "Object.Kind", u.ObjectKind(), "Object.Name", u.ObjectName())
	lists := map[string]*appsv1.DeploymentList{
		"platform-auth-service":        {},
		"platform-identity-provider":   {},
		"platform-identity-management": {},
	}
	var deployments []appsv1.Deployment
	for app, list := range lists {
		err = u.List(ctx, list, client.InNamespace(u.ObjectNamespace()), client.MatchingLabels{"app": app})
		if k8sErrors.IsNotFound(err) {
			reqLogger.Info("Deployment not found for rollout")
			continue
		} else if err != nil {
			reqLogger.Info("Error encountered while trying to get Deployment for rollout", "reason", err.Error())
			return subreconciler.RequeueWithError(err)
		}
		deployments = append(deployments, list.Items...)
	}

	if len(deployments) == 0 {
		return subreconciler.ContinueReconciling()
	}
	timestampNow := time.Now().UTC().Format(time.RFC3339)
	updated := false
	for _, deploy := range deployments {
		deploy.Spec.Template.Annotations["authentications.operator.ibm.com/restartedAt"] = timestampNow
		if err := u.Update(ctx, &deploy); k8sErrors.IsNotFound(err) {
			reqLogger.Info("Deployment not found while attempting to rollout")
			continue
		} else if err != nil {
			reqLogger.Info("Error encountered while attempting to rollout", "reason", err.Error())
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("Annotation set on Deployment")
		updated = true
	}
	if updated {
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	return subreconciler.ContinueReconciling()
}

func getPodNames(pods []corev1.Pod) []string {
	var podNames []string
	for _, pod := range pods {
		podNames = append(podNames, pod.Name)
	}
	return podNames
}

func buildIdpVolumes(ldapCACert string, routerCertSecret string) []corev1.Volume {
	return []corev1.Volume{
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
			Name: "pgsql-ca-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: ctrlcommon.DatastoreEDBSecretName,
					Items: []corev1.KeyToPath{
						{
							Key:  "ca.crt",
							Path: "ca.crt",
						},
					},
					DefaultMode: &partialAccess,
				},
			},
		},
		{
			Name: "pgsql-client-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: ctrlcommon.DatastoreEDBSecretName,
					Items: []corev1.KeyToPath{
						{
							Key:  "tls.crt",
							Path: "tls.crt",
						},
						{
							Key:  "tls.key",
							Path: "tls.key",
						},
					},
					DefaultMode: &partialAccess,
				},
			},
		},
		{
			Name: "pgsql-client-cred",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: ctrlcommon.DatastoreEDBCMName,
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
}
