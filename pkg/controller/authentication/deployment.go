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

package authentication

import (
	"context"
	"reflect"
	gorun "runtime"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/pkg/controller/shatag"
	res "github.com/IBM/ibm-iam-operator/pkg/resources"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *ReconcileAuthentication) handleDeployment(instance *operatorv1alpha1.Authentication, currentDeployment *appsv1.Deployment, currentProviderDeployment *appsv1.Deployment, currentManagerDeployment *appsv1.Deployment, requeueResult *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)

	// Check for the presence of dependencies
	consoleConfigMapName := "management-ingress-info"
	consoleConfigMap := &corev1.ConfigMap{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: consoleConfigMapName, Namespace: instance.Namespace}, consoleConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Error(err, "The configmap ", consoleConfigMapName, " is not created yet")
			return err
		} else {
			reqLogger.Error(err, "Failed to get ConfigMap", consoleConfigMapName)
			return err
		}
	}
	icpConsoleURL := consoleConfigMap.Data["MANAGEMENT_INGRESS_ROUTE_HOST"]

	// Check for the presence of dependencies, for SAAS
	reqLogger.Info("Is SAAS enabled?", "Instance spec config value", instance.Spec.Config.IBMCloudSaas)
	var saasServiceIdCrn string = ""
	saasTenantConfigMapName := "cs-saas-tenant-config"
	saasTenantConfigMap := &corev1.ConfigMap{}
	if instance.Spec.Config.IBMCloudSaas {
		err := r.client.Get(context.TODO(), types.NamespacedName{Name: saasTenantConfigMapName, Namespace: instance.Namespace}, saasTenantConfigMap)
		if err != nil {
			if errors.IsNotFound(err) {
				reqLogger.Error(err, "SAAS is enabled, waiting for the configmap ", saasTenantConfigMapName, " to be created")
				return err
			} else {
				reqLogger.Error(err, "Failed to get ConfigMap", saasTenantConfigMapName)
				return err
			}
		}
		reqLogger.Info("SAAS tenant configmap was created", "Updating service_crn_id from configmap", saasTenantConfigMapName)
		saasServiceIdCrn = saasTenantConfigMap.Data["service_crn_id"]
	}

	// Check if this Deployment already exists
	deployment := "auth-idp"
	providerDeployment := "platform-identity-provider"
	managerDeployment := "platform-identity-management"

	err = r.client.Get(context.TODO(), types.NamespacedName{Name: deployment, Namespace: instance.Namespace}, currentDeployment)
	err1 := r.client.Get(context.TODO(), types.NamespacedName{Name: providerDeployment, Namespace: instance.Namespace}, currentProviderDeployment)
	if err != nil || err1 != nil {
		if errors.IsNotFound(err) || errors.IsNotFound(err1) {
			reqLogger.Info("Creating a new Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", deployment)
			reqLogger.Info("SAAS tenant configmap was found", "Creating provider deployment with value from configmap", saasTenantConfigMapName)
			reqLogger.Info("Creating a new Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", providerDeployment)
			newProviderDeployment := generateProviderDeploymentObject(instance, r.scheme, providerDeployment, icpConsoleURL, saasServiceIdCrn)
			err = r.client.Create(context.TODO(), newProviderDeployment)
			if err != nil {
				return err
			}
			//managerDeployment := generateManagerDeploymentObject(instance, r.scheme, deployment, icpConsoleURL, saasServiceIdCrn)
			newDeployment := generateDeploymentObject(instance, r.scheme, deployment, icpConsoleURL, saasServiceIdCrn)
			err = r.client.Create(context.TODO(), newDeployment)
			if err != nil {
				return err
			}
			// Deployment created successfully - return and requeue
			*requeueResult = true
		} else {
			return err
		}
	} else {
		reqLogger.Info("Updating an existing Deployment", "Deployment.Namespace", currentDeployment.Namespace, "Deployment.Name", currentDeployment.Name)
		reqLogger.Info("SAAS tenant configmap was found", "Updating deployment with value from configmap", saasTenantConfigMapName)
		ocwDep := generateDeploymentObject(instance, r.scheme, deployment, icpConsoleURL, saasServiceIdCrn)
		certmanagerLabel := "certmanager.k8s.io/time-restarted"
		if val, ok := currentDeployment.Spec.Template.ObjectMeta.Labels[certmanagerLabel]; ok {
			ocwDep.Spec.Template.ObjectMeta.Labels[certmanagerLabel] = val
		}
		nssAnnotation := "nss.ibm.com/namespaceList"
		if val, ok := currentDeployment.Spec.Template.ObjectMeta.Annotations[nssAnnotation]; ok {
			ocwDep.Spec.Template.ObjectMeta.Annotations[nssAnnotation] = val
		}
		currentDeployment.Spec = ocwDep.Spec
		err = r.client.Update(context.TODO(), currentDeployment)
		if err != nil {
			reqLogger.Error(err, "Failed to update an existing Deployment", "Deployment.Namespace", currentDeployment.Namespace, "Deployment.Name", currentDeployment.Name)
			return err
		}
	}

	err2 := r.client.Get(context.TODO(), types.NamespacedName{Name: managerDeployment, Namespace: instance.Namespace}, currentManagerDeployment)

	if err2 != nil {
		if errors.IsNotFound(err2) {
			reqLogger.Info("Creating a new Manager Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", managerDeployment)
			reqLogger.Info("SAAS tenant configmap was found", "Creating manager deployment with value from configmap", saasTenantConfigMapName)
			reqLogger.Info("Creating a new Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", managerDeployment)
			newManagerDeployment := generateManagerDeploymentObject(instance, r.scheme, managerDeployment, icpConsoleURL, saasServiceIdCrn)
			err = r.client.Create(context.TODO(), newManagerDeployment)
			if err != nil {
				return err
			}
			// Deployment created successfully - return and requeue
			*requeueResult = true
		} else {
			return err
		}
	} else {
		reqLogger.Info("Updating an existing Deployment", "Deployment.Namespace", currentManagerDeployment.Namespace, "Deployment.Name", currentManagerDeployment.Name)
		reqLogger.Info("SAAS tenant configmap was found", "Updating deployment with value from configmap", saasTenantConfigMapName)
		ocwDep := generateDeploymentObject(instance, r.scheme, managerDeployment, icpConsoleURL, saasServiceIdCrn)
		certmanagerLabel := "certmanager.k8s.io/time-restarted"
		if val, ok := currentDeployment.Spec.Template.ObjectMeta.Labels[certmanagerLabel]; ok {
			ocwDep.Spec.Template.ObjectMeta.Labels[certmanagerLabel] = val
		}
		nssAnnotation := "nss.ibm.com/namespaceList"
		if val, ok := currentDeployment.Spec.Template.ObjectMeta.Annotations[nssAnnotation]; ok {
			ocwDep.Spec.Template.ObjectMeta.Annotations[nssAnnotation] = val
		}
		currentDeployment.Spec = ocwDep.Spec
		err = r.client.Update(context.TODO(), currentManagerDeployment)
		if err != nil {
			reqLogger.Error(err, "Failed to update an existing Deployment", "Deployment.Namespace", currentManagerDeployment.Namespace, "Deployment.Name", currentManagerDeployment.Name)
			return err
		}
	}

	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels(map[string]string{"k8s-app": deployment, "app": providerDeployment}),
	}
	if err = r.client.List(context.TODO(), podList, listOpts...); err != nil {
		reqLogger.Error(err, "Failed to list pods", "Authentication.Namespace", instance.Namespace, "Authentication.Name", deployment)
		return err
	}
	reqLogger.Info("CS??? get pod names")
	podNames := getPodNames(podList.Items)

	// Update status.Nodes if needed
	if !reflect.DeepEqual(podNames, instance.Status.Nodes) {
		instance.Status.Nodes = podNames
		reqLogger.Info("CS??? put pod names in status")
		err := r.client.Status().Update(context.TODO(), instance)
		if err != nil {
			reqLogger.Error(err, "Failed to update Authentication status")
			return err
		}
	}
	// Deployment already exists - don't requeue
	reqLogger.Info("Skip reconcile: Deployment already exists", "Deployment.Namespace", instance.Namespace, "Deployment.Name", deployment)
	return nil

}

func getPodNames(pods []corev1.Pod) []string {
	reqLogger := log.WithValues("Request.Namespace", "CS??? namespace", "Request.Name", "CS???")
	var podNames []string
	for _, pod := range pods {
		podNames = append(podNames, pod.Name)
		reqLogger.Info("CS??? pod name=" + pod.Name)
	}
	return podNames
}

func generateDeploymentObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, deployment string, icpConsoleURL string, saasCrnId string) *appsv1.Deployment {

	// Update the audit image for upgrade scenarios
	if instance.Spec.AuditService.ImageName != res.AuditImageName {
		instance.Spec.AuditService.ImageName = res.AuditImageName
	}
	reqLogger := log.WithValues("deploymentForAuthentication", "Entry", "instance.Name", instance.Name)
	authServiceImage := shatag.GetImageRef("ICP_PLATFORM_AUTH_IMAGE")
	identityProviderImage := shatag.GetImageRef("ICP_IDENTITY_PROVIDER_IMAGE")
	identityManagerImage := shatag.GetImageRef("ICP_IDENTITY_MANAGER_IMAGE")
	mongoDBImage := shatag.GetImageRef("ICP_PLATFORM_AUTH_IMAGE")
	auditImage := shatag.GetImageRef("AUDIT_SYSLOG_SERVICE_IMAGE")
	replicas := instance.Spec.Replicas
	syslogTlsPath := instance.Spec.AuditService.SyslogTlsPath
	ldapCACert := instance.Spec.AuthService.LdapsCACert
	routerCertSecret := instance.Spec.AuthService.RouterCertSecret

	idpDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployment,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": deployment},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":       deployment,
					"k8s-app":   deployment,
					"component": deployment,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":                        deployment,
						"k8s-app":                    deployment,
						"component":                  deployment,
						"app.kubernetes.io/instance": "auth-idp",
						"intent":                     "projected",
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
					TerminationGracePeriodSeconds: &seconds60,
					ServiceAccountName:            serviceAccountName,
					HostIPC:                       falseVar,
					HostPID:                       falseVar,
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/zone",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": deployment,
								},
							},
						},
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/region",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": deployment,
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
												Values:   []string{gorun.GOARCH},
											},
										},
									},
								},
							},
						},
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
								corev1.WeightedPodAffinityTerm{
									Weight: 100,
									PodAffinityTerm: corev1.PodAffinityTerm{
										TopologyKey: "kubernetes.io/hostname",
										LabelSelector: &metav1.LabelSelector{
											MatchExpressions: []metav1.LabelSelectorRequirement{
												metav1.LabelSelectorRequirement{
													Key:      "app",
													Operator: metav1.LabelSelectorOpIn,
													Values:   []string{"auth-idp"},
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
					Containers:     buildContainers(instance, auditImage, authServiceImage, identityProviderImage, identityManagerImage, syslogTlsPath, icpConsoleURL, saasCrnId),
					InitContainers: buildInitContainers(mongoDBImage),
				},
			},
		},
	}
	// Set SecretWatcher instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, idpDeployment, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Deployment")
		return nil
	}
	return idpDeployment
}

func generateProviderDeploymentObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, deployment string, icpConsoleURL string, saasCrnId string) *appsv1.Deployment {

	// Update the audit image for upgrade scenarios
	if instance.Spec.AuditService.ImageName != res.AuditImageName {
		instance.Spec.AuditService.ImageName = res.AuditImageName
	}
	reqLogger := log.WithValues("deploymentForAuthentication", "Entry", "instance.Name", instance.Name)
	identityProviderImage := shatag.GetImageRef("ICP_IDENTITY_PROVIDER_IMAGE")
	mongoDBImage := shatag.GetImageRef("ICP_PLATFORM_AUTH_IMAGE")
	auditImage := shatag.GetImageRef("AUDIT_SYSLOG_SERVICE_IMAGE")
	replicas := instance.Spec.Replicas
	syslogTlsPath := instance.Spec.AuditService.SyslogTlsPath
	ldapCACert := instance.Spec.AuthService.LdapsCACert
	routerCertSecret := instance.Spec.AuthService.RouterCertSecret

	idpDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployment,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": deployment},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":       deployment,
					"k8s-app":   deployment,
					"component": deployment,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":                        deployment,
						"k8s-app":                    deployment,
						"component":                  deployment,
						"app.kubernetes.io/instance": "platform-identity-provider",
						"intent":                     "projected",
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
					TerminationGracePeriodSeconds: &seconds60,
					ServiceAccountName:            serviceAccountName,
					HostIPC:                       falseVar,
					HostPID:                       falseVar,
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/zone",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": deployment,
								},
							},
						},
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/region",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": deployment,
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
												Values:   []string{gorun.GOARCH},
											},
										},
									},
								},
							},
						},
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
								corev1.WeightedPodAffinityTerm{
									Weight: 100,
									PodAffinityTerm: corev1.PodAffinityTerm{
										TopologyKey: "kubernetes.io/hostname",
										LabelSelector: &metav1.LabelSelector{
											MatchExpressions: []metav1.LabelSelectorRequirement{
												metav1.LabelSelectorRequirement{
													Key:      "app",
													Operator: metav1.LabelSelectorOpIn,
													Values:   []string{"platform-identity-provider"},
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
					Containers:     buildProviderContainers(instance, auditImage, identityProviderImage, syslogTlsPath, icpConsoleURL, saasCrnId),
					InitContainers: buildInitContainers(mongoDBImage),
				},
			},
		},
	}
	// Set SecretWatcher instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, idpDeployment, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Deployment")
		return nil
	}
	return idpDeployment
}

func generateManagerDeploymentObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, deployment string, icpConsoleURL string, saasCrnId string) *appsv1.Deployment {

	// Update the audit image for upgrade scenarios
	if instance.Spec.AuditService.ImageName != res.AuditImageName {
		instance.Spec.AuditService.ImageName = res.AuditImageName
	}
	reqLogger := log.WithValues("deploymentForAuthentication", "Entry", "instance.Name", instance.Name)
	identityManagerImage := shatag.GetImageRef("ICP_IDENTITY_MANAGER_IMAGE")
	mongoDBImage := shatag.GetImageRef("ICP_PLATFORM_AUTH_IMAGE")
	auditImage := shatag.GetImageRef("AUDIT_SYSLOG_SERVICE_IMAGE")
	replicas := instance.Spec.Replicas
	syslogTlsPath := instance.Spec.AuditService.SyslogTlsPath
	ldapCACert := instance.Spec.AuthService.LdapsCACert
	routerCertSecret := instance.Spec.AuthService.RouterCertSecret

	idpDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployment,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": deployment},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":       deployment,
					"k8s-app":   deployment,
					"component": deployment,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":                        deployment,
						"k8s-app":                    deployment,
						"component":                  deployment,
						"app.kubernetes.io/instance": "platform-identity-management",
						"intent":                     "projected",
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
					TerminationGracePeriodSeconds: &seconds60,
					ServiceAccountName:            serviceAccountName,
					HostIPC:                       falseVar,
					HostPID:                       falseVar,
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/zone",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": deployment,
								},
							},
						},
						{
							MaxSkew:           1,
							TopologyKey:       "topology.kubernetes.io/region",
							WhenUnsatisfiable: corev1.ScheduleAnyway,
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": deployment,
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
												Values:   []string{gorun.GOARCH},
											},
										},
									},
								},
							},
						},
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
								corev1.WeightedPodAffinityTerm{
									Weight: 100,
									PodAffinityTerm: corev1.PodAffinityTerm{
										TopologyKey: "kubernetes.io/hostname",
										LabelSelector: &metav1.LabelSelector{
											MatchExpressions: []metav1.LabelSelectorRequirement{
												metav1.LabelSelectorRequirement{
													Key:      "app",
													Operator: metav1.LabelSelectorOpIn,
													Values:   []string{"platform-identity-management"},
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
					Containers:     buildManagerContainers(instance, auditImage, identityManagerImage, syslogTlsPath, icpConsoleURL, saasCrnId),
					InitContainers: buildInitContainers(mongoDBImage),
				},
			},
		},
	}
	// Set SecretWatcher instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, idpDeployment, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Deployment")
		return nil
	}
	return idpDeployment
}

func buildIdpVolumes(ldapCACert string, routerCertSecret string) []corev1.Volume {
	return []corev1.Volume{
		{
			Name: "audit-server-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "audit-server-certs",
					Optional:   &trueVar,
				},
			},
		},
		{
			Name: "audit-ingest",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "audit-logging-fluentd-ds-http-ingesturl",
					},
					Items: []corev1.KeyToPath{
						{
							Key:  "AuditLoggingSyslogIngestURL",
							Path: "auditurl",
						},
					},
					Optional: &trueVar,
				},
			},
		},
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
				},
			},
		},
		{
			Name: "shared",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "logrotate",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp",
					},
					Items: []corev1.KeyToPath{
						{
							Key:  "logrotate",
							Path: "audit",
						},
					},
					DefaultMode: &partialAccess,
				},
			},
		},
		{
			Name: "logrotate-conf",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp",
					},
					Items: []corev1.KeyToPath{
						{
							Key:  "logrotate-conf",
							Path: "logrotate.conf",
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
							Key:  "tls.key",
							Path: "tls.key",
						},
						{
							Key:  "tls.crt",
							Path: "tls.crt",
						},
					},
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
				},
			},
		},
		{
			Name: "router-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: routerCertSecret,
					Items: []corev1.KeyToPath{
						{
							Key:  "tls.crt",
							Path: "icp-router.crt",
						},
						{
							Key:  "tls.key",
							Path: "icp-router.key",
						},
					},
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
				},
			},
		},
		{
			Name: "mongodb-ca-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "mongodb-root-ca-cert",
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
