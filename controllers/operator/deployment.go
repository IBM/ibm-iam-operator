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
	"context"
	"reflect"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/controllers/common"
	ctrlCommon "github.com/IBM/ibm-iam-operator/controllers/common"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Name of Secret containing certificates for Common Audit Logging
const AuditTLSSecretName string = "audit-tls"

func (r *AuthenticationReconciler) handleDeployment(instance *operatorv1alpha1.Authentication, currentDeployment *appsv1.Deployment, currentProviderDeployment *appsv1.Deployment, currentManagerDeployment *appsv1.Deployment, needToRequeue *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)

	// We need to cleanup existing CP2 deployment before the CP3 installation
	cp2deployment := [6]string{"auth-idp", "auth-pdp", "auth-pap", "secret-watcher", "oidcclient-watcher", "iam-policy-controller"}

	// Check for existing CP2 Deployments , Delete those if found
	for i := 0; i < len(cp2deployment); i++ {
		err := r.Client.Get(context.TODO(), types.NamespacedName{Name: cp2deployment[i], Namespace: instance.Namespace}, currentDeployment)
		if err != nil {
			if !errors.IsNotFound(err) {
				reqLogger.Info("Upgrade check : Error while getting deployment.", "Deployment.Namespace", instance.Namespace, "Deployment.Name", cp2deployment[i], "Error.Message", err)
				return err
			}
		} else {
			if err = r.Client.Delete(context.Background(), currentDeployment); err != nil {
				reqLogger.Info("Upgrade check : Error while deleting deployment.", "deployment name", currentDeployment, "error message", err)
				return err
			} else {
				reqLogger.Info("Upgrade check : Deleted deployment.", "deployment name", currentDeployment, "error message", err)
			}
		}
	}

	// Check for the presence of dependencies
	consoleConfigMapName := "ibmcloud-cluster-info"
	consoleConfigMap := &corev1.ConfigMap{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: consoleConfigMapName, Namespace: instance.Namespace}, consoleConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Error(err, "The configmap ", consoleConfigMapName, " is not created yet")
			return err
		} else {
			reqLogger.Error(err, "Failed to get ConfigMap", consoleConfigMapName)
			return err
		}
	}

	// Check if the ibmcloud-cluster-info created by IM-Operator
	ownerRefs := consoleConfigMap.OwnerReferences
	var ownRef string
	for _, ownRefs := range ownerRefs {
		ownRef = ownRefs.Kind
	}
	if ownRef != "Authentication" {
		reqLogger.Info("Reconcile Deployment : Can't find ibmcloud-cluster-info Configmap created by IM operator , IM deployment may not proceed", "Configmap.Namespace", consoleConfigMap.Namespace, "ConfigMap.Name", "ibmcloud-cluster-info")
		*needToRequeue = true
		return nil
	}

	icpConsoleURL := consoleConfigMap.Data["cluster_address"]

	// Check for the presence of dependencies, for SAAS
	reqLogger.Info("Is SAAS enabled?", "Instance spec config value", instance.Spec.Config.IBMCloudSaas)
	var saasServiceIdCrn string = ""
	saasTenantConfigMapName := "cs-saas-tenant-config"
	saasTenantConfigMap := &corev1.ConfigMap{}
	if instance.Spec.Config.IBMCloudSaas {
		err := r.Client.Get(context.TODO(), types.NamespacedName{Name: saasTenantConfigMapName, Namespace: instance.Namespace}, saasTenantConfigMap)
		if err != nil {
			if err != nil && errors.IsNotFound(err) {
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

	var auditSecretExists bool
	var auditSecretName string
	var auditURL string
	var ok bool
	// Check for the presence of audit-endpoint configmap
	authIdpConfigMapName := "platform-auth-idp"
	authIdpConfigMap := &corev1.ConfigMap{}
	if err1 := r.Client.Get(context.TODO(), types.NamespacedName{Name: authIdpConfigMapName, Namespace: instance.Namespace}, authIdpConfigMap); err1 != nil {
		if errors.IsNotFound(err1) {
			reqLogger.Error(err1, "The  Auth-idp configmap ", authIdpConfigMapName, " is not found.")
			// no requeue required
		}
		reqLogger.Error(err1, "Failed to get Auth-idp configmap ", authIdpConfigMapName)
	} else {
		if auditSecretName, ok = authIdpConfigMap.Data["AUDIT_SECRET"]; !ok {
			reqLogger.Info("Audit secret is not specified in the auth idp configmap", authIdpConfigMapName)
		}
		if auditURL, ok = authIdpConfigMap.Data["AUDIT_URL"]; !ok {
			reqLogger.Info("Audit url is not specified in the auth idp configmap", authIdpConfigMapName)
		}
		reqLogger.Info("Fetched audit url and audit secret from auth-idp configmap", auditSecretName, auditURL)
		if len(auditSecretName) == 0 || len(auditURL) == 0 {
			reqLogger.Info("Unable to fetch the audit url and audit secret from auth-idp configmap", authIdpConfigMapName)
		} else if len(auditSecretName) > 0 {
			auditSecretExists, err = CheckSecretExists(r.Client, instance.Namespace, auditSecretName)
			if err != nil {
				return err
			}
			reqLogger.Info("audit-tls secret name", "Deployment.Namespace", instance.Namespace, "Secret.Name", auditSecretName)
		}
	}

	// Check if this Deployment already exists
	deployment := "platform-auth-service"
	providerDeployment := "platform-identity-provider"
	managerDeployment := "platform-identity-management"
	reqLogger.Info("Does audit-tls secret exist?", "Deployment.Namespace", instance.Namespace, "Secret exists", auditSecretExists)

	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: deployment, Namespace: instance.Namespace}, currentDeployment)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Creating a new Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", deployment)
			reqLogger.Info("SAAS tenant configmap was found", "Creating provider deployment with value from configmap", saasTenantConfigMapName)
			reqLogger.Info("Creating a new Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", currentDeployment)
			newDeployment := generateDeploymentObject(instance, r.Scheme, deployment, icpConsoleURL, saasServiceIdCrn)
			err = r.Client.Create(context.TODO(), newDeployment)
			if err != nil {
				return err
			}
			// Deployment created successfully - return and requeue
			*needToRequeue = true
		} else {
			return err
		}
	} else {
		reqLogger.Info("Updating an existing Deployment", "Deployment.Namespace", currentDeployment.Namespace, "Deployment.Name", currentDeployment.Name)
		reqLogger.Info("SAAS tenant configmap was found", "Updating deployment with value from configmap", saasTenantConfigMapName)
		authDep := generateDeploymentObject(instance, r.Scheme, deployment, icpConsoleURL, saasServiceIdCrn)
		certmanagerLabel := "certmanager.k8s.io/time-restarted"
		if val, ok := currentDeployment.Spec.Template.ObjectMeta.Labels[certmanagerLabel]; ok {
			authDep.Spec.Template.ObjectMeta.Labels[certmanagerLabel] = val
		}
		nssAnnotation := "nss.ibm.com/namespaceList"
		if val, ok := currentDeployment.Spec.Template.ObjectMeta.Annotations[nssAnnotation]; ok {
			authDep.Spec.Template.ObjectMeta.Annotations[nssAnnotation] = val
		}
		bindInfoAnnotation := "bindinfo/restartTime"
		if val, ok := currentDeployment.Spec.Template.ObjectMeta.Annotations[bindInfoAnnotation]; ok {
			authDep.Spec.Template.ObjectMeta.Annotations[bindInfoAnnotation] = val
		}
		metaLabels := ctrlCommon.MergeMaps(nil,
			currentDeployment.Labels,
			map[string]string{"operator.ibm.com/bindinfoRefresh": "enabled"},
			ctrlCommon.GetCommonLabels())
		metaAnnotations := ctrlCommon.MergeMaps(nil, currentDeployment.Annotations, ctrlCommon.GetBindInfoRefreshMap())
		currentDeployment.Labels = metaLabels
		currentDeployment.Annotations = metaAnnotations
		currentDeployment.Spec = authDep.Spec
		err = r.Client.Update(context.TODO(), currentDeployment)
		if err != nil {
			reqLogger.Error(err, "Failed to update an existing Deployment", "Deployment.Namespace", currentDeployment.Namespace, "Deployment.Name", currentDeployment.Name)
			return err
		}
	}

	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels(map[string]string{"k8s-app": deployment}),
	}
	if err = r.Client.List(context.TODO(), podList, listOpts...); err != nil {
		reqLogger.Error(err, "Failed to list pods", "Authentication.Namespace", instance.Namespace, "Authentication.Name", deployment)
		return err
	}
	reqLogger.Info("CS??? get pod names")
	podNames := getPodNames(podList.Items)

	// Deployment already exists - don't requeue
	reqLogger.Info("Skip reconcile: Deployment already exists", "Deployment.Namespace", instance.Namespace, "Deployment.Name", deployment)

	reqLogger.Info("Reconcile: Looking for deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", currentManagerDeployment)
	err2 := r.Client.Get(context.TODO(), types.NamespacedName{Name: managerDeployment, Namespace: instance.Namespace}, currentManagerDeployment)
	if err2 != nil {
		if errors.IsNotFound(err2) {
			reqLogger.Info("Creating a new Manager Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", currentManagerDeployment)
			reqLogger.Info("SAAS tenant configmap was found", "Creating manager deployment with value from configmap", saasTenantConfigMapName)
			reqLogger.Info("Creating a new Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", managerDeployment)
			newManagerDeployment := generateManagerDeploymentObject(instance, r.Scheme, managerDeployment, icpConsoleURL, saasServiceIdCrn, auditSecretExists)
			err = r.Client.Create(context.TODO(), newManagerDeployment)
			if err != nil {
				return err
			}
			// Deployment created successfully - return and requeue
			*needToRequeue = true
		} else {
			return err
		}
	} else {
		reqLogger.Info("Updating an existing Deployment", "Deployment.Namespace", currentManagerDeployment.Namespace, "Deployment.Name", currentManagerDeployment.Name)
		reqLogger.Info("SAAS tenant configmap was found", "Updating deployment with value from configmap", saasTenantConfigMapName)
		ocwDep := generateManagerDeploymentObject(instance, r.Scheme, managerDeployment, icpConsoleURL, saasServiceIdCrn, auditSecretExists)
		certmanagerLabel := "certmanager.k8s.io/time-restarted"
		if val, ok := currentManagerDeployment.Spec.Template.ObjectMeta.Labels[certmanagerLabel]; ok {
			ocwDep.Spec.Template.ObjectMeta.Labels[certmanagerLabel] = val
		}
		nssAnnotation := "nss.ibm.com/namespaceList"
		if val, ok := currentManagerDeployment.Spec.Template.ObjectMeta.Annotations[nssAnnotation]; ok {
			ocwDep.Spec.Template.ObjectMeta.Annotations[nssAnnotation] = val
		}
		bindInfoAnnotation := "bindinfo/restartTime"
		if val, ok := currentManagerDeployment.Spec.Template.ObjectMeta.Annotations[bindInfoAnnotation]; ok {
			ocwDep.Spec.Template.ObjectMeta.Annotations[bindInfoAnnotation] = val
		}
		metaLabels := ctrlCommon.MergeMaps(nil,
			currentManagerDeployment.Labels,
			map[string]string{"operator.ibm.com/bindinfoRefresh": "enabled"},
			ctrlCommon.GetCommonLabels(),
		)
		metaAnnotations := ctrlCommon.MergeMaps(nil, currentManagerDeployment.Annotations, ctrlCommon.GetBindInfoRefreshMap())
		currentManagerDeployment.Labels = metaLabels
		currentManagerDeployment.Annotations = metaAnnotations
		currentManagerDeployment.Spec = ocwDep.Spec
		err = r.Client.Update(context.TODO(), currentManagerDeployment)
		if err != nil {
			reqLogger.Error(err, "Failed to update an existing Deployment", "Deployment.Namespace", currentManagerDeployment.Namespace, "Deployment.Name", currentManagerDeployment.Name)
			return err
		}
	}

	podListMgr := &corev1.PodList{}
	listOptsMgr := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels(map[string]string{"k8s-app": managerDeployment}),
	}
	if err = r.Client.List(context.TODO(), podListMgr, listOptsMgr...); err != nil {
		reqLogger.Error(err, "Failed to list pods", "Authentication.Namespace", instance.Namespace, "Authentication.Name", managerDeployment)
		return err
	}
	reqLogger.Info("CS??? get pod names")
	podNamesMgr := getPodNames(podListMgr.Items)
	for _, pod := range podNamesMgr {
		podNames = append(podNames, pod)
	}

	// Deployment already exists - don't requeue
	reqLogger.Info("Skip reconcile: Manager deployment already exists", "Deployment.Namespace", instance.Namespace, "Deployment.Name", managerDeployment)
	// reconcile provider
	reqLogger.Info("Reconcile: Looking for deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", currentProviderDeployment)
	err3 := r.Client.Get(context.TODO(), types.NamespacedName{Name: providerDeployment, Namespace: instance.Namespace}, currentProviderDeployment)
	if err3 != nil {
		if errors.IsNotFound(err3) {
			reqLogger.Info("Creating a new Manager Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", providerDeployment)
			reqLogger.Info("SAAS tenant configmap was found", "Creating manager deployment with value from configmap", saasTenantConfigMapName)
			reqLogger.Info("Creating a new Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", providerDeployment)
			newProviderDeployment := generateProviderDeploymentObject(instance, r.Scheme, providerDeployment, icpConsoleURL, saasServiceIdCrn, auditSecretExists)
			err = r.Client.Create(context.TODO(), newProviderDeployment)
			if err != nil {
				return err
			}
			// Deployment created successfully - return and requeue
			*needToRequeue = true
		} else {
			return err
		}
	} else {
		reqLogger.Info("Updating an existing Deployment", "Deployment.Namespace", currentProviderDeployment.Namespace, "Deployment.Name", currentProviderDeployment.Name)
		reqLogger.Info("SAAS tenant configmap was found", "Updating deployment with value from configmap", saasTenantConfigMapName)
		provDep := generateProviderDeploymentObject(instance, r.Scheme, providerDeployment, icpConsoleURL, saasServiceIdCrn, auditSecretExists)
		certmanagerLabel := "certmanager.k8s.io/time-restarted"
		if val, ok := currentProviderDeployment.Spec.Template.ObjectMeta.Labels[certmanagerLabel]; ok {
			provDep.Spec.Template.ObjectMeta.Labels[certmanagerLabel] = val
		}
		nssAnnotation := "nss.ibm.com/namespaceList"
		if val, ok := currentProviderDeployment.Spec.Template.ObjectMeta.Annotations[nssAnnotation]; ok {
			provDep.Spec.Template.ObjectMeta.Annotations[nssAnnotation] = val
		}
		bindInfoAnnotation := "bindinfo/restartTime"
		if val, ok := currentProviderDeployment.Spec.Template.ObjectMeta.Annotations[bindInfoAnnotation]; ok {
			provDep.Spec.Template.ObjectMeta.Annotations[bindInfoAnnotation] = val
		}
		metaLabels := ctrlCommon.MergeMaps(nil,
			currentProviderDeployment.Labels,
			map[string]string{"operator.ibm.com/bindinfoRefresh": "enabled"},
			ctrlCommon.GetCommonLabels())
		metaAnnotations := ctrlCommon.MergeMaps(nil, currentProviderDeployment.Annotations, ctrlCommon.GetBindInfoRefreshMap())
		currentProviderDeployment.Labels = metaLabels
		currentProviderDeployment.Annotations = metaAnnotations
		currentProviderDeployment.Spec = provDep.Spec
		err = r.Client.Update(context.TODO(), currentProviderDeployment)
		if err != nil {
			reqLogger.Error(err, "Failed to update an existing Deployment", "Deployment.Namespace", currentProviderDeployment.Namespace, "Deployment.Name", currentProviderDeployment.Name)
			return err
		}
	}

	podListProv := &corev1.PodList{}
	listOptsProv := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels(map[string]string{"k8s-app": providerDeployment}),
	}
	if err = r.Client.List(context.TODO(), podListProv, listOptsProv...); err != nil {
		reqLogger.Error(err, "Failed to list pods", "Authentication.Namespace", instance.Namespace, "Authentication.Name", providerDeployment)
		return err
	}
	reqLogger.Info("CS??? get pod names")
	podNamesProv := getPodNames(podListProv.Items)
	for _, pod := range podNamesProv {
		podNames = append(podNames, pod)
	}
	// Deployment already exists - don't requeue
	reqLogger.Info("Final pod names", "Pod names:", podNames)
	// Update status.Nodes if needed
	if !reflect.DeepEqual(podNames, instance.Status.Nodes) {
		instance.Status.Nodes = podNames
		reqLogger.Info("CS??? put pod names in status")
		err := r.Client.Status().Update(context.TODO(), instance)
		if err != nil {
			reqLogger.Error(err, "Failed to update Authentication status")
			return err
		}
	}
	// Deployment already exists - don't requeue
	reqLogger.Info("Skip reconcile: Provider deployment already exists", "Deployment.Namespace", instance.Namespace, "Deployment.Name", providerDeployment)
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

	reqLogger := log.WithValues("deploymentForAuthentication", "Entry", "instance.Name", instance.Name)
	authServiceImage := common.GetImageRef("ICP_PLATFORM_AUTH_IMAGE")
	initContainerImage := common.GetImageRef("IM_INITCONTAINER_IMAGE")
	replicas := instance.Spec.Replicas
	ldapCACert := instance.Spec.AuthService.LdapsCACert
	routerCertSecret := instance.Spec.AuthService.RouterCertSecret

	metaLabels := common.MergeMaps(nil,
		instance.Spec.Labels,
		map[string]string{"app": deployment},
		ctrlCommon.GetCommonLabels(),
		map[string]string{"operator.ibm.com/bindinfoRefresh": "enabled"})
	podMetadataLabels := map[string]string{
		"app":                        deployment,
		"k8s-app":                    deployment,
		"component":                  deployment,
		"app.kubernetes.io/instance": "platform-auth-service",
		"intent":                     "projected",
	}
	podLabels := common.MergeMaps(nil,
		instance.Spec.Labels,
		podMetadataLabels,
		ctrlCommon.GetCommonLabels())

	idpDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployment,
			Namespace: instance.Namespace,
			Labels:    metaLabels,
			Annotations: map[string]string{
				"bindinfoRefresh/configmap": ctrlCommon.DatastoreEDBCMName,
				"bindinfoRefresh/secret":    ctrlCommon.DatastoreEDBSecretName,
			},
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
													Values:   []string{"platform-auth-service"},
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
													Values:   []string{"platform-auth-service"},
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
					Volumes:        buildIdpVolumes(ldapCACert, routerCertSecret, false, false),
					Containers:     buildContainers(instance, authServiceImage),
					InitContainers: buildInitContainers(initContainerImage),
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

func generateProviderDeploymentObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, deployment string, icpConsoleURL string, saasCrnId string, auditSecretExists bool) *appsv1.Deployment {

	reqLogger := log.WithValues("deploymentForAuthentication", "Entry", "instance.Name", instance.Name)
	identityProviderImage := common.GetImageRef("ICP_IDENTITY_PROVIDER_IMAGE")
	initContainerImage := common.GetImageRef("IM_INITCONTAINER_IMAGE")
	replicas := instance.Spec.Replicas
	ldapCACert := instance.Spec.AuthService.LdapsCACert
	routerCertSecret := instance.Spec.AuthService.RouterCertSecret

	metaLabels := common.MergeMaps(nil,
		instance.Spec.Labels,
		map[string]string{"app": deployment},
		map[string]string{"operator.ibm.com/bindinfoRefresh": "enabled"},
		ctrlCommon.GetCommonLabels())
	podMetadataLabels := map[string]string{
		"app":                        deployment,
		"k8s-app":                    deployment,
		"component":                  deployment,
		"app.kubernetes.io/instance": "platform-identity-provider",
		"intent":                     "projected",
	}
	podLabels := common.MergeMaps(nil, instance.Spec.Labels, podMetadataLabels, ctrlCommon.GetCommonLabels())

	idpDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployment,
			Namespace: instance.Namespace,
			Labels:    metaLabels,
			Annotations: map[string]string{
				"bindinfoRefresh/configmap": ctrlCommon.DatastoreEDBCMName,
				"bindinfoRefresh/secret":    ctrlCommon.DatastoreEDBSecretName,
			},
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
													Values:   []string{"platform-identity-provider"},
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
					Volumes:        buildIdpVolumes(ldapCACert, routerCertSecret, auditSecretExists, true),
					Containers:     buildProviderContainers(instance, identityProviderImage, icpConsoleURL, saasCrnId, auditSecretExists),
					InitContainers: buildInitForMngrAndProvider(initContainerImage),
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

func generateManagerDeploymentObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, deployment string, icpConsoleURL string, saasCrnId string, auditSecretExists bool) *appsv1.Deployment {

	reqLogger := log.WithValues("deploymentForAuthentication", "Entry", "instance.Name", instance.Name)
	identityManagerImage := common.GetImageRef("ICP_IDENTITY_MANAGER_IMAGE")
	initContainerImage := common.GetImageRef("IM_INITCONTAINER_IMAGE")
	replicas := instance.Spec.Replicas
	ldapCACert := instance.Spec.AuthService.LdapsCACert
	routerCertSecret := instance.Spec.AuthService.RouterCertSecret

	metaLabels := common.MergeMaps(nil,
		instance.Spec.Labels,
		map[string]string{"app": deployment},
		map[string]string{"operator.ibm.com/bindinfoRefresh": "enabled"},
		ctrlCommon.GetCommonLabels())
	podMetadataLabels := map[string]string{
		"app":                        deployment,
		"k8s-app":                    deployment,
		"component":                  deployment,
		"app.kubernetes.io/instance": "platform-identity-management",
		"intent":                     "projected",
	}
	podLabels := common.MergeMaps(nil, instance.Spec.Labels, podMetadataLabels, ctrlCommon.GetCommonLabels())

	idpDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployment,
			Namespace: instance.Namespace,
			Labels:    metaLabels,
			Annotations: map[string]string{
				"bindinfoRefresh/configmap": ctrlCommon.DatastoreEDBCMName,
				"bindinfoRefresh/secret":    ctrlCommon.DatastoreEDBSecretName,
			},
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
													Values:   []string{"platform-identity-management"},
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
					Volumes:        buildIdpVolumes(ldapCACert, routerCertSecret, auditSecretExists, true),
					Containers:     buildManagerContainers(instance, identityManagerImage, icpConsoleURL, auditSecretExists),
					InitContainers: buildInitForMngrAndProvider(initContainerImage),
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

func buildIdpVolumes(ldapCACert string, routerCertSecret string, auditSecretExists bool, required bool) []corev1.Volume {
	auditVolume := corev1.Volume{
		Name: IMAuditTLSVolume,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: AuditTLSSecretName,
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
			Name: "pgsql-ca-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: ctrlCommon.DatastoreEDBSecretName,
					Items: []corev1.KeyToPath{
						{
							Key:  "ca.crt",
							Path: "ca.crt",
						},
					},
				},
			},
		},
		{
			Name: "pgsql-client-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: ctrlCommon.DatastoreEDBSecretName,
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
				},
			},
		},
		{
			Name: "pgsql-client-cred",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: ctrlCommon.DatastoreEDBCMName,
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

	if auditSecretExists && required {
		volumes = EnsureVolumePresent(volumes, auditVolume)
	}
	return volumes
}

// EnsureVolumePresent checks if a volume exists
// If not, it appends the new volume and returns the updated slice.
func EnsureVolumePresent(volumes []corev1.Volume, newVol corev1.Volume) []corev1.Volume {
	for _, v := range volumes {
		if v.Name == newVol.Name {
			return volumes // already exists
		}
	}
	return append(volumes, newVol)
}
