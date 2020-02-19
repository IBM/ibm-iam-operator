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

package policydecision

import (
	"context"
	certmgr "github.com/IBM/ibm-iam-operator/pkg/apis/certmanager/v1alpha1"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	net "k8s.io/api/networking/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_policydecision")
var trueVar bool = true
var falseVar bool = false
var defaultMode int32 = 420
var seconds60 int64 = 60
var user int64 = 21000
var port int32 = 7998

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new PolicyDecision Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcilePolicyDecision{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("policydecision-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource PolicyDecision
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.PolicyDecision{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Certificate and requeue the owner PolicyDecision
	/*err = c.Watch(&source.Kind{Type: &certmgr.Certificate{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.PolicyDecision{},
	})
	if err != nil {
		return err
	}*/

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Service and requeue the owner PolicyDecision
	err = c.Watch(&source.Kind{Type: &corev1.Service{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.PolicyDecision{},
	})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource ConfigMap and requeue the owner PolicyDecision
	err = c.Watch(&source.Kind{Type: &corev1.ConfigMap{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.PolicyDecision{},
	})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Ingress and requeue the owner PolicyDecision
	err = c.Watch(&source.Kind{Type: &net.Ingress{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.PolicyDecision{},
	})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Deployment and requeue the owner PolicyDecision
	err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.PolicyDecision{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcilePolicyDecision implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcilePolicyDecision{}

// ReconcilePolicyDecision reconciles a PolicyDecision object
type ReconcilePolicyDecision struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a PolicyDecision object and makes changes based on the state read
// and what is in the PolicyDecision.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcilePolicyDecision) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling PolicyDecision")

	// Fetch the PolicyDecision instance
	instance := &operatorv1alpha1.PolicyDecision{}
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

	// Check if this Service already exists and create it if it doesn't
	/*currentCertificate := &certmgr.Certificate{}
	recResult, err := r.handleCertificate(instance, currentCertificate)
	if err != nil {
		return recResult, err
	}*/

	// Check if this Service already exists and create it if it doesn't
	currentService := &corev1.Service{}
	recResult, err := r.handleService(instance, currentService)
	if err != nil {
		return recResult, err
	}

	// Check if this ConfigMap already exists and create it if it doesn't
	currentConfigMap := &corev1.ConfigMap{}
	recResult, err = r.handleConfigMap(instance, currentConfigMap)
	if err != nil {
		return recResult, err
	}

	// Check if this Ingress already exists and create it if it doesn't
	currentIngress := &net.Ingress{}
	recResult, err = r.handleIngress(instance, currentIngress)
	if err != nil {
		return recResult, err
	}

	// Check if this Deployment already exists and create it if it doesn't
	currentDeployment := &appsv1.Deployment{}
	recResult, err = r.handleDeployment(instance, currentDeployment)
	if err != nil {
		return recResult, err
	}

	return reconcile.Result{}, nil

}

func (r *ReconcilePolicyDecision) handleCertificate(instance *operatorv1alpha1.PolicyDecision, currentCertificate *certmgr.Certificate) (reconcile.Result, error) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "auth-pdp-cert", Namespace: instance.Namespace}, currentCertificate)
	if err != nil && errors.IsNotFound(err) {
		// Define a new certificate
		newCertificate := r.certificateForPolicyDecision(instance)
		reqLogger.Info("Creating a new Certificate", "Certificate.Namespace", instance.Namespace, "Certificate.Name", "auth-pdp-cert")
		err = r.client.Create(context.TODO(), newCertificate)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Certificate", "Certificate.Namespace", instance.Namespace, "Certificate.Name", "auth-pdp-cert")
			return reconcile.Result{}, err
		}
		// Certificate created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil

}

func (r *ReconcilePolicyDecision) handleConfigMap(instance *operatorv1alpha1.PolicyDecision, currentConfigMap *corev1.ConfigMap) (reconcile.Result, error) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "auth-pdp", Namespace: instance.Namespace}, currentConfigMap)
	if err != nil && errors.IsNotFound(err) {
		// Define a new configmap
		newConfigMap := r.configMapForPolicyDecision(instance)
		reqLogger.Info("Creating a new ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", "auth-pdp")
		err = r.client.Create(context.TODO(), newConfigMap)
		if err != nil {
			reqLogger.Error(err, "Failed to create new ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", "auth-pdp")
			return reconcile.Result{}, err
		}
		// ConfigMap created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil

}

func (r *ReconcilePolicyDecision) handleIngress(instance *operatorv1alpha1.PolicyDecision, currentIngress *net.Ingress) (reconcile.Result, error) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "iam-pdp", Namespace: instance.Namespace}, currentIngress)
	if err != nil && errors.IsNotFound(err) {
		// Define a new ingress
		newIngress := r.ingressForPolicyDecision(instance)
		reqLogger.Info("Creating a new Ingress", "Ingress.Namespace", instance.Namespace, "Ingress.Name", "iam-pdp")
		err = r.client.Create(context.TODO(), newIngress)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Ingress", "Ingress.Namespace", instance.Namespace, "Ingress.Name", "iam-pdp")
			return reconcile.Result{}, err
		}
		// Ingress created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil

}

func (r *ReconcilePolicyDecision) handleService(instance *operatorv1alpha1.PolicyDecision, currentService *corev1.Service) (reconcile.Result, error) {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "iam-pdp", Namespace: instance.Namespace}, currentService)
	if err != nil && errors.IsNotFound(err) {
		// Define a new service
		newService := r.serviceForPolicyDecision(instance)
		reqLogger.Info("Creating a new Service", "Service.Namespace", instance.Namespace, "Service.Name", "iam-pdp")
		err = r.client.Create(context.TODO(), newService)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Service", "Service.Namespace", instance.Namespace, "Service.Name", "iam-pdp")
			return reconcile.Result{}, err
		}
		// Service created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil

}

func (r *ReconcilePolicyDecision) handleDeployment(instance *operatorv1alpha1.PolicyDecision, currentDeployment *appsv1.Deployment) (reconcile.Result, error) {

	// Check if this Deployment already exists
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "auth-pdp", Namespace: instance.Namespace}, currentDeployment)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", "auth-pdp")
		newDeployment := r.deploymentForPolicyDecision(instance)
		err = r.client.Create(context.TODO(), newDeployment)
		if err != nil {
			return reconcile.Result{}, err
		}
		// Deployment created successfully - don't requeue
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels(map[string]string{"k8s-app": "auth-pdp"}),
	}
	if err = r.client.List(context.TODO(), podList, listOpts...); err != nil {
		reqLogger.Error(err, "Failed to list pods", "PolicyDecision.Namespace", instance.Namespace, "PolicyDecision.Name", "auth-pdp")
		return reconcile.Result{}, err
	}
	reqLogger.Info("CS??? get pod names")
	podNames := getPodNames(podList.Items)

	// Update status.Nodes if needed
	if !reflect.DeepEqual(podNames, instance.Status.Nodes) {
		instance.Status.Nodes = podNames
		reqLogger.Info("CS??? put pod names in status")
		err := r.client.Status().Update(context.TODO(), instance)
		if err != nil {
			reqLogger.Error(err, "Failed to update PolicyDecision status")
			return reconcile.Result{}, err
		}
	}
	// Deployment already exists - don't requeue
	reqLogger.Info("Skip reconcile: Deployment already exists", "Deployment.Namespace", instance.Namespace, "Deployment.Name", "auth-pdp")
	return reconcile.Result{}, nil

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

func (r *ReconcilePolicyDecision) certificateForPolicyDecision(instance *operatorv1alpha1.PolicyDecision) *certmgr.Certificate {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	pdpCertificate := &certmgr.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-pdp-cert",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-pdp"},
		},
		Spec: certmgr.CertificateSpec{
			SecretName: "auth-pdp-secret",
			IssuerRef: certmgr.ObjectReference{
				Name: "icp-ca-issuer",
				Kind: certmgr.ClusterIssuerKind,
			},
			CommonName: "iam-pdp",
			DNSNames:   []string{"iam-pdp"},
		},
	}

	// Set PolicyDecision instance as the owner and controller of the Certificate
	err := controllerutil.SetControllerReference(instance, pdpCertificate, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Certificate")
		return nil
	}
	return pdpCertificate

}

func (r *ReconcilePolicyDecision) serviceForPolicyDecision(instance *operatorv1alpha1.PolicyDecision) *corev1.Service {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	pdpService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "iam-pdp",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-pdp"},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "p7998",
					Port: port,
				},
			},
			Selector: map[string]string{
				"k8s-app": "auth-pdp",
			},
			Type: "ClusterIP",
		},
	}

	// Set PolicyDecision instance as the owner and controller of the Service
	err := controllerutil.SetControllerReference(instance, pdpService, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Service")
		return nil
	}
	return pdpService

}

func (r *ReconcilePolicyDecision) configMapForPolicyDecision(instance *operatorv1alpha1.PolicyDecision) *corev1.ConfigMap {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	pdpConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-pdp",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-pdp"},
		},
		Data: map[string]string{
			"AUDIT_ENABLED":  "false",
			"AUDIT_LOG_PATH": "/var/log/audit",
			"JOURNAL_PATH":   instance.Spec.AuditService.JournalPath,
			"logrotate-conf": `\n # rotate log files weekly\ndaily\n\n# use the syslog group by
								default, since this is the owning group # of /var/log/syslog.\n#su root syslog\n\n#
								keep 4 weeks worth of backlogs\nrotate 4\n\n# create new (empty) log files after
								rotating old ones \ncreate\n\n# uncomment this if you want your log files compressed\n
								#compress\n\n# packages drop log rotation information into this directory\n include
								/etc/logrotate.d\n# no packages own wtmp, or btmp -- we'll rotate them here\n`,
			"logrotate": "/var/log/audit/*.log {\n  copytruncate\n  rotate 24\n  hourly\n  missingok\n  notifempty\n}",
		},
	}

	// Set PolicyDecision instance as the owner and controller of the ConfigMap
	err := controllerutil.SetControllerReference(instance, pdpConfigMap, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
		return nil
	}
	return pdpConfigMap
}

func (r *ReconcilePolicyDecision) ingressForPolicyDecision(instance *operatorv1alpha1.PolicyDecision) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	pdpIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "iam-pdp",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-pdp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/secure-backends": "true",
				"icp.management.ibm.com/rewrite-target":  "/",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/iam-pdp/",
									Backend: net.IngressBackend{
										ServiceName: "iam-pdp",
										ServicePort: intstr.IntOrString{
											IntVal: port,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set PolicyDecision instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, pdpIngress, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return pdpIngress

}

func (r *ReconcilePolicyDecision) deploymentForPolicyDecision(instance *operatorv1alpha1.PolicyDecision) *appsv1.Deployment {

	reqLogger := log.WithValues("deploymentForPolicyDecision", "Entry", "instance.Name", instance.Name)
	pdpImage := instance.Spec.ImageRegistry + "/" + instance.Spec.ImageName + ":" + instance.Spec.ImageTag
	mongoDBImage := instance.Spec.InitMongodb.ImageRegistry + "/" + instance.Spec.InitMongodb.ImageName + ":" + instance.Spec.InitMongodb.ImageTag
	auditImage := instance.Spec.AuditService.ImageRegistry + "/" + instance.Spec.AuditService.ImageName + ":" + instance.Spec.AuditService.ImageTag
	replicas := instance.Spec.Replicas
	journalPath := instance.Spec.AuditService.JournalPath

	pdpDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-pdp",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-pdp"},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":       "auth-pdp",
					"k8s-app":   "auth-pdp",
					"component": "auth-pdp",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":       "auth-pdp",
						"k8s-app":   "auth-pdp",
						"component": "auth-pdp",
					},
					Annotations: map[string]string{
						"scheduler.alpha.kubernetes.io/critical-pod": "",
						"productName":    "IBM Cloud Platform Common Services",
						"productID":      "IBMCloudPlatformCommonServices_342_apache_0000",
						"productVersion": "3.4.2",
						"seccomp.security.alpha.kubernetes.io/pod": "docker/default",
					},
				},
				Spec: corev1.PodSpec{
					NodeSelector:                  map[string]string{"master": "true"},
					TerminationGracePeriodSeconds: &seconds60,
					HostIPC:                       falseVar,
					HostPID:                       falseVar,
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
								NodeSelectorTerms: []corev1.NodeSelectorTerm{
									{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{
												Key:      "beta.kubernetes.io/arch",
												Operator: corev1.NodeSelectorOpIn,
												Values:   []string{"amd64"},
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
					Volumes:        buildPdpVolumes(journalPath),
					Containers:     buildContainers(auditImage, pdpImage, journalPath),
					InitContainers: buildInitContainers(mongoDBImage),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser: &user,
						FSGroup:   &user,
					},
				},
			},
		},
	}
	// Set SecretWatcher instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, pdpDeployment, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Deployment")
		return nil
	}
	return pdpDeployment

}

func buildPdpVolumes(journalPath string) []corev1.Volume {
	return []corev1.Volume{
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
			Name: "mongodb-client-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "icp-mongodb-client-cert",
				},
			},
		},
		{
			Name: "journal",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: journalPath,
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
						Name: "auth-pdp",
					},
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
					Items: []corev1.KeyToPath{
						{
							Key:  "logrotate-conf",
							Path: "logrotate.conf",
						},
					},
				},
			},
		},
	}
}
