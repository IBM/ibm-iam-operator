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

package pap

import (
	"context"
	"reflect"

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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// IamPapServiceValues defines the values of iam-pap service
type IamPapServiceValues struct {
	Name     string
	PodName  string
	Type     corev1.ServiceType
	PortName string
	Port     int32
}

// IamPapCertificateValues defines the values of iam-pap certificate
type IamPapCertificateValues struct {
	Name       string
	SecretName string
	CN         string
}

// ConfigValues defines the values of pap config
type ConfigValues struct {
	ClusterCAIssuer string
}

// AuthPapValues defines the values of auth-pap container
type AuthPapValues struct {
	Name        string
	HostNetwork bool
	Image       struct {
		Repository string
		Tag        string
		PullPolicy string
	}
	Resources struct {
		Requests struct {
			CPU    string
			Memory string
		}
		Limits struct {
			CPU    string
			Memory string
		}
	}
	ContainerSecurityContext struct {
		Privileged               bool
		RunAsNonRoot             bool
		ReadOnlyRootFilesystem   bool
		AllowPrivilegeEscalation bool
		Capabilities             struct {
			Drop []string
		}
	}
	PodSecurityContext struct {
		RunAsUser int
		FsGroup   int
	}
	NodeSelector struct {
		Master string
	}
	Tolerations []struct {
		Key      string
		Operator string
		Effect   string
	}
}

// IcpAuditValues defines the values of icp-audit container
type IcpAuditValues struct {
	Name  string
	Image struct {
		Repository string
		Tag        string
		PullPolicy string
	}
	Resources struct {
		Requests struct {
			CPU    string
			Memory string
		}
		Limits struct {
			CPU    string
			Memory string
		}
	}
	ContainerSecurityContext struct {
		Privileged               bool
		RunAsNonRoot             bool
		ReadOnlyRootFilesystem   bool
		AllowPrivilegeEscalation bool
		RunAsUser                int
		SeLinuxOptions           struct {
			Type string
		}
		Capabilities struct {
			Drop []string
		}
	}
	Config struct {
		JournalPath string
	}
}

var log = logf.Log.WithName("controller_pap")

var trueVar bool = true
var falseVar bool = false
var defaultMode int32 = 420
var seconds60 int64 = 60
var user int64 = 21000
var serviceAccountName string = "ibm-iam-operator"

//var port int32 = 39001
var iamPapServiceValues = IamPapServiceValues{
	Name:     "iam-pap",
	PodName:  "auth-pap",
	Type:     "ClusterIP",
	PortName: "p39001",
	Port:     39001,
}

var iamPapCertificateValues = IamPapCertificateValues{
	Name:       "iam-pap-cert",
	SecretName: "iam-pap-secret",
	CN:         "iam-pap",
}

var configvalues = ConfigValues{
	ClusterCAIssuer: "icp-ca-issuer",
}

/*
var authPapValues = AuthPapValues{
	Name:        "auth-pap",
	HostNetwork: false,
	Image:       struct {
		Repository string
		Tag        string
		PullPolicy string
	}{
		Repository: "ibmcom/iam-policy-administration",
		Tag:        "3.3.2",
		PullPolicy: "Always",
	},
	Resources: struct {
		Requests: struct {
			CPU    string
			Memory string
		}{
			CPU:   "50m",
			Memory: "200Mi",
		},
		Limits: struct {
			CPU    string
			Memory string
		}{
			CPU:    "1000m",
			Memory: "1024Mi",
		}
	},
	ContainerSecurityContext: struct {
		Privileged               bool
		RunAsNonRoot             bool
		ReadOnlyRootFilesystem   bool
		AllowPrivilegeEscalation bool
		Capabilities             struct {
			Drop []string
		}
	}{
		Privileged:               false,
		RunAsNonRoot:             true,
		ReadOnlyRootFilesystem:   true,
		AllowPrivilegeEscalation: false,
		Capabilities:            struct {
			Drop []string
		}{
			Drop: []string {"ALL"},
		}
	},
	PodSecurityContext: struct {
		RunAsUser int
		FsGroup   int
	}{
		RunAsUser: 21000,
		FsGroup:   21000,
	},
	NodeSelector: struct {
		Master string
	}{
		Master: "true",
	},
	Tolerations: []struct {
		Key      string
		Operator string
		Effect   string
	}{
		Key      "dedicated",
		Operator "Exists",
		Effect   "NoSchedule",
	},{
		Key      "CriticalAddonsOnly",
		Operator "Exists",
		Effect   "",
	},
}
*/

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new Pap Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcilePap{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("pap-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource Pap
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.Pap{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Certificate and requeue the owner Pap
	/*err = c.Watch(&source.Kind{Type: &certmgr.Certificate{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.Pap{},
	})
	if err != nil {
		return err
	}*/

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Service and requeue the owner Pap
	err = c.Watch(&source.Kind{Type: &corev1.Service{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.Pap{},
	})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource ConfigMap and requeue the owner Pap
	err = c.Watch(&source.Kind{Type: &corev1.ConfigMap{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.Pap{},
	})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Ingress and requeue the owner Pap
	err = c.Watch(&source.Kind{Type: &net.Ingress{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.Pap{},
	})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Deployment and requeue the owner Pap
	err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.Pap{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcilePap implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcilePap{}

// ReconcilePap reconciles a Pap object
type ReconcilePap struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a Pap object and makes changes based on the state read
// and what is in the Pap.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcilePap) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Pap")

	// if we need to create several resources, set a flag so we just requeue one time instead of after each create.
	needToRequeue := false

	// Fetch the Pap instance
	instance := &operatorv1alpha1.Pap{}
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

	// Check if this Certificate already exists and create it if it doesn't
	/*currentCertificate := &certmgr.Certificate{}
	err = r.handleCertificate(instance, currentCertificate, &needToRequeue)
	if err != nil {
		return reconcile.Result{}, err
	}*/

	// Check if this Service already exists and create it if it doesn't
	currentService := &corev1.Service{}
	err = r.handleService(instance, currentService, &needToRequeue)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ConfigMap already exists and create it if it doesn't
	currentConfigMap := &corev1.ConfigMap{}
	err = r.handleConfigMap(instance, currentConfigMap, &needToRequeue)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Check if this Ingress already exists and create it if it doesn't
	currentIngress := &net.Ingress{}
	err = r.handleIngress(instance, currentIngress, &needToRequeue)
	if err != nil {
		return reconcile.Result{}, err
	}

	if needToRequeue {
		// one or more resources was created, so requeue the request
		reqLogger.Info("Requeue the request")
		return reconcile.Result{Requeue: true}, nil
	}

	// Check if this Deployment already exists and create it if it doesn't
	currentDeployment := &appsv1.Deployment{}
	err = r.handleDeployment(instance, currentDeployment)
	if err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *ReconcilePap) handleCertificate(instance *operatorv1alpha1.Pap, currentCertificate *certmgr.Certificate, needToRequeue *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: iamPapCertificateValues.Name, Namespace: instance.Namespace}, currentCertificate)
	if err != nil && errors.IsNotFound(err) {
		// Define a new certificate
		newCertificate := r.certificateForPap(instance)
		reqLogger.Info("Creating a new Certificate", "Certificate.Namespace", instance.Namespace, "Certificate.Name", iamPapCertificateValues.Name)
		err = r.client.Create(context.TODO(), newCertificate)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Certificate", "Certificate.Namespace", instance.Namespace, "Certificate.Name", iamPapCertificateValues.Name)
			return err
		}
		// Certificate created successfully - return and requeue
		*needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Certificate")
		return err
	}

	return nil

}

func (r *ReconcilePap) handleConfigMap(instance *operatorv1alpha1.Pap, currentConfigMap *corev1.ConfigMap, needToRequeue *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: iamPapServiceValues.PodName, Namespace: instance.Namespace}, currentConfigMap)
	if err != nil && errors.IsNotFound(err) {
		// Define a new configmap
		newConfigMap := r.configMapForPap(instance)
		reqLogger.Info("Creating a new ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", iamPapServiceValues.PodName)
		err = r.client.Create(context.TODO(), newConfigMap)
		if err != nil {
			reqLogger.Error(err, "Failed to create new ConfigMap", "ConfigMap.Namespace", instance.Namespace, "ConfigMap.Name", iamPapServiceValues.PodName)
			return err
		}
		// ConfigMap created successfully - return and requeue
		*needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get ConfigMap")
		return err
	}

	return nil
}

func (r *ReconcilePap) handleIngress(instance *operatorv1alpha1.Pap, currentIngress *net.Ingress, needToRequeue *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: iamPapServiceValues.Name, Namespace: instance.Namespace}, currentIngress)
	if err != nil && errors.IsNotFound(err) {
		// Define a new ingress
		newIngress := r.ingressForPap(instance)
		reqLogger.Info("Creating a new Ingress", "Ingress.Namespace", instance.Namespace, "Ingress.Name", iamPapServiceValues.Name)
		err = r.client.Create(context.TODO(), newIngress)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Ingress", "Ingress.Namespace", instance.Namespace, "Ingress.Name", iamPapServiceValues.Name)
			return err
		}
		// Ingress created successfully - return and requeue
		*needToRequeue = true
		return nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Ingress")
		return err
	}

	return nil

}

func (r *ReconcilePap) handleService(instance *operatorv1alpha1.Pap, currentService *corev1.Service, needToRequeue *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: iamPapServiceValues.Name, Namespace: instance.Namespace}, currentService)
	if err != nil && errors.IsNotFound(err) {
		// Define a new service
		newService := r.serviceForPap(instance)
		reqLogger.Info("Creating a new Service", "Service.Namespace", instance.Namespace, "Service.Name", iamPapServiceValues.Name)
		err = r.client.Create(context.TODO(), newService)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Service", "Service.Namespace", instance.Namespace, "Service.Name", iamPapServiceValues.Name)
			return err
		}
		// Service created successfully - return and requeue
		*needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return err
	}

	return nil
}

func (r *ReconcilePap) handleDeployment(instance *operatorv1alpha1.Pap, currentDeployment *appsv1.Deployment) error {

	// Check if this Deployment already exists
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: iamPapServiceValues.PodName, Namespace: instance.Namespace}, currentDeployment)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new Deployment", "Deployment.Namespace", instance.Namespace, "Deployment.Name", iamPapServiceValues.PodName)
		newDeployment := r.deploymentForPap(instance)
		err = r.client.Create(context.TODO(), newDeployment)
		if err != nil {
			return err
		}
		// Deployment created successfully - don't requeue
		return nil
	} else if err != nil {
		return err
	}

	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels(map[string]string{"k8s-app": iamPapServiceValues.PodName}),
	}
	if err = r.client.List(context.TODO(), podList, listOpts...); err != nil {
		reqLogger.Error(err, "Failed to list pods", "Pap.Namespace", instance.Namespace, "Pap.Name", iamPapServiceValues.PodName)
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
			reqLogger.Error(err, "Failed to update Pap status")
			return err
		}
	}

	// Deployment already exists - don't requeue
	reqLogger.Info("Skip reconcile: Deployment already exists", "Deployment.Namespace", instance.Namespace, "Deployment.Name", iamPapServiceValues.PodName)
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

func (r *ReconcilePap) certificateForPap(instance *operatorv1alpha1.Pap) *certmgr.Certificate {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	papCertificate := &certmgr.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      iamPapCertificateValues.Name,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": iamPapServiceValues.PodName},
		},
		Spec: certmgr.CertificateSpec{
			SecretName: iamPapCertificateValues.SecretName,
			IssuerRef: certmgr.ObjectReference{
				Name: configvalues.ClusterCAIssuer,
				Kind: certmgr.ClusterIssuerKind,
			},
			CommonName: iamPapCertificateValues.CN,
			DNSNames:   []string{iamPapCertificateValues.CN},
		},
	}

	// Set Pap instance as the owner and controller of the Certificate
	err := controllerutil.SetControllerReference(instance, papCertificate, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Certificate")
		return nil
	}
	return papCertificate

}

func (r *ReconcilePap) serviceForPap(instance *operatorv1alpha1.Pap) *corev1.Service {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	papService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      iamPapServiceValues.Name,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": iamPapServiceValues.PodName},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: iamPapServiceValues.PortName,
					Port: iamPapServiceValues.Port,
				},
			},
			Selector: map[string]string{
				"k8s-app": iamPapServiceValues.PodName,
			},
			Type: iamPapServiceValues.Type,
		},
	}

	// Set Pap instance as the owner and controller of the Service
	err := controllerutil.SetControllerReference(instance, papService, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Service")
		return nil
	}
	return papService

}

func (r *ReconcilePap) configMapForPap(instance *operatorv1alpha1.Pap) *corev1.ConfigMap {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	papConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      iamPapServiceValues.PodName,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": iamPapServiceValues.PodName},
		},
		Data: map[string]string{
			"AUDIT_ENABLED": "false",
			"AUDIT_DETAIL":  "false",
			"JOURNAL_PATH":  instance.Spec.AuditService.JournalPath,
			"logrotate-conf": "\n # rotate log files weekly\ndaily\n\n# use the syslog group by " +
				"default, since this is the owning group # of /var/log/syslog.\n#su root syslog\n\n# " +
				"keep 4 weeks worth of backlogs\nrotate 4\n\n# create new (empty) log files after " +
				"rotating old ones \ncreate\n\n# uncomment this if you want your log files compressed\n " +
				"#compress\n\n# packages drop log rotation information into this directory\n include " +
				"/etc/logrotate.d\n# no packages own wtmp, or btmp -- we'll rotate them here\n",
			"logrotate": "/app/audit/*.log {\n  copytruncate\n  rotate 24\n  hourly\n  missingok\n  notifempty\n}",
		},
	}

	// Set Pap instance as the owner and controller of the ConfigMap
	err := controllerutil.SetControllerReference(instance, papConfigMap, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for ConfigMap")
		return nil
	}
	return papConfigMap
}

func (r *ReconcilePap) ingressForPap(instance *operatorv1alpha1.Pap) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	papIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      iamPapServiceValues.Name,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": iamPapServiceValues.PodName},
			Annotations: map[string]string{
				"icp.management.ibm.com/secure-backends": "true",
				"kubernetes.io/ingress.class":            "ibm-icp-management",
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
									Path: "/iam-pap/",
									Backend: net.IngressBackend{
										ServiceName: iamPapServiceValues.Name,
										ServicePort: intstr.IntOrString{
											IntVal: iamPapServiceValues.Port,
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

	// Set Pap instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, papIngress, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return papIngress

}

func (r *ReconcilePap) deploymentForPap(instance *operatorv1alpha1.Pap) *appsv1.Deployment {

	reqLogger := log.WithValues("deploymentForPap", "Entry", "instance.Name", instance.Name)
	papImage := instance.Spec.PapService.ImageRegistry + "/" + instance.Spec.PapService.ImageName + ":" + instance.Spec.PapService.ImageTag
	auditImage := instance.Spec.AuditService.ImageRegistry + "/" + instance.Spec.AuditService.ImageName + ":" + instance.Spec.AuditService.ImageTag
	replicas := instance.Spec.Replicas
	journalPath := instance.Spec.AuditService.JournalPath

	papDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      iamPapServiceValues.PodName,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": iamPapServiceValues.PodName},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":       iamPapServiceValues.PodName,
					"k8s-app":   iamPapServiceValues.PodName,
					"component": iamPapServiceValues.PodName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":       iamPapServiceValues.PodName,
						"k8s-app":   iamPapServiceValues.PodName,
						"component": iamPapServiceValues.PodName,
					},
					Annotations: map[string]string{
						"scheduler.alpha.kubernetes.io/critical-pod": "",
						"productName":    "IBM Cloud Platform Common Services",
						"productID":      "IBMCloudPlatformCommonServices_341_apache_0000",
						"productVersion": "3.4.2",
						"seccomp.security.alpha.kubernetes.io/pod": "docker/default",
					},
				},
				Spec: corev1.PodSpec{
					TerminationGracePeriodSeconds: &seconds60,
					HostIPC:                       falseVar,
					HostPID:                       falseVar,
					ServiceAccountName:            serviceAccountName,
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
					Volumes:    buildPapVolumes(journalPath),
					Containers: buildContainers(auditImage, papImage, journalPath),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser: &user,
						FSGroup:   &user,
					},
				},
			},
		},
	}
	// Set SecretWatcher instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, papDeployment, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Deployment")
		return nil
	}
	return papDeployment

}

func buildPapVolumes(journalPath string) []corev1.Volume {
	return []corev1.Volume{
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
			Name: "cluster-ca",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					DefaultMode: &defaultMode,
					SecretName:  "cluster-ca-cert",
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
					DefaultMode: &defaultMode,
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "auth-pap",
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
					DefaultMode: &defaultMode,
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "auth-pap",
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
		{
			Name: "pap-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "iam-pap-secret",
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
	}
}
