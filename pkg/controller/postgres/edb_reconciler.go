//
// Copyright 2022 IBM Corporation
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

package postgres

import (
	"context"
	"os"

	certmgr "github.com/IBM/ibm-iam-operator/pkg/apis/certmanager/v1alpha1"
	enterprisedbv1 "github.com/IBM/ibm-iam-operator/pkg/apis/postgresql/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	crmanager "sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_postgres")
var EDBCRName = "cluster-psql-iam"

// IamPostgresServerCertificateValues defines the values of iam-postgres certificate
type IamPostgresServerCertificateValues struct {
	Name       string
	SecretName string
	CN         []string
}
type IamPostgresClientCertificateValues struct {
	Name       string
	SecretName string
	CommonName string
}

var iamPostgresServerCertificateValues = IamPostgresServerCertificateValues{
	Name:       "iam-postgres-server-cert",
	SecretName: "iam-postgres-server-cert",
	CN:         []string{EDBCRName + "-rw", EDBCRName + "-ro", EDBCRName + "-r"},
}

var iamPostgresClientCertificateValues = IamPostgresClientCertificateValues{
	Name:       "iam-postgres-client-cert",
	SecretName: "iam-postgres-client-cert",
	CommonName: "streaming_replica",
}

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new EDB Cluster Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr crmanager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr crmanager.Manager) reconcile.Reconciler {
	return &ReconcileEDBPostgres{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr crmanager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("postgres-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}
	// Watch for changes to primary resource Cluster
	err = c.Watch(&source.Kind{Type: &enterprisedbv1.Cluster{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}
	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Certificate and requeue the owner Authentication
	err = c.Watch(&source.Kind{Type: &certmgr.Certificate{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &enterprisedbv1.Cluster{},
	})
	if err != nil {
		return err
	}
	return nil
}

// blank assignment to verify that ReconcileEDBPostgres implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileEDBPostgres{}

// ReconcileEDBPostgres reconciles a EDB Cluster object
type ReconcileEDBPostgres struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a EDB CLuster object and makes changes based on the state read
// and what is in the Cluster.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileEDBPostgres) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling EDB Cluster")
	var requeueResult bool = false

	// Check if this EDB Cluster CR already exists and create it if it doesn't
	currentPostgresCluster := &enterprisedbv1.Cluster{}
	err := r.handleEDBClusterCR(currentPostgresCluster, &requeueResult)
	if err != nil {
		return reconcile.Result{}, err
	}
	// Check if this Certificate already exists and create it if it doesn't
	currentCertificate := &certmgr.Certificate{}
	err = r.handleCertificate(currentPostgresCluster, currentCertificate, &requeueResult)
	if err != nil {
		return reconcile.Result{}, err
	}
	if requeueResult {
		return reconcile.Result{Requeue: true}, nil
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileEDBPostgres) handleEDBClusterCR(instance *enterprisedbv1.Cluster, requeueResult *bool) error {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: EDBCRName, Namespace: instance.Namespace}, instance)
	if err != nil && k8serrors.IsNotFound(err) {
		// Define a new Cluster CR
		edbClusterCR := r.edbPostgresCluster(instance)
		reqLogger.Info("Creating a new EDB Cluster CR")
		err = r.client.Create(context.TODO(), edbClusterCR)
		if err != nil {
			reqLogger.Error(err, "Failed to create EDB cluster CR "+EDBCRName)
			return err
		}
		// Cluster CR created successfully - return and requeue
		*requeueResult = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Postgres Cluster CR")
		return err
	}
	return nil
}

func (r *ReconcileEDBPostgres) edbPostgresCluster(instance *enterprisedbv1.Cluster) *enterprisedbv1.Cluster {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	edbCr := instance

	edbCr.ObjectMeta.Name = EDBCRName
	edbCr.ObjectMeta.Namespace = instance.Namespace
	edbCr.ObjectMeta.Labels = map[string]string{"app": "security-iam"}
	edbCr.Spec.Instances = 3
	edbCr.Spec.Resources = &enterprisedbv1.Resources{
		Requests: &enterprisedbv1.Requests{
			Cpu:    "2",
			Memory: "2048",
		},
		Limits: &enterprisedbv1.Limits{
			Cpu:    "4",
			Memory: "4096",
		},
	}
	edbCr.Spec.Certificates.ServerCASecret = iamPostgresServerCertificateValues.SecretName
	edbCr.Spec.Certificates.ServerTLSSecret = iamPostgresServerCertificateValues.SecretName
	edbCr.Spec.Certificates.ClientCASecret = iamPostgresClientCertificateValues.SecretName
	edbCr.Spec.Certificates.ReplicationTLSSecret = iamPostgresClientCertificateValues.SecretName
	postgresImageOverride := os.Getenv("POSTGRES_IMAGE_OVERRIDE")
	if postgresImageOverride != "" {
		edbCr.Spec.ImageName = postgresImageOverride
	}
	// Set EDB Cluster instance as the owner and controller of the CR
	err := controllerutil.SetControllerReference(instance, edbCr, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Cluster CR")
		return nil
	}
	return edbCr
}

func (r *ReconcileEDBPostgres) handleCertificate(instance *enterprisedbv1.Cluster, currentCertificate *certmgr.Certificate, needToRequeue *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: iamPostgresServerCertificateValues.Name, Namespace: instance.Namespace}, currentCertificate)
	if err != nil && k8serrors.IsNotFound(err) {
		// Define a new Server certificate
		newCertificate := r.certificateForEDBCluster(instance)
		reqLogger.Info("Creating a new server Certificate", "Certificate.Namespace", instance.Namespace, "Certificate.Name", iamPostgresServerCertificateValues.Name)
		err = r.client.Create(context.TODO(), newCertificate)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Certificate", "Certificate.Namespace", instance.Namespace, "Certificate.Name", iamPostgresServerCertificateValues.Name)
			return err
		}
		// Server Certificate created successfully - return and requeue
		*needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Server Certificate")
		return err
	}

	err = r.client.Get(context.TODO(), types.NamespacedName{Name: iamPostgresClientCertificateValues.Name, Namespace: instance.Namespace}, currentCertificate)
	if err != nil && k8serrors.IsNotFound(err) {
		// Define a new Client certificate
		newCertificate := r.certificateForEDBClient(instance)
		reqLogger.Info("Creating a new client Certificate", "Certificate.Namespace", instance.Namespace, "Certificate.Name", iamPostgresClientCertificateValues.Name)
		err = r.client.Create(context.TODO(), newCertificate)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Certificate", "Certificate.Namespace", instance.Namespace, "Certificate.Name", iamPostgresClientCertificateValues.Name)
			return err
		}
		// Client Certificate created successfully - return and requeue
		*needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Client Certificate")
		return err
	}

	return nil

}

func (r *ReconcileEDBPostgres) certificateForEDBCluster(instance *enterprisedbv1.Cluster) *certmgr.Certificate {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	edbServerCertificate := &certmgr.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      iamPostgresServerCertificateValues.Name,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "security-iam", "k8s.enterprisedb.io/reload": ""},
		},
		Spec: certmgr.CertificateSpec{
			SecretName: iamPostgresServerCertificateValues.SecretName,
			IssuerRef: certmgr.ObjectReference{
				Name: "cs-ca-issuer",
				Kind: certmgr.IssuerKind,
			},
			DNSNames: iamPostgresServerCertificateValues.CN,
			Usages:   []certmgr.KeyUsage{"server auth"},
		},
	}

	// Set Pap instance as the owner and controller of the Certificate
	err := controllerutil.SetControllerReference(instance, edbServerCertificate, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Certificate")
		return nil
	}
	return edbServerCertificate
}

func (r *ReconcileEDBPostgres) certificateForEDBClient(instance *enterprisedbv1.Cluster) *certmgr.Certificate {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	edbClientCertificate := &certmgr.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      iamPostgresClientCertificateValues.Name,
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "security-iam", "k8s.enterprisedb.io/reload": ""},
		},
		Spec: certmgr.CertificateSpec{
			SecretName: iamPostgresClientCertificateValues.SecretName,
			IssuerRef: certmgr.ObjectReference{
				Name: "cs-ca-issuer",
				Kind: certmgr.IssuerKind,
			},
			CommonName: iamPostgresClientCertificateValues.CommonName,
			Usages:     []certmgr.KeyUsage{"client auth"},
		},
	}

	// Set Pap instance as the owner and controller of the Certificate
	err := controllerutil.SetControllerReference(instance, edbClientCertificate, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Certificate")
		return nil
	}
	return edbClientCertificate

}
