/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package operator

import (
	"context"

	"fmt"
	"reflect"
	"sync"
	"time"

	ctrlcommon "github.com/IBM/ibm-iam-operator/controllers/common"
	database "github.com/IBM/ibm-iam-operator/database"
	dbconn "github.com/IBM/ibm-iam-operator/database/connectors"
	"github.com/IBM/ibm-iam-operator/database/migration"
	certmgr "github.com/ibm/ibm-cert-manager-operator/apis/cert-manager/v1"
	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	net "k8s.io/api/networking/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	handler "sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	zenv1 "github.com/IBM/ibm-iam-operator/apis/zen.cpd.ibm.com/v1"
	"github.com/opdev/subreconciler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("controller_authentication")
var fullAccess int32 = 0777
var trueVar bool = true
var falseVar bool = false
var seconds60 int64 = 60
var partialAccess int32 = 420
var authServicePort int32 = 9443
var identityProviderPort int32 = 4300
var identityManagerPort int32 = 4500
var serviceAccountName string = "ibm-iam-operand-restricted"

var cpu10 = resource.NewMilliQuantity(10, resource.DecimalSI)            // 10m
var cpu50 = resource.NewMilliQuantity(50, resource.DecimalSI)            // 50m
var cpu100 = resource.NewMilliQuantity(100, resource.DecimalSI)          // 100m
var cpu1000 = resource.NewMilliQuantity(1000, resource.DecimalSI)        // 1000m
var memory32 = resource.NewQuantity(100*1024*1024, resource.BinarySI)    // 32Mi
var memory128 = resource.NewQuantity(128*1024*1024, resource.BinarySI)   // 128Mi
var memory150 = resource.NewQuantity(150*1024*1024, resource.BinarySI)   // 150Mi
var memory178 = resource.NewQuantity(178*1024*1024, resource.BinarySI)   // 178Mi
var memory300 = resource.NewQuantity(300*1024*1024, resource.BinarySI)   // 300Mi
var memory350 = resource.NewQuantity(350*1024*1024, resource.BinarySI)   // 350Mi
var memory400 = resource.NewQuantity(400*1024*1024, resource.BinarySI)   // 400Mi
var memory550 = resource.NewQuantity(550*1024*1024, resource.BinarySI)   // 550Mi
var memory650 = resource.NewQuantity(650*1024*1024, resource.BinarySI)   // 650Mi
var memory1024 = resource.NewQuantity(1024*1024*1024, resource.BinarySI) // 1024Mi

// migrationWait is used when still waiting on a result to be produced by the migration worker
var migrationWait time.Duration = 10 * time.Second

// opreqWait is used for the resources that interact with and originate from OperandRequests
var opreqWait time.Duration = 100 * time.Millisecond

// defaultLowerWait is used in instances where a requeue is needed quickly, regardless of previous requeues
var defaultLowerWait time.Duration = 5 * time.Millisecond

var rule = `^([a-z0-9]){32,}$`
var wlpClientID = ctrlcommon.GenerateRandomString(rule)
var wlpClientSecret = ctrlcommon.GenerateRandomString(rule)

// finalizerName is the finalizer appended to the Authentication CR
var finalizerName = "authentication.operator.ibm.com"

// FinalizerMigration is the finalizer appended to resources that are being retained during migration
const FinalizerMigration string = "authentication.operator.ibm.com/migration"

func (r *AuthenticationReconciler) addMongoMigrationFinalizer(ctx context.Context, key client.ObjectKey, obj client.Object) (updated bool, err error) {
	if err = r.Get(ctx, key, obj); k8sErrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	added := controllerutil.AddFinalizer(obj, FinalizerMigration)
	if added {
		if err := r.Update(ctx, obj); err != nil {
			return false, err
		}
		return true, nil
	}

	return false, nil
}

func (r *AuthenticationReconciler) finalizeMongoMigrationObject(ctx context.Context, key client.ObjectKey, obj client.Object) (finalized bool, err error) {
	if err = r.Get(ctx, key, obj); k8sErrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	removed := controllerutil.RemoveFinalizer(obj, FinalizerMigration)
	if removed {
		if err := r.Update(ctx, obj); k8sErrors.IsNotFound(err) {
			return false, nil
		} else if err != nil {
			return false, err
		}

		if err = r.Get(ctx, key, obj); k8sErrors.IsNotFound(err) {
			return true, nil
		} else if err != nil {
			return false, err
		}
	}

	if err = r.Delete(ctx, obj); err != nil && !k8sErrors.IsNotFound(err) {
		return false, err
	}

	return true, nil
}

func (r *AuthenticationReconciler) addMongoMigrationFinalizers(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "addFinalizers")
	reqLogger.Info("Add finalizers to MongoDB resources in case migration is needed")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	if needToMigrate, err := r.needToMigrateFromMongo(ctx, authCR); !needToMigrate && err == nil {
		reqLogger.Info("No MongoDB migration required, so no need for finalizers; continuing")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		reqLogger.Error(err, "Failed to determine whether migration from MongoDB is needed")
		return subreconciler.RequeueWithError(err)
	}

	updated := false

	mongoDBServiceName := "mongodb"
	mongoDBPreloadCMName := "mongodb-preload-endpoint"
	mongoAdminCredsName := "icp-mongodb-admin"
	mongoClientCertName := "icp-mongodb-client-cert"
	mongoCACertName := "mongodb-root-ca-cert"
	toAddFinalizer := map[client.ObjectKey]client.Object{
		types.NamespacedName{Name: mongoDBServiceName, Namespace: req.Namespace}:   &corev1.Service{},
		types.NamespacedName{Name: mongoDBPreloadCMName, Namespace: req.Namespace}: &corev1.ConfigMap{},
		types.NamespacedName{Name: mongoAdminCredsName, Namespace: req.Namespace}:  &corev1.Secret{},
		types.NamespacedName{Name: mongoClientCertName, Namespace: req.Namespace}:  &corev1.Secret{},
		types.NamespacedName{Name: mongoCACertName, Namespace: req.Namespace}:      &corev1.Secret{},
	}

	for key, obj := range toAddFinalizer {
		var objUpdated bool
		if objUpdated, err = r.addMongoMigrationFinalizer(ctx, key, obj); k8sErrors.IsNotFound(err) {
			reqLogger.Info("Object not found; not adding migration finalizer",
				"Object.Name", key.Name,
				"Object.Namespace", key.Namespace)
		} else if err != nil {
			reqLogger.Error(err, "Failed to update object due to an unexpected error",
				"Object.Name", key.Name,
				"Object.Namespace", key.Namespace)
			return subreconciler.RequeueWithError(err)
		} else if objUpdated {
			reqLogger.Info("Migration finalizer written to object",
				"Object.Name", key.Name,
				"Object.Namespace", key.Namespace)
			updated = true
		} else {
			reqLogger.Info("Object already had migration finalizer",
				"Object.Name", key.Name,
				"Object.Namespace", key.Namespace)
		}
	}

	if updated {
		reqLogger.Info("Resources updated with finalizers; requeueing")
		subreconciler.Requeue()
	}

	return subreconciler.ContinueReconciling()
}

func (r *AuthenticationReconciler) handleMongoDBCleanup(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "handleMongoDBCleanup")
	reqLogger.Info("Clean up MongoDB resources if no longer needed")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	// if retain annotation is unset or set to true - continue reconciling
	if authCR.HasNotBeenMigrated() {
		reqLogger.Info("Migrations have not completed yet; skipping")
		return subreconciler.ContinueReconciling()
	}
	reqLogger.Info("Condition indicates migrations have completed")

	mongoDBServiceName := "mongodb"
	mongoDBPreloadCMName := "mongodb-preload-endpoint"
	mongoAdminCredsName := "icp-mongodb-admin"
	mongoClientCertName := "icp-mongodb-client-cert"
	mongoCACertName := "mongodb-root-ca-cert"
	toFinalize := map[client.ObjectKey]client.Object{
		types.NamespacedName{Name: mongoDBServiceName, Namespace: req.Namespace}:   &corev1.Service{},
		types.NamespacedName{Name: mongoDBPreloadCMName, Namespace: req.Namespace}: &corev1.ConfigMap{},
		types.NamespacedName{Name: mongoAdminCredsName, Namespace: req.Namespace}:  &corev1.Secret{},
		types.NamespacedName{Name: mongoClientCertName, Namespace: req.Namespace}:  &corev1.Secret{},
		types.NamespacedName{Name: mongoCACertName, Namespace: req.Namespace}:      &corev1.Secret{},
	}

	anyObjUpdated := false
	for key, obj := range toFinalize {
		var objUpdated bool
		if objUpdated, err = r.finalizeMongoMigrationObject(ctx, key, obj); err != nil {
			reqLogger.Error(err, "Failed to finalize object due to an unexpected error; requeueing",
				"Object.Name", key.Name,
				"Object.Namespace", key.Namespace)
			return subreconciler.RequeueWithError(err)
		} else if objUpdated {
			anyObjUpdated = true
			reqLogger.Info("Object was finalized",
				"Object.Name", key.Name,
				"Object.Namespace", key.Namespace)
		} else {
			reqLogger.Info("Object was not found",
				"Object.Name", key.Name,
				"Object.Namespace", key.Namespace)
		}
	}

	prevAnnotationCount := len(authCR.Annotations)
	delete(authCR.Annotations, operatorv1alpha1.AnnotationAuthMigrationComplete)
	delete(authCR.Annotations, operatorv1alpha1.AnnotationAuthRetainMigrationArtifacts)
	curAnnotationCount := len(authCR.Annotations)

	if curAnnotationCount != prevAnnotationCount {
		if err = r.Update(ctx, authCR); err != nil {
			reqLogger.Error(err, "Failed to remove annotations from Authentication")
			return subreconciler.RequeueWithError(err)
		}
		anyObjUpdated = true
	}

	if anyObjUpdated {
		reqLogger.Info("One or more objects were cleaned up; requeueing")
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	reqLogger.Info("No cleanup was necessary; continuing")
	return subreconciler.ContinueReconciling()
}

func (r *AuthenticationReconciler) getPostgresDB(ctx context.Context, req ctrl.Request) (p *dbconn.PostgresDB, err error) {
	datastoreCertSecret := &corev1.Secret{}
	if err = r.Get(ctx, types.NamespacedName{Name: ctrlcommon.DatastoreEDBSecretName, Namespace: req.Namespace}, datastoreCertSecret); err != nil {
		return nil, err
	}

	datastoreCertCM := &corev1.ConfigMap{}
	if err = r.Get(ctx, types.NamespacedName{Name: ctrlcommon.DatastoreEDBCMName, Namespace: req.Namespace}, datastoreCertCM); err != nil {
		return nil, err
	}

	return dbconn.NewPostgresDB(
		dbconn.Name(datastoreCertCM.Data["DATABASE_NAME"]),
		dbconn.ID(req.Namespace),
		dbconn.Port(datastoreCertCM.Data["DATABASE_PORT"]),
		dbconn.User(datastoreCertCM.Data["DATABASE_USER"]),
		dbconn.Host(datastoreCertCM.Data["DATABASE_RW_ENDPOINT"]),
		dbconn.Schemas("platformdb", "oauthdbschema", "metadata"),
		dbconn.TLSConfig(
			datastoreCertSecret.Data["ca.crt"],
			datastoreCertSecret.Data["tls.crt"],
			datastoreCertSecret.Data["tls.key"]))
}

func (r *AuthenticationReconciler) getMongoHost(ctx context.Context, namespace string) (mongoHost string, err error) {
	var preloadCM *corev1.ConfigMap
	mongoHost = fmt.Sprintf("mongodb.%s.svc", namespace)
	if preloadCM, err = r.getPreloadMongoDBConfigMap(ctx, namespace); err != nil {
		return
	} else if preloadCM != nil {
		var ok bool
		mongoHost, ok = preloadCM.Data["ENDPOINT"]
		if !ok {
			err = fmt.Errorf("no ENDPOINT defined on ConfigMap %q", preloadCM.Name)
			return
		}
	}

	return
}

func (r *AuthenticationReconciler) getMongoDB(ctx context.Context, req ctrl.Request) (mongo *dbconn.MongoDB, err error) {
	mongoName := "platform-db"
	mongoPort := "27017"
	mongoHost, err := r.getMongoHost(ctx, req.Namespace)
	if err != nil {
		return nil, err
	}

	mongoAdminCredsName := "icp-mongodb-admin"
	mongoClientCertName := "icp-mongodb-client-cert"
	mongoCACertName := "mongodb-root-ca-cert"

	secrets := map[string]*corev1.Secret{
		mongoAdminCredsName: {},
		mongoClientCertName: {},
		mongoCACertName:     {},
	}

	for secretName, secret := range secrets {
		objKey := types.NamespacedName{Name: secretName, Namespace: req.Namespace}
		if err = r.Get(ctx, objKey, secret); err != nil {
			return nil, err
		}
	}

	return dbconn.NewMongoDB(
		dbconn.Name(mongoName),
		dbconn.Port(mongoPort),
		dbconn.Host(mongoHost),
		dbconn.User(string(secrets[mongoAdminCredsName].Data["user"])),
		dbconn.Password(string(secrets[mongoAdminCredsName].Data["password"])),
		dbconn.Schemas(mongoName),
		dbconn.TLSConfig(
			secrets[mongoCACertName].Data["ca.crt"],
			secrets[mongoClientCertName].Data["tls.crt"],
			secrets[mongoClientCertName].Data["tls.key"]))
}

func (r *AuthenticationReconciler) setMigrationCompleteStatus(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "setMigrationCompleteStatus")
	reqLogger.Info("Set the migration success condition if it is not already set")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	if authCR.HasBeenMigrated() {
		reqLogger.Info("MigrationsPerformed condition has already been set; continuing")
		return subreconciler.ContinueReconciling()
	}
	condition := operatorv1alpha1.NewMigrationCompleteCondition()
	meta.SetStatusCondition(&authCR.Status.Conditions, *condition)
	if err = r.Client.Status().Update(ctx, authCR); err != nil {
		reqLogger.Info("Failed to set migration success condition on Authentication", "reason", err.Error())
	} else {
		reqLogger.Info("Set migration success condition on Authentication", "reason", err.Error())
	}

	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

func (r *AuthenticationReconciler) handleMigrations(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "handleMigrations")
	reqLogger.Info("Perform any pending migrations")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	var migrations *migration.MigrationQueue
	var postgres *dbconn.PostgresDB
	var mongo *dbconn.MongoDB

	if postgres, err = r.getPostgresDB(ctx, req); k8sErrors.IsNotFound(err) {
		reqLogger.Info("Could not find all resources for configuring EDB connection; requeueing")
		return subreconciler.RequeueWithDelay(opreqWait)
	} else if err != nil {
		reqLogger.Error(err, "Failed to find resources for configuring EDB connection")
		return subreconciler.RequeueWithError(err)
	}

	if needsMongoMigration, err := r.needToMigrateFromMongo(ctx, authCR); err != nil {
		reqLogger.Error(err, "Failed to determine whether migration from MongoDB is needed")
		return subreconciler.RequeueWithError(err)
	} else if needsMongoMigration {
		if mongo, err = r.getMongoDB(ctx, req); k8sErrors.IsNotFound(err) {
			reqLogger.Info("Could not find all resources for configuring MongoDB connection; requeueing")
			return subreconciler.RequeueWithDelay(opreqWait)
		} else if err != nil {
			reqLogger.Error(err, "Failed to find resources for configuring MongoDB connection")
			return subreconciler.RequeueWithError(err)
		}
	}

	migrations, err = database.PlanMigrations(ctx, postgres, mongo)
	if err != nil {
		err = fmt.Errorf("failed to form a migration plan: %w", err)
		reqLogger.Error(err, "Failed to handle migrations")
		return subreconciler.RequeueWithError(err)
	}

	if migrations.Len() > 0 && r.dbSetupChan == nil {
		reqLogger.Info("Found migrations; starting a migration worker")
		r.dbSetupChan = make(chan *migration.Result, 1)
		go database.Migrate(context.Background(),
			r.dbSetupChan,
			migrations)
		condition := operatorv1alpha1.NewMigrationInProgressCondition()
		meta.SetStatusCondition(&authCR.Status.Conditions, *condition)
		if err = r.Client.Status().Update(ctx, authCR); err != nil {
			reqLogger.Error(err, "Failed to set condition on Authentication", "condition", operatorv1alpha1.ConditionMigrated)
			return subreconciler.RequeueWithDelayAndError(defaultLowerWait, err)
		}
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	if r.dbSetupChan == nil {
		reqLogger.Info("No active or pending migrations; continuing")
		return subreconciler.ContinueReconciling()
	}

	// nil serves as a sentinel value to indicate that the controller should be open to performing new migrations
	// again. The checks above ensure that, if there are migrations found, dbSetupChan is set to a new
	// channel and the migration goroutine is kicked off, which is safe to permit into the following select, or, if
	// dbSetupChan is still nil, meaning that no migration scenarios were identified on the cluster, that serves as
	// an indication that the subreconciler can signal that no more work is needed for the time being.
	//
	// The times when nil should therefore be set are when:
	// * There are no new migrations
	// * One of the current migrations has failed; this is so that, once requeued, the process of identifying and
	//   enqueueing migrations can begin anew.
	select {
	case migrationResult, ok := <-r.dbSetupChan:
		if ok {
			reqLogger.Info("Received a migration result from the worker")
		}
		var runningCondition, performedCondition *metav1.Condition
		if migrationResult != nil && migrationResult.Error != nil {
			reqLogger.Error(migrationResult.Error, "Encountered an error while performing the current migration")
			performedCondition = operatorv1alpha1.NewMigrationFailureCondition(migrationResult.Incomplete[0].Name)
		} else if migrationResult != nil {
			reqLogger.Info("Completed all migrations successfully")
			performedCondition = operatorv1alpha1.NewMigrationCompleteCondition()
		} else {
			reqLogger.Info("No migrations needed to be performed by the worker")
			performedCondition = operatorv1alpha1.NewMigrationCompleteCondition()
		}
		runningCondition = operatorv1alpha1.NewMigrationFinishedCondition()
		r.dbSetupChan = nil
		loopCtx := logf.IntoContext(ctx, reqLogger)

		r.loopUntilConditionsSet(loopCtx, req, performedCondition, runningCondition)
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	default:
		reqLogger.Info("Migration still in progress; check again in 10s")
		return subreconciler.RequeueWithDelay(migrationWait)
	}
}

func (r *AuthenticationReconciler) loopUntilConditionsSet(ctx context.Context, req ctrl.Request, conditions ...*metav1.Condition) {
	reqLogger := logf.FromContext(ctx)
	conditionsSet := false
	for !conditionsSet {
		authCR := &operatorv1alpha1.Authentication{}
		if result, err := r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
			reqLogger.Info("Failed to retrieve Authentication CR for status update; retrying")
			continue
		}
		for _, condition := range conditions {
			if condition == nil {
				continue
			}
			meta.SetStatusCondition(&authCR.Status.Conditions, *condition)
		}
		if err := r.Client.Status().Update(ctx, authCR); err != nil {
			reqLogger.Error(err, "Failed to set conditions on Authentication; retrying", "conditions", conditions)
			continue
		}
		conditionsSet = true
	}
}

func (r *AuthenticationReconciler) getPreloadMongoDBConfigMap(ctx context.Context, namespace string) (cm *corev1.ConfigMap, err error) {
	cm = &corev1.ConfigMap{}
	preloadConfigMapKey := types.NamespacedName{Name: "mongodb-preload-endpoint", Namespace: namespace}
	if err = r.Get(ctx, preloadConfigMapKey, cm); k8sErrors.IsNotFound(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return cm, nil
}

func (r *AuthenticationReconciler) hasPreloadMongoDBConfigMap(ctx context.Context, namespace string) (has bool, err error) {
	cm, err := r.getPreloadMongoDBConfigMap(ctx, namespace)
	return cm != nil, err
}

func (r *AuthenticationReconciler) hasMongoDBService(ctx context.Context, authCR *operatorv1alpha1.Authentication) (has bool, err error) {
	service := &corev1.Service{}
	if err = r.Get(ctx, types.NamespacedName{Name: "mongodb", Namespace: authCR.Namespace}, service); k8sErrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// needToMigrateFromMongo attempts to determine whether a migration from MongoDB is needed. Returns an error when an
// unexpected error occurs while trying to get resources from the cluster.
func (r *AuthenticationReconciler) needToMigrateFromMongo(ctx context.Context, authCR *operatorv1alpha1.Authentication) (need bool, err error) {
	if authCR.HasBeenMigrated() {
		return false, nil
	}
	var hasResource bool
	if hasResource, err = r.hasPreloadMongoDBConfigMap(ctx, authCR.Namespace); hasResource {
		return true, nil
	} else if err != nil {
		return false, err
	}

	if hasResource, err = r.hasMongoDBService(ctx, authCR); hasResource {
		return true, nil
	} else if err != nil {
		return false, err
	}

	return false, nil
}

// ensureDatastoreSecretAndCM makes sure that the datastore Secret and ConfigMap are present in the services namespace;
// these contain the configuration details that allow for connections to EDB
func (r *AuthenticationReconciler) ensureDatastoreSecretAndCM(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "ensureDatastoreSecretAndCM")
	reqLogger.Info("Ensure EDB datastore configuration resources available")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	cm := &corev1.ConfigMap{}
	if err = r.Get(ctx, types.NamespacedName{Name: ctrlcommon.DatastoreEDBCMName, Namespace: authCR.Namespace}, cm); k8sErrors.IsNotFound(err) {
		reqLogger.Info("ConfigMap not available yet; requeueing",
			"ConfigMap.Name", ctrlcommon.DatastoreEDBCMName,
			"ConfigMap.Namespace", authCR.Namespace)
		return subreconciler.RequeueWithDelay(opreqWait)
	} else if err != nil {
		reqLogger.Error(err, "Encountered an error when trying to get ConfigMap",
			"ConfigMap.Name", ctrlcommon.DatastoreEDBCMName,
			"ConfigMap.Namespace", authCR.Namespace)
		return subreconciler.RequeueWithError(err)
	}
	reqLogger.Info("ConfigMap found",
		"ConfigMap.Name", ctrlcommon.DatastoreEDBCMName,
		"ConfigMap.Namespace", authCR.Namespace)

	secret := &corev1.Secret{}
	if err = r.Get(ctx, types.NamespacedName{Name: ctrlcommon.DatastoreEDBSecretName, Namespace: authCR.Namespace}, secret); k8sErrors.IsNotFound(err) {
		reqLogger.Info("Secret not available yet; requeueing",
			"Secret.Name", ctrlcommon.DatastoreEDBSecretName,
			"Secret.Namespace", authCR.Namespace)
		return subreconciler.RequeueWithDelay(opreqWait)
	} else if err != nil {
		reqLogger.Error(err, "Encountered an error when trying to get Secret",
			"Secret.Name", ctrlcommon.DatastoreEDBSecretName,
			"Secret.Namespace", authCR.Namespace)
		return subreconciler.RequeueWithError(err)
	}
	reqLogger.Info("Secret found",
		"Secret.Name", ctrlcommon.DatastoreEDBSecretName,
		"Secret.Namespace", authCR.Namespace)

	return subreconciler.ContinueReconciling()
}

func (r *AuthenticationReconciler) getLatestAuthentication(ctx context.Context, req ctrl.Request, authentication *operatorv1alpha1.Authentication) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)
	if err := r.Get(ctx, req.NamespacedName, authentication); err != nil {
		if k8sErrors.IsNotFound(err) {
			reqLogger.Info("Authentication not found; skipping reconciliation")
			return subreconciler.DoNotRequeue()
		}
		reqLogger.Error(err, "Failed to get Authentication")
		return subreconciler.RequeueWithError(err)
	}
	return subreconciler.ContinueReconciling()
}

// RunningOnOpenShiftCluster returns whether the Operator is running on an OpenShift cluster
func (r *AuthenticationReconciler) RunningOnOpenShiftCluster() bool {
	return ctrlcommon.ClusterHasOpenShiftConfigGroupVerison(&r.DiscoveryClient) && ctrlcommon.ClusterHasRouteGroupVersion(&r.DiscoveryClient)
}

// RunningOnCNCFCluster returns whether the Operator is running on a CNCF cluster
func (r *AuthenticationReconciler) RunningOnCNCFCluster() bool {
	return !ctrlcommon.ClusterHasOpenShiftConfigGroupVerison(&r.DiscoveryClient) || !ctrlcommon.ClusterHasRouteGroupVersion(&r.DiscoveryClient)

}

// RunningOnUnknownCluster returns whether the Operator is running on an unknown cluster type
func (r *AuthenticationReconciler) RunningOnUnknownCluster() bool {
	return r.clusterType == ctrlcommon.Unknown
}

func (r *AuthenticationReconciler) addFinalizer(ctx context.Context, finalizerName string, instance *operatorv1alpha1.Authentication) (err error) {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	if !containsString(instance.Finalizers, finalizerName) {
		instance.Finalizers = append(instance.Finalizers, finalizerName)
		err = r.Client.Update(ctx, instance)
	}
	return
}

// removeFinalizer removes the provided finalizer from the Authentication instance.
func (r *AuthenticationReconciler) removeFinalizer(ctx context.Context, finalizerName string, instance *operatorv1alpha1.Authentication) (err error) {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	if containsString(instance.Finalizers, finalizerName) {
		instance.Finalizers = removeString(instance.Finalizers, finalizerName)
		err = r.Client.Update(ctx, instance)
		if err != nil {
			return fmt.Errorf("error updating the CR to remove the finalizer: %w", err)
		}
	}
	return
}

// needsAuditServiceDummyDataReset compares the state in an Authentication's .spec.auditService and returns whether it
// needs to be overwritten with dummy data.
func needsAuditServiceDummyDataReset(a *operatorv1alpha1.Authentication) bool {
	return a.Spec.AuditService.ImageName != operatorv1alpha1.AuditServiceIgnoreString ||
		a.Spec.AuditService.ImageRegistry != operatorv1alpha1.AuditServiceIgnoreString ||
		a.Spec.AuditService.ImageTag != operatorv1alpha1.AuditServiceIgnoreString ||
		a.Spec.AuditService.SyslogTlsPath != "" ||
		a.Spec.AuditService.Resources != nil
}

// AuthenticationReconciler reconciles a Authentication object
type AuthenticationReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	DiscoveryClient discovery.DiscoveryClient
	Mutex           sync.Mutex
	clusterType     ctrlcommon.ClusterType
	dbSetupChan     chan *migration.Result
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Authentication object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *AuthenticationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	reqLogger := log.WithValues("Request.Namespace", req.Namespace, "Request.Name", req.Name)

	needToRequeue := false

	reconcileCtx := logf.IntoContext(ctx, reqLogger)
	// Set default result
	result = ctrl.Result{}
	// Set Requeue to true if requeue is needed at end of reconcile loop
	defer func() {
		if needToRequeue {
			result.Requeue = true
		}
	}()

	reqLogger.Info("Reconciling Authentication")

	// Fetch the Authentication instance
	instance := &operatorv1alpha1.Authentication{}
	err = r.Get(reconcileCtx, req.NamespacedName, instance)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Set err to nil to signal the error has been handled
			err = nil
		}
		// Return without requeueing
		return
	}

	// Credit: kubebuilder book
	finalizerName := "authentication.operator.ibm.com"
	// Determine if the Authentication CR  is going to be deleted
	if instance.DeletionTimestamp.IsZero() {
		// Object not being deleted, but add our finalizer so we know to remove this object later when it is going to be deleted
		beforeFinalizerCount := len(instance.GetFinalizers())
		err = r.addFinalizer(reconcileCtx, finalizerName, instance)
		if err != nil {
			return
		}
		afterFinalizerCount := len(instance.GetFinalizers())
		if afterFinalizerCount > beforeFinalizerCount {
			needToRequeue = true
			return
		}
	} else {
		// Object scheduled to be deleted
		err = r.removeFinalizer(reconcileCtx, finalizerName, instance)
		return
	}

	// Be sure to update status before returning if Authentication is found (but only if the Authentication hasn't
	// already been updated, e.g. finalizer update
	defer func() {
		reqLogger.Info("Update status before finishing loop.")
		if reflect.DeepEqual(instance.Status, operatorv1alpha1.AuthenticationStatus{}) {
			instance.Status = operatorv1alpha1.AuthenticationStatus{
				Nodes: []string{},
			}
		}
		currentServiceStatus := r.getCurrentServiceStatus(ctx, r.Client, instance)
		if !reflect.DeepEqual(currentServiceStatus, instance.Status.Service) {
			instance.Status.Service = currentServiceStatus
			reqLogger.Info("Current status does not reflect current state; updating")
		}
		statusUpdateErr := r.Client.Status().Update(ctx, instance)
		if statusUpdateErr != nil {
			reqLogger.Error(statusUpdateErr, "Failed to update status; trying again")
			currentInstance := &operatorv1alpha1.Authentication{}
			r.Client.Get(ctx, req.NamespacedName, currentInstance)
			currentInstance.Status.Service = currentServiceStatus
			statusUpdateErr = r.Client.Status().Update(ctx, currentInstance)
			if statusUpdateErr != nil {
				reqLogger.Error(statusUpdateErr, "Retry failed; returning error")
				return
			}
		} else {
			reqLogger.Info("Updated status")
		}
		reqLogger.V(1).Info("Final result", "result", result, "err", err)
	}()

	if result, err := r.addMongoMigrationFinalizers(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(result, err) {
		reqLogger.V(1).Info("Should halt or requeue after addMongoMigrationFinalizers", "result", result, "err", err)
		return subreconciler.Evaluate(result, err)
	}

	if result, err := r.handleOperandRequest(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(result, err) {
		reqLogger.V(1).Info("Should halt or requeue after handleOperandRequest", "result", result, "err", err)
		return subreconciler.Evaluate(result, err)
	}

	if result, err := r.createEDBShareClaim(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(result, err) {
		reqLogger.V(1).Info("Should halt or requeue after createEDBShareClaim", "result", result, "err", err)
		return subreconciler.Evaluate(result, err)
	}

	// Check if this Certificate already exists and create it if it doesn't
	reqLogger.Info("Creating ibm-iam-operand-restricted serviceaccount")
	currentSA := &corev1.ServiceAccount{}
	err = r.createSA(instance, currentSA, &needToRequeue)
	if err != nil {
		return
	}
	// create operand role and role-binding
	r.createRole(instance)
	r.createRoleBinding(instance)

	// Check if this Certificate already exists and create it if it doesn't
	currentCertificate := &certmgr.Certificate{}
	err = r.handleCertificate(instance, currentCertificate, &needToRequeue)
	if err != nil {
		return
	}

	// Check if this Service already exists and create it if it doesn't
	currentService := &corev1.Service{}
	err = r.handleService(instance, currentService, &needToRequeue)
	if err != nil {
		return
	}

	// Check if this Secret already exists and create it if it doesn't
	currentSecret := &corev1.Secret{}
	err = r.handleSecret(instance, wlpClientID, wlpClientSecret, currentSecret, &needToRequeue)
	if err != nil {
		return
	}

	if subResult, err := r.handleConfigMaps(ctx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	// Check if this Job already exists and create it if it doesn't
	currentJob := &batchv1.Job{}
	err = r.handleJob(instance, currentJob, &needToRequeue)
	if err != nil {
		return
	}
	// create clusterrole and clusterrolebinding
	r.createClusterRole(instance)

	if subResult, err := r.handleClusterRoleBinding(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	r.ReconcileRemoveIngresses(ctx, instance, &needToRequeue)
	// updates redirecturi annotations to serviceaccount
	r.handleServiceAccount(instance, &needToRequeue)

	if subResult, err := r.ensureDatastoreSecretAndCM(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	// perform any migrations that may be needed before Deployments run
	if subResult, err := r.handleMigrations(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	if subResult, err := r.setMigrationCompleteStatus(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	if result, err := r.handleMongoDBCleanup(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(result, err) {
		reqLogger.V(1).Info("Should halt or requeue after handleMongoDBCleanup", "result", result, "err", err)
		return subreconciler.Evaluate(result, err)
	}

	// Check if this Deployment already exists and create it if it doesn't
	currentDeployment := &appsv1.Deployment{}
	currentProviderDeployment := &appsv1.Deployment{}
	currentManagerDeployment := &appsv1.Deployment{}
	err = r.handleDeployment(instance, currentDeployment, currentProviderDeployment, currentManagerDeployment, &needToRequeue)
	if err != nil {
		return
	}

	if needsAuditServiceDummyDataReset(instance) {
		instance.SetRequiredDummyData()
		err = r.Update(ctx, instance)
		if err != nil {
			return
		}
	}

	if result, err := r.handleZenFrontDoor(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(result, err) {
		return subreconciler.Evaluate(result, err)
	}

	if subResult, err := r.handleRoutes(ctx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	return
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthenticationReconciler) SetupWithManager(mgr ctrl.Manager) error {

	authCtrl := ctrl.NewControllerManagedBy(mgr).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&certmgr.Certificate{}).
		Owns(&batchv1.Job{}).
		Owns(&corev1.Service{}).
		Owns(&net.Ingress{}).
		Owns(&appsv1.Deployment{}).
		Owns(&operatorv1alpha1.OperandRequest{})

	//Add routes
	if ctrlcommon.ClusterHasOpenShiftConfigGroupVerison(&r.DiscoveryClient) {
		authCtrl.Owns(&routev1.Route{})
	}
	if ctrlcommon.ClusterHasZenExtensionGroupVersion(&r.DiscoveryClient) {
		authCtrl.Owns(&zenv1.ZenExtension{})
	}

	productCMPred := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldObj := e.ObjectOld.(*corev1.ConfigMap)
			newObj := e.ObjectNew.(*corev1.ConfigMap)

			return oldObj.Name == ZenProductConfigmapName && oldObj.Data[URL_PREFIX] != newObj.Data[URL_PREFIX]
		},

		// Allow create events
		CreateFunc: func(e event.CreateEvent) bool {
			obj := e.Object.(*corev1.ConfigMap)
			return obj.Name == ZenProductConfigmapName
		},

		// Allow delete events
		DeleteFunc: func(e event.DeleteEvent) bool {
			obj := e.Object.(*corev1.ConfigMap)
			return obj.Name == ZenProductConfigmapName
		},

		// Allow generic events (e.g., external triggers)
		GenericFunc: func(e event.GenericEvent) bool {
			obj := e.Object.(*corev1.ConfigMap)
			return obj.Name == ZenProductConfigmapName
		},
	}

	globalCMPred := predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetName() == ctrlcommon.GlobalConfigMapName
	})

	authCtrl.Watches(&corev1.ConfigMap{},
		handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) (requests []reconcile.Request) {
			authCR, _ := ctrlcommon.GetAuthentication(ctx, &r.Client)
			if authCR == nil {
				return
			}
			return []reconcile.Request{
				{NamespacedName: types.NamespacedName{
					Name:      authCR.Name,
					Namespace: authCR.Namespace,
				}},
			}
		}), builder.WithPredicates(predicate.Or(globalCMPred, productCMPred)),
	)
	return authCtrl.For(&operatorv1alpha1.Authentication{}).
		Complete(r)
}

// Helper functions to check and remove string from a slice of strings.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}
