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
	"maps"
	"os"
	"reflect"
	"sync"
	"time"

	ctrlCommon "github.com/IBM/ibm-iam-operator/controllers/common"
	"github.com/IBM/ibm-iam-operator/migration"
	certmgr "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	net "k8s.io/api/networking/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
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
var wlpClientID = ctrlCommon.GenerateRandomString(rule)
var wlpClientSecret = ctrlCommon.GenerateRandomString(rule)

// finalizerName is the finalizer appended to the Authentication CR
var finalizerName = "authentication.operator.ibm.com"

// FinalizerMigration is the finalizer appended to resources that are being retained during migration
const FinalizerMigration string = "authentication.operator.ibm.com/migration"

func (r *AuthenticationReconciler) addMigrationFinalizer(ctx context.Context, key client.ObjectKey, obj client.Object) (updated bool, err error) {
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

func (r *AuthenticationReconciler) finalizeMigrationObject(ctx context.Context, key client.ObjectKey, obj client.Object) (finalized bool, err error) {
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

func (r *AuthenticationReconciler) addMigrationFinalizers(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
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
		if objUpdated, err = r.addMigrationFinalizer(ctx, key, obj); k8sErrors.IsNotFound(err) {
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

func (r *AuthenticationReconciler) handleRetainAnnotation(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "handleRetainAnnotation")
	reqLogger.Info("Clean up MongoDB resources if no longer being retained")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	// if retain annotation is unset or set to true - continue reconciling
	if authCR.IsRetainingArtifacts() {
		reqLogger.Info("Annotation does not signal a need to clean up resources; continuing")
		return subreconciler.ContinueReconciling()
	}
	reqLogger.Info("Annotation signals a need to clean up resources")

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

	for key, obj := range toFinalize {
		var objUpdated bool
		if objUpdated, err = r.finalizeMigrationObject(ctx, key, obj); err != nil {
			reqLogger.Error(err, "Failed to finalize object due to an unexpected error; requeueing",
				"Object.Name", key.Name,
				"Object.Namespace", key.Namespace)
			return subreconciler.RequeueWithError(err)
		} else if objUpdated {
			reqLogger.Info("Object was finalized",
				"Object.Name", key.Name,
				"Object.Namespace", key.Namespace)
		} else {
			reqLogger.Info("Object was not found",
				"Object.Name", key.Name,
				"Object.Namespace", key.Namespace)
		}
	}

	delete(authCR.Annotations, operatorv1alpha1.AnnotationAuthMigrationComplete)
	delete(authCR.Annotations, operatorv1alpha1.AnnotationAuthRetainMigrationArtifacts)

	if err = r.Update(ctx, authCR); err != nil {
		reqLogger.Error(err, "Failed to remove annotations from Authentication")
		return subreconciler.RequeueWithError(err)
	}

	reqLogger.Info("All migration objects finalized; requeueing")

	return subreconciler.Requeue()
}

func (r *AuthenticationReconciler) getPostgresDB(ctx context.Context, req ctrl.Request) (p *migration.PostgresDB, err error) {
	datastoreCertSecret := &corev1.Secret{}
	if err = r.Get(ctx, types.NamespacedName{Name: ctrlCommon.DatastoreEDBSecretName, Namespace: req.Namespace}, datastoreCertSecret); err != nil {
		return nil, err
	}

	datastoreCertCM := &corev1.ConfigMap{}
	if err = r.Get(ctx, types.NamespacedName{Name: ctrlCommon.DatastoreEDBCMName, Namespace: req.Namespace}, datastoreCertCM); err != nil {
		return nil, err
	}

	return migration.NewPostgresDB(
		migration.Name(datastoreCertCM.Data["DATABASE_NAME"]),
		migration.ID(req.Namespace),
		migration.Port(datastoreCertCM.Data["DATABASE_PORT"]),
		migration.User(datastoreCertCM.Data["DATABASE_USER"]),
		migration.Host(datastoreCertCM.Data["DATABASE_RW_ENDPOINT"]),
		migration.Schemas("platformdb", "oauthdbschema"),
		migration.TLSConfig(
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

func (r *AuthenticationReconciler) getMongoDB(ctx context.Context, req ctrl.Request) (mongo *migration.MongoDB, err error) {
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

	return migration.NewMongoDB(
		migration.Name(mongoName),
		migration.Port(mongoPort),
		migration.Host(mongoHost),
		migration.User(string(secrets[mongoAdminCredsName].Data["user"])),
		migration.Password(string(secrets[mongoAdminCredsName].Data["password"])),
		migration.Schemas(mongoName),
		migration.TLSConfig(
			secrets[mongoCACertName].Data["ca.crt"],
			secrets[mongoClientCertName].Data["tls.crt"],
			secrets[mongoClientCertName].Data["tls.key"]))
}

func (r *AuthenticationReconciler) handleMigrations(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "handleMigrations")
	reqLogger.Info("Perform any pending migrations")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	// Terminating condition for handleMigration subreconciler
	if authCR.HasBeenMigrated() {
		reqLogger.Info("Mongo to EDB data migration is complete, cleaning up mongo")
		if err := r.shutdownMongo(ctx, req); err != nil {
			reqLogger.Error(err, "Failed to scale down MongoDB")
		}
		return
	}

	var postgres *migration.PostgresDB
	if postgres, err = r.getPostgresDB(ctx, req); k8sErrors.IsNotFound(err) {
		reqLogger.Info("Could not find all resources for configuring EDB connection; requeueing")
		return subreconciler.RequeueWithDelay(opreqWait)
	} else if err != nil {
		reqLogger.Error(err, "Failed to find resources for configuring EDB connection")
		return subreconciler.RequeueWithError(err)
	}

	initEDB := migration.NewMigration().
		Name("initEDB").
		To(postgres).
		RunFunc(migration.InitSchemas).
		Build()

	var migrations []*migration.Migration

	if authCR.HasNoDBSchemaVersion() {
		reqLogger.Info("DB schema version annotation unset; adding initialization migration")
		migrations = append(migrations, initEDB)
	}

	if needToMigrate, err := r.needToMigrateFromMongo(ctx, authCR); err != nil {
		reqLogger.Error(err, "Failed to determine whether migration from MongoDB is needed")
		return subreconciler.RequeueWithError(err)
	} else if needToMigrate {
		var mongo *migration.MongoDB
		if mongo, err = r.getMongoDB(ctx, req); k8sErrors.IsNotFound(err) {
			reqLogger.Info("Could not find all resources for configuring MongoDB connection; requeueing")
			return subreconciler.RequeueWithDelay(opreqWait)
		} else if err != nil {
			reqLogger.Error(err, "Failed to find resources for configuring MongoDB connection")
			return subreconciler.RequeueWithError(err)
		}
		migrateFromMongo := migration.NewMigration().
			Name("MongoToV1").
			To(postgres).
			From(mongo).
			RunFunc(migration.MongoToV1).
			Build()
		migrations = append(migrations, migrateFromMongo)
	}

	if len(migrations) > 0 && r.dbSetupChan == nil {
		reqLogger.Info("Found migrations; starting a migration worker")
		r.dbSetupChan = make(chan *migration.Result, 1)
		go migration.Migrate(context.Background(),
			r.dbSetupChan,
			migrations...)
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
		if !ok {
			reqLogger.Info("No more migrations to perform and worker closed; removing worker and continuing")
			r.dbSetupChan = nil
			return subreconciler.ContinueReconciling()
		}
		reqLogger.Info("Received a migration result from the worker")
		if migrationResult != nil && migrationResult.Error != nil {
			reqLogger.Error(migrationResult.Error, "Encountered an error while performing the current migration")
			// Remove the failed channel now so that migration can repeat on next reconcile loop
			r.dbSetupChan = nil
			condition := operatorv1alpha1.NewMigrationFailureCondition(migrationResult.Incomplete[0].Name)
			meta.SetStatusCondition(&authCR.Status.Conditions, *condition)
			if err = r.Client.Status().Update(ctx, authCR); err != nil {
				reqLogger.Error(err, "Failed to set condition on Authentication", "condition", operatorv1alpha1.ConditionMigrated)
				return subreconciler.RequeueWithDelayAndError(defaultLowerWait, migrationResult.Error)
			}
		} else if migrationResult != nil {
			reqLogger.Info("Completed all migrations successfully")
			condition := operatorv1alpha1.NewMigrationSuccessCondition()
			meta.SetStatusCondition(&authCR.Status.Conditions, *condition)
			if err = r.Client.Status().Update(ctx, authCR); err != nil {
				reqLogger.Error(err, "Failed to set condition on Authentication", "condition", operatorv1alpha1.ConditionMigrated)
				return subreconciler.RequeueWithDelayAndError(defaultLowerWait, migrationResult.Error)
			}
		}
		if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		}
		annotationsChanged := setMigrationAnnotations(authCR, migrationResult)
		if annotationsChanged {
			reqLogger.Info("Setting updated migration annotations on Authentication before requeue")
			if err = r.Update(ctx, authCR); err != nil {
				reqLogger.Error(err, "Failed to set migration annotations on Authentication")
				return subreconciler.RequeueWithError(err)
			}
		}
		if migrationResult.Error != nil {
			return subreconciler.RequeueWithDelayAndError(defaultLowerWait, migrationResult.Error)
		}
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	default:
		reqLogger.Info("Migration still in progress; check again in 10s")
		return subreconciler.RequeueWithDelay(migrationWait)
	}
}

// setMigrationAnnotations uses the values stored in a `migration.Result` to determine whether updates to the
// Authentication CR's annotations need to be made. Returns `true` if new annotation values were set on the CR.
func setMigrationAnnotations(authCR *operatorv1alpha1.Authentication, result *migration.Result) (changed bool) {
	if result == nil {
		return false
	}
	var observedAnnotations, desiredAnnotations map[string]string
	observedAnnotations = authCR.DeepCopy().GetAnnotations()
	if observedAnnotations == nil {
		observedAnnotations = make(map[string]string)
		desiredAnnotations = make(map[string]string)
	} else {
		desiredAnnotations = authCR.DeepCopy().GetAnnotations()
	}
	for _, c := range result.Complete {
		switch c.Name {
		case "initEDB":
			desiredAnnotations[operatorv1alpha1.AnnotationAuthDBSchemaVersion] = "1.0.0"
		case "MongoToV1":
			desiredAnnotations[operatorv1alpha1.AnnotationAuthMigrationComplete] = "true"
			desiredAnnotations[operatorv1alpha1.AnnotationAuthRetainMigrationArtifacts] = "true"

		}
	}
	for _, i := range result.Incomplete {
		if i.Name == "MongoToV1" {
			desiredAnnotations[operatorv1alpha1.AnnotationAuthMigrationComplete] = "false"
		}
	}

	if maps.Equal(observedAnnotations, desiredAnnotations) {
		return false
	}
	authCR.SetAnnotations(desiredAnnotations)

	return true
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
	if err = r.Get(ctx, types.NamespacedName{Name: ctrlCommon.DatastoreEDBCMName, Namespace: authCR.Namespace}, cm); k8sErrors.IsNotFound(err) {
		reqLogger.Info("ConfigMap not available yet; requeueing",
			"ConfigMap.Name", ctrlCommon.DatastoreEDBCMName,
			"ConfigMap.Namespace", authCR.Namespace)
		return subreconciler.RequeueWithDelay(opreqWait)
	} else if err != nil {
		reqLogger.Error(err, "Encountered an error when trying to get ConfigMap",
			"ConfigMap.Name", ctrlCommon.DatastoreEDBCMName,
			"ConfigMap.Namespace", authCR.Namespace)
		return subreconciler.RequeueWithError(err)
	}
	reqLogger.Info("ConfigMap found",
		"ConfigMap.Name", ctrlCommon.DatastoreEDBCMName,
		"ConfigMap.Namespace", authCR.Namespace)

	secret := &corev1.Secret{}
	if err = r.Get(ctx, types.NamespacedName{Name: ctrlCommon.DatastoreEDBSecretName, Namespace: authCR.Namespace}, secret); k8sErrors.IsNotFound(err) {
		reqLogger.Info("Secret not available yet; requeueing",
			"Secret.Name", ctrlCommon.DatastoreEDBSecretName,
			"Secret.Namespace", authCR.Namespace)
		return subreconciler.RequeueWithDelay(opreqWait)
	} else if err != nil {
		reqLogger.Error(err, "Encountered an error when trying to get Secret",
			"Secret.Name", ctrlCommon.DatastoreEDBSecretName,
			"Secret.Namespace", authCR.Namespace)
		return subreconciler.RequeueWithError(err)
	}
	reqLogger.Info("Secret found",
		"Secret.Name", ctrlCommon.DatastoreEDBSecretName,
		"Secret.Namespace", authCR.Namespace)

	return subreconciler.ContinueReconciling()
}

// cleans up the mongo pod by scaling down the mongodb operator as well as mongo statefulset
func (r *AuthenticationReconciler) shutdownMongo(ctx context.Context, req ctrl.Request) (err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "shutdownMongoDB")
	operatorNamespace, exists := os.LookupEnv("POD_NAMESPACE")
	if !exists {
		operatorNamespace = req.Namespace
	}
	desiredReplicas := int32(0)
	mongoOprDeployment := &appsv1.Deployment{}
	if err = r.Get(ctx, types.NamespacedName{Name: ctrlCommon.MongoOprDeploymentName, Namespace: operatorNamespace}, mongoOprDeployment); err != nil {
		return err
	} else {
		// scaledown the replicas to 0
		if mongoOprDeployment.Spec.Replicas != &desiredReplicas {
			mongoOprDeployment.Spec.Replicas = &desiredReplicas
			if err = r.Update(ctx, mongoOprDeployment); err != nil {
				reqLogger.Error(err, "Error updating the mongodb operator deployment")
				return err
			}
			reqLogger.Info("Mongo operator deployment is scaled down to 0")
		}
		mongoSts := &appsv1.StatefulSet{}
		if err = r.Get(ctx, types.NamespacedName{Name: ctrlCommon.MongoStatefulsetName, Namespace: req.Namespace}, mongoSts); err != nil {
			return err
		} else {
			// scaledown the replicas to 0
			if mongoSts.Spec.Replicas != &desiredReplicas {
				mongoSts.Spec.Replicas = &desiredReplicas
				if err = r.Update(ctx, mongoSts); err != nil {
					reqLogger.Error(err, "Error updating the mongodb statefulset")
					return err
				}
				reqLogger.Info("Mongo statefulset is scaled down to 0")
			}
		}
	}
	return nil
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
	return ctrlCommon.ClusterHasOpenShiftConfigGroupVerison() && ctrlCommon.ClusterHasRouteGroupVersion()
}

// RunningOnCNCFCluster returns whether the Operator is running on a CNCF cluster
func (r *AuthenticationReconciler) RunningOnCNCFCluster() bool {
	return !ctrlCommon.ClusterHasOpenShiftConfigGroupVerison() || !ctrlCommon.ClusterHasRouteGroupVersion()

}

// RunningOnUnknownCluster returns whether the Operator is running on an unknown cluster type
func (r *AuthenticationReconciler) RunningOnUnknownCluster() bool {
	return r.clusterType == ctrlCommon.Unknown
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
	Scheme      *runtime.Scheme
	Mutex       sync.Mutex
	clusterType ctrlCommon.ClusterType
	dbSetupChan chan *migration.Result
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
	}()

	if subResult, err := r.addMigrationFinalizers(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	if result, err := r.handleOperandRequest(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(result, err) {
		return subreconciler.Evaluate(result, err)
	}

	if subResult, err := r.handleRetainAnnotation(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	if result, err := r.createEDBShareClaim(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(result, err) {
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

	//Check if this ConfigMap already exists and create it if it doesn't
	currentConfigMap := &corev1.ConfigMap{}
	err = r.handleConfigMap(instance, wlpClientID, wlpClientSecret, currentConfigMap, &needToRequeue)
	if err != nil {
		return
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

	if ctrlCommon.ClusterHasRouteGroupVersion() {
		err = r.handleRoutes(ctx, instance, &needToRequeue)
		if err != nil && !k8sErrors.IsNotFound(err) {
			return
		}
	}

	if subResult, err := r.ensureDatastoreSecretAndCM(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
	}

	// perform any migrations that may be needed before Deployments run
	if subResult, err := r.handleMigrations(reconcileCtx, req); subreconciler.ShouldHaltOrRequeue(subResult, err) {
		return subreconciler.Evaluate(subResult, err)
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

	return
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthenticationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if ctrlCommon.ClusterHasOpenShiftConfigGroupVerison() {
		return ctrl.NewControllerManagedBy(mgr).
			Owns(&corev1.ConfigMap{}).
			Owns(&corev1.Secret{}).
			Owns(&certmgr.Certificate{}).
			Owns(&batchv1.Job{}).
			Owns(&corev1.Service{}).
			Owns(&net.Ingress{}).
			Owns(&appsv1.Deployment{}).
			Owns(&routev1.Route{}).
			Owns(&operatorv1alpha1.OperandRequest{}).
			For(&operatorv1alpha1.Authentication{}).
			Complete(r)
	}
	return ctrl.NewControllerManagedBy(mgr).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&certmgr.Certificate{}).
		Owns(&batchv1.Job{}).
		Owns(&corev1.Service{}).
		Owns(&net.Ingress{}).
		Owns(&appsv1.Deployment{}).
		Owns(&operatorv1alpha1.OperandRequest{}).
		For(&operatorv1alpha1.Authentication{}).
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
