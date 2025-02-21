package operator

import (
	"bytes"
	"context"
	"os"
	"text/template"
	"time"

	"fmt"

	ctrlcommon "github.com/IBM/ibm-iam-operator/controllers/common"
	database "github.com/IBM/ibm-iam-operator/database"
	dbconn "github.com/IBM/ibm-iam-operator/database/connectors"
	"github.com/IBM/ibm-iam-operator/database/migration"
	certmgr "github.com/ibm/ibm-cert-manager-operator/apis/cert-manager/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	"github.com/opdev/subreconciler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

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

// addMongoMigrationFinalizers is a subreconciler that adds finalizers to resources that are being retained during migration
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
		types.NamespacedName{Name: mongoClientCertName, Namespace: req.Namespace}:  &certmgr.Certificate{},
		types.NamespacedName{Name: mongoClientCertName, Namespace: req.Namespace}:  &corev1.Secret{},
		types.NamespacedName{Name: mongoCACertName, Namespace: req.Namespace}:      &certmgr.Certificate{},
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
	toFinalize := []struct {
		key client.ObjectKey
		obj client.Object
	}{
		{
			key: types.NamespacedName{Name: mongoDBServiceName, Namespace: req.Namespace},
			obj: &corev1.Service{},
		},
		{
			key: types.NamespacedName{Name: mongoDBPreloadCMName, Namespace: req.Namespace},
			obj: &corev1.ConfigMap{},
		},
		{
			key: types.NamespacedName{Name: mongoAdminCredsName, Namespace: req.Namespace},
			obj: &corev1.Secret{},
		},
		{
			key: types.NamespacedName{Name: mongoClientCertName, Namespace: req.Namespace},
			obj: &certmgr.Certificate{},
		},
		{
			key: types.NamespacedName{Name: mongoClientCertName, Namespace: req.Namespace},
			obj: &corev1.Secret{},
		},
		{
			key: types.NamespacedName{Name: mongoCACertName, Namespace: req.Namespace},
			obj: &certmgr.Certificate{},
		},
		{
			key: types.NamespacedName{Name: mongoCACertName, Namespace: req.Namespace},
			obj: &corev1.Secret{},
		},
	}

	anyObjUpdated := false
	for _, kvp := range toFinalize {
		var objUpdated bool
		if objUpdated, err = r.finalizeMongoMigrationObject(ctx, kvp.key, kvp.obj); err != nil {
			reqLogger.Error(err, "Failed to finalize object due to an unexpected error; requeueing",
				"Object.Name", kvp.key.Name,
				"Object.Namespace", kvp.key.Namespace)
			return subreconciler.RequeueWithError(err)
		} else if objUpdated {
			anyObjUpdated = true
			reqLogger.V(1).Info("Object was finalized",
				"Object.Name", kvp.key.Name,
				"Object.Namespace", kvp.key.Namespace)
		} else {
			reqLogger.V(1).Info("Object was not found",
				"Object.Name", kvp.key.Name,
				"Object.Namespace", kvp.key.Namespace)
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
	mongoHost = fmt.Sprintf("mongodb.%s.svc.cluster.local", namespace)
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

func (r *AuthenticationReconciler) overrideMongoDBBootstrap(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "overrideMongoDBBootstrap")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	if needsMongoMigration, err := r.needToMigrateFromMongo(ctx, authCR); err != nil {
		reqLogger.Error(err, "Failed to determine whether migration from MongoDB is needed")
		return subreconciler.RequeueWithError(err)
	} else if !needsMongoMigration {
		reqLogger.Info("Does not need MongoDB migration; skipping")
		return subreconciler.ContinueReconciling()
	}

	// find icp-mongodb-init
	icpMongoDBInitCMKey := types.NamespacedName{Namespace: req.Namespace, Name: "icp-mongodb-init"}
	icpMongoDBInitCM := &corev1.ConfigMap{}
	reqLogger.V(1).Info("Get MongoDB bootstrap ConfigMap",
		"ConfigMap.Name", icpMongoDBInitCMKey.Name,
		"ConfigMap.Namespace", icpMongoDBInitCMKey.Namespace)
	if err = r.Get(ctx, icpMongoDBInitCMKey, icpMongoDBInitCM); k8sErrors.IsNotFound(err) {
		reqLogger.Info("No MongoDB bootstrap ConfigMap to patch; continuing")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		reqLogger.Error(err, "Failed to get MongoDB bootstrap ConfigMap")
		return subreconciler.RequeueWithError(err)
	}

	// scale down MongoDB Operator
	mongoDeployKey := types.NamespacedName{Namespace: os.Getenv("POD_NAMESPACE"), Name: "ibm-mongodb-operator"}
	mongoDeploy := &appsv1.Deployment{}
	err = r.Get(ctx, mongoDeployKey, mongoDeploy)
	if k8sErrors.IsNotFound(err) {
		// try to find mongodb operator in instance namespace.
		// in LTSR -> CD Allnamespace upgrade scenario, CS operators and ibm-iam-operator stay in openshift-operators namespace
		// where as ibm-mongodb-operator stays in instance namespace(ex: ibm-common-services)
		mongoDeployKey.Namespace = req.Namespace
		err = r.Get(ctx, mongoDeployKey, mongoDeploy)
		if err == nil {
			reqLogger.Info("ibm-mongodb-operator found in instance namespace")
		}
	}
	if err != nil && !k8sErrors.IsNotFound(err) {
		return subreconciler.RequeueWithError(err)
	}
	if err == nil && mongoDeploy.Spec.Replicas != nil && *mongoDeploy.Spec.Replicas > 0 {
		mongoDeploy.Spec.Replicas = ptr.To[int32](0)
		if err = r.Update(ctx, mongoDeploy); err != nil {
			return subreconciler.RequeueWithError(err)
		}
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
	// update icp-mongodb-init ConfigMap .data["on-start.sh"]
	currentOnStartScript := icpMongoDBInitCM.Data["on-start.sh"]
	vals := struct{ Namespace string }{
		Namespace: authCR.Namespace,
	}
	bootstrapUpdateTpl := template.Must(template.New("bootstrapUpdate").Parse(bootstrapUpdateTplString))
	var bootstrapUpdateBytes bytes.Buffer
	if err = bootstrapUpdateTpl.Execute(&bootstrapUpdateBytes, vals); err != nil {
		reqLogger.Error(err, "Failed to execute bootstrapUpdate template")
		return subreconciler.RequeueWithError(err)
	}
	bootstrapUpdateString := bootstrapUpdateBytes.String()
	if bootstrapUpdateString != currentOnStartScript {
		icpMongoDBInitCM.Data["on-start.sh"] = bootstrapUpdateString
		if err = r.Update(ctx, icpMongoDBInitCM); err != nil {
			reqLogger.Error(err, "Failed to update bootstrap script in ConfigMap")
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("Updated bootstrap script in ConfigMap; requeueing")
		return subreconciler.RequeueWithDelay(time.Second * 3)
	}

	// update icp-mongodb StatefulSet .spec.template.metadata.labels
	icpMongoDBStSKey := types.NamespacedName{Name: "icp-mongodb", Namespace: req.Namespace}
	icpMongoDBStS := &appsv1.StatefulSet{}
	if err = r.Get(ctx, icpMongoDBStSKey, icpMongoDBStS); k8sErrors.IsNotFound(err) {
		reqLogger.Info("MongoDB StatefulSet not found; continuing")
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		reqLogger.Error(err, "Failed to get MongoDB StatefulSet")
		return subreconciler.RequeueWithError(err)
	}

	if icpMongoDBStS.ObjectMeta.Labels["migrating"] != "true" {
		icpMongoDBStS.ObjectMeta.Labels["migrating"] = "true"
		icpMongoDBStS.Spec.Template.Labels["migrating"] = "true"
		if err = r.Update(ctx, icpMongoDBStS); err != nil {
			reqLogger.Error(err, "Failed to label MongoDB StatefulSet and template")
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("Labeled MongoDB StatefulSet and template")
		return subreconciler.RequeueWithDelay(time.Second * 3)
	}

	if icpMongoDBStS.Status.UpdatedReplicas == *icpMongoDBStS.Spec.Replicas &&
		icpMongoDBStS.Status.AvailableReplicas == *icpMongoDBStS.Spec.Replicas {
		reqLogger.Info("MongoDB StatefulSet Pods have been updated; proceeding")
		return subreconciler.ContinueReconciling()
	}

	reqLogger.Info("MongoDB StatefulSet Pods have not been updated; requeueing")
	return subreconciler.RequeueWithDelay(time.Second * 3)
}

const bootstrapUpdateTplString string = `
#!/bin/bash

## workaround https://serverfault.com/questions/713325/openshift-unable-to-write-random-state
export RANDFILE=/tmp/.rnd
port=27017
replica_set=$REPLICA_SET
script_name=${0##*/}
credentials_file=/work-dir/credentials.txt
config_dir=/data/configdb

function log() {
    local msg="$1"
    local timestamp=$(date --iso-8601=ns)
    1>&2 echo "[$timestamp] [$script_name] $msg"
    echo "[$timestamp] [$script_name] $msg" >> /work-dir/log.txt
}

if [[ "$AUTH" == "true" ]]; then

    if [ !  -f "$credentials_file" ]; then
	log "Creds File Not found!"
	log "Original User: $ADMIN_USER"
	echo $ADMIN_USER > $credentials_file
	echo $ADMIN_PASSWORD >> $credentials_file
    fi
    admin_user=$(head -n 1 $credentials_file)
    admin_password=$(tail -n 1 $credentials_file)
    admin_auth=(-u "$admin_user" -p "$admin_password")
    log "Original User: $admin_user"
    if [[ "$METRICS" == "true" ]]; then
	metrics_user="$METRICS_USER"
	metrics_password="$METRICS_PASSWORD"
    fi
fi

function shutdown_mongo() {

    log "Running fsync..."
    mongo admin "${admin_auth[@]}" "${ssl_args[@]}" --eval "db.adminCommand( { fsync: 1, lock: true } )"

    log "Running fsync unlock..."
    mongo admin "${admin_auth[@]}" "${ssl_args[@]}" --eval "db.adminCommand( { fsyncUnlock: 1 } )"

    log "Shutting down MongoDB..."
    mongo admin "${admin_auth[@]}" "${ssl_args[@]}" --eval "db.adminCommand({ shutdown: 1, force: true, timeoutSecs: 60 })"
}

#Check if Password has change and updated in mongo , if so update Creds
function update_creds_if_changed() {
  if [ "$admin_password" != "$ADMIN_PASSWORD" ]; then
      passwd_changed=true
      log "password has changed = $passwd_changed"
      log "checking if passwd  updated in mongo"
      mongo admin  "${ssl_args[@]}" --eval "db.auth({user: '$admin_user', pwd: '$ADMIN_PASSWORD'})" | grep "Authentication failed"
      if [[ $? -eq 1 ]]; then
	log "New Password worked, update creds"
	echo $ADMIN_USER > $credentials_file
	echo $ADMIN_PASSWORD >> $credentials_file
	admin_password=$ADMIN_PASSWORD
	admin_auth=(-u "$admin_user" -p "$admin_password")
	passwd_updated=true
      fi
  fi
}

function update_mongo_password_if_changed() {
  log "checking if mongo passwd needs to be  updated"
  if [[ "$passwd_changed" == "true" ]] && [[ "$passwd_updated" != "true" ]]; then
    log "Updating to new password "
    if [[ $# -eq 1 ]]; then
	mhost="--host $1"
    else
	mhost=""
    fi

    log "host for password upd ($mhost)"
    mongo admin $mhost "${admin_auth[@]}" "${ssl_args[@]}" --eval "db.changeUserPassword('$admin_user', '$ADMIN_PASSWORD')" >> /work-dir/log.txt 2>&1
    sleep 10
    log "mongo passwd change attempted; check and update creds file if successful"
    update_creds_if_changed
  fi
}



my_hostname=$(hostname)
log "Bootstrapping MongoDB replica set member: $my_hostname"

log "Reading standard input..."
while read -ra line; do
    log "line is  ${line}"
    if [[ "${line}" == *"${my_hostname}"* ]]; then
	service_name="$line"
    fi
    peers=("${peers[@]}" "$line")
done

# Move into /work-dir
pushd /work-dir
pwd >> /work-dir/log.txt
ls -l  >> /work-dir/log.txt

# Generate the ca cert
ca_crt=$config_dir/tls.crt
if [ -f $ca_crt  ]; then
    log "Generating certificate"
    ca_key=$config_dir/tls.key
    pem=/work-dir/mongo.pem
    ssl_args=(--ssl --sslCAFile $ca_crt --sslPEMKeyFile $pem)

    echo "ca stuff created" >> /work-dir/log.txt

cat >openssl.cnf <<EOL
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = $(echo -n "$my_hostname" | sed s/-[0-9]*$//)
DNS.2 = $my_hostname
DNS.3 = $service_name
DNS.4 = localhost
DNS.5 = 127.0.0.1
DNS.6 = mongodb
DNS.7 = mongodb.{{.Namespace}}.svc
DNS.8 = mongodb.{{.Namespace}}.svc.cluster.local
EOL

    # Generate the certs
    echo "cnf stuff" >> /work-dir/log.txt
    echo "genrsa " >> /work-dir/log.txt
    openssl genrsa -out mongo.key 2048 >> /work-dir/log.txt 2>&1

    echo "req " >> /work-dir/log.txt
    openssl req -new -key mongo.key -out mongo.csr -subj "/CN=$my_hostname" -config openssl.cnf >> /work-dir/log.txt 2>&1

    echo "x509 " >> /work-dir/log.txt
    openssl x509 -req -in mongo.csr \
	-CA $ca_crt -CAkey $ca_key -CAcreateserial \
	-out mongo.crt -days 3650 -extensions v3_req -extfile openssl.cnf >> /work-dir/log.txt 2>&1

    echo "mongo stuff" >> /work-dir/log.txt

    rm mongo.csr

    cat mongo.crt mongo.key > $pem
    rm mongo.key mongo.crt
fi


log "Peers: ${peers[@]}"

log "Starting a MongoDB instance..."
mongod --config $config_dir/mongod.conf >> /work-dir/log.txt 2>&1 &
pid=$!
trap shutdown_mongo EXIT


log "Waiting for MongoDB to be ready..."
until [[ $(mongo "${ssl_args[@]}" --quiet --eval "db.adminCommand('ping').ok") == "1" ]]; do
    log "Retrying..."
    sleep 2
done

log "Initialized."

if [[ "$AUTH" == "true" ]]; then
    update_creds_if_changed
fi

iter_counter=0
while [  $iter_counter -lt 5 ]; do
  log "primary check, iter_counter is $iter_counter"
  # try to find a master and add yourself to its replica set.
  for peer in "${peers[@]}"; do
      log "Checking if ${peer} is primary"
      mongo admin --host "${peer}" --ipv6 "${admin_auth[@]}" "${ssl_args[@]}" --quiet --eval "rs.status()"  >> log.txt

      # Check rs.status() first since it could be in primary catch up mode which db.isMaster() doesn't show
      if [[ $(mongo admin --host "${peer}" --ipv6 "${admin_auth[@]}" "${ssl_args[@]}" --quiet --eval "rs.status().myState") == "1" ]]; then
	  log "Found master ${peer}, wait while its in primary catch up mode "
	  until [[ $(mongo admin --host "${peer}" --ipv6 "${admin_auth[@]}" "${ssl_args[@]}" --quiet --eval "db.isMaster().ismaster") == "true" ]]; do
	      sleep 1
	  done
	  primary="${peer}"
	  log "Found primary: ${primary}"
	  break
      fi
  done

  if [[ -z "${primary}" ]]  && [[ ${#peers[@]} -gt 1 ]] && (mongo "${ssl_args[@]}" --eval "rs.status()" | grep "no replset config has been received"); then
    log "waiting before creating a new replicaset, to avoid conflicts with other replicas"
    sleep 30
  else
    break
  fi

  let iter_counter=iter_counter+1
done


if [[ "${primary}" = "${service_name}" ]]; then
    log "This replica is already PRIMARY"

elif [[ -n "${primary}" ]]; then

    if [[ $(mongo admin --host "${primary}" --ipv6 "${admin_auth[@]}" "${ssl_args[@]}" --quiet --eval "rs.conf().members.findIndex(m => m.host == '${service_name}:${port}')") == "-1" ]]; then
      log "Adding myself (${service_name}) to replica set..."
      if (mongo admin --host "${primary}" --ipv6 "${admin_auth[@]}" "${ssl_args[@]}" --eval "rs.add('${service_name}')" | grep 'Quorum check failed'); then
	  log 'Quorum check failed, unable to join replicaset. Exiting.'
	  exit 1
      fi
    fi
    log "Done,  Added myself to replica set."

    sleep 3
    log 'Waiting for replica to reach SECONDARY state...'
    until printf '.'  && [[ $(mongo admin "${admin_auth[@]}" "${ssl_args[@]}" --quiet --eval "rs.status().myState") == '2' ]]; do
	sleep 1
    done
    log '✓ Replica reached SECONDARY state.'

elif (mongo "${ssl_args[@]}" --eval "rs.status()" | grep "no replset config has been received"); then

    log "Initiating a new replica set with myself ($service_name)..."

    mongo "${ssl_args[@]}" --eval "rs.initiate({'_id': '$replica_set', 'members': [{'_id': 0, 'host': '$service_name'}]})"
    mongo "${ssl_args[@]}" --eval "rs.status()"

    sleep 3

    log 'Waiting for replica to reach PRIMARY state...'

    log ' Waiting for rs.status state to become 1'
    until printf '.'  && [[ $(mongo "${ssl_args[@]}" --quiet --eval "rs.status().myState") == '1' ]]; do
	sleep 1
    done

    log ' Waiting for master to complete primary catchup mode'
    until [[ $(mongo  "${ssl_args[@]}" --quiet --eval "db.isMaster().ismaster") == "true" ]]; do
	sleep 1
    done

    primary="${service_name}"
    log '✓ Replica reached PRIMARY state.'


    if [[ "$AUTH" == "true" ]]; then
	# sleep a little while just to be sure the initiation of the replica set has fully
	# finished and we can create the user
	sleep 3

	log "Creating admin user..."
	mongo admin "${ssl_args[@]}" --eval "db.createUser({user: '$admin_user', pwd: '$admin_password', roles: [{role: 'root', db: 'admin'}]})"
    fi

    log "Done initiating replicaset."

fi

log "Primary: ${primary}"

if [[  -n "${primary}"   && "$AUTH" == "true" ]]; then
    # you r master and passwd has changed.. then update passwd
    update_mongo_password_if_changed $primary

    if [[ "$METRICS" == "true" ]]; then
	log "Checking if metrics user is already created ..."
	metric_user_count=$(mongo admin --host "${primary}" "${admin_auth[@]}" "${ssl_args[@]}" --eval "db.system.users.find({user: '${metrics_user}'}).count()" --quiet)
	log "User count is ${metric_user_count} "
	if [[ "${metric_user_count}" == "0" ]]; then
	    log "Creating clusterMonitor user... user - ${metrics_user}  "
	    mongo admin --host "${primary}" "${admin_auth[@]}" "${ssl_args[@]}" --eval "db.createUser({user: '${metrics_user}', pwd: '${metrics_password}', roles: [{role: 'clusterMonitor', db: 'admin'}, {role: 'read', db: 'local'}]})"
	    log "User creation return code is $? "
	    metric_user_count=$(mongo admin --host "${primary}" "${admin_auth[@]}" "${ssl_args[@]}" --eval "db.system.users.find({user: '${metrics_user}'}).count()" --quiet)
	    log "User count now is ${metric_user_count} "
	fi
    fi
fi

log "MongoDB bootstrap complete"
exit 0`
