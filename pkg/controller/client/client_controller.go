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

package client

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	oidcv1 "github.com/IBM/ibm-iam-operator/pkg/apis/oidc/v1"
	pkgCommon "github.com/IBM/ibm-iam-operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const controllerName = "controller_oidc_client"
const OptimisticLockErrorMsg = "the object has been modified; please apply your changes to the latest version and try again"

const (
	// PlatformAuthIDPConfigMapName is the name of the ConfigMap containing settings used for Client management
	PlatformAuthIDPConfigMapName string = "platform-auth-idp"
	// PlatformAuthIDPCredentialsSecretName is the name of the Secret containing default credentials
	PlatformAuthIDPCredentialsSecretName string = "platform-auth-idp-credentials"
	// PlatformOIDCCredentialsSecretName is the name of the Secret containing the OP admin oauthadmin's password
	PlatformOIDCCredentialsSecretName string = "platform-oidc-credentials"
	// CSCACertificateSecretName is the name of the Secret created by the installer in the shared services namespace
	// that contains the Common Services CA certificate and private key details
	CSCACertificateSecretName string = "cs-ca-certificate-secret"
	// CP3FinalizerName is the name of the finalizer added to Clients by the Client controller in IM v4.x
	CP3FinalizerName string = "client.oidc.security.ibm.com"
	// CP2FinalizerName is the name of the finalizer added to Clients by the OIDC Client Watcher in IAM v3.x
	CP2FinalizerName  string = "fynalyzer.client.oidc.security.ibm.com"
	AdministratorRole string = "Administrator"
)

var log = logf.Log.WithName(controllerName)
var Clock clock.Clock = clock.RealClock{}

// Add creates a new Client Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileClient{
		client:   mgr.GetClient(),
		Reader:   mgr.GetAPIReader(),
		recorder: mgr.GetEventRecorderFor(controllerName),
		scheme:   mgr.GetScheme(),
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource Client
	err = c.Watch(&source.Kind{Type: &oidcv1.Client{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}
	return nil
}

// blank assignment to verify that ReconcileClient implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileClient{}

// ReconcileClient is a split client that reads objects from the cache and writes to the apiserver
type ReconcileClient struct {
	client                  client.Client
	Reader                  client.Reader
	recorder                record.EventRecorder
	scheme                  *runtime.Scheme
	config                  ClientControllerConfig
	csCACertSecret          *corev1.Secret
	sharedServicesNamespace string
}

// SetConfig sets the ClientControllerConfig on the ReconcileClient using the platform-auth-idp ConfigMap and
// platform-auth-idp-credentials Secret that are installed on the cluster.
func (r *ReconcileClient) SetConfig(ctx context.Context, namespace string) (err error) {
	if namespace == "" {
		return fmt.Errorf("provided namespace must be non-empty")
	}
	if !r.IsConfigured() {
		r.config = ClientControllerConfig{}
	}
	if r.sharedServicesNamespace == "" {
		r.sharedServicesNamespace, err = pkgCommon.GetSharedServicesNamespace(ctx, pkgCommon.CommonServiceName)
		if err != nil {
			return fmt.Errorf("failed to get ConfigMap: %w", err)
		}
	}

	err = r.checkCSCACertificateSecret(ctx)
	if err != nil {
		return
	}

	configMap := &corev1.ConfigMap{}
	err = r.client.Get(ctx, types.NamespacedName{Name: PlatformAuthIDPConfigMapName, Namespace: r.sharedServicesNamespace}, configMap)
	if err != nil {
		return fmt.Errorf("client failed to GET ConfigMap: %w", err)
	}
	err = r.config.ApplyConfigMap(configMap, identityManagementURLKey, identityProviderURLKey, rOKSEnabledKey, authServiceURLKey)
	if err != nil {
		return fmt.Errorf("failed to configure: %w", err)
	}
	platformAuthIDPCredentialsSecret := &corev1.Secret{}
	err = r.client.Get(ctx, types.NamespacedName{Name: PlatformAuthIDPCredentialsSecretName, Namespace: r.sharedServicesNamespace}, platformAuthIDPCredentialsSecret)
	if err != nil {
		return
	}
	err = r.config.ApplySecret(platformAuthIDPCredentialsSecret, defaultAdminUserKey, defaultAdminPasswordKey)
	if err != nil {
		return fmt.Errorf("failed to configure: %w", err)
	}
	platformOIDCCredentialsSecret := &corev1.Secret{}
	err = r.client.Get(ctx, types.NamespacedName{Name: PlatformOIDCCredentialsSecretName, Namespace: r.sharedServicesNamespace}, platformOIDCCredentialsSecret)
	if err != nil {
		return
	}
	err = r.config.ApplySecret(platformOIDCCredentialsSecret, oAuthAdminPasswordKey)
	if err != nil {
		return fmt.Errorf("failed to configure: %w", err)
	}
	return
}

// checkCSCACertificateSecret synchronizes the state of cached certificates from the Common Services CA based
// upon events received from the cluster.
func (r *ReconcileClient) checkCSCACertificateSecret(ctx context.Context) (err error) {
	reqLogger := logf.FromContext(ctx).WithName("checkCSCACertificateSecret")
	currentCertSecret := &corev1.Secret{}
	namespacedName := types.NamespacedName{Name: CSCACertificateSecretName, Namespace: r.sharedServicesNamespace}
	var verb string
	err = r.Reader.Get(ctx, namespacedName, currentCertSecret)
	if errors.IsNotFound(err) {
		reqLogger.Info("cs-ca-certificate-secret not found; removing cached certificate")
		verb = "delete"
		r.deleteCSCACertificateSecret(ctx)
		reqLogger.Info("certificate registration succeeded", "action", verb)
		return nil
	} else if err != nil {
		// Some other issue arose
		return
	}

	oldCertSecret := r.csCACertSecret
	if oldCertSecret == nil {
		reqLogger.Info("cs-ca-certificate-secret not registered; caching certificate")
		err = r.setCSCACertificateSecret(ctx, currentCertSecret)
		verb = "create"
	} else if currentCertSecret.GetDeletionTimestamp() != nil {
		reqLogger.Info("cs-ca-certificate-secret deleted; removing cached certificate")
		r.deleteCSCACertificateSecret(ctx)
		verb = "delete"
	} else {
		if reflect.DeepEqual(oldCertSecret.Data, currentCertSecret.Data]) {
		//if string(oldCertSecret.Data[corev1.TLSCertKey]) != string(currentCertSecret.Data[corev1.TLSCertKey]) {
			reqLogger.Info("cs-ca-certificate-secret was updated; caching updated certificate")
			err = r.setCSCACertificateSecret(ctx, currentCertSecret)
			verb = "update"
		} else {
			reqLogger.Info("cs-ca-certificate-secret has not changed")
			return
		}
	}
	if err != nil {
		reqLogger.Info("certificate registration failed", "action", verb)
	} else {
		reqLogger.Info("certificate registration succeeded", "action", verb)
	}
	return
}

// Reconcile reads that state of the cluster for a Client object and makes changes based on the state read
// and what is in the Client.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileClient) Reconcile(ctx context.Context, request reconcile.Request) (result reconcile.Result, err error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)

	reqLogger.Info("Gathering objects from the cluster to see if any updates to cache needed")

	err = r.SetConfig(ctx, request.Namespace)
	if err != nil {
		// Return error if the attempt to configure the ReconcileClient did not work
		return reconcile.Result{}, fmt.Errorf("failed to set controller config: %w", err)
	} else {
		reqLogger.Info("successfully set config for controller")
	}
	// If this is a cache update only, return
	if request.Name == "CACHE_UPDATE" {
		return reconcile.Result{}, nil
	}

	reqLogger.Info("Reconciling OIDC Client data")

	// Fetch the OIDC Client instance
	instance := &oidcv1.Client{}
	err = r.Reader.Get(ctx, request.NamespacedName, instance)
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

	processOidcRegistrationCtx := logf.IntoContext(ctx, reqLogger)
	errorRg := r.processOidcRegistration(processOidcRegistrationCtx, instance)
	if errorRg != nil {
		//Occassionally we will receive an error message stating the object had been modified and needs to
		//be reloaded.  k8s says these are benign - we will eat the error and requeue
		//https://github.com/kubernetes/kubernetes/issues/28149
		if strings.Contains(errorRg.Error(), OptimisticLockErrorMsg) {
			reqLogger.Info("Client modified during reconcile - requeueing")
			// do manaul retry without error
			return reconcile.Result{RequeueAfter: time.Second * 1}, nil
		}

		return reconcile.Result{}, errorRg
	} else {
		reqLogger.Info("Reconciling OIDC Client complete")
		return reconcile.Result{}, nil
	}
}

// createClient handles all aspects of tying out the creation of a new OIDC client, including registering the client in
// the OP, updates the ibm-iam-operand-restricted ServiceAccount with new redirect uris from client CR  and registers the Zen instance in IAM if the required fields are supplied.
func (r *ReconcileClient) createClient(ctx context.Context, client *oidcv1.Client) (err error) {
	reqLogger := logf.FromContext(ctx).WithName("createClient")
	clientCreds := r.generateClientCredentials("")
	reqLogger.Info("generated new client ID/secret pair", "clientId", clientCreds.ClientID)
	_, err = r.CreateClientRegistration(ctx, client, clientCreds)
	if err != nil {
		r.handleOIDCClientError(ctx, client, err, PostType)
		err = fmt.Errorf("error occurred during client registration: %w", err)
		return
	}

	// Now that the Client has been registered in the provider, set the Client ID on the Client
	client.Spec.ClientId = clientCreds.ClientID
	reqLogger = reqLogger.WithValues("clientId", client.Spec.ClientId)
	_, err = r.createNewSecretForClient(ctx, client, clientCreds)
	if err != nil {
		return
	}

	reqLogger.Info("adding annotations to ibm-iam-operand-restricted ServiceAccount")
	reqLogger.Info("SharedServicesNamespace is", "iamoperandnamespace", r.sharedServicesNamespace)

	r.handleServiceAccount(ctx, client, r.sharedServicesNamespace)
	if client.Spec.ZenInstanceId == "" {
		err = r.processZenRegistration(ctx, client, clientCreds)
		if err != nil {
			reqLogger.Error(err, "An error occurred during Zen registration", "clientId", client.Spec.ClientId)
		}
	}
	if err == nil {
		SetClientCondition(client,
			oidcv1.ClientConditionReady,
			oidcv1.ConditionTrue,
			ReasonCreateClientSuccessful,
			MessageClientSuccessful)
		r.recorder.Event(client, corev1.EventTypeNormal, ReasonCreateClientSuccessful, MessageCreateClientSuccessful)
	}
	return
}

// updateClient handles all aspects of tying out the update of an OIDC client, including any updates that may be needed
// for the Client's OpenShift OAuthClient resource and matching Zen instance, if applicable.
func (r *ReconcileClient) updateClient(ctx context.Context, client *oidcv1.Client) (err error) {
	reqLogger := logf.FromContext(ctx).WithValues("clientId", client.Spec.ClientId)
	var secret *corev1.Secret
	var clientCreds *ClientCredentials

	r.cp3RoleFinalizerUpdate(ctx, client)

	secret, err = r.getSecretFromClient(ctx, client)
	//secretCreated := false
	if err != nil {
		reqLogger.Error(err, "Secret could not be retrieved for Client; creating a replacement Secret", "secretName", client.Spec.Secret)
		clientCreds = r.generateClientCredentials(client.Spec.ClientId)
		secret, err = r.createNewSecretForClient(ctx, client, clientCreds)
		if err != nil {
			return fmt.Errorf("failed to create a new Secret: %w", err)
		}
		reqLogger.Info("Created Secret", "secretName", client.Spec.Secret)
		//secretCreated = true
		err = nil
	} else {
		clientCreds, err = getClientCredsFromSecret(secret)
		if err != nil {
			return fmt.Errorf("could not create new ClientCredentials struct: %w", err)
		}
	}
	var response *http.Response
	response, err = r.UpdateClientRegistration(ctx, client, clientCreds)
	if err != nil {
		r.handleOIDCClientError(ctx, client, err, PutType)
		err = fmt.Errorf("error occurred during update oidc client registration: %w", err)
		return
	}
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Error(err, "Failed to read response body")
		err = nil
	}
	reqLogger.Info("Received response", "body", responseBody)

	// secret is nil if getSecretFromClient produces an error, which we assume to mean that the Secret sought after didn't
	// turn up. If this happens, try to create a new secret using the clientCreds that were freshly generated and used for
	// the successful registration update.
	if secret == nil {
		_, err = r.createNewSecretForClient(ctx, client, clientCreds)
		if err != nil {
			return fmt.Errorf("failed to create a new Secret: %w", err)
		}
	}

	reqLogger.Info("Updating annotations to ibm-iam-operand-restricted ServiceAccount")
	reqLogger.Info("SharedServicesNamespace is", "iamoperandnamespace", r.sharedServicesNamespace)
	r.handleServiceAccount(ctx, client, r.sharedServicesNamespace)

	err = r.processZenRegistration(ctx, client, clientCreds)
	if err != nil {
		reqLogger.Error(err, "An error occurred during zen registration")
	}
	return
}

func (r *ReconcileClient) processOidcRegistration(ctx context.Context, client *oidcv1.Client) (err error) {
	reqLogger := logf.FromContext(ctx).WithName("processOidcRegistration")
	reqLogger.Info("Processing OIDC client Registration")

	// If the Client is marked for deletion, process that action
	if client.GetDeletionTimestamp() != nil {
		err = r.deleteClient(ctx, client)
		if err != nil {
			reqLogger.Error(err, "Error occurred while deleting oidc registration")
		}
		return
	}

	// Attempt to get the Client registration; if it isn't there, create a new one, otherwise, update
	_, err = r.GetClientRegistration(ctx, client)
	if err != nil {
		reqLogger.Info("Client not found, create new Client")
		err = r.createClient(ctx, client)
	} else {
		reqLogger.Info("Client found, update Client")
		err = r.updateClient(ctx, client)
	}

	// add finalizer if not already present
	addFinalizer(client)

	//Hit a strange issue ... the code above possibly updates both the spec fields and the status, however when
	//client.Update is called, this is reloading the client object from the server which is over-writing the changed
	//status so status changes are never saved in the status update below when they have changed.
	//To work around this, we will keep a copy of the status before update and apply after the update is complete

	savedStatus := client.DeepCopy().Status

	// Update the client
	reqLogger.Info("Updating Client CR")
	errUpdate := r.client.Update(ctx, client)
	if errUpdate != nil {
		return errUpdate
	}

	//apply saved status
	client.Status = savedStatus

	reqLogger.Info("Updating status")
	err = r.client.Status().Update(ctx, client)
	return
}

func (r *ReconcileClient) processZenRegistration(ctx context.Context, client *oidcv1.Client, clientCreds *ClientCredentials) (err error) {
	reqLogger := logf.FromContext(ctx)
	if client.Spec.ZenInstanceId == "" {
		reqLogger.Info("Zen instance ID not specified, skipping zen registration")
		return
	}
	var zenReg *ZenInstance
	zenReg, err = r.GetZenInstance(ctx, client)
	if err != nil {
		//Set the status to false since zen registration cannot be completed
		SetClientCondition(client, oidcv1.ClientConditionReady, oidcv1.ConditionFalse, ReasonCreateZenRegistrationFailed,
			MessageCreateZenRegistrationFailed)
		r.recorder.Event(client, corev1.EventTypeWarning, ReasonCreateZenRegistrationFailed, err.Error())
		return
	}
	if zenReg != nil {
		//Zen registration exists - currently updates to the zen registration are not supported
		reqLogger.Info("Zen registration already exists for oidc client - the zen instance will not be updated", "clientId", client.Spec.ClientId, "zenInstanceId", client.Spec.ZenInstanceId)
		return
	}

	//Zen registration does not exist, create
	reqLogger.Info("Creating zen registration for client")
	err = r.CreateZenInstance(ctx, client, clientCreds)
	if err != nil {
		//Set the status to false since zen registration cannot be completed
		SetClientCondition(client, oidcv1.ClientConditionReady, oidcv1.ConditionFalse, ReasonCreateZenRegistrationFailed,
			MessageCreateZenRegistrationFailed)
		r.recorder.Event(client, corev1.EventTypeWarning, ReasonCreateZenRegistrationFailed, err.Error())
	}

	return
}

// addFinalizer adds a finalizer to the Client if it hasn't already been marked for deletion.
func addFinalizer(client *oidcv1.Client) {
	if client.ObjectMeta.DeletionTimestamp.IsZero() {
		if !containsString(client.ObjectMeta.Finalizers, CP3FinalizerName) {
			client.ObjectMeta.Finalizers = append(client.ObjectMeta.Finalizers, CP3FinalizerName)
		}
	}
}

// cp2 specific handling during cp3 upgrade
func (r *ReconcileClient) cp3RoleFinalizerUpdate(ctx context.Context, client *oidcv1.Client) {

	reqLogger := logf.FromContext(ctx, "Request.Namespace", client.Namespace, "Request.Name", client.Name)

	if len(client.Spec.ZenInstanceId) == 0 && len(client.Spec.Roles) == 0 && containsString(client.ObjectMeta.Finalizers, CP2FinalizerName) {
		reqLogger.Info("Upgrade check : Non-ZEN cp2 Client CR Role would be updated : ", "Role", AdministratorRole)
		client.Spec.Roles = append(client.Spec.Roles, AdministratorRole)
		reqLogger.Info("Upgrade check : Non-ZEN CP2 Client CR Finalizers would be updated : ", "Finalizer", CP3FinalizerName)
		addFinalizer(client)
		removeFinalizer(client, CP2FinalizerName)
	} else if len(client.Spec.ZenInstanceId) > 0 && containsString(client.ObjectMeta.Finalizers, CP2FinalizerName) {
		reqLogger.Info("Upgrade check : ZEN cp2 Client CR Finalizers would be updated : ", "Finalizer", CP3FinalizerName)
		addFinalizer(client)
		removeFinalizer(client, CP2FinalizerName)
	}
}

// removeFinalizer removes the Client controller's finalizer from a Client resource.
func removeFinalizer(client *oidcv1.Client, finalizerName string) {
	finalizers := client.ObjectMeta.GetFinalizers()
	updatedFinalizers := make([]string, 0)
	for i, finalizer := range finalizers {
		if finalizer == finalizerName {
			updatedFinalizers = append(updatedFinalizers, finalizers[:i]...)
			updatedFinalizers = append(updatedFinalizers, finalizers[i+1:]...)
			break
		}
	}
	client.SetFinalizers(updatedFinalizers)
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// deleteClient deletes any registrations or resources created as a result of the provided Client
// resource's installation. By default, only the Client's registration in the OP will be deleted.
// If the Client is for a particular Zen instance, that Zen instance's registration in the
// Identity Management service will be deleted. If any of the operations attempted produce errors, those are returned.
func (r *ReconcileClient) deleteClient(ctx context.Context, client *oidcv1.Client) (err error) {
	reqLogger := logf.FromContext(ctx).WithName("deleteClient").WithValues("clientId", client.Spec.ClientId)
	// In the event that a Client needs to be deleted and it doesn't have a Client ID (meaning it was never properly
	// registered), remove the finalizer and update.
	if client.Spec.ClientId == "" {
		// Remove the finalizers
		reqLogger.Info("Removing finalizer from Client", "clientId", client.Spec.ClientId)
		// This condition is to handle deleteEvent during upgrade , when we still have cp2 finalizers
		if containsString(client.ObjectMeta.Finalizers, CP2FinalizerName) {
			removeFinalizer(client, CP2FinalizerName)
		}
		if containsString(client.ObjectMeta.Finalizers, CP3FinalizerName) {
			removeFinalizer(client, CP3FinalizerName)
		}
		// Update CR
		err = r.client.Update(ctx, client)
		if err != nil {
			reqLogger.Error(err, "Finalizer update failed")
		}
		return
	}
	_, err = r.DeleteClientRegistration(ctx, client)
	if err != nil {
		r.handleOIDCClientError(ctx, client, err, DeleteType)
		err = fmt.Errorf("error occurred during delete oidc client registration: %w", err)
		return
	}
	reqLogger.Info("Client registration successfully deleted")

	reqLogger.Info("Deleting annotations from ibm-iam-operand-restricted ServiceAccount")
	reqLogger.Info("SharedServicesNamespace is", "iamoperandnamespace", r.sharedServicesNamespace)
	r.RemoveAnnotationFromSA(ctx, client, r.sharedServicesNamespace)
	// Delete the zeninstance if it has been specified
	if client.Spec.ZenInstanceId != "" {
		reqLogger.Info("Client has a zenInstanceId, attempt to delete the matching Zen instance")
		err = r.DeleteZenInstance(ctx, client)
		if err != nil {
			reqLogger.Error(err, "Zen instance deletion failed", "zenInstanceId", client.Spec.ZenInstanceId)
			return
		}
		reqLogger.Info("Zen instance deletion succeeded", "ZenInstanceId", client.Spec.ZenInstanceId)
	}
	// Remove the finalizers
	reqLogger.Info("Removing finalizer from Client", "clientId", client.Spec.ClientId)

	// This condition is to handle deleteEvent during upgrade , when we still have cp2 finalizers
	if containsString(client.ObjectMeta.Finalizers, CP2FinalizerName) {
		removeFinalizer(client, CP2FinalizerName)
	}
	if containsString(client.ObjectMeta.Finalizers, CP3FinalizerName) {
		removeFinalizer(client, CP3FinalizerName)
	}
	// Update CR
	err = r.client.Update(ctx, client)
	if err != nil {
		reqLogger.Error(err, "Finalizer update failed")
	}
	return
}

// getSecretFromClient attempts to read the secret named in the provided Client resource and returns its contents if
// found. Returns an error if the attempt to read the Secret off of the cluster fails for any reason.
func (r *ReconcileClient) getSecretFromClient(ctx context.Context, client *oidcv1.Client) (secret *corev1.Secret, err error) {
	secret = &corev1.Secret{}
	err = r.Reader.Get(ctx, types.NamespacedName{Name: client.Spec.Secret, Namespace: client.Namespace}, secret)
	if err == nil {
		return secret, nil
	} else {
		return nil, err
	}
}

// getClientCredsFromSecret takes a Secret and uses its Data field to create and return a new ClientCredentials struct.
// Returns an error instead if the provided Secret is missing the Data field or the `CLIENT_ID` or `CLIENT_SECRET` keys
// in that field.
func getClientCredsFromSecret(secret *corev1.Secret) (clientCreds *ClientCredentials, err error) {
	var clientId, clientSecret []byte
	var ok bool
	if secret.Data == nil {
		return nil, fmt.Errorf("secret data empty")
	}
	if clientId, ok = secret.Data["CLIENT_ID"]; !ok {
		return nil, fmt.Errorf(`"CLIENT_ID" not set`)
	}
	if clientSecret, ok = secret.Data["CLIENT_SECRET"]; !ok {
		return nil, fmt.Errorf(`"CLIENT_SECRET" not set`)
	}
	return &ClientCredentials{
		ClientID:     string(clientId[:]),
		ClientSecret: string(clientSecret[:]),
	}, nil
}

func (r *ReconcileClient) createNewSecretForClient(ctx context.Context, client *oidcv1.Client, clientCreds *ClientCredentials) (*corev1.Secret, error) {
	reqLogger := logf.FromContext(ctx, "Request.Namespace", client.Namespace, "client.Name", client.Name)
	labels := map[string]string{
		"app.kubernetes.io/managed-by":          "OIDCClientRegistration.oidc.security.ibm.com",
		"client.oidc.security.ibm.com/owned-by": client.Name,
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      client.Spec.Secret,
			Namespace: client.Namespace,
			Labels:    labels,
		},
	}

	// Set OIDC Client instance as the owner and controller
	if err := controllerutil.SetControllerReference(client, secret, r.scheme); err != nil {
		return nil, err
	}

	if clientCreds != new(ClientCredentials) && clientCreds != nil {
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		clientId := clientCreds.ClientID
		clientSecret := clientCreds.ClientSecret
		secret.Data["CLIENT_ID"] = []byte(clientId)
		secret.Data["CLIENT_SECRET"] = []byte(clientSecret)
	} else {
		return secret, nil
	}
	err := r.client.Create(ctx, secret)
	if err != nil {
		reqLogger.Error(err, "Error occurred during secret creation")
		return nil, err
	}
	return secret, nil
}

// handleServiceAccount updates ibm-iam-operand-restricted SA with redirecturi's present present in the Client CR for updateClient Call
func (r *ReconcileClient) handleServiceAccount(ctx context.Context, client *oidcv1.Client, sAccNamespace string) {

	reqLogger := logf.FromContext(ctx).WithValues("Request.Namespace", client.Namespace, "client.Name", client.Name)
	clientName := client.ObjectMeta.Name
	redirectURIs := client.Spec.OidcLibertyClient.RedirectUris
	sAccName := "ibm-iam-operand-restricted"
	serviceAccount := &corev1.ServiceAccount{}
	err := r.client.Get(ctx, types.NamespacedName{Name: sAccName, Namespace: sAccNamespace}, serviceAccount)
	if err != nil {
		reqLogger.Error(err, "failed to GET ServiceAccount ibm-iam-operand-restricted")
		return
	}
	if serviceAccount.ObjectMeta.Annotations == nil {
		serviceAccount.ObjectMeta.Annotations = make(map[string]string)
	}
	for i := 0; i < len(redirectURIs); i++ {
		key := "serviceaccounts.openshift.io/oauth-redirecturi." + clientName
		serviceAccount.ObjectMeta.Annotations[key+strconv.Itoa(i)] = redirectURIs[i]
	}
	// update the SAcc with this annotation
	errUpdate := r.client.Update(ctx, serviceAccount)
	if errUpdate != nil {
		// error updating annotation
		reqLogger.Error(errUpdate, "error updating annotation in ServiceAccount")
	} else {
		// annotation got updated properly
		reqLogger.Info("ibm-iam-operand-restricted SA is updated with annotations successfully")
	}

}

// RemoveAnnotationFromSA removes respective redirecturi annotation present in ibm-iam-operand-restricted SA for deleteClient Call
func (r *ReconcileClient) RemoveAnnotationFromSA(ctx context.Context, client *oidcv1.Client, sAccNamespace string) {

	reqLogger := logf.FromContext(ctx).WithValues("Request.Namespace", client.Namespace, "client.Name", client.Name)
	clientName := client.ObjectMeta.Name
	redirectURIs := client.Spec.OidcLibertyClient.RedirectUris
	sAccName := "ibm-iam-operand-restricted"
	serviceAccount := &corev1.ServiceAccount{}
	err := r.client.Get(ctx, types.NamespacedName{Name: sAccName, Namespace: sAccNamespace}, serviceAccount)
	if err != nil {
		reqLogger.Error(err, "failed to GET ServiceAccount ibm-iam-operand-restricted")
		return
	}
	if serviceAccount.ObjectMeta.Annotations == nil {
		serviceAccount.ObjectMeta.Annotations = make(map[string]string)
	}
	for i := 0; i < len(redirectURIs); i++ {
		key := "serviceaccounts.openshift.io/oauth-redirecturi." + clientName
		// serviceAccount.ObjectMeta.Annotations[key+strconv.Itoa(i)] = redirectURIs[i]
		delete(serviceAccount.ObjectMeta.Annotations, key+strconv.Itoa(i))
	}
	// update the SAcc with this annotation
	errUpdate := r.client.Update(ctx, serviceAccount)
	if errUpdate != nil {
		// error updating annotation
		reqLogger.Error(errUpdate, "error removing annotation in ServiceAccount")
	} else {
		// annotation got updated properly
		reqLogger.Info("ibm-iam-operand-restricted SA is removed with annotations successfully")
	}

}
