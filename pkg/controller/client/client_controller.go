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
	"time"

	"strings"

	condition "github.com/IBM/ibm-iam-operator/pkg/api/util"
	oidcv1 "github.com/IBM/ibm-iam-operator/pkg/apis/oidc/v1"
	"github.com/go-logr/logr"
	oauthv1 "github.com/openshift/api/oauth/v1"
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
    client: mgr.GetClient(),
    Reader: mgr.GetAPIReader(),
    recorder: mgr.GetEventRecorderFor(controllerName),
    scheme: mgr.GetScheme(),
    config: ClientControllerConfig{},
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
	client   client.Client
	Reader   client.Reader
	recorder record.EventRecorder
	scheme   *runtime.Scheme
  config   ClientControllerConfig
}

// SetConfig sets the ClientControllerConfig on the ReconcileClient using the platform-auth-idp ConfigMap and
// platform-auth-idp-credentials Secret that are installed on the cluster.
func (r *ReconcileClient) SetConfig(ctx context.Context, namespace string) (err error) {
  if namespace == "" {
    return fmt.Errorf("provided namespace must be non-empty")
  }
  if !r.IsConfigured(){
    r.config = ClientControllerConfig{}
  }
  configMap := &corev1.ConfigMap{}
  err = r.client.Get(ctx, types.NamespacedName{Name: PlatformAuthIDPConfigMapName, Namespace: namespace}, configMap)
  if err != nil {
    return fmt.Errorf("client failed to GET ConfigMap: %w", err)
  }
  err = r.config.ApplyConfigMap(configMap, identityManagementURLKey, identityProviderURLKey, rOKSEnabledKey, authServiceURLKey)
  if err != nil {
    return fmt.Errorf("failed to configure: %w", err)
  }
  secret := &corev1.Secret{}
  err = r.client.Get(ctx, types.NamespacedName{Name: PlatformAuthIDPCredentialsSecretName, Namespace: namespace}, secret)
  if err != nil {
    return
  }
  err = r.config.ApplySecret(secret, defaultAdminUserKey, defaultAdminPasswordKey)
  if err != nil {
    return fmt.Errorf("failed to configure: %w", err)
  }
  return
}

// Reconcile reads that state of the cluster for a Client object and makes changes based on the state read
// and what is in the Client.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileClient) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {

	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling OIDC Client data")

	// Fetch the OIDC Client instance
	instance := &oidcv1.Client{}
	err := r.Reader.Get(ctx, request.NamespacedName, instance)
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
  
  reqLogger.Info("checking to see if controller is fully configured")
  if !r.IsConfigured() {
    err = r.SetConfig(ctx, request.Namespace)
    if err != nil {
      // Return error if the attempt to configure the ReconcileClient did not work
      return reconcile.Result{}, fmt.Errorf("failed to set controller config: %w", err)
    } else {
      reqLogger.Info("successfully set config for controller")
    }
  } else {
    reqLogger.Info("controller is fully configured")
  }
	errorRg := r.processOidcRegistration(ctx, reqLogger, instance)
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

func (r *ReconcileClient) processOidcRegistration(ctx context.Context, reqLogger logr.Logger, client *oidcv1.Client) error {
	reqLogger.Info("Processing OIDC client Registration")
	var errReg, errSecret, errOauthClient, errZen error
	var isDeleteEvent, clientIdExists bool

	isRoksEnabled, err := r.GetROKSEnabled()
  if err != nil {
    return err
  }

  isOSAuthEnabled, err := r.GetOSAuthEnabled()
  if err != nil {
    return err
  }

	errReg, isDeleteEvent = r.processDeleteRegistration(ctx, reqLogger, client)
	if isDeleteEvent && errReg == nil {
		return nil
	} else if isDeleteEvent && errReg != nil {
		reqLogger.Error(nil, "Error occurred while deleting oidc registration.")
	} else {
		clientCreds := &ClientCredentials{}
		secret := &corev1.Secret{}
		clientIdExists, clientCreds, errReg = r.ClientIdExists(ctx, client)
		if errReg != nil {
      reqLogger.Error(nil, "ClientId not registered")
		} else if !clientIdExists {
			reqLogger.Info("ClientId don't exist, create new registration")
			clientCreds, errReg = r.CreateClientCredentials(ctx, client)
			if errReg != nil {
				return errReg
			}
			_, errSecret = r.newSecretForClient(ctx, client, clientCreds)
      reqLogger.Info("current ROKS_ENABLED setting", "ROKS_ENABLED", isRoksEnabled)
      reqLogger.Info("current OSAUTH_ENABLED setting", "OSAUTH_ENABLED", isOSAuthEnabled)
			if isOSAuthEnabled {
        reqLogger.Info("OSAUTH_ENABLED is set to true, creating OAuthClient")
				_, errOauthClient = r.newOAuthClientForClient(ctx, client, clientCreds)
        if errOauthClient != nil {
          reqLogger.Error(errOauthClient, "error during OAuthClient creation")
        }
			} else {
        reqLogger.Info("OSAUTH_ENABLED is set to false, skipping OAuthClient creation")
      }

			errZen = r.processZenRegistration(reqLogger, client)
			if errZen != nil {
				reqLogger.Error(errZen, "An error occurred during zen registration")
			}

		} else {
			reqLogger.Info("ClientId exist, update existing registration")
			secret = r.reconcileSecret(ctx, client, clientCreds)
			if isRoksEnabled {
				_ = r.reconcileOAuthClient(ctx, client, clientCreds)
			}
			_, errReg = r.UpdateClientCredentials(ctx, client, secret)

			errZen = r.processZenRegistration(reqLogger, client)
			if errZen != nil {
				reqLogger.Error(errZen, "An error occurred during zen registration")
			}
		}
		if errReg == nil && errSecret == nil && errOauthClient == nil && errZen == nil {
			condition.SetClientCondition(client,
				oidcv1.ClientConditionReady,
				oidcv1.ConditionTrue,
				ReasonCreateClientSuccessful,
				MessageClientSuccessful)
			if !clientIdExists {
				r.recorder.Event(client, corev1.EventTypeNormal, ReasonCreateClientSuccessful, MessageCreateClientSuccessful)
			} else {
				r.recorder.Event(client, corev1.EventTypeNormal, ReasonUpdateClientSuccessful, MessageUpdateClientSuccessful)
			}
		}
	}

	if errAddFin := addFinalizer(reqLogger, client); errAddFin != nil {
		return errAddFin
	}

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
	errUpdate = r.client.Status().Update(ctx, client)
	if errUpdate != nil {
		return errUpdate
	}
	if errReg != nil || errSecret != nil || errOauthClient != nil || errZen != nil {
		errReg = fmt.Errorf("Error occurred while procesing the request")
		return errReg
	} else {
		return nil
	}
}

func (r *ReconcileClient) processZenRegistration(reqLogger logr.Logger, client *oidcv1.Client) error {

	if client.Spec.ZenInstanceId == "" {
		reqLogger.Info("Zen instance ID not specified, skipping zen registration")
		return nil
	}

	zenReg, zenErr := r.GetZenInstance(client)
	if zenErr != nil {
		//Set the status to false since zen registration cannot be completed
		condition.SetClientCondition(client, oidcv1.ClientConditionReady, oidcv1.ConditionFalse, ReasonCreateZenRegistrationFailed,
			MessageCreateZenRegistrationFailed)
		r.recorder.Event(client, corev1.EventTypeWarning, ReasonCreateZenRegistrationFailed, zenErr.Error())
		return zenErr
	}
	if zenReg != nil {
		//Zen registration exists - currently updates to the zen registration are not supported
		reqLogger.Info("Zen registration already exists for oidc client - the zen instance will not be updated", "clientId", client.Spec.ClientId, "zenInstanceId", client.Spec.ZenInstanceId)
		return nil
	}

	//Zen registration does not exist, create
	reqLogger.Info("Creating zen registration for client")
	err := r.CreateZenInstance(client)
	if err != nil {
		//Set the status to false since zen registration cannot be completed
		condition.SetClientCondition(client, oidcv1.ClientConditionReady, oidcv1.ConditionFalse, ReasonCreateZenRegistrationFailed,
			MessageCreateZenRegistrationFailed)
		r.recorder.Event(client, corev1.EventTypeWarning, ReasonCreateZenRegistrationFailed, err.Error())
		return err
	}

	return nil
}

// addFinalizer will add this attribute to the Memcached CR
func addFinalizer(reqLogger logr.Logger, client *oidcv1.Client) error {
	if client.ObjectMeta.DeletionTimestamp.IsZero() {
		finalizerName := "fynalyzer.client.oidc.security.ibm.com"
		if !containsString(client.ObjectMeta.Finalizers, finalizerName) {
			client.ObjectMeta.Finalizers = append(client.ObjectMeta.Finalizers, finalizerName)
		}
	}
	return nil
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func (r *ReconcileClient) processDeleteRegistration(ctx context.Context, reqLogger logr.Logger, client *oidcv1.Client) (error, bool) {

	isInstanceMarkedToBeDeleted := client.GetDeletionTimestamp() != nil
	// Update finalizer to allow delete CR
	if isInstanceMarkedToBeDeleted {
		errDel := r.DeleteClientCredentials(ctx, client)
		if errDel != nil {
			reqLogger.Error(errDel, "Failed to Delete OIDC Client.")
			return errDel, true
		}
    isOSAuthEnabled, err := r.GetOSAuthEnabled()
    if err != nil {
      return err, false
    }

		if isOSAuthEnabled  {
			oAuthClientToBeDeleted := &oauthv1.OAuthClient{}
			clientId := client.Spec.ClientId
			errGet := r.Reader.Get(ctx, types.NamespacedName{Name: clientId}, oAuthClientToBeDeleted)
			if errGet == nil {
				errDelOAuthClient := r.client.Delete(ctx, oAuthClientToBeDeleted)
				if errDelOAuthClient != nil {
					reqLogger.Error(errDelOAuthClient, "Failed to delete Oauth Client")
					return errDelOAuthClient, true
				}
			} else {
				if !errors.IsNotFound(errGet) {
					reqLogger.Error(errGet, "Failed to get Oauth Client")
					return errGet, true
				}
			}
		}

		//Delete the zeninstance if it has been specified
		if client.Spec.ZenInstanceId != "" {
			err := r.DeleteZenInstance(client)
			if err != nil {
				reqLogger.Error(errDel, "Failed to Delete the zen instance")
				return err, true
			}
			reqLogger.Info("Zen registration deleted", "ZenInstanceId", client.Spec.ZenInstanceId)
		} else {
			reqLogger.Info("No Zen instance has been registered - no deletion required")
		}

		client.SetFinalizers(nil)
		// Update CR
		errUpdate := r.client.Update(ctx, client)
		if errUpdate != nil {
			return errUpdate, true
		}
		return nil, true
	}
	return nil, false

}

func (r *ReconcileClient) reconcileSecret(ctx context.Context, client *oidcv1.Client, clientCreds *ClientCredentials) *corev1.Secret {
	found := &corev1.Secret{}
	err := r.Reader.Get(ctx, types.NamespacedName{Name: client.Spec.Secret, Namespace: client.Namespace}, found)
	if err == nil {
		return found
	} else {
		secret, errSec := r.newSecretForClient(ctx, client, clientCreds)
		if errSec == nil {
			return secret
		} else {
			return nil
		}
	}
}

func (r *ReconcileClient) reconcileOAuthClient(ctx context.Context, client *oidcv1.Client, clientCreds *ClientCredentials) *oauthv1.OAuthClient {
	found := &oauthv1.OAuthClient{}

	err := r.Reader.Get(ctx, types.NamespacedName{Name: clientCreds.CLIENT_ID}, found)
	if err != nil {
		return nil
	}

	oauthclient, errOauth := r.updateOAuthClientForClient(ctx, found, client, clientCreds)
	if errOauth == nil {
		return oauthclient
	} else {
		return nil
	}
}

// newPodForCR returns a busybox pod with the same name/namespace as the cr
func (r *ReconcileClient) newSecretForClient(ctx context.Context, client *oidcv1.Client, clientCreds *ClientCredentials) (*corev1.Secret, error) {
	reqLogger := log.WithValues("Request.Namespace", client.Namespace, "client.Name", client.Name)
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
		clientId := clientCreds.CLIENT_ID
		clientSecret := clientCreds.CLIENT_SECRET
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

// newPodForCR returns a busybox pod with the same name/namespace as the cr
func (r *ReconcileClient) newOAuthClientForClient(ctx context.Context, client *oidcv1.Client, clientCreds *ClientCredentials) (*oauthv1.OAuthClient, error) {
	reqLogger := log.WithValues("Request.Namespace", client.Namespace, "client.Name", client.Name)

	labels := map[string]string{
		"app.kubernetes.io/managed-by":          "OIDCClientRegistration.oidc.security.ibm.com",
		"client.oidc.security.ibm.com/owned-by": client.Name,
	}

	oauthclient := &oauthv1.OAuthClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:   clientCreds.CLIENT_ID,
			Labels: labels,
		},
	}

	if clientCreds != new(ClientCredentials) && clientCreds != nil {
		if oauthclient.RedirectURIs == nil {
			oauthclient.RedirectURIs = []string{}
		}
		oauthclient.Secret = clientCreds.CLIENT_SECRET
		oauthclient.GrantMethod = "auto"
		oauthclient.RedirectURIs = client.Spec.OidcLibertyClient.RedirectUris
	} else {
		reqLogger.Error(nil, "Client Creds are not set")
		return oauthclient, nil
	}
	err := r.client.Create(ctx, oauthclient)
	if err != nil {
		return nil, err
	}
	return oauthclient, nil
}

// newPodForCR returns a busybox pod with the same name/namespace as the cr
func (r *ReconcileClient) updateOAuthClientForClient(ctx context.Context, oauthclient *oauthv1.OAuthClient, client *oidcv1.Client, clientCreds *ClientCredentials) (*oauthv1.OAuthClient, error) {
	reqLogger := log.WithValues("Request.Namespace", client.Namespace, "client.Name", client.Name)

	oauthclient.RedirectURIs = []string{}
	oauthclient.GrantMethod = "auto"
	oauthclient.RedirectURIs = client.Spec.OidcLibertyClient.RedirectUris

	errUpdate := r.client.Update(ctx, oauthclient)
	if errUpdate != nil {
		reqLogger.Error(errUpdate, "Failed to update oauth client")
		return nil, errUpdate
	}

	return oauthclient, nil
}
