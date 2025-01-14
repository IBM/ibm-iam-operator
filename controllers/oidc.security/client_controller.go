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

package oidcsecurity

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IBM/ibm-iam-operator/controllers/common"

	"fmt"

	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	runtimeClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/apis/oidc.security/v1"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	"github.com/opdev/subreconciler"
)

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
const controllerName = "controller_oidc_client"

const baseAuthenticationWaitTime time.Duration = time.Minute

var Clock clock.Clock = clock.RealClock{}
var log = logf.Log.WithName(controllerName)

// ClientReconciler reconciles a Client object
type ClientReconciler struct {
	runtimeClient.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	reqLogger := log.WithValues("Request.Namespace", req.Namespace, "Request.Name", req.Name)

	reqLogger.Info("Reconciling Client CR")

	subreconcilersForClient := []subreconciler.FnWithRequest{
		r.confirmAuthenticationIsReady,
		r.addFinalizer,
		r.handleDeletion,
		r.ensureSecretAndClientIdSet,
		r.processOidcRegistration,
		r.annotateServiceAccount,
		r.processZenRegistration,
		r.updateStatus,
	}

	subreconcilerCtx := logf.IntoContext(ctx, reqLogger)
	for _, f := range subreconcilersForClient {
		if r, err := f(subreconcilerCtx, req); subreconciler.ShouldHaltOrRequeue(r, err) {
			return subreconciler.Evaluate(r, err)
		}
	}

	reqLogger.Info("Reconciling Client CR complete")

	return subreconciler.Evaluate(subreconciler.DoNotRequeue())
}

// Begin subreconcilers

func (r *ClientReconciler) confirmAuthenticationIsReady(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "confirmAuthenticationIsReady")
	reqLogger.Info("Confirm that Authentication CR for IM is ready before reconciling Client")

	var authCR *operatorv1alpha1.Authentication
	if authCR, err = common.GetAuthentication(ctx, &r.Client); err != nil {
		reqLogger.Info("Failed to get the Authentication for this install of IM", "reason", err.Error())
		return subreconciler.RequeueWithDelay(wait.Jitter(baseAuthenticationWaitTime, 1.0))
	}

	if authCR.Status.Service.DeploymentsReady() && authCR.Status.Service.ServicesReady() {
		reqLogger.Info("Authentication Deployments and Services are ready; proceding with Client reconciliation")
		return subreconciler.ContinueReconciling()
	}

	reqLogger.Info("Authentication Deployments and Services are not ready yet; delaying Client reconciliation")
	return subreconciler.RequeueWithDelay(wait.Jitter(baseAuthenticationWaitTime, 1.0))
}

// addFinalizer first performs any required migration steps on the Client if it was created using
// icp-oidcclient-watcher, then adds this controller's finalizer to it.
func (r *ClientReconciler) addFinalizer(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "addFinalizer")
	reqLogger.Info("Add finalizer to Client if not already present")

	clientCR := &oidcsecurityv1.Client{}

	if result, err = r.getLatestClient(ctx, req, clientCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	// Skip the rest of this subreconciler if the Client is marked for deletion
	if isMarkedForDeletion(clientCR) {
		reqLogger.Info("Client is marked for deletion; moving to Client deletion handler")
		return subreconciler.ContinueReconciling()
	}

	migrated := migrateCP2Client(ctx, clientCR)

	added := controllerutil.AddFinalizer(clientCR, CP3FinalizerName)
	if added {
		reqLogger.Info("Added missing finalizer to Client")
	}

	if migrated || added {
		if err := r.Update(ctx, clientCR); err != nil {
			reqLogger.Error(err, "Failed to update Client to add finalizer")
			return subreconciler.RequeueWithError(err)
		}
	} else {
		reqLogger.Info("All Client finalizers were already set; skipping")
	}

	return subreconciler.ContinueReconciling()
}

// handleDeletion performs finalizing tasks and removes any finalizers set by this Operator to allow for safe deletion
// of a Client if it has been marked for deletion.
func (r *ClientReconciler) handleDeletion(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "handleDeletion")
	reqLogger.Info("Handle cleanup of Client if it has been marked for deletion")

	clientCR := &oidcsecurityv1.Client{}
	requestMethod := http.MethodDelete

	if _, err = r.getLatestClient(ctx, req, clientCR); err != nil {
		if k8sErrors.IsNotFound(err) {
			// Assume that the Client was already deleted
			return subreconciler.DoNotRequeue()
		}
		reqLogger.Error(err, "Failed to get latest Client")
		reqLogger.Info("Updating status")
		if err := r.writeErrorConditionsAndEvents(ctx, clientCR, err, requestMethod); err != nil {
			reqLogger.Error(err, "Failed to update Client status")
			return subreconciler.RequeueWithError(err)
		}
		return subreconciler.RequeueWithError(err)
	}

	if isNotMarkedForDeletion(clientCR) {
		reqLogger.Info("Client is not being deleted; skipping")
		return subreconciler.ContinueReconciling()
	}

	reqLogger.Info("Client is marked for deletion")

	if result, err = r.finalizeClient(ctx, req); subreconciler.ShouldRequeue(result, err) {
		if err == nil {
			return subreconciler.Requeue()
		}
		reqLogger.Error(err, "Error occurred while finalizing Client")
		reqLogger.Info("Updating status")
		if err := r.writeErrorConditionsAndEvents(ctx, clientCR, err, requestMethod); err != nil {
			reqLogger.Error(err, "Failed to update Client status")
			return subreconciler.RequeueWithError(err)
		}
		return subreconciler.RequeueWithError(err)
	}

	reqLogger.Info("Updating status")
	if err = r.writeErrorConditionsAndEvents(ctx, clientCR, err, requestMethod); err != nil {
		reqLogger.Error(err, "Failed to update Client status")
		return subreconciler.RequeueWithError(err)
	}

	// Writing status out means the Client needs to be retrieved again
	if err = r.Get(ctx, req.NamespacedName, clientCR); err != nil {
		reqLogger.Error(err, "Failed to fetch Client")
		return subreconciler.RequeueWithError(err)
	}

	// This condition is to handle deleteEvent during upgrade , when we still have cp2 finalizers
	controllerutil.RemoveFinalizer(clientCR, CP2FinalizerName)
	controllerutil.RemoveFinalizer(clientCR, CP3FinalizerName)

	if err = r.Update(ctx, clientCR); err != nil {
		reqLogger.Error(err, "Failed to remove finalizers")
		return subreconciler.RequeueWithError(err)
	}

	return subreconciler.DoNotRequeue()
}

// ensureSecretAndClientIdSet checks a Client CR to be sure that its corresponding Secret containing the client ID and
// client secret has been created and that the ID on the CR itself has been set to match the value in the Secret.
func (r *ClientReconciler) ensureSecretAndClientIdSet(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "ensureSecretAndClientIdSet")
	reqLogger.Info("Ensuring Secret and Client ID are set")

	clientCR := &oidcsecurityv1.Client{}
	if result, err = r.getLatestClient(ctx, req, clientCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	var secret *corev1.Secret

	// If a Secret name isn't set on the Client, report that the secret must be set; otherwise, try to obtain the
	// Secret to check for changes
	if clientCR.Spec.Secret == "" {
		reqLogger.Info(".spec.secret is not set; set to a non-empty value to continue reconciling this Client")
		return subreconciler.DoNotRequeue()
	} else {
		secret, err = r.getSecretFromClient(ctx, clientCR)
		if err != nil && !k8sErrors.IsNotFound(err) {
			reqLogger.Error(err, "Failed to get Secret from Client", "secretName", clientCR.Spec.Secret)
			reqLogger.Info("Updating status")
			if err := r.writeErrorConditionsAndEvents(ctx, clientCR, err, ""); err != nil {
				reqLogger.Error(err, "Failed to write status to Client")
				return subreconciler.RequeueWithError(err)
			}
			return subreconciler.RequeueWithError(err)
		}
	}

	// If there isn't a Secret found, then a Secret needs to be created
	if secret == nil {
		reqLogger.Info("Secret was not found", "secretName", clientCR.Spec.Secret)
		secret, err = r.createNewSecretForClient(ctx, clientCR)
		if err != nil {
			if k8sErrors.IsAlreadyExists(err) {
				reqLogger.Info("Secret was already created, requeuing")
				return subreconciler.Requeue()
			}
			reqLogger.Error(err, "Failed to get Secret from Client", "secretName", clientCR.Spec.Secret)
			reqLogger.Info("Updating status")
			if err := r.writeErrorConditionsAndEvents(ctx, clientCR, err, ""); err != nil {
				reqLogger.Error(err, "Failed to write status to Client")
				return subreconciler.RequeueWithError(err)
			}
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("Successfully created Secret for Client", "secretName", clientCR.Spec.Secret)
		return subreconciler.Requeue()
	}

	secretClientId := string(secret.Data["CLIENT_ID"])
	if clientCR.Spec.ClientId != secretClientId {
		clientCR.Spec.ClientId = string(secret.Data["CLIENT_ID"])
		if err = r.Update(ctx, clientCR); err != nil {
			reqLogger.Error(err, "Failed to update ClientId on Client")
			reqLogger.Info("Updating status")
			if err := r.writeErrorConditionsAndEvents(ctx, clientCR, err, ""); err != nil {
				reqLogger.Error(err, "Failed to write status to Client")
				return subreconciler.RequeueWithError(err)
			}
			return subreconciler.RequeueWithError(err)
		}
		return subreconciler.Requeue()
	}

	return subreconciler.ContinueReconciling()
}

// processOidcRegistration creates a new OIDC client or updates an existing one with whatever state is observed in the
// Client CR.
func (r *ClientReconciler) processOidcRegistration(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "processOidcRegistration")
	reqLogger.Info("Processing OIDC client registration")

	var requestMethod string
	clientCR := &oidcsecurityv1.Client{}

	if result, err = r.getLatestClient(ctx, req, clientCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	config := &AuthenticationConfig{}
	err = GetConfig(ctx, &r.Client, config)
	if err != nil {
		reqLogger.Error(err, "Failed to gather Authentication configuration")
		return subreconciler.RequeueWithError(err)
	}

	var authenticationNamespace string
	if authenticationNamespace, err = config.GetAuthenticationNamespace(); err != nil {
		reqLogger.Error(err, "No Authentication CR found to determine services namespace")
		return subreconciler.RequeueWithError(err)
	}

	available, err := r.isDeploymentAvailable(ctx, common.PlatformIdentityProvider, authenticationNamespace)
	if err != nil {
		reqLogger.Error(err, "Deployment needed for OIDC registration could not be retrieved",
			"Deployment.Name", common.PlatformIdentityProvider,
			"Deployment.Namespace", authenticationNamespace)
		return subreconciler.RequeueWithDelayAndError(wait.Jitter(baseAuthenticationWaitTime, 1.0), err)
	} else if !available {
		reqLogger.Info("Deployment is not available yet; requeueing",
			"Deployment.Name", common.PlatformIdentityProvider,
			"Deployment.Namespace", authenticationNamespace)
		return subreconciler.RequeueWithDelay(wait.Jitter(baseAuthenticationWaitTime, 1.0))
	}

	reqLogger.Info("Deployment is available",
		"Deployment.Name", common.PlatformIdentityProvider,
		"Deployment.Namespace", authenticationNamespace)

	// Attempt to get the Client registration; if it isn't there, create a new one, otherwise, update
	_, err = r.getClientRegistration(ctx, clientCR, config)
	if err != nil {
		reqLogger.Info("Client not found, create new Client")
		requestMethod = http.MethodPost
		if _, err = r.createClientRegistration(ctx, clientCR, config); err != nil {
			reqLogger.Error(err, "Failed to create OIDC client registration")
			if err := r.writeErrorConditionsAndEvents(ctx, clientCR, err, http.MethodPost); err != nil {
				reqLogger.Error(err, "Failed to update Client status")
				return subreconciler.RequeueWithError(err)
			}
			return subreconciler.RequeueWithError(err)
		}

		r.Recorder.Event(clientCR, corev1.EventTypeNormal, ReasonCreateClientSuccessful, MessageCreateClientSuccessful)
	} else {
		reqLogger.Info("Client found, update Client")
		requestMethod = http.MethodPut
		if _, err = r.updateClientRegistration(ctx, clientCR, config); err != nil {
			reqLogger.Error(err, "Failed to update OIDC client registration")
			if err := r.writeErrorConditionsAndEvents(ctx, clientCR, err, requestMethod); err != nil {
				reqLogger.Error(err, "Failed to update Client status")
				return subreconciler.RequeueWithError(err)
			}
			return subreconciler.RequeueWithError(err)
		}
		r.Recorder.Event(clientCR, corev1.EventTypeNormal, ReasonUpdateClientSuccessful, MessageUpdateClientSuccessful)
	}

	// Update the client
	reqLogger.Info("Updating Client CR spec")
	if err = r.Update(ctx, clientCR); err != nil {
		reqLogger.Error(err, "Client CR spec update failed")
		return subreconciler.RequeueWithError(err)
	}

	return subreconciler.ContinueReconciling()
}

// annotateServiceAccount updates ibm-iam-operand-restricted SA with redirecturi's present in the Client CR for
// updateClient Call
func (r *ClientReconciler) annotateServiceAccount(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "annotateServiceAccount")
	reqLogger.Info("Add any missing Client annotations to ibm-iam-operand-restricted ServiceAccount")

	clientCR := &oidcsecurityv1.Client{}

	if result, err = r.getLatestClient(ctx, req, clientCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	clientName := clientCR.Name
	redirectURIs := clientCR.Spec.OidcLibertyClient.RedirectUris

	// Though there should be redirectURIs, if there are none, there is nothing to do but continue reconciling
	if len(redirectURIs) == 0 {
		reqLogger.Info("No annotations to add to ServiceAccount ibm-iam-operand-restricted; skipping")
		return subreconciler.ContinueReconciling()
	}

	sAccName := "ibm-iam-operand-restricted"
	sAccNamespace, err := common.GetServicesNamespace(ctx, &r.Client)
	if err != nil {
		return subreconciler.RequeueWithError(err)
	}

	serviceAccount := &corev1.ServiceAccount{}
	err = r.Get(ctx, types.NamespacedName{Name: sAccName, Namespace: sAccNamespace}, serviceAccount)
	if err != nil {
		reqLogger.Error(err, "failed to GET ServiceAccount ibm-iam-operand-restricted")
		return subreconciler.RequeueWithError(err)
	}

	changed := false
	if serviceAccount.Annotations == nil {
		serviceAccount.Annotations = make(map[string]string)
		changed = true
	}
	for i := 0; i < len(redirectURIs); i++ {
		key := "serviceaccounts.openshift.io/oauth-redirecturi." + clientName + strconv.Itoa(i)
		if value, found := serviceAccount.Annotations[key]; !found || value != redirectURIs[i] {
			serviceAccount.Annotations[key] = redirectURIs[i]
			changed = true
		}
	}

	if !changed {
		reqLogger.Info("No new annotations to add to ServiceAccount ibm-iam-operand-restricted; skipping")
		return subreconciler.ContinueReconciling()
	}

	// update the SAcc with this annotation
	if err = r.Update(ctx, serviceAccount); err != nil {
		// error updating annotation
		reqLogger.Error(err, "error updating annotation in ServiceAccount")
		return subreconciler.RequeueWithError(err)
	}

	// annotation got updated properly
	reqLogger.Info("ibm-iam-operand-restricted SA is updated with annotations successfully")

	return subreconciler.Requeue()
}

// processZenRegistration registers the OIDC client credentials for use with the Zen instance that has the same ID as
// the one specified on the Client CR's .spec.ZenInstanceId.
func (r *ClientReconciler) processZenRegistration(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "processZenRegistration")
	reqLogger.Info("Processing Zen instance registration for Client, if configured")
	clientCR := &oidcsecurityv1.Client{}

	if result, err = r.getLatestClient(ctx, req, clientCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	if clientCR.Spec.ZenInstanceId == "" {
		reqLogger.Info("Zen instance ID not specified on Client, skipping Zen registration")
		return subreconciler.ContinueReconciling()
	}

	config := &AuthenticationConfig{}
	err = GetConfig(ctx, &r.Client, config)
	if err != nil {
		reqLogger.Error(err, "Failed to gather Authentication configuration")
		return subreconciler.RequeueWithError(err)
	}

	var authenticationNamespace string
	if authenticationNamespace, err = config.GetAuthenticationNamespace(); err != nil {
		reqLogger.Error(err, "No Authentication CR found to determine services namespace")
		return subreconciler.RequeueWithError(err)
	}

	available, err := r.isDeploymentAvailable(ctx, common.PlatformIdentityManagement, authenticationNamespace)
	if err != nil {
		reqLogger.Error(err, "Deployment needed for OIDC registration could not be retrieved",
			"Deployment.Name", common.PlatformIdentityManagement,
			"Deployment.Namespace", authenticationNamespace)
		return subreconciler.RequeueWithDelayAndError(wait.Jitter(baseAuthenticationWaitTime, 1.0), err)
	} else if !available {
		reqLogger.Info("Deployment is not available yet; requeueing",
			"Deployment.Name", common.PlatformIdentityManagement,
			"Deployment.Namespace", authenticationNamespace)
		return subreconciler.RequeueWithDelay(wait.Jitter(baseAuthenticationWaitTime, 1.0))
	}

	reqLogger.Info("Deployment is available",
		"Deployment.Name", common.PlatformIdentityManagement,
		"Deployment.Namespace", authenticationNamespace)

	var zenReg *ZenInstance
	zenReg, err = r.getZenInstanceRegistration(ctx, clientCR, config)
	if err != nil {
		reqLogger.Error(err, "Failed to get Zen instance")
		if err := r.writeErrorConditionsAndEvents(ctx, clientCR, err, http.MethodPost); err != nil {
			reqLogger.Error(err, "Failed ot update Client status")
			return subreconciler.RequeueWithError(err)
		}
		return subreconciler.RequeueWithError(err)
	}

	clientCreds, err := r.GetClientCreds(ctx, clientCR)
	if err != nil {
		reqLogger.Error(err, "Failed to get client credentials from Secret", "secretName", clientCR.Spec.Secret)
		r.Recorder.Event(clientCR, corev1.EventTypeWarning, ReasonCreateZenRegistrationFailed, err.Error())
		reqLogger.Info("Updating status")
		return subreconciler.RequeueWithError(err)
	}

	//Zen registration exist, update
	if zenReg != nil {
		//Zen registration exists - going to update zen instance registration
		reqLogger.Info("Zen registration already exists for oidc client - the zen instance will be updated",
			"clientId", clientCR.Spec.ClientId, "zenInstanceId", clientCR.Spec.ZenInstanceId)
		if err = r.registerZenInstance(ctx, clientCR, clientCreds, config); err != nil {
			reqLogger.Error(err, "Failed to update Zen registration")
			if err := r.writeErrorConditionsAndEvents(ctx, clientCR, err, http.MethodPost); err != nil {
				reqLogger.Error(err, "Failed ot update Client status")
				return subreconciler.RequeueWithError(err)
			}
			return subreconciler.RequeueWithError(err)
		}
		return subreconciler.ContinueReconciling()
	}

	//Zen registration does not exist, create
	reqLogger.Info("Creating Zen registration for client")
	if err = r.registerZenInstance(ctx, clientCR, clientCreds, config); err != nil {
		reqLogger.Error(err, "Failed to create Zen registration")
		if err := r.writeErrorConditionsAndEvents(ctx, clientCR, err, http.MethodPost); err != nil {
			reqLogger.Error(err, "Failed ot update Client status")
			return subreconciler.RequeueWithError(err)
		}

		return subreconciler.RequeueWithError(err)
	}

	return subreconciler.ContinueReconciling()
}

// updateStatus sets success-related conditions in the Client CR's status.
func (r *ClientReconciler) updateStatus(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx).WithValues("subreconciler", "updateStatus")
	reqLogger.Info("Marking Client Ready condition as \"True\"")

	clientCR := &oidcsecurityv1.Client{}
	if result, err = r.getLatestClient(ctx, req, clientCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}
	condition := metav1.Condition{
		Type:    oidcsecurityv1.ClientConditionReady,
		Status:  metav1.ConditionTrue,
		Reason:  ReasonCreateClientSuccessful,
		Message: MessageClientSuccessful,
	}
	meta.SetStatusCondition(&clientCR.Status.Conditions, condition)
	reqLogger.Info("Updating Client status")
	if err := r.Status().Update(ctx, clientCR); err != nil {
		reqLogger.Error(err, "Failed to update Client status")
		return subreconciler.RequeueWithError(err)
	}

	return subreconciler.ContinueReconciling()
}

// End subreconcilers

func (r *ClientReconciler) getLatestClient(ctx context.Context, req ctrl.Request, client *oidcsecurityv1.Client) (*ctrl.Result, error) {
	reqLogger := logf.FromContext(ctx)

	if err := r.Get(ctx, req.NamespacedName, client); err != nil {
		if k8sErrors.IsNotFound(err) {
			reqLogger.Info("Client not found; skipping reconciliation")
			return subreconciler.DoNotRequeue()
		}
		reqLogger.Error(err, "Failed to get Client")
		return subreconciler.RequeueWithError(err)
	}
	return subreconciler.ContinueReconciling()
}

// isMarkedForDeletion returns true if the Client is in the process of being deleted
func isMarkedForDeletion(client *oidcsecurityv1.Client) bool {
	return client.GetDeletionTimestamp() != nil
}

// isNotMarkedForDeletion returns the inverse of isMarkedForDeletion
func isNotMarkedForDeletion(client *oidcsecurityv1.Client) bool {
	return !isMarkedForDeletion(client)
}

// createPostfixedName creates a new name that stays below the Kubernetes max length for a name with a postfix.
func createPostfixedName(original, postfix string) (newName string) {
	const k8sMaxNameLength int = 253
	const separator = "-"
	if len(original)+len(postfix)+1 > k8sMaxNameLength {
		// Max length minus postfix length with separator
		truncLen := k8sMaxNameLength - len(postfix) - 1
		return strings.Join([]string{original[:truncLen], postfix}, separator)
	}
	return strings.Join([]string{original, postfix}, separator)
}

// finalizeClient performs all clean up that needs to be performed before a Client CR can be deleted safely.
func (r *ClientReconciler) finalizeClient(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)
	clientCR := &oidcsecurityv1.Client{}

	if _, err = r.getLatestClient(ctx, req, clientCR); err != nil {
		if k8sErrors.IsNotFound(err) {
			// Assume that the Client was already deleted
			return subreconciler.DoNotRequeue()
		}
		return subreconciler.RequeueWithError(err)
	}

	config := &AuthenticationConfig{}
	err = GetConfig(ctx, &r.Client, config)
	if err != nil {
		reqLogger.Error(err, "Failed to gather Authentication configuration")
		return subreconciler.RequeueWithError(err)
	}

	if clientCR.Spec.ZenInstanceId != "" {
		reqLogger.Info("Client has a zenInstanceId, attempt to delete the matching Zen instance")
		err = r.unregisterZenInstance(ctx, clientCR, config)
		if err != nil {
			reqLogger.Error(err, "Zen instance registration deletion failed", "zenInstanceId", clientCR.Spec.ZenInstanceId)
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("Zen instance registration deletion succeeded", "ZenInstanceId", clientCR.Spec.ZenInstanceId)
	}

	reqLogger.Info("Deleting annotations from ibm-iam-operand-restricted ServiceAccount")
	if result, err = r.removeAnnotationFromSA(ctx, req); subreconciler.ShouldRequeue(result, err) {
		return subreconciler.RequeueWithError(err)
	}

	reqLogger.Info("Attempting deletion of the OIDC client registration")
	_, err = r.deleteClientRegistration(ctx, clientCR, config)
	if err != nil {
		return subreconciler.RequeueWithError(err)
	}
	reqLogger.Info("Client registration successfully deleted")

	return subreconciler.ContinueReconciling()
}

func isDeploymentConditionTrue(conditions []v1.DeploymentCondition, conditionType v1.DeploymentConditionType) bool {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func (r *ClientReconciler) isDeploymentAvailable(ctx context.Context, deploymentName common.DeploymentName, namespace string) (available bool, err error) {
	key := types.NamespacedName{
		Name:      string(deploymentName),
		Namespace: namespace,
	}
	deploy := &v1.Deployment{}
	if err = r.Get(ctx, key, deploy); err != nil {
		return
	}
	return isDeploymentConditionTrue(deploy.Status.Conditions, v1.DeploymentAvailable), nil
}

// migrateCP2Client updates an existing Client that has the finalizer from the icp-oidcclient-watcher Operator and
// replaces it with this controller's. It also adds the Administrator role if the Client is not configured for use with
// an instance of Zen and has no roles specified. Returns whether a change to the Client was made.
func migrateCP2Client(ctx context.Context, clientCR *oidcsecurityv1.Client) (clientChanged bool) {
	reqLogger := logf.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(clientCR, CP2FinalizerName) {
		return false
	}

	if clientCR.Spec.ZenInstanceId == "" && len(clientCR.Spec.Roles) == 0 {
		reqLogger.Info("Upgrade check : Non-ZEN cp2 Client CR Role would be updated : ", "Role", AdministratorRole)
		clientCR.Spec.Roles = append(clientCR.Spec.Roles, AdministratorRole)
		reqLogger.Info("Upgrade check : Non-ZEN CP2 Client CR Finalizers would be updated : ", "Finalizer", CP3FinalizerName)
		controllerutil.RemoveFinalizer(clientCR, CP2FinalizerName)
		return true
	} else if clientCR.Spec.ZenInstanceId != "" {
		reqLogger.Info("Upgrade check : ZEN cp2 Client CR Finalizers would be updated : ", "Finalizer", CP3FinalizerName)
		controllerutil.RemoveFinalizer(clientCR, CP2FinalizerName)
		return true
	}

	return false
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// getSecretFromClient attempts to read the secret named in the provided Client resource and returns its contents if
// found. Returns an error if the attempt to read the Secret off of the cluster fails for any reason.
func (r *ClientReconciler) getSecretFromClient(ctx context.Context, client *oidcsecurityv1.Client) (secret *corev1.Secret, err error) {
	if client == nil || client.Spec.Secret == "" {
		return
	}
	secret = &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Name: client.Spec.Secret, Namespace: client.Namespace}, secret)
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
	if secret == nil || secret.Data == nil {
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

func (r *ClientReconciler) createNewSecretForClient(ctx context.Context, client *oidcsecurityv1.Client) (*corev1.Secret, error) {
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
	if err := controllerutil.SetControllerReference(client, secret, r.Scheme); err != nil {
		return nil, err
	}

	reqLogger.Info("Generating client credentials for new Secret")
	clientCreds := r.generateClientCredentials(client.Spec.ClientId)
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	clientId := clientCreds.ClientID
	clientSecret := clientCreds.ClientSecret
	secret.Data["CLIENT_ID"] = []byte(clientId)
	secret.Data["CLIENT_SECRET"] = []byte(clientSecret)

	err := r.Create(ctx, secret)
	if err != nil {
		reqLogger.Error(err, "Error occurred during secret creation")
		return nil, err
	}
	reqLogger.Info("Created Secret", "secretName", secret.Name)
	return secret, nil
}

// removeAnnotationFromSA removes respective redirecturi annotation present in ibm-iam-operand-restricted SA for deleteClient Call
func (r *ClientReconciler) removeAnnotationFromSA(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)
	clientCR := &oidcsecurityv1.Client{}

	if result, err = r.getLatestClient(ctx, req, clientCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	clientName := clientCR.Name

	// Though there should be redirectURIs, if there are none, there is nothing to do but continue reconciling
	redirectURIs := clientCR.Spec.OidcLibertyClient.RedirectUris
	if len(redirectURIs) == 0 {
		return subreconciler.ContinueReconciling()
	}

	sAccName := "ibm-iam-operand-restricted"
	sAccNamespace, err := common.GetServicesNamespace(ctx, &r.Client)
	if err != nil {
		reqLogger.Error(err, "Failed to get services namespace")
		return subreconciler.RequeueWithError(err)
	}

	serviceAccount := &corev1.ServiceAccount{}
	err = r.Get(ctx, types.NamespacedName{Name: sAccName, Namespace: sAccNamespace}, serviceAccount)
	if err != nil {
		reqLogger.Error(err, "failed to GET ServiceAccount ibm-iam-operand-restricted")
		return subreconciler.RequeueWithError(err)
	}

	// If there are no annotations, nothing to do - continue reconciling
	if serviceAccount.Annotations == nil {
		return subreconciler.ContinueReconciling()
	}

	changed := false
	for i := 0; i < len(redirectURIs); i++ {
		key := "serviceaccounts.openshift.io/oauth-redirecturi." + clientName + strconv.Itoa(i)
		if _, found := serviceAccount.Annotations[key]; found {
			delete(serviceAccount.Annotations, key)
			changed = true
		}
	}

	if !changed {
		reqLogger.Info("No annotation deletions on SA ibm-iam-operand-restricted necessary")
		return subreconciler.ContinueReconciling()
	}

	// update the SAcc with this annotation
	err = r.Update(ctx, serviceAccount)
	if err != nil {
		// error updating annotation
		reqLogger.Error(err, "Error removing annotation in ServiceAccount")
		return subreconciler.RequeueWithError(err)
	}

	// annotation got updated properly
	reqLogger.Info("Annotations for Client removed from ibm-iam-operand-restricted SA successfully")

	return subreconciler.Requeue()
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&oidcsecurityv1.Client{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
