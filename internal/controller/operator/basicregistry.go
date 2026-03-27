//
// Copyright 2025 IBM Corporation
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
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/opdev/subreconciler"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// Secret names for basicRegistry accounts
	PlatformAuthIDPCredentialsSecretName  = "platform-auth-idp-credentials"
	PlatformAuthSCIMCredentialsSecretName = "platform-auth-scim-credentials"
	PlatformOIDCCredentialsSecretName     = "platform-oidc-credentials"

	// Secret data keys
	AdminUsernameKey                  = "admin_username"
	AdminPasswordKey                  = "admin_password"
	SCIMAdminUsernameKey              = "scim_admin_username"
	SCIMAdminPasswordKey              = "scim_admin_password"
	OAuth2ClientRegistrationSecretKey = "OAUTH2_CLIENT_REGISTRATION_SECRET"
	OAuthAdminUsername                = "oauthadmin"

	// Auth service endpoint
	AuthServiceURL                   = "https://platform-auth-service:9443"
	OIDCRegistrationEndpointTemplate = "/oidc/endpoint/OP/registration/%s"

	// Job name for OIDC client registration
	OIDCClientRegistrationJobName = "oidc-client-registration"
)

// basicRegistryAccount represents a single account to validate
type basicRegistryAccount struct {
	name        string
	username    string
	password    string
	secretName  string
	usernameKey string
	passwordKey string
}

// validateBasicRegistryAccounts is a SubreconcilerFn that validates the three basicRegistry accounts
// are properly registered in the auth service's Liberty server
func (r *AuthenticationReconciler) validateBasicRegistryAccounts(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Validating basicRegistry accounts registration")

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	// Check if a rollout is in progress
	rolloutInProgress, err := r.isRolloutInProgress(debugCtx, authCR.Namespace)
	if err != nil {
		log.Error(err, "Failed to check if rollout is in progress")
		return subreconciler.RequeueWithError(err)
	}
	if rolloutInProgress {
		log.Info("Deployment rollout is in progress; requeueing")
		return subreconciler.RequeueWithDelay(15 * time.Second)
	}

	// Get the WLP client ID for the registration endpoint
	wlpClientID, err := r.getWLPClientID(debugCtx, authCR.Namespace)
	if err != nil {
		log.Error(err, "Failed to get WLP client ID")
		return subreconciler.RequeueWithError(err)
	}

	// Define the three accounts to validate
	accounts := []basicRegistryAccount{
		{
			name:        "default admin",
			secretName:  PlatformAuthIDPCredentialsSecretName,
			usernameKey: AdminUsernameKey,
			passwordKey: AdminPasswordKey,
		},
		{
			name:        "SCIM admin",
			secretName:  PlatformAuthSCIMCredentialsSecretName,
			usernameKey: SCIMAdminUsernameKey,
			passwordKey: SCIMAdminPasswordKey,
		},
		{
			name:        "OAuth2 admin",
			username:    OAuthAdminUsername,
			secretName:  PlatformOIDCCredentialsSecretName,
			passwordKey: OAuth2ClientRegistrationSecretKey,
		},
	}

	// Retrieve credentials for all accounts
	for i := range accounts {
		if err := r.getAccountCredentials(debugCtx, authCR.Namespace, &accounts[i]); err != nil {
			log.Error(err, "Failed to get credentials for account", "account", accounts[i].name)
			return subreconciler.RequeueWithError(err)
		}
	}

	// Validate each account
	hasUnauthorized := false
	hasNotFound := false

	for _, account := range accounts {
		statusCode, err := r.testBasicRegistryAccount(debugCtx, account, wlpClientID)
		if err != nil {
			log.Error(err, "Failed to test basicRegistry account", "account", account.name)
			return subreconciler.RequeueWithError(err)
		}

		log.Info("BasicRegistry account validation result",
			"account", account.name,
			"statusCode", statusCode)

		switch statusCode {
		case http.StatusOK:
			// Account is properly registered and client exists
			log.Info("Account is properly registered and client exists", "account", account.name)
		case http.StatusNotFound:
			// Account is registered but client doesn't exist
			// This is expected on fresh install - allow reconciliation to continue
			log.Info("Account is registered but client not found (may be fresh install)", "account", account.name)
			hasNotFound = true
		case http.StatusForbidden:
			// HTTP 403 indicates account is registered but client may or may not exist
			// This is acceptable - the account credentials are valid
			log.Info("Account is registered (HTTP 403 received - account valid but client existence uncertain)", "account", account.name)
		case http.StatusUnauthorized:
			// Account is not registered or not authorized - need rollout
			log.Info("Account is not properly registered or authorized", "account", account.name, "statusCode", statusCode)
			hasUnauthorized = true
		default:
			// Unexpected status code
			err := fmt.Errorf("unexpected HTTP status code %d for account %s", statusCode, account.name)
			log.Error(err, "Unexpected status code received")
			return subreconciler.RequeueWithError(err)
		}
	}

	// Handle the results based on priority
	if hasUnauthorized {
		// Accounts not registered - trigger rollout and requeue
		log.Info("One or more accounts not registered; triggering deployment rollout")
		r.needsRollout = true
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	// All client registration GETs worked - continue
	if !hasNotFound {
		log.Info("All basicRegistry accounts are properly registered and client exists")
		return subreconciler.ContinueReconciling()
	}

	// Check if the OIDC client registration Job exists
	jobExists, err := r.oidcClientRegistrationJobExists(debugCtx, authCR.Namespace)
	if err != nil {
		log.Error(err, "Failed to check if OIDC client registration Job exists")
		return subreconciler.RequeueWithError(err)
	}

	if !jobExists {
		// Job doesn't exist and client not found - this is expected on fresh install
		// Continue to allow the OIDC client registration Job to be created
		log.Info("Client not found but Job doesn't exist yet; continuing to allow Job creation")
		return subreconciler.ContinueReconciling()
	}

	// Job exists but client still not found - delete job and requeue
	log.Info("OIDC client registration Job exists but client not found; deleting Job")
	if err := r.deleteOIDCClientRegistrationJob(debugCtx, authCR.Namespace); err != nil {
		log.Error(err, "Failed to delete OIDC client registration Job")
		return subreconciler.RequeueWithError(err)
	}
	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

// getAccountCredentials retrieves the username and password for a basicRegistry account
func (r *AuthenticationReconciler) getAccountCredentials(ctx context.Context, namespace string, account *basicRegistryAccount) error {
	log := logf.FromContext(ctx)

	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{
		Name:      account.secretName,
		Namespace: namespace,
	}

	if err := r.Get(ctx, secretKey, secret); err != nil {
		if k8sErrors.IsNotFound(err) {
			return fmt.Errorf("secret %s not found in namespace %s", account.secretName, namespace)
		}
		return fmt.Errorf("failed to get secret %s: %w", account.secretName, err)
	}

	// Get username (if not already set)
	if account.username == "" {
		if account.usernameKey == "" {
			return fmt.Errorf("username key not specified for account %s", account.name)
		}
		username, ok := secret.Data[account.usernameKey]
		if !ok {
			return fmt.Errorf("username key %s not found in secret %s", account.usernameKey, account.secretName)
		}
		account.username = string(username)
	}

	// Get password
	password, ok := secret.Data[account.passwordKey]
	if !ok {
		return fmt.Errorf("password key %s not found in secret %s", account.passwordKey, account.secretName)
	}
	account.password = string(password)

	log.V(1).Info("Retrieved credentials for account", "account", account.name, "username", account.username)
	return nil
}

// getWLPClientID retrieves the WLP client ID from the platform-oidc-credentials secret
func (r *AuthenticationReconciler) getWLPClientID(ctx context.Context, namespace string) (string, error) {
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{
		Name:      PlatformOIDCCredentialsSecretName,
		Namespace: namespace,
	}

	if err := r.Get(ctx, secretKey, secret); err != nil {
		return "", fmt.Errorf("failed to get WLP client ID secret: %w", err)
	}

	clientID, ok := secret.Data["WLP_CLIENT_ID"]
	if !ok {
		return "", fmt.Errorf("WLP_CLIENT_ID not found in secret %s", PlatformOIDCCredentialsSecretName)
	}

	return string(clientID), nil
}

// testBasicRegistryAccount tests if an account is registered by attempting to GET the OAuth client registration
func (r *AuthenticationReconciler) testBasicRegistryAccount(ctx context.Context, account basicRegistryAccount, wlpClientID string) (int, error) {
	log := logf.FromContext(ctx)

	// Build the registration endpoint URL
	endpoint := fmt.Sprintf(OIDCRegistrationEndpointTemplate, wlpClientID)
	url := AuthServiceURL + endpoint

	// Create HTTP client with TLS verification disabled (internal service)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set basic auth
	req.SetBasicAuth(account.username, account.password)
	req.Header.Set("Content-Type", "application/json")

	log.V(1).Info("Testing basicRegistry account",
		"account", account.name,
		"username", account.username,
		"url", url)

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

// oidcClientRegistrationJobExists checks if the OIDC client registration Job exists
func (r *AuthenticationReconciler) oidcClientRegistrationJobExists(ctx context.Context, namespace string) (bool, error) {
	job := &batchv1.Job{}
	jobKey := types.NamespacedName{
		Name:      OIDCClientRegistrationJobName,
		Namespace: namespace,
	}

	if err := r.Get(ctx, jobKey, job); err != nil {
		if k8sErrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check if OIDC client registration Job exists: %w", err)
	}

	return true, nil
}

// deleteOIDCClientRegistrationJob deletes the OIDC client registration Job if it exists
func (r *AuthenticationReconciler) deleteOIDCClientRegistrationJob(ctx context.Context, namespace string) error {
	log := logf.FromContext(ctx)

	job := &batchv1.Job{}
	jobKey := types.NamespacedName{
		Name:      OIDCClientRegistrationJobName,
		Namespace: namespace,
	}

	if err := r.Get(ctx, jobKey, job); err != nil {
		if k8sErrors.IsNotFound(err) {
			log.Info("OIDC client registration Job not found; nothing to delete")
			return nil
		}
		return fmt.Errorf("failed to get OIDC client registration Job: %w", err)
	}

	// Delete the Job
	if err := r.Delete(ctx, job); err != nil {
		return fmt.Errorf("failed to delete OIDC client registration Job: %w", err)
	}

	log.Info("Successfully deleted OIDC client registration Job")
	return nil
}

// isRolloutInProgress checks if any of the authentication deployments are currently rolling out
func (r *AuthenticationReconciler) isRolloutInProgress(ctx context.Context, namespace string) (bool, error) {
	log := logf.FromContext(ctx)

	// List of deployment names to check
	deploymentNames := []string{
		"platform-auth-service",
		"platform-identity-provider",
		"platform-identity-management",
	}

	for _, deploymentName := range deploymentNames {
		deployment := &appsv1.Deployment{}
		deploymentKey := types.NamespacedName{
			Name:      deploymentName,
			Namespace: namespace,
		}

		if err := r.Get(ctx, deploymentKey, deployment); err != nil {
			if k8sErrors.IsNotFound(err) {
				// Deployment doesn't exist yet, consider this as rollout in progress
				log.V(1).Info("Deployment not found, considering rollout in progress", "deployment", deploymentName)
				return true, nil
			}
			return false, fmt.Errorf("failed to get deployment %s: %w", deploymentName, err)
		}

		// Check if rollout is in progress by comparing generation and observedGeneration
		// and checking if all replicas are updated and available
		if deployment.Generation != deployment.Status.ObservedGeneration {
			log.V(1).Info("Deployment rollout in progress (generation mismatch)",
				"deployment", deploymentName,
				"generation", deployment.Generation,
				"observedGeneration", deployment.Status.ObservedGeneration)
			return true, nil
		}

		// Check if all replicas are updated and available
		desiredReplicas := int32(1)
		if deployment.Spec.Replicas != nil {
			desiredReplicas = *deployment.Spec.Replicas
		}

		if deployment.Status.UpdatedReplicas < desiredReplicas ||
			deployment.Status.AvailableReplicas < desiredReplicas ||
			deployment.Status.ReadyReplicas < desiredReplicas {
			log.V(1).Info("Deployment rollout in progress (replicas not ready)",
				"deployment", deploymentName,
				"desired", desiredReplicas,
				"updated", deployment.Status.UpdatedReplicas,
				"available", deployment.Status.AvailableReplicas,
				"ready", deployment.Status.ReadyReplicas)
			return true, nil
		}
	}

	log.V(1).Info("No deployment rollouts in progress")
	return false, nil
}

// Made with Bob
