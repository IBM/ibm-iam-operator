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

package operator

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"time"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/opdev/subreconciler"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *AuthenticationReconciler) handleSecrets(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	debugLog := log.V(1)
	debugCtx := logf.IntoContext(ctx, debugLog)

	log.Info("Ensure Secrets are present and updated")
	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(debugCtx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	secretSubreconcilers, err := r.getSecretSubreconcilers(debugCtx, authCR)
	if err != nil {
		log.Error(err, "Failed to generate updaters for Secrets")
		return subreconciler.RequeueWithError(err)
	}

	results := []*ctrl.Result{}
	errs := []error{}
	for _, secretSubreconciler := range secretSubreconcilers {
		result, err = secretSubreconciler.Reconcile(debugCtx)
		results = append(results, result)
		errs = append(errs, err)
	}

	return ctrlcommon.ReduceSubreconcilerResultsAndErrors(results, errs)
}

func scrubSecretValues(s common.SecondaryReconciler, ctx context.Context, observed, generated *corev1.Secret) error {
	if observed != nil && observed.Data != nil {
		common.ScrubMap(observed.Data)
	}
	if generated != nil && generated.Data != nil {
		common.ScrubMap(generated.Data)
	}
	observed = nil
	generated = nil
	return nil
}

func (r *AuthenticationReconciler) getSecretSubreconcilers(ctx context.Context, authCR *operatorv1alpha1.Authentication) (subRecs []ctrlcommon.Subreconciler, err error) {
	var caCert []byte
	caCert, err = r.getPlatformAuthSecret(ctx, authCR)
	if err != nil {
		return
	}

	wlpClientID, err := r.GenerateBytes(ctrlcommon.LowerAlphaNum, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wlpClientID: %w", err)
	}
	wlpClientSecret, err := r.GenerateBytes(ctrlcommon.LowerAlphaNum, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wlpClientSecret: %w", err)
	}
	adminPassword, err := r.GenerateBytes(ctrlcommon.AlphaNum, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate adminPassword: %w", err)
	}
	scimAdminPassword, err := r.GenerateBytes(ctrlcommon.AlphaNum, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate scimAdminPassword: %w", err)
	}
	encryptionKey, err := r.GenerateBytes(ctrlcommon.AlphaNum, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryptionKey: %w", err)
	}
	wlpClientRegistrationSecret, err := r.GenerateBytes(ctrlcommon.AlphaNum, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wlpClientRegistrationSecret: %w", err)
	}
	encryptionIV, err := r.GenerateBytes(ctrlcommon.AlphaNum, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryptionIV: %w", err)
	}

	builders := []*ctrlcommon.SecondaryReconcilerBuilder[*corev1.Secret]{
		ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.Secret]().
			WithName("platform-auth-ldaps-ca-cert").
			WithGenerateFns(generateSecretObject(map[string][]byte{"certificate": []byte("")})).
			WithModifyFns(ensureSecretLabels),
		ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.Secret]().
			WithName("im-cert-auth-certificates").
			WithGenerateFns(generateSecretObject(map[string][]byte{"data": []byte("")})).
			WithModifyFns(ensureSecretLabels),
		ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.Secret]().
			WithName("platform-auth-idp-credentials").
			WithGenerateFns(generateSecretObject(
				map[string][]byte{
					"admin_username": []byte(authCR.Spec.Config.DefaultAdminUser),
					"admin_password": adminPassword,
				})).
			WithModifyFns(ensureSecretLabels, ensureChecksumAnnotation).
			WithOnWriteFns(signalNeedRolloutFn[*corev1.Secret](r)),
		ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.Secret]().
			WithName("platform-auth-scim-credentials").
			WithGenerateFns(generateSecretObject(
				map[string][]byte{
					"scim_admin_username": []byte(authCR.Spec.Config.ScimAdminUser),
					"scim_admin_password": scimAdminPassword,
				})).
			WithModifyFns(ensureSecretLabels, ensureChecksumAnnotation).
			WithOnWriteFns(signalNeedRolloutFn[*corev1.Secret](r)),
		ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.Secret]().
			WithName("platform-auth-idp-encryption").
			WithGenerateFns(generateSecretObject(
				map[string][]byte{
					"ENCRYPTION_KEY": encryptionKey,
					"ENCRYPTION_IV":  encryptionIV,
					"algorithm":      []byte("aes256"),
					"inputEncoding":  []byte("utf8"),
					"outputEncoding": []byte("hex"),
				})).
			WithModifyFns(ensureSecretLabels, ensureIVSet),
		ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.Secret]().
			WithName("oauth-client-secret").
			WithGenerateFns(generateSecretObject(
				map[string][]byte{
					"WLP_CLIENT_REGISTRATION_SECRET": wlpClientRegistrationSecret,
					"DEFAULT_ADMIN_USER":             []byte(authCR.Spec.Config.DefaultAdminUser),
				})).
			WithModifyFns(ensureSecretLabels),
		ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.Secret]().
			WithName("platform-oidc-credentials").
			WithGenerateFns(generateSecretObject(
				map[string][]byte{
					"WLP_CLIENT_ID":                     wlpClientID,
					"WLP_CLIENT_SECRET":                 wlpClientSecret,
					"WLP_SCOPE":                         []byte("openid+profile+email"),
					"OAUTH2_CLIENT_REGISTRATION_SECRET": wlpClientRegistrationSecret,
					"IBMID_CLIENT_SECRET":               []byte("903305fb599c8328a4d86d4cbdd07368"),
					"IBMID_PROFILE_CLIENT_SECRET":       []byte("C1bR0rO7kE0cE3xM2tV1gI0mG1cH3jK4dD7iQ8rW6pF1aF4mQ5"),
				})).
			WithModifyFns(ensureSecretLabels, ensureChecksumAnnotation).
			WithOnWriteFns(signalNeedRolloutFn[*corev1.Secret](r)),
		ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.Secret]().
			WithName("platform-auth-ibmid-jwk").
			WithGenerateFns(generateSecretObject(
				map[string][]byte{"cert": []byte("")},
			)).
			WithModifyFns(ensureSecretLabels),
		ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.Secret]().
			WithName("platform-auth-ibmid-ssl-chain").
			WithGenerateFns(generateSecretObject(map[string][]byte{"cert": []byte("")})).
			WithModifyFns(ensureSecretLabels),
		ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.Secret]().
			WithName(ClusterSecretName).
			WithGenerateFns(generateSecretObject(
				map[string][]byte{"ca.crt": caCert},
				map[string]string{
					"app":                          "platform-auth-service",
					"component":                    "platform-auth-service",
					"app.kubernetes.io/component":  "platform-auth-service",
					"app.kubernetes.io/name":       "platform-auth-service",
					"app.kubernetes.io/instance":   "platform-auth-service",
					"app.kubernetes.io/managed-by": "",
				})).
			WithModifyFns(modifyClusterCACert()),
	}

	subRecs = []ctrlcommon.Subreconciler{}
	for i := range builders {
		subRecs = append(subRecs, builders[i].
			WithNamespace(authCR.Namespace).
			WithOnFinishedFns(scrubSecretValues).
			WithPrimary(authCR).
			WithClient(r.Client).
			MustBuild())
	}

	return
}

func (r *AuthenticationReconciler) waitForSecret(ctx context.Context, instance *operatorv1alpha1.Authentication, name string, secret *corev1.Secret) (err error) {
	log := logf.FromContext(ctx)

	log.Info("Waiting for secret", "Certificate.Namespace", instance.Namespace, "Secret.Name", name)

	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 10*time.Minute, true, func(innerCtx context.Context) (done bool, err error) {
		if innerErr := r.Get(innerCtx, types.NamespacedName{Name: name, Namespace: instance.Namespace}, secret); innerErr != nil {
			log.Error(err, "Failed to get Secret")
			return false, nil
		}
		log.Info("Got Secret")
		return true, nil
	})

	if err != nil {
		log.Error(err, "Encountered some error")
	}

	return
}

func (r *AuthenticationReconciler) getPlatformAuthSecret(ctx context.Context, authCR *operatorv1alpha1.Authentication) (caCert []byte, err error) {
	// get ca.crt from platform-auth-secret
	log := logf.FromContext(ctx)
	secret := &corev1.Secret{}
	err = r.waitForSecret(ctx, authCR, "platform-auth-secret", secret)
	if err != nil {
		log.Error(err, "Waiting for Secret failed")
		return
	}

	caCert = secret.Data["ca.crt"]
	return
}

// ensureSecretLabels makes sure that the base set of labels for Secrets has been set on the Secret.
func ensureSecretLabels(s ctrlcommon.SecondaryReconciler, ctx context.Context, observed, generated *corev1.Secret) (modified bool, err error) {
	generatedLabels := ctrlcommon.MergeMaps(nil, observed.Labels, ctrlcommon.GetCommonLabels())
	if !maps.Equal(generatedLabels, observed.Labels) {
		observed.Labels = generatedLabels
		modified = true
	}
	return
}

// ensureIVSet makes sure that the ENCRYPTION_IV key is set on the given Secret.
func ensureIVSet(s ctrlcommon.SecondaryReconciler, ctx context.Context, observed, generated *corev1.Secret) (modified bool, err error) {
	modified = updatesValuesWhen(not(observedKeySet[*corev1.Secret]("ENCRYPTION_IV")))(observed, generated)
	return
}

// getSecretDataSHA1Sum calculates the SHA1
func getSecretDataSHA1Sum(s *corev1.Secret) (sha string, err error) {
	var dataBytes []byte
	if s.Data == nil {
		return "", errors.New("no .data defined on Secret")
	}
	if dataBytes, err = json.Marshal(s.Data); err != nil {
		return "", err
	}
	dataSHA := sha1.Sum(dataBytes)
	return fmt.Sprintf("%x", dataSHA[:]), nil
}

func ensureChecksumAnnotation(s ctrlcommon.SecondaryReconciler, ctx context.Context, observed, generated *corev1.Secret) (modified bool, err error) {
	beforeSum := observed.Annotations[AnnotationSHA1Sum]
	afterSum, err := getSecretDataSHA1Sum(observed)
	if err != nil {
		return false, err
	}

	if observed.Annotations == nil {
		observed.Annotations = map[string]string{
			AnnotationSHA1Sum: afterSum,
		}
		return true, nil
	}

	if beforeSum != afterSum {
		observed.Annotations[AnnotationSHA1Sum] = afterSum
		return true, nil
	}
	return
}

func generateSecretObject(data map[string][]byte, labels ...map[string]string) ctrlcommon.GenerateFn[*corev1.Secret] {
	return func(s ctrlcommon.SecondaryReconciler, ctx context.Context, secret *corev1.Secret) (err error) {
		log := logf.FromContext(ctx)
		var updatedLabels map[string]string
		if len(labels) > 0 {
			updatedLabels = ctrlcommon.MergeMaps(nil, labels...)
		}
		updatedLabels = ctrlcommon.MergeMaps(updatedLabels, ctrlcommon.GetCommonLabels())
		*secret = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.GetName(),
				Namespace: s.GetNamespace(),
				Labels:    updatedLabels,
			},
			Type: corev1.SecretTypeOpaque,
			Data: data,
		}

		// Set Authentication instance as the owner and controller of the Secret
		err = controllerutil.SetControllerReference(s.GetPrimary(), secret, s.GetClient().Scheme())
		if err != nil {
			log.Info("Failed to set owner for Secret")
		}
		return
	}
}

func modifyClusterCACert() ctrlcommon.ModifyFn[*corev1.Secret] {
	return func(s ctrlcommon.SecondaryReconciler, ctx context.Context, observed, generated *corev1.Secret) (modified bool, err error) {
		if !ctrlcommon.IsControllerOf(s.GetClient().Scheme(), s.GetPrimary(), observed) {
			if err = controllerutil.SetControllerReference(s.GetPrimary(), observed, s.GetClient().Scheme()); err != nil {
				return
			}
			modified = true
		}

		if !reflect.DeepEqual(generated.Data, observed.Data) {
			observed.Data = generated.Data
			modified = true
		}

		return
	}
}
