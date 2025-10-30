// Assisted by watsonx Code Assistant

// configmap_test.go
package operator

import (
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Configmap Reconciliation", func() {
	Describe("registrationJsonConfigMap", func() {
		It("generates a valid JSON file for client registration", func() {
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme)
			cl := cb.Build()
			r := &AuthenticationReconciler{
				Client: cl,
				Scheme: cl.Scheme(),
			}
			authCR := &operatorv1alpha1.Authentication{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "example-authentication",
					Namespace: "test-ns",
				},
			}
			wlpClientID := []byte("1234567890123456")
			wlpClientSecret := []byte("deadbeef")
			icpConsoleURL := "example.com"
			cm := registrationJsonConfigMap(authCR, wlpClientID, wlpClientSecret, icpConsoleURL, r.Scheme)
			Expect(cm.Name).To(Equal("registration-json"))
			Expect(cm.Namespace).To(Equal(authCR.Namespace))
			Expect(cm.Data["platform-oidc-registration.json"]).To(MatchJSON(`{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "1234567890123456",
  "client_secret": "deadbeef",
  "scope": "openid profile email",
  "grant_types": [
    "authorization_code",
    "client_credentials",
    "password",
    "implicit",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:jwt-bearer"
  ],
  "response_types": [
    "code",
    "token",
    "id_token token"
  ],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["https://example.com/console/logout"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": ["Administrator"],
  "trusted_uri_prefixes": ["https://example.com"],
  "redirect_uris": ["https://example.com/auth/liberty/callback", "https://127.0.0.1:443/idauth/oidc/endpoint/OP"]
}`))
		})
	})
})
