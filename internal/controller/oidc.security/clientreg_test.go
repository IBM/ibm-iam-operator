// Assisted by watsonx Code Assistant

package oidcsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/api/oidc.security/v1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type MockHTTPClientReconciler struct {
	ClientReconciler
	getHTTPClientFunc func([]byte) (*http.Client, error)
}

func (m *MockHTTPClientReconciler) GetHTTPClient(caCert []byte) (client *http.Client, err error) {
	return m.getHTTPClientFunc(caCert)
}

var _ = Describe("Client registration", func() {
	BeforeEach(func() {
		servicesNS = "test-namespace"
		caCert = []byte(`-----BEGIN CERTIFICATE-----                                     
MIIDBTCCAe2gAwIBAgIRALjjIZKywraUok2HqxUljgMwDQYJKoZIhvcNAQELBQAw
HDEaMBgGA1UEAxMRY3MtY2EtY2VydGlmaWNhdGUwHhcNMjUwOTI0MTYyMzUyWhcN
MjcwOTI0MTYyMzUyWjAcMRowGAYDVQQDExFjcy1jYS1jZXJ0aWZpY2F0ZTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM6RYdsTZSEncNekvSq+W9RUkfj7
h5vOx8tzmExcjIN27WhPPh9X0Ag1dar05uIXfGnnkbGJKwn0a9VkosW4/Apyhvwm
dt1O4+IeFEhX4jNTiuvzStyyNPDJfvPF+fhie4GJ6frqdvwA45Pov4D9WEIvGVhL
YCGjAIlgfnCslHsHBVkYQ2OeJj1TE0lwF+ymVHO4rdlFiANvK9XCOm4XMi25HWFf
W2VQKUJiUx5G9aiR/p5En1Y89QZanMSMZkEqUGOZZn4ujCDdAk3bGvjtaPquXLeE
q5KuyMIXODumPi8npgmycI5GI7Jd7f8RDpqw98fTh37goULCXNmgXuU/Br0CAwEA
AaNCMEAwDgYDVR0PAQH/BAQDAgKkMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
FP6S/nbvkQc6vA0Z4xHooKw5tLvuMA0GCSqGSIb3DQEBCwUAA4IBAQAk1XIR3hx1
fwnNfT9P3nWB7qhpNffoahcFpXWk6Z8/EsUseqXtKWq6q75zqGhXd82ILJQQz4Si
jYx/oAvCKUknCRfcBx8YzKTlyGUZAf8COAu/HPHCbkDf5bVCrVg3KbEYiSUYo16d
pDVaihBVC3pOLFNm+hBflX1GW/sdsIoN+cyDTbBu62OV0lqR0BmER83AfiXMFdo+
znkWbVy4ymswjWupNQPrL4EXHQp3V3j5WepA6SO8POs2U9SZhkvXMNc/sOyS2E3r
ykrAOx1C9LZujHhxXocukksq62XCzy9G+R5Do8xVjcXrbhyXdhIraUc78206WIBj
kgg1AGBe2QS+                                                    
-----END CERTIFICATE-----`)
	})

	validateRequest := func(req *http.Request, username, password string) {
		Expect(req.URL.Path).To(HavePrefix("/idprovider/v1/auth/registration"))
		Expect(req.Header[http.CanonicalHeaderKey("content-type")]).To(Equal([]string{"application/json"}))
		reqUsername, reqPassword, ok := req.BasicAuth()
		Expect(reqUsername).To(Equal(username))
		Expect(reqPassword).To(Equal(password))
		Expect(ok).To(BeTrue())
	}

	validatePayload := func(req *http.Request, client *oidcsecurityv1.Client, clientSecret *corev1.Secret) {
		defer req.Body.Close()
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(req.Body)
		Expect(err).ToNot(HaveOccurred())
		bodyBytes := buf.Bytes()
		Expect(bodyBytes).ToNot(BeEmpty())
		var body map[string]any
		Expect(json.Unmarshal(bodyBytes, &body)).To(Succeed())
		Expect(body["client_id"]).To(Equal(client.Spec.ClientId))
		Expect(body["client_secret"]).To(Equal(string(clientSecret.Data["CLIENT_SECRET"])))
		Expect(body["post_logout_redirect_uris"]).To(ContainElements(client.Spec.OidcLibertyClient.LogoutUris))
		Expect(body["trusted_uri_prefixes"]).To(ContainElements(client.Spec.OidcLibertyClient.TrustedUris))
		Expect(body["redirect_uris"]).To(ContainElements(client.Spec.OidcLibertyClient.RedirectUris))
	}

	getClientRegistrationHandler := func(clientID, username, password string, status int) http.HandlerFunc {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			validateRequest(req, username, password)
			Expect(req.URL.Path).To(HavePrefix("/idprovider/v1/auth/registration"))
			splitPath := strings.Split(req.URL.Path, "/")
			Expect(splitPath[len(splitPath)-1]).To(Equal(clientID))
			Expect(req.Method).To(Equal(http.MethodGet))
			rw.WriteHeader(status)
			fmt.Fprintf(rw, "%s", "")
		})
	}

	createClientRegistrationHandler := func(username, password string, client *oidcsecurityv1.Client, clientSecret *corev1.Secret, status int) http.HandlerFunc {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			validateRequest(req, username, password)
			Expect(req.Method).To(Equal(http.MethodPost))
			validatePayload(req, client, clientSecret)
			rw.WriteHeader(status)
			fmt.Fprintf(rw, "%s", "")
		})
	}

	updateClientRegistrationHandler := func(username, password string, client *oidcsecurityv1.Client, clientSecret *corev1.Secret, status int) http.HandlerFunc {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			validateRequest(req, username, password)
			Expect(req.Method).To(Equal(http.MethodPut))
			validatePayload(req, client, clientSecret)
			rw.WriteHeader(status)
			fmt.Fprintf(rw, "%s", "")
		})
	}

	deleteClientRegistrationHandler := func(clientID, username, password string, status int) http.HandlerFunc {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			validateRequest(req, username, password)
			Expect(req.URL.Path).To(HavePrefix("/idprovider/v1/auth/registration"))
			splitPath := strings.Split(req.URL.Path, "/")
			Expect(splitPath[len(splitPath)-1]).To(Equal(clientID))
			Expect(req.Method).To(Equal(http.MethodDelete))
			rw.WriteHeader(status)
			fmt.Fprintf(rw, "%s", "")
		})
	}

	Describe("#getClientRegistration", func() {
		It("succeeds when receives 200", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			server := httptest.NewServer(getClientRegistrationHandler(clientID, oidcUsername, oidcPassword, http.StatusOK))
			defer server.Close()
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			csCACertSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "cs-ca-certificate-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"tls.crt": caCert,
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret, csCACertSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.getClientRegistration(ctx, zenclient, servicesNS)
			Expect(err).ToNot(HaveOccurred())
			Expect(response.StatusCode).To(Equal(200))
		})

		It("handles non-200 response status", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			server := httptest.NewServer(getClientRegistrationHandler(clientID, oidcUsername, oidcPassword, http.StatusNotFound))
			defer server.Close()
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			csCACertSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "cs-ca-certificate-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"tls.crt": caCert,
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret, csCACertSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			_, err := r.getClientRegistration(ctx, zenclient, servicesNS)
			Expect(err).To(HaveOccurred())
			oidcErr, ok := err.(*OIDCClientRegistrationError)
			Expect(ok).To(BeTrue())
			Expect(oidcErr.response.StatusCode).To(Equal(404))
			Expect(oidcErr.ClientID()).To(Equal(clientID))
			Expect(oidcErr.Description).To(HavePrefix("did not get client successfully"))
		})

		It("handles error during call", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
					OidcLibertyClient: oidcsecurityv1.OidcLibertyClient{
						RedirectUris: []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/login/oidc/callback"},
						TrustedUris:  []string{"https://cpd-test-namespace.apps.example.ibm.com"},
						LogoutUris:   []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/doLogout"},
					},
				},
			}
			server := httptest.NewServer(getClientRegistrationHandler(clientID, oidcUsername, oidcPassword, http.StatusOK))
			defer server.Close()
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.createClientRegistration(ctx, zenclient, servicesNS)
			Expect(response).To(BeNil())
			Expect(err).To(HaveOccurred())
			oidcErr, ok := err.(*OIDCClientRegistrationError)
			Expect(ok).To(BeTrue())
			Expect(oidcErr.Description).To(Equal("secrets \"cs-ca-certificate-secret\" not found"))
			Expect(oidcErr.clientID).To(Equal(clientID))
		})
	})

	Describe("#createClientRegistration", func() {
		It("succeeds when receives 201", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			csCACertSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "cs-ca-certificate-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"tls.crt": caCert,
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
					OidcLibertyClient: oidcsecurityv1.OidcLibertyClient{
						RedirectUris: []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/login/oidc/callback"},
						TrustedUris:  []string{"https://cpd-test-namespace.apps.example.ibm.com"},
						LogoutUris:   []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/doLogout"},
					},
				},
			}
			server := httptest.NewServer(createClientRegistrationHandler(oidcUsername, oidcPassword, zenclient, clientSecretObj, http.StatusCreated))
			defer server.Close()
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret, csCACertSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.createClientRegistration(ctx, zenclient, servicesNS)
			Expect(err).ToNot(HaveOccurred())
			Expect(response.StatusCode).To(Equal(201))
		})

		It("handles non-201 status", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			csCACertSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "cs-ca-certificate-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"tls.crt": caCert,
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
					OidcLibertyClient: oidcsecurityv1.OidcLibertyClient{
						RedirectUris: []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/login/oidc/callback"},
						TrustedUris:  []string{"https://cpd-test-namespace.apps.example.ibm.com"},
						LogoutUris:   []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/doLogout"},
					},
				},
			}
			server := httptest.NewServer(createClientRegistrationHandler(oidcUsername, oidcPassword, zenclient, clientSecretObj, http.StatusOK))
			defer server.Close()
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret, csCACertSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.createClientRegistration(ctx, zenclient, servicesNS)
			Expect(response).To(BeNil())
			Expect(err).To(HaveOccurred())
			oidcErr, ok := err.(*OIDCClientRegistrationError)
			Expect(ok).To(BeTrue())
			Expect(oidcErr.Description).To(Equal("got status 200 OK"))
			Expect(oidcErr.response.StatusCode).To(Equal(200))
		})

		It("handles error during call", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
					OidcLibertyClient: oidcsecurityv1.OidcLibertyClient{
						RedirectUris: []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/login/oidc/callback"},
						TrustedUris:  []string{"https://cpd-test-namespace.apps.example.ibm.com"},
						LogoutUris:   []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/doLogout"},
					},
				},
			}
			server := httptest.NewServer(createClientRegistrationHandler(oidcUsername, oidcPassword, zenclient, clientSecretObj, http.StatusOK))
			defer server.Close()
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.createClientRegistration(ctx, zenclient, servicesNS)
			Expect(response).To(BeNil())
			Expect(err).To(HaveOccurred())
			oidcErr, ok := err.(*OIDCClientRegistrationError)
			Expect(ok).To(BeTrue())
			Expect(oidcErr.Description).To(Equal("secrets \"cs-ca-certificate-secret\" not found"))
			Expect(oidcErr.clientID).To(Equal(clientID))
		})
	})

	Describe("#updateClientRegistration", func() {
		It("succeeds when receives 200", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			csCACertSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "cs-ca-certificate-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"tls.crt": caCert,
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
					OidcLibertyClient: oidcsecurityv1.OidcLibertyClient{
						RedirectUris: []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/login/oidc/callback"},
						TrustedUris:  []string{"https://cpd-test-namespace.apps.example.ibm.com"},
						LogoutUris:   []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/doLogout"},
					},
				},
			}
			server := httptest.NewServer(updateClientRegistrationHandler(oidcUsername, oidcPassword, zenclient, clientSecretObj, http.StatusOK))
			defer server.Close()
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret, csCACertSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.updateClientRegistration(ctx, zenclient, servicesNS)
			Expect(err).ToNot(HaveOccurred())
			Expect(response.StatusCode).To(Equal(200))
		})

		It("handles non-200 status", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			csCACertSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "cs-ca-certificate-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"tls.crt": caCert,
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
					OidcLibertyClient: oidcsecurityv1.OidcLibertyClient{
						RedirectUris: []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/login/oidc/callback"},
						TrustedUris:  []string{"https://cpd-test-namespace.apps.example.ibm.com"},
						LogoutUris:   []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/doLogout"},
					},
				},
			}
			server := httptest.NewServer(updateClientRegistrationHandler(oidcUsername, oidcPassword, zenclient, clientSecretObj, http.StatusAccepted))
			defer server.Close()
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret, csCACertSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.updateClientRegistration(ctx, zenclient, servicesNS)
			Expect(response).To(BeNil())
			Expect(err).To(HaveOccurred())
			oidcErr, ok := err.(*OIDCClientRegistrationError)
			Expect(ok).To(BeTrue())
			Expect(oidcErr.Description).To(Equal("got status 202 Accepted"))
			Expect(oidcErr.response.StatusCode).To(Equal(202))
		})

		It("handles error during call", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
					OidcLibertyClient: oidcsecurityv1.OidcLibertyClient{
						RedirectUris: []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/login/oidc/callback"},
						TrustedUris:  []string{"https://cpd-test-namespace.apps.example.ibm.com"},
						LogoutUris:   []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/doLogout"},
					},
				},
			}
			server := httptest.NewServer(updateClientRegistrationHandler(oidcUsername, oidcPassword, zenclient, clientSecretObj, http.StatusOK))
			defer server.Close()
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.updateClientRegistration(ctx, zenclient, servicesNS)
			Expect(response).To(BeNil())
			Expect(err).To(HaveOccurred())
			oidcErr, ok := err.(*OIDCClientRegistrationError)
			Expect(ok).To(BeTrue())
			Expect(oidcErr.Description).To(Equal("secrets \"cs-ca-certificate-secret\" not found"))
			Expect(oidcErr.clientID).To(Equal(clientID))
		})
	})

	Describe("#deleteClientRegistration", func() {
		It("handles Client missing client ID", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			csCACertSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "cs-ca-certificate-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"tls.crt": caCert,
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      "",
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
					OidcLibertyClient: oidcsecurityv1.OidcLibertyClient{
						RedirectUris: []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/login/oidc/callback"},
						TrustedUris:  []string{"https://cpd-test-namespace.apps.example.ibm.com"},
						LogoutUris:   []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/doLogout"},
					},
				},
			}
			server := httptest.NewServer(deleteClientRegistrationHandler(zenclient.Spec.ClientId, oidcUsername, oidcPassword, http.StatusNoContent))
			defer server.Close()
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret, csCACertSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.deleteClientRegistration(ctx, zenclient, servicesNS)
			Expect(err).To(BeNil())
			Expect(response).To(BeNil())
		})

		It("succeeds when it receives 204", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			csCACertSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "cs-ca-certificate-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"tls.crt": caCert,
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
					OidcLibertyClient: oidcsecurityv1.OidcLibertyClient{
						RedirectUris: []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/login/oidc/callback"},
						TrustedUris:  []string{"https://cpd-test-namespace.apps.example.ibm.com"},
						LogoutUris:   []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/doLogout"},
					},
				},
			}
			server := httptest.NewServer(deleteClientRegistrationHandler(zenclient.Spec.ClientId, oidcUsername, oidcPassword, http.StatusNoContent))
			defer server.Close()
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret, csCACertSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.deleteClientRegistration(ctx, zenclient, servicesNS)
			Expect(err).ToNot(HaveOccurred())
			Expect(response.StatusCode).To(Equal(204))
		})

		It("succeeds when it receives 404", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			csCACertSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "cs-ca-certificate-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"tls.crt": caCert,
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
					OidcLibertyClient: oidcsecurityv1.OidcLibertyClient{
						RedirectUris: []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/login/oidc/callback"},
						TrustedUris:  []string{"https://cpd-test-namespace.apps.example.ibm.com"},
						LogoutUris:   []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/doLogout"},
					},
				},
			}
			server := httptest.NewServer(deleteClientRegistrationHandler(zenclient.Spec.ClientId, oidcUsername, oidcPassword, http.StatusNotFound))
			defer server.Close()
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret, csCACertSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.deleteClientRegistration(ctx, zenclient, servicesNS)
			Expect(err).ToNot(HaveOccurred())
			Expect(response.StatusCode).To(Equal(404))
		})

		It("handles non-204/non-404 status", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			csCACertSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "cs-ca-certificate-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"tls.crt": caCert,
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
					OidcLibertyClient: oidcsecurityv1.OidcLibertyClient{
						RedirectUris: []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/login/oidc/callback"},
						TrustedUris:  []string{"https://cpd-test-namespace.apps.example.ibm.com"},
						LogoutUris:   []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/doLogout"},
					},
				},
			}
			server := httptest.NewServer(deleteClientRegistrationHandler(zenclient.Spec.ClientId, oidcUsername, oidcPassword, http.StatusForbidden))
			defer server.Close()
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret, csCACertSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.deleteClientRegistration(ctx, zenclient, servicesNS)
			Expect(response).To(BeNil())
			Expect(err).To(HaveOccurred())
			oidcErr, ok := err.(*OIDCClientRegistrationError)
			Expect(ok).To(BeTrue())
			Expect(oidcErr.Description).To(Equal("got status 403 Forbidden"))
			Expect(oidcErr.response.StatusCode).To(Equal(403))
		})

		It("handles error during call", func() {
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			clientSecretObj := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte(clientID),
					"CLIENT_SECRET": []byte(clientSecret),
				},
			}
			platformAuthIDPSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"admin_username": []byte(defaultUsername),
					"admin_password": []byte(defaultPassword),
				},
			}
			platformOIDCSecret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(oidcPassword),
				},
			}
			zenclient := &oidcsecurityv1.Client{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Client",
					APIVersion: oidcsecurityv1.GroupVersion.Group + "/" + oidcsecurityv1.GroupVersion.Version,
				},
				Spec: oidcsecurityv1.ClientSpec{
					Secret:        clientSecretObj.Name,
					ClientId:      string(clientSecretObj.Data["CLIENT_ID"]),
					ZenInstanceId: "some-id",
					ZenAuditUrl:   "https://example.ibm.com",
					Roles:         []string{"role1"},
					OidcLibertyClient: oidcsecurityv1.OidcLibertyClient{
						RedirectUris: []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/login/oidc/callback"},
						TrustedUris:  []string{"https://cpd-test-namespace.apps.example.ibm.com"},
						LogoutUris:   []string{"https://cpd-test-namespace.apps.example.ibm.com/auth/doLogout"},
					},
				},
			}
			server := httptest.NewServer(deleteClientRegistrationHandler(zenclient.Spec.ClientId, oidcUsername, oidcPassword, http.StatusOK))
			defer server.Close()
			cm := &corev1.ConfigMap{
				ObjectMeta: v1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"BASE_OIDC_URL":         server.URL + "/OP",
					"IDENTITY_MGMT_URL":     server.URL + "/idmgmt",
					"IDENTITY_PROVIDER_URL": server.URL + "/idprovider",
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(zenclient, clientSecretObj, cm, platformAuthIDPSecret, platformOIDCSecret)
			cl := cb.Build()

			r := &MockHTTPClientReconciler{
				ClientReconciler: ClientReconciler{
					Client: &common.FallbackClient{
						Client: cl,
						Reader: cl,
					},
					RunMode: common.LocalRunMode,
				},
				getHTTPClientFunc: func(caCert []byte) (*http.Client, error) {
					return server.Client(), nil
				},
			}
			ctx = context.Background()
			response, err := r.deleteClientRegistration(ctx, zenclient, servicesNS)
			Expect(response).To(BeNil())
			Expect(err).To(HaveOccurred())
			oidcErr, ok := err.(*OIDCClientRegistrationError)
			Expect(ok).To(BeTrue())
			Expect(oidcErr.Description).To(Equal("secrets \"cs-ca-certificate-secret\" not found"))
			Expect(oidcErr.clientID).To(Equal(clientID))
		})
	})
})
