// Assisted by watsonx Code Assistant

package oidcsecurity

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/api/oidc.security/v1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	r          ClientReconciler
	servicesNS string
	caCert     []byte
	tokenErr   error
)

func getIdentityTokenEndpointHandler(username, password, payload string) http.HandlerFunc {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		Expect(req.URL.Path).To(Equal("/idprovider/v1/auth/identitytoken"))
		Expect(req.Method).To(Equal(http.MethodPost))
		Expect(req.Header[http.CanonicalHeaderKey("content-type")]).To(Equal([]string{"application/x-www-form-urlencoded;charset=UTF-8"}))
		Expect(req.ParseForm()).To(Succeed())
		Expect(req.Form["scope"]).To(Equal([]string{"openid"}))
		Expect(req.Form["grant_type"]).To(Equal([]string{"password"}))
		Expect(req.Form["username"]).To(Equal([]string{username}))
		Expect(req.Form["password"]).To(Equal([]string{password}))
		rw.WriteHeader(http.StatusOK)
		fmt.Fprintf(rw, "%s", payload)
	})
}

var _ = Describe("OIDC Security Controller", func() {
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

	Describe("#getTokenInfoFromResponse", func() {
		It("should return correct token info", func() {
			resp := httptest.NewRecorder()
			resp.WriteHeader(http.StatusOK)
			resp.Body.Write([]byte(`{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c","token_type":"Bearer","expires_in":3600,"scope":"openid","refresh_token":"some_refresh_token","id_token":"some_id_token"}`))

			tokenInfo, err := getTokenInfoFromResponse(resp.Result())
			Expect(err).ToNot(HaveOccurred())
			Expect(string(tokenInfo.TokenType)).To(Equal("Bearer"))
			Expect(*tokenInfo).To(Equal(TokenInfo{
				AccessToken:  []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
				TokenType:    []byte("Bearer"),
				ExpiresIn:    3600,
				Scope:        []byte("openid"),
				RefreshToken: []byte("some_refresh_token"),
				IdToken:      []byte("some_id_token"),
			}))
		})

		It("should return an error for invalid JSON", func() {
			resp := httptest.NewRecorder()
			resp.WriteHeader(http.StatusOK)
			resp.Body.Write([]byte("invalid json"))

			_, tokenErr = getTokenInfoFromResponse(resp.Result())
			Expect(tokenErr).To(HaveOccurred())
		})
	})

	getTokenEndpointHandler := func(clientID, clientSecret, username, password, payload string) http.HandlerFunc {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			Expect(req.URL.Path).To(Equal("/idprovider/v1/auth/token"))
			Expect(req.Method).To(Equal(http.MethodPost))
			Expect(req.Header[http.CanonicalHeaderKey("content-type")]).To(Equal([]string{"application/x-www-form-urlencoded;charset=UTF-8"}))
			Expect(req.ParseForm()).To(Succeed())
			Expect(req.Form["scope"]).To(Equal([]string{"openid"}))
			Expect(req.Form["grant_type"]).To(Equal([]string{"cpclient_credentials"}))
			Expect(req.Form["client_id"]).To(Equal([]string{clientID}))
			Expect(req.Form["client_secret"]).To(Equal([]string{clientSecret}))
			reqUsername, reqPassword, ok := req.BasicAuth()
			Expect(reqUsername).To(Equal(username))
			Expect(reqPassword).To(Equal(password))
			Expect(ok).To(BeTrue())
			rw.WriteHeader(http.StatusOK)
			fmt.Fprintf(rw, "%s", payload)
		})
	}

	Describe("#getAuthnTokens", func() {
		It("should return tokens for grant_type=cpclient_credentials", func() {
			payload := `{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c","token_type":"Bearer","expires_in":3600,"scope":"openid","refresh_token":"some_refresh_token","id_token":"some_id_token"}`
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcUsername := "oauthadmin"
			oidcPassword := "oauthpass"
			server := httptest.NewServer(getTokenEndpointHandler(clientID, clientSecret, oidcUsername, oidcPassword, payload))
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
				WithObjects(clientSecretObj, zenclient, cm, platformAuthIDPSecret, platformOIDCSecret, csCACertSecret)
			cl := cb.Build()

			r := &ClientReconciler{
				Client: &common.FallbackClient{
					Client: cl,
					Reader: cl,
				},
				RunMode: common.LocalRunMode,
			}
			ctx = context.Background()

			tokenInfo, tokenErr := r.getAuthnTokens(ctx, zenclient, servicesNS, server.Client())
			Expect(tokenErr).ToNot(HaveOccurred())
			Expect(*tokenInfo).To(Equal(TokenInfo{
				AccessToken:  []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
				TokenType:    []byte("Bearer"),
				ExpiresIn:    3600,
				Scope:        []byte("openid"),
				RefreshToken: []byte("some_refresh_token"),
				IdToken:      []byte("some_id_token"),
			}))
		})

		It("should return tokens for grant_type=password", func() {
			payload := `{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c","token_type":"Bearer","expires_in":3600,"scope":"openid","refresh_token":"some_refresh_token","id_token":"some_id_token"}`
			clientID := "uniqueclientid"
			clientSecret := "uniqueclientsecret"
			defaultUsername := "cpadmin"
			defaultPassword := "testpassword1234"
			oidcPassword := "oauthpass"
			server := httptest.NewServer(getIdentityTokenEndpointHandler(defaultUsername, defaultPassword, payload))
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
					Secret:   clientSecretObj.Name,
					ClientId: string(clientSecretObj.Data["CLIENT_ID"]),
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(clientSecretObj, zenclient, cm, platformAuthIDPSecret, platformOIDCSecret, csCACertSecret)
			cl := cb.Build()

			r := &ClientReconciler{
				Client: &common.FallbackClient{
					Client: cl,
					Reader: cl,
				},
				RunMode: common.LocalRunMode,
			}
			ctx = context.Background()

			tokenInfo, tokenErr := r.getAuthnTokens(ctx, zenclient, servicesNS, server.Client())
			Expect(tokenErr).ToNot(HaveOccurred())
			Expect(*tokenInfo).To(Equal(TokenInfo{
				AccessToken:  []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
				TokenType:    []byte("Bearer"),
				ExpiresIn:    3600,
				Scope:        []byte("openid"),
				RefreshToken: []byte("some_refresh_token"),
				IdToken:      []byte("some_id_token"),
			}))
		})

		It("should return an error for non cpclient_credentials", func() {
			secret := &corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-client-secret",
					Namespace: servicesNS,
				},
				TypeMeta: v1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				Data: map[string][]byte{
					"CLIENT_ID":     []byte("uniqueclientid"),
					"CLIENT_SECRET": []byte("uniqueclientsecret"),
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
					"BASE_OIDC_URL":         "https://platform-auth-service:9443/oidc/endpoint/OP",
					"IDENTITY_MGMT_URL":     "https://platform-identity-management:4500",
					"IDENTITY_PROVIDER_URL": "https://platform-identity-provider:4300",
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
					Secret:   secret.Name,
					ClientId: string(secret.Data["CLIENT_ID"]),
				},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(oidcsecurityv1.AddToScheme(scheme)).To(Succeed())
			cb := *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(secret, zenclient, cm)
			cl := cb.Build()

			r := &ClientReconciler{
				Client: &common.FallbackClient{
					Client: cl,
					Reader: cl,
				},
				RunMode: common.LocalRunMode,
			}
			ctx = context.Background()
			httpClient, err := createHTTPClient(caCert)
			Expect(err).ToNot(HaveOccurred())
			_, tokenErr = r.getAuthnTokens(ctx, &oidcsecurityv1.Client{}, servicesNS, httpClient)
			Expect(tokenErr).To(HaveOccurred())
		})
	})

	Describe("#createHTTPClient", func() {
		It("should create a valid HTTP client", func() {
			client, err := createHTTPClient(caCert)
			Expect(err).ToNot(HaveOccurred())
			Expect(client.Timeout).To(Equal(10 * time.Second))
		})
	})
})
