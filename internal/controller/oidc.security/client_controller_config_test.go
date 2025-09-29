// Assisted by watsonx Code Assistant

package oidcsecurity

import (
	"context"
	"errors"
	"fmt"

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/api/oidc.security/v1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	"github.com/IBM/ibm-iam-operator/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("OIDC Security Controller", func() {
	var (
		ctx context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
	})
	generatePlatformAuthIDPCM := func(ns string, cp2 bool) *corev1.ConfigMap {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "platform-auth-idp",
				Namespace: ns,
			},
			Data: map[string]string{
				"BASE_OIDC_URL":         "https://platform-auth-service:9443/oidc/endpoint/OP",
				"IDENTITY_MGMT_URL":     "https://platform-identity-management:4500",
				"IDENTITY_PROVIDER_URL": "https://platform-identity-provider:4300",
			},
		}
		if cp2 {
			cm.Data["BASE_OIDC_URL"] = "https://127.0.0.1:9443/oidc/endpoint/OP"
			cm.Data["IDENTITY_MGMT_URL"] = "https://127.0.0.1:4500"
			cm.Data["IDENTITY_PROVIDER_URL"] = "https://127.0.0.1:4300"
		}
		return cm
	}

	generatePlatformAuthIDPCredentialsSecret := func(ns string) *corev1.Secret {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "platform-auth-idp-credentials",
				Namespace: ns,
			},
			Data: map[string][]byte{
				"admin_username": []byte("cpadmin"),
				"admin_password": []byte("testpassword1234"),
			},
		}
		return s
	}

	generatePlatformOIDCCredentialsSecret := func(ns string) *corev1.Secret {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "platform-oidc-credentials",
				Namespace: ns,
			},
			Data: map[string][]byte{
				"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte("oauthpass"),
			},
		}
		return s
	}
	generateCSCACertSecret := func(ns string) *corev1.Secret {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cs-ca-certificate-secret",
				Namespace: ns,
			},
			Data: map[string][]byte{
				corev1.TLSCertKey: []byte("some bytes"),
			},
		}
		return s
	}
	getClient := func(addToSchemes []func(*runtime.Scheme) error, objs []client.Object) (cl client.Client) {
		scheme := runtime.NewScheme()
		for _, addToScheme := range addToSchemes {
			Expect(addToScheme(scheme)).To(Succeed())
		}
		cb := *fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(objs...)
		return cb.Build()
	}
	Describe("#GetDefaultAdminCredentials", func() {
		It("should return correct username and password", func() {
			namespace := utils.GetRandomizedNamespace("test")
			cl := getClient([]func(*runtime.Scheme) error{
				corev1.AddToScheme, oidcsecurityv1.AddToScheme, batchv1.AddToScheme,
			}, []client.Object{generatePlatformAuthIDPCredentialsSecret(namespace)})
			username, password, err := GetDefaultAdminCredentials(cl, ctx, namespace)
			Expect(err).ToNot(HaveOccurred())
			Expect(username).To(Equal([]byte("cpadmin")))
			Expect(password).To(Equal([]byte("testpassword1234")))
		})

		It("should return an error when key not found", func() {

		})
	})

	Describe("#GetOAuthAdminCredentials", func() {
		It("should return correct username and password", func() {
			namespace := utils.GetRandomizedNamespace("test")
			cl := getClient([]func(*runtime.Scheme) error{
				corev1.AddToScheme, oidcsecurityv1.AddToScheme, batchv1.AddToScheme,
			}, []client.Object{generatePlatformOIDCCredentialsSecret(namespace)})
			username, password, err := GetOAuthAdminCredentials(cl, ctx, namespace)
			Expect(err).ToNot(HaveOccurred())
			Expect(username).To(Equal([]byte("oauthadmin")))
			Expect(password).To(Equal([]byte("oauthpass")))
		})

		It("should return an error when key not found", func() {
		})
	})

	Describe("#GetCommonServiceCATLSKey", func() {
		It("should return the correct key", func() {
			namespace := utils.GetRandomizedNamespace("test")
			cl := getClient([]func(*runtime.Scheme) error{
				corev1.AddToScheme, oidcsecurityv1.AddToScheme, batchv1.AddToScheme,
			}, []client.Object{generateCSCACertSecret(namespace)})
			tlskey, err := GetCommonServiceCATLSKey(cl, ctx, namespace)
			Expect(err).ToNot(HaveOccurred())
			Expect(tlskey).To(Equal([]byte("some bytes")))
		})

		It("should return an error when key not found", func() {
			namespace := utils.GetRandomizedNamespace("test")
			cl := getClient([]func(*runtime.Scheme) error{
				corev1.AddToScheme, oidcsecurityv1.AddToScheme, batchv1.AddToScheme,
			}, []client.Object{})
			tlskey, err := GetCommonServiceCATLSKey(cl, ctx, namespace)
			Expect(err).To(HaveOccurred())
			Expect(tlskey).To(BeEmpty())
		})
	})

	Describe("#getServiceURL", func() {
		It("should return the correct URL", func() {
			namespace := utils.GetRandomizedNamespace("test")
			cl := getClient([]func(*runtime.Scheme) error{
				corev1.AddToScheme, oidcsecurityv1.AddToScheme, batchv1.AddToScheme,
			}, []client.Object{generatePlatformAuthIDPCM(namespace, false)})
			r.Client = cl
			r.RunMode = common.ClusterRunMode
			for _, key := range []ServiceURLKey{AuthServiceURLKey, IdentityManagementURLKey, IdentityProviderURLKey} {
				url, err := r.getServiceURL(ctx, namespace, key)
				Expect(err).ToNot(HaveOccurred())
				switch key {
				case AuthServiceURLKey:
					Expect(url).To(Equal(fmt.Sprintf("https://platform-auth-service.%s.svc:9443/oidc/endpoint/OP", namespace)))
				case IdentityManagementURLKey:
					Expect(url).To(Equal(fmt.Sprintf("https://platform-identity-management.%s.svc:4500", namespace)))
				case IdentityProviderURLKey:
					Expect(url).To(Equal(fmt.Sprintf("https://platform-identity-provider.%s.svc:4300", namespace)))
				}
			}
		})

		It("should return an error when URL format is incorrect", func() {
			namespace := utils.GetRandomizedNamespace("test")
			cl := getClient([]func(*runtime.Scheme) error{
				corev1.AddToScheme, oidcsecurityv1.AddToScheme, batchv1.AddToScheme,
			}, []client.Object{generatePlatformAuthIDPCM(namespace, true)})
			r.Client = cl
			r.RunMode = common.ClusterRunMode
			for _, key := range []ServiceURLKey{AuthServiceURLKey, IdentityManagementURLKey, IdentityProviderURLKey} {
				url, err := r.getServiceURL(ctx, namespace, key)
				Expect(url).To(BeEmpty())
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, &CP2ServiceURLFormatError{})).To(BeTrue())
			}
		})
	})
})
