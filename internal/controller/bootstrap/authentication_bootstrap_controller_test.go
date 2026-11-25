/*
Copyright 2026 IBM Corporation

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

package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func createValidCertAndKey() ([]byte, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	Expect(err).NotTo(HaveOccurred())

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPem, keyPem
}

var _ = Describe("BootstrapReconciler Ingress Customization", func() {
	var (
		ctx    context.Context
		scheme *runtime.Scheme
		ns     string
	)

	BeforeEach(func() {
		ctx = context.Background()
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(routev1.AddToScheme(scheme)).To(Succeed())
		Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
		ns = "test-ns"
	})

	Context("setIngressSecretIfCustomized", func() {
		It("should preserve existing Spec.Config.Ingress.Secret and skip custom-tls-secret validation even if custom-tls-secret is invalid", func() {
			// Bug #70362 Scenario 2: Authentication CR already has custom ingress secret,
			// but a stale/invalid custom-tls-secret exists in the namespace.
			invalidSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "custom-tls-secret",
					Namespace: ns,
				},
				Data: map[string][]byte{
					"tls.crt": []byte("invalid-cert-data"),
					"tls.key": []byte("invalid-key-data"),
				},
			}

			client := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(invalidSecret).
				Build()

			r := &BootstrapReconciler{
				Client: client,
			}

			authCR := &operatorv1alpha1.Authentication{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "example-authentication",
					Namespace: ns,
				},
				Spec: operatorv1alpha1.AuthenticationSpec{
					Config: operatorv1alpha1.ConfigSpec{
						Ingress: &operatorv1alpha1.IngressConfig{
							Secret: ptr.To("cpd-custom-tls-secret"),
						},
					},
				},
			}

			err := r.setIngressSecretIfCustomized(ctx, authCR)
			Expect(err).NotTo(HaveOccurred())
			Expect(authCR.Spec.Config.Ingress.Secret).NotTo(BeNil())
			Expect(*authCR.Spec.Config.Ingress.Secret).To(Equal("cpd-custom-tls-secret"))
		})

		It("should preserve existing Spec.Config.Ingress.Secret and not create custom-tls-secret when Route has custom TLS", func() {
			// Bug #70362 Scenario 1: Authentication CR already has custom ingress secret,
			// custom-tls-secret does not exist, and cpd route has custom TLS.
			certPem, keyPem := createValidCertAndKey()
			cpdRoute := &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cpd",
					Namespace: ns,
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Certificate:   string(certPem),
						Key:           string(keyPem),
						CACertificate: string(certPem),
					},
				},
			}

			client := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(cpdRoute).
				Build()

			r := &BootstrapReconciler{
				Client: client,
			}

			authCR := &operatorv1alpha1.Authentication{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "example-authentication",
					Namespace: ns,
				},
				Spec: operatorv1alpha1.AuthenticationSpec{
					Config: operatorv1alpha1.ConfigSpec{
						ZenFrontDoor: true,
						Ingress: &operatorv1alpha1.IngressConfig{
							Secret: ptr.To("my-custom-tls-secret"),
						},
					},
				},
			}

			err := r.setIngressSecretIfCustomized(ctx, authCR)
			Expect(err).NotTo(HaveOccurred())
			Expect(authCR.Spec.Config.Ingress.Secret).NotTo(BeNil())
			Expect(*authCR.Spec.Config.Ingress.Secret).To(Equal("my-custom-tls-secret"))

			// Verify custom-tls-secret was NOT created
			secret := &corev1.Secret{} // pragma: allowlist secret
			getErr := client.Get(ctx, types.NamespacedName{Name: "custom-tls-secret", Namespace: ns}, secret)
			Expect(getErr).To(HaveOccurred())
		})

		It("should bootstrap custom-tls-secret when Ingress.Secret is not set and a valid custom-tls-secret exists", func() {
			certPem, keyPem := createValidCertAndKey()
			validSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "custom-tls-secret",
					Namespace: ns,
				},
				Data: map[string][]byte{
					"tls.crt": certPem,
					"tls.key": keyPem,
					"ca.crt":  certPem,
				},
			}

			client := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(validSecret).
				Build()

			r := &BootstrapReconciler{
				Client: client,
			}

			authCR := &operatorv1alpha1.Authentication{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "example-authentication",
					Namespace: ns,
				},
				Spec: operatorv1alpha1.AuthenticationSpec{
					Config: operatorv1alpha1.ConfigSpec{},
				},
			}

			err := r.setIngressSecretIfCustomized(ctx, authCR)
			Expect(err).NotTo(HaveOccurred())
			Expect(authCR.Spec.Config.Ingress).NotTo(BeNil())
			Expect(authCR.Spec.Config.Ingress.Secret).NotTo(BeNil())
			Expect(*authCR.Spec.Config.Ingress.Secret).To(Equal("custom-tls-secret"))
		})

		It("should return validation error when Ingress.Secret is not set and an invalid custom-tls-secret exists", func() {
			invalidSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "custom-tls-secret",
					Namespace: ns,
				},
				Data: map[string][]byte{
					"tls.crt": []byte("invalid-cert-data"),
					"tls.key": []byte("invalid-key-data"),
				},
			}

			client := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(invalidSecret).
				Build()

			r := &BootstrapReconciler{
				Client: client,
			}

			authCR := &operatorv1alpha1.Authentication{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "example-authentication",
					Namespace: ns,
				},
				Spec: operatorv1alpha1.AuthenticationSpec{
					Config: operatorv1alpha1.ConfigSpec{},
				},
			}

			err := r.setIngressSecretIfCustomized(ctx, authCR)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("setIngressHostnameIfCustomized", func() {
		It("should preserve existing Spec.Config.Ingress.Hostname when already set", func() {
			clusterInfoCM := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      common.IBMCloudClusterInfoCMName,
					Namespace: ns,
				},
				Data: map[string]string{
					"cluster_address": "other.hostname.com",
				},
			}

			client := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(clusterInfoCM).
				Build()

			r := &BootstrapReconciler{
				Client: client,
			}

			authCR := &operatorv1alpha1.Authentication{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "example-authentication",
					Namespace: ns,
				},
				Spec: operatorv1alpha1.AuthenticationSpec{
					Config: operatorv1alpha1.ConfigSpec{
						Ingress: &operatorv1alpha1.IngressConfig{
							Hostname: ptr.To("existing.hostname.com"),
						},
					},
				},
			}

			err := r.setIngressHostnameIfCustomized(ctx, authCR)
			Expect(err).NotTo(HaveOccurred())
			Expect(authCR.Spec.Config.Ingress.Hostname).NotTo(BeNil())
			Expect(*authCR.Spec.Config.Ingress.Hostname).To(Equal("existing.hostname.com"))
		})
	})

	Context("bootstrapIngressCustomization", func() {
		It("should succeed and preserve Authentication CR ingress settings without error when CR has custom ingress and invalid custom-tls-secret exists", func() {
			invalidSecret := &corev1.Secret{ // pragma: allowlist secret
				ObjectMeta: metav1.ObjectMeta{
					Name:      "custom-tls-secret",
					Namespace: ns,
				},
				Data: map[string][]byte{
					"tls.crt": []byte("invalid-cert-data"),
					"tls.key": []byte("invalid-key-data"),
				},
			}

			client := fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(invalidSecret).
				Build()

			r := &BootstrapReconciler{
				Client: client,
			}

			authCR := &operatorv1alpha1.Authentication{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "example-authentication",
					Namespace: ns,
				},
				Spec: operatorv1alpha1.AuthenticationSpec{
					Config: operatorv1alpha1.ConfigSpec{
						Ingress: &operatorv1alpha1.IngressConfig{
							Hostname: ptr.To("custom.cpd.domain"),
							Secret:   ptr.To("cpd-custom-tls-secret"),
						},
					},
				},
			}

			err := r.bootstrapIngressCustomization(ctx, authCR)
			Expect(err).NotTo(HaveOccurred())
			Expect(*authCR.Spec.Config.Ingress.Hostname).To(Equal("custom.cpd.domain"))
			Expect(*authCR.Spec.Config.Ingress.Secret).To(Equal("cpd-custom-tls-secret"))
		})
	})
})
