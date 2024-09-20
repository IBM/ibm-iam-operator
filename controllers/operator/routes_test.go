package operator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	zenv1 "github.com/IBM/ibm-iam-operator/apis/zen.cpd.ibm.com/v1"
	testutil "github.com/IBM/ibm-iam-operator/testing"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/discovery"
	restclient "k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

var _ = Describe("Route handling", func() {
	var r *AuthenticationReconciler
	var clusterInfoConfigMap *corev1.ConfigMap
	var platformOIDCCredentialsSecret *corev1.Secret
	var platformAuthSecretSecret *corev1.Secret
	var platformIdentityManagementSecret *corev1.Secret
	var identityProviderSecretSecret *corev1.Secret
	var authCR *operatorv1alpha1.Authentication
	var cb fakeclient.ClientBuilder
	var cl client.WithWatch
	var scheme *runtime.Scheme
	var ctx context.Context
	var frontdoor *zenv1.ZenExtension

	Describe("getClusterInfoConfigMap", func() {
		var cm *corev1.ConfigMap
		BeforeEach(func() {
			authCR = &operatorv1alpha1.Authentication{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "operator.ibm.com/v1alpha1",
					Kind:       "Authentication",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "example-authentication",
					Namespace:       "data-ns",
					ResourceVersion: trackerAddResourceVersion,
				},
			}
			clusterInfoConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"cluster_address":      "cp-console-example.apps.cluster.ibm.com",
					"cluster_address_auth": "cp-console-example.apps.cluster.ibm.com",
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(routev1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(clusterInfoConfigMap, authCR)
			cl = cb.Build()
			dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			Expect(err).NotTo(HaveOccurred())

			r = &AuthenticationReconciler{
				Client:          cl,
				DiscoveryClient: *dc,
			}
			ctx = context.Background()
			cm = &corev1.ConfigMap{}
		})
		It("will produce a function that signals to continue reconciling when the ConfigMap is found", func() {
			fn := r.getClusterInfoConfigMap(authCR, cm)
			result, err := fn(ctx)
			testutil.ConfirmThatItContinuesReconciling(result, err)
		})
		It("will produce a function that signals to requeue with a delay when the ConfigMap is not found", func() {
			err := r.Delete(ctx, clusterInfoConfigMap)
			Expect(err).ToNot(HaveOccurred())
			fn := r.getClusterInfoConfigMap(authCR, cm)
			result, err := fn(ctx)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
		})
		It("will produce a function that signals to requeue with an error when an unexpected error occurs", func() {
			rFailing := &AuthenticationReconciler{
				Client: &testutil.FakeTimeoutClient{
					Client: cl,
				},
			}
			fn := rFailing.getClusterInfoConfigMap(authCR, cm)
			result, err := fn(ctx)
			testutil.ConfirmThatItRequeuesWithError(result, err)
		})
	})

	Describe("verifyConfigMapHasCorrectOwnership", func() {
		BeforeEach(func() {
			authCR = &operatorv1alpha1.Authentication{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "operator.ibm.com/v1alpha1",
					Kind:       "Authentication",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "example-authentication",
					Namespace:       "data-ns",
					ResourceVersion: trackerAddResourceVersion,
				},
			}
			clusterInfoConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"cluster_address":      "cp-console-example.apps.cluster.ibm.com",
					"cluster_address_auth": "cp-console-example.apps.cluster.ibm.com",
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(clusterInfoConfigMap, authCR)
			cl = cb.Build()
			r = &AuthenticationReconciler{
				Client: cl,
			}
			ctx = context.Background()
		})
		It("will produce a function that signals to continue reconciling when the ConfigMap is owned by the Authentication", func() {
			cm := &corev1.ConfigMap{}
			err := r.Get(ctx, types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}, cm)
			Expect(err).ToNot(HaveOccurred())
			controllerutil.SetOwnerReference(authCR, cm, scheme)
			fn := r.verifyConfigMapHasCorrectOwnership(authCR, cm)
			result, err := fn(ctx)
			testutil.ConfirmThatItContinuesReconciling(result, err)
		})
		It("will produce a function that signals to requeue with a delay when the ConfigMap is not owned by the Authentication", func() {
			cm := &corev1.ConfigMap{}
			err := r.Get(ctx, types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}, cm)
			Expect(err).ToNot(HaveOccurred())
			fn := r.verifyConfigMapHasCorrectOwnership(authCR, cm)
			result, err := fn(ctx)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
		})
	})

	Describe("verifyConfigMapHasField", func() {
		BeforeEach(func() {
			authCR = &operatorv1alpha1.Authentication{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "operator.ibm.com/v1alpha1",
					Kind:       "Authentication",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "example-authentication",
					Namespace:       "data-ns",
					ResourceVersion: trackerAddResourceVersion,
				},
			}
			clusterInfoConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"cluster_address":      "cp-console-example.apps.cluster.ibm.com",
					"cluster_address_auth": "cp-console-example.apps.cluster.ibm.com",
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(clusterInfoConfigMap, authCR)
			cl = cb.Build()
			r = &AuthenticationReconciler{
				Client: cl,
			}
			ctx = context.Background()
		})
		It("will produce a function that signals to continue reconciling when the ConfigMap has the field", func() {
			cm := &corev1.ConfigMap{}
			err := r.Get(ctx, types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}, cm)
			Expect(err).ToNot(HaveOccurred())
			fn := r.verifyConfigMapHasField(authCR, "cluster_address", cm)
			result, err := fn(ctx)
			testutil.ConfirmThatItContinuesReconciling(result, err)
		})
		It("will produce a function that signals to requeue with an error when the ConfigMap does not have the field", func() {
			cm := &corev1.ConfigMap{}
			err := r.Get(ctx, types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}, cm)
			Expect(err).ToNot(HaveOccurred())
			fn := r.verifyConfigMapHasField(authCR, "some-other-field", cm)
			result, err := fn(ctx)
			testutil.ConfirmThatItRequeuesWithError(result, err)
		})
		It("will produce a function that signals to requeue with an error when the ConfigMap's Data is empty", func() {
			cm := &corev1.ConfigMap{}
			fn := r.verifyConfigMapHasField(authCR, "some-other-field", cm)
			result, err := fn(ctx)
			testutil.ConfirmThatItRequeuesWithError(result, err)
		})
	})

	Describe("ensureConfigMapHasEqualFields", func() {
		BeforeEach(func() {
			authCR = &operatorv1alpha1.Authentication{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "operator.ibm.com/v1alpha1",
					Kind:       "Authentication",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "example-authentication",
					Namespace:       "data-ns",
					ResourceVersion: trackerAddResourceVersion,
				},
			}
			clusterInfoConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"cluster_address":      "cp-console-example.apps.cluster.ibm.com",
					"cluster_address_auth": "cp-console-example.apps.cluster.ibm.com",
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(clusterInfoConfigMap, authCR)
			cl = cb.Build()
			r = &AuthenticationReconciler{
				Client: cl,
			}
			ctx = context.Background()
		})
		It("will produce a function that signals to continue reconciling when no changes need to be made", func() {
			cm := &corev1.ConfigMap{}
			err := r.Get(ctx, types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}, cm)
			Expect(err).ToNot(HaveOccurred())
			fields := map[string]string{
				"cluster_address_auth": "cp-console-example.apps.cluster.ibm.com",
			}
			fn := r.ensureConfigMapHasEqualFields(authCR, fields, cm)
			result, err := fn(ctx)
			testutil.ConfirmThatItContinuesReconciling(result, err)
		})
		It("will produce a function that signals to requeue with a delay when the ConfigMap is changed successfully", func() {
			cm := &corev1.ConfigMap{}
			err := r.Get(ctx, types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}, cm)
			Expect(err).ToNot(HaveOccurred())
			fields := map[string]string{
				"cluster_address_auth": "cp-console-different-example.apps.cluster.ibm.com",
				"an_extra_field":       "an_extra_value",
			}
			fn := r.ensureConfigMapHasEqualFields(authCR, fields, cm)
			result, err := fn(ctx)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			err = r.Get(ctx, types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}, cm)
			Expect(err).ToNot(HaveOccurred())
			Expect(cm.Data).To(HaveKeyWithValue("cluster_address_auth", "cp-console-different-example.apps.cluster.ibm.com"))
			Expect(cm.Data).To(HaveKeyWithValue("an_extra_field", "an_extra_value"))
		})
		It("will produce a function that signals to requeue with an error when the ConfigMap is not changed successfully", func() {
			cm := &corev1.ConfigMap{}
			err := r.Get(ctx, types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}, cm)
			Expect(err).ToNot(HaveOccurred())
			fields := map[string]string{
				"cluster_address_auth": "cp-console-different-example.apps.cluster.ibm.com",
				"an_extra_field":       "an_extra_value",
			}
			rFailing := &AuthenticationReconciler{
				Client: &testutil.FakeTimeoutClient{
					Client: cl,
				},
			}
			fn := rFailing.ensureConfigMapHasEqualFields(authCR, fields, cm)
			result, err := fn(ctx)
			testutil.ConfirmThatItRequeuesWithError(result, err)
			err = r.Get(ctx, types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}, cm)
			Expect(err).ToNot(HaveOccurred())
			Expect(cm.Data).ToNot(HaveKeyWithValue("cluster_address_auth", "cp-console-different-example.apps.cluster.ibm.com"))
			Expect(cm.Data).ToNot(HaveKeyWithValue("an_extra_field", "an_extra_value"))
		})
	})

	Describe("getWlpClientID", func() {
		var wlpClientID string
		BeforeEach(func() {
			authCR = &operatorv1alpha1.Authentication{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "operator.ibm.com/v1alpha1",
					Kind:       "Authentication",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "example-authentication",
					Namespace:       "data-ns",
					ResourceVersion: trackerAddResourceVersion,
				},
			}
			platformOIDCCredentialsSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: "data-ns",
				},
				Data: map[string][]byte{
					"WLP_CLIENT_ID": []byte("test-id"),
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(platformOIDCCredentialsSecret, authCR)
			cl = cb.Build()
			r = &AuthenticationReconciler{
				Client: cl,
			}
			ctx = context.Background()
			wlpClientID = ""
		})
		It("will produce a function that signals to continue reconciling when the client ID is retrieved successfully", func() {
			fn := r.getWlpClientID(authCR, &wlpClientID)
			result, err := fn(ctx)
			Expect(wlpClientID).To(Equal("test-id"))
			testutil.ConfirmThatItContinuesReconciling(result, err)
		})
		It("will produce a function that signals to requeue with a delay when the Secret is not found", func() {
			err := r.Delete(ctx, platformOIDCCredentialsSecret)
			Expect(err).ToNot(HaveOccurred())
			fn := r.getWlpClientID(authCR, &wlpClientID)
			result, err := fn(ctx)
			Expect(wlpClientID).To(Equal(""))
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
		})
		It("will produce a function that signals to requeue with an error when the ConfigMap is not changed successfully", func() {
			rFailing := &AuthenticationReconciler{
				Client: &testutil.FakeTimeoutClient{
					Client: cl,
				},
			}
			fn := rFailing.getWlpClientID(authCR, &wlpClientID)
			result, err := fn(ctx)
			Expect(wlpClientID).To(Equal(""))
			testutil.ConfirmThatItRequeuesWithError(result, err)
		})
	})
	Describe("getCertificateForService", func() {
		BeforeEach(func() {
			authCR = &operatorv1alpha1.Authentication{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "operator.ibm.com/v1alpha1",
					Kind:       "Authentication",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "example-authentication",
					Namespace:       "data-ns",
					ResourceVersion: trackerAddResourceVersion,
				},
			}
			platformAuthSecretSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "platform-auth-secret",
					Namespace: "data-ns",
				},
				Data: map[string][]byte{
					"ca.crt":  []byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCRENDQWV5Z0F3SUJBZ0lRQzV1T0VGSDBDd0VwRWpXWmE0L2lnVEFOQmdrcWhraUc5dzBCQVFzRkFEQWMKTVJvd0dBWURWUVFERXhGamN5MWpZUzFqWlhKMGFXWnBZMkYwWlRBZUZ3MHlOREE0TWpneE1USXhNVGxhRncweQpOakE0TWpneE1USXhNVGxhTUJ3eEdqQVlCZ05WQkFNVEVXTnpMV05oTFdObGNuUnBabWxqWVhSbE1JSUJJakFOCkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXVEY2ExWkVlRm55K1BrMHhNNnhTWTlUVDBTK28KQUpTQk1QQTNFbS85S3lobE9Ob1ZzdlpneHFEQmxRSlpxQWNKQXN1NDJMNno2TkhNRVJscmlRUGFVanU1UjlYTgprTXNjSGh6UzRLYzNOaDd6ZkJNRURodzFNeDVCbjdsMTZyM1BEclE5aDRhY0pZMjFmNEZlUTM5S0R5K0RMUThiCjFURUp1dVlUNU8zV2N0ZTNoNWQ4TGxpbFhJVUJKUmdFdGx3eHFqWCt1d24rT0p5aGR3ZWo2NmVVNWhURVZHaEoKZWY5K0d1QnFjdEFITjlKU2Q2ZFZNYUp3eG9hZEpERnpaVE1TQ3ZuSkZPTmxkM1V4YW1wUmtpdm9BUVdLOFFycwplTlI1anhOT0h6d1lXOG1TMnNXL3NFRmduTG5haWJtNXRJWjBrajRZS0srTFVTeW5iOUF1NnVQOUd3SURBUUFCCm8wSXdRREFPQmdOVkhROEJBZjhFQkFNQ0FxUXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QWRCZ05WSFE0RUZnUVUKbE9mbm9YY1RPSU04NjJwOWFEc2VHMFdaRjlRd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFGTzdlaUdZTkM2Mgo0RytnTy9zRC9GVnRpU0gwTnQ1cW94TFJLVndsc3ZIU0dTSGE4L21jWGRQdTNlWHlMazdUa09hUm5YV3NRMEphCjBaS2VWNDBzN3o4YmdaZGRsOGRKSGloQTg4c0FzTDdtWS9ZdjZZUTlCaGJ3eGJEWDVhbFpaMytMcFZXandRcW0KWUxLUWQyNVZLZkxlNHRRVjgyTDJRMTBZTjh1U0hVYUc4SnQ0b1I4MXR3YVp4Y1oxcE9ETGdkZ0N0a3BvSjhQWgpnemt1bHhzL1NOaXgrTGxhTTg1Z2x6L2V3eFJaR0RNVms5SGthdGdvYmtUNlZhK2NQdUV2bmFDVFQ5QzlUTGFkCk84bmtwMDBodW5nUG9Vb0pzQ3BNMHBCa3grYkNNd1IzT2pzUVBDdmYvTU84bzlKNWRjcXQyeTBhNVhPbGZsbEQKTlBoWGJOWm1qS3M9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"),
					"tls.crt": []byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURRakNDQWlxZ0F3SUJBZ0lSQU5HTVl2U3BlN3N1ejdnSmgzZ3Z1Q1F3RFFZSktvWklodmNOQVFFTEJRQXcKSERFYU1CZ0dBMVVFQXhNUlkzTXRZMkV0WTJWeWRHbG1hV05oZEdVd0hoY05NalF3T0RJNE1URXlNVE0xV2hjTgpNalV3T1RNd01URXlNVE0xV2pBZ01SNHdIQVlEVlFRREV4VndiR0YwWm05eWJTMWhkWFJvTFhObGNuWnBZMlV3CmdnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURHZkp3M1RRRkdYN0VWM2dkdVdFT1UKY0ZrenVUK2h0QWJscmxTbWpOSk52VzN5WDN4UW16aExvdEE3a1FJRkd1ZEN6TmRzSEZTSGRIYXZibThETG0zbgpuOWFzalgvSjNPdjVaeTVTOVZHR0FSeS9FR0QvblorVlZZOU1sM2o1Z3ZDRmVhMXp3cUlFQUhXV3FuaFdpUWlKCjg0eXA2cld1U0hUb2NtYVFvZElxQTN0a01RbWg2Zm9XRWljNlFkWVhuYmlzdm9pWDJ0cDVMdCs0MWhqakJFMFgKNU8rbFlSSEtmY2p4QXV1UzUvd05ERDkzcVQ2Mm1PWk9kV2N1WGFSY1phUnNsSFdpVk9lT21PSWdyUUV6dlV1SwpTZExkUFhOVFFoRnZmN3ZvZ0dIVFNJMWJwMFhWS1lCakFRT0pkdUZHNmhwQnhiZzM5MHprOTl2UlhxOWFpTndwCkFnTUJBQUdqZXpCNU1BNEdBMVVkRHdFQi93UUVBd0lGb0RBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVkKTUJhQUZKVG41NkYzRXppRFBPdHFmV2c3SGh0Rm1SZlVNRGdHQTFVZEVRUXhNQytDRlhCc1lYUm1iM0p0TFdGMQpkR2d0YzJWeWRtbGpaWWNFZndBQUFZY1FBQUFBQUFBQUFBQUFBQUFBQUFBQUFUQU5CZ2txaGtpRzl3MEJBUXNGCkFBT0NBUUVBdDF5M0ZNUXlZc2lzTU5jd3l4b0lPQ0NnWk15emZUcEpTeW8raWp5SDdRa0hNMnFwTm85aXBvbXAKWmdGaFRQUE5HVmYvNWNVOFI3Q3JUVHRhZWVrb3FEeGxyS2h5U2w5bkF5VFdieVBJWThKbzBGMmVnelBtaUVIKwpBZ3ozVU82THZ4UkNGeG9qS3RUcWxacDVUOTdFTFgxQ1FKc0NCVGtQKyttK3R0V1RVclU1YWF6bFJRQjJlTC92CllVTDFMcTErUUp1NzZSRGlKVS9hWmlGaTFDWURNMkdPSDRDaXI0ZXFvUnhrVXV4TjQ2Sm5QWWlLMmRyY0Q1bEMKdWp6dGxjZ3p0cWwrK1lCalUzMnBBYzhtNEpOTGhFMU9SY0NuaXRnK0lOQVNMbkVSUXhSckJSUFdwSm80TXl1eQo4K2ZtQlJaMjlZL1k0Z0VMM09mMTFnM05UY2FsMkE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="),
					"tls.key": []byte("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBeG55Y04wMEJSbCt4RmQ0SGJsaERsSEJaTTdrL29iUUc1YTVVcG96U1RiMXQ4bDk4ClVKczRTNkxRTzVFQ0JScm5Rc3pYYkJ4VWgzUjJyMjV2QXk1dDU1L1dySTEveWR6citXY3VVdlZSaGdFY3Z4QmcKLzUyZmxWV1BUSmQ0K1lMd2hYbXRjOEtpQkFCMWxxcDRWb2tJaWZPTXFlcTFya2gwNkhKbWtLSFNLZ043WkRFSgpvZW42RmhJbk9rSFdGNTI0ckw2SWw5cmFlUzdmdU5ZWTR3Uk5GK1R2cFdFUnluM0k4UUxya3VmOERRdy9kNmsrCnRwam1UblZuTGwya1hHV2tiSlIxb2xUbmpwamlJSzBCTTcxTGlrblMzVDF6VTBJUmIzKzc2SUJoMDBpTlc2ZEYKMVNtQVl3RURpWGJoUnVvYVFjVzROL2RNNVBmYjBWNnZXb2pjS1FJREFRQUJBb0lCQUhBRVB6MU9iaHZEUVhOdgozSTIvcmxRRm03SC9LQlFnUDR3NytIWU9IMW5VUUVwNjdQT294ZnFacGg4WDFTWUFhdWRlSjIxU0I3cHlWZERuCjZDckpkeWt6SWJvOEdSUlpZNnRiT2QrRHAwQ1RQQi93SkczZURRUUFSMkVZVXlPdGJBUklDVVc5WUNZV0JFYkYKYWlpY0tYK0JQYTlmVUsxTkl2MVVJdUlaRVR5M3Y2RWRrb3IrYWxoOFU4OXpmOFhmZmxhWHJDR0V2TzNFVmM2VgpmZSs2UzZVVXZxVGZBZzZ1YXFmWUhVR0hLMWRZWjlOVDFBU2VFLytQVkJyQ2ZwZ0JiRElBenI4K0loYUI1QVdpCktOWlJmd2NxVG5Pelc3bWsvQ3BtRHVpc1ZKc3I3eS8vWWdEUDgwNzFNZUNHcmwzbDVhSDRhUThobWc1Q0lBdm0KV1hMc25Ba0NnWUVBN0dHM1k4dXNMOWtZUzVPdmlMcCtxaUZYK1YrQWdac3pzTEVXRENOaEhvWFNqM2hjUkhGagplSnZSM3NSRWhVUHJoQ0NDY0ZhekRMbDlxOFhZWXp5TWNKc0xKZmR4Z0xUMXdzcWhtWWRDTHRQQ0hrbytTaWkyClMxNG4yUEN4cEJTd1o0L0M3STQvOUxYRE9kK2VySGtkckNqUW5rZCtCcTU1MjhnQ3FhY1ZFajhDZ1lFQTF2WEMKU09lR1ZSQnNvUC9FWjltVFhXaHUxU1dvby9aWm44YVlmeHlVQnpEODB1eDhHR2hKRFhnTEN3MDB6MjdpK0VCMwpGakI4RWhzT2IrRTk2V0l2TWJma1hhS0ZYdEVWRXk5b1F0V0NiUU1aeTBOUk9mNFFNcWczcWlvd0U2d0RYNldxCjFLdytjY0dXVW9FU3BVTFRlcnkwOVpBYmhVK0JZREM5Z256TXA1Y0NnWUFrVk95VUNTVUJBYlFyUVpyVVFCM2gKMWxnb094YU1WU2QvdStnd20ydDgvb0tiakp0WjViZXRQUDNuNkhERHJ1blBHQlFVWWk4SkFLV2hOanFKSGpCVAp5bkRQT0JZWSt6ZGU1amdxV2REQlU4amRVUG43K2YveTI1anlUaVJ2bk1KMFdITlVXcFRYN3V2L3hEQW1RRU5nClI3R3c4am9ibXN1ZURVTGpnb3ZKandLQmdRQ2dnbEhZYmtqNEs1TnhoSW43b1pOUUpETGVKWWlQSmR3MldleDAKdmJvcXhJR0VYZUVydUhNVUE1YjdZWmtWYXc4L242Tk1obGVlaldWeVZSWU50cXJXelNGUWFaSjlBbEppU1B2cApLOVIvNGRqWTFpTkkwbFQxL25YU01qNUQ4aVZ5dmhtWlJDUThmUGpxRWtjQjc2eEo4YTZOemxVK2JlZUZFOS91CkY1SVpjUUtCZ0dEeDN4OVhYbkxweWQ4TnRlTDIvdzh5a2taaFRvcFZURi9DdnpaRFhJRTEwd3ZXNWhGTlEzOFQKeUNiOTFCTC9kZWFGS3NQSVpYNnlROFNTbGxwTUlSZTBLWVdsN25qdDVtbUh0dzc1K054em8zRHlIQk1EWjNvLwpJeUNnbFhpMWhKSFJJTi8rNUwyK0lIMytad0dVQW00bWtCZlphTWhEL0FPdDJTR3JsbitMCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=="),
				},
			}
			platformIdentityManagementSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "platform-identity-management",
					Namespace: "data-ns",
				},
				Data: map[string][]byte{
					"ca.crt":  []byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCRENDQWV5Z0F3SUJBZ0lRQzV1T0VGSDBDd0VwRWpXWmE0L2lnVEFOQmdrcWhraUc5dzBCQVFzRkFEQWMKTVJvd0dBWURWUVFERXhGamN5MWpZUzFqWlhKMGFXWnBZMkYwWlRBZUZ3MHlOREE0TWpneE1USXhNVGxhRncweQpOakE0TWpneE1USXhNVGxhTUJ3eEdqQVlCZ05WQkFNVEVXTnpMV05oTFdObGNuUnBabWxqWVhSbE1JSUJJakFOCkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXVEY2ExWkVlRm55K1BrMHhNNnhTWTlUVDBTK28KQUpTQk1QQTNFbS85S3lobE9Ob1ZzdlpneHFEQmxRSlpxQWNKQXN1NDJMNno2TkhNRVJscmlRUGFVanU1UjlYTgprTXNjSGh6UzRLYzNOaDd6ZkJNRURodzFNeDVCbjdsMTZyM1BEclE5aDRhY0pZMjFmNEZlUTM5S0R5K0RMUThiCjFURUp1dVlUNU8zV2N0ZTNoNWQ4TGxpbFhJVUJKUmdFdGx3eHFqWCt1d24rT0p5aGR3ZWo2NmVVNWhURVZHaEoKZWY5K0d1QnFjdEFITjlKU2Q2ZFZNYUp3eG9hZEpERnpaVE1TQ3ZuSkZPTmxkM1V4YW1wUmtpdm9BUVdLOFFycwplTlI1anhOT0h6d1lXOG1TMnNXL3NFRmduTG5haWJtNXRJWjBrajRZS0srTFVTeW5iOUF1NnVQOUd3SURBUUFCCm8wSXdRREFPQmdOVkhROEJBZjhFQkFNQ0FxUXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QWRCZ05WSFE0RUZnUVUKbE9mbm9YY1RPSU04NjJwOWFEc2VHMFdaRjlRd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFGTzdlaUdZTkM2Mgo0RytnTy9zRC9GVnRpU0gwTnQ1cW94TFJLVndsc3ZIU0dTSGE4L21jWGRQdTNlWHlMazdUa09hUm5YV3NRMEphCjBaS2VWNDBzN3o4YmdaZGRsOGRKSGloQTg4c0FzTDdtWS9ZdjZZUTlCaGJ3eGJEWDVhbFpaMytMcFZXandRcW0KWUxLUWQyNVZLZkxlNHRRVjgyTDJRMTBZTjh1U0hVYUc4SnQ0b1I4MXR3YVp4Y1oxcE9ETGdkZ0N0a3BvSjhQWgpnemt1bHhzL1NOaXgrTGxhTTg1Z2x6L2V3eFJaR0RNVms5SGthdGdvYmtUNlZhK2NQdUV2bmFDVFQ5QzlUTGFkCk84bmtwMDBodW5nUG9Vb0pzQ3BNMHBCa3grYkNNd1IzT2pzUVBDdmYvTU84bzlKNWRjcXQyeTBhNVhPbGZsbEQKTlBoWGJOWm1qS3M9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"),
					"tls.crt": []byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURZRENDQWtpZ0F3SUJBZ0lRQ2xraXpINnNGcUgyN3lYRXFXM2ZCREFOQmdrcWhraUc5dzBCQVFzRkFEQWMKTVJvd0dBWURWUVFERXhGamN5MWpZUzFqWlhKMGFXWnBZMkYwWlRBZUZ3MHlOREE0TWpneE1USXhNek5hRncweQpOVEE1TXpBeE1USXhNek5hTUNjeEpUQWpCZ05WQkFNVEhIQnNZWFJtYjNKdExXbGtaVzUwYVhSNUxXMWhibUZuClpXMWxiblF3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQ2k0OHZKc0orcnV2UGMKVnpzM3JvRlB4dGphZmFoOE9EZmFudFV2ZFdHMHpGZ0txdXFjUzBnbjJoN2FxUUlpUnlySDdnRlF1R3o2M1V1YQpzcHMyZFQ0TDIvOUdiU1N5SHFNN0JhOE1VVnhSRktEaSt3cytzMElPb2hHbmlxUTZBTXNUbjc3OExPK0E1UVVlCkJsMGVFMEJwYzY5RUowK0NORkZIRFBhemxBVWNxVm11RWlmY2JnMUVYWjk0RHk5SGNCeU5uNTRLakxNaFlqV1oKb3pmTUovd2J0MEpTYzdYemdmWGtIWWsyVFlVSy8vNGRzOS93U21UV2VkRHhCRW5KYkRCVkZxUi9Uc0RYWG1aeApPWVhSZllJa1VOTkozM1FlNDJyRFE0OGxCbG1IcGhScXlacjMvL2I2QSswVCs3bTliVEVsUjFVRWp6ak9hWTBKCk53YVFwTkl2QWdNQkFBR2pnWkl3Z1k4d0RnWURWUjBQQVFIL0JBUURBZ1dnTUF3R0ExVWRFd0VCL3dRQ01BQXcKSHdZRFZSMGpCQmd3Rm9BVWxPZm5vWGNUT0lNODYycDlhRHNlRzBXWkY5UXdUZ1lEVlIwUkJFY3dSWUljY0d4aApkR1p2Y20wdGFXUmxiblJwZEhrdGJXRnVZV2RsYldWdWRJSWxjR3hoZEdadmNtMHRhV1JsYm5ScGRIa3RiV0Z1CllXZGxiV1Z1ZEM0d01pMXpMbk4yWXpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQWUyWCtUaW9TdFVMYk9sS1EKcE8zWUY0TDlRazViSW9XVjl1RkRCOEZpQ2ppaTVDQm5CckJmcm8vd3d6YXhiWStONnBqZTBLZUJRVHFCbHc4TQpSMEhaSWF6UnVWUmlWaTFLS20vN3gzRHI5MEg4dnhVZ3IzZ3hiUm1Iemt5eEFJK2ZjNHdrUHA4LzB5WHArRVZPCm43QVNUTkNYd3RhS0pydEFLaGFUcW5CNVBGN3NIb0Rob1liYkNkaDNYb1gzUlhLR1RMNzlNSVJja1RkV1QyUDkKWWVPZmRTZWQwY2RPWW9xcEozSXF6dVBNOC9tZlZMVE5pRlJQUnNIQzVUelZUdDlzVDFjVWdpdXR1eHJuRnFWNwphMTlIL2pZYnhHdm1ZVmh3d2Y0NTh6LzRwRmJqcnBudzNrK2JGNGh0ZDBGT044WSs0cGZKK204cE5XZzRqZGFsClhiK0c0UT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"),
					"tls.key": []byte("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBb3VQTHliQ2ZxN3J6M0ZjN042NkJUOGJZMm4yb2ZEZzMycDdWTDNWaHRNeFlDcXJxCm5FdElKOW9lMnFrQ0lrY3F4KzRCVUxocyt0MUxtcktiTm5VK0M5di9SbTBrc2g2ak93V3ZERkZjVVJTZzR2c0wKUHJOQ0RxSVJwNHFrT2dETEU1KysvQ3p2Z09VRkhnWmRIaE5BYVhPdlJDZFBnalJSUnd6MnM1UUZIS2xacmhJbgozRzROUkYyZmVBOHZSM0FjalorZUNveXpJV0kxbWFNM3pDZjhHN2RDVW5PMTg0SDE1QjJKTmsyRkN2LytIYlBmCjhFcGsxbm5ROFFSSnlXd3dWUmFrZjA3QTExNW1jVG1GMFgyQ0pGRFRTZDkwSHVOcXcwT1BKUVpaaDZZVWFzbWEKOS8vMitnUHRFL3U1dlcweEpVZFZCSTg0em1tTkNUY0drS1RTTHdJREFRQUJBb0lCQVFDR3JxdFZmTURKRWErSQp4R2VtUnBlTkN2RksxeE4wZ2xkTVlJQU0yWldNRkZuSG1FS2NNSExjNExFYVF4d01rNk4vNC84YWF5TlEyYUVsCnJBQkNLdmErZjR5M0FvK1E1MXczOVI4anBESWNxRjNPejV3Z243OUNzaWErelJlMURlcmJzdjRMTEd4cnV2RmMKUGc3SVMwcTY1bmhJZGVoNzFCNVFEUnYrcDZrQ1pJSXdwd093VjVnR0p5V0JoL0xCckJ6MkZpWUliQU9vNnNTdQpNbTZ5ZUhxM1dHcFUwN3BJUUZhdVRML0ZvTVNPbWs3NGxBN0ZuQWpoTVdxM0xnRzdiS28xS25aeXRpTndNTFcvCmNrSmFJT0hOaGJpYmJmLzF6TWxvREwyTlJxajlCbzRWc2RtZ0JqYmtSWno0VG5HWW9BaEVwVzNWVHgyaVd5a2QKT3ZiVkJyMGhBb0dCQU1JNXl0aGNobXpIaHl6dkJOQmd2Njl0M28zRStmM2Y3RTBOM24rTDdXb2NzS21uUjA2UgpNa01HOVhWK1ZVR2NvVXE0QTdNNmJ0a1V4SlBYR0wvNUpwWDZEVWFVRFBOVWJCS0djZjQra1BPeVVSSzMrMHBTCnBRb1ljUENSOU1mWTBodjBwMlZwSGhYVERxSUFJWGdpS01SSktYbnpOVFdRL2diRkZRYXpHM1ZkQW9HQkFOYXkKazZ3aStNMStFZVpHL083M0xEODdOMGloUUtNaEFLNkNHT2NFWXFWRnF1Rmw0djRXemdNdTdXUTZidTFsTVBaUgpQdnZReGRjWUNjM1FING4rNnUwMkNHTFRvZitGZFk4OERsM1kzYmp6M05iT2NjTSthcmJReHVvZHFOU0s2Qm1wCm9QU3MzM2M5blE1M0duRGtRbVlsNjhRNklKSDdjanhJS0ZScFQ4RDdBb0dBZlVNK2twbmh6R2hHd3ZFSVhzZjIKK0ZKWXRZQXpac3V6SCtMdys3dW9DOGFqSFZlWVFwQ2NKT1JwRERURkVZTE45MTJFYldRak4zZ1FhL1RPcm9rbQpuSlZmV0lTRmNhMmg0YlM1OGlveDNDbkY1ZGVvaHIrVVYxVjZDWDFvckRjbkV3YVBxM1RIQlhaUU9xVHc4UVMrCjNCRC9ZZm83OStjaUhnV2ZVT25VckxVQ2dZRUF6aTRXaE5QYzdiTHBTNlRXbUVLRW1vQ3FtYlJKMTU4RkFaRnMKaXNaNldVOXJTQ1JKZGt1K01lNXFDYnZYOVdFZFFSOUxCaGM3TjFJZGNDb3piNW1BVUtkNExEZ2pOYmtiNlo3NgpDUVFRQWVNbkxKNTdQODM4TzI2SjZDRHRscGVEUjhuUUNjak9uYnRzell4eHR3SnVCWnpiS3NuTHA0VzY4Y3MxCjk4SmUxZXNDZ1lCUENzdUhkZ1krdTRadHFvVnZ1YXlLU3BhUm1WRjFlU0krR1NaZ201aUQvQmRDTFN0SlVZeXYKNm5WZkxlWEJmWis0TG5kdG9hTWRNaVJuaE41T3dCUDk3ZlgvK2s0cmVpOUNjVUVObDJQT2NaN2NFQlYySllkVApJTmR2MjVhcnhraTJwMCs2cGw4Q0VWVFhCSy9kMkpLMk1MY244ZlRnMklPK3ZGNnNCZnM5YWc9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="),
				},
			}
			identityProviderSecretSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "identity-provider-secret",
					Namespace: "data-ns",
				},
				Data: map[string][]byte{
					"ca.crt":  []byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCRENDQWV5Z0F3SUJBZ0lRQzV1T0VGSDBDd0VwRWpXWmE0L2lnVEFOQmdrcWhraUc5dzBCQVFzRkFEQWMKTVJvd0dBWURWUVFERXhGamN5MWpZUzFqWlhKMGFXWnBZMkYwWlRBZUZ3MHlOREE0TWpneE1USXhNVGxhRncweQpOakE0TWpneE1USXhNVGxhTUJ3eEdqQVlCZ05WQkFNVEVXTnpMV05oTFdObGNuUnBabWxqWVhSbE1JSUJJakFOCkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXVEY2ExWkVlRm55K1BrMHhNNnhTWTlUVDBTK28KQUpTQk1QQTNFbS85S3lobE9Ob1ZzdlpneHFEQmxRSlpxQWNKQXN1NDJMNno2TkhNRVJscmlRUGFVanU1UjlYTgprTXNjSGh6UzRLYzNOaDd6ZkJNRURodzFNeDVCbjdsMTZyM1BEclE5aDRhY0pZMjFmNEZlUTM5S0R5K0RMUThiCjFURUp1dVlUNU8zV2N0ZTNoNWQ4TGxpbFhJVUJKUmdFdGx3eHFqWCt1d24rT0p5aGR3ZWo2NmVVNWhURVZHaEoKZWY5K0d1QnFjdEFITjlKU2Q2ZFZNYUp3eG9hZEpERnpaVE1TQ3ZuSkZPTmxkM1V4YW1wUmtpdm9BUVdLOFFycwplTlI1anhOT0h6d1lXOG1TMnNXL3NFRmduTG5haWJtNXRJWjBrajRZS0srTFVTeW5iOUF1NnVQOUd3SURBUUFCCm8wSXdRREFPQmdOVkhROEJBZjhFQkFNQ0FxUXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QWRCZ05WSFE0RUZnUVUKbE9mbm9YY1RPSU04NjJwOWFEc2VHMFdaRjlRd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFGTzdlaUdZTkM2Mgo0RytnTy9zRC9GVnRpU0gwTnQ1cW94TFJLVndsc3ZIU0dTSGE4L21jWGRQdTNlWHlMazdUa09hUm5YV3NRMEphCjBaS2VWNDBzN3o4YmdaZGRsOGRKSGloQTg4c0FzTDdtWS9ZdjZZUTlCaGJ3eGJEWDVhbFpaMytMcFZXandRcW0KWUxLUWQyNVZLZkxlNHRRVjgyTDJRMTBZTjh1U0hVYUc4SnQ0b1I4MXR3YVp4Y1oxcE9ETGdkZ0N0a3BvSjhQWgpnemt1bHhzL1NOaXgrTGxhTTg1Z2x6L2V3eFJaR0RNVms5SGthdGdvYmtUNlZhK2NQdUV2bmFDVFQ5QzlUTGFkCk84bmtwMDBodW5nUG9Vb0pzQ3BNMHBCa3grYkNNd1IzT2pzUVBDdmYvTU84bzlKNWRjcXQyeTBhNVhPbGZsbEQKTlBoWGJOWm1qS3M9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"),
					"tls.crt": []byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURXekNDQWtPZ0F3SUJBZ0lSQUp2VHMwVDRrcitGL1VFY1dUanlWek13RFFZSktvWklodmNOQVFFTEJRQXcKSERFYU1CZ0dBMVVFQXhNUlkzTXRZMkV0WTJWeWRHbG1hV05oZEdVd0hoY05NalF3T0RJNE1URXlNVE16V2hjTgpNalV3T1RNd01URXlNVE16V2pBbE1TTXdJUVlEVlFRREV4cHdiR0YwWm05eWJTMXBaR1Z1ZEdsMGVTMXdjbTkyCmFXUmxjakNDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFLdjdtTzZuRHlCbTRlVngKNzFpa0J6bXMzSnNjcHBncGl5VDk2SFJ4R3p5WEJLb0owMytvaW1TZU55dmk0MkNEaHEyRlBCQmhucTJqZEdvdQptY2ZGTXZBVnpCcTRhMktkRWQyOEdVak1jYi92UkdPV2RKdS9xSUVYWjdyTUQwOVpwQ1ZOVDF6VEE2a29Gd1VnCmxyZjZuQW1UU0ttNlV2SlJSbjdXK0tFYW9NVktOWjdleVB6T004K0NPODEzaDZCUjQ3NVkxalROeVRTa3NyMTcKN3JBdVdYY0tQMWRNblFqZlFpdTFDUzlPNUdCZHk1cHpJdEppR2Zoa2lTNDlGS0Z3SkYyeU02OXNEOExBTDNQSApBRUs2UEtVL1BTaTJ3TzZxemFiNGVYRlhNZ1RCSjNwTWtsdkJmc2wwWTAvVVBjMUxxSWhuSnNxakVnYUwwNWNsCm5KSm0yQjBDQXdFQUFhT0JqakNCaXpBT0JnTlZIUThCQWY4RUJBTUNCYUF3REFZRFZSMFRBUUgvQkFJd0FEQWYKQmdOVkhTTUVHREFXZ0JTVTUrZWhkeE00Z3p6cmFuMW9PeDRiUlprWDFEQktCZ05WSFJFRVF6QkJnaHB3YkdGMApabTl5YlMxcFpHVnVkR2wwZVMxd2NtOTJhV1JsY29JamNHeGhkR1p2Y20wdGFXUmxiblJwZEhrdGNISnZkbWxrClpYSXVNREl0Y3k1emRtTXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBQnVDVW5ZYVF5Tm5vWmlXTFZUVFF2dTAKK0FBTUZGWGpJT1VkMUV2ZnRyWVhwYkJRbHlJYU1qU2Iyd25oNEdBd25CWUh1emRzWFFwQ2t0WHRESmJvWnBsKwp6Mk1CVkJMYjNqaDJ4WGttdVVubWhFQmZFcXJicUo5L0puekd2NndkVGUxVmNLbUNCbHlsRjhvWDRQOGtIZVRhCmczMGFBdjRsK01VVldka29BMG1jUENSZHczOHN0VkdvQ3cyeUxPUWVNN1FtWHlkK2tLRzdMT0d1WFIxR2gzM3EKNjJYV1NDMzlFUEc5ZjZzMlFRWjJuMXZtMzMvTVJLZ3V5VFV6aHFZMnh2VzB0SXRJck80MUtZNDlxQ21zMEpxRQowVzJ0cEdxazd2aFFlUlhsUGFtZlhUWUZ6SE5pSnZLM1BjWjJBK2tCNXYyTVZ3TkZaRGl5WldlMDFtK2JNTUE9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"),
					"tls.key": []byte("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBcS91WTdxY1BJR2JoNVhIdldLUUhPYXpjbXh5bW1DbUxKUDNvZEhFYlBKY0VxZ25UCmY2aUtaSjQzSytMallJT0dyWVU4RUdHZXJhTjBhaTZaeDhVeThCWE1HcmhyWXAwUjNid1pTTXh4dis5RVk1WjAKbTcrb2dSZG51c3dQVDFta0pVMVBYTk1EcVNnWEJTQ1d0L3FjQ1pOSXFicFM4bEZHZnRiNG9ScWd4VW8xbnQ3SQovTTR6ejRJN3pYZUhvRkhqdmxqV05NM0pOS1N5dlh2dXNDNVpkd28vVjB5ZENOOUNLN1VKTDA3a1lGM0xtbk1pCjBtSVorR1NKTGowVW9YQWtYYkl6cjJ3UHdzQXZjOGNBUXJvOHBUODlLTGJBN3FyTnB2aDVjVmN5Qk1FbmVreVMKVzhGK3lYUmpUOVE5elV1b2lHY215cU1TQm92VGx5V2NrbWJZSFFJREFRQUJBb0lCQUdrQit0T2tueURLa0p6Mgpud3hCUXNRZFhxazZxaUY0SkNSVy82cXhNTThpNms4a0pzWG9VMit5QnIrK0RkVHRHYnN6QVlTREJrN0E0YUMvCmlWZW5lVDJNSVk0akVqWW83ekt5MmNGUVN4ZkU4TDNacktNNE41dHlmZnhaQWZRU0tKNDZBUDROUFV2NFZXM2wKQXdHY2U4K0E1VG4wc1JhUk4zalVxd1E2N1BUb0pVc2JMVGV2d3FFVUtGbVgzVXFaT3dGT2x0cmJ6bEhSN2hHNApQRGRKSEdvd0V0REhKYjlDY1huY1I4Q1hDdnh0R2xEYzdxSkVBNUNXV0NheTYzR3gydm5oa3EyTU9kNEdwb2UrCm1ydGJmZGFXWjB5YzJLUEphdG96R1NGWXBVQVluNyt4dVpMSFpGdWdNMnZOWDZ2RllvQ2ZzZHJXcmdXN2RBUWUKZG93UG9tVUNnWUVBeXZPcGQ3MWx4dXkrYUZKMEcyYkdidHMrYjkzNWhiU2ppNk5wa0lQSk5UcXUveTF5eC9xQwpybHlyZFI4MXZ6SUc2ZXFmNnAwVGZQdC9NZkVJdVJ1YVNiNkJBZll6VmdiMDVBa3pCTE45VG1iYkxBNEE3eU44CmZkbk13Q0dXdWFsaGNHaHN3T2ZvWU9oaW16TlVodVVrS012bHk3MlBybjA1NlRIOXdwQ3R2Z2NDZ1lFQTJPK3MKSWEwT2VSbVB6NVJmUVRFSi9BYlBpL3JUMGpOdUZkelFFZWQvU2x0dTBJSFJjckpnTGxDMG51YTRTQ2o3Nk10MgpERkhGc3dMT3piOTZlV3ZYQ2lhOEVEbVR4NmpYVXk0eitpcERaQlpHd1BTQXVXVkVTaS9TZG1JbGVMNFFaN0ZZCklUYnYwSVR2SE4rRXJRMjZIN093S2ZJeUxNb2NvYkJybmZzb2I3c0NnWUEzSXoyK1gwRmdhdjlML21LMjh4UWsKR0FKOWgvUDdoRmtPWGVZWE1nYWZKSU5ZcG5OUnExaUhvSHVnaFVzbjE2S1RPSUFiMEhMeitLdlUyS1JERGlHNwp1VHI1V25jVi95dlhMRHlsSVZLQTAyYm1NQ1BHMUlCRS9NQW96cmRSVjVnMlh0aDFERXhRejdIQ2NvNmJXM09ZCmRkVEhwb2Q3bzEveFgvaU9QSnBIVHdLQmdRRFRzSTE0RHplZ1ZLRlJIcWdWSlpWb3FmeTl5L1lIbU1oRDdVWGQKTXRtejVhVXRNb0VBTzdBL2dlRy9iY1ZHSlRnczR0NC9CMHkwY25qN3JXNEdMb1daRWxOU1FkMURhQzgyckU5cwpQdkdrS1ZqQjBkWUxGQmFmamlzQitxUTJQc0lqYlp0aVRnbVdvU0gwT3VsdE5ZZjZoNDNRWU5jMWZjU1N3MlZBCnRHV3hJUUtCZ1FDOHpQV0J6bUdYL3dHbHVWY1MvTTVRekxNWDlJcm10MjkwdHJqeXBxeFJ6ekJuT0xNQTRZd3IKRVBGUWhuY2JJOUdkN3VXeXhrZVNxcFh3WXNyazkyMGZuWUdFTGhOOHNDRVYrNVVEUStFT1R6ZDVxTCtLYkFpagp3U1BxakliS3d0V0t3TDRPcmg0clkwY1lqYmV2K0ZDUm4xOWNReHREa0libUQ3SGVtV1d5R3c9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="),
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(
					platformAuthSecretSecret,
					platformIdentityManagementSecret,
					identityProviderSecretSecret,
					authCR,
				)
			cl = cb.Build()
			r = &AuthenticationReconciler{
				Client: cl,
			}
			ctx = context.Background()

		})

		testSuccessfulCertRetrieval := func(serviceName string, secret *corev1.Secret) {
			certificate := []byte{}
			fn := r.getCertificateForService(serviceName, authCR, &certificate)
			result, err := fn(ctx)
			Expect(certificate).To(Equal(secret.Data["ca.crt"]))
			testutil.ConfirmThatItContinuesReconciling(result, err)
		}
		testCertNotFound := func(serviceName string, secret *corev1.Secret) {
			certificate := []byte{}
			err := r.Delete(ctx, secret)
			Expect(err).ToNot(HaveOccurred())
			fn := r.getCertificateForService(serviceName, authCR, &certificate)
			result, err := fn(ctx)
			Expect(certificate).To(Equal([]byte{}))
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
		}
		testFailedCertRetrieval := func(serviceName string) {
			certificate := []byte{}
			rFailing := &AuthenticationReconciler{
				Client: &testutil.FakeTimeoutClient{
					Client: cl,
				},
			}
			fn := rFailing.getCertificateForService(serviceName, authCR, &certificate)
			result, err := fn(ctx)
			Expect(certificate).To(Equal([]byte{}))
			testutil.ConfirmThatItRequeuesWithError(result, err)
		}

		It("produces a function that signals to continue reconciling when certificate retrieved", func() {
			testSuccessfulCertRetrieval(PlatformAuthServiceName, platformAuthSecretSecret)
			testSuccessfulCertRetrieval(PlatformIdentityManagementServiceName, platformIdentityManagementSecret)
			testSuccessfulCertRetrieval(PlatformIdentityProviderServiceName, identityProviderSecretSecret)
		})
		It("produces a function that signals to requeue with delay when certificate is not found", func() {
			testCertNotFound(PlatformAuthServiceName, platformAuthSecretSecret)
			testCertNotFound(PlatformIdentityManagementServiceName, platformIdentityManagementSecret)
			testCertNotFound(PlatformIdentityProviderServiceName, identityProviderSecretSecret)
		})
		It("produces a function that signals to requeue with an error when Secret cannot otherwise be retrieved", func() {
			testFailedCertRetrieval(PlatformAuthServiceName)
			testFailedCertRetrieval(PlatformIdentityManagementServiceName)
			testFailedCertRetrieval(PlatformIdentityProviderServiceName)
		})
		It("produces a function that signals to requeue with an error when name of Service doesn't match one of the relevant ones", func() {
			certificate := []byte{}
			fn := r.getCertificateForService("some-other-name", authCR, &certificate)
			result, err := fn(ctx)
			Expect(certificate).To(Equal([]byte{}))
			testutil.ConfirmThatItRequeuesWithError(result, err)
		})
		It("produces a function that signals to requeue with an error when Secret does not have \"ca.crt\" field set", func() {
			certificate := []byte{}
			delete(platformAuthSecretSecret.Data, "ca.crt")
			err := r.Update(ctx, platformAuthSecretSecret)
			Expect(err).ToNot(HaveOccurred())
			fn := r.getCertificateForService(PlatformAuthServiceName, authCR, &certificate)
			result, err := fn(ctx)
			Expect(certificate).To(Equal([]byte{}))
			testutil.ConfirmThatItRequeuesWithError(result, err)
		})
	})

	Describe("getClusterAddress", func() {
		var clusterAddress string
		BeforeEach(func() {
			crds, err := envtest.InstallCRDs(cfg, envtest.CRDInstallOptions{
				Paths: []string{filepath.Join(".", "testdata", "crds", "routes")},
			})
			Expect(crds).To(HaveLen(1))
			Expect(err).ToNot(HaveOccurred())
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(routev1.AddToScheme(scheme)).To(Succeed())

			authCR = &operatorv1alpha1.Authentication{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "operator.ibm.com/v1alpha1",
					Kind:       "Authentication",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "example-authentication",
					Namespace:       "data-ns",
					ResourceVersion: trackerAddResourceVersion,
				},
			}
			clusterInfoConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"cluster_address":      "cp-console-example.apps.cluster.ibm.com",
					"cluster_address_auth": "cp-console-example.apps.cluster.ibm.com",
				},
			}
			controllerutil.SetOwnerReference(authCR, clusterInfoConfigMap, scheme)
			ctx = context.Background()
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(clusterInfoConfigMap, authCR)
			cl = cb.Build()
			r = &AuthenticationReconciler{
				Client: cl,
			}
			clusterAddress = ""
		})

		It("returns a function that signals to continue reconciling when cluster address is retrieved successfully", func() {
			fn := r.getClusterAddress(authCR, &clusterAddress)
			result, err := fn(ctx)
			Expect(clusterAddress).To(Equal(clusterInfoConfigMap.Data["cluster_address"]))
			testutil.ConfirmThatItContinuesReconciling(result, err)
		})

		It("returns a function that signals to requeue with a delay when ConfigMap is not present", func() {
			err := r.Delete(ctx, clusterInfoConfigMap)
			Expect(err).ToNot(HaveOccurred())
			fn := r.getClusterAddress(authCR, &clusterAddress)
			result, err := fn(ctx)
			Expect(clusterAddress).To(BeZero())
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
		})

		It("returns a function that signals to requeue with an error when ConfigMap cannot be retrieved for some other reason", func() {
			err := r.Delete(ctx, clusterInfoConfigMap)
			Expect(err).ToNot(HaveOccurred())
			rFailing := &AuthenticationReconciler{
				Client: &testutil.FakeTimeoutClient{
					Client: cl,
				},
			}
			fn := rFailing.getClusterAddress(authCR, &clusterAddress)
			result, err := fn(ctx)
			Expect(clusterAddress).To(BeZero())
			testutil.ConfirmThatItRequeuesWithError(result, err)
		})
	})

	Describe("handleRoutes", func() {
		BeforeEach(func() {
			crds, err := envtest.InstallCRDs(cfg, envtest.CRDInstallOptions{
				Paths: []string{
					filepath.Join(".", "testdata", "crds", "routes"),
					filepath.Join(".", "testdata", "crds", "zen"),
				},
			})
			Expect(crds).To(HaveLen(2))
			Expect(err).ToNot(HaveOccurred())

			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(routev1.AddToScheme(scheme)).To(Succeed())
			Expect(zenv1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			authCR = &operatorv1alpha1.Authentication{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "operator.ibm.com/v1alpha1",
					Kind:       "Authentication",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "example-authentication",
					Namespace:       "data-ns",
					ResourceVersion: trackerAddResourceVersion,
				},
			}
			clusterInfoConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"cluster_address":      "cp-console-example.apps.cluster.ibm.com",
					"cluster_address_auth": "cp-console-example.apps.cluster.ibm.com",
				},
			}
			platformAuthSecretSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "platform-auth-secret",
					Namespace: "data-ns",
				},
				Data: map[string][]byte{
					"ca.crt":  []byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCRENDQWV5Z0F3SUJBZ0lRQzV1T0VGSDBDd0VwRWpXWmE0L2lnVEFOQmdrcWhraUc5dzBCQVFzRkFEQWMKTVJvd0dBWURWUVFERXhGamN5MWpZUzFqWlhKMGFXWnBZMkYwWlRBZUZ3MHlOREE0TWpneE1USXhNVGxhRncweQpOakE0TWpneE1USXhNVGxhTUJ3eEdqQVlCZ05WQkFNVEVXTnpMV05oTFdObGNuUnBabWxqWVhSbE1JSUJJakFOCkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXVEY2ExWkVlRm55K1BrMHhNNnhTWTlUVDBTK28KQUpTQk1QQTNFbS85S3lobE9Ob1ZzdlpneHFEQmxRSlpxQWNKQXN1NDJMNno2TkhNRVJscmlRUGFVanU1UjlYTgprTXNjSGh6UzRLYzNOaDd6ZkJNRURodzFNeDVCbjdsMTZyM1BEclE5aDRhY0pZMjFmNEZlUTM5S0R5K0RMUThiCjFURUp1dVlUNU8zV2N0ZTNoNWQ4TGxpbFhJVUJKUmdFdGx3eHFqWCt1d24rT0p5aGR3ZWo2NmVVNWhURVZHaEoKZWY5K0d1QnFjdEFITjlKU2Q2ZFZNYUp3eG9hZEpERnpaVE1TQ3ZuSkZPTmxkM1V4YW1wUmtpdm9BUVdLOFFycwplTlI1anhOT0h6d1lXOG1TMnNXL3NFRmduTG5haWJtNXRJWjBrajRZS0srTFVTeW5iOUF1NnVQOUd3SURBUUFCCm8wSXdRREFPQmdOVkhROEJBZjhFQkFNQ0FxUXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QWRCZ05WSFE0RUZnUVUKbE9mbm9YY1RPSU04NjJwOWFEc2VHMFdaRjlRd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFGTzdlaUdZTkM2Mgo0RytnTy9zRC9GVnRpU0gwTnQ1cW94TFJLVndsc3ZIU0dTSGE4L21jWGRQdTNlWHlMazdUa09hUm5YV3NRMEphCjBaS2VWNDBzN3o4YmdaZGRsOGRKSGloQTg4c0FzTDdtWS9ZdjZZUTlCaGJ3eGJEWDVhbFpaMytMcFZXandRcW0KWUxLUWQyNVZLZkxlNHRRVjgyTDJRMTBZTjh1U0hVYUc4SnQ0b1I4MXR3YVp4Y1oxcE9ETGdkZ0N0a3BvSjhQWgpnemt1bHhzL1NOaXgrTGxhTTg1Z2x6L2V3eFJaR0RNVms5SGthdGdvYmtUNlZhK2NQdUV2bmFDVFQ5QzlUTGFkCk84bmtwMDBodW5nUG9Vb0pzQ3BNMHBCa3grYkNNd1IzT2pzUVBDdmYvTU84bzlKNWRjcXQyeTBhNVhPbGZsbEQKTlBoWGJOWm1qS3M9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"),
					"tls.crt": []byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURRakNDQWlxZ0F3SUJBZ0lSQU5HTVl2U3BlN3N1ejdnSmgzZ3Z1Q1F3RFFZSktvWklodmNOQVFFTEJRQXcKSERFYU1CZ0dBMVVFQXhNUlkzTXRZMkV0WTJWeWRHbG1hV05oZEdVd0hoY05NalF3T0RJNE1URXlNVE0xV2hjTgpNalV3T1RNd01URXlNVE0xV2pBZ01SNHdIQVlEVlFRREV4VndiR0YwWm05eWJTMWhkWFJvTFhObGNuWnBZMlV3CmdnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURHZkp3M1RRRkdYN0VWM2dkdVdFT1UKY0ZrenVUK2h0QWJscmxTbWpOSk52VzN5WDN4UW16aExvdEE3a1FJRkd1ZEN6TmRzSEZTSGRIYXZibThETG0zbgpuOWFzalgvSjNPdjVaeTVTOVZHR0FSeS9FR0QvblorVlZZOU1sM2o1Z3ZDRmVhMXp3cUlFQUhXV3FuaFdpUWlKCjg0eXA2cld1U0hUb2NtYVFvZElxQTN0a01RbWg2Zm9XRWljNlFkWVhuYmlzdm9pWDJ0cDVMdCs0MWhqakJFMFgKNU8rbFlSSEtmY2p4QXV1UzUvd05ERDkzcVQ2Mm1PWk9kV2N1WGFSY1phUnNsSFdpVk9lT21PSWdyUUV6dlV1SwpTZExkUFhOVFFoRnZmN3ZvZ0dIVFNJMWJwMFhWS1lCakFRT0pkdUZHNmhwQnhiZzM5MHprOTl2UlhxOWFpTndwCkFnTUJBQUdqZXpCNU1BNEdBMVVkRHdFQi93UUVBd0lGb0RBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVkKTUJhQUZKVG41NkYzRXppRFBPdHFmV2c3SGh0Rm1SZlVNRGdHQTFVZEVRUXhNQytDRlhCc1lYUm1iM0p0TFdGMQpkR2d0YzJWeWRtbGpaWWNFZndBQUFZY1FBQUFBQUFBQUFBQUFBQUFBQUFBQUFUQU5CZ2txaGtpRzl3MEJBUXNGCkFBT0NBUUVBdDF5M0ZNUXlZc2lzTU5jd3l4b0lPQ0NnWk15emZUcEpTeW8raWp5SDdRa0hNMnFwTm85aXBvbXAKWmdGaFRQUE5HVmYvNWNVOFI3Q3JUVHRhZWVrb3FEeGxyS2h5U2w5bkF5VFdieVBJWThKbzBGMmVnelBtaUVIKwpBZ3ozVU82THZ4UkNGeG9qS3RUcWxacDVUOTdFTFgxQ1FKc0NCVGtQKyttK3R0V1RVclU1YWF6bFJRQjJlTC92CllVTDFMcTErUUp1NzZSRGlKVS9hWmlGaTFDWURNMkdPSDRDaXI0ZXFvUnhrVXV4TjQ2Sm5QWWlLMmRyY0Q1bEMKdWp6dGxjZ3p0cWwrK1lCalUzMnBBYzhtNEpOTGhFMU9SY0NuaXRnK0lOQVNMbkVSUXhSckJSUFdwSm80TXl1eQo4K2ZtQlJaMjlZL1k0Z0VMM09mMTFnM05UY2FsMkE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="),
					"tls.key": []byte("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBeG55Y04wMEJSbCt4RmQ0SGJsaERsSEJaTTdrL29iUUc1YTVVcG96U1RiMXQ4bDk4ClVKczRTNkxRTzVFQ0JScm5Rc3pYYkJ4VWgzUjJyMjV2QXk1dDU1L1dySTEveWR6citXY3VVdlZSaGdFY3Z4QmcKLzUyZmxWV1BUSmQ0K1lMd2hYbXRjOEtpQkFCMWxxcDRWb2tJaWZPTXFlcTFya2gwNkhKbWtLSFNLZ043WkRFSgpvZW42RmhJbk9rSFdGNTI0ckw2SWw5cmFlUzdmdU5ZWTR3Uk5GK1R2cFdFUnluM0k4UUxya3VmOERRdy9kNmsrCnRwam1UblZuTGwya1hHV2tiSlIxb2xUbmpwamlJSzBCTTcxTGlrblMzVDF6VTBJUmIzKzc2SUJoMDBpTlc2ZEYKMVNtQVl3RURpWGJoUnVvYVFjVzROL2RNNVBmYjBWNnZXb2pjS1FJREFRQUJBb0lCQUhBRVB6MU9iaHZEUVhOdgozSTIvcmxRRm03SC9LQlFnUDR3NytIWU9IMW5VUUVwNjdQT294ZnFacGg4WDFTWUFhdWRlSjIxU0I3cHlWZERuCjZDckpkeWt6SWJvOEdSUlpZNnRiT2QrRHAwQ1RQQi93SkczZURRUUFSMkVZVXlPdGJBUklDVVc5WUNZV0JFYkYKYWlpY0tYK0JQYTlmVUsxTkl2MVVJdUlaRVR5M3Y2RWRrb3IrYWxoOFU4OXpmOFhmZmxhWHJDR0V2TzNFVmM2VgpmZSs2UzZVVXZxVGZBZzZ1YXFmWUhVR0hLMWRZWjlOVDFBU2VFLytQVkJyQ2ZwZ0JiRElBenI4K0loYUI1QVdpCktOWlJmd2NxVG5Pelc3bWsvQ3BtRHVpc1ZKc3I3eS8vWWdEUDgwNzFNZUNHcmwzbDVhSDRhUThobWc1Q0lBdm0KV1hMc25Ba0NnWUVBN0dHM1k4dXNMOWtZUzVPdmlMcCtxaUZYK1YrQWdac3pzTEVXRENOaEhvWFNqM2hjUkhGagplSnZSM3NSRWhVUHJoQ0NDY0ZhekRMbDlxOFhZWXp5TWNKc0xKZmR4Z0xUMXdzcWhtWWRDTHRQQ0hrbytTaWkyClMxNG4yUEN4cEJTd1o0L0M3STQvOUxYRE9kK2VySGtkckNqUW5rZCtCcTU1MjhnQ3FhY1ZFajhDZ1lFQTF2WEMKU09lR1ZSQnNvUC9FWjltVFhXaHUxU1dvby9aWm44YVlmeHlVQnpEODB1eDhHR2hKRFhnTEN3MDB6MjdpK0VCMwpGakI4RWhzT2IrRTk2V0l2TWJma1hhS0ZYdEVWRXk5b1F0V0NiUU1aeTBOUk9mNFFNcWczcWlvd0U2d0RYNldxCjFLdytjY0dXVW9FU3BVTFRlcnkwOVpBYmhVK0JZREM5Z256TXA1Y0NnWUFrVk95VUNTVUJBYlFyUVpyVVFCM2gKMWxnb094YU1WU2QvdStnd20ydDgvb0tiakp0WjViZXRQUDNuNkhERHJ1blBHQlFVWWk4SkFLV2hOanFKSGpCVAp5bkRQT0JZWSt6ZGU1amdxV2REQlU4amRVUG43K2YveTI1anlUaVJ2bk1KMFdITlVXcFRYN3V2L3hEQW1RRU5nClI3R3c4am9ibXN1ZURVTGpnb3ZKandLQmdRQ2dnbEhZYmtqNEs1TnhoSW43b1pOUUpETGVKWWlQSmR3MldleDAKdmJvcXhJR0VYZUVydUhNVUE1YjdZWmtWYXc4L242Tk1obGVlaldWeVZSWU50cXJXelNGUWFaSjlBbEppU1B2cApLOVIvNGRqWTFpTkkwbFQxL25YU01qNUQ4aVZ5dmhtWlJDUThmUGpxRWtjQjc2eEo4YTZOemxVK2JlZUZFOS91CkY1SVpjUUtCZ0dEeDN4OVhYbkxweWQ4TnRlTDIvdzh5a2taaFRvcFZURi9DdnpaRFhJRTEwd3ZXNWhGTlEzOFQKeUNiOTFCTC9kZWFGS3NQSVpYNnlROFNTbGxwTUlSZTBLWVdsN25qdDVtbUh0dzc1K054em8zRHlIQk1EWjNvLwpJeUNnbFhpMWhKSFJJTi8rNUwyK0lIMytad0dVQW00bWtCZlphTWhEL0FPdDJTR3JsbitMCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=="),
				},
			}
			platformIdentityManagementSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "platform-identity-management",
					Namespace: "data-ns",
				},
				Data: map[string][]byte{
					"ca.crt":  []byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCRENDQWV5Z0F3SUJBZ0lRQzV1T0VGSDBDd0VwRWpXWmE0L2lnVEFOQmdrcWhraUc5dzBCQVFzRkFEQWMKTVJvd0dBWURWUVFERXhGamN5MWpZUzFqWlhKMGFXWnBZMkYwWlRBZUZ3MHlOREE0TWpneE1USXhNVGxhRncweQpOakE0TWpneE1USXhNVGxhTUJ3eEdqQVlCZ05WQkFNVEVXTnpMV05oTFdObGNuUnBabWxqWVhSbE1JSUJJakFOCkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXVEY2ExWkVlRm55K1BrMHhNNnhTWTlUVDBTK28KQUpTQk1QQTNFbS85S3lobE9Ob1ZzdlpneHFEQmxRSlpxQWNKQXN1NDJMNno2TkhNRVJscmlRUGFVanU1UjlYTgprTXNjSGh6UzRLYzNOaDd6ZkJNRURodzFNeDVCbjdsMTZyM1BEclE5aDRhY0pZMjFmNEZlUTM5S0R5K0RMUThiCjFURUp1dVlUNU8zV2N0ZTNoNWQ4TGxpbFhJVUJKUmdFdGx3eHFqWCt1d24rT0p5aGR3ZWo2NmVVNWhURVZHaEoKZWY5K0d1QnFjdEFITjlKU2Q2ZFZNYUp3eG9hZEpERnpaVE1TQ3ZuSkZPTmxkM1V4YW1wUmtpdm9BUVdLOFFycwplTlI1anhOT0h6d1lXOG1TMnNXL3NFRmduTG5haWJtNXRJWjBrajRZS0srTFVTeW5iOUF1NnVQOUd3SURBUUFCCm8wSXdRREFPQmdOVkhROEJBZjhFQkFNQ0FxUXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QWRCZ05WSFE0RUZnUVUKbE9mbm9YY1RPSU04NjJwOWFEc2VHMFdaRjlRd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFGTzdlaUdZTkM2Mgo0RytnTy9zRC9GVnRpU0gwTnQ1cW94TFJLVndsc3ZIU0dTSGE4L21jWGRQdTNlWHlMazdUa09hUm5YV3NRMEphCjBaS2VWNDBzN3o4YmdaZGRsOGRKSGloQTg4c0FzTDdtWS9ZdjZZUTlCaGJ3eGJEWDVhbFpaMytMcFZXandRcW0KWUxLUWQyNVZLZkxlNHRRVjgyTDJRMTBZTjh1U0hVYUc4SnQ0b1I4MXR3YVp4Y1oxcE9ETGdkZ0N0a3BvSjhQWgpnemt1bHhzL1NOaXgrTGxhTTg1Z2x6L2V3eFJaR0RNVms5SGthdGdvYmtUNlZhK2NQdUV2bmFDVFQ5QzlUTGFkCk84bmtwMDBodW5nUG9Vb0pzQ3BNMHBCa3grYkNNd1IzT2pzUVBDdmYvTU84bzlKNWRjcXQyeTBhNVhPbGZsbEQKTlBoWGJOWm1qS3M9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"),
					"tls.crt": []byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURZRENDQWtpZ0F3SUJBZ0lRQ2xraXpINnNGcUgyN3lYRXFXM2ZCREFOQmdrcWhraUc5dzBCQVFzRkFEQWMKTVJvd0dBWURWUVFERXhGamN5MWpZUzFqWlhKMGFXWnBZMkYwWlRBZUZ3MHlOREE0TWpneE1USXhNek5hRncweQpOVEE1TXpBeE1USXhNek5hTUNjeEpUQWpCZ05WQkFNVEhIQnNZWFJtYjNKdExXbGtaVzUwYVhSNUxXMWhibUZuClpXMWxiblF3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQ2k0OHZKc0orcnV2UGMKVnpzM3JvRlB4dGphZmFoOE9EZmFudFV2ZFdHMHpGZ0txdXFjUzBnbjJoN2FxUUlpUnlySDdnRlF1R3o2M1V1YQpzcHMyZFQ0TDIvOUdiU1N5SHFNN0JhOE1VVnhSRktEaSt3cytzMElPb2hHbmlxUTZBTXNUbjc3OExPK0E1UVVlCkJsMGVFMEJwYzY5RUowK0NORkZIRFBhemxBVWNxVm11RWlmY2JnMUVYWjk0RHk5SGNCeU5uNTRLakxNaFlqV1oKb3pmTUovd2J0MEpTYzdYemdmWGtIWWsyVFlVSy8vNGRzOS93U21UV2VkRHhCRW5KYkRCVkZxUi9Uc0RYWG1aeApPWVhSZllJa1VOTkozM1FlNDJyRFE0OGxCbG1IcGhScXlacjMvL2I2QSswVCs3bTliVEVsUjFVRWp6ak9hWTBKCk53YVFwTkl2QWdNQkFBR2pnWkl3Z1k4d0RnWURWUjBQQVFIL0JBUURBZ1dnTUF3R0ExVWRFd0VCL3dRQ01BQXcKSHdZRFZSMGpCQmd3Rm9BVWxPZm5vWGNUT0lNODYycDlhRHNlRzBXWkY5UXdUZ1lEVlIwUkJFY3dSWUljY0d4aApkR1p2Y20wdGFXUmxiblJwZEhrdGJXRnVZV2RsYldWdWRJSWxjR3hoZEdadmNtMHRhV1JsYm5ScGRIa3RiV0Z1CllXZGxiV1Z1ZEM0d01pMXpMbk4yWXpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQWUyWCtUaW9TdFVMYk9sS1EKcE8zWUY0TDlRazViSW9XVjl1RkRCOEZpQ2ppaTVDQm5CckJmcm8vd3d6YXhiWStONnBqZTBLZUJRVHFCbHc4TQpSMEhaSWF6UnVWUmlWaTFLS20vN3gzRHI5MEg4dnhVZ3IzZ3hiUm1Iemt5eEFJK2ZjNHdrUHA4LzB5WHArRVZPCm43QVNUTkNYd3RhS0pydEFLaGFUcW5CNVBGN3NIb0Rob1liYkNkaDNYb1gzUlhLR1RMNzlNSVJja1RkV1QyUDkKWWVPZmRTZWQwY2RPWW9xcEozSXF6dVBNOC9tZlZMVE5pRlJQUnNIQzVUelZUdDlzVDFjVWdpdXR1eHJuRnFWNwphMTlIL2pZYnhHdm1ZVmh3d2Y0NTh6LzRwRmJqcnBudzNrK2JGNGh0ZDBGT044WSs0cGZKK204cE5XZzRqZGFsClhiK0c0UT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"),
					"tls.key": []byte("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBb3VQTHliQ2ZxN3J6M0ZjN042NkJUOGJZMm4yb2ZEZzMycDdWTDNWaHRNeFlDcXJxCm5FdElKOW9lMnFrQ0lrY3F4KzRCVUxocyt0MUxtcktiTm5VK0M5di9SbTBrc2g2ak93V3ZERkZjVVJTZzR2c0wKUHJOQ0RxSVJwNHFrT2dETEU1KysvQ3p2Z09VRkhnWmRIaE5BYVhPdlJDZFBnalJSUnd6MnM1UUZIS2xacmhJbgozRzROUkYyZmVBOHZSM0FjalorZUNveXpJV0kxbWFNM3pDZjhHN2RDVW5PMTg0SDE1QjJKTmsyRkN2LytIYlBmCjhFcGsxbm5ROFFSSnlXd3dWUmFrZjA3QTExNW1jVG1GMFgyQ0pGRFRTZDkwSHVOcXcwT1BKUVpaaDZZVWFzbWEKOS8vMitnUHRFL3U1dlcweEpVZFZCSTg0em1tTkNUY0drS1RTTHdJREFRQUJBb0lCQVFDR3JxdFZmTURKRWErSQp4R2VtUnBlTkN2RksxeE4wZ2xkTVlJQU0yWldNRkZuSG1FS2NNSExjNExFYVF4d01rNk4vNC84YWF5TlEyYUVsCnJBQkNLdmErZjR5M0FvK1E1MXczOVI4anBESWNxRjNPejV3Z243OUNzaWErelJlMURlcmJzdjRMTEd4cnV2RmMKUGc3SVMwcTY1bmhJZGVoNzFCNVFEUnYrcDZrQ1pJSXdwd093VjVnR0p5V0JoL0xCckJ6MkZpWUliQU9vNnNTdQpNbTZ5ZUhxM1dHcFUwN3BJUUZhdVRML0ZvTVNPbWs3NGxBN0ZuQWpoTVdxM0xnRzdiS28xS25aeXRpTndNTFcvCmNrSmFJT0hOaGJpYmJmLzF6TWxvREwyTlJxajlCbzRWc2RtZ0JqYmtSWno0VG5HWW9BaEVwVzNWVHgyaVd5a2QKT3ZiVkJyMGhBb0dCQU1JNXl0aGNobXpIaHl6dkJOQmd2Njl0M28zRStmM2Y3RTBOM24rTDdXb2NzS21uUjA2UgpNa01HOVhWK1ZVR2NvVXE0QTdNNmJ0a1V4SlBYR0wvNUpwWDZEVWFVRFBOVWJCS0djZjQra1BPeVVSSzMrMHBTCnBRb1ljUENSOU1mWTBodjBwMlZwSGhYVERxSUFJWGdpS01SSktYbnpOVFdRL2diRkZRYXpHM1ZkQW9HQkFOYXkKazZ3aStNMStFZVpHL083M0xEODdOMGloUUtNaEFLNkNHT2NFWXFWRnF1Rmw0djRXemdNdTdXUTZidTFsTVBaUgpQdnZReGRjWUNjM1FING4rNnUwMkNHTFRvZitGZFk4OERsM1kzYmp6M05iT2NjTSthcmJReHVvZHFOU0s2Qm1wCm9QU3MzM2M5blE1M0duRGtRbVlsNjhRNklKSDdjanhJS0ZScFQ4RDdBb0dBZlVNK2twbmh6R2hHd3ZFSVhzZjIKK0ZKWXRZQXpac3V6SCtMdys3dW9DOGFqSFZlWVFwQ2NKT1JwRERURkVZTE45MTJFYldRak4zZ1FhL1RPcm9rbQpuSlZmV0lTRmNhMmg0YlM1OGlveDNDbkY1ZGVvaHIrVVYxVjZDWDFvckRjbkV3YVBxM1RIQlhaUU9xVHc4UVMrCjNCRC9ZZm83OStjaUhnV2ZVT25VckxVQ2dZRUF6aTRXaE5QYzdiTHBTNlRXbUVLRW1vQ3FtYlJKMTU4RkFaRnMKaXNaNldVOXJTQ1JKZGt1K01lNXFDYnZYOVdFZFFSOUxCaGM3TjFJZGNDb3piNW1BVUtkNExEZ2pOYmtiNlo3NgpDUVFRQWVNbkxKNTdQODM4TzI2SjZDRHRscGVEUjhuUUNjak9uYnRzell4eHR3SnVCWnpiS3NuTHA0VzY4Y3MxCjk4SmUxZXNDZ1lCUENzdUhkZ1krdTRadHFvVnZ1YXlLU3BhUm1WRjFlU0krR1NaZ201aUQvQmRDTFN0SlVZeXYKNm5WZkxlWEJmWis0TG5kdG9hTWRNaVJuaE41T3dCUDk3ZlgvK2s0cmVpOUNjVUVObDJQT2NaN2NFQlYySllkVApJTmR2MjVhcnhraTJwMCs2cGw4Q0VWVFhCSy9kMkpLMk1MY244ZlRnMklPK3ZGNnNCZnM5YWc9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="),
				},
			}
			identityProviderSecretSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "identity-provider-secret",
					Namespace: "data-ns",
				},
				Data: map[string][]byte{
					"ca.crt":  []byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCRENDQWV5Z0F3SUJBZ0lRQzV1T0VGSDBDd0VwRWpXWmE0L2lnVEFOQmdrcWhraUc5dzBCQVFzRkFEQWMKTVJvd0dBWURWUVFERXhGamN5MWpZUzFqWlhKMGFXWnBZMkYwWlRBZUZ3MHlOREE0TWpneE1USXhNVGxhRncweQpOakE0TWpneE1USXhNVGxhTUJ3eEdqQVlCZ05WQkFNVEVXTnpMV05oTFdObGNuUnBabWxqWVhSbE1JSUJJakFOCkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXVEY2ExWkVlRm55K1BrMHhNNnhTWTlUVDBTK28KQUpTQk1QQTNFbS85S3lobE9Ob1ZzdlpneHFEQmxRSlpxQWNKQXN1NDJMNno2TkhNRVJscmlRUGFVanU1UjlYTgprTXNjSGh6UzRLYzNOaDd6ZkJNRURodzFNeDVCbjdsMTZyM1BEclE5aDRhY0pZMjFmNEZlUTM5S0R5K0RMUThiCjFURUp1dVlUNU8zV2N0ZTNoNWQ4TGxpbFhJVUJKUmdFdGx3eHFqWCt1d24rT0p5aGR3ZWo2NmVVNWhURVZHaEoKZWY5K0d1QnFjdEFITjlKU2Q2ZFZNYUp3eG9hZEpERnpaVE1TQ3ZuSkZPTmxkM1V4YW1wUmtpdm9BUVdLOFFycwplTlI1anhOT0h6d1lXOG1TMnNXL3NFRmduTG5haWJtNXRJWjBrajRZS0srTFVTeW5iOUF1NnVQOUd3SURBUUFCCm8wSXdRREFPQmdOVkhROEJBZjhFQkFNQ0FxUXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QWRCZ05WSFE0RUZnUVUKbE9mbm9YY1RPSU04NjJwOWFEc2VHMFdaRjlRd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFGTzdlaUdZTkM2Mgo0RytnTy9zRC9GVnRpU0gwTnQ1cW94TFJLVndsc3ZIU0dTSGE4L21jWGRQdTNlWHlMazdUa09hUm5YV3NRMEphCjBaS2VWNDBzN3o4YmdaZGRsOGRKSGloQTg4c0FzTDdtWS9ZdjZZUTlCaGJ3eGJEWDVhbFpaMytMcFZXandRcW0KWUxLUWQyNVZLZkxlNHRRVjgyTDJRMTBZTjh1U0hVYUc4SnQ0b1I4MXR3YVp4Y1oxcE9ETGdkZ0N0a3BvSjhQWgpnemt1bHhzL1NOaXgrTGxhTTg1Z2x6L2V3eFJaR0RNVms5SGthdGdvYmtUNlZhK2NQdUV2bmFDVFQ5QzlUTGFkCk84bmtwMDBodW5nUG9Vb0pzQ3BNMHBCa3grYkNNd1IzT2pzUVBDdmYvTU84bzlKNWRjcXQyeTBhNVhPbGZsbEQKTlBoWGJOWm1qS3M9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"),
					"tls.crt": []byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURXekNDQWtPZ0F3SUJBZ0lSQUp2VHMwVDRrcitGL1VFY1dUanlWek13RFFZSktvWklodmNOQVFFTEJRQXcKSERFYU1CZ0dBMVVFQXhNUlkzTXRZMkV0WTJWeWRHbG1hV05oZEdVd0hoY05NalF3T0RJNE1URXlNVE16V2hjTgpNalV3T1RNd01URXlNVE16V2pBbE1TTXdJUVlEVlFRREV4cHdiR0YwWm05eWJTMXBaR1Z1ZEdsMGVTMXdjbTkyCmFXUmxjakNDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFLdjdtTzZuRHlCbTRlVngKNzFpa0J6bXMzSnNjcHBncGl5VDk2SFJ4R3p5WEJLb0owMytvaW1TZU55dmk0MkNEaHEyRlBCQmhucTJqZEdvdQptY2ZGTXZBVnpCcTRhMktkRWQyOEdVak1jYi92UkdPV2RKdS9xSUVYWjdyTUQwOVpwQ1ZOVDF6VEE2a29Gd1VnCmxyZjZuQW1UU0ttNlV2SlJSbjdXK0tFYW9NVktOWjdleVB6T004K0NPODEzaDZCUjQ3NVkxalROeVRTa3NyMTcKN3JBdVdYY0tQMWRNblFqZlFpdTFDUzlPNUdCZHk1cHpJdEppR2Zoa2lTNDlGS0Z3SkYyeU02OXNEOExBTDNQSApBRUs2UEtVL1BTaTJ3TzZxemFiNGVYRlhNZ1RCSjNwTWtsdkJmc2wwWTAvVVBjMUxxSWhuSnNxakVnYUwwNWNsCm5KSm0yQjBDQXdFQUFhT0JqakNCaXpBT0JnTlZIUThCQWY4RUJBTUNCYUF3REFZRFZSMFRBUUgvQkFJd0FEQWYKQmdOVkhTTUVHREFXZ0JTVTUrZWhkeE00Z3p6cmFuMW9PeDRiUlprWDFEQktCZ05WSFJFRVF6QkJnaHB3YkdGMApabTl5YlMxcFpHVnVkR2wwZVMxd2NtOTJhV1JsY29JamNHeGhkR1p2Y20wdGFXUmxiblJwZEhrdGNISnZkbWxrClpYSXVNREl0Y3k1emRtTXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBQnVDVW5ZYVF5Tm5vWmlXTFZUVFF2dTAKK0FBTUZGWGpJT1VkMUV2ZnRyWVhwYkJRbHlJYU1qU2Iyd25oNEdBd25CWUh1emRzWFFwQ2t0WHRESmJvWnBsKwp6Mk1CVkJMYjNqaDJ4WGttdVVubWhFQmZFcXJicUo5L0puekd2NndkVGUxVmNLbUNCbHlsRjhvWDRQOGtIZVRhCmczMGFBdjRsK01VVldka29BMG1jUENSZHczOHN0VkdvQ3cyeUxPUWVNN1FtWHlkK2tLRzdMT0d1WFIxR2gzM3EKNjJYV1NDMzlFUEc5ZjZzMlFRWjJuMXZtMzMvTVJLZ3V5VFV6aHFZMnh2VzB0SXRJck80MUtZNDlxQ21zMEpxRQowVzJ0cEdxazd2aFFlUlhsUGFtZlhUWUZ6SE5pSnZLM1BjWjJBK2tCNXYyTVZ3TkZaRGl5WldlMDFtK2JNTUE9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"),
					"tls.key": []byte("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBcS91WTdxY1BJR2JoNVhIdldLUUhPYXpjbXh5bW1DbUxKUDNvZEhFYlBKY0VxZ25UCmY2aUtaSjQzSytMallJT0dyWVU4RUdHZXJhTjBhaTZaeDhVeThCWE1HcmhyWXAwUjNid1pTTXh4dis5RVk1WjAKbTcrb2dSZG51c3dQVDFta0pVMVBYTk1EcVNnWEJTQ1d0L3FjQ1pOSXFicFM4bEZHZnRiNG9ScWd4VW8xbnQ3SQovTTR6ejRJN3pYZUhvRkhqdmxqV05NM0pOS1N5dlh2dXNDNVpkd28vVjB5ZENOOUNLN1VKTDA3a1lGM0xtbk1pCjBtSVorR1NKTGowVW9YQWtYYkl6cjJ3UHdzQXZjOGNBUXJvOHBUODlLTGJBN3FyTnB2aDVjVmN5Qk1FbmVreVMKVzhGK3lYUmpUOVE5elV1b2lHY215cU1TQm92VGx5V2NrbWJZSFFJREFRQUJBb0lCQUdrQit0T2tueURLa0p6Mgpud3hCUXNRZFhxazZxaUY0SkNSVy82cXhNTThpNms4a0pzWG9VMit5QnIrK0RkVHRHYnN6QVlTREJrN0E0YUMvCmlWZW5lVDJNSVk0akVqWW83ekt5MmNGUVN4ZkU4TDNacktNNE41dHlmZnhaQWZRU0tKNDZBUDROUFV2NFZXM2wKQXdHY2U4K0E1VG4wc1JhUk4zalVxd1E2N1BUb0pVc2JMVGV2d3FFVUtGbVgzVXFaT3dGT2x0cmJ6bEhSN2hHNApQRGRKSEdvd0V0REhKYjlDY1huY1I4Q1hDdnh0R2xEYzdxSkVBNUNXV0NheTYzR3gydm5oa3EyTU9kNEdwb2UrCm1ydGJmZGFXWjB5YzJLUEphdG96R1NGWXBVQVluNyt4dVpMSFpGdWdNMnZOWDZ2RllvQ2ZzZHJXcmdXN2RBUWUKZG93UG9tVUNnWUVBeXZPcGQ3MWx4dXkrYUZKMEcyYkdidHMrYjkzNWhiU2ppNk5wa0lQSk5UcXUveTF5eC9xQwpybHlyZFI4MXZ6SUc2ZXFmNnAwVGZQdC9NZkVJdVJ1YVNiNkJBZll6VmdiMDVBa3pCTE45VG1iYkxBNEE3eU44CmZkbk13Q0dXdWFsaGNHaHN3T2ZvWU9oaW16TlVodVVrS012bHk3MlBybjA1NlRIOXdwQ3R2Z2NDZ1lFQTJPK3MKSWEwT2VSbVB6NVJmUVRFSi9BYlBpL3JUMGpOdUZkelFFZWQvU2x0dTBJSFJjckpnTGxDMG51YTRTQ2o3Nk10MgpERkhGc3dMT3piOTZlV3ZYQ2lhOEVEbVR4NmpYVXk0eitpcERaQlpHd1BTQXVXVkVTaS9TZG1JbGVMNFFaN0ZZCklUYnYwSVR2SE4rRXJRMjZIN093S2ZJeUxNb2NvYkJybmZzb2I3c0NnWUEzSXoyK1gwRmdhdjlML21LMjh4UWsKR0FKOWgvUDdoRmtPWGVZWE1nYWZKSU5ZcG5OUnExaUhvSHVnaFVzbjE2S1RPSUFiMEhMeitLdlUyS1JERGlHNwp1VHI1V25jVi95dlhMRHlsSVZLQTAyYm1NQ1BHMUlCRS9NQW96cmRSVjVnMlh0aDFERXhRejdIQ2NvNmJXM09ZCmRkVEhwb2Q3bzEveFgvaU9QSnBIVHdLQmdRRFRzSTE0RHplZ1ZLRlJIcWdWSlpWb3FmeTl5L1lIbU1oRDdVWGQKTXRtejVhVXRNb0VBTzdBL2dlRy9iY1ZHSlRnczR0NC9CMHkwY25qN3JXNEdMb1daRWxOU1FkMURhQzgyckU5cwpQdkdrS1ZqQjBkWUxGQmFmamlzQitxUTJQc0lqYlp0aVRnbVdvU0gwT3VsdE5ZZjZoNDNRWU5jMWZjU1N3MlZBCnRHV3hJUUtCZ1FDOHpQV0J6bUdYL3dHbHVWY1MvTTVRekxNWDlJcm10MjkwdHJqeXBxeFJ6ekJuT0xNQTRZd3IKRVBGUWhuY2JJOUdkN3VXeXhrZVNxcFh3WXNyazkyMGZuWUdFTGhOOHNDRVYrNVVEUStFT1R6ZDVxTCtLYkFpagp3U1BxakliS3d0V0t3TDRPcmg0clkwY1lqYmV2K0ZDUm4xOWNReHREa0libUQ3SGVtV1d5R3c9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="),
				},
			}
			platformOIDCCredentialsSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: "data-ns",
				},
				Data: map[string][]byte{
					"WLP_CLIENT_ID": []byte("test-id"),
				},
			}
			controllerutil.SetOwnerReference(authCR, clusterInfoConfigMap, scheme)
			frontdoor = &zenv1.ZenExtension{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ImZenExtName,
					Namespace: "data-ns",
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "ZenExtension",
					APIVersion: "zen.cpd.ibm.com/v1",
				},
			}
			frontdoor.Status.Conditions = []metav1.Condition{
				{
					Type:   zenv1.ConditionTypeSuccessful,
					Status: metav1.ConditionTrue,
				},
				{
					Type:   zenv1.ConditionTypeRunning,
					Status: metav1.ConditionTrue,
				},
				{
					Type:   zenv1.ConditionTypeFailure,
					Status: metav1.ConditionFalse,
				},
			}
			frontdoor.Status.Status = zenv1.ZenExtensionStatusCompleted

			ctx = context.Background()
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(
					clusterInfoConfigMap,
					platformAuthSecretSecret,
					platformIdentityManagementSecret,
					identityProviderSecretSecret,
					platformOIDCCredentialsSecret,
					authCR,
					frontdoor,
				)
			cl = cb.Build()
			dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			Expect(err).NotTo(HaveOccurred())

			r = &AuthenticationReconciler{
				Client:          cl,
				DiscoveryClient: *dc,
			}
		})

		hasAllValidRoutes := func(routes *routev1.RouteList) {
			Expect(routes.Items).To(HaveLen(7))
			for _, route := range routes.Items {
				Expect(route.Spec.Host).To(Equal(clusterInfoConfigMap.Data["cluster_address"]))
				for k, v := range commonRouteAnnotations {
					Expect(route.Annotations).To(HaveKeyWithValue(k, v))
				}
				switch route.Name {
				case "id-mgmt":
					Expect(route.Spec.Path).To(Equal("/idmgmt/"))
					Expect(route.Spec.Port).To(Equal(&routev1.RoutePort{TargetPort: intstr.FromInt(4500)}))
					Expect(route.Spec.To.Name).To(Equal(PlatformIdentityManagementServiceName))
					Expect(route.Spec.TLS.DestinationCACertificate).To(Equal(string(platformIdentityManagementSecret.Data["ca.crt"])))
					Expect(route.Annotations).To(HaveKeyWithValue("haproxy.router.openshift.io/rewrite-target", "/"))
				case "platform-auth":
					Expect(route.Spec.Path).To(Equal("/v1/auth/"))
					Expect(route.Spec.Port).To(Equal(&routev1.RoutePort{TargetPort: intstr.FromInt(4300)}))
					Expect(route.Spec.To.Name).To(Equal(PlatformIdentityProviderServiceName))
					Expect(route.Spec.TLS.DestinationCACertificate).To(Equal(string(identityProviderSecretSecret.Data["ca.crt"])))
					Expect(route.Annotations).To(HaveKeyWithValue("haproxy.router.openshift.io/rewrite-target", "/v1/auth/"))
				case "platform-id-provider":
					Expect(route.Spec.Path).To(Equal("/idprovider/"))
					Expect(route.Spec.Port).To(Equal(&routev1.RoutePort{TargetPort: intstr.FromInt(4300)}))
					Expect(route.Spec.To.Name).To(Equal(PlatformIdentityProviderServiceName))
					Expect(route.Spec.TLS.DestinationCACertificate).To(Equal(string(identityProviderSecretSecret.Data["ca.crt"])))
					Expect(route.Annotations).To(HaveKeyWithValue("haproxy.router.openshift.io/rewrite-target", "/"))
				case "platform-login":
					Expect(route.Spec.Path).To(Equal("/login"))
					Expect(route.Spec.Port).To(Equal(&routev1.RoutePort{TargetPort: intstr.FromInt(4300)}))
					Expect(route.Spec.To.Name).To(Equal(PlatformIdentityProviderServiceName))
					Expect(route.Spec.TLS.DestinationCACertificate).To(Equal(string(identityProviderSecretSecret.Data["ca.crt"])))
					Expect(route.Annotations).To(HaveKeyWithValue("haproxy.router.openshift.io/rewrite-target", "/v1/auth/authorize?client_id=test-id&redirect_uri=https://cp-console-example.apps.cluster.ibm.com/auth/liberty/callback&response_type=code&scope=openid+email+profile&orig=/login"))
				case "platform-oidc":
					Expect(route.Spec.Path).To(Equal("/oidc"))
					Expect(route.Spec.Port).To(Equal(&routev1.RoutePort{TargetPort: intstr.FromInt(9443)}))
					Expect(route.Spec.To.Name).To(Equal(PlatformAuthServiceName))
					Expect(route.Spec.TLS.DestinationCACertificate).To(Equal(string(platformAuthSecretSecret.Data["ca.crt"])))
					Expect(route.Annotations).To(HaveKeyWithValue("haproxy.router.openshift.io/balance", "source"))
				case "saml-ui-callback":
					Expect(route.Spec.Path).To(Equal("/ibm/saml20/defaultSP/acs"))
					Expect(route.Spec.Port).To(Equal(&routev1.RoutePort{TargetPort: intstr.FromInt(9443)}))
					Expect(route.Spec.To.Name).To(Equal(PlatformAuthServiceName))
					Expect(route.Spec.TLS.DestinationCACertificate).To(Equal(string(platformAuthSecretSecret.Data["ca.crt"])))
					Expect(route.Annotations).To(HaveKeyWithValue("haproxy.router.openshift.io/balance", "source"))
					Expect(route.Annotations).To(HaveKeyWithValue("haproxy.router.openshift.io/rewrite-target", "/ibm/saml20/defaultSP/acs"))
				case "social-login-callback":
					Expect(route.Spec.Path).To(Equal("/ibm/api/social-login"))
					Expect(route.Spec.Port).To(Equal(&routev1.RoutePort{TargetPort: intstr.FromInt(9443)}))
					Expect(route.Spec.To.Name).To(Equal(PlatformAuthServiceName))
					Expect(route.Spec.TLS.DestinationCACertificate).To(Equal(string(platformAuthSecretSecret.Data["ca.crt"])))
					Expect(route.Annotations).To(HaveKeyWithValue("haproxy.router.openshift.io/balance", "source"))
					Expect(route.Annotations).To(HaveKeyWithValue("haproxy.router.openshift.io/rewrite-target", "/ibm/api/social-login"))
				}
			}
		}

		createDummyRoutes := func() {
			names := []string{
				"id-mgmt",
				"platform-auth",
				"platform-id-provider",
				"platform-login",
				"platform-oidc",
				"saml-ui-callback",
				"social-login-callback",
			}

			for _, name := range names {
				route := &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: "data-ns",
					},
				}
				err := r.Create(ctx, route)
				Expect(err).ToNot(HaveOccurred())
			}
			routes := &routev1.RouteList{}
			listOpts := []client.ListOption{
				client.InNamespace("data-ns"),
			}
			err := r.List(ctx, routes, listOpts...)
			Expect(err).ToNot(HaveOccurred())
			Expect(routes.Items).To(HaveLen(7))
		}

		It("creates all Routes when zenFrontDoor is not enabled", func() {
			result, err := r.handleRoutes(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      "example-authentication",
						Namespace: "data-ns",
					},
				},
			)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			routes := &routev1.RouteList{}
			listOpts := []client.ListOption{
				client.InNamespace("data-ns"),
			}
			err = r.List(ctx, routes, listOpts...)
			Expect(err).ToNot(HaveOccurred())
			hasAllValidRoutes(routes)
		})

		It("deletes all Routes when zenFrontDoor is enabled", func() {
			createDummyRoutes()
			authCR.Spec.Config.ZenFrontDoor = true
			err := r.Update(ctx, authCR)
			Expect(err).ToNot(HaveOccurred())
			result, err := r.handleRoutes(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      "example-authentication",
						Namespace: "data-ns",
					},
				},
			)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			routes := &routev1.RouteList{}
			listOpts := []client.ListOption{
				client.InNamespace("data-ns"),
			}
			err = r.List(ctx, routes, listOpts...)
			Expect(err).ToNot(HaveOccurred())
			Expect(routes.Items).To(HaveLen(0))
		})

		It("updates all Routes when differences are found and requeues", func() {
			createDummyRoutes()
			result, err := r.handleRoutes(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      "example-authentication",
						Namespace: "data-ns",
					},
				},
			)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			routes := &routev1.RouteList{}
			listOpts := []client.ListOption{
				client.InNamespace("data-ns"),
			}
			err = r.List(ctx, routes, listOpts...)
			Expect(err).ToNot(HaveOccurred())
			hasAllValidRoutes(routes)
		})

		It("signals to continue reconciling if the Routes are already correct", func() {
			result, err := r.handleRoutes(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      "example-authentication",
						Namespace: "data-ns",
					},
				},
			)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			routes := &routev1.RouteList{}
			listOpts := []client.ListOption{
				client.InNamespace("data-ns"),
			}
			err = r.List(ctx, routes, listOpts...)
			Expect(err).ToNot(HaveOccurred())
			hasAllValidRoutes(routes)
			result, err = r.handleRoutes(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      "example-authentication",
						Namespace: "data-ns",
					},
				},
			)
			testutil.ConfirmThatItContinuesReconciling(result, err)
			hasAllValidRoutes(routes)
		})

		It("skips deleting Routes when ZenExtension Successful Condition is false", func() {
			createDummyRoutes()
			By("setting Successful Condition to false")
			meta.SetStatusCondition(&frontdoor.Status.Conditions, metav1.Condition{
				Type:   zenv1.ConditionTypeSuccessful,
				Status: metav1.ConditionFalse,
			})
			result, err := r.handleRoutes(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      "example-authentication",
						Namespace: "data-ns",
					},
				},
			)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			routes := &routev1.RouteList{}
			listOpts := []client.ListOption{
				client.InNamespace("data-ns"),
			}
			err = r.List(ctx, routes, listOpts...)
			Expect(err).ToNot(HaveOccurred())
			hasAllValidRoutes(routes)
		})

		It("skips deleting Routes when ZenExtension Running Condition is false", func() {
			createDummyRoutes()
			By("setting Running Condition to false")
			meta.SetStatusCondition(&frontdoor.Status.Conditions, metav1.Condition{
				Type:   zenv1.ConditionTypeRunning,
				Status: metav1.ConditionFalse,
			})
			result, err := r.handleRoutes(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      "example-authentication",
						Namespace: "data-ns",
					},
				},
			)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			routes := &routev1.RouteList{}
			listOpts := []client.ListOption{
				client.InNamespace("data-ns"),
			}
			err = r.List(ctx, routes, listOpts...)
			Expect(err).ToNot(HaveOccurred())
			hasAllValidRoutes(routes)
		})

		It("skips deleting Routes when ZenExtension Failure Condition is true", func() {
			createDummyRoutes()
			By("setting Failure Condition to false")
			meta.SetStatusCondition(&frontdoor.Status.Conditions, metav1.Condition{
				Type:   zenv1.ConditionTypeFailure,
				Status: metav1.ConditionTrue,
			})
			result, err := r.handleRoutes(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      "example-authentication",
						Namespace: "data-ns",
					},
				},
			)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			routes := &routev1.RouteList{}
			listOpts := []client.ListOption{
				client.InNamespace("data-ns"),
			}
			err = r.List(ctx, routes, listOpts...)
			Expect(err).ToNot(HaveOccurred())
			hasAllValidRoutes(routes)
		})

		It("skips deleting Routes when ZenExtension Status is not completed", func() {
			createDummyRoutes()
			By("setting Successful Condition to false")
			frontdoor.Status.Status = "In Progress"
			result, err := r.handleRoutes(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      "example-authentication",
						Namespace: "data-ns",
					},
				},
			)
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			routes := &routev1.RouteList{}
			listOpts := []client.ListOption{
				client.InNamespace("data-ns"),
			}
			err = r.List(ctx, routes, listOpts...)
			Expect(err).ToNot(HaveOccurred())
			hasAllValidRoutes(routes)
		})

		It("continues reconciling when Routes API not available", func() {
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(routev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme)
			cl = cb.Build()
			ctx = context.Background()
			By("ensuring Routes API is not available")
			err := envtest.UninstallCRDs(cfg, envtest.CRDInstallOptions{
				Paths: []string{filepath.Join(".", "testdata", "crds", "routes")},
			})
			Expect(err).ToNot(HaveOccurred())

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, err = w.Write([]byte{})
				Expect(err).ToNot(HaveOccurred())
			}))
			defer server.Close()
			dc := discovery.NewDiscoveryClientForConfigOrDie(&restclient.Config{Host: server.URL})
			resources, err := dc.ServerResourcesForGroupVersion(strings.Join([]string{routev1.GroupVersion.Group, routev1.GroupVersion.Version}, "/"))
			Expect(err).To(HaveOccurred())
			Expect(resources).To(BeNil())
			r = &AuthenticationReconciler{
				Client:          cl,
				DiscoveryClient: *dc,
			}
			result, err := r.handleRoutes(ctx,
				ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      "example-authentication",
						Namespace: "data-ns",
					},
				},
			)
			testutil.ConfirmThatItContinuesReconciling(result, err)
			routes := &routev1.RouteList{}
			listOpts := []client.ListOption{
				client.InNamespace("data-ns"),
			}
			err = r.List(ctx, routes, listOpts...)
			Expect(err).ToNot(HaveOccurred())
			Expect(routes.Items).To(HaveLen(0))
		})

	})
})
