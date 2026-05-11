//
// Copyright 2024 IBM Corporation
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
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strconv"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	testutil "github.com/IBM/ibm-iam-operator/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type objectUpdater[T client.Object] struct {
	name   string
	kind   string
	authCR *operatorv1alpha1.Authentication
	client.Client
}

func (d objectUpdater[T]) GetEmptyObject() client.Object {
	rType := reflect.TypeFor[T]().Elem()
	return reflect.New(rType).Interface().(T)
}

func (d objectUpdater[T]) GetKind() string {
	return d.kind
}

func (d objectUpdater[T]) GetName() string {
	return d.name
}

func (d objectUpdater[T]) GetNamespace() string {
	return d.authCR.Namespace
}

func (d objectUpdater[T]) GetClient() client.Client {
	return d.Client
}

var _ = Describe("ConfigMap handling", func() {

	Describe("how controller determines whether it is configured for CNCF", func() {
		var r *AuthenticationReconciler
		var authCR *operatorv1alpha1.Authentication
		var cb fakeclient.ClientBuilder
		var cl client.WithWatch
		var scheme *runtime.Scheme
		var ctx context.Context
		var globalConfigMap *corev1.ConfigMap
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
			globalConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibm-cpp-config",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"kubernetes_cluster_type": "cncf",
					"domain_name":             "example.ibm.com",
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(batchv1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(globalConfigMap, authCR)
			cl = cb.Build()
			dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			Expect(err).NotTo(HaveOccurred())

			r = &AuthenticationReconciler{
				Client: &ctrlcommon.FallbackClient{
					Client: cl,
					Reader: cl,
				},
				DiscoveryClient: *dc,
			}
			ctx = context.Background()
		})
		It("retrieves the domain name when configured for CNCF", func() {
			dn, err := GetCNCFDomain(ctx, r.Client, authCR)
			Expect(err).NotTo(HaveOccurred())
			Expect(dn).To(Equal("example.ibm.com"))
		})
		It("retrieves nothing when not configured for CNCF", func() {
			globalConfigMap.Data["kubernetes_cluster_type"] = "other"
			r.Update(ctx, globalConfigMap)
			dn, err := GetCNCFDomain(ctx, r.Client, authCR)
			Expect(err).NotTo(HaveOccurred())
			Expect(dn).To(Equal(""))
		})
		It("produces an error when ibm-cpp-config does not have domain_name set", func() {
			delete(globalConfigMap.Data, "domain_name")
			r.Update(ctx, globalConfigMap)
			dn, err := GetCNCFDomain(ctx, r.Client, authCR)
			Expect(err).To(HaveOccurred())
			Expect(dn).To(Equal(""))
			Expect(err.Error()).To(Equal("domain name not configured"))
		})
		It("produces an error when ibm-cpp-config isn't found", func() {
			r.Delete(ctx, globalConfigMap)
			dn, err := GetCNCFDomain(ctx, r.Client, authCR)
			Expect(dn).To(Equal(""))
			Expect(err).To(HaveOccurred())
		})
		It("objectDetails", func() {
			d := objectUpdater[*corev1.Secret]{
				authCR: authCR,
				name:   "name",
			}
			_, ok := d.GetEmptyObject().(*corev1.Secret)
			Expect(ok).To(BeTrue())
			_, ok = d.GetEmptyObject().(*corev1.ConfigMap)
			Expect(ok).To(BeFalse())
		})
	})

	Describe("ibmcloud-cluster-info handling", func() {
		var r *AuthenticationReconciler
		var authCR *operatorv1alpha1.Authentication
		var cb fakeclient.ClientBuilder
		var cl client.WithWatch
		var scheme *runtime.Scheme
		var ctx context.Context
		var globalConfigMap *corev1.ConfigMap
		var ibmcloudClusterInfo *corev1.ConfigMap
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
				Spec: operatorv1alpha1.AuthenticationSpec{
					Config: operatorv1alpha1.ConfigSpec{
						OnPremMultipleDeploy: true,
					},
				},
			}
			globalConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibm-cpp-config",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"kubernetes_cluster_type": "cncf",
					"domain_name":             "example.ibm.com",
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(batchv1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(globalConfigMap, authCR)
			cl = cb.Build()
			dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			Expect(err).NotTo(HaveOccurred())

			r = &AuthenticationReconciler{
				Client: &ctrlcommon.FallbackClient{
					Client: cl,
					Reader: cl,
				},
				DiscoveryClient: *dc,
			}
			ctx = context.Background()
			ibmcloudClusterInfo = &corev1.ConfigMap{}
		})
		It("creates ibmcloud-cluster-info when it is not already present in services namespace", func() {
			result, err := r.handleIBMCloudClusterInfo(ctx, authCR, ibmcloudClusterInfo)
			cmKey := types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			observed := &corev1.ConfigMap{}
			err = r.Get(ctx, cmKey, observed)
			Expect(err).ToNot(HaveOccurred())
			Expect(observed).ToNot(BeNil())
		})
		It("does not require a requeue or perform updates when observed state is the same as calculated state", func() {
			ibmcloudClusterInfo = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "operator.ibm.com/v1alpha1",
							Kind:               "Authentication",
							Name:               "example-authentication",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					Labels: map[string]string{
						"app": "auth-idp",
					},
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"im_idprovider_endpoint":    "https://platform-identity-provider.data-ns.svc:4300",
					"proxy_address":             "cp-console-data-ns.example.ibm.com",
					"cluster_address":           "cp-console-data-ns.example.ibm.com",
					"cluster_address_auth":      "cp-console-data-ns.example.ibm.com",
					"cluster_endpoint":          "https://cp-console-data-ns.example.ibm.com",
					"cluster_name":              "mycluster",
					"cluster_router_http_port":  "80",
					"cluster_router_https_port": "443",
					"im_idmgmt_endpoint":        "https://platform-identity-management.data-ns.svc:4500",
				},
			}
			ibmcloudClusterInfoCopy := ibmcloudClusterInfo.DeepCopy()
			Expect(r.Create(ctx, ibmcloudClusterInfo)).To(Succeed())
			result, err := r.handleIBMCloudClusterInfo(ctx, authCR, ibmcloudClusterInfo)
			Expect(err).ToNot(HaveOccurred())
			cmKey := types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}
			observed := &corev1.ConfigMap{}
			err = r.Get(ctx, cmKey, observed)
			Expect(err).ToNot(HaveOccurred())
			Expect(ibmcloudClusterInfo.Data).ToNot(BeNil())
			Expect(ibmcloudClusterInfo.Data).To(Equal(ibmcloudClusterInfoCopy.Data))
			testutil.ConfirmThatItContinuesReconciling(result, err)
		})
		It("produces an error when ibm-cpp-config does not have domain_name set", func() {
			ibmcloudClusterInfo = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "operator.ibm.com/v1alpha1",
							Kind:               "Authentication",
							Name:               "example-authentication",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					Labels: map[string]string{
						"app": "auth-idp",
					},
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"im_idprovider_endpoint":    "https://platform-identity-provider.data-ns.svc:4300",
					"proxy_address":             "cp-console-data-ns.example.ibm.com",
					"cluster_address":           "cp-console-data-ns.example.ibm.com",
					"cluster_address_auth":      "cp-console-data-ns.example.ibm.com",
					"cluster_endpoint":          "https://cp-console-data-ns.example.ibm.com",
					"cluster_name":              "mycluster",
					"cluster_router_http_port":  "80",
					"cluster_router_https_port": "443",
					"im_idmgmt_endpoint":        "https://platform-identity-management.data-ns.svc:4500",
				},
			}
			Expect(r.Create(ctx, ibmcloudClusterInfo)).To(Succeed())
			result, err := r.handleIBMCloudClusterInfo(ctx, authCR, ibmcloudClusterInfo)
			cmKey := types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}
			testutil.ConfirmThatItContinuesReconciling(result, err)
			observed := &corev1.ConfigMap{}
			err = r.Get(ctx, cmKey, observed)
			Expect(err).ToNot(HaveOccurred())
			Expect(ibmcloudClusterInfo.Data).ToNot(BeNil())
		})
		It("only updates ibmcloud-cluster-info when ownership and labels do not match expected values", func() {
			globalConfigMap.Data["domain_name"] = "example1.ibm.com"
			Expect(r.Update(ctx, globalConfigMap)).To(Succeed())
			ibmcloudClusterInfo = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"im_idprovider_endpoint":    "https://platform-identity-provider.different-ns.svc:4300",
					"proxy_address":             "cp-console-different-ns.example.ibm.com",
					"cluster_address":           "cp-console-different-ns.example.ibm.com",
					"cluster_address_auth":      "cp-console-different-ns.example.ibm.com",
					"cluster_endpoint":          "https://cp-console-different-ns.example.ibm.com",
					"cluster_name":              "mycluster",
					"cluster_router_http_port":  "80",
					"cluster_router_https_port": "443",
					"im_idmgmt_endpoint":        "https://platform-identity-management.different-ns.svc:4500",
				},
			}
			Expect(r.Create(ctx, ibmcloudClusterInfo)).To(Succeed())
			result, err := r.handleIBMCloudClusterInfo(ctx, authCR, ibmcloudClusterInfo)
			cmKey := types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			observed := &corev1.ConfigMap{}
			err = r.Get(ctx, cmKey, observed)
			Expect(err).ToNot(HaveOccurred())
			Expect(observed.Data).ToNot(BeNil())
			Expect(observed.Labels).ToNot(BeNil())
			Expect(observed.Labels["app"]).To(Equal("auth-idp"))
			Expect(observed.OwnerReferences).ToNot(BeEmpty())
			Expect(*observed.OwnerReferences[0].Controller).To(BeTrue())
		})

		It("updates ibmcloud-cluster-info when cluster_address_auth is not set", func() {
			globalConfigMap.Data["domain_name"] = "example1.ibm.com"
			Expect(r.Update(ctx, globalConfigMap)).To(Succeed())
			ibmcloudClusterInfo = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "operator.ibm.com/v1alpha1",
							Kind:               "Authentication",
							Name:               "example-authentication",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					Labels: map[string]string{
						"app": "auth-idp",
					},
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"im_idprovider_endpoint":    "https://platform-identity-provider.data-ns.svc:4300",
					"proxy_address":             "cp-console-data-ns.example.ibm.com",
					"cluster_address":           "cp-console-data-ns.example.ibm.com",
					"cluster_endpoint":          "https://cp-console-data-ns.example.ibm.com",
					"cluster_name":              "mycluster",
					"cluster_router_http_port":  "80",
					"cluster_router_https_port": "443",
					"im_idmgmt_endpoint":        "https://platform-identity-management.data-ns.svc:4500",
				},
			}
			Expect(r.Create(ctx, ibmcloudClusterInfo)).To(Succeed())
			result, err := r.handleIBMCloudClusterInfo(ctx, authCR, ibmcloudClusterInfo)
			cmKey := types.NamespacedName{Name: "ibmcloud-cluster-info", Namespace: "data-ns"}
			testutil.ConfirmThatItRequeuesWithDelay(result, err, defaultLowerWait)
			observed := &corev1.ConfigMap{}
			err = r.Get(ctx, cmKey, observed)
			Expect(err).ToNot(HaveOccurred())
			Expect(observed.Data).ToNot(BeNil())
			Expect(observed.Data["cluster_address_auth"]).To(Equal("cp-console-data-ns.example1.ibm.com"))
			Expect(observed.Labels).ToNot(BeNil())
			Expect(observed.Labels["app"]).To(Equal("auth-idp"))
			Expect(observed.OwnerReferences).ToNot(BeEmpty())
			Expect(*observed.OwnerReferences[0].Controller).To(BeTrue())
		})
	})

	generateAuthCR := func(ns string) (authCR *operatorv1alpha1.Authentication) {
		authCR = &operatorv1alpha1.Authentication{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "operator.ibm.com/v1alpha1",
				Kind:       "Authentication",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "example-authentication",
				Namespace:       fmt.Sprintf("%s-%d", ns, rand.Intn(500)),
				ResourceVersion: trackerAddResourceVersion,
			},
			Spec: operatorv1alpha1.AuthenticationSpec{
				Config: operatorv1alpha1.ConfigSpec{
					ClusterName:           "mycluster",
					ClusterCADomain:       "domain.example.com",
					DefaultAdminUser:      "myadmin",
					ZenFrontDoor:          true,
					PreferredLogin:        "ldap",
					ProviderIssuerURL:     "example.com",
					ROKSURL:               "",
					ROKSEnabled:           false,
					FIPSEnabled:           true,
					NONCEEnabled:          true,
					OIDCIssuerURL:         "oidc.example.com",
					SaasClientRedirectUrl: "saasclient.example.com",
					ClaimsMap:             "someclaims",
					ScopeClaim:            "scopeclaimexample",
					IsOpenshiftEnv:        false,
				},
			},
		}
		return
	}

	Describe("platform-auth-idp handling", func() {
		var r *AuthenticationReconciler
		var authCR *operatorv1alpha1.Authentication
		var cb fakeclient.ClientBuilder
		var cl client.WithWatch
		var scheme *runtime.Scheme
		var ctx context.Context
		var globalConfigMap *corev1.ConfigMap
		var ibmcloudClusterInfo *corev1.ConfigMap
		var updated bool
		var imHasSAMLJob *batchv1.Job
		var imHasSAMLPod *corev1.Pod
		BeforeEach(func() {
			authCR = generateAuthCR("data-ns")
			globalConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibm-cpp-config",
					Namespace: authCR.Namespace,
				},
				Data: map[string]string{
					"kubernetes_cluster_type": "cncf",
					"domain_name":             "example.ibm.com",
				},
			}
			ibmcloudClusterInfo = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: authCR.Namespace,
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "operator.ibm.com/v1alpha1",
							Kind:               "Authentication",
							Name:               "example-authentication",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					Labels: map[string]string{
						"app": "auth-idp",
					},
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"im_idprovider_endpoint":    "https://platform-identity-provider.data-ns.svc:4300",
					"proxy_address":             "cp-console-data-ns.example.ibm.com",
					"cluster_address":           "cp-console-data-ns.example.ibm.com",
					"cluster_endpoint":          "https://cp-console-data-ns.example.ibm.com",
					"cluster_name":              "mycluster",
					"cluster_router_http_port":  "80",
					"cluster_router_https_port": "443",
					"im_idmgmt_endpoint":        "https://platform-identity-management.data-ns.svc:4500",
				},
			}
			imHasSAMLJob = &batchv1.Job{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "batch/v1",
					Kind:       "Job",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "im-has-saml",
					Namespace: authCR.Namespace,
					UID:       types.UID("96467cef-a1d2-455c-97be-eae3d6196e95"),
				},
				Spec: batchv1.JobSpec{},
			}
			imHasSAMLPod = &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "im-has-saml-pod",
					Namespace: authCR.Namespace,
					Labels: map[string]string{
						"batch.kubernetes.io/controller-uid": "96467cef-a1d2-455c-97be-eae3d6196e95",
						"batch.kubernetes.io/job-name":       "im-has-saml",
					},
				},
				Spec: corev1.PodSpec{},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name: "im-has-saml",
							State: corev1.ContainerState{
								Terminated: &corev1.ContainerStateTerminated{
									ExitCode: 0,
								},
							},
						},
					},
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(batchv1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(globalConfigMap, ibmcloudClusterInfo, authCR, imHasSAMLJob, imHasSAMLPod)
			cl = cb.Build()
			dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			Expect(err).NotTo(HaveOccurred())

			r = &AuthenticationReconciler{
				Client: &ctrlcommon.FallbackClient{
					Client: cl,
					Reader: cl,
				},
				DiscoveryClient: *dc,
			}
			ctx = context.Background()
		})

		getObserved := func(ns string) *corev1.ConfigMap {
			return &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: ns,
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "operator.ibm.com/v1alpha1",
							Kind:               "Authentication",
							Name:               "example-authentication",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					Labels: map[string]string{
						"app": "auth-idp",
					},
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					// primary keys that affect updates of other keys
					"DB_SSL_MODE":                  "require",
					"SCIM_LDAP_ATTRIBUTES_MAPPING": scimLdapAttributesMapping,
					"SCIM_AUTH_CACHE_MAX_SIZE":     "1000",
					"SCIM_AUTH_CACHE_TTL_VALUE":    "60",
					"AUTH_SVC_LDAP_CONFIG_TIMEOUT": "25",
					"IBM_CLOUD_SAAS":               "false",
					"ATTR_MAPPING_FROM_CONFIG":     "false",
					"LDAP_CTX_POOL_INITSIZE":       "10",
					"DB_CONNECT_TIMEOUT":           "60000",
					"PREFERRED_LOGIN":              "ldap",
					"PROVIDER_ISSUER_URL":          "example.com",
					"CLAIMS_SUPPORTED":             "false",
					"LDAP_RECURSIVE_SEARCH":        "true",
					// the rest
					"BASE_AUTH_URL":                      "/v1",
					"BASE_OIDC_URL":                      "https://platform-auth-service:9443/oidc/endpoint/OP",
					"CLUSTER_NAME":                       authCR.Spec.Config.ClusterName,
					"HTTP_ONLY":                          "false",
					"IDENTITY_AUTH_DIRECTORY_URL":        "https://platform-auth-service:3100",
					"IDENTITY_PROVIDER_URL":              "https://platform-identity-provider:4300",
					"IDENTITY_MGMT_URL":                  "https://platform-identity-management:4500",
					"MASTER_HOST":                        ibmcloudClusterInfo.Data["cluster_address"],
					"MASTER_PATH":                        "/idauth",
					"AUDIT_URL":                          "",
					"AUDIT_SECRET":                       "",
					"NODE_ENV":                           "production",
					"ENABLE_JIT_EXTRA_ATTR":              "false",
					"AUDIT_ENABLED_IDPROVIDER":           "false",
					"AUDIT_ENABLED_IDMGMT":               "false",
					"AUDIT_DETAIL":                       "false",
					"LOG_LEVEL_IDPROVIDER":               "info",
					"LOG_LEVEL_AUTHSVC":                  "info",
					"LOG_LEVEL_IDMGMT":                   "info",
					"LOG_LEVEL_MW":                       "info",
					"DEFAULT_LOGIN":                      "",
					"IDTOKEN_LIFETIME":                   "12h",
					"SESSION_TIMEOUT":                    "43200s",
					"OIDC_ISSUER_URL":                    authCR.Spec.Config.OIDCIssuerURL,
					"PDP_REDIS_CACHE_DEFAULT_TTL":        "600",
					"FIPS_ENABLED":                       strconv.FormatBool(authCR.Spec.Config.FIPSEnabled),
					"NONCE_ENABLED":                      strconv.FormatBool(authCR.Spec.Config.NONCEEnabled),
					"ROKS_ENABLED":                       strconv.FormatBool(authCR.Spec.Config.ROKSEnabled),
					"SAAS_CLIENT_REDIRECT_URL":           authCR.Spec.Config.SaasClientRedirectUrl,
					"ROKS_URL":                           "",
					"ROKS_USER_PREFIX":                   "changeme",
					"CLAIMS_MAP":                         authCR.Spec.Config.ClaimsMap,
					"SCOPE_CLAIM":                        authCR.Spec.Config.ScopeClaim,
					"BOOTSTRAP_USERID":                   "kubeadmin",
					"LIBERTY_TOKEN_LENGTH":               "1024",
					"OS_TOKEN_LENGTH":                    "51",
					"LIBERTY_DEBUG_ENABLED":              "false",
					"LOGJAM_DHKEYSIZE_2048_BITS_ENABLED": "true",
					"LDAP_ATTR_CACHE_SIZE":               "2000",
					"LDAP_ATTR_CACHE_TIMEOUT":            "1200s",
					"LDAP_ATTR_CACHE_ENABLED":            "true",
					"LDAP_ATTR_CACHE_SIZELIMIT":          "2000",
					"LDAP_SEARCH_CACHE_SIZE":             "2000",
					"LDAP_SEARCH_CACHE_TIMEOUT":          "1200s",
					"LDAP_SEARCH_CACHE_ENABLED":          "true",
					"LDAP_SEARCH_CACHE_SIZELIMIT":        "2000",
					"IGNORE_LDAP_FILTERS_VALIDATION":     "false",
					"LDAP_SEARCH_EXCLUDE_WILDCARD_CHARS": "false",
					"LDAP_SEARCH_SIZE_LIMIT":             "50",
					"LDAP_SEARCH_TIME_LIMIT":             "10",
					"LDAP_SEARCH_CN_ATTR_ONLY":           "false",
					"LDAP_SEARCH_ID_ATTR_ONLY":           "false",
					"LDAP_CTX_POOL_MAXSIZE":              "50",
					"LDAP_CTX_POOL_TIMEOUT":              "30s",
					"LDAP_CTX_POOL_WAITTIME":             "60s",
					"LDAP_CTX_POOL_PREFERREDSIZE":        "10",
					"SAML_NAMEID_FORMAT":                 "unspecified",
					"DB_IDLE_TIMEOUT":                    "20000",
					"DB_CONNECT_MAX_RETRIES":             "5",
					"DB_POOL_MIN_SIZE":                   "5",
					"DB_POOL_MAX_SIZE":                   "15",
					"SEQL_LOGGING":                       "false",
					"SCIM_LDAP_SEARCH_SIZE_LIMIT":        "4500",
					"SCIM_LDAP_SEARCH_TIME_LIMIT":        "10",
					"SCIM_ASYNC_PARALLEL_LIMIT":          "100",
					"SCIM_GET_DISPLAY_FOR_GROUP_USERS":   "true",
					"IS_OPENSHIFT_ENV":                   "false",
				},
			}
		}

		It("sets certain values when other values are not set", func() {
			// Value used to confirm that certain values are overwritten

			updateOnNotSetKeys := []struct {
				primaryKey string
				keys       []string
			}{
				{
					"LDAP_RECURSIVE_SEARCH",
					[]string{"LDAP_RECURSIVE_SEARCH"},
				},
				{
					"DEFAULT_LOGIN",
					[]string{"DEFAULT_LOGIN"},
				},
				{
					"DB_CONNECT_TIMEOUT",
					[]string{
						"DB_CONNECT_TIMEOUT",
						"DB_IDLE_TIMEOUT",
						"DB_CONNECT_MAX_RETRIES",
						"DB_POOL_MIN_SIZE",
						"DB_POOL_MAX_SIZE",
						"SEQL_LOGGING",
					},
				},
				{
					"DB_SSL_MODE",
					[]string{
						"DB_SSL_MODE",
					},
				},
				{
					"AUDIT_URL",
					[]string{
						"AUDIT_URL",
						"AUDIT_SECRET",
					},
				},
				{
					"OAUTH_21_ENABLED",
					[]string{
						"OAUTH_21_ENABLED",
					},
				},
				{
					"IAM_UM",
					[]string{
						"IAM_UM",
					},
				},
				{
					"ACCOUNT_IAM_URL",
					[]string{
						"ACCOUNT_IAM_URL",
					},
				},
				{
					"LIBERTY_SAMESITE_COOKIE",
					[]string{
						"LIBERTY_SAMESITE_COOKIE",
					},
				},
				{
					"SCIM_LDAP_ATTRIBUTES_MAPPING",
					[]string{
						"SCIM_LDAP_ATTRIBUTES_MAPPING",
						"SCIM_LDAP_SEARCH_SIZE_LIMIT",
						"SCIM_LDAP_SEARCH_TIME_LIMIT",
						"SCIM_ASYNC_PARALLEL_LIMIT",
						"SCIM_GET_DISPLAY_FOR_GROUP_USERS",
					},
				},
				{
					"SCIM_AUTH_CACHE_MAX_SIZE",
					[]string{
						"SCIM_AUTH_CACHE_MAX_SIZE",
					},
				},
				{
					"SCIM_AUTH_CACHE_TTL_VALUE",
					[]string{
						"SCIM_AUTH_CACHE_TTL_VALUE",
					},
				},
				{
					"AUTH_SVC_LDAP_CONFIG_TIMEOUT",
					[]string{
						"AUTH_SVC_LDAP_CONFIG_TIMEOUT",
					},
				},
				{
					"IBM_CLOUD_SAAS",
					[]string{
						"IBM_CLOUD_SAAS",
						"SAAS_CLIENT_REDIRECT_URL",
					},
				},
				{
					"ATTR_MAPPING_FROM_CONFIG",
					[]string{
						"ATTR_MAPPING_FROM_CONFIG",
					},
				},
				{
					"LDAP_CTX_POOL_INITSIZE",
					[]string{
						"LDAP_CTX_POOL_INITSIZE",
						"LDAP_CTX_POOL_MAXSIZE",
						"LDAP_CTX_POOL_TIMEOUT",
						"LDAP_CTX_POOL_WAITTIME",
						"LDAP_CTX_POOL_PREFERREDSIZE",
					},
				},
				{
					"LIBERTY_AUTH_CACHE_TIMEOUT",
					[]string{
						"LIBERTY_AUTH_CACHE_TIMEOUT",
					},
				},
				{
					"LDAP_CLIENT_CONNECT_TIMEOUT",
					[]string{
						"LDAP_CLIENT_CONNECT_TIMEOUT",
					},
				},
			}

			setDummyData := func(pkey string, keys []string, o *corev1.ConfigMap) {
				dummyValue := "dummy"
				for _, k := range keys {
					if k == pkey {
						delete(o.Data, k)
						continue
					}
					o.Data[k] = dummyValue
				}
			}

			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			for _, test := range updateOnNotSetKeys {
				observed := &corev1.ConfigMap{}
				r.Create(ctx, &batchv1.Job{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "batch/v1",
						Kind:       "Job",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "im-has-saml",
						Namespace: authCR.Namespace,
						UID:       types.UID("96467cef-a1d2-455c-97be-eae3d6196e95"),
					},
					Spec: batchv1.JobSpec{},
				})
				Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, observed)).
					To(Succeed())

				r.Create(ctx, &batchv1.Job{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "batch/v1",
						Kind:       "Job",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "im-has-saml",
						Namespace: authCR.Namespace,
						UID:       types.UID("96467cef-a1d2-455c-97be-eae3d6196e95"),
					},
					Spec: batchv1.JobSpec{},
				})
				generated := &corev1.ConfigMap{}
				err := r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
				Expect(err).NotTo(HaveOccurred())
				updated, err = updatePlatformAuthIDP(resource, ctx, observed, generated)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue()) // Update happens due to SHA change
				setDummyData(test.primaryKey, test.keys, observed)
				updated, err = updatePlatformAuthIDP(resource, ctx, observed, generated)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated).To(BeTrue())
				for _, k := range test.keys {
					Expect(observed.Data[k]).To(Equal(generated.Data[k]))
				}
			}
		})

		It("sets fields when the values do not match the expected value", func() {
			updateOnNotUpToDate := []struct {
				primaryKey string
				keys       []string
			}{
				{
					"DEFAULT_LOGIN",
					[]string{"DEFAULT_LOGIN"},
				},
			}

			setDummyData := func(_ string, keys []string, o *corev1.ConfigMap) {
				dummyValue := "dummy"
				for _, k := range keys {
					o.Data[k] = dummyValue
				}
			}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			for _, test := range updateOnNotUpToDate {
				observed := &corev1.ConfigMap{}
				r.Create(ctx, &batchv1.Job{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "batch/v1",
						Kind:       "Job",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "im-has-saml",
						Namespace: authCR.Namespace,
						UID:       types.UID("96467cef-a1d2-455c-97be-eae3d6196e95"),
					},
					Spec: batchv1.JobSpec{},
				})
				Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, observed)).
					To(Succeed())
				generated := &corev1.ConfigMap{}
				r.Create(ctx, &batchv1.Job{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "batch/v1",
						Kind:       "Job",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "im-has-saml",
						Namespace: authCR.Namespace,
						UID:       types.UID("96467cef-a1d2-455c-97be-eae3d6196e95"),
					},
					Spec: batchv1.JobSpec{},
				})
				err := r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
				Expect(err).NotTo(HaveOccurred())
				updated, err = updatePlatformAuthIDP(resource, ctx, observed, generated)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue()) // Update happens due to SHA change
				setDummyData(test.primaryKey, test.keys, observed)
				updated, err = updatePlatformAuthIDP(resource, ctx, observed, generated)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated).To(BeTrue())
				for _, k := range test.keys {
					Expect(observed.Data[k]).To(Equal(generated.Data[k]))
				}
			}
		})

		It("replaces fields using 127.0.0.1 with the Service domain", func() {
			updateWhenLocalhostUsed := []string{
				"IDENTITY_MGMT_URL",
				"BASE_OIDC_URL",
				"IDENTITY_AUTH_DIRECTORY_URL",
				"IDENTITY_PROVIDER_URL",
			}

			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			for _, k := range updateWhenLocalhostUsed {
				observed := getObserved(authCR.Namespace)
				// Set the keys in observed to contain localhost IP
				observed.Data[k] = "https://127.0.0.1:12345"
				generated := &corev1.ConfigMap{}
				r.Create(ctx, &batchv1.Job{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "batch/v1",
						Kind:       "Job",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "im-has-saml",
						Namespace: authCR.Namespace,
						UID:       types.UID("96467cef-a1d2-455c-97be-eae3d6196e95"),
					},
					Spec: batchv1.JobSpec{},
				})
				Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).
					To(Succeed())
				updated, err := updatePlatformAuthIDP(resource, ctx, observed, generated)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated).To(BeTrue())
				Expect(observed.Data[k]).To(Equal(generated.Data[k]))
			}
		})

		It("replaces value in OS_TOKEN_LENGTH only when it is set to 45", func() {
			observed := &corev1.ConfigMap{}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			r.Create(ctx, &batchv1.Job{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "batch/v1",
					Kind:       "Job",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "im-has-saml",
					Namespace: authCR.Namespace,
					UID:       types.UID("96467cef-a1d2-455c-97be-eae3d6196e95"),
				},
				Spec: batchv1.JobSpec{},
			})
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, observed)).
				To(Succeed())
			// Set the keys in observed to contain localhost IP
			k := "OS_TOKEN_LENGTH"
			observed.Data[k] = "24"
			generated := &corev1.ConfigMap{}
			r.Create(ctx, &batchv1.Job{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "batch/v1",
					Kind:       "Job",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "im-has-saml",
					Namespace: authCR.Namespace,
					UID:       types.UID("96467cef-a1d2-455c-97be-eae3d6196e95"),
				},
				Spec: batchv1.JobSpec{},
			})
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).
				To(Succeed())
			updated, err := updatePlatformAuthIDP(resource, ctx, observed, generated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated).To(BeTrue()) // Update happens due to SHA change
			Expect(observed.Data[k]).NotTo(Equal(generated.Data[k]))
			observed.Data[k] = "45"
			updated, err = updatePlatformAuthIDP(resource, ctx, observed, generated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated).To(BeTrue())
			Expect(observed.Data[k]).To(Equal(generated.Data[k]))
		})

		It("always replaces certain values if they differ", func() {
			updateAlways := []string{
				"ROKS_URL",
				"ROKS_USER_PREFIX",
				"ROKS_ENABLED",
				"BOOTSTRAP_USERID",
				"CLAIMS_SUPPORTED",
				"CLAIMS_MAP",
				"SCOPE_CLAIM",
				"NONCE_ENABLED",
				"PREFERRED_LOGIN",
				"OIDC_ISSUER_URL",
				"PROVIDER_ISSUER_URL",
				"CLUSTER_NAME",
			}

			setDummyData := func(k string, o *corev1.ConfigMap) {
				dummyValue := "dummy"
				o.Data[k] = dummyValue
			}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			for _, test := range updateAlways {
				observed := getObserved(authCR.Namespace)
				r.Create(ctx, &batchv1.Job{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "batch/v1",
						Kind:       "Job",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "im-has-saml",
						Namespace: authCR.Namespace,
						UID:       types.UID("96467cef-a1d2-455c-97be-eae3d6196e95"),
					},
					Spec: batchv1.JobSpec{},
				})
				Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, observed)).
					To(Succeed())
				generated := &corev1.ConfigMap{}
				r.Create(ctx, &batchv1.Job{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "batch/v1",
						Kind:       "Job",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "im-has-saml",
						Namespace: authCR.Namespace,
						UID:       types.UID("96467cef-a1d2-455c-97be-eae3d6196e95"),
					},
					Spec: batchv1.JobSpec{},
				})
				Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).
					To(Succeed())
				updated, err := updatePlatformAuthIDP(resource, ctx, observed, generated)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeTrue()) // Update happens due to SHA change
				setDummyData(test, observed)
				Expect(observed.Data[test]).To(Equal("dummy"))
				updated, err = updatePlatformAuthIDP(resource, ctx, observed, generated)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated).To(BeTrue())
				Expect(observed.Data[test]).To(Equal(generated.Data[test]))
			}
		})

		It("sets EXPOSE_ADDITIONAL_PATHS to true when .spec.config.ingress.gvk is 'none'", func() {
			gvk := "none"
			authCR.Spec.Config.Ingress = &operatorv1alpha1.IngressConfig{
				GVK: &gvk,
			}
			Expect(r.Update(ctx, authCR)).To(Succeed())

			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).
				To(Succeed())

			Expect(generated.Data).To(HaveKeyWithValue("EXPOSE_ADDITIONAL_PATHS", "true"))
		})

		It("sets EXPOSE_ADDITIONAL_PATHS to false when .spec.config.ingress.gvk is 'openshift.io/v1/route'", func() {
			// Configure for OpenShift environment (not CNCF)
			delete(globalConfigMap.Data, "kubernetes_cluster_type")
			Expect(r.Update(ctx, globalConfigMap)).To(Succeed())

			gvk := "openshift.io/v1/route"
			authCR.Spec.Config.Ingress = &operatorv1alpha1.IngressConfig{
				GVK: &gvk,
			}
			Expect(r.Update(ctx, authCR)).To(Succeed())

			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).
				To(Succeed())

			Expect(generated.Data).To(HaveKeyWithValue("EXPOSE_ADDITIONAL_PATHS", "false"))
		})

		It("sets EXPOSE_ADDITIONAL_PATHS to false when .spec.config.ingress.gvk is unspecified on OpenShift", func() {
			// Configure for OpenShift environment (not CNCF) - remove kubernetes_cluster_type to make isOSEnv true
			delete(globalConfigMap.Data, "kubernetes_cluster_type")
			Expect(r.Update(ctx, globalConfigMap)).To(Succeed())

			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).
				To(Succeed())

			Expect(generated.Data).To(HaveKeyWithValue("EXPOSE_ADDITIONAL_PATHS", "false"))
		})

		It("sets EXPOSE_ADDITIONAL_PATHS to true when running on CNCF cluster", func() {
			// Update ibm-cpp-config to indicate CNCF cluster
			globalConfigMap.Data["kubernetes_cluster_type"] = "cncf"
			globalConfigMap.Data["domain_name"] = "example.ibm.com"
			Expect(r.Update(ctx, globalConfigMap)).To(Succeed())

			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).
				To(Succeed())

			Expect(generated.Data).To(HaveKeyWithValue("EXPOSE_ADDITIONAL_PATHS", "true"))
		})

		It("sets EXPOSE_ADDITIONAL_PATHS to true when gvk='none' even on OpenShift", func() {
			// Configure for OpenShift environment (not CNCF) - remove kubernetes_cluster_type to make isOSEnv true
			delete(globalConfigMap.Data, "kubernetes_cluster_type")
			Expect(r.Update(ctx, globalConfigMap)).To(Succeed())

			gvk := "none"
			authCR.Spec.Config.Ingress = &operatorv1alpha1.IngressConfig{
				GVK: &gvk,
			}
			Expect(r.Update(ctx, authCR)).To(Succeed())

			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).
				To(Succeed())

			Expect(generated.Data).To(HaveKeyWithValue("EXPOSE_ADDITIONAL_PATHS", "true"))
		})

		It("always updates EXPOSE_ADDITIONAL_PATHS field in updatePlatformAuthIDP", func() {
			// Test that EXPOSE_ADDITIONAL_PATHS is in the always-update list
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			// Create observed ConfigMap with different value
			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"EXPOSE_ADDITIONAL_PATHS": "dummy_value",
				},
			}

			// Generate the expected ConfigMap
			generated := &corev1.ConfigMap{}
			r.Create(ctx, &batchv1.Job{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "batch/v1",
					Kind:       "Job",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "im-has-saml",
					Namespace: authCR.Namespace,
					UID:       types.UID("96467cef-a1d2-455c-97be-eae3d6196e95"),
				},
				Spec: batchv1.JobSpec{},
			})
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).
				To(Succeed())

			// Call updatePlatformAuthIDP
			updated, err := updatePlatformAuthIDP(resource, ctx, observed, generated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated).To(BeTrue())

			// Verify that EXPOSE_ADDITIONAL_PATHS was updated to match generated value
			Expect(observed.Data["EXPOSE_ADDITIONAL_PATHS"]).To(Equal(generated.Data["EXPOSE_ADDITIONAL_PATHS"]))
		})

		It("updates EXPOSE_ADDITIONAL_PATHS when value changes from false to true", func() {
			// Start with OpenShift setup (EXPOSE_ADDITIONAL_PATHS should be false)
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"EXPOSE_ADDITIONAL_PATHS": "false",
				},
			}

			// Generate ConfigMap for CNCF cluster (should be true)
			globalConfigMap.Data["kubernetes_cluster_type"] = "cncf"
			globalConfigMap.Data["domain_name"] = "example.ibm.com"
			Expect(r.Update(ctx, globalConfigMap)).To(Succeed())

			generated := &corev1.ConfigMap{}
			r.Create(ctx, &batchv1.Job{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "batch/v1",
					Kind:       "Job",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "im-has-saml",
					Namespace: authCR.Namespace,
					UID:       types.UID("96467cef-a1d2-455c-97be-eae3d6196e95"),
				},
				Spec: batchv1.JobSpec{},
			})
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).
				To(Succeed())

			// Verify generated has true
			Expect(generated.Data["EXPOSE_ADDITIONAL_PATHS"]).To(Equal("true"))

			// Call updatePlatformAuthIDP
			updated, err := updatePlatformAuthIDP(resource, ctx, observed, generated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated).To(BeTrue())

			// Verify that observed was updated to true
			Expect(observed.Data["EXPOSE_ADDITIONAL_PATHS"]).To(Equal("true"))
		})

		It("sets CSP_FRAME_ANCESTORS and CSP_CONNECT_SRC to 'self' when cspExtension is not configured in the auth CR", func() {
			// authCR has no CSPExtension set (nil)
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).To(Succeed())
			Expect(generated.Data).To(HaveKey("CSP_FRAME_ANCESTORS"))
			Expect(generated.Data["CSP_FRAME_ANCESTORS"]).To(Equal("'self'"))
			Expect(generated.Data).To(HaveKey("CSP_CONNECT_SRC"))
			Expect(generated.Data["CSP_CONNECT_SRC"]).To(Equal("'self'"))
		})

		It("sets CSP_FRAME_ANCESTORS and CSP_CONNECT_SRC with 'self' prepended when cspExtension is configured in the auth CR", func() {
			authCR.Spec.Config.CSPExtension = &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"https://cpd-zen.apps.cluster.com/", "https://custom-portal.customer.com/"},
				ConnectSrc:     []string{"https://cpd-api.apps.cluster.com/"},
			}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).To(Succeed())
			Expect(generated.Data).To(HaveKey("CSP_FRAME_ANCESTORS"))
			Expect(generated.Data["CSP_FRAME_ANCESTORS"]).To(Equal("'self' https://cpd-zen.apps.cluster.com/ https://custom-portal.customer.com/"))
			Expect(generated.Data).To(HaveKey("CSP_CONNECT_SRC"))
			Expect(generated.Data["CSP_CONNECT_SRC"]).To(Equal("'self' https://cpd-api.apps.cluster.com/"))
		})

		It("sets CSP_FRAME_ANCESTORS with 'self' prepended when only frameAncestors is set and CSP_CONNECT_SRC defaults to 'self'", func() {
			authCR.Spec.Config.CSPExtension = &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"https://cpd-zen.apps.cluster.com/"},
			}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).To(Succeed())
			Expect(generated.Data).To(HaveKey("CSP_FRAME_ANCESTORS"))
			Expect(generated.Data["CSP_FRAME_ANCESTORS"]).To(Equal("'self' https://cpd-zen.apps.cluster.com/"))
			Expect(generated.Data).To(HaveKey("CSP_CONNECT_SRC"))
			Expect(generated.Data["CSP_CONNECT_SRC"]).To(Equal("'self'"))
		})

		It("sets CSP_CONNECT_SRC with 'self' prepended when only connectSrc is set and CSP_FRAME_ANCESTORS defaults to 'self'", func() {
			authCR.Spec.Config.CSPExtension = &operatorv1alpha1.CSPExtensionConfig{
				ConnectSrc: []string{"https://cpd-api.apps.cluster.com/"},
			}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).To(Succeed())
			Expect(generated.Data).To(HaveKey("CSP_FRAME_ANCESTORS"))
			Expect(generated.Data["CSP_FRAME_ANCESTORS"]).To(Equal("'self'"))
			Expect(generated.Data).To(HaveKey("CSP_CONNECT_SRC"))
			Expect(generated.Data["CSP_CONNECT_SRC"]).To(Equal("'self' https://cpd-api.apps.cluster.com/"))
		})

		It("always overwrites CSP_FRAME_ANCESTORS and CSP_CONNECT_SRC in observed configmap from the generated value", func() {
			authCR.Spec.Config.CSPExtension = &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"https://cpd-zen.apps.cluster.com/"},
				ConnectSrc:     []string{"https://cpd-api.apps.cluster.com/"},
			}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			observed := getObserved(authCR.Namespace)
			observed.Data["CSP_FRAME_ANCESTORS"] = "stale-frame-value"
			observed.Data["CSP_CONNECT_SRC"] = "stale-connect-value"
			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).To(Succeed())
			updated, err := updatePlatformAuthIDP(resource, ctx, observed, generated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated).To(BeTrue())
			Expect(observed.Data["CSP_FRAME_ANCESTORS"]).To(Equal(generated.Data["CSP_FRAME_ANCESTORS"]))
			Expect(observed.Data["CSP_CONNECT_SRC"]).To(Equal(generated.Data["CSP_CONNECT_SRC"]))
		})

		It("overwrites CSP_FRAME_ANCESTORS and CSP_CONNECT_SRC in observed configmap with 'self' when cspExtension is removed from auth CR", func() {
			// authCR has no CSPExtension (nil) — simulates removing it after it was previously set
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			observed := getObserved(authCR.Namespace)
			observed.Data["CSP_FRAME_ANCESTORS"] = "https://old-value.example.com/"
			observed.Data["CSP_CONNECT_SRC"] = "https://old-api.example.com/"
			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).To(Succeed())
			Expect(generated.Data["CSP_FRAME_ANCESTORS"]).To(Equal("'self'"))
			Expect(generated.Data["CSP_CONNECT_SRC"]).To(Equal("'self'"))
			updated, err := updatePlatformAuthIDP(resource, ctx, observed, generated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated).To(BeTrue())
			Expect(observed.Data["CSP_FRAME_ANCESTORS"]).To(Equal("'self'"))
			Expect(observed.Data["CSP_CONNECT_SRC"]).To(Equal("'self'"))
		})
		It("returns an error from generateAuthIdpConfigMap when cspExtension contains invalid entries in frameAncestors and connectSrc", func() {
			authCR.Spec.Config.CSPExtension = &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"http://insecure.example.com/"},
				ConnectSrc:     []string{"https://*.wildcard.example.com/"},
			}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			generated := &corev1.ConfigMap{}
			err := r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("frameAncestors"))
			Expect(err.Error()).To(ContainSubstring("connectSrc"))
		})

		It("avoids duplicate 'self' when frameAncestors contains 'self' (unquoted)", func() {
			authCR.Spec.Config.CSPExtension = &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"self", "https://example.com/"},
			}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).To(Succeed())
			Expect(generated.Data["CSP_FRAME_ANCESTORS"]).To(Equal("'self' https://example.com/"))
		})

		It("avoids duplicate 'self' when frameAncestors contains 'self' (quoted)", func() {
			authCR.Spec.Config.CSPExtension = &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"'self'", "https://example.com/"},
			}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).To(Succeed())
			Expect(generated.Data["CSP_FRAME_ANCESTORS"]).To(Equal("'self' https://example.com/"))
		})

		It("avoids duplicate 'self' when connectSrc contains both 'self' forms", func() {
			authCR.Spec.Config.CSPExtension = &operatorv1alpha1.CSPExtensionConfig{
				ConnectSrc: []string{"self", "'self'", "https://api.example.com/"},
			}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).To(Succeed())
			Expect(generated.Data["CSP_CONNECT_SRC"]).To(Equal("'self' https://api.example.com/"))
		})

		It("sets only 'self' when frameAncestors contains only 'self' (unquoted)", func() {
			authCR.Spec.Config.CSPExtension = &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"self"},
			}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).To(Succeed())
			Expect(generated.Data["CSP_FRAME_ANCESTORS"]).To(Equal("'self'"))
		})

		It("sets only 'self' when connectSrc contains only 'self' (quoted)", func() {
			authCR.Spec.Config.CSPExtension = &operatorv1alpha1.CSPExtensionConfig{
				ConnectSrc: []string{"'self'"},
			}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("platform-auth-idp").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			generated := &corev1.ConfigMap{}
			Expect(r.generateAuthIdpConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)).To(Succeed())
			Expect(generated.Data["CSP_CONNECT_SRC"]).To(Equal("'self'"))
		})
	})

	Describe("validate CSPExtension", func() {
		It("returns nil when CSPExtension is nil", func() {
			Expect(validateCSPExtension(nil)).To(Succeed())
		})

		It("returns nil when CSPExtension has empty slices", func() {
			Expect(validateCSPExtension(&operatorv1alpha1.CSPExtensionConfig{})).To(Succeed())
		})

		It("returns nil for valid https URLs in frameAncestors and connectSrc", func() {
			csp := &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{
					"https://cpd-zen.apps.cluster.com/",
					"https://custom-portal.customer.com/",
				},
				ConnectSrc: []string{
					"https://cpd-api.apps.cluster.com/",
				},
			}
			Expect(validateCSPExtension(csp)).To(Succeed())
		})

		It("returns an error when a frameAncestors entry contains a wildcard", func() {
			csp := &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"https://*.example.com/"},
			}
			err := validateCSPExtension(csp)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("frameAncestors"))
			Expect(err.Error()).To(ContainSubstring("wildcard"))
		})

		It("returns an error when a connectSrc entry contains a wildcard", func() {
			csp := &operatorv1alpha1.CSPExtensionConfig{
				ConnectSrc: []string{"https://*.api.example.com/"},
			}
			err := validateCSPExtension(csp)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("connectSrc"))
			Expect(err.Error()).To(ContainSubstring("wildcard"))
		})

		It("returns an error when a frameAncestors entry uses http instead of https", func() {
			csp := &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"http://insecure.example.com/"},
			}
			err := validateCSPExtension(csp)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("frameAncestors"))
			Expect(err.Error()).To(ContainSubstring("not a valid https URL"))
		})

		It("returns an error when a connectSrc entry uses http instead of https", func() {
			csp := &operatorv1alpha1.CSPExtensionConfig{
				ConnectSrc: []string{"http://insecure-api.example.com/"},
			}
			err := validateCSPExtension(csp)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("connectSrc"))
			Expect(err.Error()).To(ContainSubstring("not a valid https URL"))
		})

		It("returns an error when a frameAncestors entry is not a URL at all", func() {
			csp := &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"not-a-url"},
			}
			err := validateCSPExtension(csp)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("frameAncestors"))
			Expect(err.Error()).To(ContainSubstring("not a valid https URL"))
		})

		It("returns an error listing all invalid entries when multiple are invalid", func() {
			csp := &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{
					"https://valid.example.com/",
					"http://bad.example.com/",
					"https://*.wildcard.example.com/",
				},
				ConnectSrc: []string{
					"https://valid-api.example.com/",
					"ftp://wrong-scheme.example.com/",
				},
			}
			err := validateCSPExtension(csp)
			Expect(err).To(HaveOccurred())
			// Should mention both invalid entries
			Expect(err.Error()).To(ContainSubstring(`"http://bad.example.com/"`))
			Expect(err.Error()).To(ContainSubstring(`"https://*.wildcard.example.com/"`))
			Expect(err.Error()).To(ContainSubstring(`"ftp://wrong-scheme.example.com/"`))
			// Should NOT mention the valid entries
			Expect(err.Error()).NotTo(ContainSubstring("valid.example.com"))
			Expect(err.Error()).NotTo(ContainSubstring("valid-api.example.com"))
		})

		It("returns an error when a frameAncestors entry has no host", func() {
			csp := &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"https://"},
			}
			err := validateCSPExtension(csp)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not a valid https URL"))
		})

		It("returns nil when frameAncestors contains 'self' (unquoted)", func() {
			csp := &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"self"},
			}
			Expect(validateCSPExtension(csp)).To(Succeed())
		})

		It("returns nil when frameAncestors contains 'self' (quoted)", func() {
			csp := &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"'self'"},
			}
			Expect(validateCSPExtension(csp)).To(Succeed())
		})

		It("returns nil when both 'self' forms are mixed with valid URLs", func() {
			csp := &operatorv1alpha1.CSPExtensionConfig{
				FrameAncestors: []string{"self", "https://example.com/"},
				ConnectSrc:     []string{"'self'", "https://api.example.com/"},
			}
			Expect(validateCSPExtension(csp)).To(Succeed())
		})
	})

	Describe("oauth-client-map handling", func() {
		var authCR *operatorv1alpha1.Authentication
		var cb fakeclient.ClientBuilder
		var cl client.WithWatch
		var scheme *runtime.Scheme
		var ctx context.Context
		var globalConfigMap *corev1.ConfigMap
		var ibmcloudClusterInfo *corev1.ConfigMap
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
				Spec: operatorv1alpha1.AuthenticationSpec{
					Config: operatorv1alpha1.ConfigSpec{
						ClusterName:              "mycluster",
						ClusterCADomain:          "domain.example.com",
						DefaultAdminUser:         "myadmin",
						ZenFrontDoor:             true,
						PreferredLogin:           "ldap",
						ProviderIssuerURL:        "example.com",
						ROKSURL:                  "",
						ROKSEnabled:              false,
						FIPSEnabled:              true,
						NONCEEnabled:             true,
						OIDCIssuerURL:            "oidc.example.com",
						SaasClientRedirectUrl:    "saasclient.example.com",
						ClaimsMap:                "someclaims",
						ScopeClaim:               "scopeclaimexample",
						IsOpenshiftEnv:           false,
						OAuth21Enabled:           ptr.To(false),
						LibertyAuthCacheTimeout:  ptr.To("10m"),
						LdapClientConnectTimeout: ptr.To("30000"),
					},
				},
			}
			globalConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibm-cpp-config",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"kubernetes_cluster_type": "cncf",
					"domain_name":             "example.ibm.com",
				},
			}
			ibmcloudClusterInfo = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "operator.ibm.com/v1alpha1",
							Kind:               "Authentication",
							Name:               "example-authentication",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					Labels: map[string]string{
						"app": "auth-idp",
					},
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"im_idprovider_endpoint":    "https://platform-identity-provider.data-ns.svc:4300",
					"proxy_address":             "cp-console-data-ns.example.ibm.com",
					"cluster_address":           "cp-console-data-ns.example.ibm.com",
					"cluster_endpoint":          "https://cp-console-data-ns.example.ibm.com",
					"cluster_name":              "mycluster",
					"cluster_router_http_port":  "80",
					"cluster_router_https_port": "443",
					"im_idmgmt_endpoint":        "https://platform-identity-management.data-ns.svc:4500",
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(globalConfigMap, ibmcloudClusterInfo, authCR)
			cl = cb.Build()
			//dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			//Expect(err).NotTo(HaveOccurred())

			//r = &AuthenticationReconciler{
			//	Client: &ctrlcommon.FallbackClient{
			//		Client: cl,
			//		Reader: cl,
			//	},
			//	DiscoveryClient: *dc,
			//}
			ctx = context.Background()
		})
		It("Test apiutil.GVKForObject", func() {
			o := &corev1.ConfigMap{}
			gvk, err := apiutil.GVKForObject(o, scheme)
			Expect(err).ToNot(HaveOccurred())
			Expect(gvk.Kind).To(Equal("ConfigMap"))
			authGVK, err := apiutil.GVKForObject(authCR, scheme)
			Expect(err).ToNot(HaveOccurred())
			Expect(authGVK.Kind).To(Equal("Authentication"))
		})
		It("generates a ConfigMap based upon values in ibmcloud-cluster-info and Authentication CR", func() {
			generated := &corev1.ConfigMap{}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("oauth-client-map").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			err := generateOAuthClientConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(generated.Data).ToNot(BeNil())
			Expect(generated.Data["MASTER_IP"]).To(Equal(ibmcloudClusterInfo.Data["cluster_address"]))
			Expect(generated.Data["PROXY_IP"]).To(Equal(ibmcloudClusterInfo.Data["proxy_address"]))
			Expect(generated.Data["CLUSTER_CA_DOMAIN"]).To(Equal(ibmcloudClusterInfo.Data["cluster_address"]))
			Expect(generated.Data["CLUSTER_NAME"]).To(Equal(authCR.Spec.Config.ClusterName))
			//var findings []metav1.OwnerReference
			expected := metav1.OwnerReference{
				APIVersion:         "operator.ibm.com/v1alpha1",
				Kind:               "Authentication",
				Name:               "example-authentication",
				Controller:         ptr.To(true),
				UID:                authCR.UID,
				BlockOwnerDeletion: ptr.To(true),
			}
			Expect(generated.OwnerReferences).To(ContainElement(expected))
		})

		It("updates that ConfigMap based upon values in ibmcloud-cluster-info and Authentication CR", func() {
			fakeObserved := &corev1.ConfigMap{}

			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("oauth-client-map").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			err := generateOAuthClientConfigMap(ibmcloudClusterInfo)(resource, ctx, fakeObserved)
			Expect(err).ToNot(HaveOccurred())
			Expect(fakeObserved.Data).ToNot(BeNil())
			fakeObserved.Data["MASTER_IP"] = "dummy-address"
			fakeObserved.Data["CLUSTER_NAME"] = "dummy-name"
			generated := &corev1.ConfigMap{}
			err = generateOAuthClientConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(generated.Data).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			updated, err := updateOAuthClientConfigMap(resource, ctx, fakeObserved, generated)
			Expect(updated).To(BeTrue())
			Expect(err).ToNot(HaveOccurred())
			Expect(generated.Data["MASTER_IP"]).To(Equal(ibmcloudClusterInfo.Data["cluster_address"]))
			Expect(generated.Data["PROXY_IP"]).To(Equal(ibmcloudClusterInfo.Data["proxy_address"]))
			Expect(generated.Data["CLUSTER_CA_DOMAIN"]).To(Equal(ibmcloudClusterInfo.Data["cluster_address"]))
			Expect(generated.Data["CLUSTER_NAME"]).To(Equal(authCR.Spec.Config.ClusterName))
			expected := metav1.OwnerReference{
				APIVersion:         "operator.ibm.com/v1alpha1",
				Kind:               "Authentication",
				Name:               "example-authentication",
				Controller:         ptr.To(true),
				UID:                authCR.UID,
				BlockOwnerDeletion: ptr.To(true),
			}
			Expect(generated.OwnerReferences).To(ContainElement(expected))
		})
	})

	Describe("registration-script handling", func() {
		var authCR *operatorv1alpha1.Authentication
		var cb fakeclient.ClientBuilder
		var cl client.WithWatch
		var scheme *runtime.Scheme
		var ctx context.Context
		var globalConfigMap *corev1.ConfigMap
		var ibmcloudClusterInfo *corev1.ConfigMap
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
				Spec: operatorv1alpha1.AuthenticationSpec{
					Config: operatorv1alpha1.ConfigSpec{
						ClusterName:           "mycluster",
						ClusterCADomain:       "domain.example.com",
						DefaultAdminUser:      "myadmin",
						ZenFrontDoor:          true,
						PreferredLogin:        "ldap",
						ProviderIssuerURL:     "example.com",
						ROKSURL:               "",
						ROKSEnabled:           false,
						FIPSEnabled:           true,
						NONCEEnabled:          true,
						OIDCIssuerURL:         "oidc.example.com",
						SaasClientRedirectUrl: "saasclient.example.com",
						ClaimsMap:             "someclaims",
						ScopeClaim:            "scopeclaimexample",
						IsOpenshiftEnv:        false,
					},
				},
			}
			globalConfigMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibm-cpp-config",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"kubernetes_cluster_type": "cncf",
					"domain_name":             "example.ibm.com",
				},
			}
			ibmcloudClusterInfo = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "operator.ibm.com/v1alpha1",
							Kind:               "Authentication",
							Name:               "example-authentication",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					Labels: map[string]string{
						"app": "auth-idp",
					},
				},
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				Data: map[string]string{
					"im_idprovider_endpoint":    "https://platform-identity-provider.data-ns.svc:4300",
					"proxy_address":             "cp-console-data-ns.example.ibm.com",
					"cluster_address":           "cp-console-data-ns.example.ibm.com",
					"cluster_endpoint":          "https://cp-console-data-ns.example.ibm.com",
					"cluster_name":              "mycluster",
					"cluster_router_http_port":  "80",
					"cluster_router_https_port": "443",
					"im_idmgmt_endpoint":        "https://platform-identity-management.data-ns.svc:4500",
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(globalConfigMap, ibmcloudClusterInfo, authCR)
			cl = cb.Build()
			//dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			//Expect(err).NotTo(HaveOccurred())

			//r = &AuthenticationReconciler{
			//	Client: &ctrlcommon.FallbackClient{
			//		Client: cl,
			//		Reader: cl,
			//	},
			//	DiscoveryClient: *dc,
			//}
			ctx = context.Background()
		})

		It("generates a ConfigMap based upon values in ibmcloud-cluster-info and Authentication CR", func() {
			generated := &corev1.ConfigMap{}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-script").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			err := generateRegisterClientScript(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(generated.Data).ToNot(BeNil())
			Expect(generated.Data["register-client.sh"]).To(Equal(registerClientScript))
			expected := metav1.OwnerReference{
				APIVersion:         "operator.ibm.com/v1alpha1",
				Kind:               "Authentication",
				Name:               "example-authentication",
				Controller:         ptr.To(true),
				UID:                authCR.UID,
				BlockOwnerDeletion: ptr.To(true),
			}
			Expect(generated.OwnerReferences).To(ContainElement(expected))
		})
	})
	DescribeTable("getConfigMapDataSHA1Sum",
		func(cm1, cm2 *corev1.ConfigMap, success1, success2, match bool) {
			digest1, err := getConfigMapDataSHA1Sum(cm1)
			if !success1 {
				Expect(err).To(HaveOccurred())
				Expect(digest1).To(BeEmpty())
				return
			} else {
				Expect(err).ToNot(HaveOccurred())
				Expect(digest1).ToNot(BeEmpty())
			}
			digest2, err := getConfigMapDataSHA1Sum(cm2)
			if !success2 {
				Expect(err).To(HaveOccurred())
				Expect(digest2).To(BeEmpty())
			} else {
				Expect(err).ToNot(HaveOccurred())
				Expect(digest2).ToNot(BeEmpty())
			}
			if !success1 || !success2 {
				return
			}

			if match {
				Expect(digest1).To(Equal(digest2))
				return
			}
			Expect(digest1).ToNot(Equal(digest2))
		},
		Entry("example 1", &corev1.ConfigMap{}, nil, false, false, false),
		Entry("example 2",
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "one"}, Data: map[string]string{}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "two"}, Data: map[string]string{}},
			true, true, true),
		Entry("example 3",
			&corev1.ConfigMap{
				Data: map[string]string{
					"key1": "value1",
				},
			},
			&corev1.ConfigMap{
				Data: map[string]string{
					"key1": "value1",
				},
			}, true, true, true),
		Entry("example 4",
			&corev1.ConfigMap{
				Data: map[string]string{
					"key1": "value1",
				},
			},
			&corev1.ConfigMap{
				Data: map[string]string{
					"key2": "value2",
				},
			}, true, true, false),
		Entry("example 4",
			&corev1.ConfigMap{
				Data: map[string]string{
					"key1": "value1",
				},
			},
			&corev1.ConfigMap{
				Data: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			}, true, true, false),
	)

	Describe("registration-json handling", func() {
		var authCR *operatorv1alpha1.Authentication
		var cb fakeclient.ClientBuilder
		var cl client.WithWatch
		var scheme *runtime.Scheme
		var ctx context.Context
		var ibmcloudClusterInfo *corev1.ConfigMap
		var platformOIDCCredentials *corev1.Secret

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
				Spec: operatorv1alpha1.AuthenticationSpec{
					Config: operatorv1alpha1.ConfigSpec{
						ClusterName: "mycluster",
					},
				},
			}
			ibmcloudClusterInfo = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"cluster_address": "cp-console.example.com",
				},
			}
			platformOIDCCredentials = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: "data-ns",
				},
				Data: map[string][]byte{
					"WLP_CLIENT_ID":     []byte("test-client-id"),
					"WLP_CLIENT_SECRET": []byte("test-client-secret"),
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(ibmcloudClusterInfo, authCR, platformOIDCCredentials)
			cl = cb.Build()
			ctx = context.Background()
		})

		It("generates a ConfigMap with registration JSON", func() {
			generated := &corev1.ConfigMap{}
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(generated.Data).ToNot(BeNil())
			Expect(generated.Data["platform-oidc-registration.json"]).ToNot(BeEmpty())
		})

		It("replaces observed data with generated when observed JSON is malformed", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": "invalid json {{{",
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			updated, err := updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated).To(BeTrue())
			Expect(observed.Data["platform-oidc-registration.json"]).To(Equal(generated.Data["platform-oidc-registration.json"]))
		})

		It("appends missing URIs to trusted_uri_prefixes", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code", "client_credentials", "password", "implicit", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
  "response_types": ["code", "token", "id_token token"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["https://cp-console.example.com"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["https://existing-uri.example.com"],
  "redirect_uris": ["https://cp-console.example.com/auth/liberty/callback"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			updated, err := updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated).To(BeTrue())

			// Verify the observed data now contains both old and new URIs
			var updatedJSON registrationJSONData
			err = json.Unmarshal([]byte(observed.Data["platform-oidc-registration.json"]), &updatedJSON)
			Expect(err).ToNot(HaveOccurred())
			Expect(updatedJSON.TrustedURIPrefixes).To(ContainElement("https://existing-uri.example.com"))
			Expect(len(updatedJSON.TrustedURIPrefixes)).To(BeNumerically(">", 1))
		})

		It("appends missing URIs to redirect_uris", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["https://cp-console.example.com"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["https://cp-console.example.com"],
  "redirect_uris": ["https://old-redirect.example.com/callback"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			updated, err := updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated).To(BeTrue())

			var updatedJSON registrationJSONData
			err = json.Unmarshal([]byte(observed.Data["platform-oidc-registration.json"]), &updatedJSON)
			Expect(err).ToNot(HaveOccurred())
			Expect(updatedJSON.RedirectURIs).To(ContainElement("https://old-redirect.example.com/callback"))
			Expect(len(updatedJSON.RedirectURIs)).To(BeNumerically(">", 1))
		})

		It("appends missing URIs to post_logout_redirect_uris", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["https://old-logout.example.com"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["https://cp-console.example.com"],
  "redirect_uris": ["https://cp-console.example.com/auth/liberty/callback"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			updated, err := updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated).To(BeTrue())

			var updatedJSON registrationJSONData
			err = json.Unmarshal([]byte(observed.Data["platform-oidc-registration.json"]), &updatedJSON)
			Expect(err).ToNot(HaveOccurred())
			Expect(updatedJSON.PostLogoutRedirectURIs).To(ContainElement("https://old-logout.example.com"))
			Expect(len(updatedJSON.PostLogoutRedirectURIs)).To(BeNumerically(">", 1))
		})

		It("does not update when all URIs are already present", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			// Use the same data for observed as generated
			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": generated.Data["platform-oidc-registration.json"],
				},
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: generated.GetOwnerReferences(),
				},
			}

			updated, err := updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated).To(BeFalse())
		})

		It("appends multiple missing URIs across all three fields", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["https://old-logout1.example.com", "https://old-logout2.example.com"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["https://old-trusted1.example.com"],
  "redirect_uris": ["https://old-redirect1.example.com"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			updated, err := updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated).To(BeTrue())

			var updatedJSON registrationJSONData
			err = json.Unmarshal([]byte(observed.Data["platform-oidc-registration.json"]), &updatedJSON)
			Expect(err).ToNot(HaveOccurred())

			// Verify old URIs are preserved
			Expect(updatedJSON.TrustedURIPrefixes).To(ContainElement("https://old-trusted1.example.com"))
			Expect(updatedJSON.RedirectURIs).To(ContainElement("https://old-redirect1.example.com"))
			Expect(updatedJSON.PostLogoutRedirectURIs).To(ContainElement("https://old-logout1.example.com"))
			Expect(updatedJSON.PostLogoutRedirectURIs).To(ContainElement("https://old-logout2.example.com"))

			// Verify new URIs are added
			Expect(len(updatedJSON.TrustedURIPrefixes)).To(BeNumerically(">", 1))
			Expect(len(updatedJSON.RedirectURIs)).To(BeNumerically(">", 1))
			Expect(len(updatedJSON.PostLogoutRedirectURIs)).To(BeNumerically(">", 2))
		})

		It("handles empty URI arrays in observed data", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": [],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": [],
  "redirect_uris": []
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			updated, err := updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated).To(BeTrue())

			var updatedJSON registrationJSONData
			err = json.Unmarshal([]byte(observed.Data["platform-oidc-registration.json"]), &updatedJSON)
			Expect(err).ToNot(HaveOccurred())

			// All URIs from generated should be added
			Expect(len(updatedJSON.TrustedURIPrefixes)).To(BeNumerically(">", 0))
			Expect(len(updatedJSON.RedirectURIs)).To(BeNumerically(">", 0))
			Expect(len(updatedJSON.PostLogoutRedirectURIs)).To(BeNumerically(">", 0))
		})

		It("updates owner references when they differ", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": generated.Data["platform-oidc-registration.json"],
				},
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{}, // Different from generated
				},
			}

			updated, err := updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated).To(BeTrue())
			Expect(observed.GetOwnerReferences()).To(Equal(generated.GetOwnerReferences()))
		})
	})

	Describe("ConfigMap checksum annotation handling", func() {
		var authCR *operatorv1alpha1.Authentication
		var cb fakeclient.ClientBuilder
		var cl client.WithWatch
		var scheme *runtime.Scheme
		var ctx context.Context
		var ibmcloudClusterInfo *corev1.ConfigMap
		var platformOIDCCredentials *corev1.Secret

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
				Spec: operatorv1alpha1.AuthenticationSpec{
					Config: operatorv1alpha1.ConfigSpec{
						ClusterName: "mycluster",
					},
				},
			}
			ibmcloudClusterInfo = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"cluster_address": "cp-console.example.com",
				},
			}
			platformOIDCCredentials = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: "data-ns",
				},
				Data: map[string][]byte{
					"WLP_CLIENT_ID":     []byte("test-client-id"),
					"WLP_CLIENT_SECRET": []byte("test-client-secret"),
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(ibmcloudClusterInfo, authCR, platformOIDCCredentials)
			cl = cb.Build()
			ctx = context.Background()
		})

		It("ensureConfigMapChecksumAnnotation sets annotation when missing", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("test-configmap").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			cm := &corev1.ConfigMap{
				Data: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			}

			modified, err := ensureConfigMapChecksumAnnotation(resource, ctx, cm, cm)
			Expect(err).ToNot(HaveOccurred())
			Expect(modified).To(BeTrue())
			Expect(cm.Annotations).ToNot(BeNil())
			Expect(cm.Annotations[AnnotationSHA1Sum]).ToNot(BeEmpty())
		})

		It("ensureConfigMapChecksumAnnotation updates annotation when data changes", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("test-configmap").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			cm := &corev1.ConfigMap{
				Data: map[string]string{
					"key1": "value1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationSHA1Sum: "old-checksum",
					},
				},
			}

			modified, err := ensureConfigMapChecksumAnnotation(resource, ctx, cm, cm)
			Expect(err).ToNot(HaveOccurred())
			Expect(modified).To(BeTrue())
			Expect(cm.Annotations[AnnotationSHA1Sum]).ToNot(Equal("old-checksum"))
		})

		It("ensureConfigMapChecksumAnnotation does not modify when checksum matches", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("test-configmap").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			cm := &corev1.ConfigMap{
				Data: map[string]string{
					"key1": "value1",
				},
			}

			// First call to set the checksum
			modified, err := ensureConfigMapChecksumAnnotation(resource, ctx, cm, cm)
			Expect(err).ToNot(HaveOccurred())
			Expect(modified).To(BeTrue())
			originalChecksum := cm.Annotations[AnnotationSHA1Sum]

			// Second call should not modify
			modified, err = ensureConfigMapChecksumAnnotation(resource, ctx, cm, cm)
			Expect(err).ToNot(HaveOccurred())
			Expect(modified).To(BeFalse())
			Expect(cm.Annotations[AnnotationSHA1Sum]).To(Equal(originalChecksum))
		})

		It("generateRegistrationJsonConfigMap sets checksum annotation", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(generated.Annotations).ToNot(BeNil())
			Expect(generated.Annotations[AnnotationSHA1Sum]).ToNot(BeEmpty())
		})

		It("updateRegistrationJSON updates checksum when URIs change", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			// Generate initial ConfigMap with checksum
			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())
			originalChecksum := generated.Annotations[AnnotationSHA1Sum]

			// Create observed with additional URIs
			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code", "client_credentials", "password", "implicit", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
  "response_types": ["code", "token", "id_token token"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["https://cp-console.example.com", "https://custom-logout.example.com"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["https://cp-console.example.com", "https://custom-trusted.example.com"],
  "redirect_uris": ["https://cp-console.example.com/auth/liberty/callback", "https://custom-redirect.example.com/callback"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationSHA1Sum: originalChecksum,
					},
				},
			}

			updated, err := updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated).To(BeTrue())
			Expect(observed.Annotations[AnnotationSHA1Sum]).ToNot(Equal(originalChecksum))
		})

		It("updateRegistrationJSON does not update checksum when URIs match", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			// Generate ConfigMap
			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			// Create observed with same data
			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": generated.Data["platform-oidc-registration.json"],
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationSHA1Sum: generated.Annotations[AnnotationSHA1Sum],
					},
					OwnerReferences: generated.GetOwnerReferences(),
				},
			}

			updated, err := updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated).To(BeFalse())
		})

		It("updateRegistrationJSON calculates correct checksum with observed URIs", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			// Generate initial ConfigMap
			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			// Parse generated JSON to get base URIs
			var generatedJSON registrationJSONData
			err = json.Unmarshal([]byte(generated.Data["platform-oidc-registration.json"]), &generatedJSON)
			Expect(err).ToNot(HaveOccurred())

			// Create observed with ONLY custom URIs (not including generated ones)
			// This will trigger the update logic to append the generated URIs
			customTrusted := "https://custom-trusted.example.com"
			customRedirect := "https://custom-redirect.example.com/callback"
			customLogout := "https://custom-logout.example.com"

			observedJSON := registrationJSONData{
				TokenEndpointAuthMethod: generatedJSON.TokenEndpointAuthMethod,
				ClientID:                generatedJSON.ClientID,
				ClientSecret:            generatedJSON.ClientSecret,
				Scope:                   generatedJSON.Scope,
				GrantTypes:              generatedJSON.GrantTypes,
				ResponseTypes:           generatedJSON.ResponseTypes,
				ApplicationType:         generatedJSON.ApplicationType,
				SubjectType:             generatedJSON.SubjectType,
				PreauthorizedScope:      generatedJSON.PreauthorizedScope,
				IntrospectTokens:        generatedJSON.IntrospectTokens,
				FunctionalUserGroupIDs:  generatedJSON.FunctionalUserGroupIDs,
				TrustedURIPrefixes:      []string{customTrusted},
				RedirectURIs:            []string{customRedirect},
				PostLogoutRedirectURIs:  []string{customLogout},
			}

			observedBytes, err := json.MarshalIndent(observedJSON, "", "  ")
			Expect(err).ToNot(HaveOccurred())

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": string(observedBytes),
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationSHA1Sum: "old-checksum",
					},
				},
			}

			// Update should append generated URIs and calculate new checksum
			updated, err := updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated).To(BeTrue())

			// Parse the updated observed JSON
			var updatedObservedJSON registrationJSONData
			err = json.Unmarshal([]byte(observed.Data["platform-oidc-registration.json"]), &updatedObservedJSON)
			Expect(err).ToNot(HaveOccurred())

			// Verify custom URIs are preserved
			Expect(updatedObservedJSON.TrustedURIPrefixes).To(ContainElement(customTrusted))
			Expect(updatedObservedJSON.RedirectURIs).To(ContainElement(customRedirect))
			Expect(updatedObservedJSON.PostLogoutRedirectURIs).To(ContainElement(customLogout))

			// Verify generated URIs were appended
			for _, uri := range generatedJSON.TrustedURIPrefixes {
				Expect(updatedObservedJSON.TrustedURIPrefixes).To(ContainElement(uri))
			}
			for _, uri := range generatedJSON.RedirectURIs {
				Expect(updatedObservedJSON.RedirectURIs).To(ContainElement(uri))
			}
			for _, uri := range generatedJSON.PostLogoutRedirectURIs {
				Expect(updatedObservedJSON.PostLogoutRedirectURIs).To(ContainElement(uri))
			}

			// Verify the checksum was updated and is not the old value
			Expect(observed.Annotations[AnnotationSHA1Sum]).ToNot(Equal("old-checksum"))
			Expect(observed.Annotations[AnnotationSHA1Sum]).ToNot(BeEmpty())
		})

		It("updateRegistrationJSON handles malformed JSON and sets new checksum", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": "invalid json {{{",
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationSHA1Sum: "old-checksum",
					},
				},
			}

			updated, err := updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
			Expect(updated).To(BeTrue())
			Expect(observed.Data["platform-oidc-registration.json"]).To(Equal(generated.Data["platform-oidc-registration.json"]))
			Expect(observed.Annotations[AnnotationSHA1Sum]).To(Equal(generated.Annotations[AnnotationSHA1Sum]))
		})
	})

	Describe("registration-json URI validation", func() {
		var authCR *operatorv1alpha1.Authentication
		var cb fakeclient.ClientBuilder
		var cl client.WithWatch
		var scheme *runtime.Scheme
		var ctx context.Context
		var ibmcloudClusterInfo *corev1.ConfigMap
		var platformOIDCCredentials *corev1.Secret

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
				Spec: operatorv1alpha1.AuthenticationSpec{
					Config: operatorv1alpha1.ConfigSpec{
						ClusterName: "mycluster",
					},
				},
			}
			ibmcloudClusterInfo = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ibmcloud-cluster-info",
					Namespace: "data-ns",
				},
				Data: map[string]string{
					"cluster_address": "cp-console.example.com",
				},
			}
			platformOIDCCredentials = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "platform-oidc-credentials",
					Namespace: "data-ns",
				},
				Data: map[string][]byte{
					"WLP_CLIENT_ID":     []byte("test-client-id"),
					"WLP_CLIENT_SECRET": []byte("test-client-secret"),
				},
			}
			scheme = runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(ibmcloudClusterInfo, authCR, platformOIDCCredentials)
			cl = cb.Build()
			ctx = context.Background()
		})

		It("accepts valid URIs with https scheme", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["https://valid-logout.example.com/logout"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["https://valid-trusted.example.com"],
  "redirect_uris": ["https://valid-redirect.example.com/callback"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			_, err = updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
		})

		It("accepts valid URIs with http scheme", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["http://localhost:8080/logout"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["http://localhost:8080"],
  "redirect_uris": ["http://localhost:8080/callback"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			_, err = updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
		})

		It("rejects URIs without scheme in trusted_uri_prefixes", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["https://cp-console.example.com"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["invalid-uri-without-scheme"],
  "redirect_uris": ["https://cp-console.example.com/auth/liberty/callback"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			_, err = updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid URIs found"))
			Expect(err.Error()).To(ContainSubstring("trusted_uri_prefixes"))
			Expect(err.Error()).To(ContainSubstring("invalid-uri-without-scheme"))
		})

		It("rejects URIs without host in redirect_uris", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["https://cp-console.example.com"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["https://cp-console.example.com"],
  "redirect_uris": ["https://"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			_, err = updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid URIs found"))
			Expect(err.Error()).To(ContainSubstring("redirect_uris"))
		})

		It("rejects completely malformed URIs in post_logout_redirect_uris", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["ht!tp://invalid url with spaces"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["https://cp-console.example.com"],
  "redirect_uris": ["https://cp-console.example.com/auth/liberty/callback"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			_, err = updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid URIs found"))
			Expect(err.Error()).To(ContainSubstring("post_logout_redirect_uris"))
		})

		It("rejects multiple invalid URIs across different fields", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["not-a-valid-uri", "https://valid.example.com"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["missing-scheme.example.com"],
  "redirect_uris": ["https://", "https://valid-redirect.example.com/callback"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			_, err = updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid URIs found"))
			Expect(err.Error()).To(ContainSubstring("trusted_uri_prefixes"))
			Expect(err.Error()).To(ContainSubstring("redirect_uris"))
			Expect(err.Error()).To(ContainSubstring("post_logout_redirect_uris"))
		})

		It("accepts URIs with ports", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["https://example.com:8443/logout"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["https://example.com:8443"],
  "redirect_uris": ["https://example.com:8443/callback"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			_, err = updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
		})

		It("accepts URIs with paths and query parameters", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["https://example.com/path/to/logout?param=value"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["https://example.com/path"],
  "redirect_uris": ["https://example.com/auth/callback?state=xyz"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			_, err = updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).ToNot(HaveOccurred())
		})

		It("rejects empty string URIs", func() {
			resource := ctrlcommon.NewSecondaryReconcilerBuilder[*corev1.ConfigMap]().
				WithName("registration-json").
				WithNamespace(authCR.Namespace).
				WithClient(cl).
				WithPrimary(authCR).MustBuild()

			observedData := `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "scope": "openid profile email",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": [""],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": [],
  "trusted_uri_prefixes": ["https://cp-console.example.com"],
  "redirect_uris": ["https://cp-console.example.com/auth/liberty/callback"]
}`

			observed := &corev1.ConfigMap{
				Data: map[string]string{
					"platform-oidc-registration.json": observedData,
				},
			}

			generated := &corev1.ConfigMap{}
			err := generateRegistrationJsonConfigMap(ibmcloudClusterInfo)(resource, ctx, generated)
			Expect(err).ToNot(HaveOccurred())

			_, err = updateRegistrationJSON(resource, ctx, observed, generated)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid URIs found"))
			Expect(err.Error()).To(ContainSubstring("post_logout_redirect_uris"))
		})
	})
})
