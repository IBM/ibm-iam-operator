package operator

import (
	"context"
	"strconv"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	testutil "github.com/IBM/ibm-iam-operator/testing"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

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
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(globalConfigMap, authCR)
			cl = cb.Build()
			dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			Expect(err).NotTo(HaveOccurred())

			r = &AuthenticationReconciler{
				Client:          cl,
				DiscoveryClient: *dc,
			}
			ctx = context.Background()
		})
		It("retrieves the domain name when configured for CNCF", func() {
			dn, err := getCNCFDomain(ctx, r.Client, authCR)
			Expect(err).NotTo(HaveOccurred())
			Expect(dn).To(Equal("example.ibm.com"))
		})
		It("retrieves nothing when not configured for CNCF", func() {
			globalConfigMap.Data["kubernetes_cluster_type"] = "other"
			r.Update(ctx, globalConfigMap)
			dn, err := getCNCFDomain(ctx, r.Client, authCR)
			Expect(err).NotTo(HaveOccurred())
			Expect(dn).To(Equal(""))
		})
		It("produces an error when ibm-cpp-config does not have domain_name set", func() {
			delete(globalConfigMap.Data, "domain_name")
			r.Update(ctx, globalConfigMap)
			dn, err := getCNCFDomain(ctx, r.Client, authCR)
			Expect(err).To(HaveOccurred())
			Expect(dn).To(Equal(""))
			Expect(err.Error()).To(Equal("domain name not configured"))
		})
		It("produces an error when ibm-cpp-config isn't found", func() {
			r.Delete(ctx, globalConfigMap)
			dn, err := getCNCFDomain(ctx, r.Client, authCR)
			Expect(dn).To(Equal(""))
			Expect(err).To(HaveOccurred())
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
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(globalConfigMap, authCR)
			cl = cb.Build()
			dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			Expect(err).NotTo(HaveOccurred())

			r = &AuthenticationReconciler{
				Client:          cl,
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
							Controller:         ptr.To[bool](true),
							BlockOwnerDeletion: ptr.To[bool](true),
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
							Controller:         ptr.To[bool](true),
							BlockOwnerDeletion: ptr.To[bool](true),
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
							Controller:         ptr.To[bool](true),
							BlockOwnerDeletion: ptr.To[bool](true),
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
			Expect(observed.Data["cluster_address_auth"]).To(Equal(observed.Data["cluster_address"]))
			Expect(observed.Labels).ToNot(BeNil())
			Expect(observed.Labels["app"]).To(Equal("auth-idp"))
			Expect(observed.OwnerReferences).ToNot(BeEmpty())
			Expect(*observed.OwnerReferences[0].Controller).To(BeTrue())
		})
	})

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
							Controller:         ptr.To[bool](true),
							BlockOwnerDeletion: ptr.To[bool](true),
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
			dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			Expect(err).NotTo(HaveOccurred())

			r = &AuthenticationReconciler{
				Client:          cl,
				DiscoveryClient: *dc,
			}
			ctx = context.Background()
		})

		getObserved := func() *corev1.ConfigMap {
			return &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "platform-auth-idp",
					Namespace: "data-ns",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "operator.ibm.com/v1alpha1",
							Kind:               "Authentication",
							Name:               "example-authentication",
							Controller:         ptr.To[bool](true),
							BlockOwnerDeletion: ptr.To[bool](true),
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
					"MASTER_HOST":                        authCR.Spec.Config.ClusterCADomain,
					"NODE_ENV":                           "production",
					"AUDIT_ENABLED_IDPROVIDER":           "false",
					"AUDIT_ENABLED_IDMGMT":               "false",
					"AUDIT_DETAIL":                       "false",
					"LOG_LEVEL_IDPROVIDER":               "info",
					"LOG_LEVEL_AUTHSVC":                  "info",
					"LOG_LEVEL_IDMGMT":                   "info",
					"LOG_LEVEL_MW":                       "info",
					"DEFAULT_LOGIN":                      "",
					"IDTOKEN_LIFETIME":                   "12h",
					"SESSION_TIMEOUT":                    "43200",
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
					"IBMID_CLIENT_ID":                    "d3c8d1cf59a77cf73df35b073dfc1dc8",
					"IBMID_CLIENT_ISSUER":                "idaas.iam.ibm.com",
					"IBMID_PROFILE_URL":                  "https://w3-dev.api.ibm.com/profilemgmt/test/ibmidprofileait/v2/users",
					"IBMID_PROFILE_CLIENT_ID":            "1c36586c-cf48-4bce-9b9b-1a0480cc798b",
					"IBMID_PROFILE_FIELDS":               "displayName,name,emails",
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
					"CLAIMS_SUPPORTED",
					[]string{
						"CLAIMS_SUPPORTED",
						"CLAIMS_MAP",
						"SCOPE_CLAIM",
						"BOOTSTRAP_USERID",
					},
				},
				{
					"DEFAULT_LOGIN",
					[]string{"DEFAULT_LOGIN"},
				},
				{
					"PROVIDER_ISSUER_URL",
					[]string{
						"PROVIDER_ISSUER_URL",
					},
				},
				{
					"PREFERRED_LOGIN",
					[]string{
						"PREFERRED_LOGIN",
					},
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

			for _, test := range updateOnNotSetKeys {
				observed := getObserved()
				generated := &corev1.ConfigMap{}
				err := generateAuthIdpConfigMap(ctx, r.Client, authCR, ibmcloudClusterInfo, generated)
				Expect(err).NotTo(HaveOccurred())
				updated, err = updatePlatformAuthIDP(observed, generated)
				Expect(err).ToNot(HaveOccurred())
				Expect(updated).To(BeFalse())
				setDummyData(test.primaryKey, test.keys, observed)
				updated, err = updatePlatformAuthIDP(observed, generated)
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

			for _, k := range updateWhenLocalhostUsed {
				observed := getObserved()
				// Set the keys in observed to contain localhost IP
				observed.Data[k] = "https://127.0.0.1:12345"
				generated := &corev1.ConfigMap{}
				Expect(generateAuthIdpConfigMap(ctx, r.Client, authCR, ibmcloudClusterInfo, generated)).
					To(Succeed())
				updated, err := updatePlatformAuthIDP(observed, generated)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated).To(BeTrue())
				Expect(observed.Data[k]).To(Equal(generated.Data[k]))
			}
		})

		It("replaces value in OS_TOKEN_LENGTH only when it is set to 45", func() {
			observed := getObserved()
			// Set the keys in observed to contain localhost IP
			k := "OS_TOKEN_LENGTH"
			observed.Data[k] = "24"
			generated := &corev1.ConfigMap{}
			Expect(generateAuthIdpConfigMap(ctx, r.Client, authCR, ibmcloudClusterInfo, generated)).
				To(Succeed())
			updated, err := updatePlatformAuthIDP(observed, generated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated).To(BeFalse())
			Expect(observed.Data[k]).NotTo(Equal(generated.Data[k]))
			observed.Data[k] = "45"
			updated, err = updatePlatformAuthIDP(observed, generated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated).To(BeTrue())
			Expect(observed.Data[k]).To(Equal(generated.Data[k]))
		})
	})

	Describe("oauth-client-map handling", func() {
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
							Controller:         ptr.To[bool](true),
							BlockOwnerDeletion: ptr.To[bool](true),
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
			dc, err := discovery.NewDiscoveryClientForConfig(cfg)
			Expect(err).NotTo(HaveOccurred())

			r = &AuthenticationReconciler{
				Client:          cl,
				DiscoveryClient: *dc,
			}
			ctx = context.Background()
		})
		It("generates a ConfigMap based upon values in ibmcloud-cluster-info and Authentication CR", func() {
			generated := &corev1.ConfigMap{}
			err := generateOAuthClientConfigMap(ctx, r.Client, authCR, ibmcloudClusterInfo, generated)
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
				Controller:         ptr.To[bool](true),
				UID:                authCR.UID,
				BlockOwnerDeletion: ptr.To[bool](true),
			}
			Expect(generated.OwnerReferences).To(ContainElement(expected))
		})
	})
})
