package v1

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Migration Suite")
}

var _ = Describe("IdpConfig", func() {
	Describe("ToAnySlice", func() {
		var idpConfig *IdpConfig
		var idpConfigSlice []any
		Context("When IdpConfig is not empty", func() {
			BeforeEach(func() {
				idpConfig = &IdpConfig{
					UID:         "some_id",
					Description: "a description",
					Enabled:     true,
					Name:        "idp name",
					Type:        "Custom",
					Protocol:    "ldap",
				}
			})
			It("produces a []any containing field values", func() {
				idpConfigSlice = idpConfig.ToAnySlice()
				Expect(idpConfigSlice[0]).To(Equal(idpConfig.UID))
			})
		})
	})
	Describe("ToAnyMap", func() {
		var idpConfig *IdpConfig
		var idpConfigMap map[string]any
		Context("When IdpConfig is not empty", func() {
			BeforeEach(func() {
				idpConfig = &IdpConfig{
					UID:         string("some_id"),
					Description: "a description",
					Enabled:     true,
					Name:        "idp name",
					Type:        "Custom",
					Protocol:    "ldap",
					LDAPId:      "blah",
				}
			})
			It("produces a map[string]any containing field values", func() {
				idpConfigMap = idpConfig.ToAnyMap()
				Expect(idpConfigMap["uid"]).To(Equal(idpConfig.UID))
				Expect(idpConfigMap["ldap_id"]).To(Equal(idpConfig.LDAPId))
				Expect(idpConfigMap["description"]).To(Equal(idpConfig.Description))
				Expect(idpConfigMap["scim_config"]).To(BeNil())

			})
		})
	})
	Describe("ConvertV2DirectoryToV3IdpConfig", func() {
		var dirMap map[string]any
		Context("When Directory map is valid", func() {
			It("produces a valid pointer to an IdpConfig struct", func() {
				dirMap = map[string]any{
					"_id":                   "someidentifier",
					"LDAP_ID":               "openLDAP",
					"LDAP_REALM":            "openLDAPRealm",
					"LDAP_HOST":             "100.100.100.100",
					"LDAP_PORT":             "389",
					"LDAP_IGNORECASE":       "true",
					"LDAP_BASEDN":           "dc=ibm,dc=com",
					"LDAP_BINDDN":           "cn=example,dc=ibm,dc=com",
					"LDAP_BINDPASSWORD":     "supersecret",
					"LDAP_TYPE":             "Custom",
					"LDAP_USERFILTER":       "(&(uid=%v)(objectclass=person))",
					"LDAP_GROUPFILTER":      "(&(cn=%v)(objectclass=groupOfUniqueNames))",
					"LDAP_USERIDMAP":        "*:uid",
					"LDAP_GROUPIDMAP":       "*:cn",
					"LDAP_GROUPMEMBERIDMAP": "groupOfUniqueNames:uniquemember",
				}
				idpConfig, err := ConvertV2DirectoryToV3IdpConfig(dirMap)
				Expect(idpConfig).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(idpConfig.Name).To(Equal("openLDAP"))
				Expect(idpConfig.Type).To(Equal("Custom"))
				Expect(idpConfig.Protocol).To(Equal("ldap"))
				Expect(idpConfig.UID).To(Equal("someidentifier"))
				Expect(idpConfig.Description).To(Equal(""))
				Expect(idpConfig.IDPConfig).ToNot(BeEmpty())
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_id", "openLDAP"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_realm", "openLDAPRealm"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_host", "100.100.100.100"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_port", "389"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_ignorecase", "true"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_basedn", "dc=ibm,dc=com"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_binddn", "cn=example,dc=ibm,dc=com"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_bindpassword", "supersecret"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_type", "Custom"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_userfilter", "(&(uid=%v)(objectclass=person))"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_groupfilter", "(&(cn=%v)(objectclass=groupOfUniqueNames))"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_useridmap", "*:uid"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_groupidmap", "*:cn"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_groupmemberidmap", "groupOfUniqueNames:uniquemember"))
				Expect(idpConfig.IDPConfig).ShouldNot(HaveKey("ldap_nestedsearch"))
				Expect(idpConfig.IDPConfig).ShouldNot(HaveKey("ldap_pagingsearch"))
				Expect(idpConfig.IDPConfig).ShouldNot(HaveKey("ldap_pagingsize"))
			})
		})
		Context("When Directory map has CP3MIGRATED", func() {
			It("returns a valid pointer to a IdpConfig when it is set to \"true\"", func() {
				dirMap = map[string]any{
					"_id":                   "someidentifier",
					"LDAP_ID":               "openLDAP",
					"LDAP_REALM":            "openLDAPRealm",
					"LDAP_HOST":             "100.100.100.100",
					"LDAP_PORT":             "389",
					"LDAP_IGNORECASE":       "true",
					"LDAP_BASEDN":           "dc=ibm,dc=com",
					"LDAP_BINDDN":           "cn=example,dc=ibm,dc=com",
					"LDAP_BINDPASSWORD":     "supersecret",
					"LDAP_TYPE":             "Custom",
					"LDAP_USERFILTER":       "(&(uid=%v)(objectclass=person))",
					"LDAP_GROUPFILTER":      "(&(cn=%v)(objectclass=groupOfUniqueNames))",
					"LDAP_USERIDMAP":        "*:uid",
					"LDAP_GROUPIDMAP":       "*:cn",
					"LDAP_GROUPMEMBERIDMAP": "groupOfUniqueNames:uniquemember",
					"CP3MIGRATED":           "true",
				}
				idpConfig, err := ConvertV2DirectoryToV3IdpConfig(dirMap)
				Expect(idpConfig).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(idpConfig.Name).To(Equal("openLDAP"))
				Expect(idpConfig.Type).To(Equal("Custom"))
				Expect(idpConfig.Protocol).To(Equal("ldap"))
				Expect(idpConfig.UID).To(Equal("someidentifier"))
				Expect(idpConfig.Description).To(Equal(""))
				Expect(idpConfig.IDPConfig).ToNot(BeEmpty())
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_id", "openLDAP"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_realm", "openLDAPRealm"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_host", "100.100.100.100"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_port", "389"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_ignorecase", "true"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_basedn", "dc=ibm,dc=com"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_binddn", "cn=example,dc=ibm,dc=com"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_bindpassword", "supersecret"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_type", "Custom"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_userfilter", "(&(uid=%v)(objectclass=person))"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_groupfilter", "(&(cn=%v)(objectclass=groupOfUniqueNames))"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_useridmap", "*:uid"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_groupidmap", "*:cn"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_groupmemberidmap", "groupOfUniqueNames:uniquemember"))
				Expect(idpConfig.IDPConfig).ShouldNot(HaveKey("ldap_nestedsearch"))
				Expect(idpConfig.IDPConfig).ShouldNot(HaveKey("ldap_pagingsearch"))
				Expect(idpConfig.IDPConfig).ShouldNot(HaveKey("ldap_pagingsize"))
			})
			It("returns a valid pointer to a IdpConfig when it is not set to \"true\"", func() {
				dirMap = map[string]any{
					"_id":                   "someidentifier",
					"LDAP_ID":               "openLDAP",
					"LDAP_REALM":            "openLDAPRealm",
					"LDAP_HOST":             "100.100.100.100",
					"LDAP_PORT":             "389",
					"LDAP_IGNORECASE":       "true",
					"LDAP_BASEDN":           "dc=ibm,dc=com",
					"LDAP_BINDDN":           "cn=example,dc=ibm,dc=com",
					"LDAP_BINDPASSWORD":     "supersecret",
					"LDAP_TYPE":             "Custom",
					"LDAP_USERFILTER":       "(&(uid=%v)(objectclass=person))",
					"LDAP_GROUPFILTER":      "(&(cn=%v)(objectclass=groupOfUniqueNames))",
					"LDAP_USERIDMAP":        "*:uid",
					"LDAP_GROUPIDMAP":       "*:cn",
					"LDAP_GROUPMEMBERIDMAP": "groupOfUniqueNames:uniquemember",
					"CP3MIGRATED":           "false",
				}
				idpConfig, err := ConvertV2DirectoryToV3IdpConfig(dirMap)
				Expect(idpConfig).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(idpConfig.Name).To(Equal("openLDAP"))
				Expect(idpConfig.Type).To(Equal("Custom"))
				Expect(idpConfig.Protocol).To(Equal("ldap"))
				Expect(idpConfig.UID).To(Equal("someidentifier"))
				Expect(idpConfig.Description).To(Equal(""))
				Expect(idpConfig.IDPConfig).ToNot(BeEmpty())
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_id", "openLDAP"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_realm", "openLDAPRealm"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_host", "100.100.100.100"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_port", "389"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_ignorecase", "true"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_basedn", "dc=ibm,dc=com"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_binddn", "cn=example,dc=ibm,dc=com"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_bindpassword", "supersecret"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_type", "Custom"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_userfilter", "(&(uid=%v)(objectclass=person))"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_groupfilter", "(&(cn=%v)(objectclass=groupOfUniqueNames))"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_useridmap", "*:uid"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_groupidmap", "*:cn"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_groupmemberidmap", "groupOfUniqueNames:uniquemember"))
				Expect(idpConfig.IDPConfig).ShouldNot(HaveKey("ldap_nestedsearch"))
				Expect(idpConfig.IDPConfig).ShouldNot(HaveKey("ldap_pagingsearch"))
				Expect(idpConfig.IDPConfig).ShouldNot(HaveKey("ldap_pagingsize"))
			})
			It("returns a valid point to a IdpConfig when it is not set to \"true\"", func() {
				dirMap = map[string]any{
					"_id":                   "someidentifier",
					"LDAP_ID":               "openLDAP",
					"LDAP_REALM":            "openLDAPRealm",
					"LDAP_HOST":             "100.100.100.100",
					"LDAP_PORT":             "389",
					"LDAP_IGNORECASE":       "true",
					"LDAP_BASEDN":           "dc=ibm,dc=com",
					"LDAP_BINDDN":           "cn=example,dc=ibm,dc=com",
					"LDAP_BINDPASSWORD":     "supersecret",
					"LDAP_TYPE":             "Custom",
					"LDAP_USERFILTER":       "(&(uid=%v)(objectclass=person))",
					"LDAP_GROUPFILTER":      "(&(cn=%v)(objectclass=groupOfUniqueNames))",
					"LDAP_USERIDMAP":        "*:uid",
					"LDAP_GROUPIDMAP":       "*:cn",
					"LDAP_GROUPMEMBERIDMAP": "groupOfUniqueNames:uniquemember",
					"CP3MIGRATED":           "trueish",
				}
				idpConfig, err := ConvertV2DirectoryToV3IdpConfig(dirMap)
				Expect(idpConfig).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(idpConfig.Name).To(Equal("openLDAP"))
				Expect(idpConfig.Type).To(Equal("Custom"))
				Expect(idpConfig.Protocol).To(Equal("ldap"))
				Expect(idpConfig.UID).To(Equal("someidentifier"))
				Expect(idpConfig.Description).To(Equal(""))
				Expect(idpConfig.IDPConfig).ToNot(BeEmpty())
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_id", "openLDAP"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_realm", "openLDAPRealm"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_host", "100.100.100.100"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_port", "389"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_ignorecase", "true"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_basedn", "dc=ibm,dc=com"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_binddn", "cn=example,dc=ibm,dc=com"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_bindpassword", "supersecret"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_type", "Custom"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_userfilter", "(&(uid=%v)(objectclass=person))"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_groupfilter", "(&(cn=%v)(objectclass=groupOfUniqueNames))"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_useridmap", "*:uid"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_groupidmap", "*:cn"))
				Expect(idpConfig.IDPConfig).Should(HaveKeyWithValue("ldap_groupmemberidmap", "groupOfUniqueNames:uniquemember"))
				Expect(idpConfig.IDPConfig).ShouldNot(HaveKey("ldap_nestedsearch"))
				Expect(idpConfig.IDPConfig).ShouldNot(HaveKey("ldap_pagingsearch"))
				Expect(idpConfig.IDPConfig).ShouldNot(HaveKey("ldap_pagingsize"))
			})
		})
		Context("When Directory map is invalid", func() {
			It("returns nil", func() {
				dirMap = map[string]any{
					"_id":                   "someidentifier",
					"LDAP_ID":               123,
					"LDAP_REALM":            "openLDAPRealm",
					"LDAP_HOST":             "100.100.100.100",
					"LDAP_PORT":             "389",
					"LDAP_IGNORECASE":       "true",
					"LDAP_BASEDN":           "dc=ibm,dc=com",
					"LDAP_BINDDN":           "cn=example,dc=ibm,dc=com",
					"LDAP_BINDPASSWORD":     "supersecret",
					"LDAP_TYPE":             "Custom",
					"LDAP_USERFILTER":       "(&(uid=%v)(objectclass=person))",
					"LDAP_GROUPFILTER":      "(&(cn=%v)(objectclass=groupOfUniqueNames))",
					"LDAP_USERIDMAP":        "*:uid",
					"LDAP_GROUPIDMAP":       "*:cn",
					"LDAP_GROUPMEMBERIDMAP": "groupOfUniqueNames:uniquemember",
				}
				idpConfig, err := ConvertV2DirectoryToV3IdpConfig(dirMap)
				Expect(idpConfig).To(BeNil())
				Expect(err).To(HaveOccurred())
			})
		})
	})
	Describe("ConvertV2SamlToIdpConfig", func() {
		var samlMap map[string]any
		It("converts basic V2 SAML to V3 IdP", func() {
			tokenAttrMap := map[string]string{
				"uid":        "uid",
				"first_name": "firstName",
				"last_name":  "lastName",
				"groups":     "blueGroups",
				"email":      "emailAddress",
			}
			samlMap = map[string]any{
				"name":                     "w3id-sample-saml",
				"description":              "w3id-sample-saml-test",
				"protocol":                 "saml",
				"idp_type":                 "default",
				"scim":                     "no",
				"saml_ldap":                "None",
				"jit":                      "yes",
				"token_attribute_mappings": tokenAttrMap,
				"status":                   "enabled",
			}
			idpConfig, err := ConvertV2SamlToIdpConfig(samlMap)
			Expect(idpConfig).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			Expect(idpConfig).To(HaveField("Name", "w3id-sample-saml"))
			Expect(idpConfig).To(HaveField("Description", "w3id-sample-saml-test"))
			Expect(idpConfig).To(HaveField("Protocol", "saml"))
			Expect(idpConfig).To(HaveField("Type", "default"))
			Expect(idpConfig).To(HaveField("JIT", true))
			Expect(idpConfig.IDPConfig).ToNot(BeEmpty())
			Expect(idpConfig.IDPConfig).To(HaveKey("token_attribute_mappings"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("sub", "uid"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("given_name", "firstName"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("family_name", "lastName"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("groups", "blueGroups"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("email", "emailAddress"))
		})

		It("converts V2 SAML with SCIM dependency registration to V3 IdP", func() {
			samlMap = map[string]any{
				"name":                     "idp_saml_isv",
				"description":              "This is a saml isv config",
				"protocol":                 "saml",
				"idp_type":                 "isv",
				"scim":                     "yes",
				"scim_base_path":           "https://example.ibm.com/v2.0/",
				"token_attribute_mappings": map[string]string{"uid": "userID", "first_name": "given_name", "last_name": "family_name", "groups": "groupIds", "email": "email"},
				"jit":                      "yes",
				"scim_attribute_mappings": map[string]any{
					"user": map[string]any{
						"principalName": "userName",
						"givenName":     "name.givenName",
						"middleName":    "name.middleName",
						"familyName":    "name.familyName",
						"formatted":     "name.formatted",
					},
					"group": map[string]any{
						"principalName": "displayName",
						"created":       "meta.created",
						"lastModified":  "meta.lastModified",
					},
				},
				"config": map[string]any{
					"grant_type":    "client_credentials",
					"token_url":     "https://example.ibm.com/v1.0/endpoint/default/token",
					"client_id":     "9de6991f-a6e0-4aab-af3a-d8abd8c9cc95",
					"client_secret": "somesecret",
				},
				"status": "enabled",
			}
			idpConfig, err := ConvertV2SamlToIdpConfig(samlMap)
			Expect(idpConfig).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			Expect(idpConfig).To(HaveField("Name", "idp_saml_isv"))
			Expect(idpConfig).To(HaveField("Description", "This is a saml isv config"))
			Expect(idpConfig).To(HaveField("Protocol", "saml"))
			Expect(idpConfig).To(HaveField("Type", "isv"))
			Expect(idpConfig).To(HaveField("JIT", true))
			Expect(idpConfig.IDPConfig).ToNot(BeEmpty())
			Expect(idpConfig.IDPConfig).To(HaveKey("token_attribute_mappings"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("sub", "userID"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("given_name", "given_name"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("family_name", "family_name"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("groups", "groupIds"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("email", "email"))
			Expect(idpConfig.SCIMConfig).To(HaveKeyWithValue("scim_base_path", "https://example.ibm.com/v2.0/"))
			Expect(idpConfig.SCIMConfig).To(HaveKeyWithValue("grant_type", "client_credentials"))
			Expect(idpConfig.SCIMConfig).To(HaveKeyWithValue("token_url", "https://example.ibm.com/v1.0/endpoint/default/token"))
			Expect(idpConfig.SCIMConfig).To(HaveKeyWithValue("client_id", "9de6991f-a6e0-4aab-af3a-d8abd8c9cc95"))
			Expect(idpConfig.SCIMConfig).To(HaveKeyWithValue("client_secret", "somesecret"))
			Expect(idpConfig.SCIMConfig).To(HaveKey("scim_attribute_mappings"))
			Expect(idpConfig.SCIMConfig["scim_attribute_mappings"]).To(HaveKey("user"))
			Expect(idpConfig.SCIMConfig["scim_attribute_mappings"]).To(HaveKey("group"))
			var user map[string]any
			var group map[string]any
			if value, ok := idpConfig.SCIMConfig["scim_attribute_mappings"].(map[string]any); ok {
				user = value["user"].(map[string]any)
				group = value["group"].(map[string]any)
			}
			Expect(user).To(HaveKeyWithValue("principalName", "userName"))
			Expect(user).To(HaveKeyWithValue("givenName", "name.givenName"))
			Expect(user).To(HaveKeyWithValue("middleName", "name.middleName"))
			Expect(user).To(HaveKeyWithValue("familyName", "name.familyName"))
			Expect(user).To(HaveKeyWithValue("formatted", "name.formatted"))
			Expect(group).To(HaveKeyWithValue("principalName", "displayName"))
			Expect(group).To(HaveKeyWithValue("created", "meta.created"))
			Expect(group).To(HaveKeyWithValue("lastModified", "meta.lastModified"))
		})

		It("converts V2 SAML with LDAP dependency to V3 IdP", func() {
			samlMap = map[string]any{
				"name":        "tivoli-saml-test",
				"description": "saml bluepages with ldap",
				"protocol":    "saml",
				"idp_type":    "default",
				"saml_ldap":   "IBM Tivoli Directory Server",
				"token_attribute_mappings": map[string]string{
					"uid":        "uid",
					"first_name": "firstName",
					"last_name":  "lastName",
					"groups":     "blueGroups",
					"email":      "email",
				},
				"jit":    "no",
				"status": "enabled",
			}
			idpConfig, err := ConvertV2SamlToIdpConfig(samlMap)
			Expect(idpConfig).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			Expect(idpConfig).To(HaveField("Name", "tivoli-saml-test"))
			Expect(idpConfig).To(HaveField("Description", "saml bluepages with ldap"))
			Expect(idpConfig).To(HaveField("Protocol", "saml"))
			Expect(idpConfig).To(HaveField("Type", "default"))
			Expect(idpConfig).To(HaveField("JIT", false))
			Expect(idpConfig.IDPConfig).ToNot(BeEmpty())
			Expect(idpConfig.IDPConfig).To(HaveKey("token_attribute_mappings"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("sub", "uid"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("given_name", "firstName"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("family_name", "lastName"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("groups", "blueGroups"))
			Expect(idpConfig.IDPConfig["token_attribute_mappings"]).To(HaveKeyWithValue("email", "email"))
			Expect(idpConfig.LDAPId).To(Equal("IBM Tivoli Directory Server"))
		})
	})
})

var _ = Describe("SCIM JIT Migration", func() {
	Describe("Converts input map to Group struct", func() {
		var grp map[string]any
		It("Converts foo to bar", func() {
			grp = map[string]any{
				"_id":         "test-group",
				"displayName": "test-group",
			}
			group, err := ConvertToGroup(grp)
			Expect(group).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			Expect(group).To(HaveField("GroupID", "test-group"))
			Expect(group).To(HaveField("DisplayName", "test-group"))
			Expect(group).To(HaveField("RealmID", "defaultSP"))
		})
	})

	Describe("GetMembersForGroup", func() {
		var grp map[string]any
		It("Returns all member.value as slice", func() {
			grp = map[string]any{
				"members": []Member{
					{
						Value:   "test-user-1",
						Display: "Test User 1",
					},
					{
						Value:   "test-user-2",
						Display: "Test User 2",
					},
				},
			}
			members, err := GetMembersForGroup(grp)
			Expect(members).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			Expect(len(members)).To(Equal(2))
			Expect(members).To(HaveExactElements(
				"test-user-1",
				"test-user-2",
			))
		})
	})
})
