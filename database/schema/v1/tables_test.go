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

package v1

import (
	"github.com/jackc/pgx/v5/pgtype"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

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
				idpConfigMap = RowDataToAnyMap(idpConfig)
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

var _ = DescribeTable("TeamUsers.GetUser", func(id string, expected *TeamUser) {
	users := TeamUsers{
		&TeamUser{UserID: "user1", Roles: TeamRoles{&TeamRole{ID: "crn:v1:icp:private:iam::::role:ClusterAdministrator"}}},
		&TeamUser{UserID: "user2", Roles: TeamRoles{&TeamRole{ID: "crn:v1:icp:private:iam::::role:Viewer"}}},
		&TeamUser{UserID: "user3", Roles: TeamRoles{&TeamRole{ID: "crn:v1:icp:private:iam::::role:Editor"}}},
		&TeamUser{UserID: "user4", Roles: TeamRoles{&TeamRole{ID: "crn:v1:icp:private:iam::::role:Administrator"}}},
		&TeamUser{UserID: "user4", Roles: TeamRoles{&TeamRole{ID: "crn:v1:icp:private:iam::::role:"}}},
		&TeamUser{UserID: "user5", Roles: TeamRoles{&TeamRole{ID: ""}}},
	}
	actual := users.GetUser(id)
	Expect(actual).To(Equal(expected))
},
	Entry("", "user1", &TeamUser{UserID: "user1", Roles: TeamRoles{&TeamRole{ID: "crn:v1:icp:private:iam::::role:ClusterAdministrator"}}}),
	Entry("", "user2", &TeamUser{UserID: "user2", Roles: TeamRoles{&TeamRole{ID: "crn:v1:icp:private:iam::::role:Viewer"}}}),
	Entry("", "user3", &TeamUser{UserID: "user3", Roles: TeamRoles{&TeamRole{ID: "crn:v1:icp:private:iam::::role:Editor"}}}),
	Entry("", "user4", &TeamUser{UserID: "user4", Roles: TeamRoles{&TeamRole{ID: "crn:v1:icp:private:iam::::role:Administrator"}}}),
	Entry("", "user5", &TeamUser{UserID: "user5", Roles: TeamRoles{&TeamRole{ID: ""}}}),
	Entry("", "user0", nil),
)

var _ = DescribeTable("TeamRoles.GetHighestRole", func(roles TeamRoles, expected Role) {
	actual := roles.GetHighestRole()
	Expect(actual).To(Equal(expected))
},
	Entry("Returns correct role from role CRN", TeamRoles{&TeamRole{ID: "crn:v1:icp:private:iam::::role:ClusterAdministrator"}}, ClusterAdmin),
	Entry("Returns Authenticated role when *TeamRole has empty ID", TeamRoles{&TeamRole{ID: ""}}, Authenticated),
	Entry("Returns Authenticated role when *TeamRole is nil", nil, Authenticated),
	Entry("Retrieves highest role among elements in TeamRoles", TeamRoles{
		&TeamRole{ID: "crn:v1:icp:private:iam::::role:Administrator"},
		&TeamRole{ID: "crn:v1:icp:private:iam::::role:"},
		&TeamRole{ID: "crn:v1:icp:private:iam::::role:ClusterAdministrator"},
		&TeamRole{ID: "crn:v1:icp:private:iam::::role:Viewer"},
		nil,
	}, ClusterAdmin),
	Entry("Returns Authenticated role if CRN prefix is invalid", TeamRoles{&TeamRole{ID: "crncrn:v1:icp:private:iam::::role:ClusterAdministrator"}}, Authenticated),
)

var _ = DescribeTable("Role.ToV3String", func(r Role, expected string) {
	actual := r.ToV3String()
	Expect(actual).To(Equal(expected))
},
	Entry("ClusterAdministrator is converted to Administrator for V3", ClusterAdmin, "Administrator"),
	Entry("CloudPakAdministrator is converted to Administrator for V3", CloudPakAdmin, "Administrator"),
	Entry("Administrator is Administrator for V3", Administrator, "Administrator"),
	Entry("Operator is converted to Viewer for V3", Operator, "Viewer"),
	Entry("Editor is converted to Viewer for V3", Editor, "Viewer"),
	Entry("Viewer is Viewer for V3", Viewer, "Viewer"),
	Entry("Auditor is converted to Viewer for V3", Auditor, "Viewer"),
	Entry("Authenticated is \"\" for V3", Authenticated, ""),
	Entry("Anything else is the Authenticated role", Role(8), ""),
)

var _ = DescribeTable("GetRole", func(s string, expected Role) {
	actual := GetRole(s)
	Expect(actual).To(Equal(expected))
},
	Entry("ClusterAdministrator has corresponding role", "ClusterAdministrator", ClusterAdmin),
	Entry("CloudPakAdministrator has corresponding role", "CloudPakAdministrator", CloudPakAdmin),
	Entry("Administrator has corresponding role", "Administrator", Administrator),
	Entry("Operator has corresponding role", "Operator", Operator),
	Entry("Editor has corresponding role", "Editor", Editor),
	Entry("Auditor has corresponding role", "Auditor", Auditor),
	Entry("Viewer has corresponding role", "Viewer", Viewer),
	Entry("\"\" has corresponding role", "", Authenticated),
	Entry("Anything else is the Authenticated role", "someotherstring", Authenticated),
)

var _ = DescribeTable("Role.ToString", func(r Role, expected string) {
	actual := r.ToString()
	Expect(actual).To(Equal(expected))
},
	Entry("ClusterAdministrator", ClusterAdmin, "ClusterAdministrator"),
	Entry("CloudPakAdministrator", CloudPakAdmin, "CloudPakAdministrator"),
	Entry("Administrator", Administrator, "Administrator"),
	Entry("Operator", Operator, "Operator"),
	Entry("Editor", Editor, "Editor"),
	Entry("Auditor", Auditor, "Auditor"),
	Entry("Viewer", Viewer, "Viewer"),
	Entry("\"\"", Authenticated, ""),
	Entry("\"\"", Role(8), ""),
)

var _ = DescribeTable("RowDataToAnyMap", func(r RowData, expected map[string]any) {
	actual := RowDataToAnyMap(r)
	Expect(actual).To(Equal(expected))
},
	Entry("on Changelog",
		&Changelog{
			ID:          5,
			Name:        "TestChange",
			IMVersion:   "4.10.0",
			InstallTime: &pgtype.Timestamptz{},
		},
		map[string]any{
			"id":           5,
			"name":         "TestChange",
			"im_version":   "4.10.0",
			"install_time": &pgtype.Timestamptz{},
		}),
	Entry("on OauthToken",
		&OauthToken{
			LookupKey:   "lookupkey",
			UniqueID:    "uniqueid",
			ProviderID:  "providerid",
			Type:        "type",
			SubType:     "subtype",
			CreatedAt:   int64(0),
			Lifetime:    int(1),
			Expires:     int64(2),
			TokenString: "tokenstring",
			ClientID:    "clientid",
			UserName:    "username",
			Scope:       "scope",
			RedirectUri: "redirecturi",
			StateID:     "stateid",
			Props:       "props",
		},
		map[string]any{
			"LOOKUPKEY":   "lookupkey",
			"UNIQUEID":    "uniqueid",
			"PROVIDERID":  "providerid",
			"TYPE":        "type",
			"SUBTYPE":     "subtype",
			"CREATEDAT":   int64(0),
			"LIFETIME":    int(1),
			"EXPIRES":     int64(2),
			"TOKENSTRING": "tokenstring",
			"CLIENTID":    "clientid",
			"USERNAME":    "username",
			"SCOPE":       "scope",
			"REDIRECTURI": "redirecturi",
			"STATEID":     "stateid",
			"PROPS":       "props",
		}))
