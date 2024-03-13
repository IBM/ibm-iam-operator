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
				idpConfig := ConvertV2DirectoryToV3IdpConfig(dirMap)
				Expect(idpConfig).ToNot(BeNil())
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
			It("returns nil when it is set to \"true\"", func() {
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
				idpConfig := ConvertV2DirectoryToV3IdpConfig(dirMap)
				Expect(idpConfig).To(BeNil())
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
					"CP3MIGRATED":           "false",
				}
				idpConfig := ConvertV2DirectoryToV3IdpConfig(dirMap)
				Expect(idpConfig).ToNot(BeNil())
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
				idpConfig := ConvertV2DirectoryToV3IdpConfig(dirMap)
				Expect(idpConfig).ToNot(BeNil())
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
				idpConfig := ConvertV2DirectoryToV3IdpConfig(dirMap)
				Expect(idpConfig).To(BeNil())
			})
		})
	})
})
