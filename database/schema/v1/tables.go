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
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"reflect"
	"strings"

	dbconn "github.com/IBM/ibm-iam-operator/database/connectors"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Row represents a row in a table, whether that be one directly retrieved from a database or one being used as part of
// a write or other query to that database.
type RowData interface {
	ToAnySlice() []any        // converts the row into a slice where each index contains one column's data
	GetColumnNames() []string // states the column names for the row; a column name must be in the same index as its corresponding data in the return from ToAnySlice.
	GetInsertSQL() string     // produces the SQL used to perform an INSERT of this row
}

// RowDataToAnyMap produces a map of column names to column data for the provided RowData.
func RowDataToAnyMap(r RowData) map[string]any {
	m := make(map[string]any)
	anySlice := r.ToAnySlice()
	for i, col := range r.GetColumnNames() {
		m[col] = anySlice[i]
	}
	return m
}

// GetNamedArgsFromRow generates a pgx.NamedArgs for use with the pgx's Conn functions.
// e.g.
//
//	conn.Exec(ctx, rowData.GetInsertSQL(), GetNamedArgsFromRow(rowData))
func GetNamedArgsFromRow(r RowData) pgx.NamedArgs {
	args := pgx.NamedArgs{}
	for k, v := range RowDataToAnyMap(r) {
		args[k] = v
	}
	return args
}

//go:embed dbinit.sql
var DBInitMigration string

// translateMongoDBFieldsToPostgresColumns ensures that the MongoDB schema is converted over to the schema written to
// Postgres; it takes a map of MongoDB field names to their Postgres column names.
func translateMongoDBFieldsToPostgresColumns(fieldMap map[string]string, m map[string]any) {
	for fieldName, colName := range fieldMap {
		if _, ok := m[fieldName]; !ok {
			continue
		}
		fieldValue := reflect.ValueOf(m[fieldName])
		if fieldValue.IsValid() && !reflect.DeepEqual(fieldValue.Interface(), reflect.Zero(fieldValue.Type())) {
			m[colName] = m[fieldName]
		}
	}
}

type OIDCClient struct {
	ID           string `json:"_id"`
	ClientID     string `json:"clientid"`
	ProviderID   string `json:"providerid"`
	ClientSecret string `json:"clientsecret"`
	DisplayName  string `json:"displayname"`
	Enabled      bool   `json:"enabled"`
	Metadata     string `json:"metadata"`
}

func ConvertToOIDCClient(clientMap map[string]any, oc *OIDCClient) (err error) {
	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(clientMap); err != nil {
		return
	}

	if err = json.Unmarshal(jsonBytes, oc); err != nil {
		return
	}

	return nil
}

func ConvertToOIDCClients(clientMaps []map[string]any, ocRows []OIDCClient) (err error) {
	for i, clientMap := range clientMaps {
		oc := &OIDCClient{}
		if err = ConvertToOIDCClient(clientMap, oc); err != nil {
			return fmt.Errorf("failed to convert map to OIDCClient: %w", err)
		}
		ocRows[i] = *oc
	}
	return
}

func (oc *OIDCClient) GetColumnNames() []string {
	return []string{
		"_id",
		"clientid",
		"providerid",
		"clientsecret",
		"displayname",
		"enabled",
		"metadata",
	}
}

func (oc *OIDCClient) GetInsertSQL() string {
	return `
		INSERT INTO oauthdbschema.oauthclient
		(_id, clientid, providerid, clientsecret, displayname, enabled, metadata)
		VALUES (DEFAULT, @clientid, @providerid, @clientsecret, @displayname, @enabled, @metadata)
		ON CONFLICT DO NOTHING
		RETURNING _id;`
}

func (oc *OIDCClient) GetTableIdentifier() pgx.Identifier {
	return pgx.Identifier{"oauthdbschema", "oauthclient"}
}

func (oc *OIDCClient) ToAnySlice() []any {
	return []any{
		oc.ID,
		oc.ClientID,
		oc.ProviderID,
		oc.ClientSecret,
		oc.DisplayName,
		oc.Enabled,
		oc.Metadata,
	}
}

// IdpConfig is a row from the `platformdb.idp_configs` table
type IdpConfig struct {
	UID         string         `json:"uid"`
	Description string         `json:"description"`
	Enabled     bool           `json:"enabled"`
	IDPConfig   map[string]any `json:"idp_config"`
	Name        string         `json:"name"`
	Protocol    string         `json:"protocol"`
	Type        string         `json:"type"`
	SCIMConfig  map[string]any `json:"scim_config"`
	JIT         bool           `json:"jit"`
	LDAPId      string         `json:"ldap_id"`
}

func (i *IdpConfig) ToAnySlice() []any {
	return []any{
		i.UID,
		i.Description,
		i.Enabled,
		i.IDPConfig,
		i.Name,
		i.Protocol,
		i.Type,
		i.SCIMConfig,
		i.JIT,
		i.LDAPId,
	}
}

func (i *IdpConfig) GetColumnNames() []string {
	return IdpConfigColumnNames
}

func (i *IdpConfig) GetTableIdentifier() pgx.Identifier {
	return IdpConfigsIdentifier
}

func (i *IdpConfig) GetInsertSQL() string {
	return `
		INSERT INTO platformdb.idp_configs
		(uid, description, enabled, idp_config, name, protocol, type, scim_config, jit, ldap_id)
		VALUES (@uid, @description, @enabled, @idp_config, @name, @protocol, @type, @scim_config, @jit, @ldap_id)
		ON CONFLICT (uid) DO NOTHING
		RETURNING uid;`
}

var IdpConfigColumnNames []string = []string{
	"uid",
	"description",
	"enabled",
	"idp_config",
	"name",
	"protocol",
	"type",
	"scim_config",
	"jit",
	"ldap_id",
}

var IdpConfigsIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "idp_configs"}

func ConvertToIdpConfig(idpMap map[string]any, idpConfig *IdpConfig) (err error) {
	// DDL defaults enabled to true
	if enabled, ok := idpMap["enabled"]; ok && (enabled == "false" || enabled == false) {
		idpMap["enabled"] = false
	} else {
		idpMap["enabled"] = true
	}
	// SAML with LDAP dependency mongo document will have ldap_config: {ldap_id: <value>}
	// which directly maps to ldap_id column in sql
	if ldap_config, ok := idpMap["ldap_config"]; ok {
		if ldap_config, ok := ldap_config.(map[string]any); ok {
			// If ldap_config is already a map, fetch the ldap_id
			ldap_id := ldap_config["ldap_id"]
			idpMap["ldap_id"] = ldap_id
		}

	}

	if ldapConfig, ok := idpMap["ldap_config"]; ok {
		if ldapConfigMap, isMap := ldapConfig.(map[string]string); isMap {
			if ldapID, hasID := ldapConfigMap["ldap_id"]; hasID {
				idpMap["ldap_id"] = ldapID
			}
		}
	}

	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(idpMap); err != nil {
		return
	}

	if err = json.Unmarshal(jsonBytes, idpConfig); err != nil {
		return
	}

	return nil
}

func ConvertToIdpConfigs(idpMaps []map[string]any, idpRows []IdpConfig) (err error) {
	for i, idpMap := range idpMaps {
		idpConfig := &IdpConfig{}
		if err = ConvertToIdpConfig(idpMap, idpConfig); err != nil {
			return fmt.Errorf("failed to convert map to IdpConfig: %w", err)
		}
		idpRows[i] = *idpConfig
	}
	return
}

// User is a row from the `platformdb.users` table
type User struct {
	UID                *uuid.UUID `json:"uid"`
	UserID             string     `json:"user_id"`
	RealmID            string     `json:"realm_id,omitempty"`
	FirstName          string     `json:"first_name,omitempty"`
	LastName           string     `json:"last_name,omitempty"`
	Email              string     `json:"email,omitempty"`
	Type               string     `json:"type,omitempty"`
	Status             string     `json:"status,omitempty"`
	UserBaseDN         string     `json:"user_basedn,omitempty"`
	Groups             []string   `json:"groups,omitempty"`
	Role               string     `json:"role,omitempty"`
	UniqueSecurityName string     `json:"unique_security_name,omitempty"`
	PreferredUsername  string     `json:"preferred_username,omitempty"`
	DisplayName        string     `json:"display_name,omitempty"`
	Subject            string     `json:"subject,omitempty"`
}

var UserColumnNames []string = []string{
	"uid",
	"user_id",
	"realm_id",
	"first_name",
	"last_name",
	"email",
	"type",
	"status",
	"user_basedn",
	"groups",
	"role",
	"unique_security_name",
	"preferred_username",
	"display_name",
	"subject",
}

var UsersIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "users"}

func (u *User) ToAnySlice() []any {
	return []any{
		u.UID,
		u.UserID,
		u.RealmID,
		u.FirstName,
		u.LastName,
		u.Email,
		u.Type,
		u.Status,
		u.UserBaseDN,
		u.Groups,
		u.Role,
		u.UniqueSecurityName,
		u.PreferredUsername,
		u.DisplayName,
		u.Subject,
	}
}

func (u *User) GetColumnNames() []string {
	return UserColumnNames
}

func (u *User) GetTableIdentifier() pgx.Identifier {
	return UsersIdentifier
}

func (u *User) GetInsertSQL() string {
	return `
		INSERT INTO platformdb.users
		(uid, user_id, realm_id, first_name, last_name, email, type, status, user_basedn, groups, role, unique_security_name, preferred_username, display_name, subject)
		VALUES (
			  DEFAULT
			, @user_id
			, @realm_id
			, @first_name
			, @last_name
			, @email
			, @type
			, @status
			, @user_basedn
			, @groups
			, @role
			, @unique_security_name
			, @preferred_username
			, @display_name
			, @subject
		)
		ON CONFLICT (user_id) DO NOTHING
		RETURNING uid;`
}

func ConvertToUser(userMap map[string]any, user *User) (err error) {
	// If lastLogin is an empty string, delete it in order to make zero value consistent
	if lastLogin, ok := userMap["lastLogin"]; ok && lastLogin == "" {
		delete(userMap, "lastLogin")
	}
	// for SAML type, directoryId can be considered as 'defaultSP'
	if _, ok := userMap["directoryId"]; !ok && userMap["type"] == "SAML" {
		userMap["directoryId"] = "defaultSP"
	}
	fieldMap := map[string]string{
		"_id":                "user_id",
		"uniqueSecurityName": "unique_security_name",
		"userBaseDN":         "user_basedn",
		"firstName":          "first_name",
		"lastName":           "last_name",
		"directoryId":        "realm_id",
	}
	translateMongoDBFieldsToPostgresColumns(fieldMap, userMap)
	if _, ok := userMap["uid"]; !ok {
		userMap["uid"] = uuid.New()
	}
	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(userMap); err != nil {
		return fmt.Errorf("failed to marshal User _id=%q: %w", userMap["_id"], err)
	}

	if err = json.Unmarshal(jsonBytes, user); err != nil {
		return fmt.Errorf("failed to unmarshal User _id=%q: %w", userMap["_id"], err)
	}

	return nil
}

func ConvertToUsers(userMaps []map[string]any, users []User) (err error) {
	for i, userMap := range userMaps {
		user := &User{}
		if err = ConvertToUser(userMap, user); err != nil {
			return fmt.Errorf("failed to convert map to User: %w", err)
		}
		users[i] = *user
	}
	return
}

// UserPreferences is a row from the `platformdb.users_preferences` table
type UserPreferences struct {
	UID        string              `json:"uid"`
	UserUID    string              `json:"user_uid"`
	LastLogin  *pgtype.Timestamptz `json:"last_login"`
	LastLogout *pgtype.Timestamptz `json:"last_logout,omitempty"`
	LoginCount int                 `json:"login_count,omitempty"`
}

var UserPreferencesColumnNames []string = []string{
	"uid",
	"user_uid",
	"last_login",
	"last_logout",
	"login_count",
}

var UsersPreferencesIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "users_preferences"}

func (u *UserPreferences) ToAnySlice() []any {
	return []any{
		u.UID,
		u.UserUID,
		u.LastLogin,
		u.LastLogout,
		u.LoginCount,
	}
}

func (u *UserPreferences) GetColumnNames() []string {
	return UserPreferencesColumnNames
}

func (u *UserPreferences) GetTableIdentifier() pgx.Identifier {
	return UsersPreferencesIdentifier
}

func (u *UserPreferences) GetInsertSQL() string {
	return `
		INSERT INTO platformdb.users_preferences
		(uid, user_uid, last_login, last_logout, login_count)
		VALUES (DEFAULT, @user_uid, @last_login, @last_logout, @login_count)
		ON CONFLICT DO NOTHING;`
}

func ConvertToUserPreferences(userPrefsMap map[string]any, userPrefs *UserPreferences) (err error) {
	// If either of the following is an empty string, delete it in order to make zero value consistent
	if lastLogin, ok := userPrefsMap["lastLogin"]; ok && lastLogin == "" {
		delete(userPrefsMap, "lastLogin")
	}
	if lastLogin, ok := userPrefsMap["lastLogout"]; ok && lastLogin == "" {
		delete(userPrefsMap, "lastLogout")
	}
	if id, ok := userPrefsMap["_id"]; ok {
		if s, sok := id.(string); sok {
			userPrefsMap["_id"] = strings.TrimPrefix(s, "preferenceId_")
		}
	}
	fieldMap := map[string]string{
		"_id":        "user_id",
		"lastLogin":  "last_login",
		"lastLogout": "last_logout",
		"loginCount": "login_count",
	}
	translateMongoDBFieldsToPostgresColumns(fieldMap, userPrefsMap)
	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(userPrefsMap); err != nil {
		return
	}

	if err = json.Unmarshal(jsonBytes, userPrefs); err != nil {
		return fmt.Errorf("failed to unmarshal UserPreference _id=%q: %w", userPrefsMap["_id"], err)
	}

	return nil
}

func ConvertToUsersPreferences(usersPrefsMaps []map[string]any, usersPrefs []UserPreferences) (err error) {
	for i, userPrefsMap := range usersPrefsMaps {
		userPrefs := &UserPreferences{}
		if err = ConvertToUserPreferences(userPrefsMap, userPrefs); err != nil {
			return fmt.Errorf("failed to convert map to UserPreferences: %w", err)
		}
		usersPrefs[i] = *userPrefs
	}
	return
}

// UserAttributes is a row from the `platformdb.users_attributes` table
type UserAttributes struct {
	UID     *uuid.UUID `json:"uid"`
	UserUID *uuid.UUID `json:"user_uid"`
	Name    string     `json:"name,omitempty"`
	Value   string     `json:"value,omitempty"`
}

var UserAttributesColumnNames []string = []string{
	"uid",
	"user_uid",
	"name",
	"value",
}

var UsersAttributesIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "users_attributes"}

func ConvertToUserAttributes(userAttrMap map[string]any, userAttr *UserAttributes) (err error) {
	if _, ok := userAttrMap["uid"]; !ok {
		userAttrMap["uid"] = uuid.New()
	}
	if _, ok := userAttrMap["user_uid"]; !ok {
		userAttrMap["user_uid"] = uuid.New()
	}
	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(userAttrMap); err != nil {
		return
	}

	if err = json.Unmarshal(jsonBytes, userAttr); err != nil {
		return
	}

	return nil
}

func ConvertToUsersAttributes(usersAttrsMaps []map[string]any, usersAttrs []UserAttributes) (err error) {
	for i, userAttrsMap := range usersAttrsMaps {
		userAttr := &UserAttributes{}
		if err = ConvertToUserAttributes(userAttrsMap, userAttr); err != nil {
			return fmt.Errorf("failed to convert map to UserAttributes: %w", err)
		}
		usersAttrs[i] = *userAttr
	}
	return
}

// ZenInstance is a row from the `platformdb.zen_instances` table
type ZenInstance struct {
	InstanceID     string `json:"instance_id"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	ProductNameURL string `json:"product_name_url"`
	ZenAuditURL    string `json:"zen_audit_url,omitempty"`
	Namespace      string `json:"namespace"`
}

var ZenInstanceColumnNames []string = []string{
	"instance_id",
	"client_id",
	"client_secret",
	"product_name_url",
	"zen_audit_url",
	"namespace",
}

var ZenInstancesIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "zen_instances"}

func (z *ZenInstance) ToAnySlice() []any {
	return []any{
		z.InstanceID,
		z.ClientID,
		z.ClientSecret,
		z.ProductNameURL,
		z.ZenAuditURL,
		z.Namespace,
	}
}

func (z *ZenInstance) GetColumnNames() []string {
	return ZenInstanceColumnNames
}

func (z *ZenInstance) GetTableIdentifier() pgx.Identifier {
	return ZenInstancesIdentifier
}

func (z *ZenInstance) GetInsertSQL() string {
	return `
		INSERT INTO platformdb.zen_instances
		(instance_id, namespace, product_name_url, client_id, client_secret, zen_audit_url)
		VALUES (@instance_id, @namespace, @product_name_url, @client_id, @client_secret, @zen_audit_url)
		ON CONFLICT DO NOTHING;`
}

func ConvertToZenInstance(zenInstanceMap map[string]any, zenInstance *ZenInstance) (err error) {
	fieldMap := map[string]string{
		"_id":            "instance_id",
		"clientId":       "client_id",
		"clientSecret":   "client_secret",
		"productNameUrl": "product_name_url",
		"zenAuditUrl":    "zen_audit_url",
	}
	translateMongoDBFieldsToPostgresColumns(fieldMap, zenInstanceMap)
	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(zenInstanceMap); err != nil {
		return
	}

	if err = json.Unmarshal(jsonBytes, zenInstance); err != nil {
		return
	}

	return nil
}

func ConvertToZenInstances(zenInstanceMaps []map[string]any, zenInstances []ZenInstance) (err error) {
	for i, zenInstanceMap := range zenInstanceMaps {
		zenInstance := &ZenInstance{}
		if err = ConvertToZenInstance(zenInstanceMap, zenInstance); err != nil {
			return fmt.Errorf("failed to convert map to ZenInstance: %w", err)
		}
		zenInstances[i] = *zenInstance
	}
	return
}

// ZenInstanceUser is a row from the `platformdb.zen_instances_users` table
type ZenInstanceUser struct {
	UID           string `json:"uid"`
	ZenInstanceID string `json:"zen_instance_id"`
	UserID        string `json:"user_id"`
}

var ZenInstanceUserColumnNames []string = []string{
	"uid",
	"zen_instance_id",
	"user_id",
}

var ZenInstanceUsersIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "zen_instances_users"}

func (z *ZenInstanceUser) ToAnySlice() []any {
	return []any{
		z.UID,
		z.ZenInstanceID,
		z.UserID,
	}
}

func (z *ZenInstanceUser) GetColumnNames() []string {
	return ZenInstanceUserColumnNames
}

func (z *ZenInstanceUser) GetTableIdentifier() pgx.Identifier {
	return ZenInstanceUsersIdentifier
}

func (z *ZenInstanceUser) GetInsertSQL() string {
	return `
		INSERT INTO platformdb.zen_instances_users
		(uid, zen_instance_id, user_id)
		VALUES (DEFAULT, @zen_instance_id, @user_id)
		ON CONFLICT DO NOTHING;`
}

func ConvertToZenInstanceUser(zenInstanceUserMap map[string]any, zenInstanceUser *ZenInstanceUser) (err error) {
	fieldMap := map[string]string{
		"_id":           "uid",
		"zenInstanceId": "zen_instance_id",
		"usersId":       "user_id",
	}
	translateMongoDBFieldsToPostgresColumns(fieldMap, zenInstanceUserMap)
	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(zenInstanceUserMap); err != nil {
		return
	}

	if err = json.Unmarshal(jsonBytes, zenInstanceUser); err != nil {
		return
	}

	return nil
}

func ConvertToZenInstanceUsers(zenInstanceUserMaps []map[string]any, zenInstanceUsers []ZenInstanceUser) (err error) {
	for i, zenInstanceUserMap := range zenInstanceUserMaps {
		zenInstanceUser := &ZenInstanceUser{}
		if err = ConvertToZenInstanceUser(zenInstanceUserMap, zenInstanceUser); err != nil {
			return fmt.Errorf("failed to convert map to ZenInstanceUser: %w", err)
		}
		zenInstanceUsers[i] = *zenInstanceUser
	}
	return
}

type SCIMAttributes struct {
	ID    string         `json:"id"`
	Group map[string]any `json:"group"`
	User  map[string]any `json:"user"`
}

var SCIMAttributesColumnNames []string = []string{
	"id",
	"group",
	"user",
}

var SCIMAttributesIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "scim_attributes"}

func ConvertToSCIMAttributes(scimAttributesMap map[string]any, scimAttributes *SCIMAttributes) (err error) {
	fieldMap := map[string]string{
		"_id": "id",
	}
	translateMongoDBFieldsToPostgresColumns(fieldMap, scimAttributesMap)
	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(scimAttributesMap); err != nil {
		return
	}

	if err = json.Unmarshal(jsonBytes, scimAttributes); err != nil {
		return
	}

	return nil
}

func ConvertToSCIMAttributesSlice(scimAttributesMaps []map[string]any, scimAttributesSlice []SCIMAttributes) (err error) {
	for i, scimAttributesMap := range scimAttributesMaps {
		scimAttributes := &SCIMAttributes{}
		if err = ConvertToSCIMAttributes(scimAttributesMap, scimAttributes); err != nil {
			return fmt.Errorf("failed to convert map to ZenInstanceUser: %w", err)
		}
		scimAttributesSlice[i] = *scimAttributes
	}
	return
}

type SCIMAttributesMapping struct {
	IdpID   string         `json:"idp_id"`
	IdpType string         `json:"idp_type"`
	Group   map[string]any `json:"group"`
	User    map[string]any `json:"user"`
}

var SCIMAttributesMappingsColumnNames []string = []string{
	"idp_id",
	"idp_type",
	"group",
	"user",
}

var SCIMAttributesMappingsIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "scim_attributes_mappings"}

func ConvertToSCIMAttributesMapping(scimAttributesMappingMap map[string]any, scimAttributesMapping *SCIMAttributesMapping) (err error) {
	fieldMap := map[string]string{
		"_id": "idp_id",
	}
	translateMongoDBFieldsToPostgresColumns(fieldMap, scimAttributesMappingMap)
	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(scimAttributesMappingMap); err != nil {
		return
	}

	if err = json.Unmarshal(jsonBytes, scimAttributesMapping); err != nil {
		return
	}

	return nil
}

func ConvertToSCIMAttributesMappingSlice(scimAttributesMappingMaps []map[string]any, scimAttributesMappingSlice []SCIMAttributesMapping) (err error) {
	for i, scimAttributesMappingMap := range scimAttributesMappingMaps {
		scimAttributesMapping := &SCIMAttributesMapping{}
		if err = ConvertToSCIMAttributesMapping(scimAttributesMappingMap, scimAttributesMapping); err != nil {
			return fmt.Errorf("failed to convert map to ZenInstanceUser: %w", err)
		}
		scimAttributesMappingSlice[i] = *scimAttributesMapping
	}
	return
}

func ConvertV2DirectoryToV3IdpConfig(dirMap map[string]any) (v3Config *IdpConfig, err error) {
	v3Config = &IdpConfig{}
	idpConfig := make(map[string]any)

	if uid, ok := dirMap["_id"]; ok {
		if v3Config.UID, ok = uid.(string); !ok {
			return nil, fmt.Errorf("_id of Directory is not a string")
		}
	}
	if id, ok := dirMap["LDAP_ID"]; ok {
		if v3Config.Name, ok = id.(string); !ok {
			return nil, fmt.Errorf("LDAP_ID of Directory is not a string")
		}
		idpConfig["ldap_id"] = id
	}
	if lType, ok := dirMap["LDAP_TYPE"]; ok {
		if v3Config.Type, ok = lType.(string); !ok {
			return nil, fmt.Errorf("LDAP_TYPE of Directory is not a string")
		}
		idpConfig["ldap_type"] = lType
	}
	if realm, ok := dirMap["LDAP_REALM"]; ok {
		idpConfig["ldap_realm"] = realm
	}
	if url, ok := dirMap["LDAP_URL"]; ok {
		idpConfig["ldap_url"] = url
	}
	if host, ok := dirMap["LDAP_HOST"]; ok {
		idpConfig["ldap_host"] = host
	}
	if port, ok := dirMap["LDAP_PORT"]; ok {
		idpConfig["ldap_port"] = port
	}
	if protocol, ok := dirMap["LDAP_PROTOCOL"]; ok {
		idpConfig["ldap_protocol"] = protocol
	}
	if basedn, ok := dirMap["LDAP_BASEDN"]; ok {
		idpConfig["ldap_basedn"] = basedn
	}
	if binddn, ok := dirMap["LDAP_BINDDN"]; ok {
		idpConfig["ldap_binddn"] = binddn
	}
	if bindpassword, ok := dirMap["LDAP_BINDPASSWORD"]; ok {
		idpConfig["ldap_bindpassword"] = bindpassword
	}
	if ignoreCase, ok := dirMap["LDAP_IGNORECASE"]; ok {
		idpConfig["ldap_ignorecase"] = ignoreCase
	}
	if userfilter, ok := dirMap["LDAP_USERFILTER"]; ok {
		idpConfig["ldap_userfilter"] = userfilter
	}
	if useridmap, ok := dirMap["LDAP_USERIDMAP"]; ok {
		idpConfig["ldap_useridmap"] = useridmap
	}
	if groupfilter, ok := dirMap["LDAP_GROUPFILTER"]; ok {
		idpConfig["ldap_groupfilter"] = groupfilter
	}
	if groupidmap, ok := dirMap["LDAP_GROUPIDMAP"]; ok {
		idpConfig["ldap_groupidmap"] = groupidmap
	}
	if groupmemberidmap, ok := dirMap["LDAP_GROUPMEMBERIDMAP"]; ok {
		idpConfig["ldap_groupmemberidmap"] = groupmemberidmap
	}
	if nestedSearch, ok := dirMap["LDAP_NESTEDSEARCH"]; ok {
		idpConfig["ldap_nestedsearch"] = nestedSearch
	}
	if pagingSearch, ok := dirMap["LDAP_PAGINGSEARCH"]; ok {
		idpConfig["ldap_pagingsearch"] = pagingSearch
	}
	if pagingSize, ok := dirMap["LDAP_PAGINGSIZE"]; ok {
		idpConfig["ldap_pagingsize"] = pagingSize
	}
	v3Config.Description = ""
	v3Config.Protocol = "ldap"
	v3Config.IDPConfig = idpConfig
	v3Config.Enabled = true

	return
}

func ConvertV2SamlToIdpConfig(samlMap map[string]any) (v3Config *IdpConfig, err error) {
	v3Config = &IdpConfig{}
	idpConfig := make(map[string]any)
	scimConfig := make(map[string]any)
	tokenAttributeMapping := make(map[string]any)
	v3Config.UID = "defaultSP"

	if protocol, ok := samlMap["protocol"]; ok {
		if v3Config.Protocol, ok = protocol.(string); !ok {
			return nil, fmt.Errorf("protocol of SAML is not a string")
		} else if v3Config.Protocol != "saml" {
			return nil, fmt.Errorf("protocol of SAML is not \"saml\"")
		}
	} else {
		return nil, fmt.Errorf("protocol of SAML is not set")
	}
	if name, ok := samlMap["name"]; ok {
		if v3Config.Name, ok = name.(string); !ok {
			return nil, fmt.Errorf("name of SAML is not a string")
		}
	}
	if description, ok := samlMap["description"]; ok {
		if v3Config.Description, ok = description.(string); !ok {
			return nil, fmt.Errorf("description of SAML is not a string")
		}
	}
	if iType, ok := samlMap["idp_type"]; ok {
		if v3Config.Type, ok = iType.(string); !ok {
			return nil, fmt.Errorf("idp_type of SAML is not a string")
		}
	}
	if jit, ok := samlMap["jit"]; ok {
		if jitString, ok := jit.(string); ok && jitString == "yes" {
			v3Config.JIT = true
		}
	}
	if value, ok := samlMap["saml_ldap"]; ok {
		if samlLdap, ok := value.(string); ok && strings.ToLower(samlLdap) != "none" {
			v3Config.LDAPId = samlLdap
		}
	}
	if value, ok := samlMap["token_attribute_mappings"]; ok {
		if mappings, ok := value.(map[string]string); ok {
			tokenAttributeMapping["sub"] = ""
			tokenAttributeMapping["given_name"] = ""
			tokenAttributeMapping["family_name"] = ""
			tokenAttributeMapping["groups"] = ""
			tokenAttributeMapping["email"] = ""
			if sub, ok := mappings["uid"]; ok {
				tokenAttributeMapping["sub"] = sub
			}
			if givenName, ok := mappings["first_name"]; ok {
				tokenAttributeMapping["given_name"] = givenName
			}
			if familyName, ok := mappings["last_name"]; ok {
				tokenAttributeMapping["family_name"] = familyName
			}
			if groups, ok := mappings["groups"]; ok {
				tokenAttributeMapping["groups"] = groups
			}
			if email, ok := mappings["email"]; ok {
				tokenAttributeMapping["email"] = email
			}
		}
	}
	idpConfig["token_attribute_mappings"] = tokenAttributeMapping
	v3Config.IDPConfig = idpConfig

	if value, ok := samlMap["scim"]; ok {
		if scimEnabled, ok := value.(string); !ok || scimEnabled != "yes" {
			return
		}
	}
	if value, ok := samlMap["scim_base_path"]; !ok {
		return
	} else {
		scimConfig["scim_base_path"] = ""
		if scimBasePath, ok := value.(string); ok {
			scimConfig["scim_base_path"] = scimBasePath
		}
	}
	scimConfig["grant_type"] = ""
	scimConfig["token_url"] = ""
	scimConfig["client_id"] = ""
	scimConfig["client_secret"] = ""

	if value, ok := samlMap["config"]; ok {
		if config, ok := value.(map[string]any); ok {
			if grantType, ok := config["grant_type"]; ok {
				scimConfig["grant_type"] = grantType
			}
			if tokenUrl, ok := config["token_url"]; ok {
				scimConfig["token_url"] = tokenUrl
			}
			if clientId, ok := config["client_id"]; ok {
				scimConfig["client_id"] = clientId
			}
			if clientSecret, ok := config["client_secret"]; ok {
				scimConfig["client_secret"] = clientSecret
			}
		}
	}
	scimAttributeMappings := make(map[string]any)
	if value, ok := samlMap["scim_attribute_mappings"]; ok {
		if mappings, ok := value.(map[string]any); ok {
			if user, ok := mappings["user"]; ok {
				scimAttributeMappings["user"] = user
			}
			if group, ok := mappings["group"]; ok {
				scimAttributeMappings["group"] = group
			}
		}
	}
	scimConfig["scim_attribute_mappings"] = scimAttributeMappings
	v3Config.SCIMConfig = scimConfig
	v3Config.Enabled = true
	return
}

type Role int

const (
	Authenticated Role = iota
	Viewer
	Auditor
	Editor
	Operator
	Administrator
	CloudPakAdmin
	ClusterAdmin
)

// ToString returns an IAM-compatible role name as a string.
func (r Role) ToString() (s string) {
	switch r {
	case ClusterAdmin:
		return "ClusterAdministrator"
	case CloudPakAdmin:
		return "CloudPakAdministrator"
	case Administrator:
		return "Administrator"
	case Operator:
		return "Operator"
	case Editor:
		return "Editor"
	case Viewer:
		return "Viewer"
	case Auditor:
		return "Auditor"
	default:
		return
	}
}

// GetRole takes a string role name and returns the corresponding Role. If the string is not a known name, it returns
// the lowest role.
func GetRole(s string) (r Role) {
	switch s {
	case "ClusterAdministrator":
		return ClusterAdmin
	case "CloudPakAdministrator":
		return CloudPakAdmin
	case "Administrator":
		return Administrator
	case "Operator":
		return Operator
	case "Editor":
		return Editor
	case "Viewer":
		return Viewer
	case "Auditor":
		return Auditor
	default:
		return Authenticated
	}
}

// ToV3String returns an IM-compatible role name as a string. In IM, there are only three valid roles - Administrator,
// Viewer, and Authenticated.
func (r Role) ToV3String() (s string) {
	if r >= Administrator && r <= ClusterAdmin {
		return Administrator.ToString()
	} else if r >= Viewer && r < Administrator {
		return Viewer.ToString()
	} else {
		return Authenticated.ToString()
	}
}

type TeamRole struct {
	ID string `bson:"id"`
}

type TeamRoles []*TeamRole

func (t TeamRoles) GetHighestRole() (highest Role) {
	crnPrefix := "crn:v1:icp:private:iam::::role:"
	for _, r := range t {
		if r == nil {
			continue
		}
		if current := GetRole(strings.TrimPrefix(r.ID, crnPrefix)); current > highest {
			highest = current
		}
	}
	return
}

type TeamUser struct {
	UserID string    `bson:"userId"`
	Roles  TeamRoles `bson:"roles"`
}

type TeamUsers []*TeamUser

func (t TeamUsers) GetUser(id string) (user *TeamUser) {
	for _, user := range t {
		if user.UserID == id {
			return user
		}
	}
	return nil
}

type Team struct {
	ID    string    `bson:"_id"`
	Users TeamUsers `bson:"users"`
}

// ScimServerUser is a row from the `platformdb.scim_server_users` table
type ScimServerUser struct {
	ID           string         `json:"id"`
	Schemas      []string       `json:"schemas,omitempty"`
	ExternalID   string         `json:"external_id,omitempty"`
	UserName     string         `json:"user_name,omitempty"`
	Name         map[string]any `json:"name,omitempty"`
	DisplayName  string         `json:"display_name,omitempty"`
	Emails       []any          `json:"emails,omitempty"`
	Addresses    []any          `json:"addresses,omitempty"`
	PhoneNumbers []any          `json:"phone_numbers,omitempty"`
	USerType     string         `json:"user_type,omitempty"`
	Active       bool           `json:"active,omitempty"`
	Meta         map[string]any `json:"meta,omitempty"`
	Groups       []any          `json:"groups,omitempty"`
}

var ScimServerUsersColumnNames []string = []string{
	"id",
	"schemas",
	"external_id",
	"user_name",
	"name",
	"display_name",
	"emails",
	"addresses",
	"phone_numbers",
	"user_type",
	"active",
	"meta",
	"groups",
}

var ScimServerUsersMongoFieldNames []string = []string{
	"id",
	"schemas",
	"externalId",
	"userName",
	"name",
	"displayName",
	"emails",
	"addresses",
	"phoneNumbers",
	"userType",
	"active",
	"meta",
	"groups",
}

var ScimServerUsersIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "scim_server_users"}

func (ssu *ScimServerUser) ToAnySlice() []any {
	return []any{
		ssu.ID,
		ssu.Schemas,
		ssu.ExternalID,
		ssu.UserName,
		ssu.Name,
		ssu.DisplayName,
		ssu.Emails,
		ssu.Addresses,
		ssu.PhoneNumbers,
		ssu.USerType,
		ssu.Active,
		ssu.Meta,
		ssu.Groups,
	}
}

func (ssu *ScimServerUser) GetColumnNames() []string {
	return ScimServerUsersColumnNames
}

func (ssu *ScimServerUser) GetTableIdentifier() pgx.Identifier {
	return ScimServerUsersIdentifier
}

func (ssu *ScimServerUser) GetInsertSQL() string {
	return `
		INSERT INTO platformdb.scim_server_users
		(id, schemas, external_id, user_name, name, display_name, emails, addresses, phone_numbers, user_type, active, meta, groups)
		VALUES (@id, @schemas, @external_id, @user_name, @name, @display_name, @emails, @addresses, @phone_numbers, @user_type, @active, @meta, @groups)
		ON CONFLICT DO NOTHING RETURNING id;`
}

func ConvertToScimServerUser(scimServerUserMap map[string]any, scimServerUser *ScimServerUser) (err error) {
	delete(scimServerUserMap, "_id")
	fieldMap := map[string]string{
		"externalId":   "external_id",
		"userName":     "user_name",
		"displayName":  "display_name",
		"phoneNumbers": "phone_numbers",
		"userType":     "user_type",
	}
	translateMongoDBFieldsToPostgresColumns(fieldMap, scimServerUserMap)
	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(scimServerUserMap); err != nil {
		return
	}

	if err = json.Unmarshal(jsonBytes, scimServerUser); err != nil {
		return fmt.Errorf("failed to unmarshal ScimServerUser id=%q: %w", scimServerUserMap["id"], err)
	}

	return nil
}

// ScimServerUserCustom is a row from the `platformdb.scim_server_users_custom` table
type ScimServerUserCustom struct {
	ScimServerUserUID     string `json:"scim_server_user_uid"`
	AttributeKey          string `json:"attribute_key"`
	SchemaName            string `json:"schema_name,omitempty"`
	AttributeValue        string `json:"attribute_value,omitempty"`
	AttributeValueComplex any    `json:"attribute_value_complex,omitempty"`
}

var ScimServerUsersCustomColumnNames []string = []string{
	"scim_server_user_uid",
	"attribute_key",
	"schema_name",
	"attribute_value",
	"attribute_value_complex",
}

var ScimServerUsersCustomIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "scim_server_users_custom"}

func (ssuc *ScimServerUserCustom) ToAnySlice() []any {
	return []any{
		ssuc.ScimServerUserUID,
		ssuc.AttributeKey,
		ssuc.SchemaName,
		ssuc.AttributeValue,
		ssuc.AttributeValueComplex,
	}
}

func (ssuc *ScimServerUserCustom) GetColumnNames() []string {
	return ScimServerUsersCustomColumnNames
}

func (ssuc *ScimServerUserCustom) GetTableIdentifier() pgx.Identifier {
	return ScimServerUsersCustomIdentifier
}

func (ssuc *ScimServerUserCustom) GetInsertSQL() string {
	return `
		INSERT INTO platformdb.scim_server_users_custom
		(scim_server_user_uid, attribute_key, schema_name, attribute_value, attribute_value_complex)
		VALUES (@scim_server_user_uid, @attribute_key, @schema_name, @attribute_value, @attribute_value_complex)
		ON CONFLICT DO NOTHING RETURNING scim_server_user_uid;`
}

// ScimServerGroup is a row from the `platformdb.scim_server_groups` table
type ScimServerGroup struct {
	ID          string         `json:"id"`
	Schemas     []string       `json:"schemas,omitempty"`
	DisplayName string         `json:"display_name,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
	Members     []any          `json:"members,omitempty"`
}

var ScimServerGroupsColumnNames []string = []string{
	"id",
	"schemas",
	"display_name",
	"meta",
	"members",
}

var ScimServerGroupsMongoFieldNames []string = []string{
	"id",
	"schemas",
	"displayName",
	"meta",
	"members",
}

var ScimServerGroupsIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "scim_server_groups"}

func (ssg *ScimServerGroup) ToAnySlice() []any {
	return []any{
		ssg.ID,
		ssg.Schemas,
		ssg.DisplayName,
		ssg.Meta,
		ssg.Members,
	}
}

func (ssg *ScimServerGroup) GetColumnNames() []string {
	return ScimServerGroupsColumnNames
}

func (ssg *ScimServerGroup) GetTableIdentifier() pgx.Identifier {
	return ScimServerGroupsIdentifier
}

func (ssg *ScimServerGroup) GetInsertSQL() string {
	return `
		INSERT INTO platformdb.scim_server_groups
		(id, schemas, members, display_name, meta)
		VALUES (@id, @schemas, @members, @display_name, @meta)
		ON CONFLICT DO NOTHING RETURNING id;`
}

func ConvertToScimServerGroup(scimServerGroupMap map[string]any, scimServerGroup *ScimServerGroup) (err error) {
	delete(scimServerGroupMap, "_id")
	fieldMap := map[string]string{
		"displayName": "display_name",
	}
	translateMongoDBFieldsToPostgresColumns(fieldMap, scimServerGroupMap)
	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(scimServerGroupMap); err != nil {
		return
	}

	if err = json.Unmarshal(jsonBytes, scimServerGroup); err != nil {
		return fmt.Errorf("failed to unmarshal ScimServerGroup id=%q: %w", scimServerGroupMap["id"], err)
	}

	return nil
}

// ScimServerGroupCustom is a row from the `platformdb.scim_server_groups_custom` table
type ScimServerGroupCustom struct {
	ScimServerGroupUID    string `json:"scim_server_group_uid"`
	AttributeKey          string `json:"attribute_key"`
	SchemaName            string `json:"schema_name,omitempty"`
	AttributeValue        string `json:"attribute_value,omitempty"`
	AttributeValueComplex any    `json:"attribute_value_complex,omitempty"`
}

var ScimServerGroupsCustomColumnNames []string = []string{
	"scim_server_group_uid",
	"attribute_key",
	"schema_name",
	"attribute_value",
	"attribute_value_complex",
}

var ScimServerGroupsCustomIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "scim_server_groups_custom"}

func (ssgc *ScimServerGroupCustom) ToAnySlice() []any {
	return []any{
		ssgc.ScimServerGroupUID,
		ssgc.AttributeKey,
		ssgc.SchemaName,
		ssgc.AttributeValue,
		ssgc.AttributeValueComplex,
	}
}

func (ssgc *ScimServerGroupCustom) GetColumnNames() []string {
	return ScimServerGroupsCustomColumnNames
}

func (ssgc *ScimServerGroupCustom) GetTableIdentifier() pgx.Identifier {
	return ScimServerUsersCustomIdentifier
}

func (ssgc *ScimServerGroupCustom) GetInsertSQL() string {
	return `
		INSERT INTO platformdb.scim_server_groups_custom
		(scim_server_group_uid, attribute_key, schema_name, attribute_value, attribute_value_complex)
		VALUES (@scim_server_group_uid, @attribute_key, @schema_name, @attribute_value, @attribute_value_complex)
		ON CONFLICT DO NOTHING RETURNING scim_server_group_uid;`
}

type Member struct {
	Value   string `bson:"value"`
	Display string `bson:"display"`
}

func (m *Member) GetArgs() pgx.NamedArgs {
	return pgx.NamedArgs{
		"userId":  m.Value,
		"realmId": "defaultSP",
		"type":    "SAML",
	}
}

type Group struct {
	GroupID     string   `bson:"_id"`
	DisplayName string   `bson:"displayName"`
	Members     []Member `bson:"members"`
}

func (g *Group) GetArgs() pgx.NamedArgs {
	return pgx.NamedArgs{
		"groupId":     g.GroupID,
		"displayName": g.DisplayName,
		"realmId":     "defaultSP",
	}
}

func (g *Group) GetInsertSQL() string {
	return `
		INSERT INTO platformdb.groups(group_id, display_name, realm_id)
		VALUES (@groupId, @displayName, @realmId) ON CONFLICT DO NOTHING;`
}

type UserGroup struct {
	UserUID  *uuid.UUID `json:"user_uid"`
	GroupUID *uuid.UUID `json:"group_uid"`
}

func (ug *UserGroup) GetInsertSQL() string {
	return `
		INSERT INTO platformdb.users_groups(user_uid, group_uid)
		VALUES (
			(SELECT uid from platformdb.users WHERE user_id=@userId AND (realm_id=@realmId OR type=@type)),
			(SELECT uid from platformdb.groups WHERE group_id=@groupId AND realm_id=@realmId)
		) ON CONFLICT DO NOTHING;`
}

type OauthToken struct {
	LookupKey   string `bson:"LOOKUPKEY"`
	UniqueID    string `bson:"UNIQUEID"`
	ProviderID  string `bson:"PROVIDERID"`
	Type        string `bson:"TYPE"`
	SubType     string `bson:"SUBTYPE"`
	CreatedAt   int64  `bson:"CREATEDAT"`
	Lifetime    int    `bson:"LIFETIME"`
	Expires     int64  `bson:"EXPIRES"`
	TokenString string `bson:"TOKENSTRING"`
	ClientID    string `bson:"CLIENTID"`
	UserName    string `bson:"USERNAME"`
	Scope       string `bson:"SCOPE"`
	RedirectUri string `bson:"REDIRECTURI"`
	StateID     string `bson:"STATEID"`
	Props       string `bson:"PROPS"`
}

func (ot *OauthToken) GetInsertSQL() string {
	return `INSERT INTO oauthdbschema.oauthtoken
			(LOOKUPKEY, UNIQUEID, PROVIDERID, TYPE, SUBTYPE, CREATEDAT, LIFETIME, EXPIRES, TOKENSTRING, CLIENTID, USERNAME, SCOPE, REDIRECTURI, STATEID, PROPS)
			VALUES (@LOOKUPKEY, @UNIQUEID, @PROVIDERID, @TYPE, @SUBTYPE, @CREATEDAT, @LIFETIME, @EXPIRES, @TOKENSTRING, @CLIENTID, @USERNAME, @SCOPE, @REDIRECTURI, @STATEID, @PROPS)
			ON CONFLICT DO NOTHING;`
}

func (ot *OauthToken) GetColumnNames() []string {
	return []string{
		"LOOKUPKEY",
		"UNIQUEID",
		"PROVIDERID",
		"TYPE",
		"SUBTYPE",
		"CREATEDAT",
		"LIFETIME",
		"EXPIRES",
		"TOKENSTRING",
		"CLIENTID",
		"USERNAME",
		"SCOPE",
		"REDIRECTURI",
		"STATEID",
		"PROPS",
	}
}

func (ot *OauthToken) ToAnySlice() []any {
	return []any{
		ot.LookupKey,
		ot.UniqueID,
		ot.ProviderID,
		ot.Type,
		ot.SubType,
		ot.CreatedAt,
		ot.Lifetime,
		ot.Expires,
		ot.TokenString,
		ot.ClientID,
		ot.UserName,
		ot.Scope,
		ot.RedirectUri,
		ot.StateID,
		ot.Props,
	}
}

type Changelog struct {
	ID          int                 `json:"id"`
	Name        string              `json:"name"`
	IMVersion   string              `json:"im_version"`
	InstallTime *pgtype.Timestamptz `json:"install_version"`
}

func (c *Changelog) GetInsertSQL() string {
	return `INSERT INTO metadata.changelog
		(id, name, im_version, install_time)
		VALUES (@id, @name, @im_version, @install_time)
		ON CONFLICT DO NOTHING;`
}

func (c *Changelog) GetColumnNames() []string {
	return []string{
		"id",
		"name",
		"im_version",
		"install_time",
	}
}

func (c *Changelog) ToAnySlice() []any {
	return []any{
		c.ID,
		c.Name,
		c.IMVersion,
		c.InstallTime,
	}
}

var ChangelogTableIdentifier pgx.Identifier = pgx.Identifier{"metadata", "changelog"}

func (c *Changelog) GetTableIdentifier() pgx.Identifier {
	return ChangelogTableIdentifier
}

var ErrTableDoesNotExist error = errors.New("table does not exist")

func HasTable(ctx context.Context, postgres *dbconn.PostgresDB, identifier pgx.Identifier) (has bool, err error) {
	reqLogger := logf.FromContext(ctx)
	if postgres.Conn.IsClosed() {
		reqLogger.Info("Connecting to PostgresDB", "PostgresDB.Host", postgres.Host, "PostgresDB.Port", postgres.Port)
		if err = postgres.Connect(ctx); err != nil {
			reqLogger.Error(err, "Failed to connect to PostgresDB")
			return
		}
		defer postgres.Disconnect(ctx)
	}

	existenceQuery := "SELECT EXISTS ( SELECT FROM pg_tables WHERE schemaname = $1 AND tablename = $2 );"
	err = postgres.Conn.QueryRow(ctx, existenceQuery, identifier[0], identifier[1]).Scan(&has)
	return
}

func GetChangelogs(ctx context.Context, from dbconn.DBConn) (c map[int]*Changelog, err error) {
	reqLogger := logf.FromContext(ctx)
	postgres, ok := from.(*dbconn.PostgresDB)
	if !ok {
		return nil, fmt.Errorf("from should be an instance of Postgres")
	}
	reqLogger.Info("Connecting to PostgresDB", "PostgresDB.Host", postgres.Host, "PostgresDB.Port", postgres.Port)
	if err = postgres.Connect(ctx); err != nil {
		reqLogger.Error(err, "Failed to connect to PostgresDB")
		return
	}
	defer postgres.Disconnect(ctx)

	if has, err := HasTable(ctx, postgres, ChangelogTableIdentifier); err != nil {
		return nil, fmt.Errorf("failed to query %s: %w", ChangelogTableIdentifier.Sanitize(), err)
	} else if !has {
		return nil, fmt.Errorf("failed to query %s: %w", ChangelogTableIdentifier.Sanitize(), ErrTableDoesNotExist)
	}
	retrievalQuery := `SELECT id, name, im_version, install_time FROM metadata.changelog;`
	rows, err := postgres.Conn.Query(ctx, retrievalQuery)
	if err != nil {
		return
	}

	defer rows.Close()

	for rows.Next() {
		var id int
		var name string
		var imVersion string
		var installTime pgtype.Timestamptz

		err = rows.Scan(&id, &name, &imVersion, &installTime)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		if c == nil {
			c = make(map[int]*Changelog, 0)
		}
		c[id] = &Changelog{ID: id, Name: name, IMVersion: imVersion, InstallTime: &installTime}
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("error encountered while retrieving rows: %w", rows.Err())
	}

	return
}
