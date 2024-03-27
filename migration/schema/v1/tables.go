package v1

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

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

func ConvertToOIDCClient(clientMap map[string]interface{}, oc *OIDCClient) (err error) {
	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(clientMap); err != nil {
		return
	}

	if err = json.Unmarshal(jsonBytes, oc); err != nil {
		return
	}

	return nil
}

func ConvertToOIDCClients(clientMaps []map[string]interface{}, ocRows []OIDCClient) (err error) {
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

func (oc *OIDCClient) GetArgs() pgx.NamedArgs {
	args := pgx.NamedArgs{}
	for k, v := range oc.ToAnyMap() {
		args[k] = v
	}
	return args
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

func (oc *OIDCClient) ToAnyMap() map[string]any {
	m := make(map[string]any)
	anySlice := oc.ToAnySlice()
	for i, col := range oc.GetColumnNames() {
		m[col] = anySlice[i]
	}
	return m
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

func (i *IdpConfig) ToAnyMap() map[string]any {
	m := make(map[string]any)
	anySlice := i.ToAnySlice()
	for i, col := range i.GetColumnNames() {
		m[col] = anySlice[i]
	}
	return m
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

func (i *IdpConfig) GetArgs() pgx.NamedArgs {
	args := pgx.NamedArgs{}
	for k, v := range i.ToAnyMap() {
		args[k] = v
	}
	return args
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

func ConvertToIdpConfig(idpMap map[string]interface{}, idpConfig *IdpConfig) (err error) {
	// DDL defaults enabled to true
	if enabled, ok := idpMap["enabled"]; ok && (enabled == "false" || enabled == false) {
		idpMap["enabled"] = false
	} else {
		idpMap["enabled"] = true
	}
	// SAML with LDAP dependency mongo document will have ldap_config: {ldap_id: <value>}
	// which directly maps to ldap_id column in sql
	if ldap_config, ok := idpMap["ldap_config"]; ok {
		if ldap_config, ok := ldap_config.(map[string]interface{}); ok {
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

func ConvertToIdpConfigs(idpMaps []map[string]interface{}, idpRows []IdpConfig) (err error) {
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

func (u *User) ToAnyMap() map[string]any {
	m := make(map[string]any)
	anySlice := u.ToAnySlice()
	for i, col := range u.GetColumnNames() {
		m[col] = anySlice[i]
	}
	return m
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

func (u *User) GetArgs() pgx.NamedArgs {
	args := pgx.NamedArgs{}
	for k, v := range u.ToAnyMap() {
		args[k] = v
	}
	return args
}

func ConvertToUser(userMap map[string]interface{}, user *User) (err error) {
	// If lastLogin is an empty string, delete it in order to make zero value consistent
	if lastLogin, ok := userMap["lastLogin"]; ok && lastLogin == "" {
		delete(userMap, "lastLogin")
	}
	fieldMap := map[string]string{
		"_id":                "user_id",
		"uniqueSecurityName": "unique_security_name",
		"userBaseDN":         "user_basedn",
		"firstName":          "first_name",
		"lastName":           "last_name",
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

func ConvertToUsers(userMaps []map[string]interface{}, users []User) (err error) {
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

func (u *UserPreferences) ToAnyMap() map[string]any {
	m := make(map[string]any)
	anySlice := u.ToAnySlice()
	for i, col := range u.GetColumnNames() {
		m[col] = anySlice[i]
	}
	return m
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

func (u *UserPreferences) GetArgs() pgx.NamedArgs {
	args := pgx.NamedArgs{}
	for k, v := range u.ToAnyMap() {
		args[k] = v
	}
	return args
}

func ConvertToUserPreferences(userPrefsMap map[string]interface{}, userPrefs *UserPreferences) (err error) {
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

func ConvertToUsersPreferences(usersPrefsMaps []map[string]interface{}, usersPrefs []UserPreferences) (err error) {
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

func ConvertToUserAttributes(userAttrMap map[string]interface{}, userAttr *UserAttributes) (err error) {
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

func ConvertToUsersAttributes(usersAttrsMaps []map[string]interface{}, usersAttrs []UserAttributes) (err error) {
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

func (z *ZenInstance) ToAnyMap() map[string]any {
	m := make(map[string]any)
	anySlice := z.ToAnySlice()
	for i, col := range z.GetColumnNames() {
		m[col] = anySlice[i]
	}
	return m
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

func (z *ZenInstance) GetArgs() pgx.NamedArgs {
	args := pgx.NamedArgs{}
	for k, v := range z.ToAnyMap() {
		args[k] = v
	}
	return args
}

func ConvertToZenInstance(zenInstanceMap map[string]interface{}, zenInstance *ZenInstance) (err error) {
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

func ConvertToZenInstances(zenInstanceMaps []map[string]interface{}, zenInstances []ZenInstance) (err error) {
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

func (z *ZenInstanceUser) ToAnyMap() map[string]any {
	m := make(map[string]any)
	anySlice := z.ToAnySlice()
	for i, col := range z.GetColumnNames() {
		m[col] = anySlice[i]
	}
	return m
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

func (z *ZenInstanceUser) GetArgs() pgx.NamedArgs {
	args := pgx.NamedArgs{}
	for k, v := range z.ToAnyMap() {
		args[k] = v
	}
	return args
}

func ConvertToZenInstanceUser(zenInstanceUserMap map[string]interface{}, zenInstanceUser *ZenInstanceUser) (err error) {
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

func ConvertToZenInstanceUsers(zenInstanceUserMaps []map[string]interface{}, zenInstanceUsers []ZenInstanceUser) (err error) {
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
	ID    string                 `json:"id"`
	Group map[string]interface{} `json:"group"`
	User  map[string]interface{} `json:"user"`
}

var SCIMAttributesColumnNames []string = []string{
	"id",
	"group",
	"user",
}

var SCIMAttributesIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "scim_attributes"}

func ConvertToSCIMAttributes(scimAttributesMap map[string]interface{}, scimAttributes *SCIMAttributes) (err error) {
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

func ConvertToSCIMAttributesSlice(scimAttributesMaps []map[string]interface{}, scimAttributesSlice []SCIMAttributes) (err error) {
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
	IdpID   string                 `json:"idp_id"`
	IdpType string                 `json:"idp_type"`
	Group   map[string]interface{} `json:"group"`
	User    map[string]interface{} `json:"user"`
}

var SCIMAttributesMappingsColumnNames []string = []string{
	"idp_id",
	"idp_type",
	"group",
	"user",
}

var SCIMAttributesMappingsIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "scim_attributes_mappings"}

func ConvertToSCIMAttributesMapping(scimAttributesMappingMap map[string]interface{}, scimAttributesMapping *SCIMAttributesMapping) (err error) {
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

func ConvertToSCIMAttributesMappingSlice(scimAttributesMappingMaps []map[string]interface{}, scimAttributesMappingSlice []SCIMAttributesMapping) (err error) {
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
