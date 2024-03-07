package v1

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

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
	LDAPConfig  map[string]any `json:"ldap_config"`
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
		i.LDAPConfig,
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
		(uid, description, enabled, idp_config, name, protocol, type, scim_config, jit, ldap_config)
		VALUES (@uid, @description, @enabled, @idp_config, @name, @protocol, @type, @scim_config, @jit, @ldap_config)
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
	"ldap_config",
}

var IdpConfigsIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "idp_configs"}

func ConvertToIdpConfig(idpMap map[string]interface{}, idpConfig *IdpConfig) (err error) {
	// DDL defaults enabled to true
	if enabled, ok := idpMap["enabled"]; ok && (enabled == "false" || enabled == false) {
		idpMap["enabled"] = false
	} else {
		idpMap["enabled"] = true
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
	UID                *uuid.UUID          `json:"uid"`
	UserID             string              `json:"user_id"`
	RealmID            string              `json:"realm_id,omitempty"`
	FirstName          string              `json:"first_name,omitempty"`
	LastName           string              `json:"last_name,omitempty"`
	Email              string              `json:"email,omitempty"`
	Type               string              `json:"type,omitempty"`
	LastLogin          *pgtype.Timestamptz `json:"last_login,omitempty"`
	Status             string              `json:"status,omitempty"`
	UserBaseDN         string              `json:"user_basedn,omitempty"`
	Groups             []string            `json:"groups,omitempty"`
	Role               string              `json:"role,omitempty"`
	UniqueSecurityName string              `json:"unique_security_name,omitempty"`
	PreferredUsername  string              `json:"preferred_username,omitempty"`
	DisplayName        string              `json:"display_name,omitempty"`
	Subject            string              `json:"subject,omitempty"`
}

var UserColumnNames []string = []string{
	"uid",
	"user_id",
	"realm_id",
	"first_name",
	"last_name",
	"email",
	"type",
	"last_login",
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
		"lastLogin":          "last_login",
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
	UserID     string              `json:"user_id"`
	LastLogin  *pgtype.Timestamptz `json:"last_login"`
	LastLogout *pgtype.Timestamptz `json:"last_logout,omitempty"`
	LoginCount int                 `json:"login_count,omitempty"`
}

var UserPreferencesColumnNames []string = []string{
	"user_id",
	"last_login",
	"last_logout",
	"login_count",
}

var UsersPreferencesIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "users_preferences"}

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
	UZID          string `json:"uz_id"`
	ZenInstanceID string `json:"zen_instance_id"`
	UserID        string `json:"user_id"`
}

var ZenInstanceUserColumnNames []string = []string{
	"uz_id",
	"zen_instance_id",
	"user_id",
}

var ZenInstanceUsersIdentifier pgx.Identifier = pgx.Identifier{"platformdb", "zen_instances_users"}

func ConvertToZenInstanceUser(zenInstanceUserMap map[string]interface{}, zenInstanceUser *ZenInstanceUser) (err error) {
	fieldMap := map[string]string{
		"_id":           "uz_id",
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
	ID    string                 `json:"_id"`
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
