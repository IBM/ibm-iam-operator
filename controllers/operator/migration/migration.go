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

package migration

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	v1schema "github.com/IBM/ibm-iam-operator/controllers/operator/migration/schema/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	mongoOptions "go.mongodb.org/mongo-driver/mongo/options"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

//go:embed v1.sql
var initDDL string

// TODO Add any helpful properties
type Result struct {
	Complete   []*Migration
	Incomplete []*Migration

	Error error
}

type DBConn interface {
	Connect(context.Context) error
	Configure(...DBOption) error
	RunDDL(context.Context, string) error
	HasSchemas(context.Context) (bool, error)
	Disconnect(context.Context) error
}

type PostgresDB struct {
	*DBOptions
	Conn *pgx.Conn
}

func NewPostgresDB(opts ...DBOption) (*PostgresDB, error) {
	p := &PostgresDB{
		DBOptions: &DBOptions{},
	}
	if err := p.Configure(opts...); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *PostgresDB) Connect(ctx context.Context) (err error) {
	dsn := fmt.Sprintf("host=%s user=%s dbname=%s port=%s sslmode=require", p.Host, p.User, p.Name, p.Port)
	var connConfig *pgx.ConnConfig
	if connConfig, err = pgx.ParseConfig(dsn); err != nil {
		return err
	}
	connConfig.TLSConfig = p.TLSConfig
	if p.Conn, err = pgx.ConnectConfig(ctx, connConfig); err != nil {
		return err
	}

	return
}

func (p *PostgresDB) Disconnect(ctx context.Context) error {
	return p.Conn.Close(ctx)
}

func (p *PostgresDB) RunDDL(ctx context.Context, ddl string) (err error) {
	_, err = p.Conn.Exec(ctx, initDDL)
	return
}

var _ DBConn = &PostgresDB{}

type MongoDB struct {
	*DBOptions
	Client *mongo.Client
}

func NewMongoDB(opts ...DBOption) (m *MongoDB, err error) {
	m = &MongoDB{
		DBOptions: &DBOptions{},
	}
	if err := m.Configure(opts...); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *MongoDB) Connect(ctx context.Context) (err error) {
	uri := fmt.Sprintf("mongodb://%s:%s@%s:%s/?ssl=true&replicaSet=rs0&readPreference=secondaryPreferred&authSource=%s",
		m.User,
		m.Password,
		m.Host,
		m.Port,
		"admin")
	mongoClientOpts := mongoOptions.Client().ApplyURI(uri).SetTLSConfig(m.TLSConfig)
	if m.Client, err = mongo.Connect(ctx, mongoClientOpts); err != nil {
		return err
	}
	return
}

func (m *MongoDB) Disconnect(ctx context.Context) error {
	return m.Client.Disconnect(ctx)
}

func (m *MongoDB) RunDDL(ctx context.Context, ddl string) error {
	return fmt.Errorf("does not support executing DDL")
}

func (m *MongoDB) HasSchemas(ctx context.Context) (bool, error) {
	return false, nil
}

var _ DBConn = &MongoDB{}

type Migration struct {
	Name    string
	To      DBConn
	From    DBConn
	runFunc func(context.Context, DBConn, DBConn) error
}

type MigrationBuilder struct {
	Migration *Migration
}

func NewMigration() *MigrationBuilder {
	return &MigrationBuilder{
		Migration: &Migration{},
	}
}

func (m *MigrationBuilder) Build() *Migration {
	return m.Migration
}

func (m *MigrationBuilder) Name(name string) *MigrationBuilder {
	m.Migration.Name = name
	return m
}

func (m *MigrationBuilder) To(to DBConn) *MigrationBuilder {
	m.Migration.To = to
	return m
}

func (m *MigrationBuilder) From(from DBConn) *MigrationBuilder {
	m.Migration.From = from
	return m
}

func (m *MigrationBuilder) RunFunc(f func(context.Context, DBConn, DBConn) error) *MigrationBuilder {
	m.Migration.runFunc = f
	return m
}

func (m *Migration) Run(ctx context.Context) (err error) {
	if m.To != nil {
		if err = m.To.Connect(ctx); err != nil {
			return fmt.Errorf("failed to connect to target database: %w", err)
		}
		defer m.To.Disconnect(ctx)
	}
	if m.From != nil {
		if err = m.From.Connect(ctx); err != nil {
			return fmt.Errorf("failed to connect to source database: %w", err)
		}
		defer m.From.Disconnect(ctx)
	}
	return m.runFunc(ctx, m.To, m.From)
}

// Migrate initializes the EDB database for the IM Operands and performs any additional migrations that may be needed.
func Migrate(ctx context.Context, c chan *Result, migrations ...*Migration) {
	reqLogger := logf.FromContext(ctx).WithName("migration_worker")

	migrationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	migrationCtx = logf.IntoContext(migrationCtx, reqLogger)

	var err error
	result := &Result{}
	for _, m := range migrations {
		if len(result.Incomplete) > 0 {
			result.Incomplete = append(result.Incomplete, m)
			continue
		}
		if err = m.Run(migrationCtx); err != nil {
			result.Error = fmt.Errorf("failure occurred during %s: %w", m.Name, err)
			result.Incomplete = append(result.Incomplete, m)
			continue
		}
		result.Complete = append(result.Complete, m)
	}

	c <- result
	close(c)
}

func (p *PostgresDB) HasSchemas(ctx context.Context) (bool, error) {
	reqLogger := logf.FromContext(ctx)
	var err error
	var rows pgx.Rows
	if rows, err = p.Conn.Query(ctx, "SELECT schema_name FROM information_schema.schemata;"); err != nil {
		reqLogger.Error(err, "Failed to retrieve schema names")
		return false, err
	}
	defer rows.Close()

	foundSchemas := map[string]bool{}

	for _, schemaName := range p.Schemas {
		foundSchemas[schemaName] = false
	}

	for rows.Next() {
		var s string
		if err = rows.Scan(&s); err != nil {
			return false, err
		}
		if _, ok := foundSchemas[s]; ok {
			foundSchemas[s] = true
		}
	}

	if rows.Err() != nil {
		return false, err
	}

	for _, present := range foundSchemas {
		if !present {
			return false, nil
		}
	}

	return true, nil
}

// InitSchemas executes the DDL that initializes the schemas and tables that the different IM Operands will use.
func InitSchemas(ctx context.Context, to, from DBConn) (err error) {
	reqLogger := logf.FromContext(ctx)
	postgres, ok := to.(*PostgresDB)
	if !ok {
		return fmt.Errorf("from should be an instance of Postgres")
	}
	if err = postgres.Connect(ctx); err != nil {
		reqLogger.Error(err, "Failed to connect to Postgres")
		return
	}
	defer postgres.Disconnect(ctx)

	var schemasPresent bool
	schemasPresent, err = postgres.HasSchemas(ctx)
	if err != nil {
		reqLogger.Error(err, "Failed to determine whether schemas present")
		return
	}
	if !schemasPresent {
		if err = to.RunDDL(ctx, initDDL); err != nil {
			reqLogger.Error(err, "Failed to execute DDL")
		}
	}
	return
}

func MongoToV1(ctx context.Context, to, from DBConn) (err error) {
	reqLogger := logf.FromContext(ctx)
	mongodb, ok := from.(*MongoDB)
	if !ok {
		return fmt.Errorf("from should be an instance of MongoDB")
	}
	if err = mongodb.Connect(ctx); err != nil {
		reqLogger.Error(err, "Failed to connect to MongoDB")
		return
	}
	defer mongodb.Disconnect(ctx)

	postgres, ok := to.(*PostgresDB)
	if !ok {
		return fmt.Errorf("from should be an instance of Postgres")
	}
	if err = postgres.Connect(ctx); err != nil {
		reqLogger.Error(err, "Failed to connect to Postgres")
		return
	}
	defer postgres.Disconnect(ctx)

	copyFuncs := []copyFunc{
		insertIdpConfigs,
		insertUsers,
		insertUserPreferences,
		insertZenInstances,
		insertZenInstanceUsers,
		insertSCIMAttributes,
		insertSCIMAttributeMappings,
	}

	for _, f := range copyFuncs {
		if err = f(ctx, mongodb, postgres); err != nil {
			reqLogger.Error(err, "failed to copy to postgres")
			return
		}
	}

	return
}

func (m *MongoDB) FindAll(ctx context.Context, db string, collection string, filter interface{}) (results []map[string]interface{}, err error) {
	reqLogger := logf.FromContext(ctx)
	cursor, err := m.Client.Database(db).Collection(collection).Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get records from MongoDB")
		return
	}
	if err = cursor.All(context.TODO(), &results); err != nil {
		reqLogger.Error(err, "Failed to read all results from MongoDB")
		return
	}
	return
}

func insertIdpConfigs(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{{"migrated", bson.D{{"$ne", true}}}}
	cursor, err := mongodb.Client.Database("platform-db").Collection("cloudpak_ibmid_v3").Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		idpConfig := &v1schema.IdpConfig{}
		if err = v1schema.ConvertToIdpConfig(result, idpConfig); err != nil {
			reqLogger.Error(err, "Failed to unmarshal idp_config")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		args := pgx.NamedArgs{
			"UID":         idpConfig.UID,
			"Description": idpConfig.Description,
			"Enabled":     idpConfig.Enabled,
			"IDPConfig":   idpConfig.IDPConfig,
			"Name":        idpConfig.Name,
			"Protocol":    idpConfig.Protocol,
			"Type":        idpConfig.Type,
			"SCIMConfig":  idpConfig.SCIMConfig,
			"JIT":         idpConfig.JIT,
			"LDAPConfig":  idpConfig.LDAPConfig,
		}

		query := `
			INSERT INTO platformdb.idp_configs
			(uid, description, enabled, idp_config, name, protocol, type, scim_config, jit, ldap_config)
			VALUES (@UID, @Description, @Enabled, @IDPConfig, @Name, @Protocol, @Type, @SCIMConfig, @JIT, @LDAPConfig)
			ON CONFLICT (uid) DO NOTHING
			RETURNING uid;`
		var uid *string
		err := postgres.Conn.QueryRow(ctx, query, args).Scan(&uid)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.idp_configs")
			errCount++
			continue
		}
		updateFilter := bson.D{{"uid", idpConfig.UID}}
		update := bson.D{{"$set", bson.D{{"migrated", true}}}}
		updateResult, err := mongodb.Client.Database("platform-db").Collection("cloudpak_ibmid_v3").UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo")
			errCount++
			continue
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult)
		migrateCount++
	}
	if errCount > 0 {
		err = fmt.Errorf("encountered errors that prevented the migration of documents")
		reqLogger.Error(err, "Migration of platform-db.cloudpak_ibmid_v3 not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing")
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		// TODO: Handle this further
		return
	}
	reqLogger.Info("Successfully copied over IDP configs to EDB", "rowsInserted", migrateCount)
	return
}

func insertUsers(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{{"migrated", bson.D{{"$ne", true}}}}
	cursor, err := mongodb.Client.Database("platform-db").Collection("Users").Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		user := &v1schema.User{}
		if err = v1schema.ConvertToUser(result, user); err != nil {
			reqLogger.Error(err, "Failed to unmarshal user")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		args := pgx.NamedArgs{
			"UserID":             user.UserID,
			"RealmID":            user.RealmID,
			"FirstName":          user.FirstName,
			"LastName":           user.LastName,
			"Email":              user.Email,
			"Type":               user.Type,
			"LastLogin":          user.LastLogin,
			"Status":             user.Status,
			"UserBaseDN":         user.UserBaseDN,
			"Groups":             user.Groups,
			"Role":               user.Role,
			"UniqueSecurityName": user.UniqueSecurityName,
			"PreferredUsername":  user.PreferredUsername,
			"DisplayName":        user.DisplayName,
			"Subject":            user.Subject,
		}

		query := `
			INSERT INTO platformdb.users
			(uid, user_id, realm_id, first_name, last_name, email, type, last_login, status, user_basedn, groups, role, unique_security_name, preferred_username, display_name, subject)
			VALUES (
				  DEFAULT
				, @UserID
				, @RealmID
				, @FirstName
				, @LastName
				, @Email
				, @Type
				, @LastLogin
				, @Status
				, @UserBaseDN
				, @Groups
				, @Role
				, @UniqueSecurityName
				, @PreferredUsername
				, @DisplayName
				, @Subject
			)
			ON CONFLICT (user_id) DO NOTHING
			RETURNING uid;`
		var uid *string
		err := postgres.Conn.QueryRow(ctx, query, args).Scan(&uid)
		if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.users")
			errCount++
			continue
		}
		updateFilter := bson.D{{"_id", user.UserID}}
		update := bson.D{{"$set", bson.D{{"migrated", true}}}}
		updateResult, err := mongodb.Client.Database("platform-db").Collection("Users").UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo")
			errCount++
			continue
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult)
		migrateCount++
	}
	if errCount > 0 {
		err = fmt.Errorf("encountered errors that prevented the migration of documents")
		reqLogger.Error(err, "Migration of platform-db.Users not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing")
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		// TODO: Handle this further
		return
	}
	reqLogger.Info("Successfully copied over Users to EDB", "rowsInserted", migrateCount)
	return
}

func insertUserPreferences(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{{"migrated", bson.D{{"$ne", true}}}}
	cursor, err := mongodb.Client.Database("platform-db").Collection("UserPreferences").Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		userPrefs := &v1schema.UserPreferences{}
		if err = v1schema.ConvertToUserPreferences(result, userPrefs); err != nil {
			reqLogger.Error(err, "Failed to unmarshal UserPreferences")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		args := pgx.NamedArgs{
			"UserID":     userPrefs.UserID,
			"LastLogin":  userPrefs.LastLogin,
			"LastLogout": userPrefs.LastLogout,
			"LoginCount": userPrefs.LoginCount,
		}

		query := `
			INSERT INTO platformdb.users_preferences
			(user_id, last_login, last_logout, login_count)
			VALUES (@UserID, @LastLogin, @LastLogout, @LoginCount)
			ON CONFLICT DO NOTHING;`
		_, err := postgres.Conn.Exec(ctx, query, args)
		if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.users_preferences")
			errCount++
			continue
		}
		updateFilter := bson.D{{"_id", strings.Join([]string{"preferenceId", userPrefs.UserID}, "_")}}
		update := bson.D{{"$set", bson.D{{"migrated", true}}}}
		updateResult, err := mongodb.Client.Database("platform-db").Collection("UserPreferences").UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo")
			errCount++
			continue
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult)
		migrateCount++
	}
	if errCount > 0 {
		err = fmt.Errorf("encountered errors that prevented the migration of documents")
		reqLogger.Error(err, "Migration of platform-db.UserPreferences not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing")
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		// TODO: Handle this further
		return
	}
	reqLogger.Info("Successfully copied over UserPreferences to EDB", "rowsInserted", migrateCount)
	return
}

func insertZenInstances(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{{"migrated", bson.D{{"$ne", true}}}}
	cursor, err := mongodb.Client.Database("platform-db").Collection("ZenInstances").Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		zenInstance := &v1schema.ZenInstance{}
		if err = v1schema.ConvertToZenInstance(result, zenInstance); err != nil {
			reqLogger.Error(err, "Failed to unmarshal ZenInstance")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		args := pgx.NamedArgs{
			"InstanceID":     zenInstance.InstanceID,
			"Namespace":      zenInstance.Namespace,
			"ProductNameURL": zenInstance.ProductNameURL,
			"ClientID":       zenInstance.ClientID,
			"ClientSecret":   zenInstance.ClientSecret,
			"ZenAuditURL":    zenInstance.ZenAuditURL,
		}

		query := `
			INSERT INTO platformdb.zen_instances
			(instance_id, namespace, product_name_url, client_id, client_secret, zen_audit_url)
			VALUES (@InstanceID, @Namespace, @ProductNameURL, @ClientID, @ClientSecret, @ZenAuditURL)
			ON CONFLICT DO NOTHING;`
		_, err := postgres.Conn.Exec(ctx, query, args)
		if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.zen_instances")
			errCount++
			continue
		}
		updateFilter := bson.D{{"instance_id", zenInstance.InstanceID}}
		update := bson.D{{"$set", bson.D{{"migrated", true}}}}
		updateResult, err := mongodb.Client.Database("platform-db").Collection("ZenInstances").UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo")
			errCount++
			continue
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult)
		migrateCount++
	}
	if errCount > 0 {
		err = fmt.Errorf("encountered errors that prevented the migration of documents")
		reqLogger.Error(err, "Migration of platform-db.ZenInstances not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing")
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		// TODO: Handle this further
		return
	}
	reqLogger.Info("Successfully copied over ZenInstances to EDB", "rowsInserted", migrateCount)
	return
}

func insertZenInstanceUsers(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{{"migrated", bson.D{{"$ne", true}}}}
	cursor, err := mongodb.Client.Database("platform-db").Collection("ZenInstanceUsers").Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		zenInstanceUser := &v1schema.ZenInstanceUser{}
		if err = v1schema.ConvertToZenInstanceUser(result, zenInstanceUser); err != nil {
			reqLogger.Error(err, "Failed to unmarshal ZenInstanceUser")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		args := pgx.NamedArgs{
			"UZID":          zenInstanceUser.UZID,
			"UserID":        zenInstanceUser.UserID,
			"ZenInstanceID": zenInstanceUser.ZenInstanceID,
		}

		query := `
			INSERT INTO platformdb.zen_instances_users
			(uz_id, zen_instance_id, user_id)
			VALUES (@UZID, @ZenInstanceID, @UserID)
			ON CONFLICT DO NOTHING;`
		_, err := postgres.Conn.Exec(ctx, query, args)
		if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.zen_instances_users")
			errCount++
			continue
		}
		updateFilter := bson.D{{"_id", zenInstanceUser.UZID}}
		update := bson.D{{"$set", bson.D{{"migrated", true}}}}
		updateResult, err := mongodb.Client.Database("platform-db").Collection("ZenInstanceUsers").UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo")
			errCount++
			continue
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult)
		migrateCount++
	}
	if errCount > 0 {
		err = fmt.Errorf("encountered errors that prevented the migration of documents")
		reqLogger.Error(err, "Migration of platform-db.ZenInstanceUsers not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing")
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		// TODO: Handle this further
		return
	}
	reqLogger.Info("Successfully copied over ZenInstanceUsers to EDB", "rowsInserted", migrateCount)
	return
}

func insertSCIMAttributes(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{{"migrated", bson.D{{"$ne", true}}}}
	cursor, err := mongodb.Client.Database("platform-db").Collection("ScimAttributes").Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		scimAttr := &v1schema.SCIMAttributes{}
		if err = v1schema.ConvertToSCIMAttributes(result, scimAttr); err != nil {
			reqLogger.Error(err, "Failed to unmarshal ScimAttributes")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		args := pgx.NamedArgs{
			"ID":    scimAttr.ID,
			"Group": scimAttr.Group,
			"User":  scimAttr.User,
		}

		query := `
			INSERT INTO platformdb.scim_attributes
			(id, "group", "user")
			VALUES (@ID, @Group, @User)
			ON CONFLICT DO NOTHING;`
		_, err := postgres.Conn.Exec(ctx, query, args)
		if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.scim_attributes")
			errCount++
			continue
		}
		updateFilter := bson.D{{"id", scimAttr.ID}}
		update := bson.D{{"$set", bson.D{{"migrated", true}}}}
		updateResult, err := mongodb.Client.Database("platform-db").Collection("ScimAttributes").UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo")
			errCount++
			continue
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult)
		migrateCount++
	}
	if errCount > 0 {
		err = fmt.Errorf("encountered errors that prevented the migration of documents")
		reqLogger.Error(err, "Migration of platform-db.ScimAttributes not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing")
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		// TODO: Handle this further
		return
	}
	reqLogger.Info("Successfully copied over ScimAttributes to EDB", "rowsInserted", migrateCount)
	return
}

func insertSCIMAttributeMappings(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{{"migrated", bson.D{{"$ne", true}}}}
	cursor, err := mongodb.Client.Database("platform-db").Collection("ScimAttributeMapping").Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		scimAttrMapping := &v1schema.SCIMAttributesMapping{}
		if err = v1schema.ConvertToSCIMAttributesMapping(result, scimAttrMapping); err != nil {
			reqLogger.Error(err, "Failed to unmarshal ScimAttributeMapping")
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}
		args := pgx.NamedArgs{
			"IdpID":   scimAttrMapping.IdpID,
			"IdpType": scimAttrMapping.IdpType,
			"Group":   scimAttrMapping.Group,
			"User":    scimAttrMapping.User,
		}

		query := `
			INSERT INTO platformdb.scim_attributes_mappings
			(idp_id, idp_type, "group", "user")
			VALUES (@IdpID, @IdpType, @Group, @User)
			ON CONFLICT DO NOTHING;`
		_, err := postgres.Conn.Exec(ctx, query, args)
		if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.scim_attributes_mappings")
			errCount++
			continue
		}
		updateFilter := bson.D{{"_id", scimAttrMapping.IdpID}}
		update := bson.D{{"$set", bson.D{{"migrated", true}}}}
		updateResult, err := mongodb.Client.Database("platform-db").Collection("ScimAttributeMapping").UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo")
			errCount++
			continue
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult)
		migrateCount++
	}
	if errCount > 0 {
		err = fmt.Errorf("encountered errors that prevented the migration of documents")
		reqLogger.Error(err, "Migration of platform-db.ScimAttributeMapping not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing")
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		// TODO: Handle this further
		return
	}
	reqLogger.Info("Successfully copied over ScimAttributeMapping to EDB", "rowsInserted", migrateCount)
	return
}

type copyFunc func(context.Context, *MongoDB, *PostgresDB) error

func copyIdpConfigs(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.FindAll(ctx, "platform-db", "cloudpak_ibmid_v3", filter); err != nil {
		reqLogger.Error(err, "Failed to read all results from MongoDB")
		return
	}
	reqLogger.Info("Retrieved bson", "bson", results)

	idpRows := make([]v1schema.IdpConfig, len(results))
	if err = v1schema.ConvertToIdpConfigs(results, idpRows); err != nil {
		reqLogger.Error(err, "Failed to assemble idp rows")
		return
	}

	var _ int64
	_, err = postgres.Conn.CopyFrom(
		ctx,
		v1schema.IdpConfigsIdentifier,
		v1schema.IdpConfigColumnNames,
		pgx.CopyFromSlice(len(idpRows), func(i int) ([]any, error) {
			return []any{
				idpRows[i].UID,
				idpRows[i].Description,
				idpRows[i].Enabled,
				idpRows[i].IDPConfig,
				idpRows[i].Name,
				idpRows[i].Protocol,
				idpRows[i].Type,
				idpRows[i].SCIMConfig,
				idpRows[i].JIT,
				idpRows[i].LDAPConfig}, nil
		}),
	)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.IdpConfigsIdentifier)
	} else if pgErr != nil && pgErr.Code == "23505" {
		reqLogger.Info("COPY failed due to unique constraint violation; skipping", "pgx.Identifier", v1schema.IdpConfigsIdentifier)
		err = nil
	}
	return
}

func copyUsers(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.FindAll(ctx, "platform-db", "Users", filter); err != nil {
		reqLogger.Error(err, "Failed to read all results from MongoDB")
		return
	}
	reqLogger.Info("Retrieved bson", "bson", results)

	userRows := make([]v1schema.User, len(results))
	if err = v1schema.ConvertToUsers(results, userRows); err != nil {
		reqLogger.Error(err, "Failed to assemble user rows")
		return
	}

	var _ int64
	_, err = postgres.Conn.CopyFrom(
		ctx,
		v1schema.UsersIdentifier,
		v1schema.UserColumnNames,
		pgx.CopyFromSlice(len(userRows), func(i int) ([]any, error) {
			return []any{
				userRows[i].UID,
				userRows[i].UserID,
				userRows[i].RealmID,
				userRows[i].FirstName,
				userRows[i].LastName,
				userRows[i].Email,
				userRows[i].Type,
				userRows[i].LastLogin,
				userRows[i].Status,
				userRows[i].UserBaseDN,
				userRows[i].Groups,
				userRows[i].Role,
				userRows[i].UniqueSecurityName,
				userRows[i].PreferredUsername,
				userRows[i].DisplayName,
				userRows[i].Subject}, nil
		}),
	)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.UsersIdentifier)
	} else if pgErr != nil && pgErr.Code == "23505" {
		reqLogger.Info("COPY failed due to unique constraint violation; skipping", "pgx.Identifier", v1schema.UsersIdentifier)
		err = nil
	}
	return
}

func removeInvalidUserPreferences(usersPrefs []v1schema.UserPreferences) (updated []v1schema.UserPreferences) {
	for _, userPrefs := range usersPrefs {
		if userPrefs.LastLogin != nil {
			updated = append(updated, userPrefs)
		}
	}
	return
}

func copyUsersPreferences(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.FindAll(ctx, "platform-db", "UserPreferences", filter); err != nil {
		reqLogger.Error(err, "Failed to read all results from MongoDB")
		return
	}
	reqLogger.Info("Retrieved bson", "bson", results)

	userPrefsRows := make([]v1schema.UserPreferences, len(results))
	if err = v1schema.ConvertToUsersPreferences(results, userPrefsRows); err != nil {
		reqLogger.Error(err, "Failed to assemble user rows")
		return
	}

	filteredUserPrefsRows := removeInvalidUserPreferences(userPrefsRows)

	var _ int64
	_, err = postgres.Conn.CopyFrom(
		ctx,
		v1schema.UsersPreferencesIdentifier,
		v1schema.UserPreferencesColumnNames,
		pgx.CopyFromSlice(len(filteredUserPrefsRows), func(i int) ([]any, error) {
			return []any{
				filteredUserPrefsRows[i].UserID,
				filteredUserPrefsRows[i].LastLogin,
				filteredUserPrefsRows[i].LastLogout,
				filteredUserPrefsRows[i].LoginCount}, nil
		}),
	)
	var pgErr *pgconn.PgError
	if err != nil && (!errors.As(err, &pgErr) || pgErr.Code != "23505") {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.UsersPreferencesIdentifier)
	} else if pgErr != nil && pgErr.Code == "23505" {
		reqLogger.Info("COPY failed due to unique constraint violation; skipping", "pgx.Identifier", v1schema.UsersPreferencesIdentifier)
		err = nil
	}
	return
}

func copyZenInstances(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.FindAll(ctx, "platform-db", "ZenInstance", filter); err != nil {
		reqLogger.Error(err, "Failed to read all results from MongoDB")
		return
	}
	reqLogger.Info("Retrieved bson", "bson", results)

	zenInstanceRows := make([]v1schema.ZenInstance, len(results))
	if err = v1schema.ConvertToZenInstances(results, zenInstanceRows); err != nil {
		reqLogger.Error(err, "Failed to assemble user rows")
		return
	}

	var _ int64
	_, err = postgres.Conn.CopyFrom(
		ctx,
		v1schema.ZenInstancesIdentifier,
		v1schema.ZenInstanceColumnNames,
		pgx.CopyFromSlice(len(zenInstanceRows), func(i int) ([]any, error) {
			return []any{
				zenInstanceRows[i].InstanceID,
				zenInstanceRows[i].ClientID,
				zenInstanceRows[i].ClientSecret,
				zenInstanceRows[i].ProductNameURL,
				zenInstanceRows[i].ZenAuditURL,
				zenInstanceRows[i].Namespace}, nil
		}),
	)
	var pgErr *pgconn.PgError
	if err != nil && (!errors.As(err, &pgErr) || pgErr.Code != "23505") {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.ZenInstancesIdentifier)
	} else if pgErr != nil && pgErr.Code == "23505" {
		reqLogger.Info("COPY failed due to unique constraint violation; skipping", "pgx.Identifier", v1schema.ZenInstancesIdentifier)
		err = nil
	}
	return
}

func copyZenInstanceUsers(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.FindAll(ctx, "platform-db", "ZenInstanceUsers", filter); err != nil {
		reqLogger.Error(err, "Failed to read all results from MongoDB")
		return
	}
	reqLogger.Info("Retrieved bson", "bson", results)

	zenInstanceUserRows := make([]v1schema.ZenInstanceUser, len(results))
	if err = v1schema.ConvertToZenInstanceUsers(results, zenInstanceUserRows); err != nil {
		reqLogger.Error(err, "Failed to assemble user rows")
		return
	}

	var _ int64
	_, err = postgres.Conn.CopyFrom(
		ctx,
		v1schema.ZenInstanceUsersIdentifier,
		v1schema.ZenInstanceUserColumnNames,
		pgx.CopyFromSlice(len(zenInstanceUserRows), func(i int) ([]any, error) {
			return []any{
				zenInstanceUserRows[i].UZID,
				zenInstanceUserRows[i].ZenInstanceID,
				zenInstanceUserRows[i].UserID}, nil
		}),
	)

	var pgErr *pgconn.PgError
	if err != nil && (!errors.As(err, &pgErr) || pgErr.Code != "23505") {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.ZenInstanceUsersIdentifier)
	} else if pgErr != nil && pgErr.Code == "23505" {
		reqLogger.Info("COPY failed due to unique constraint violation; skipping", "pgx.Identifier", v1schema.ZenInstanceUsersIdentifier)
		err = nil
	}

	return
}

func copySCIMAttributes(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.FindAll(ctx, "platform-db", "ScimAttributes", filter); err != nil {
		reqLogger.Error(err, "Failed to read all results from MongoDB")
		return
	}
	reqLogger.Info("Retrieved bson", "bson", results)

	scimAttributesRows := make([]v1schema.SCIMAttributes, len(results))
	if err = v1schema.ConvertToSCIMAttributesSlice(results, scimAttributesRows); err != nil {
		reqLogger.Error(err, "Failed to assemble user rows")
		return
	}

	var _ int64
	_, err = postgres.Conn.CopyFrom(
		ctx,
		v1schema.SCIMAttributesIdentifier,
		v1schema.SCIMAttributesColumnNames,
		pgx.CopyFromSlice(len(scimAttributesRows), func(i int) ([]any, error) {
			return []any{
				scimAttributesRows[i].ID,
				scimAttributesRows[i].Group,
				scimAttributesRows[i].User}, nil
		}),
	)
	var pgErr *pgconn.PgError
	if err != nil && (!errors.As(err, &pgErr) || pgErr.Code != "23505") {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.SCIMAttributesIdentifier)
	} else if pgErr != nil && pgErr.Code == "23505" {
		reqLogger.Info("COPY failed due to unique constraint violation; skipping", "pgx.Identifier", v1schema.SCIMAttributesIdentifier)
		err = nil
	}

	return
}

func copySCIMAttributesMappings(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.FindAll(ctx, "platform-db", "ScimAttributeMapping", filter); err != nil {
		reqLogger.Error(err, "Failed to read all results from MongoDB")
		return
	}
	reqLogger.Info("Retrieved bson", "bson", results)

	scimAttributesMappingRows := make([]v1schema.SCIMAttributesMapping, len(results))
	if err = v1schema.ConvertToSCIMAttributesMappingSlice(results, scimAttributesMappingRows); err != nil {
		reqLogger.Error(err, "Failed to assemble user rows")
		return
	}

	var _ int64
	_, err = postgres.Conn.CopyFrom(
		ctx,
		v1schema.SCIMAttributesMappingsIdentifier,
		v1schema.SCIMAttributesMappingsColumnNames,
		pgx.CopyFromSlice(len(scimAttributesMappingRows), func(i int) ([]any, error) {
			return []any{
				scimAttributesMappingRows[i].IdpID,
				scimAttributesMappingRows[i].IdpType,
				scimAttributesMappingRows[i].Group,
				scimAttributesMappingRows[i].User}, nil
		}),
	)
	var pgErr *pgconn.PgError
	if err != nil && (!errors.As(err, &pgErr) || pgErr.Code != "23505") {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.SCIMAttributesMappingsIdentifier)
	} else if pgErr != nil && pgErr.Code == "23505" {
		reqLogger.Info("COPY failed due to unique constraint violation; skipping", "pgx.Identifier", v1schema.SCIMAttributesMappingsIdentifier)
		err = nil
	}

	return
}
