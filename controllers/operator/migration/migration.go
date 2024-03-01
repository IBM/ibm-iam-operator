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
	"fmt"

	v1schema "github.com/IBM/ibm-iam-operator/controllers/operator/migration/schema/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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
	return to.RunDDL(ctx, initDDL)
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
		copyIdpConfigs,
		copyUsers,
		copyUsersPreferences,
		copyZenInstances,
		copySCIMAttributes,
		copySCIMAttributesMappings,
	}

	for _, f := range copyFuncs {
		if err = f(ctx, mongodb, postgres); err != nil {
			reqLogger.Error(err, "failed to copy to postgres")
			return
		}
	}

	return
}

func (m *MongoDB) Find(ctx context.Context, db string, collection string, filter interface{}) (results []map[string]interface{}, err error) {
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

type copyFunc func(context.Context, *MongoDB, *PostgresDB) error

func copyIdpConfigs(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.Find(ctx, "platform-db", "cloudpak_ibmid_v3", filter); err != nil {
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
	if err != nil {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.IdpConfigsIdentifier)
	}
	return
}

func copyUsers(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.Find(ctx, "platform-db", "Users", filter); err != nil {
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
	if err != nil {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.UsersIdentifier)
	}
	return
}

func removeInvalidUserPreferences(usersPrefs []v1schema.UserPreferences) (updated []v1schema.UserPreferences) {
	for _, userPrefs := range usersPrefs {
		if userPrefs.LastLogin != (pgtype.Timestamptz{}) {
			updated = append(updated, userPrefs)
		}
	}
	return
}

func copyUsersPreferences(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.Find(ctx, "platform-db", "UserPreferences", filter); err != nil {
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
	if err != nil {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.UsersPreferencesIdentifier)
	}
	return
}

func copyZenInstances(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.Find(ctx, "platform-db", "ZenInstance", filter); err != nil {
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
	if err != nil {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.ZenInstancesIdentifier)
	}
	return
}

func copySCIMAttributes(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.Find(ctx, "platform-db", "ScimAttributes", filter); err != nil {
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
	if err != nil {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.SCIMAttributesIdentifier)
	}
	return
}

func copySCIMAttributesMappings(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{}
	var results []map[string]interface{}
	if results, err = mongodb.Find(ctx, "platform-db", "ScimAttributeMapping", filter); err != nil {
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
	if err != nil {
		reqLogger.Error(err, "Failed to copy to postgres", "pgx.Identifier", v1schema.SCIMAttributesMappingsIdentifier)
	}
	return
}
