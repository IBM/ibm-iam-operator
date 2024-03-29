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
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	v1schema "github.com/IBM/ibm-iam-operator/migration/schema/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	mongoOptions "go.mongodb.org/mongo-driver/mongo/options"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type Result struct {
	Complete   []*Migration
	Incomplete []*Migration

	Error error
}

func (r *Result) IsFailure() bool {
	return r.Error != nil && len(r.Incomplete) > 0
}

func (r *Result) IsSuccess() bool {
	return !r.IsFailure()
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
	_, err = p.Conn.Exec(ctx, ddl)
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
		if err = to.RunDDL(ctx, v1schema.DBInitMigration); err != nil {
			reqLogger.Error(err, "Failed to execute DDL")
		}
	}
	return
}

func MongoToV1(ctx context.Context, to, from DBConn) (err error) {
	reqLogger := logf.FromContext(ctx)
	mongodb, ok := from.(*MongoDB)
	reqLogger.Info("Connecting to MongoDB", "MongoDB.Host", mongodb.Host, "MongoDB.Port", mongodb.Port)
	if !ok {
		return fmt.Errorf("from should be an instance of MongoDB")
	}
	if err = mongodb.Connect(ctx); err != nil {
		reqLogger.Error(err, "Failed to connect to MongoDB")
		return
	}
	defer mongodb.Disconnect(ctx)

	postgres, ok := to.(*PostgresDB)
	reqLogger.Info("Connecting to PostgresDB", "PostgresDB.Host", postgres.Host, "PostgresDB.Port", postgres.Port)
	if !ok {
		return fmt.Errorf("from should be an instance of Postgres")
	}
	if err = postgres.Connect(ctx); err != nil {
		reqLogger.Error(err, "Failed to connect to Postgres")
		return
	}
	defer postgres.Disconnect(ctx)

	copyFuncs := []copyFunc{
		insertOIDCClients,
		insertIdpConfigs,
		insertDirectoriesAsIdpConfigs,
		insertV2SamlAsIdpConfig,
		insertZenInstances,
		insertUserRelatedRows,
		insertSCIMAttributes,
		insertSCIMAttributeMappings,
		insertSSUserRelatedRows,
		insertSSGroupRelatedRows,
		insertGroupsAndMemberRefs,
	}

	for _, f := range copyFuncs {
		if err = f(ctx, mongodb, postgres); err != nil {
			reqLogger.Error(err, "failed to copy to postgres")
			return
		}
	}

	return
}

func insertOIDCClients(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	dbName := "OAuthDBSchema"
	collectionName := "OauthClient"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	filter := bson.D{{Key: "migrated", Value: bson.D{{Key: "$ne", Value: true}}}}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
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
			errCount++
			err = nil
			continue
		}

		oc := &v1schema.OIDCClient{}
		if err = v1schema.ConvertToOIDCClient(result, oc); err != nil {
			reqLogger.Error(err, "Failed to unmarshal oauthclient")
			errCount++
			err = nil
			continue
		}
		query := oc.GetInsertSQL()
		args := oc.GetArgs()
		var id *string
		err = postgres.Conn.QueryRow(ctx, query, args).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "oauthdbschema.oauthclient")
			errCount++
			continue
		}
		updateFilter := bson.D{{Key: "CLIENTID", Value: oc.ClientID}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		updateResult, err := mongodb.Client.Database(dbName).Collection(collectionName).UpdateOne(ctx, updateFilter, update)
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
		reqLogger.Error(err, "Migration of oauthdbschema.oauthclient not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing")
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		return
	}
	reqLogger.Info("Successfully copied over OIDC clients to EDB", "rowsInserted", migrateCount)
	return
}

func insertIdpConfigs(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "cloudpak_ibmid_v3"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	filter := bson.D{{Key: "migrated", Value: bson.D{{Key: "$ne", Value: true}}}}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
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
			errCount++
			err = nil
			continue
		}
		idpConfig := &v1schema.IdpConfig{}
		if err = v1schema.ConvertToIdpConfig(result, idpConfig); err != nil {
			reqLogger.Error(err, "Failed to unmarshal idp_config")
			errCount++
			err = nil
			continue
		}
		query := idpConfig.GetInsertSQL()
		args := idpConfig.GetArgs()
		var uid *string
		err := postgres.Conn.QueryRow(ctx, query, args).Scan(&uid)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.idp_configs")
			errCount++
			continue
		}
		updateFilter := bson.D{{Key: "uid", Value: idpConfig.UID}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
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
		return
	}
	reqLogger.Info("Successfully copied over IDP configs to EDB", "rowsInserted", migrateCount)
	return
}

func insertDirectoriesAsIdpConfigs(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "Directory"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	filter := bson.M{
		"$and": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{"CP3MIGRATED": bson.M{"$ne": "true"}},
		},
	}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
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
			errCount++
			err = nil
			continue
		}

		var idpConfig *v1schema.IdpConfig
		var uid string
		if idpConfig, err = v1schema.ConvertV2DirectoryToV3IdpConfig(result); err != nil {
			reqLogger.Error(err, "Failed to convert Directory to v3-compatible IDP config")
			errCount++
			continue
		}
		query := idpConfig.GetInsertSQL()
		args := idpConfig.GetArgs()
		err := postgres.Conn.QueryRow(ctx, query, args).Scan(&uid)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.idp_configs")
			errCount++
			continue
		}
		updateFilter := bson.D{{Key: "_id", Value: idpConfig.UID}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		updateResult, err := mongodb.Client.Database(dbName).Collection(collectionName).UpdateOne(ctx, updateFilter, update)
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
		reqLogger.Error(err, "Migration of platform-db.Directory not successful", "failedCount", errCount, "successCount", migrateCount)
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

func insertV2SamlAsIdpConfig(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "cloudpak_ibmid_v2"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	v3SamlFilter := bson.M{"protocol": "saml"}
	v3Saml := &v1schema.IdpConfig{}
	err = mongodb.Client.Database(dbName).Collection("cloudpak_ibmid_v3").FindOne(ctx, v3SamlFilter).Decode(v3Saml)
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		reqLogger.Error(err, "Failed to read v3 SAML document from MongoDB", "MongoDB.DB", "platform-db", "MongoDB.Collection", "cloudpak_ibmid_v3")
		return
	} else if err == nil {
		reqLogger.Info("A v3 SAML IdP already existed, so migration of v2 configuration will be skipped",
			"MongoDB.DB", "platform-db",
			"MongoDB.Collection", "cloudpak_ibmid_v3")
		return
	}
	filter := bson.M{"migrated": bson.M{"$ne": true}}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB", "MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
		return
	}
	errCount := 0
	migrateCount := 0
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document", "MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
			// TODO: Handle this further
			errCount++
			err = nil
			continue
		}

		var idpConfig *v1schema.IdpConfig
		var uid string
		if idpConfig, err = v1schema.ConvertV2SamlToIdpConfig(result); err != nil {
			reqLogger.Error(err, "Failed to convert SAML to v3-compatible IDP config")
			errCount++
			continue
		}
		type samlMeta struct {
			Metadata string `bson:"metadata"`
		}
		saml := samlMeta{}
		err = mongodb.Client.Database("samlDB").Collection("saml").FindOne(ctx, bson.D{}).Decode(&saml)
		if err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document for saml metadata", "MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
			errCount++
			err = nil
			continue
		}
		idpConfig.IDPConfig["idp_metadata"] = saml.Metadata
		query := idpConfig.GetInsertSQL()
		args := idpConfig.GetArgs()
		err := postgres.Conn.QueryRow(ctx, query, args).Scan(&uid)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.idp_configs")
			errCount++
			continue
		}
		updateFilter := bson.D{{Key: "protocol", Value: "saml"}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		updateResult, err := mongodb.Client.Database(dbName).Collection(collectionName).UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo", "MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
			errCount++
			continue
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult, "MongoDB.DB", dbName, "MongoDB.Collection", collectionName)

		samlDBUpdateFilter := bson.D{{Key: "name", Value: "saml"}}
		samlDBUpdate := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		samlUpdateResult, err := mongodb.Client.Database("samlDB").Collection("saml").UpdateOne(ctx, samlDBUpdateFilter, samlDBUpdate)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo", "MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
			errCount++
			continue
		}
		reqLogger.Info("Wrote back document migration", "updateResult", samlUpdateResult, "MongoDB.DB", "samlDB", "MongoDB.Collection", "saml")
		migrateCount++
	}
	if errCount > 0 {
		err = fmt.Errorf("encountered errors that prevented the migration of documents")
		reqLogger.Error(err, "Migration of platform-db.cloudpak_ibmid_v2 not successful", "failedCount", errCount, "successCount", migrateCount)
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

func insertUser(ctx context.Context, postgres *PostgresDB, user *v1schema.User) (uid *uuid.UUID, err error) {
	reqLogger := logf.FromContext(ctx)
	args := user.GetArgs()
	query := user.GetInsertSQL()
	uid = &uuid.UUID{}
	err = postgres.Conn.QueryRow(ctx, query, args).Scan(uid)
	if errors.Is(err, pgx.ErrNoRows) {
		reqLogger.Info("Row already exists in EDB")
		return nil, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.users")
		return nil, err
	}
	return
}

func getUserFromMongoCursor(cursor *mongo.Cursor) (user *v1schema.User, err error) {
	var result map[string]any
	if err = cursor.Decode(&result); err != nil {
		err = fmt.Errorf("failed to decode MongoDB document: %w", err)
		return
	}
	user = &v1schema.User{}
	if err = v1schema.ConvertToUser(result, user); err != nil {
		err = fmt.Errorf("failed to unmarshal into user: %w", err)
		user = nil
		return
	}
	return
}

func insertUserRelatedRows(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "Users"
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{{Key: "migrated", Value: bson.D{{Key: "$ne", Value: true}}}}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	for cursor.Next(ctx) {
		var user *v1schema.User
		user, err = getUserFromMongoCursor(cursor)
		if err != nil {
			errCount++
			err = nil
			continue
		}
		if _, err = setUserV3Role(ctx, mongodb, user); err != nil {
			reqLogger.Error(err, "Failed to set role for user")
			errCount++
			err = nil
			continue
		}
		var uid *uuid.UUID
		if uid, err = insertUser(ctx, postgres, user); err != nil {
			errCount++
			err = nil
			continue
		}
		user.UID = uid
		updateFilter := bson.D{{Key: "_id", Value: user.UserID}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		updateResult, err := mongodb.Client.Database(dbName).Collection(collectionName).UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo")
			errCount++
			continue
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult)
		migrateCount++

		if err = migrateUserPreferencesRowForUser(ctx, mongodb, postgres, user); err != nil {
			errCount++
			reqLogger.Error(err, "Inserting UserPreferences failed", "identifier", v1schema.UsersIdentifier)
			continue
		}
		if err = migrateZenInstanceUserRowForUser(ctx, mongodb, postgres, user); err != nil {
			errCount++
			reqLogger.Error(err, "Inserting ZenInstanceUser failed", "identifier", v1schema.UsersIdentifier)
			continue
		}
		if err != nil {
			errCount++
			reqLogger.Error(err, "Failed to complete transaction", "table", "platformdb.users")
			continue
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult)
	}
	if errCount > 0 {
		err = fmt.Errorf("encountered errors that prevented the migration of documents")
		reqLogger.Error(err, "Migration of platform-db.Users not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing", "identifier", v1schema.UsersIdentifier)
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		return
	}
	reqLogger.Info("Successfully copied over Users to EDB", "rowsInserted", migrateCount)
	return
}

func migrateUserPreferencesRowForUser(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB, user *v1schema.User) (err error) {
	reqLogger := logf.FromContext(ctx)
	preferenceId := strings.Join([]string{"preferenceId", user.UserID}, "_")
	filter := bson.M{
		"$and": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{"_id": preferenceId},
		},
	}
	cursor, err := mongodb.Client.Database("platform-db").Collection("UserPreferences").Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB", "identifier", v1schema.UsersPreferencesIdentifier)
		return
	}
	migrateCount := 0
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document", "identifier", v1schema.UsersPreferencesIdentifier)
			return err
		}
		userPrefs := &v1schema.UserPreferences{}
		if err = v1schema.ConvertToUserPreferences(result, userPrefs); err != nil {
			reqLogger.Error(err, "Failed to unmarshal UserPreferences", "identifier", v1schema.UsersPreferencesIdentifier)
			return err
		}
		userPrefs.UserUID = user.UID.String()
		args := userPrefs.GetArgs()

		query := userPrefs.GetInsertSQL()
		reqLogger.Info("Executing query for UserPreferences", "preferenceId", preferenceId, "uid", userPrefs.UserUID)
		_, err = postgres.Conn.Exec(ctx, query, args)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
			err = nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.users_preferences", "identifier", v1schema.UsersPreferencesIdentifier)
			return err
		}
		updateFilter := bson.D{{Key: "_id", Value: preferenceId}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		var updateResult *mongo.UpdateResult
		updateResult, err = mongodb.Client.Database("platform-db").Collection("UserPreferences").UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo")
			return
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult)
		migrateCount++
	}
	if migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing", "identifier", v1schema.UsersPreferencesIdentifier)
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		return
	}
	reqLogger.Info("Successfully copied over UserPreferences row for User to EDB", "uid", user.UID)
	return
}

// xorDecode decodes an xor-encoded string
func xorDecode(e string) (d string, err error) {
	xorPrefix := "{xor}"
	eWithoutPrefix := strings.TrimPrefix(e, xorPrefix)
	var decodedFromBase64 []byte
	if decodedFromBase64, err = base64.StdEncoding.DecodeString(eWithoutPrefix); err != nil {
		return "", fmt.Errorf("failed to decode xor string: %w", err)
	}
	var dBytes []byte
	for _, b := range decodedFromBase64 {
		dBytes = append(dBytes, b^'_')
	}
	return string(dBytes), nil
}

func setClientSecretIfEmpty(ctx context.Context, mongodb *MongoDB, zenInstance *v1schema.ZenInstance) (set bool, err error) {
	if zenInstance.ClientSecret != "" {
		return
	}

	dbName := "OAuthDBSchema"
	collectionName := "OauthClient"
	clientIDFilter := bson.D{{Key: "CLIENTID", Value: zenInstance.ClientID}}
	oc := &v1schema.OIDCClient{}
	err = mongodb.Client.
		Database(dbName).
		Collection(collectionName).
		FindOne(ctx, clientIDFilter).
		Decode(oc)
	if err != nil {
		err = fmt.Errorf("failed to get OauthClient for ZenInstance: %w", err)
		return
	}

	decodedSecret, err := xorDecode(oc.ClientSecret)
	if err != nil {
		err = fmt.Errorf("failed to decode client_secret for ZenInstance: %w", err)
		return
	}

	zenInstance.ClientSecret = decodedSecret
	set = true

	return
}

func getHighestRoleForUserFromTeam(userID string, team *v1schema.Team) (role v1schema.Role) {
	teamUser := team.Users.GetUser(userID)
	if teamUser == nil {
		return v1schema.Authenticated
	}
	return teamUser.Roles.GetHighestRole()
}

func setUserV3Role(ctx context.Context, mongodb *MongoDB, user *v1schema.User) (set bool, err error) {
	if user.Role != "" {
		return
	}
	dbName := "platform-db"
	collectionName := "Team"
	filter := bson.D{}
	cursor, err := mongodb.Client.
		Database(dbName).
		Collection(collectionName).
		Find(ctx, filter)

	var highest v1schema.Role
	for cursor.Next(ctx) {
		team := &v1schema.Team{}
		if err = cursor.Decode(&team); err != nil {
			return
		}

		if current := getHighestRoleForUserFromTeam(user.UserID, team); current > highest {
			highest = current
		}
	}
	user.Role = highest.ToV3String()
	set = true
	return
}

func insertZenInstances(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "ZenInstance"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	filter := bson.D{{Key: "migrated", Value: bson.D{{Key: "$ne", Value: true}}}}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
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
			errCount++
			err = nil
			continue
		}

		zenInstance := &v1schema.ZenInstance{}
		if err = v1schema.ConvertToZenInstance(result, zenInstance); err != nil {
			reqLogger.Error(err, "Failed to unmarshal ZenInstance")
			errCount++
			err = nil
			continue
		}

		if _, err = setClientSecretIfEmpty(ctx, mongodb, zenInstance); err != nil {
			reqLogger.Error(err, "Failed to set client_secret on ZenInstance")
			errCount++
			err = nil
			continue
		}

		args := zenInstance.GetArgs()
		query := zenInstance.GetInsertSQL()
		_, err := postgres.Conn.Exec(ctx, query, args)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.zen_instances")
			errCount++
			continue
		}

		updateFilter := bson.D{{Key: "_id", Value: result["_id"]}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		updateResult, err := mongodb.Client.Database("platform-db").Collection("ZenInstance").UpdateOne(ctx, updateFilter, update)
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
		return
	}
	reqLogger.Info("Successfully copied over ZenInstances to EDB", "rowsInserted", migrateCount)
	return
}

func migrateZenInstanceUserRowForUser(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB, user *v1schema.User) (err error) {
	dbName := "platform-db"
	collectionName := "ZenInstanceUsers"
	reqLogger := logf.FromContext(ctx).WithValues()
	filter := bson.M{
		"$and": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{"usersId": user.UserID},
		},
	}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	migrateCount := 0
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			return
		}

		zenInstanceUser := &v1schema.ZenInstanceUser{}
		if err = v1schema.ConvertToZenInstanceUser(result, zenInstanceUser); err != nil {
			reqLogger.Error(err, "Failed to unmarshal ZenInstanceUser")
			return
		}
		args := zenInstanceUser.GetArgs()

		query := zenInstanceUser.GetInsertSQL()
		_, err = postgres.Conn.Exec(ctx, query, args)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.zen_instances_users")
			return
		}
		updateFilter := bson.D{{Key: "_id", Value: result["_id"]}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		var updateResult *mongo.UpdateResult
		updateResult, err = mongodb.Client.Database("platform-db").Collection("ZenInstanceUsers").UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo")
			return
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult)
		migrateCount++
	}
	if migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing")
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		return
	}
	reqLogger.Info("Successfully copied over ZenInstanceUsers row for User to EDB", "uid", user.UID)
	return
}

func insertSCIMAttributes(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "ScimAttributes"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	filter := bson.D{{Key: "migrated", Value: bson.D{{Key: "$ne", Value: true}}}}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
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
			errCount++
			err = nil
			continue
		}
		scimAttr := &v1schema.SCIMAttributes{}
		if err = v1schema.ConvertToSCIMAttributes(result, scimAttr); err != nil {
			reqLogger.Error(err, "Failed to unmarshal ScimAttributes")
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
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.scim_attributes")
			errCount++
			continue
		}
		updateFilter := bson.D{{Key: "_id", Value: result["_id"]}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		updateResult, err := mongodb.Client.Database(dbName).Collection(collectionName).UpdateOne(ctx, updateFilter, update)
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
		return
	}
	reqLogger.Info("Successfully copied over ScimAttributes to EDB", "rowsInserted", migrateCount)
	return
}

func insertSCIMAttributeMappings(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "ScimAttributeMapping"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	filter := bson.D{{Key: "migrated", Value: bson.D{{Key: "$ne", Value: true}}}}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
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
			errCount++
			err = nil
			continue
		}
		scimAttrMapping := &v1schema.SCIMAttributesMapping{}
		if err = v1schema.ConvertToSCIMAttributesMapping(result, scimAttrMapping); err != nil {
			reqLogger.Error(err, "Failed to unmarshal ScimAttributeMapping")
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
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.scim_attributes_mappings")
			errCount++
			continue
		}
		updateFilter := bson.D{{Key: "_id", Value: scimAttrMapping.IdpID}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		updateResult, err := mongodb.Client.Database(dbName).Collection(collectionName).UpdateOne(ctx, updateFilter, update)
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
		return
	}
	reqLogger.Info("Successfully copied over ScimAttributeMapping to EDB", "rowsInserted", migrateCount)
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

func getSSUserFromMap(result map[string]any) (ssUser *v1schema.ScimServerUser, err error) {
	ssUser = &v1schema.ScimServerUser{}
	if err = v1schema.ConvertToScimServerUser(result, ssUser); err != nil {
		err = fmt.Errorf("failed to unmarshal into scimserveruser: %w", err)
		ssUser = nil
		return
	}
	return
}

func insertSSUser(ctx context.Context, postgres *PostgresDB, ssUser *v1schema.ScimServerUser) (err error) {
	reqLogger := logf.FromContext(ctx)
	args := ssUser.GetArgs()
	query := ssUser.GetInsertSQL()
	var id *string
	err = postgres.Conn.QueryRow(ctx, query, args).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		reqLogger.Info("Row already exists in EDB table platformdb.scim_server_users")
		return nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.scim_server_users")
		return err
	}
	return
}

func insertSSUserCustom(ctx context.Context, postgres *PostgresDB, ssUserCustom *v1schema.ScimServerUserCustom) (err error) {
	reqLogger := logf.FromContext(ctx)
	args := ssUserCustom.GetArgs()
	query := ssUserCustom.GetInsertSQL()
	var id *string
	err = postgres.Conn.QueryRow(ctx, query, args).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		reqLogger.Info("Row already exists in EDB table platformdb.scim_server_users_custom")
		return nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.scim_server_users_custom")
		return err
	}
	return
}

func insertSSUserRelatedRows(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "ScimServerUsers"
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{{Key: "migrated", Value: bson.D{{Key: "$ne", Value: true}}}}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	for cursor.Next(ctx) {
		var ssUser *v1schema.ScimServerUser
		// mongo doc is split into 3 maps
		// ssUserMap - goes as a row into scim_server_users table
		// ssUserCustomMap - goes as a multiple rows into scim_server_users_custom table
		// ssUserCustomSchemaMap - goes as a multiple rows into scim_server_users_custom table
		var ssUserMap map[string]interface{}
		if err = cursor.Decode(&ssUserMap); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			errCount++
			err = nil
			continue
		}
		ssUserCustomMap := populateSSUserCustomMap(ssUserMap)
		ssUserCustomSchemaMap := populateSSUserCustomSchemaMap(ssUserCustomMap)
		ssUser, err = getSSUserFromMap(ssUserMap)
		if err != nil {
			reqLogger.Error(err, "Failed to convert map to ScimServerUser")
			errCount++
			err = nil
			continue
		}
		id := ssUser.ID
		if err = insertSSUser(ctx, postgres, ssUser); err != nil {
			errCount++
			err = nil
			continue
		}
		for key, value := range ssUserCustomMap {
			switch v := value.(type) {
			case string:
				ssUserCustom := &v1schema.ScimServerUserCustom{
					ScimServerUserUID: id,
					AttributeKey:      key,
					AttributeValue:    v,
				}
				if err = insertSSUserCustom(ctx, postgres, ssUserCustom); err != nil {
					errCount++
					err = nil
					continue
				}
			case any:
				ssUserCustom := &v1schema.ScimServerUserCustom{
					ScimServerUserUID:     id,
					AttributeKey:          key,
					AttributeValueComplex: v,
				}
				if err = insertSSUserCustom(ctx, postgres, ssUserCustom); err != nil {
					errCount++
					err = nil
					continue
				}
			}
		}
		for key, value := range ssUserCustomSchemaMap {
			schemaName := key
			switch v := value.(type) {
			case string:
				reqLogger.Info("invalid format")
			case map[string]any:
				for k, val := range v {
					switch v := val.(type) {
					case string:
						ssUserCustom := &v1schema.ScimServerUserCustom{
							ScimServerUserUID: id,
							AttributeKey:      k,
							AttributeValue:    v,
							SchemaName:        schemaName,
						}
						if err = insertSSUserCustom(ctx, postgres, ssUserCustom); err != nil {
							errCount++
							err = nil
							continue
						}
					case any:
						ssUserCustom := &v1schema.ScimServerUserCustom{
							ScimServerUserUID:     id,
							AttributeKey:          k,
							AttributeValueComplex: v,
							SchemaName:            schemaName,
						}
						if err = insertSSUserCustom(ctx, postgres, ssUserCustom); err != nil {
							errCount++
							err = nil
							continue
						}
					}
				}
			}
		}
		updateFilter := bson.D{{Key: "id", Value: id}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		updateResult, err := mongodb.Client.Database(dbName).Collection(collectionName).UpdateOne(ctx, updateFilter, update)
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
		reqLogger.Error(err, "Migration of platform-db.ScimServerUsers not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing", "identifier", v1schema.ScimServerUsersIdentifier)
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		return
	}
	reqLogger.Info("Successfully copied over ScimServerUsers to EDB", "docsMigrated", migrateCount)
	return
}

func getSSGroupFromMap(result map[string]any) (ssGroup *v1schema.ScimServerGroup, err error) {
	ssGroup = &v1schema.ScimServerGroup{}
	if err = v1schema.ConvertToScimServerGroup(result, ssGroup); err != nil {
		err = fmt.Errorf("failed to unmarshal into scimservergroup: %w", err)
		ssGroup = nil
		return
	}
	return
}

func insertSSGroup(ctx context.Context, postgres *PostgresDB, ssGroup *v1schema.ScimServerGroup) (err error) {
	reqLogger := logf.FromContext(ctx)
	args := ssGroup.GetArgs()
	query := ssGroup.GetInsertSQL()
	var id *string
	err = postgres.Conn.QueryRow(ctx, query, args).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		reqLogger.Info("Row already exists in EDB table platformdb.scim_server_groups")
		return nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.scim_server_groups")
		return err
	}
	return
}

func insertSSGroupCustom(ctx context.Context, postgres *PostgresDB, ssGroupCustom *v1schema.ScimServerGroupCustom) (err error) {
	reqLogger := logf.FromContext(ctx)
	args := ssGroupCustom.GetArgs()
	query := ssGroupCustom.GetInsertSQL()
	var id *string
	err = postgres.Conn.QueryRow(ctx, query, args).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		reqLogger.Info("Row already exists in EDB table platformdb.scim_server_groups_custom")
		return nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.scim_server_groups_custom")
		return err
	}
	return
}

func insertSSGroupRelatedRows(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "ScimServerGroups"
	reqLogger := logf.FromContext(ctx)
	filter := bson.D{{Key: "migrated", Value: bson.D{{Key: "$ne", Value: true}}}}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	for cursor.Next(ctx) {
		var ssGroup *v1schema.ScimServerGroup
		// mongo doc is split into 3 maps
		// ssGroupMap - goes as a row into scim_server_groups table
		// ssGroupCustomMap - goes as a multiple rows into scim_server_groups_custom table
		// ssGroupCustomSchemaMap - goes as a multiple rows into scim_server_groups_custom table
		var ssGroupMap map[string]interface{}
		if err = cursor.Decode(&ssGroupMap); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			errCount++
			err = nil
			continue
		}
		ssGroupCustomMap := populateSSGroupCustomMap(ssGroupMap)
		ssGroupCustomSchemaMap := populateSSGroupCustomSchemaMap(ssGroupCustomMap)
		ssGroup, err = getSSGroupFromMap(ssGroupMap)
		if err != nil {
			reqLogger.Error(err, "Failed to convert map to ScimServerGroup")
			errCount++
			err = nil
			continue
		}
		id := ssGroup.ID
		if err = insertSSGroup(ctx, postgres, ssGroup); err != nil {
			errCount++
			err = nil
			continue
		}
		for key, value := range ssGroupCustomMap {
			switch v := value.(type) {
			case string:
				ssGroupCustom := &v1schema.ScimServerGroupCustom{
					ScimServerGroupUID: id,
					AttributeKey:       key,
					AttributeValue:     v,
				}
				if err = insertSSGroupCustom(ctx, postgres, ssGroupCustom); err != nil {
					errCount++
					err = nil
					continue
				}
			case any:
				ssGroupCustom := &v1schema.ScimServerGroupCustom{
					ScimServerGroupUID:    id,
					AttributeKey:          key,
					AttributeValueComplex: v,
				}
				if err = insertSSGroupCustom(ctx, postgres, ssGroupCustom); err != nil {
					errCount++
					err = nil
					continue
				}
			}
		}
		for key, value := range ssGroupCustomSchemaMap {
			schemaName := key
			switch v := value.(type) {
			case string:
				reqLogger.Info("invalid format")
			case map[string]any:
				for k, val := range v {
					switch v := val.(type) {
					case string:
						ssGroupCustom := &v1schema.ScimServerGroupCustom{
							ScimServerGroupUID: id,
							AttributeKey:       k,
							AttributeValue:     v,
							SchemaName:         schemaName,
						}
						if err = insertSSGroupCustom(ctx, postgres, ssGroupCustom); err != nil {
							errCount++
							err = nil
							continue
						}
					case any:
						ssGroupCustom := &v1schema.ScimServerGroupCustom{
							ScimServerGroupUID:    id,
							AttributeKey:          k,
							AttributeValueComplex: v,
							SchemaName:            schemaName,
						}
						if err = insertSSGroupCustom(ctx, postgres, ssGroupCustom); err != nil {
							errCount++
							err = nil
							continue
						}
					}
				}
			}
		}
		updateFilter := bson.D{{Key: "id", Value: id}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		updateResult, err := mongodb.Client.Database(dbName).Collection(collectionName).UpdateOne(ctx, updateFilter, update)
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
		reqLogger.Error(err, "Migration of platform-db.ScimServerGroups not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing", "identifier", v1schema.ScimServerUsersIdentifier)
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		return
	}
	reqLogger.Info("Successfully copied over ScimServerGroups to EDB", "docsMigrated", migrateCount)
	return
}

func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func populateSSUserCustomMap(ssUserMap map[string]any) map[string]any {
	delete(ssUserMap, "_id")
	ssUserCustomMap := make(map[string]any)
	for key, value := range ssUserMap {
		if !contains(v1schema.ScimServerUsersMongoFieldNames, key) {
			ssUserCustomMap[key] = value
		}
	}
	return ssUserCustomMap
}

func populateSSGroupCustomMap(ssGroupMap map[string]any) map[string]any {
	delete(ssGroupMap, "_id")
	ssGroupCustomMap := make(map[string]any)
	for key, value := range ssGroupMap {
		if !contains(v1schema.ScimServerGroupsMongoFieldNames, key) {
			ssGroupCustomMap[key] = value
		}
	}
	return ssGroupCustomMap
}

func populateSSUserCustomSchemaMap(ssUserCustomMap map[string]any) map[string]any {
	usrSchemaMap := make(map[string]interface{})
	usrSchemaPrefix := "urn:ietf:params:scim:schemas"
	for key, value := range ssUserCustomMap {
		if strings.HasPrefix(key, usrSchemaPrefix) {
			if strings.Contains(key, "replaceDot") {
				newKey := strings.ReplaceAll(key, "replaceDot", ".")
				usrSchemaMap[newKey] = value
			} else if strings.Contains(key, "replaceDollar") {
				newKey := strings.ReplaceAll(key, "replaceDollar", "$")
				usrSchemaMap[newKey] = value
			} else {
				usrSchemaMap[key] = value
			}
			delete(ssUserCustomMap, key)
		}
	}
	return usrSchemaMap
}

func populateSSGroupCustomSchemaMap(ssGroupCustomMap map[string]any) map[string]any {
	grpSchemaMap := make(map[string]interface{})
	grpSchemaPrefix := "urn:ietf:params:scim:schemas"
	for key, value := range ssGroupCustomMap {
		if strings.HasPrefix(key, grpSchemaPrefix) {
			if strings.Contains(key, "replaceDot") {
				newKey := strings.ReplaceAll(key, "replaceDot", ".")
				grpSchemaMap[newKey] = value
			} else if strings.Contains(key, "replaceDollar") {
				newKey := strings.ReplaceAll(key, "replaceDollar", "$")
				grpSchemaMap[newKey] = value
			} else {
				grpSchemaMap[key] = value
			}
			delete(ssGroupCustomMap, key)
		}
	}
	return grpSchemaMap
}

func insertGroupsAndMemberRefs(ctx context.Context, mongodb *MongoDB, postgres *PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "Groups"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	filter := bson.M{
		"$and": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{"type": bson.M{"$eq": "SAML"}},
		},
	}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	var xref v1schema.UserGroup
	xrefQuery := xref.GetInsertSQL()
	for cursor.Next(ctx) {
		var group v1schema.Group
		if err = cursor.Decode(&group); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			errCount++
			err = nil
			continue
		}
		args := group.GetArgs()
		query := group.GetInsertSQL()
		_, err = postgres.Conn.Exec(ctx, query, args)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.groups")
			errCount++
			continue
		}
		membersNotMigrated := 0
		if group.Members != nil {
			for _, member := range group.Members {
				args := member.GetArgs()
				args["groupId"] = group.GroupID
				_, err = postgres.Conn.Exec(ctx, xrefQuery, args)
				if errors.Is(err, pgx.ErrNoRows) {
					reqLogger.Info("Row already exists in EDB")
				} else if err != nil {
					reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.users_groups")
					membersNotMigrated++
					continue
				}
			}
		}
		if membersNotMigrated != 0 {
			reqLogger.Error(err, fmt.Sprintf("%d of %d members could not be migrated for group %s", membersNotMigrated, len(group.Members), group.GroupID))
			errCount++
			continue
		}
		updateFilter := bson.D{{Key: "_id", Value: group.GroupID}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "migrated", Value: true}}}}
		updateResult, err := mongodb.Client.Database(dbName).Collection(collectionName).UpdateOne(ctx, updateFilter, update)
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
		reqLogger.Error(err, "Migration of platform-db.groups not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing")
		return
	}
	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		return
	}
	reqLogger.Info("Successfully copied over Groups to EDB", "rowsInserted", migrateCount)
	return
}

type copyFunc func(context.Context, *MongoDB, *PostgresDB) error
