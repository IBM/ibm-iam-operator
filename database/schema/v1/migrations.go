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
	"fmt"

	dbconn "github.com/IBM/ibm-iam-operator/database/connectors"
	"github.com/IBM/ibm-iam-operator/database/migration"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func AllMigrations() []*migration.Migration {
	return []*migration.Migration{
		CreateMetadataSchema,
		InitOperandSchemas,
		MongoToEDBv1,
		IncreaseOIDCUsernameSize,
		IncreaseTokenstringSize,
		AlterUsersAttributesUniqueAndCascadeDeleteConstraint,
	}
}

var CreateMetadataSchema *migration.Migration = migration.NewMigration().
	Name("CreateMetadataSchema").
	ID(0).
	RunFunc(&createMetadataSchemaFunc).
	Build()

var InitOperandSchemas *migration.Migration = migration.NewMigration().
	Name("InitOperandSchemas").
	ID(1).
	RunFunc(&initOperandSchemasFunc).
	Dependencies([]*migration.Migration{CreateMetadataSchema}).
	Build()

var MongoToEDBv1 *migration.Migration = migration.NewMigration().
	Name("MongoToEDBv1").
	ID(2).
	RunFunc(&mongoToV1Func).
	Dependencies([]*migration.Migration{IncreaseOIDCUsernameSize, InitOperandSchemas}).
	Build()

var IncreaseOIDCUsernameSize *migration.Migration = migration.NewMigration().
	Name("IncreaseOIDCUsernameSize").
	ID(3).
	RunFunc(&increaseOIDCUsernameSizeFunc).
	Dependencies([]*migration.Migration{InitOperandSchemas, CreateMetadataSchema}).
	Build()

var IncreaseTokenstringSize *migration.Migration = migration.NewMigration().
	Name("IncreaseTokenstringSize").
	ID(4).
	RunFunc(&increaseTokenstringSizeFunc).
	Dependencies([]*migration.Migration{InitOperandSchemas, CreateMetadataSchema}).
	Build()

var AlterUsersAttributesUniqueAndCascadeDeleteConstraint *migration.Migration = migration.NewMigration().
	Name("AlterUsersAttributesUniqueAndCascadeDeleteConstraint").
	ID(5).
	RunFunc(&alterUsersAttributesUniqueAndCascadeDeleteConstraint).
	Dependencies([]*migration.Migration{InitOperandSchemas, CreateMetadataSchema}).
	Build()

var initOperandSchemasFunc migration.MigrationFunc = func(ctx context.Context, to, from dbconn.DBConn) (err error) {
	reqLogger := logf.FromContext(ctx)
	postgres, ok := to.(*dbconn.PostgresDB)
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
		reqLogger.Info("Running DDL for initial schema")
		if err = to.RunDDL(ctx, DBInitMigration); err != nil {
			reqLogger.Error(err, "Failed to execute DDL")
			return
		}
	}
	reqLogger.Info("Initial schema already exists; marking as complete")

	return
}

var alterUsersAttributesUniqueAndCascadeDeleteConstraint migration.MigrationFunc = func(ctx context.Context, to, from dbconn.DBConn) (err error) {
	reqLogger := logf.FromContext(ctx)
	postgres, ok := to.(*dbconn.PostgresDB)
	if !ok {
		return fmt.Errorf("to should be an instance of Postgres")
	}
	reqLogger.Info("Connecting to PostgresDB", "PostgresDB.Host", postgres.Host, "PostgresDB.Port", postgres.Port)
	if err = postgres.Connect(ctx); err != nil {
		reqLogger.Error(err, "Failed to connect to Postgres")
		return
	}
	defer postgres.Disconnect(ctx)
	tx, err := postgres.Conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, "ALTER TABLE platformdb.users_attributes ADD CONSTRAINT users_attributes_uniqueness UNIQUE (user_uid,name);")
	if err != nil {
		return
	}
	_, err = tx.Exec(ctx, "ALTER TABLE platformdb.users_attributes DROP CONSTRAINT fk_useratt_fk;")
	if err != nil {
		return
	}
	_, err = tx.Exec(ctx, "ALTER TABLE platformdb.users_attributes ADD CONSTRAINT fk_useratt_fk FOREIGN KEY (user_uid) REFERENCES platformdb.users (uid) ON DELETE CASCADE;")
	if err != nil {
		return
	}

	err = tx.Commit(ctx)
	return
}

var increaseOIDCUsernameSizeFunc migration.MigrationFunc = func(ctx context.Context, to, from dbconn.DBConn) (err error) {
	reqLogger := logf.FromContext(ctx)
	postgres, ok := to.(*dbconn.PostgresDB)
	if !ok {
		return fmt.Errorf("to should be an instance of Postgres")
	}
	reqLogger.Info("Connecting to PostgresDB", "PostgresDB.Host", postgres.Host, "PostgresDB.Port", postgres.Port)
	if err = postgres.Connect(ctx); err != nil {
		reqLogger.Error(err, "Failed to connect to Postgres")
		return
	}
	defer postgres.Disconnect(ctx)
	tx, err := postgres.Conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, "ALTER TABLE oauthdbschema.oauthtoken ALTER COLUMN username TYPE varchar;")
	if err != nil {
		return
	}
	_, err = tx.Exec(ctx, "ALTER TABLE oauthdbschema.oauthconsent ALTER COLUMN username TYPE varchar;")
	if err != nil {
		return
	}

	err = tx.Commit(ctx)
	return
}

var increaseTokenstringSizeFunc migration.MigrationFunc = func(ctx context.Context, to, from dbconn.DBConn) (err error) {
	reqLogger := logf.FromContext(ctx)
	postgres, ok := to.(*dbconn.PostgresDB)
	if !ok {
		return fmt.Errorf("to should be an instance of Postgres")
	}
	reqLogger.Info("Connecting to PostgresDB", "PostgresDB.Host", postgres.Host, "PostgresDB.Port", postgres.Port)
	if err = postgres.Connect(ctx); err != nil {
		reqLogger.Error(err, "Failed to connect to Postgres")
		return
	}
	defer postgres.Disconnect(ctx)
	tx, err := postgres.Conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, "ALTER TABLE oauthdbschema.oauthtoken ALTER COLUMN tokenstring TYPE varchar;")
	if err != nil {
		return
	}
	err = tx.Commit(ctx)
	return
}

var createMetadataSchemaFunc migration.MigrationFunc = func(ctx context.Context, to, from dbconn.DBConn) (err error) {
	reqLogger := logf.FromContext(ctx)
	postgres, ok := to.(*dbconn.PostgresDB)
	if !ok {
		return fmt.Errorf("to should be an instance of Postgres")
	}
	reqLogger.Info("Connecting to PostgresDB", "PostgresDB.Host", postgres.Host, "PostgresDB.Port", postgres.Port)
	if err = postgres.Connect(ctx); err != nil {
		reqLogger.Error(err, "Failed to connect to Postgres")
		return
	}
	defer postgres.Disconnect(ctx)
	tx, err := postgres.Conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var createMetadataSchemaQuery = "CREATE SCHEMA IF NOT EXISTS metadata;"
	_, err = tx.Exec(ctx, createMetadataSchemaQuery)
	if err != nil {
		return
	}
	var createChangelogTableQuery = `
CREATE TABLE IF NOT EXISTS metadata.changelog
(
  id int NOT NULL,
  name varchar NOT NULL,
  im_version varchar NOT NULL,
  install_time timestamptz NOT NULL,
  CONSTRAINT pk_id PRIMARY KEY (id)
);`
	_, err = tx.Exec(ctx, createChangelogTableQuery)
	if err != nil {
		return
	}
	err = tx.Commit(ctx)
	return
}
