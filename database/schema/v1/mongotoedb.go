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
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	dbconn "github.com/IBM/ibm-iam-operator/database/connectors"
	"github.com/IBM/ibm-iam-operator/database/migration"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var mongoToV1Func migration.MigrationFunc = func(ctx context.Context, to, from dbconn.DBConn) (err error) {
	reqLogger := logf.FromContext(ctx)
	mongodb, ok := from.(*dbconn.MongoDB)
	reqLogger.Info("Connecting to MongoDB", "MongoDB.Host", mongodb.Host, "MongoDB.Port", mongodb.Port)
	if !ok {
		return fmt.Errorf("from should be an instance of MongoDB")
	}
	if err = mongodb.Connect(ctx); err != nil {
		reqLogger.Error(err, "Failed to connect to MongoDB")
		return
	}
	defer mongodb.Disconnect(ctx)

	postgres, ok := to.(*dbconn.PostgresDB)
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
		insertOauthTokens,
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

func insertOIDCClients(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB) (err error) {
	dbName := "OAuthDBSchema"
	collectionName := "OauthClient"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	migrationKey := postgres.GetMigrationKey()
	filter := bson.M{
		"$or": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{migrationKey: bson.M{"$ne": true}},
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

		oc := &OIDCClient{}
		if err = ConvertToOIDCClient(result, oc); err != nil {
			reqLogger.Error(err, "Failed to unmarshal oauthclient")
			errCount++
			err = nil
			continue
		}
		query := oc.GetInsertSQL()
		args := GetNamedArgsFromRow(oc)
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
		update := bson.D{{Key: "$set", Value: bson.D{{Key: migrationKey, Value: true}}}}
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

func insertOauthTokens(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB) (err error) {
	dbName := "OAuthDBSchema"
	collectionName := "OauthToken"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	migrationKey := postgres.GetMigrationKey()
	filter := bson.D{{Key: migrationKey, Value: bson.D{{Key: "$ne", Value: true}}}}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	for cursor.Next(ctx) {
		token := &OauthToken{}
		if err = cursor.Decode(token); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			errCount++
			err = nil
			continue
		}

		query := token.GetInsertSQL()
		args := GetNamedArgsFromRow(token)
		_, err = postgres.Conn.Exec(ctx, query, args)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "oauthdbschema.oauthtoken")
			errCount++
			continue
		}
		updateFilter := bson.D{{Key: "LOOKUPKEY", Value: token.LookupKey}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: migrationKey, Value: true}}}}
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
		reqLogger.Error(err, "Migration of oauthdbschema.oauthtoken not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing")
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		return
	}
	reqLogger.Info("Successfully copied over OAuth tokens to EDB", "rowsInserted", migrateCount)
	return
}

func insertIdpConfigs(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "cloudpak_ibmid_v3"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	migrationKey := postgres.GetMigrationKey()
	filter := bson.M{
		"$or": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{migrationKey: bson.M{"$ne": true}},
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
		idpConfig := &IdpConfig{}
		if err = ConvertToIdpConfig(result, idpConfig); err != nil {
			reqLogger.Error(err, "Failed to unmarshal idp_config")
			errCount++
			err = nil
			continue
		}
		query := idpConfig.GetInsertSQL()
		args := GetNamedArgsFromRow(idpConfig)
		var uid *string
		err := postgres.Conn.QueryRow(ctx, query, args).Scan(&uid)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.idp_configs")
			errCount++
			continue
		}
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

func insertDirectoriesAsIdpConfigs(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "Directory"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	migrationKey := postgres.GetMigrationKey()
	filter := bson.M{
		"$and": bson.A{
			bson.M{migrationKey: bson.M{"$ne": true}},
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

		var idpConfig *IdpConfig
		var uid string
		if idpConfig, err = ConvertV2DirectoryToV3IdpConfig(result); err != nil {
			reqLogger.Error(err, "Failed to convert Directory to v3-compatible IDP config")
			errCount++
			continue
		}
		query := idpConfig.GetInsertSQL()
		args := GetNamedArgsFromRow(idpConfig)
		err := postgres.Conn.QueryRow(ctx, query, args).Scan(&uid)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.idp_configs")
			errCount++
			continue
		}
		updateFilter := bson.D{{Key: "_id", Value: idpConfig.UID}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: migrationKey, Value: true}}}}
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

func insertV2SamlAsIdpConfig(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "cloudpak_ibmid_v2"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	v3SamlFilter := bson.M{"protocol": "saml"}
	v3Saml := &IdpConfig{}
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
	migrationKey := postgres.GetMigrationKey()
	// filter := bson.M{migrationKey: bson.M{"$ne": true}}
	filter := bson.M{
		"$or": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{migrationKey: bson.M{"$ne": true}},
		},
	}
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

		var idpConfig *IdpConfig
		var uid string
		if idpConfig, err = ConvertV2SamlToIdpConfig(result); err != nil {
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
		args := GetNamedArgsFromRow(idpConfig)
		err := postgres.Conn.QueryRow(ctx, query, args).Scan(&uid)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.idp_configs")
			errCount++
			continue
		}
		updateFilter := bson.D{{Key: "protocol", Value: "saml"}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: migrationKey, Value: true}}}}
		updateResult, err := mongodb.Client.Database(dbName).Collection(collectionName).UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo", "MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
			errCount++
			continue
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult, "MongoDB.DB", dbName, "MongoDB.Collection", collectionName)

		samlDBUpdateFilter := bson.D{{Key: "name", Value: "saml"}}
		samlDBUpdate := bson.D{{Key: "$set", Value: bson.D{{Key: migrationKey, Value: true}}}}
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

func insertUser(ctx context.Context, postgres *dbconn.PostgresDB, user *User) (uid *uuid.UUID, err error) {
	reqLogger := logf.FromContext(ctx)
	args := GetNamedArgsFromRow(user)
	query := user.GetInsertSQL()
	uid = &uuid.UUID{}
	err = postgres.Conn.QueryRow(ctx, query, args).Scan(uid)
	if errors.Is(err, pgx.ErrNoRows) {
		reqLogger.Info("Row already exists in EDB")
		queryIfRowExists := "SELECT uid from platformdb.users WHERE user_id = @user_id;"
		args = pgx.NamedArgs{"user_id": user.UserID}
		if err := postgres.Conn.QueryRow(ctx, queryIfRowExists, args).Scan(uid); err != nil {
			return nil, errors.New(fmt.Sprint("failed to get uid for userId:", user.UserID))
		}
		return uid, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.users")
		return nil, err
	}
	return
}

func getUserFromMongoCursor(cursor *mongo.Cursor) (user *User, err error) {
	var result map[string]any
	if err = cursor.Decode(&result); err != nil {
		err = fmt.Errorf("failed to decode MongoDB document: %w", err)
		return
	}
	user = &User{}
	if err = ConvertToUser(result, user); err != nil {
		err = fmt.Errorf("failed to unmarshal into user: %w", err)
		user = nil
		return
	}
	return
}

func insertUserRelatedRows(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "Users"
	reqLogger := logf.FromContext(ctx)
	migrationKey := postgres.GetMigrationKey()
	// filter := bson.D{{Key: migrationKey, Value: bson.D{{Key: "$ne", Value: true}}}}
	filter := bson.M{
		"$or": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{migrationKey: bson.M{"$ne": true}},
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
		var user *User
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
		update := bson.D{{Key: "$set", Value: bson.D{{Key: migrationKey, Value: true}}}}
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
			reqLogger.Error(err, "Inserting UserPreferences failed", "identifier", UsersIdentifier)
			continue
		}
		if err = migrateZenInstanceUserRowForUser(ctx, mongodb, postgres, user); err != nil {
			errCount++
			reqLogger.Error(err, "Inserting ZenInstanceUser failed", "identifier", UsersIdentifier)
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
		reqLogger.Info("No documents needed to be migrated; continuing", "identifier", UsersIdentifier)
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		return
	}
	reqLogger.Info("Successfully copied over Users to EDB", "rowsInserted", migrateCount)
	return
}

func migrateUserPreferencesRowForUser(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB, user *User) (err error) {
	reqLogger := logf.FromContext(ctx)
	preferenceId := strings.Join([]string{"preferenceId", user.UserID}, "_")
	migrationKey := postgres.GetMigrationKey()
	filter := bson.M{
		"$and": bson.A{
			bson.M{migrationKey: bson.M{"$ne": true}},
			bson.M{"_id": preferenceId},
		},
	}
	cursor, err := mongodb.Client.Database("platform-db").Collection("UserPreferences").Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB", "identifier", UsersPreferencesIdentifier)
		return
	}
	migrateCount := 0
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document", "identifier", UsersPreferencesIdentifier)
			return err
		}
		userPrefs := &UserPreferences{}
		if err = ConvertToUserPreferences(result, userPrefs); err != nil {
			reqLogger.Error(err, "Failed to unmarshal UserPreferences", "identifier", UsersPreferencesIdentifier)
			return err
		}
		userPrefs.UserUID = user.UID.String()
		args := GetNamedArgsFromRow(userPrefs)

		query := userPrefs.GetInsertSQL()
		reqLogger.Info("Executing query for UserPreferences", "preferenceId", preferenceId, "uid", userPrefs.UserUID)
		_, err = postgres.Conn.Exec(ctx, query, args)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
			err = nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.users_preferences", "identifier", UsersPreferencesIdentifier)
			return err
		}
		updateFilter := bson.D{{Key: "_id", Value: preferenceId}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: migrationKey, Value: true}}}}
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
		reqLogger.Info("No documents needed to be migrated; continuing", "identifier", UsersPreferencesIdentifier)
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

func setClientSecretIfEmpty(ctx context.Context, mongodb *dbconn.MongoDB, zenInstance *ZenInstance) (set bool, err error) {
	if zenInstance.ClientSecret != "" {
		return
	}

	dbName := "OAuthDBSchema"
	collectionName := "OauthClient"
	clientIDFilter := bson.D{{Key: "CLIENTID", Value: zenInstance.ClientID}}
	oc := &OIDCClient{}
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

func getHighestRoleForUserFromTeam(userID string, team *Team) (role Role) {
	teamUser := team.Users.GetUser(userID)
	if teamUser == nil {
		return Authenticated
	}
	return teamUser.Roles.GetHighestRole()
}

func setUserV3Role(ctx context.Context, mongodb *dbconn.MongoDB, user *User) (set bool, err error) {
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

	var highest Role
	for cursor.Next(ctx) {
		team := &Team{}
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

func insertZenInstances(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "ZenInstance"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	migrationKey := postgres.GetMigrationKey()
	filter := bson.M{
		"$or": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{migrationKey: bson.M{"$ne": true}},
		},
	}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	errCount := 0
	migrateCount := 0
	skipped := []string{}
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			errCount++
			err = nil
			continue
		}

		zenInstance := &ZenInstance{}
		if err = ConvertToZenInstance(result, zenInstance); err != nil {
			reqLogger.Error(err, "Failed to unmarshal ZenInstance")
			errCount++
			err = nil
			continue
		}

		if _, err = setClientSecretIfEmpty(ctx, mongodb, zenInstance); err != nil {
			reqLogger.Info("Failed to set client_secret on ZenInstance; skipping it as it is potentially invalid", "reason", err.Error())
			skipped = append(skipped, zenInstance.InstanceID)
			err = nil
			continue
		}

		args := GetNamedArgsFromRow(zenInstance)
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
		update := bson.D{{Key: "$set", Value: bson.D{{Key: migrationKey, Value: true}}}}
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
	} else if len(skipped) > 0 {
		reqLogger.Info("The migration of the following documents was skipped", "skippedIDs", skipped)
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

func migrateZenInstanceUserRowForUser(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB, user *User) (err error) {
	dbName := "platform-db"
	collectionName := "ZenInstanceUsers"
	reqLogger := logf.FromContext(ctx).WithValues()
	migrationKey := postgres.GetMigrationKey()
	filter := bson.M{
		"$and": bson.A{
			bson.M{migrationKey: bson.M{"$ne": true}},
			bson.M{"usersId": user.UserID},
		},
	}
	cursor, err := mongodb.Client.Database(dbName).Collection(collectionName).Find(ctx, filter)
	if err != nil {
		reqLogger.Error(err, "Failed to get cursor from MongoDB")
		return
	}
	migrateCount := 0
	skipped := false
	for cursor.Next(ctx) {
		var result map[string]interface{}
		if err = cursor.Decode(&result); err != nil {
			reqLogger.Error(err, "Failed to decode Mongo document")
			return
		}

		zenInstanceUser := &ZenInstanceUser{}
		if err = ConvertToZenInstanceUser(result, zenInstanceUser); err != nil {
			reqLogger.Error(err, "Failed to unmarshal ZenInstanceUser")
			return
		}
		hasMigratedFilter := bson.M{
			"$or": bson.A{
				bson.M{"migrated": bson.M{"$eq": true}},
				bson.M{migrationKey: bson.M{"$eq": true}},
			},
		}

		hasMatchingZenInstanceIDFilter := bson.M{"_id": bson.M{"$eq": zenInstanceUser.ZenInstanceID}}

		matchingZenInstanceIDAndHasMigratedFilter := bson.M{
			"$and": bson.A{
				hasMigratedFilter,
				hasMatchingZenInstanceIDFilter,
			},
		}
		zenInstanceQueryResult := mongodb.
			Client.
			Database(dbName).
			Collection("ZenInstance").
			FindOne(ctx, matchingZenInstanceIDAndHasMigratedFilter)
		if errors.Is(zenInstanceQueryResult.Err(), mongo.ErrNoDocuments) {
			reqLogger.Info("The ZenInstance this ZenInstanceUser is associated with was not migrated; skipping this document")
			skipped = true
			continue
		} else if zenInstanceQueryResult.Err() != nil {
			reqLogger.Error(err, "Failed to determine migration status of ZenInstance referred to by this ZenInstanceUser")
			return
		}
		args := GetNamedArgsFromRow(zenInstanceUser)

		query := zenInstanceUser.GetInsertSQL()
		_, err = postgres.Conn.Exec(ctx, query, args)
		if errors.Is(err, pgx.ErrNoRows) {
			reqLogger.Info("Row already exists in EDB")
		} else if err != nil {
			reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.zen_instances_users")
			return
		}
		updateFilter := bson.D{{Key: "_id", Value: result["_id"]}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: migrationKey, Value: true}}}}
		var updateResult *mongo.UpdateResult
		updateResult, err = mongodb.Client.Database("platform-db").Collection("ZenInstanceUsers").UpdateOne(ctx, updateFilter, update)
		if err != nil {
			reqLogger.Error(err, "Failed to write back migration completion to Mongo")
			return
		}
		reqLogger.Info("Wrote back document migration", "updateResult", updateResult)
		migrateCount++
	}
	if skipped {
		reqLogger.Info("The migration of the following document was skipped", "uid", user.UserID)
		return
	} else if migrateCount == 0 {
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

func insertSCIMAttributes(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "ScimAttributes"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	migrationKey := postgres.GetMigrationKey()
	// filter := bson.D{{Key: migrationKey, Value: bson.D{{Key: "$ne", Value: true}}}}
	filter := bson.M{
		"$or": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{migrationKey: bson.M{"$ne": true}},
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
		scimAttr := &SCIMAttributes{}
		if err = ConvertToSCIMAttributes(result, scimAttr); err != nil {
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
		update := bson.D{{Key: "$set", Value: bson.D{{Key: migrationKey, Value: true}}}}
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

func insertSCIMAttributeMappings(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "ScimAttributeMapping"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	migrationKey := postgres.GetMigrationKey()
	// filter := bson.D{{Key: migrationKey, Value: bson.D{{Key: "$ne", Value: true}}}}
	filter := bson.M{
		"$or": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{migrationKey: bson.M{"$ne": true}},
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
		scimAttrMapping := &SCIMAttributesMapping{}
		if err = ConvertToSCIMAttributesMapping(result, scimAttrMapping); err != nil {
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
		update := bson.D{{Key: "$set", Value: bson.D{{Key: migrationKey, Value: true}}}}
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

func removeInvalidUserPreferences(usersPrefs []UserPreferences) (updated []UserPreferences) {
	for _, userPrefs := range usersPrefs {
		if userPrefs.LastLogin != nil {
			updated = append(updated, userPrefs)
		}
	}
	return
}

func getSSUserFromMap(result map[string]any) (ssUser *ScimServerUser, err error) {
	ssUser = &ScimServerUser{}
	if err = ConvertToScimServerUser(result, ssUser); err != nil {
		err = fmt.Errorf("failed to unmarshal into scimserveruser: %w", err)
		ssUser = nil
		return
	}
	return
}

func insertSSUser(ctx context.Context, postgres *dbconn.PostgresDB, ssUser *ScimServerUser) (err error) {
	reqLogger := logf.FromContext(ctx)
	args := GetNamedArgsFromRow(ssUser)
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

func insertSSUserCustom(ctx context.Context, postgres *dbconn.PostgresDB, ssUserCustom *ScimServerUserCustom) (err error) {
	reqLogger := logf.FromContext(ctx)
	args := GetNamedArgsFromRow(ssUserCustom)
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

func insertSSUserRelatedRows(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "ScimServerUsers"
	reqLogger := logf.FromContext(ctx)
	migrationKey := postgres.GetMigrationKey()
	// filter := bson.D{{Key: migrationKey, Value: bson.D{{Key: "$ne", Value: true}}}}
	filter := bson.M{
		"$or": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{migrationKey: bson.M{"$ne": true}},
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
		var ssUser *ScimServerUser
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
				ssUserCustom := &ScimServerUserCustom{
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
				ssUserCustom := &ScimServerUserCustom{
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
						ssUserCustom := &ScimServerUserCustom{
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
						ssUserCustom := &ScimServerUserCustom{
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
		migrateCount++

	}
	if errCount > 0 {
		err = fmt.Errorf("encountered errors that prevented the migration of documents")
		reqLogger.Error(err, "Migration of platform-db.ScimServerUsers not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing", "identifier", ScimServerUsersIdentifier)
		return
	}

	if err = cursor.Err(); err != nil {
		reqLogger.Error(err, "MongoDB cursor encountered an error")
		return
	}
	reqLogger.Info("Successfully copied over ScimServerUsers to EDB", "docsMigrated", migrateCount)
	return
}

func getSSGroupFromMap(result map[string]any) (ssGroup *ScimServerGroup, err error) {
	ssGroup = &ScimServerGroup{}
	if err = ConvertToScimServerGroup(result, ssGroup); err != nil {
		err = fmt.Errorf("failed to unmarshal into scimservergroup: %w", err)
		ssGroup = nil
		return
	}
	return
}

func insertSSGroup(ctx context.Context, postgres *dbconn.PostgresDB, ssGroup *ScimServerGroup) (err error) {
	reqLogger := logf.FromContext(ctx)
	args := GetNamedArgsFromRow(ssGroup)
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

func insertSSGroupCustom(ctx context.Context, postgres *dbconn.PostgresDB, ssGroupCustom *ScimServerGroupCustom) (err error) {
	reqLogger := logf.FromContext(ctx)
	args := GetNamedArgsFromRow(ssGroupCustom)
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

func insertSSGroupRelatedRows(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "ScimServerGroups"
	reqLogger := logf.FromContext(ctx)
	migrationKey := postgres.GetMigrationKey()
	// filter := bson.D{{Key: migrationKey, Value: bson.D{{Key: "$ne", Value: true}}}}
	filter := bson.M{
		"$or": bson.A{
			bson.M{"migrated": bson.M{"$ne": true}},
			bson.M{migrationKey: bson.M{"$ne": true}},
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
		var ssGroup *ScimServerGroup
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
				ssGroupCustom := &ScimServerGroupCustom{
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
				ssGroupCustom := &ScimServerGroupCustom{
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
						ssGroupCustom := &ScimServerGroupCustom{
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
						ssGroupCustom := &ScimServerGroupCustom{
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
		migrateCount++

	}
	if errCount > 0 {
		err = fmt.Errorf("encountered errors that prevented the migration of documents")
		reqLogger.Error(err, "Migration of platform-db.ScimServerGroups not successful", "failedCount", errCount, "successCount", migrateCount)
		return
	} else if errCount == 0 && migrateCount == 0 {
		reqLogger.Info("No documents needed to be migrated; continuing", "identifier", ScimServerUsersIdentifier)
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
		if !contains(ScimServerUsersMongoFieldNames, key) {
			ssUserCustomMap[key] = value
		}
	}
	return ssUserCustomMap
}

func populateSSGroupCustomMap(ssGroupMap map[string]any) map[string]any {
	delete(ssGroupMap, "_id")
	ssGroupCustomMap := make(map[string]any)
	for key, value := range ssGroupMap {
		if !contains(ScimServerGroupsMongoFieldNames, key) {
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

func insertGroupsAndMemberRefs(ctx context.Context, mongodb *dbconn.MongoDB, postgres *dbconn.PostgresDB) (err error) {
	dbName := "platform-db"
	collectionName := "Groups"
	reqLogger := logf.FromContext(ctx).WithValues("MongoDB.DB", dbName, "MongoDB.Collection", collectionName)
	migrationKey := postgres.GetMigrationKey()
	filter := bson.M{
		"$and": bson.A{
			bson.M{migrationKey: bson.M{"$ne": true}},
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
	var xref UserGroup
	xrefQuery := xref.GetInsertSQL()
	for cursor.Next(ctx) {
		var group Group
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
		acknowledgeErr := true
		if group.Members != nil {
			for _, member := range group.Members {
				args := member.GetArgs()
				args["groupId"] = group.GroupID
				_, err = postgres.Conn.Exec(ctx, xrefQuery, args)
				if errors.Is(err, pgx.ErrNoRows) {
					reqLogger.Info("Row already exists in EDB")
				} else if err != nil {
					reqLogger.Error(err, "Failed to INSERT into table", "table", "platformdb.users_groups")
					if strings.Contains(err.Error(), "SQLSTATE 23502") {
						reqLogger.Error(errors.New("platformdb.users_groups mapping encountered SQLSTATE 23502 error"), fmt.Sprintf("Group ID = %s, Member Value = %s", group.GroupID, member.Value))
						acknowledgeErr = false
						err = nil // reset error to nil
					} else {
						membersNotMigrated++
					}
					continue
				}
			}
		}
		if membersNotMigrated != 0 {
			reqLogger.Error(err, fmt.Sprintf("%d of %d members could not be migrated for group %s", membersNotMigrated, len(group.Members), group.GroupID))
			if acknowledgeErr {
				errCount++
			}
			continue
		}
		updateFilter := bson.D{{Key: "_id", Value: group.GroupID}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: migrationKey, Value: true}}}}
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

type copyFunc func(context.Context, *dbconn.MongoDB, *dbconn.PostgresDB) error
