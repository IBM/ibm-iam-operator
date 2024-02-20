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
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

//go:embed v1.sql
var initDDL string

// TODO Add any helpful properties
type Result struct {
	Error    error
	Complete bool
}

type DatastoreConfig struct {
	Name       string
	Port       string
	User       string
	RWEndpoint string
	REndpoint  string
	CACert     []byte
	ClientCert []byte
	ClientKey  []byte
}

// Migrate initializes the EDB database for the IM Operands and performs any additional migrations that may be needed.
func Migrate(ctx context.Context, c chan *Result, config *DatastoreConfig) {
	reqLogger := logf.FromContext(ctx).WithName("migration_worker")
	reqLogger.Info("Initializing EDB schemas")

	result := &Result{}
	var conn *pgx.Conn
	var err error
	if conn, err = getEDBConn(ctx, config); err != nil {
		reqLogger.Error(err, "Failed to connect to DB")
		c <- &Result{Error: err}
		close(c)
		return
	}
	defer conn.Close(ctx)

	if found, err := hasSchemas(ctx, conn); err != nil {
		reqLogger.Error(err, "Failed to get schemas")
		result.Error = err
		c <- result
		close(c)
		return
	} else if found {
		reqLogger.Info("Schemas found in DB; no migration required")
		c <- result
		close(c)
		return
	}

	err = initEDB(logf.IntoContext(ctx, reqLogger), conn)

	if err != nil {
		reqLogger.Error(result.Error, "Failed to migrate")
		result.Error = err
	} else {
		reqLogger.Info("Migration completed")
	}
	c <- result
	close(c)
}

type IdpConfig struct {
	UID         string            `db:"uid"`
	Name        string            `db:"name"`
	Protocol    string            `db:"protocol"`
	Type        string            `db:"type"`
	Description string            `db:"description"`
	Enabled     string            `db:"enabled"`
	IDPConfig   map[string]string `db:"idp_config"`
	SCIMConfig  map[string]string `db:"scim_config"`
	LDAPConfig  map[string]string `db:"ldap_config"`
	JIT         bool              `db:"jit"`
}

func getEDBConn(ctx context.Context, config *DatastoreConfig) (conn *pgx.Conn, err error) {
	reqLogger := logf.FromContext(ctx)
	dsn := fmt.Sprintf("host=%s user=%s dbname=%s port=%s sslmode=require", config.RWEndpoint, config.User, config.Name, config.Port)

	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(config.CACert)
	var clientCert tls.Certificate
	if clientCert, err = tls.X509KeyPair(config.ClientCert, config.ClientKey); err != nil {
		reqLogger.Error(err, "Failed to assemble client key pair")
		return nil, err
	}
	reqLogger.Info("Assembled client key pair")

	var connConfig *pgx.ConnConfig
	if connConfig, err = pgx.ParseConfig(dsn); err != nil {
		reqLogger.Error(err, "Failed to parse database configuration")
		return nil, err
	}
	reqLogger.Info("Connection to DB configured")

	connConfig.TLSConfig = &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            rootCertPool,
		InsecureSkipVerify: true,
	}

	if conn, err = pgx.ConnectConfig(ctx, connConfig); err != nil {
		reqLogger.Error(err, "Failed to connect to database")
		return nil, err
	}
	reqLogger.Info("Connected to DB")

	return
}

func hasSchemas(ctx context.Context, conn *pgx.Conn) (bool, error) {
	reqLogger := logf.FromContext(ctx)
	var err error
	var rows pgx.Rows
	if rows, err = conn.Query(ctx, "SELECT schema_name FROM information_schema.schemata;"); err != nil {
		reqLogger.Error(err, "Failed to retrieve schema names")
		return false, err
	}
	defer rows.Close()

	foundSchemas := map[string]bool{
		"platformdb":    false,
		"oauthdbschema": false,
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

// initEDB executes the DDL that initializes the schemas and tables that the different IM Operands will use.
func initEDB(ctx context.Context, conn *pgx.Conn) (err error) {
	if _, err = conn.Exec(ctx, initDDL); err != nil {
		return err
	}
	return
}
