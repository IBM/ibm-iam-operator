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
	"github.com/jackc/pgx/v5/pgconn"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

//go:embed v1.sql
var initDDL string

// TODO Add any helpful properties
type Result struct {
	Error    error
	Migrated bool
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

	result := initEDB(logf.IntoContext(ctx, reqLogger), config)

	if result.Error != nil {
		reqLogger.Error(result.Error, "Failed to migrate")
	} else {
		reqLogger.Info("Migration completed", "result", result)
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

// initEDB executes the DDL that initializes the schemas and tables that the different IM Operands will use.
func initEDB(ctx context.Context, config *DatastoreConfig) (result *Result) {
	reqLogger := logf.FromContext(ctx)
	result = &Result{}
	dsn := fmt.Sprintf("host=%s user=%s dbname=%s port=%s sslmode=require", config.RWEndpoint, config.User, config.Name, config.Port)

	var err error
	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(config.CACert)
	var clientCert tls.Certificate
	if clientCert, err = tls.X509KeyPair(config.ClientCert, config.ClientKey); err != nil {
		reqLogger.Error(err, "Failed to assemble client key pair")
		return &Result{Error: err}
	}
	reqLogger.Info("Assembled client key pair")

	var connConfig *pgx.ConnConfig
	if connConfig, err = pgx.ParseConfig(dsn); err != nil {
		reqLogger.Error(err, "Failed to parse database configuration")
		return &Result{Error: err}
	}
	reqLogger.Info("Connection to DB configured")

	connConfig.TLSConfig = &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            rootCertPool,
		InsecureSkipVerify: true,
	}

	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var imConn *pgx.Conn
	if imConn, err = pgx.ConnectConfig(queryCtx, connConfig); err != nil {
		reqLogger.Error(err, "Failed to connect to database")
		return &Result{Error: err}
	}
	reqLogger.Info("Connected to DB")

	var commandTag pgconn.CommandTag
	if commandTag, err = imConn.Exec(queryCtx, initDDL); err != nil {
		reqLogger.Error(err, "Failed to execute DDL")
		return &Result{Error: err}
	}
	reqLogger.Info("Executed DDL", "commandTag", commandTag.String())
	result.Migrated = true

	return
}
