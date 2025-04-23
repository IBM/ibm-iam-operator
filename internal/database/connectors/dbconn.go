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

package connectors

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.mongodb.org/mongo-driver/mongo"
	mongoOptions "go.mongodb.org/mongo-driver/mongo/options"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type DBConn interface {
	Connect(context.Context) error
	Configure(...DBOption) error
	RunDDL(context.Context, string) error
	HasSchemas(context.Context) (bool, error)
	Disconnect(context.Context) error
	LogChanges(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type PostgresDB struct {
	*DBOptions
	Conn *pgx.Conn
}

// LogChanges
func (p *PostgresDB) LogChanges(ctx context.Context, query string, args ...any) (tag pgconn.CommandTag, err error) {
	if p.Conn.IsClosed() {
		p.Connect(ctx)
		defer p.Disconnect(ctx)
	}

	return p.Conn.Exec(ctx, query, args...)
}

// LogChanges is a stub so that MongoDB can satisfy DBConn
func (m *MongoDB) LogChanges(ctx context.Context, query string, args ...any) (tag pgconn.CommandTag, err error) {
	return pgconn.CommandTag{}, fmt.Errorf("no changelog defined for MongoDB")
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

	reqLogger.Info("Schemas to find", "schemas", p.Schemas)
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

	reqLogger.Info("Found schemas", "schemas", foundSchemas)
	for _, present := range foundSchemas {
		if !present {
			return false, nil
		}
	}

	return true, nil
}
func (p *PostgresDB) HasMetadataSchema(ctx context.Context) (has bool, err error) {
	query := "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'metadata'"
	var table string
	err = p.Conn.QueryRow(ctx, query).Scan(&table)
	has = table != ""
	return
}

func (p *PostgresDB) GetInstalledSchemaVersion(ctx context.Context) (version string, err error) {
	query := "SELECT schema_version FROM metadata.changelog ORDER BY install_time DESC LIMIT 1;"
	err = p.Conn.QueryRow(ctx, query).Scan(&version)
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
