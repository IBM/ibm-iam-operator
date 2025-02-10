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

package database

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"time"

	dbconn "github.com/IBM/ibm-iam-operator/database/connectors"
	"github.com/IBM/ibm-iam-operator/database/migration"
	v1schema "github.com/IBM/ibm-iam-operator/database/schema/v1"
	"github.com/IBM/ibm-iam-operator/version"
	"github.com/jackc/pgx/v5/pgtype"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// PlanMigrations produces a priority queue of Migrations to perform based upon the database connections that have been
// provided.
func PlanMigrations(ctx context.Context, to, from dbconn.DBConn) (mq *migration.MigrationQueue, err error) {
	reqLogger := logf.FromContext(ctx)
	var postgres *dbconn.PostgresDB
	var mongo *dbconn.MongoDB
	if to == nil {
		return nil, fmt.Errorf("to should be an instance of Postgres")
	}
	postgres, ok := to.(*dbconn.PostgresDB)
	if !ok {
		return nil, fmt.Errorf("to should be an instance of Postgres")
	}

	// For the time being, the assumption is that, if data is being copied from one DB to another, the source is
	// MongoDB; if that should change, this needs to change.
	if from != nil {
		mongo, ok = from.(*dbconn.MongoDB)
		if !ok {
			return nil, fmt.Errorf("from should be an instance of MongoDB")
		}
	}
	mq = &migration.MigrationQueue{}
	*mq = make(migration.MigrationQueue, 0)

	reqLogger.Info("Retrieving change logs")
	// CreateMetadataSchema needs to be checked for and run a little differently from the others because, without
	// it, all attempts to log future schema changes will fail due to the schema/table for that not existing yet.
	changelogs, err := v1schema.GetChangelogs(ctx, postgres)
	if errors.Is(err, v1schema.ErrTableDoesNotExist) {
		err = nil
		reqLogger.Info("Table metadata.changelog not present; adding migration", "migrationName", v1schema.CreateMetadataSchema.Name)
		*mq = append(*mq, migration.FromMigration(v1schema.CreateMetadataSchema).
			To(to).
			Build())
	} else if err != nil {
		return nil, fmt.Errorf("failed to retrieve changelogs: %w", err)
	}

	if _, ok := changelogs[v1schema.InitOperandSchemas.ID]; !ok {
		reqLogger.Info("Adding migration", "migrationName", v1schema.InitOperandSchemas.Name)
		*mq = append(*mq, migration.FromMigration(v1schema.InitOperandSchemas).
			To(to).
			Build())
	}

	if _, ok := changelogs[v1schema.IncreaseOIDCUsernameSize.ID]; !ok {
		reqLogger.Info("Adding migration", "migrationName", v1schema.IncreaseOIDCUsernameSize.Name)
		*mq = append(*mq, migration.FromMigration(v1schema.IncreaseOIDCUsernameSize).
			To(to).
			Build())
	}

	if _, ok := changelogs[v1schema.IncreaseTokenstringSize.ID]; !ok {
		reqLogger.Info("Adding migration", "migrationName", v1schema.IncreaseTokenstringSize.Name)
		*mq = append(*mq, migration.FromMigration(v1schema.IncreaseTokenstringSize).
			To(to).
			Build())
	}

	if _, ok := changelogs[v1schema.AlterUsersAttributesUniqueAndCascadeDeleteConstraint.ID]; !ok {
		reqLogger.Info("Adding migration", "migrationName", v1schema.AlterUsersAttributesUniqueAndCascadeDeleteConstraint.Name)
		*mq = append(*mq, migration.FromMigration(v1schema.AlterUsersAttributesUniqueAndCascadeDeleteConstraint).
			To(to).
			Build())
	}

	if _, ok := changelogs[v1schema.MongoToEDBv1.ID]; !ok && mongo != nil {
		reqLogger.Info("Adding migration", "migrationName", v1schema.MongoToEDBv1.Name)
		*mq = append(*mq, migration.FromMigration(v1schema.MongoToEDBv1).
			To(to).
			From(from).
			Build())
	}
	mq.UpdatePrioritiesByDependencyCount()
	heap.Init(mq)

	return
}

// Migrate initializes the EDB database for the IM Operands and performs any additional migrations that may be needed.
func Migrate(ctx context.Context, c chan *migration.Result, migrations *migration.MigrationQueue) {
	reqLogger := logf.FromContext(ctx).WithName("migration_worker")

	migrationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	migrationCtx = logf.IntoContext(migrationCtx, reqLogger)

	var err error
	result := &migration.Result{}

	for _, m := range *migrations {
		if len(result.Incomplete) > 0 {
			result.Incomplete = append(result.Incomplete, m)
			continue
		}
		if err = m.Run(migrationCtx); err != nil {
			result.Error = fmt.Errorf("failure occurred during %s: %w", m.Name, err)
			result.Incomplete = append(result.Incomplete, m)
			continue
		}
		tstz := pgtype.Timestamptz{
			Time:  time.Now(),
			Valid: true,
		}
		c := &v1schema.Changelog{
			ID:          m.ID,
			Name:        m.Name,
			IMVersion:   version.Version,
			InstallTime: &tstz,
		}
		_, err = m.To.LogChanges(migrationCtx, c.GetInsertSQL(), v1schema.GetNamedArgsFromRow(c))
		if err != nil {
			result.Error = fmt.Errorf("failure occurred during logging of migration %s: %w", m.Name, err)
			result.Incomplete = append(result.Incomplete, m)
			continue
		} else {
			reqLogger.Info("Completed migration", "migrationName", m.Name)
		}
		result.Complete = append(result.Complete, m)
	}

	c <- result
	close(c)
}
