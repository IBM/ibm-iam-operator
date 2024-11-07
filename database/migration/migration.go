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
	"container/heap"
	"context"
	"fmt"

	dbconn "github.com/IBM/ibm-iam-operator/database/connectors"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type Result struct {
	Complete   []*Migration
	Incomplete []*Migration

	Error error
}

func has(a []*Migration, m *Migration) bool {
	for _, item := range a {
		if item == m {
			return true
		}
	}
	return false
}

func (r *Result) IsMarkedComplete(m *Migration) bool {
	return has(r.Complete, m)
}

func (r *Result) IsMarkedIncomplete(m *Migration) bool {
	return has(r.Incomplete, m)
}

func (r *Result) IsFailure() bool {
	return r.Error != nil && len(r.Incomplete) > 0
}

func (r *Result) IsSuccess() bool {
	return !r.IsFailure()
}

// Migration represents some sort of transformation or transfer of data from one database to another.
type Migration struct {
	Name         string         // name of the migration registered in the changelog
	ID           int            // integer used as a unique identifier for the migration
	To           dbconn.DBConn  // connection to database where data is being moved to or transformed on
	From         dbconn.DBConn  // connection to database where data is coming from
	Dependencies []*Migration   // migrations that must be performed before this one
	priority     int            // priority of migration; used by MigrationQueue
	index        int            // index of item in MigrationQueue; maintained by heap.Interface
	RunFunc      *MigrationFunc // function containing migration logic
}

type MigrationBuilder struct {
	Migration *Migration
}

func NewMigration() *MigrationBuilder {
	return FromMigration(&Migration{index: -1})
}

func FromMigration(m *Migration) *MigrationBuilder {
	return &MigrationBuilder{
		Migration: m,
	}
}

func (m *MigrationBuilder) Build() *Migration {
	return m.Migration
}

func (m *MigrationBuilder) Name(name string) *MigrationBuilder {
	m.Migration.Name = name
	return m
}

func (m *MigrationBuilder) ID(id int) *MigrationBuilder {
	m.Migration.ID = id
	return m
}

func (m *MigrationBuilder) Dependencies(d []*Migration) *MigrationBuilder {
	m.Migration.Dependencies = d
	return m
}

func (m *MigrationBuilder) To(to dbconn.DBConn) *MigrationBuilder {
	m.Migration.To = to
	return m
}

func (m *MigrationBuilder) From(from dbconn.DBConn) *MigrationBuilder {
	m.Migration.From = from
	return m
}

type MigrationFunc func(context.Context, dbconn.DBConn, dbconn.DBConn) error

func (m *MigrationBuilder) RunFunc(f *MigrationFunc) *MigrationBuilder {
	m.Migration.RunFunc = f
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
	return (*m.RunFunc)(ctx, m.To, m.From)
}

// MigrationQueue is a priority queue for Migrations. It pops off Migrations in decreasing order of priority.
// Implementation based upon example from documentation for container/heap.
type MigrationQueue []*Migration

var _ heap.Interface = &MigrationQueue{}

func (mq MigrationQueue) Len() int { return len(mq) }

func (mq MigrationQueue) Less(i, j int) bool {
	return mq[i].priority > mq[j].priority
}

func (mq MigrationQueue) Swap(i, j int) {
	mq[i], mq[j] = mq[j], mq[i]
	mq[i].index = i
	mq[j].index = j
}

func (mq *MigrationQueue) Push(x any) {
	n := len(*mq)
	m := x.(*Migration)
	m.index = n
	*mq = append(*mq, x.(*Migration))
}

func (mq *MigrationQueue) Pop() any {
	old := *mq
	n := len(old)
	m := old[n-1]
	old[n-1] = nil
	m.index = -1
	*mq = old[0 : n-1]
	return m
}

func (mq *MigrationQueue) update(m *Migration, priority int) {
	newPriority := 1 << priority
	if m.priority < newPriority {
		m.priority = newPriority
		heap.Fix(mq, m.index)
		for _, d := range m.Dependencies {
			mq.update(d, priority+1)
		}
	}
}

// UpdatePrioritiesByDependencyCount updates the priority values of Migrations in the MigrationQueue to 2^(h-1), where h
// is the max distance from another Migration in terms of dependencies.
// For example, consider the following chain of dependencies:
//
//	A <- depends - B <- depends - C <- depends - D
//
// `A` would have a priority of 8 (2^3), `B` would have 4, `C` would have 2, and `D` would have 1.
//
// A Migration that is childless and has no dependencies retains the default priority of 0.
func (mq *MigrationQueue) UpdatePrioritiesByDependencyCount() {
	for _, m := range *mq {
		if len(m.Dependencies) > 0 {
			mq.update(m, 0)
		}
	}
}

// PlanMigrations produces a priority queue of Migrations to perform based upon the database connections that have been
// provided.
func PlanMigrations(ctx context.Context, to, from dbconn.DBConn) (mq *MigrationQueue, err error) {
	return
}

// Migrate initializes the EDB database for the IM Operands and performs any additional migrations that may be needed.
func Migrate(ctx context.Context, c chan *Result, to, from dbconn.DBConn) {
	reqLogger := logf.FromContext(ctx).WithName("migration_worker")

	migrationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	migrationCtx = logf.IntoContext(migrationCtx, reqLogger)

	var err error
	result := &Result{}
	postgres, ok := to.(*dbconn.PostgresDB)
	if !ok {
		err = fmt.Errorf("to database should be an instance of Postgres")
		result.Error = err
		c <- result
		close(c)
		return
	}

	mongo, ok := from.(*dbconn.MongoDB)
	if to != nil && !ok {
		err = fmt.Errorf("from database should be an instance of MongoDB")
		result.Error = err
		c <- result
		close(c)
		return
	}

	migrations, err := PlanMigrations(migrationCtx, postgres, mongo)
	if err != nil {
		err = fmt.Errorf("failed to form a migration plan: %w", err)
		result.Error = err
		c <- result
		close(c)
		return
	}

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
		result.Complete = append(result.Complete, m)
	}

	c <- result
	close(c)
}
