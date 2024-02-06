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
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"time"
)

// TODO Remove this
var countdown int = 10

// TODO Add any helpful properties
type Result struct{}

// TODO Add EDB config struct as an addiitonal argument
func Migrate(ctx context.Context, c chan *Result, caCert, clientCert, clientKey []byte) {
	reqLogger := logf.FromContext(ctx).WithName("migration_worker")

	// TODO Replace with migration implementation
	for countdown > 0 {
		reqLogger.Info("Countdown", "count", countdown)
		time.Sleep(1 * time.Second)
		countdown--
	}

	reqLogger.Info("Migration completed")
	c <- &Result{}
	close(c)
}

//import (
//	"gorm.io/gorm"
//	"gorm.io/driver/postgres"
//)
//
//func initEDB() {
//	host := ""
//	port := ""
//	user := ""
//	dbname := ""
//	sslrootcert := ""
//	sslkey := ""
//	sslcert := ""
//
//	dsn := ``
//	postgres.New(postgres.Config{})
//}
