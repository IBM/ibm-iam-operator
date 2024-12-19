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
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

type DBOption func(*DBOptions) error

// DBOptions repesent a series of details about a given database instance
type DBOptions struct {
	Name      string      // the name of the database used in a DSN
	ID        string      // the identifier used for logs, recording migration activity, etc.
	Port      string      // the port used to connect to
	User      string      // the user to authenticate as
	Password  string      // the password to authenticate with
	Host      string      // the database hostname/URL
	TLSConfig *tls.Config // the certificates used to authenticate with
	Schemas   []string    // a list of schema names
}

// GetMigrationKey returns a key name used for writing back successful migration state to some other database
func (o *DBOptions) GetMigrationKey() string {
	return fmt.Sprintf("migrated_to_%s", o.ID)
}

func (o *DBOptions) Configure(opts ...DBOption) (err error) {
	for _, option := range opts {
		if err = option(o); err != nil {
			return
		}
	}
	return
}

func TLSConfig(caCert, clientCert, clientKey []byte) DBOption {
	return func(c *DBOptions) (err error) {
		if c == nil {
			return
		}
		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return fmt.Errorf("failed to add CA certificate to cert pool")
		}
		var clientCertificate tls.Certificate
		if clientCertificate, err = tls.X509KeyPair(clientCert, clientKey); err != nil {
			return err
		}
		tlsConfig := &tls.Config{
			RootCAs:            caCertPool,
			Certificates:       []tls.Certificate{clientCertificate},
			InsecureSkipVerify: true,
		}
		c.TLSConfig = tlsConfig
		return
	}
}

func Name(name string) DBOption {
	return func(c *DBOptions) (err error) {
		if c != nil {
			c.Name = name
		}
		return
	}
}

func ID(id string) DBOption {
	return func(c *DBOptions) (err error) {
		if c != nil {
			c.ID = id
		}
		return
	}
}

func Port(port string) DBOption {
	return func(c *DBOptions) (err error) {
		if c != nil {
			c.Port = port
		}
		return
	}
}

func User(user string) DBOption {
	return func(c *DBOptions) (err error) {
		if c != nil {
			c.User = user
		}
		return
	}
}

func Password(password string) DBOption {
	return func(c *DBOptions) (err error) {
		if c != nil {
			c.Password = password
		}
		return
	}
}

func Host(host string) DBOption {
	return func(c *DBOptions) (err error) {
		if c != nil {
			c.Host = host
		}
		return
	}
}

func Schemas(schemas ...string) DBOption {
	return func(c *DBOptions) (err error) {
		if c == nil {
			return
		}
		if len(c.Schemas) == 0 {
			c.Schemas = []string{}
		}
		c.Schemas = append(c.Schemas, schemas...)
		return
	}
}
