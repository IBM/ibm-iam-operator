package migration

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

type DBOption func(*DBOptions) error

type DBOptions struct {
	Name      string
	Port      string
	User      string
	Password  string
	Host      string
	TLSConfig *tls.Config
	Schemas   []string
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
