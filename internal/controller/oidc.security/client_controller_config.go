//
// Copyright 2022 IBM Corporation
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
//

package oidcsecurity

import (
	"context"
	"fmt"
	"strings"

	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Key interface {
	String() string
}

type SecretKey int

const (
	DefaultAdminUserKey SecretKey = iota
	DefaultAdminPasswordKey
	OAuthAdminPasswordKey
	TLSCertKey
)

func (s SecretKey) String() string {
	switch s {
	case DefaultAdminUserKey:
		return "admin_username"
	case DefaultAdminPasswordKey:
		return "admin_password"
	case OAuthAdminPasswordKey:
		return "OAUTH2_CLIENT_REGISTRATION_SECRET"
	case TLSCertKey:
		return corev1.TLSCertKey
	default:
		return "Unknown key"
	}
}

type ServiceURLKey int

const (
	AuthServiceURLKey ServiceURLKey = iota
	IdentityManagementURLKey
	IdentityProviderURLKey
)

func (s ServiceURLKey) String() string {
	switch s {
	case AuthServiceURLKey:
		return "BASE_OIDC_URL"
	case IdentityManagementURLKey:
		return "IDENTITY_MGMT_URL"
	case IdentityProviderURLKey:
		return "IDENTITY_PROVIDER_URL"
	default:
		return "Unknown Key"
	}
}

// DataKeyNotSetError is returned when a specific key is not available in the AuthenticationConfig
type DataKeyNotSetError struct {
	key       string
	kind      string
	name      string
	namespace string
}

func (e *DataKeyNotSetError) Error() string {
	return fmt.Sprintf("unable to retrieve value for key %s from %s %s in namespace %s", e.key, e.kind, e.name, e.namespace)
}

// DataNotSetError is returned when a specific key is not available in the AuthenticationConfig
type DataNotSetError struct {
	kind      string
	name      string
	namespace string
}

func (e *DataNotSetError) Error() string {
	return fmt.Sprintf("%s %s in namespace %s has no data set", e.kind, e.name, e.namespace)
}

func NewDataKeyNotSetError(obj client.Object, key string) (err error) {
	kind := obj.GetObjectKind().GroupVersionKind().Kind
	return &DataKeyNotSetError{
		key:       key,
		kind:      kind,
		name:      obj.GetName(),
		namespace: obj.GetNamespace(),
	}
}

func (e *DataKeyNotSetError) GetKey() string {
	return e.key
}

func (e *DataKeyNotSetError) GetName() string {
	return e.name
}

func (e *DataKeyNotSetError) GetNamespace() string {
	return e.namespace
}

func (e *DataKeyNotSetError) GetKind() string {
	return e.kind
}

var ConfigNotSetError error = fmt.Errorf("config is not set")

type InvalidResourceError struct {
	kind      string
	name      string
	namespace string
	reason    string
}

func (e *InvalidResourceError) Error() string {
	return fmt.Sprintf("%s %s in namespace %s is invalid: %s", e.kind, e.name, e.namespace, e.reason)
}

func NewInvalidResourceError(kind, name, namespace, reason string) (err error) {
	return &InvalidResourceError{
		kind:      kind,
		name:      name,
		namespace: namespace,
		reason:    reason,
	}
}

type CP2ServiceURLFormatError struct{}

func (e *CP2ServiceURLFormatError) Error() string {
	return "found ConfigMap service data with cp2 format : 127.0.0.1"
}

func NewCP2ServiceURLFormatError() (err error) {
	return &CP2ServiceURLFormatError{}
}

func mustGetValuesFromSecret(cl client.Client, ctx context.Context, objKey client.ObjectKey, keys ...Key) (values [][]byte, err error) {
	s := &corev1.Secret{}
	err = cl.Get(ctx, types.NamespacedName{Name: objKey.Name, Namespace: objKey.Namespace}, s)
	if err != nil {
		return
	} else if s.Data == nil {
		return nil, &DataNotSetError{}
	}
	defer func() {
		s.Data = nil
		s = nil
	}()
	values = [][]byte{}
	for _, key := range keys {
		if value, ok := s.Data[key.String()]; !ok || len(value) == 0 {
			return nil, NewDataKeyNotSetError(s, key.String())
		}
		values = append(values, s.Data[key.String()])
	}
	return
}

func mustGetValuesFromConfigMap(cl client.Client, ctx context.Context, objKey client.ObjectKey, keys ...Key) (values []string, err error) {
	c := &corev1.ConfigMap{}
	err = cl.Get(ctx, types.NamespacedName{Name: objKey.Name, Namespace: objKey.Namespace}, c)
	if err != nil {
		return
	} else if c.Data == nil {
		return nil, &DataNotSetError{}
	}
	defer func() {
		c.Data = nil
		c = nil
	}()
	values = []string{}
	for _, key := range keys {
		if value, ok := c.Data[key.String()]; !ok || len(value) == 0 {
			return nil, NewDataKeyNotSetError(c, key.String())
		}
		values = append(values, c.Data[key.String()])
	}
	return
}

func GetDefaultAdminCredentials(cl client.Client, ctx context.Context, namespace string) (username []byte, password []byte, err error) {
	objKey := types.NamespacedName{Name: PlatformAuthIDPCredentialsSecretName, Namespace: namespace}
	values, err := mustGetValuesFromSecret(cl, ctx, objKey, DefaultAdminUserKey, DefaultAdminPasswordKey)
	if err != nil {
		return
	}
	return values[0], values[1], nil
}

func GetOAuthAdminCredentials(cl client.Client, ctx context.Context, namespace string) (username, password []byte, err error) {
	username = []byte("oauthadmin")
	objKey := types.NamespacedName{Name: PlatformOIDCCredentialsSecretName, Namespace: namespace}
	values, err := mustGetValuesFromSecret(cl, ctx, objKey, OAuthAdminPasswordKey)
	if err != nil {
		return
	}
	return []byte("oauthadmin"), values[0], nil
}

func GetCommonServiceCATLSKey(cl client.Client, ctx context.Context, namespace string) (key []byte, err error) {
	objKey := types.NamespacedName{Name: CSCACertificateSecretName, Namespace: namespace}
	values, err := mustGetValuesFromSecret(cl, ctx, objKey, TLSCertKey)
	if err != nil {
		return
	}
	return values[0], nil
}

// getClusterDomainNameForServiceURL converts the provided URL string from just a Service name to "<service
// name>.<namespace>.svc"
func getClusterDomainNameForServiceURL(url string, namespace string) string {
	suffix := ".svc"
	splitByColons := strings.Split(url, ":")
	port := splitByColons[len(splitByColons)-1]
	everythingBeforePort := strings.Join(splitByColons[:len(splitByColons)-1], ":")
	return everythingBeforePort + "." + namespace + suffix + ":" + port
}

func (r *ClientReconciler) getServiceURL(ctx context.Context, namespace string, key ServiceURLKey) (value string, err error) {
	objKey := types.NamespacedName{Name: PlatformAuthIDPConfigMapName, Namespace: namespace}
	values, err := mustGetValuesFromConfigMap(r.Client, ctx, objKey, key)
	if err != nil {
		return
	}
	if r.RunMode == common.LocalRunMode {
		return values[0], nil
	}
	if strings.Contains(values[0], "127.0.0.1") {
		return "", NewCP2ServiceURLFormatError()
	}
	return getClusterDomainNameForServiceURL(values[0], namespace), nil
}
