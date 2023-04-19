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

package client

import (
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func newCSCACertSecretPredicate(namespace string) predicate.Predicate {
	isCSCACertSecret := func(obj client.Object) bool {
		if obj.GetName() != CSCACertificateSecretName {
			return false
		}
		if obj.GetNamespace() != namespace {
			return false
		}
		secret, ok := obj.(*corev1.Secret)
		if !ok {
			return false
		}
		return secret.Type == corev1.SecretTypeTLS
	}
	return predicate.NewPredicateFuncs(isCSCACertSecret)
}

func newNameFilterFunc(name string) func(obj client.Object) bool {
	return func(obj client.Object) bool {
		return obj.GetName() == name
	}
}

func newNamespacesPredicate(namespaces ...string) predicate.Predicate {
	if len(namespaces) == 0 {
		return nil
	}

	nsPredicates := []predicate.Predicate{}
	for _, namespace := range namespaces {
		nsPredicate := predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				return false
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return newNameFilterFunc(namespace)(e.Object)
			},
			GenericFunc: func(e event.GenericEvent) bool {
				return false
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				return false
			},
		}
		nsPredicates = append(nsPredicates, nsPredicate)
	}
	return predicate.Or(nsPredicates...)
}

var PlatformAuthIDPCredentialsPredicate predicate.Predicate = predicate.NewPredicateFuncs(
	newNameFilterFunc(PlatformAuthIDPCredentialsSecretName))

var PlatformOIDCCredentialsPredicate predicate.Predicate = predicate.NewPredicateFuncs(
	newNameFilterFunc(PlatformOIDCCredentialsSecretName))

var PlatformAuthIDPPredicate predicate.Predicate = predicate.NewPredicateFuncs(
	newNameFilterFunc(PlatformAuthIDPConfigMapName))

func isOwnedByClient(obj client.Object) bool {
	ownerRefs := obj.GetOwnerReferences()
	if len(ownerRefs) > 0 &&
		ownerRefs[0].Kind == "Client" &&
		ownerRefs[0].APIVersion == "oidc.security.ibm.com/v1" &&
		*ownerRefs[0].Controller {
		return true
	}
	return false
}

var OwnedByClientPredicate predicate.Predicate = predicate.NewPredicateFuncs(isOwnedByClient)
