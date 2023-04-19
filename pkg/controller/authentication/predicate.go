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

package authentication

import (
	osconfigv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"strings"
)

func ownedByAuthentication(obj client.Object) bool {
	ownerRefs := obj.GetOwnerReferences()
	if len(ownerRefs) > 0 &&
		ownerRefs[0].Kind == "Authentication" &&
		ownerRefs[0].APIVersion == "operator.ibm.com/v1alpha1" &&
		*ownerRefs[0].Controller {
		return true
	}
	return false
}

var OwnedByAuthentication predicate.Predicate = predicate.NewPredicateFuncs(ownedByAuthentication)

const OpenShiftClusterIngressName string = "cluster"

type ClusterIngressDomainChangedPredicate struct {
	predicate.Funcs
}

// Create, Delete, and Generic are explicitly returning false because this Predicate should only lead to enqueueing
// requests on update events on the
func (ClusterIngressDomainChangedPredicate) Create(e event.CreateEvent) bool {
	return false
}
func (ClusterIngressDomainChangedPredicate) Delete(e event.DeleteEvent) bool {
	return false
}
func (ClusterIngressDomainChangedPredicate) Generic(e event.GenericEvent) bool {
	return false
}

func (ClusterIngressDomainChangedPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil {
		log.Error(nil, "Update event has no old object to update", "event", e)
		return false
	}
	if e.ObjectNew == nil {
		log.Error(nil, "Update event has no new object to update", "event", e)
		return false
	}

	if e.ObjectOld.GetName() != OpenShiftClusterIngressName || e.ObjectNew.GetName() != OpenShiftClusterIngressName {
		return false
	}

	ingressCfgOld, ok := e.ObjectOld.(*osconfigv1.Ingress)
	if !ok {
		log.Error(nil, "Update event for ingress.config.openshift.io contained invalid old object", "event", e)
		return false
	}
	ingressCfgNew, ok := e.ObjectNew.(*osconfigv1.Ingress)
	if !ok {
		log.Error(nil, "Update event for ingress.config.openshift.io contained invalid new object", "event", e)
		return false
	}
	return ingressCfgOld.Spec.Domain != ingressCfgNew.Spec.Domain
}

var isIBMCPPConfig func(obj client.Object) bool = func(obj client.Object) bool {
	namespaces := strings.Split(os.Getenv("WATCH_NAMESPACE"), ",")
	return obj.GetName() == "ibm-cpp-config" && containsString(namespaces, obj.GetNamespace())
}

type CPPConfigDomainChangedPredicate struct {
	predicate.Funcs
}

func (CPPConfigDomainChangedPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil {
		log.Error(nil, "Update event has no old object to update", "event", e)
		return false
	}
	if e.ObjectNew == nil {
		log.Error(nil, "Update event has no new object to update", "event", e)
		return false
	}
	if !isIBMCPPConfig(e.ObjectNew) || !isIBMCPPConfig(e.ObjectOld) {
		return false
	}

	cmOld, ok := e.ObjectOld.(*corev1.ConfigMap)
	if !ok {
		log.Error(nil, "Update event for ConfigMap received a non-ConfigMap old object", "event", e)
		return false
	}

	cmNew, ok := e.ObjectNew.(*corev1.ConfigMap)
	if !ok {
		log.Error(nil, "Update event for ConfigMap received a non-ConfigMap new object", "event", e)
		return false
	}

	return cmOld.Data["domain_name"] != cmNew.Data["domain_name"]
}

func cppConfigPredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return isIBMCPPConfig(e.ObjectOld)
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return isIBMCPPConfig(e.Object)
		},
	}
}
