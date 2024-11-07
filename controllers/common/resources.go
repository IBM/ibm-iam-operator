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

package common

import (
	"regexp"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var CsConfigAnnotationSuffix = "common-service/config"
var CsDefaultNamespace = "ibm-common-services"

// GetCsConfigAnnotation returns '<namespace>.common-service/config' annotation name for given namespace
func GetCsConfigAnnotation(namespace string) string {
	if len(namespace) == 0 {
		return CsDefaultNamespace + "." + CsConfigAnnotationSuffix
	}

	return namespace + "." + CsConfigAnnotationSuffix
}

// IsCsConfigAnnotationExists checks if '<namespace>.common-service/config' annotation name exists in the given annotations map or not
func IsCsConfigAnnotationExists(annotations map[string]string) bool {
	if len(annotations) == 0 {
		return false
	}
	csAnnotationFound := false
	reg, _ := regexp.Compile(`^(.*)\.common-service\/config`)
	for anno := range annotations {
		if reg.MatchString(anno) {
			csAnnotationFound = true
			break
		}
	}
	if csAnnotationFound {
		return true
	}
	return false
}

func isOwnerOf(owner client.Object, ownerRef v1.OwnerReference) (isOwner bool) {
	ownerGVK := owner.GetObjectKind().GroupVersionKind()
	if ownerRef.Kind == ownerGVK.Kind && ownerRef.UID == owner.GetUID() && ownerRef.Name == owner.GetName() && ownerRef.APIVersion == ownerGVK.GroupVersion().String() {
		return true
	}
	return
}

func isControllerOf(controller client.Object, ownerRef v1.OwnerReference) (isController bool) {
	if isOwnerOf(controller, ownerRef) && *ownerRef.Controller {
		return true
	}
	return
}

// IsOwnerOf determines whether one object is listed in another object's OwnerReferences.
func IsOwnerOf(owner, owned client.Object) (isOwner bool) {
	ownerRefs := owned.GetOwnerReferences()
	if len(ownerRefs) == 0 {
		return
	}
	for _, ownerRef := range ownerRefs {
		if isOwnerOf(owner, ownerRef) {
			return true
		}
	}
	return
}

// IsControllerOf determines whether one object is listed as the controller of another object within its
// OwnerReferences.
func IsControllerOf(controller, controlled client.Object) (isController bool) {
	ownerRefs := controlled.GetOwnerReferences()
	if len(ownerRefs) == 0 {
		return
	}
	for _, ownerRef := range ownerRefs {
		if isControllerOf(controller, ownerRef) {
			return true
		}
	}
	return
}

func GetControllerKind(controlled client.Object) (kind string) {
	index := GetControllerRefIndex(controlled)
	if index == -1 {
		return
	}
	return controlled.GetOwnerReferences()[index].Kind
}

func GetControllerRefIndex(controlled client.Object) (index int) {
	index = -1
	ownerRefs := controlled.GetOwnerReferences()
	if len(ownerRefs) == 0 {
		return
	}

	for i, ownerRef := range ownerRefs {
		if *ownerRef.Controller {
			return i
		}
	}
	return
}
