//
// Copyright 2021 IBM Corporation
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

package resources

import (
	"regexp"
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

func IsOAuthAnnotationExists(annotations map[string]string) bool {
	if len(annotations) == 0 {
		return false
	}
	csOauthAnnotationFound := false
	reg, _ := regexp.Compile(`^(.*)\/oauth-redirectreference`)
	for anno := range annotations {
		if reg.MatchString(anno) {
			csOauthAnnotationFound = true
			break
		}
	}
	if csOauthAnnotationFound {
		return true
	}
	return false
}
