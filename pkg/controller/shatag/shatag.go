//
// Copyright 2020 IBM Corporation
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

package shatag

import (
	"os"
	"strings"
)



func GetImageRef(envVar string ) string{

	var imageSuffix string
	imageTagOrSHA := os.Getenv(envVar)
	if strings.HasPrefix(imageTagOrSHA, "sha256:") {
		imageSuffix = "@" + imageTagOrSHA
	} else {		
		imageSuffix = ":" + imageTagOrSHA
	}

	return imageSuffix
}
 
func ValidateImageFormat(image string) string {
	tagIndex := strings.Index(image, ":")
	shaIndex := strings.Index(image, "@")
	
	if string(image[tagIndex - 1]) == "/" {
		return image[:tagIndex-1] + "" + image[tagIndex:]
	} else if string(image[shaIndex - 1]) == "/" {
		return image[:shaIndex-1] + "" + image[shaIndex:]
	}	
	return image
}