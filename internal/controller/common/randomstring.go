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

package common

import (
	"math/rand"
	"time"

	regen "github.com/zach-klippenstein/goregen"
)

// GenerateRandomString generates a random string based upon a string that is a valid regex pattern.
func GenerateRandomString(rule string) string {

	generator, _ := regen.NewGenerator(rule, &regen.GeneratorArgs{
		RngSource:               rand.NewSource(time.Now().UnixNano()),
		MaxUnboundedRepeatCount: 1})
	randomString := generator.Generate()
	return randomString
}
