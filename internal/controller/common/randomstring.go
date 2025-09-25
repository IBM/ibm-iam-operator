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
	"crypto/rand"
	"math/big"
)

const (
	AlphaNum      string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	LowerAlphaNum string = "abcdefghijklmnopqrstuvwxyz0123456789"
)

type ByteGenerator interface {
	GenerateBytes(charset string, n int) (b []byte, err error)
}

type RandomByteGenerator struct{}

func (g *RandomByteGenerator) GenerateBytes(charset string, n int) (b []byte, err error) {
	return generateRandomBytes(charset, n)
}

func generateRandomBytes(charset string, n int) (b []byte, err error) {
	b = make([]byte, n)
	for i := range n {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return nil, err
		}
		b[i] = charset[num.Int64()]
	}
	return
}
