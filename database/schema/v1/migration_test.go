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

package v1

import (
	"container/heap"

	"github.com/IBM/ibm-iam-operator/database/migration"
	"github.com/jackc/pgx/v5/pgtype"

	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Migration", func() {
	Describe("removeInvalidUserPreferences", func() {
		var userPrefs []UserPreferences
		Context("When no LastLogin set on UserPreferences", func() {
			BeforeEach(func() {
				userPrefs = []UserPreferences{{}}
			})
			It("filters out that entry (empty struct)", func() {
				filtered := removeInvalidUserPreferences(userPrefs)
				Expect(len(filtered)).To(Equal(0))
			})
			It("filters out that entry (partially-filled struct)", func() {
				userPrefs = append(userPrefs, UserPreferences{
					UserUID:    "some-id",
					LoginCount: 0,
					LastLogout: &pgtype.Timestamptz{
						Time: time.Now(),
					},
				})
				filtered := removeInvalidUserPreferences(userPrefs)
				Expect(len(filtered)).To(Equal(0))
			})
		})

		Context("When a LastLogin set on UserPreferences", func() {
			BeforeEach(func() {
				userPrefs = []UserPreferences{
					{
						LastLogin: &pgtype.Timestamptz{
							Time: time.Now(),
						},
					},
				}
			})

			It("retains that entry", func() {
				filtered := removeInvalidUserPreferences(userPrefs)
				Expect(len(filtered)).To(Equal(1))
			})
		})
	})
})

var _ = DescribeTable("xorDecode",
	func(encoded, decoded string, shouldError bool) {
		value, err := xorDecode(encoded)
		Expect(value).To(Equal(decoded))
		if shouldError {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).ToNot(HaveOccurred())
		}
	},
	Entry("Returns the decoded string when it has the prefix", "{xor}LDo8LTor", "secret", false),
	Entry("Returns the decoded string when it does not have the prefix", "LDo8LTor", "secret", false),
	Entry("Returns an empty string when argument is empty", "", "", false),
	Entry("Returns error when input has malformed prefix", "{{xor}", "", true),
	Entry("Returns error when input with prefix is not valid base64", "{xor}&#&(*asdbasdf", "", true),
	Entry("Returns error when input without prefix is not valid base64", "&#&(*asdbasdf", "", true),
)

var _ = Describe("MigrationQueue", func() {
	DescribeTable("UpdatePrioritiesByDependencyCount",
		func(mSliceFunc func() []*migration.Migration, orderedNames []string) {
			mq := make(migration.MigrationQueue, 0)
			heap.Init(&mq)
			mSlice := mSliceFunc()
			for _, m := range mSlice {
				heap.Push(&mq, m)
			}
			mq.UpdatePrioritiesByDependencyCount()
			i := 0
			for mq.Len() > 0 {
				current := heap.Pop(&mq).(*migration.Migration)
				Expect(current.Name).Should(Equal(orderedNames[i]))
				i++
			}
		},
		Entry("InitOperandSchemas alone",
			func() []*migration.Migration {
				return []*migration.Migration{
					InitOperandSchemas,
				}
			}, []string{InitOperandSchemas.Name}),
		Entry("InitOperandSchemas and IncreaseOIDCUsernameSize",
			func() []*migration.Migration {
				return []*migration.Migration{
					IncreaseOIDCUsernameSize,
					InitOperandSchemas,
				}
			}, []string{InitOperandSchemas.Name, IncreaseOIDCUsernameSize.Name}),
		Entry("InitOperandSchemas, IncreaseOIDCUsernameSize, CreateMetadataSchema, and MongoToEDBv1",
			func() []*migration.Migration {
				return []*migration.Migration{
					IncreaseOIDCUsernameSize,
					MongoToEDBv1,
					InitOperandSchemas,
					CreateMetadataSchema,
				}
			}, []string{CreateMetadataSchema.Name, InitOperandSchemas.Name, IncreaseOIDCUsernameSize.Name, MongoToEDBv1.Name}),
	)
})
