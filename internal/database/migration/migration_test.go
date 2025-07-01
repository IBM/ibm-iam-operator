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

package migration

import (
	"container/heap"

	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "MigrationQueue Suite")
}

var _ = Describe("MigrationQueue", func() {
	var (
		A *Migration
		B *Migration
		C *Migration
		D *Migration
		E *Migration
		F *Migration
		G *Migration
		H *Migration
		I *Migration
		J *Migration
	)
	BeforeEach(func() {
		A = NewMigration().Name("A").Build()
		B = NewMigration().Name("B").Dependencies([]*Migration{A}).Build()
		C = NewMigration().Name("C").Dependencies([]*Migration{B}).Build()
		D = NewMigration().Name("D").Dependencies([]*Migration{B}).Build()
		E = NewMigration().Name("E").Dependencies([]*Migration{A, D}).Build()
		F = NewMigration().Name("F").Dependencies([]*Migration{E}).Build()
		G = NewMigration().Name("G").Dependencies([]*Migration{A, E, C}).Build()

		// Circular dependencies
		H = NewMigration().Name("H").Dependencies([]*Migration{J}).Build()
		I = NewMigration().Name("I").Dependencies([]*Migration{H}).Build()
		J = NewMigration().Name("J").Dependencies([]*Migration{I}).Build()

	})
	DescribeTable("updatePrioritiesByDependencyCount",
		func(mSliceFunc func() []*Migration) {
			mq := make(MigrationQueue, 0)
			heap.Init(&mq)
			mSlice := mSliceFunc()
			for _, m := range mSlice {
				heap.Push(&mq, m)
			}
			mq.UpdatePrioritiesByDependencyCount()
			previousItems := make([]*Migration, 0)
			for mq.Len() > 0 {
				Expect(mq[0].index).Should(BeNumerically(">", -1))
				current := heap.Pop(&mq).(*Migration)
				Expect(current.index).Should(BeNumerically("==", -1))
				for _, d := range current.Dependencies {
					Expect(d.priority).Should(BeNumerically(">", current.priority))
				}
				previousItems = append(previousItems, current)
			}
			for i := range previousItems {
				if i == 0 {
					continue
				}
				Expect(previousItems[i].priority).Should(BeNumerically("<=", previousItems[i-1].priority))
			}
		},
		Entry("Single Migration with no dependencies", func() []*Migration { return []*Migration{A} }),
		Entry("One Migration depending on the other should lead to dependency being first and with higher priority", func() []*Migration { return []*Migration{A, B} }),
		Entry("One Migration depending on the other should lead to dependency being first and with higher priority, even if the initial order is inverted", func() []*Migration { return []*Migration{B, A} }),
		Entry("Multiple Migrations dependent upon another should still assign higher priorities to Migrations with more dependents", func() []*Migration { return []*Migration{A, B, C, D, E, F, G} }),
	)
})
