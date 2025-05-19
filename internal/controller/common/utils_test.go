//
// Copyright 2025 IBM Corporation
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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("objectTable", func() {
	var cb fakeclient.ClientBuilder
	var cl client.WithWatch
	var scheme *runtime.Scheme
	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		cb = *fakeclient.NewClientBuilder().
			WithScheme(scheme)
		cl = cb.Build()
	})
	// Reminder: closures necessary if using Before* with DescribeTable
	DescribeTable("GetEmptyObject",
		func(build func() Secondary, obj client.Object) {
			s := build()
			o := s.GetEmptyObject()
			Expect(o).To(Equal(obj))
			Expect(o).ToNot(BeNil())
		},
		Entry("*corev1.Secret", func() Secondary { return NewSecondaryReconcilerBuilder[*corev1.Secret]().WithClient(cl).MustBuild() }, &corev1.Secret{}))
})
