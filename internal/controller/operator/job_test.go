//
// Copyright 2026 IBM Corporation
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

package operator

import (
	"context"
	"reflect"

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/api/oidc.security/v1"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// jobSecondary is a minimal SecondaryReconciler used only in job generate-function
// tests. It satisfies the full interface with no-op stubs for methods not
// exercised by the generate functions under test.
type jobSecondary struct {
	name      string
	namespace string
	authCR    *operatorv1alpha1.Authentication
	client.Client
}

func (j jobSecondary) GetEmptyObject() client.Object {
	rType := reflect.TypeFor[*batchv1.Job]().Elem()
	return reflect.New(rType).Interface().(*batchv1.Job)
}
func (j jobSecondary) GetKind() string                                   { return "Job" }
func (j jobSecondary) GetName() string                                   { return j.name }
func (j jobSecondary) GetNamespace() string                              { return j.namespace }
func (j jobSecondary) GetPrimary() client.Object                         { return j.authCR }
func (j jobSecondary) GetClient() client.Client                          { return j.Client }
func (j jobSecondary) Reconcile(context.Context) (*ctrl.Result, error)   { return nil, nil }
func (j jobSecondary) Generate(_ context.Context, _ client.Object) error { return nil }
func (j jobSecondary) Modify(_ context.Context, _, _ client.Object) (bool, error) {
	return false, nil
}
func (j jobSecondary) OnWrite(context.Context) error                          { return nil }
func (j jobSecondary) OnFinished(_ context.Context, _, _ client.Object) error { return nil }

// newJobSecondary builds a jobSecondary backed by a fake client that has all
// types needed by generateJobObject and generateMigratorJobObject registered.
func newJobSecondary(name string, authCR *operatorv1alpha1.Authentication) jobSecondary {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = batchv1.AddToScheme(s)
	_ = operatorv1alpha1.AddToScheme(s)
	_ = oidcsecurityv1.AddToScheme(s)
	cl := fakeclient.NewClientBuilder().WithScheme(s).WithObjects(authCR).Build()
	return jobSecondary{
		name:      name,
		namespace: authCR.Namespace,
		authCR:    authCR,
		Client:    cl,
	}
}

// builtInJobTolerations are the two tolerations hard-coded into every Job pod
// spec by generateJobObject and generateMigratorJobObject.
var builtInJobTolerations = []corev1.Toleration{
	{Key: "dedicated", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	{Key: "CriticalAddonsOnly", Operator: corev1.TolerationOpExists},
}

var _ = Describe("Job handling", func() {
	var ctx context.Context
	var authCR *operatorv1alpha1.Authentication
	var customToleration corev1.Toleration

	BeforeEach(func() {
		ctx = context.Background()
		customToleration = corev1.Toleration{
			Key:      "custom-taint",
			Operator: corev1.TolerationOpEqual,
			Value:    "custom-value",
			Effect:   corev1.TaintEffectNoSchedule,
		}
		authCR = &operatorv1alpha1.Authentication{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "operator.ibm.com/v1alpha1",
				Kind:       "Authentication",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "example-authentication",
				Namespace:       "data-ns",
				ResourceVersion: trackerAddResourceVersion,
			},
			Spec: operatorv1alpha1.AuthenticationSpec{
				OperatorVersion: "4.0.0",
				Replicas:        1,
				Config:          operatorv1alpha1.ConfigSpec{},
			},
		}
	})

	DescribeTable("generateJobObject propagates NodeSelector and Tolerations from the Authentication CR",
		func(nodeSelector map[string]string, tolerations []corev1.Toleration) {
			authCR.Spec.NodeSelector = nodeSelector
			authCR.Spec.Tolerations = tolerations
			s := newJobSecondary("ibm-iam-operator", authCR)
			job := &batchv1.Job{}
			err := generateJobObject(s, ctx, job)
			Expect(err).NotTo(HaveOccurred())

			// NodeSelector: cloned onto pod spec only when non-empty
			if len(nodeSelector) > 0 {
				Expect(job.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))
			} else {
				Expect(job.Spec.Template.Spec.NodeSelector).To(BeNil())
			}

			// Built-in tolerations are always present
			Expect(job.Spec.Template.Spec.Tolerations).To(ContainElements(builtInJobTolerations))

			// Custom tolerations are appended after the built-ins
			for _, t := range tolerations {
				Expect(job.Spec.Template.Spec.Tolerations).To(ContainElement(t))
			}
		},
		Entry("sets nodeSelector and appends custom toleration when both are specified",
			map[string]string{"node-role.kubernetes.io/worker": "true"},
			[]corev1.Toleration{customToleration},
		),
		Entry("leaves nodeSelector nil and keeps only built-in tolerations when neither field is set",
			map[string]string(nil),
			[]corev1.Toleration(nil),
		),
	)

	DescribeTable("generateMigratorJobObject propagates NodeSelector and Tolerations from the Authentication CR",
		func(nodeSelector map[string]string, tolerations []corev1.Toleration) {
			authCR.Spec.NodeSelector = nodeSelector
			authCR.Spec.Tolerations = tolerations
			s := newJobSecondary(MigrationJobName, authCR)
			job := &batchv1.Job{}
			err := generateMigratorJobObject(s, ctx, job)
			Expect(err).NotTo(HaveOccurred())

			// NodeSelector: cloned onto pod spec only when non-empty
			if len(nodeSelector) > 0 {
				Expect(job.Spec.Template.Spec.NodeSelector).To(Equal(nodeSelector))
			} else {
				Expect(job.Spec.Template.Spec.NodeSelector).To(BeNil())
			}

			// Built-in tolerations are always present
			Expect(job.Spec.Template.Spec.Tolerations).To(ContainElements(builtInJobTolerations))

			// Custom tolerations are appended after the built-ins
			for _, t := range tolerations {
				Expect(job.Spec.Template.Spec.Tolerations).To(ContainElement(t))
			}
		},
		Entry("sets nodeSelector and appends custom toleration when both are specified",
			map[string]string{"node-role.kubernetes.io/worker": "true"},
			[]corev1.Toleration{customToleration},
		),
		Entry("leaves nodeSelector nil and keeps only built-in tolerations when neither field is set",
			map[string]string(nil),
			[]corev1.Toleration(nil),
		),
	)
})
