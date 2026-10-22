/*
Copyright 2026 IBM Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package operator

import (
	"context"
	"errors"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
)

// applyOperationStatus is exercised pass by pass, as a reconcile uses it: the
// dependency checks see the CR as fetched at the start of the pass; the status
// step then sets the service status the pass computed, applies, and the result
// is stored only if the simulated status write succeeds.
var _ = Describe("applyOperationStatus", func() {
	var (
		r       *AuthenticationReconciler
		stored  *operatorv1alpha1.Authentication
		key     types.NamespacedName
		created metav1.Time
		now     time.Time
	)

	type pass struct {
		ctx      context.Context
		fetched  *operatorv1alpha1.Authentication // as the dependency checks see it
		observed *operatorv1alpha1.Authentication // as the status step computes it
		previous string
	}

	// newPass starts a pass that reached checkpoint reached (nil for none) and
	// computed serviceStatus.
	newPass := func(reached *checkpoint, serviceStatus string) *pass {
		ctx := withPassProgress(logf.IntoContext(context.Background(), zap.New(zap.UseDevMode(true))))
		if reached != nil {
			reachCheckpoint(ctx, *reached)
		}
		p := &pass{ctx: ctx, fetched: stored.DeepCopy(), observed: stored.DeepCopy(), previous: stored.Status.Service.Status}
		p.observed.Status.Service.Status = serviceStatus
		return p
	}

	// apply runs applyOperationStatus and, if writeSucceeds, stores the result
	// and calls onPersisted.
	apply := func(p *pass, writeSucceeds bool) (modified bool) {
		now = now.Add(time.Minute)
		modified, onPersisted := r.applyOperationStatus(p.ctx, p.observed, p.previous, now)
		if writeSucceeds {
			stored = p.observed
			onPersisted()
		}
		return modified
	}

	cp := func(c checkpoint) *checkpoint { return &c }

	BeforeEach(func() {
		r = &AuthenticationReconciler{Recorder: record.NewFakeRecorder(100)}
		created = metav1.NewTime(time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC))
		stored = &operatorv1alpha1.Authentication{
			ObjectMeta: metav1.ObjectMeta{Name: "example-authentication", Namespace: "test-ns", CreationTimestamp: created},
		}
		key = client.ObjectKeyFromObject(stored)
		now = time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	})

	It("tracks a fresh install from 0% to one completed timing entry", func() {
		p := newPass(cp(progressCheckpoints.DBRequested), ResourceNotReadyState)
		r.dependencyWaiting(p.ctx, p.fetched, embeddedDBDependency)
		Expect(apply(p, true)).To(BeTrue())
		Expect(stored.Status.Progress).To(Equal("20%"))
		Expect(stored.Status.ProgressMessage).To(Equal(progressCheckpoints.DBRequested.msg))

		p = newPass(cp(progressCheckpoints.RoutesHPAsDone), ResourceNotReadyState)
		r.dependencyReady(p.ctx, p.fetched, embeddedDBDependency)
		apply(p, true)
		Expect(stored.Status.Progress).To(Equal("95%"))
		Expect(stored.Status.OperationTiming).To(BeEmpty(), "not Ready yet")

		apply(newPass(cp(progressCheckpoints.RoutesHPAsDone), ResourceReadyState), true)
		Expect(stored.Status.Progress).To(Equal("100%"))
		Expect(stored.Status.ReconcileHistory).To(HaveExactElements(HaveSuffix(reconcileSuccessMessage)))
		Expect(stored.Status.OperationTiming).To(HaveExactElements(And(
			HaveField("StartTime", created),
			HaveField("DependencyTime", HaveExactElements(HaveField("Component", embeddedDBDependency))),
		)))
		Expect(r.operations).NotTo(HaveKey(key))
	})

	It("records an operation that waited on no dependency with an empty dependency list", func() {
		stored.Status.Service.Status = ResourceReadyState
		stored.Status.Progress = "100%"
		stored.Status.ProgressMessage = progressCheckpoints.Complete.msg

		apply(newPass(cp(progressCheckpoints.MigrationDone), ResourceNotReadyState), true)
		apply(newPass(cp(progressCheckpoints.RoutesHPAsDone), ResourceReadyState), true)

		Expect(stored.Status.OperationTiming).To(HaveLen(1))
		Expect(stored.Status.OperationTiming[0].DependencyTime).To(BeEmpty())
	})

	It("restarts progress when a completed CR stops being Ready", func() {
		stored.Status.Service.Status = ResourceReadyState
		stored.Status.Progress = "100%"

		apply(newPass(cp(progressCheckpoints.MigrationDone), ResourceNotReadyState), true)
		Expect(stored.Status.Progress).To(Equal("55%"))
		Expect(stored.Status.ProgressMessage).To(Equal(progressCheckpoints.MigrationDone.msg))
	})

	It("reports no change while waiting at the same checkpoint, so status is not rewritten", func() {
		apply(newPass(cp(progressCheckpoints.DBRequested), ResourceNotReadyState), true)
		Expect(apply(newPass(cp(progressCheckpoints.DBRequested), ResourceNotReadyState), true)).To(BeFalse())
	})

	It("reports no change on a steady-state pass of a Ready CR", func() {
		stored.Status.Service.Status = ResourceReadyState
		stored.Status.Progress = "100%"
		stored.Status.ProgressMessage = progressCheckpoints.Complete.msg

		Expect(apply(newPass(cp(progressCheckpoints.RoutesHPAsDone), ResourceReadyState), true)).To(BeFalse())
		Expect(stored.Status.ReconcileHistory).To(BeEmpty())
	})

	It("completes a Ready CR created before these fields existed, once", func() {
		stored.Status.Service.Status = ResourceReadyState

		Expect(apply(newPass(nil, ResourceReadyState), true)).To(BeTrue())
		Expect(stored.Status.Progress).To(Equal("100%"))
		Expect(apply(newPass(nil, ResourceReadyState), true)).To(BeFalse())
		Expect(stored.Status.ReconcileHistory).To(HaveLen(1))
	})

	It("keeps the operation when the status write fails and records it on the retry", func() {
		p := newPass(cp(progressCheckpoints.DBRequested), ResourceNotReadyState)
		r.dependencyWaiting(p.ctx, p.fetched, embeddedDBDependency)
		apply(p, true)
		p = newPass(cp(progressCheckpoints.RoutesHPAsDone), ResourceNotReadyState)
		r.dependencyReady(p.ctx, p.fetched, embeddedDBDependency)
		apply(p, true)
		op := r.operations[key]

		apply(newPass(cp(progressCheckpoints.RoutesHPAsDone), ResourceReadyState), false)
		Expect(r.operations[key]).To(BeIdenticalTo(op), "a failed write must not lose the operation")
		Expect(stored.Status.OperationTiming).To(BeEmpty())

		apply(newPass(cp(progressCheckpoints.RoutesHPAsDone), ResourceReadyState), true)
		Expect(stored.Status.OperationTiming).To(HaveExactElements(HaveField("StartTime", op.start)))
		Expect(r.operations).NotTo(HaveKey(key))
	})

	Describe("after a recorded failure", func() {
		BeforeEach(func() {
			stored.Status.Service.Status = ResourceReadyState
			stored.Status.Progress = "100%"
			stored.Status.ProgressMessage = progressCheckpoints.Complete.msg
			stored.Status.ReconcileHistory = []string{"2026-09-29T09:30:00Z " + reconcileFailurePrefix + "boom"}
		})

		It("records nothing while passes still stop early", func() {
			Expect(apply(newPass(cp(progressCheckpoints.OIDCDone), ResourceReadyState), true)).To(BeFalse())
			Expect(stored.Status.ReconcileHistory).To(HaveLen(1))
		})

		It("records success on the first complete pass, once", func() {
			Expect(apply(newPass(cp(progressCheckpoints.RoutesHPAsDone), ResourceReadyState), true)).To(BeTrue())
			Expect(stored.Status.ReconcileHistory[0]).To(HaveSuffix(reconcileSuccessMessage))

			Expect(apply(newPass(cp(progressCheckpoints.RoutesHPAsDone), ResourceReadyState), true)).To(BeFalse())
			Expect(stored.Status.ReconcileHistory).To(HaveLen(2))
		})
	})
})

var _ = Describe("recordReconcileFailure", func() {
	var (
		ctx           context.Context
		r             *AuthenticationReconciler
		cl            client.Client
		req           ctrl.Request
		statusUpdates int
	)

	storedHistory := func() []string {
		authCR := &operatorv1alpha1.Authentication{}
		Expect(cl.Get(ctx, req.NamespacedName, authCR)).To(Succeed())
		return authCR.Status.ReconcileHistory
	}

	BeforeEach(func() {
		ctx = logf.IntoContext(context.Background(), zap.New(zap.UseDevMode(true)))
		authCR := &operatorv1alpha1.Authentication{
			ObjectMeta: metav1.ObjectMeta{Name: "example-authentication", Namespace: "test-ns"},
		}
		scheme := runtime.NewScheme()
		Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
		statusUpdates = 0
		cl = fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(authCR).
			WithStatusSubresource(authCR).
			WithInterceptorFuncs(interceptor.Funcs{
				SubResourceUpdate: func(ctx context.Context, c client.Client, subResource string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
					statusUpdates++
					return c.SubResource(subResource).Update(ctx, obj, opts...)
				},
			}).
			Build()
		r = &AuthenticationReconciler{Client: cl}
		req = ctrl.Request{NamespacedName: client.ObjectKeyFromObject(authCR)}
	})

	It("writes the failure to the stored CR's history", func() {
		r.recordReconcileFailure(ctx, req, errors.New("deployment update failed"))
		Expect(storedHistory()).To(HaveExactElements(HaveSuffix(reconcileFailurePrefix + "deployment update failed")))
	})

	It("does not write the status again for a repeat of the latest failure", func() {
		r.recordReconcileFailure(ctx, req, errors.New("deployment update failed"))
		r.recordReconcileFailure(ctx, req, errors.New("deployment update failed"))

		Expect(storedHistory()).To(HaveLen(1))
		Expect(statusUpdates).To(Equal(1))
	})

	It("does nothing when the CR no longer exists", func() {
		gone := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "test-ns", Name: "gone"}}
		r.recordReconcileFailure(ctx, gone, errors.New("x"))
		Expect(statusUpdates).To(BeZero())
	})
})

var _ = Describe("onlyConflicts", func() {
	conflict := func() error {
		return k8sErrors.NewConflict(schema.GroupResource{Group: "operator.ibm.com", Resource: "authentications"}, "example-authentication", errors.New("modified"))
	}

	DescribeTable("decides whether a pass error is only update conflicts",
		func(err error, expected bool) {
			Expect(onlyConflicts(err)).To(Equal(expected))
		},
		Entry("a conflict", conflict(), true),
		Entry("a wrapped conflict", fmt.Errorf("update status: %w", conflict()), true),
		Entry("joined conflicts", errors.Join(conflict(), conflict()), true),
		Entry("a conflict joined with a real failure", errors.Join(conflict(), errors.New("boom")), false),
		Entry("a real failure", errors.New("boom"), false),
	)
})

// The Authentication CRD is maintained by hand, so check against the envtest
// API server that the status fields are accepted, stored and validated.
var _ = Describe("Authentication CRD status schema", func() {
	var (
		ctx    context.Context
		authCR *operatorv1alpha1.Authentication
	)

	BeforeEach(func() {
		ctx = context.Background()
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "status-schema-"}}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, ns)).To(Succeed()) })

		authCR = &operatorv1alpha1.Authentication{
			ObjectMeta: metav1.ObjectMeta{Name: "example-authentication", Namespace: ns.Name},
		}
		Expect(k8sClient.Create(ctx, authCR)).To(Succeed())
	})

	It("stores progress, reconcileHistory and operationTiming, with and without dependencies", func() {
		start := metav1.NewTime(time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC))
		end := metav1.NewTime(start.Add(12 * time.Minute))
		authCR.Status = operatorv1alpha1.AuthenticationStatus{
			Nodes:            []string{},
			Progress:         "100%",
			ProgressMessage:  progressCheckpoints.Complete.msg,
			ReconcileHistory: []string{"2026-09-29T10:12:00Z " + reconcileSuccessMessage},
			OperationTiming: []operatorv1alpha1.OperationTimingEntry{
				{StartTime: start, EndTime: end, TotalDuration: "12m0s", Phase: operationPhaseCompleted},
				{StartTime: start, EndTime: end, TotalDuration: "12m0s", Phase: operationPhaseCompleted,
					DependencyTime: []operatorv1alpha1.DependencyTime{{
						Component: embeddedDBDependency, StartTime: start, ReadyTime: end, DependencyDuration: "12m0s",
					}}},
			},
		}
		want := authCR.Status.DeepCopy()
		Expect(k8sClient.Status().Update(ctx, authCR)).To(Succeed())

		stored := &operatorv1alpha1.Authentication{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(authCR), stored)).To(Succeed())
		Expect(stored.Status.Progress).To(Equal(want.Progress))
		Expect(stored.Status.ProgressMessage).To(Equal(want.ProgressMessage))
		Expect(stored.Status.ReconcileHistory).To(Equal(want.ReconcileHistory))
		Expect(stored.Status.OperationTiming).To(HaveLen(2))
		Expect(stored.Status.OperationTiming[0].DependencyTime).To(BeEmpty())
		Expect(stored.Status.OperationTiming[1].DependencyTime).To(HaveExactElements(And(
			HaveField("Component", embeddedDBDependency),
			HaveField("DependencyDuration", "12m0s"),
		)))
	})

	It("rejects an operationTiming entry missing a required field", func() {
		patch := []byte(`{"status":{"nodes":[],"operationTiming":[{"startTime":"2026-09-29T10:00:00Z","endTime":"2026-09-29T10:01:00Z","totalDuration":"1m0s"}]}}`)
		err := k8sClient.Status().Patch(ctx, authCR, client.RawPatch(types.MergePatchType, patch))
		Expect(k8sErrors.IsInvalid(err)).To(BeTrue(), "got %v", err)
	})
})
