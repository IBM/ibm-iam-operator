package testing

import (
	"context"
	"time"

	. "github.com/onsi/gomega"
	"github.com/opdev/subreconciler"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func ConfirmThatItRequeuesWithError(result *ctrl.Result, err error) {
	Expect(result).ToNot(BeNil())
	Expect(result.Requeue).To(BeTrue())
	Expect(result.RequeueAfter).To(BeZero())
	Expect(err).To(HaveOccurred())
	Expect(subreconciler.ShouldContinue(result, err)).To(BeFalse())
	Expect(subreconciler.ShouldRequeue(result, err)).To(BeTrue())
	Expect(subreconciler.ShouldHaltOrRequeue(result, err)).To(BeTrue())
}

func ConfirmThatItRequeuesWithDelay(result *ctrl.Result, err error, expectedDelay time.Duration) {
	Expect(result).ToNot(BeNil())
	Expect(result.Requeue).To(BeTrue())
	Expect(result.RequeueAfter).To(Equal(expectedDelay))
	Expect(err).ToNot(HaveOccurred())
	Expect(subreconciler.ShouldContinue(result, err)).To(BeFalse())
	Expect(subreconciler.ShouldRequeue(result, err)).To(BeTrue())
	Expect(subreconciler.ShouldHaltOrRequeue(result, err)).To(BeTrue())
}

func ConfirmThatItContinuesReconciling(result *ctrl.Result, err error) {
	Expect(result).To(BeNil())
	Expect(err).ToNot(HaveOccurred())
	Expect(subreconciler.ShouldContinue(result, err)).To(BeTrue())
	Expect(subreconciler.ShouldRequeue(result, err)).To(BeFalse())
	Expect(subreconciler.ShouldHaltOrRequeue(result, err)).To(BeFalse())
}

type FakeTimeoutClient struct {
	client.Client
	goodCalls int
}

func (f *FakeTimeoutClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if f.goodCalls > 0 {
		f.goodCalls--
		return f.Client.Get(ctx, key, obj, opts...)
	}
	return k8sErrors.NewTimeoutError("dummy error", 500)
}

func (f *FakeTimeoutClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if f.goodCalls > 0 {
		f.goodCalls--
		return f.Client.Update(ctx, obj, opts...)
	}
	return k8sErrors.NewTimeoutError("dummy error", 500)
}

func (f *FakeTimeoutClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if f.goodCalls > 0 {
		f.goodCalls--
		return f.Client.Create(ctx, obj, opts...)
	}
	return k8sErrors.NewTimeoutError("dummy error", 500)
}

func (f *FakeTimeoutClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if f.goodCalls > 0 {
		f.goodCalls--
		return f.Client.Delete(ctx, obj, opts...)
	}
	return k8sErrors.NewTimeoutError("dummy error", 500)
}

var _ client.Client = &FakeTimeoutClient{}
