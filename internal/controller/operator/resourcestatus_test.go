// Assisted by watsonx Code Assistant

package operator

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	routev1 "github.com/openshift/api/route/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("AuthenticationReconciler", func() {
	var (
		r   *AuthenticationReconciler
		ctx context.Context
	)

	getReconciler := func() *AuthenticationReconciler {
		scheme := runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
		Expect(batchv1.AddToScheme(scheme)).To(Succeed())
		Expect(routev1.AddToScheme(scheme)).To(Succeed())
		authCR := &operatorv1alpha1.Authentication{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "operator.ibm.com/v1alpha1",
				Kind:       "Authentication",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "example-authentication",
				Namespace:       "data-ns",
				ResourceVersion: trackerAddResourceVersion,
			},
		}
		cb := *fakeclient.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(authCR.DeepCopy())
		cl := cb.Build()
		dc, err := discovery.NewDiscoveryClientForConfig(cfg)
		Expect(err).NotTo(HaveOccurred())

		r = &AuthenticationReconciler{
			Client: &ctrlcommon.FallbackClient{
				Client: cl,
				Reader: cl,
			},
			DiscoveryClient: *dc,
		}
		return r
	}

	addNodePods := func(cl client.Client, ctx context.Context, ns string) {
		appNames := []string{"platform-auth-service", "platform-identity-management", "platform-identity-provider"}
		for i := range appNames {
			for _, appName := range appNames {
				po := &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      fmt.Sprintf("%s-%d", appName, i%len(appNames)),
						Namespace: ns,
						Labels: map[string]string{
							"k8s-app": appName,
						},
					},
				}
				Expect(cl.Create(ctx, po)).To(Succeed())
			}
		}
	}

	addJob := func(cl client.Client, ctx context.Context, ns string, replace bool) {
		job := &batchv1.Job{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Job",
				APIVersion: "batch/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      MigrationJobName,
				Namespace: ns,
			},
		}
		if replace {
			Expect(cl.Delete(ctx, job.DeepCopy())).To(Succeed())
		}
		Expect(cl.Create(ctx, job)).To(Succeed())
	}

	addCompletedJob := func(cl client.Client, ctx context.Context, ns string) {
		now := metav1.NewTime(time.Now())
		job := &batchv1.Job{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Job",
				APIVersion: "batch/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      MigrationJobName,
				Namespace: ns,
			},
			Status: batchv1.JobStatus{
				CompletionTime: &now,
			},
		}
		Expect(cl.Create(ctx, job)).To(Succeed())
	}

	addFailedJob := func(cl client.Client, ctx context.Context, ns string, complete bool, backoffLimit *int32) {
		job := &batchv1.Job{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Job",
				APIVersion: "batch/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      MigrationJobName,
				Namespace: ns,
			},
			Spec:   batchv1.JobSpec{},
			Status: batchv1.JobStatus{},
		}
		if backoffLimit != nil {
			job.Spec.BackoffLimit = backoffLimit
		}
		if complete && backoffLimit != nil {
			job.Status.Failed = *backoffLimit
		} else if complete {
			job.Status.Failed = 6
		} else {
			job.Status.Failed = 1
		}
		Expect(cl.Create(ctx, job)).To(Succeed())
	}

	Context("setAuthenticationStatus", func() {
		It("should update the status when nodes change", func() {
			r := getReconciler()
			ctx = context.Background()
			addNodePods(r.Client, ctx, "data-ns")
			addJob(r.Client, ctx, "data-ns", false)
			authCR := &operatorv1alpha1.Authentication{}
			Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())
			modified, err := r.setAuthenticationStatus(ctx, authCR)
			Expect(err).NotTo(HaveOccurred())
			Expect(modified).To(BeTrue())
			Expect(authCR.Status.Nodes).To(Equal([]string{
				"platform-auth-service-0",
				"platform-auth-service-1",
				"platform-auth-service-2",
				"platform-identity-management-0",
				"platform-identity-management-1",
				"platform-identity-management-2",
				"platform-identity-provider-0",
				"platform-identity-provider-1",
				"platform-identity-provider-2",
			}))
		})

		It("should not update the status when nodes do not change", func() {
			r := getReconciler()
			ctx = context.Background()
			authCR := &operatorv1alpha1.Authentication{}
			Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())
			modified, err := r.setAuthenticationStatus(ctx, authCR)
			Expect(err).NotTo(HaveOccurred())
			Expect(modified).To(BeTrue())
			Expect(authCR.Status.Nodes).To(Equal([]string{}))
		})
	})

	Context("setMigrationStatusConditions", func() {
		It("should set conditions when job is completed", func() {
			r := getReconciler()
			ctx = context.Background()
			addCompletedJob(r.Client, ctx, "data-ns")
			authCR := &operatorv1alpha1.Authentication{}
			Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())
			Expect(r.setMigrationStatusConditions(ctx, authCR)).To(Succeed())
			Expect(len(authCR.Status.Conditions)).To(Equal(2))
			By("setting MigrationsPerformed status to True and reason to ReasonMigrationComplete")
			migratedCondition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrated)
			Expect(migratedCondition).ToNot(BeNil())
			Expect(migratedCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(migratedCondition.Reason).To(Equal(operatorv1alpha1.ReasonMigrationComplete))
			By("setting MigrationsRunning status to False and reason to ReasonMigrationsDone")
			runningCondition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrationsRunning)
			Expect(runningCondition).ToNot(BeNil())
			Expect(runningCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(runningCondition.Reason).To(Equal(operatorv1alpha1.ReasonMigrationsDone))
		})

		It("should set conditions when job is running and conditions are not set", func() {
			r := getReconciler()
			ctx = context.Background()
			addJob(r.Client, ctx, "data-ns", false)
			authCR := &operatorv1alpha1.Authentication{}
			Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())
			Expect(r.setMigrationStatusConditions(ctx, authCR)).To(Succeed())
			Expect(len(authCR.Status.Conditions)).To(Equal(2))
			By("setting MigrationsPerformed status to False and reason to ReasonMigrationsInProgress")
			migratedCondition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrated)
			Expect(migratedCondition).ToNot(BeNil())
			Expect(migratedCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(migratedCondition.Reason).To(Equal(operatorv1alpha1.ReasonMigrationsInProgress))
			By("setting MigrationsRunning status to True and reason to ReasonMigrationsInProgress")
			runningCondition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrationsRunning)
			Expect(runningCondition).ToNot(BeNil())
			Expect(runningCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(runningCondition.Reason).To(Equal(operatorv1alpha1.ReasonMigrationsInProgress))
		})

		It("should set conditions when job is running again after a previous success", func() {
			r := getReconciler()
			ctx = context.Background()
			addCompletedJob(r.Client, ctx, "data-ns")
			authCR := &operatorv1alpha1.Authentication{}
			Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())
			Expect(r.setMigrationStatusConditions(ctx, authCR)).To(Succeed())
			Expect(len(authCR.Status.Conditions)).To(Equal(2))
			By("setting MigrationsPerformed status to True and reason to ReasonMigrationComplete")
			migratedCondition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrated)
			Expect(migratedCondition).ToNot(BeNil())
			Expect(migratedCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(migratedCondition.Reason).To(Equal(operatorv1alpha1.ReasonMigrationComplete))
			By("setting MigrationsRunning status to False and reason to ReasonMigrationsDone")
			runningCondition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrationsRunning)
			Expect(runningCondition).ToNot(BeNil())
			Expect(runningCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(runningCondition.Reason).To(Equal(operatorv1alpha1.ReasonMigrationsDone))
			By("replacing the completed Job with a new Job")
			addJob(r.Client, ctx, "data-ns", true)
			Expect(r.setMigrationStatusConditions(ctx, authCR)).To(Succeed())
			Expect(len(authCR.Status.Conditions)).To(Equal(2))
			By("setting MigrationsPerformed status to False and reason to ReasonMigrationsInProgress")
			migratedConditionUpdate := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrated)
			Expect(migratedConditionUpdate).ToNot(BeNil())
			Expect(migratedConditionUpdate.Status).To(Equal(metav1.ConditionFalse))
			Expect(migratedConditionUpdate.Reason).To(Equal(operatorv1alpha1.ReasonMigrationsInProgress))
			By("setting MigrationsRunning status to True and reason to ReasonMigrationsInProgress")
			runningConditionUpdate := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrationsRunning)
			Expect(runningConditionUpdate).ToNot(BeNil())
			Expect(runningConditionUpdate.Status).To(Equal(metav1.ConditionTrue))
			Expect(runningConditionUpdate.Reason).To(Equal(operatorv1alpha1.ReasonMigrationsInProgress))
		})

		It("should preserve conditions when job is running again after a previous, incomplete failure", func() {
			r := getReconciler()
			ctx = context.Background()
			addFailedJob(r.Client, ctx, "data-ns", false, nil)
			authCR := &operatorv1alpha1.Authentication{}
			Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())
			Expect(r.setMigrationStatusConditions(ctx, authCR)).To(Succeed())
			Expect(len(authCR.Status.Conditions)).To(Equal(2))
			By("setting MigrationsPerformed status to False and reason to ReasonMigrationFailure")
			migratedCondition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrated)
			Expect(migratedCondition).ToNot(BeNil())
			Expect(migratedCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(migratedCondition.Reason).To(Equal(operatorv1alpha1.ReasonMigrationFailure))
			By("setting MigrationsRunning status to True and reason to ReasonMigrationsInProgress")
			runningCondition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrationsRunning)
			Expect(runningCondition).ToNot(BeNil())
			Expect(runningCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(runningCondition.Reason).To(Equal(operatorv1alpha1.ReasonMigrationsInProgress))
			By("replacing the incompletely failed Job with a new Job")
			addJob(r.Client, ctx, "data-ns", true)
			Expect(r.setMigrationStatusConditions(ctx, authCR)).To(Succeed())
			Expect(len(authCR.Status.Conditions)).To(Equal(2))
			By("not changing MigrationsPerformed status or reason")
			migratedConditionUpdate := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrated)
			Expect(migratedConditionUpdate).ToNot(BeNil())
			Expect(migratedConditionUpdate.Status).To(Equal(metav1.ConditionFalse))
			Expect(migratedConditionUpdate.Reason).To(Equal(operatorv1alpha1.ReasonMigrationFailure))
			By("not changing MigrationsRunning status or reason")
			runningConditionUpdate := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrationsRunning)
			Expect(runningConditionUpdate).ToNot(BeNil())
			Expect(runningConditionUpdate.Status).To(Equal(metav1.ConditionTrue))
			Expect(runningConditionUpdate.Reason).To(Equal(operatorv1alpha1.ReasonMigrationsInProgress))
		})

		It("should preserve ReasonMigrationFailure reason when job is running again after a previous, complete failure", func() {
			r := getReconciler()
			ctx = context.Background()
			addFailedJob(r.Client, ctx, "data-ns", true, nil)
			authCR := &operatorv1alpha1.Authentication{}
			Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())
			Expect(r.setMigrationStatusConditions(ctx, authCR)).To(Succeed())
			Expect(len(authCR.Status.Conditions)).To(Equal(2))
			By("setting MigrationsPerformed status to False and reason to ReasonMigrationFailure")
			migratedCondition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrated)
			Expect(migratedCondition).ToNot(BeNil())
			Expect(migratedCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(migratedCondition.Reason).To(Equal(operatorv1alpha1.ReasonMigrationFailure))
			By("setting MigrationsRunning status to False and reason to ReasonMigrationsDone")
			runningCondition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrationsRunning)
			Expect(runningCondition).ToNot(BeNil())
			Expect(runningCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(runningCondition.Reason).To(Equal(operatorv1alpha1.ReasonMigrationsDone))
			By("replacing the completely failed Job with a new Job")
			addJob(r.Client, ctx, "data-ns", true)
			Expect(r.setMigrationStatusConditions(ctx, authCR)).To(Succeed())
			Expect(len(authCR.Status.Conditions)).To(Equal(2))
			By("not changing MigrationsPerformed status or reason")
			migratedConditionUpdate := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrated)
			Expect(migratedConditionUpdate).ToNot(BeNil())
			Expect(migratedConditionUpdate.Status).To(Equal(metav1.ConditionFalse))
			Expect(migratedConditionUpdate.Reason).To(Equal(operatorv1alpha1.ReasonMigrationFailure))
			By("setting MigrationsRunning status to True and reason to ReasonMigrationsInProgress")
			runningConditionUpdate := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrationsRunning)
			Expect(runningConditionUpdate).ToNot(BeNil())
			Expect(runningConditionUpdate.Status).To(Equal(metav1.ConditionTrue))
			Expect(runningConditionUpdate.Reason).To(Equal(operatorv1alpha1.ReasonMigrationsInProgress))
		})
	})

	Context("getNodesStatus", func() {
		It("should return a sorted list of IM Pod names", func() {
			_ = []corev1.Pod{
				{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"k8s-app": "platform-auth-service"}}},
				{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"k8s-app": "platform-identity-management"}}},
				{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"k8s-app": "platform-identity-provider"}}},
			}
		})
	})

	Context("getCurrentServiceStatus", func() {
		It("should return ResourceNotReadyState if any resource is not ready", func() {
		})

		It("should return ResourceReadyState if all resources are ready", func() {
		})
	})
})
