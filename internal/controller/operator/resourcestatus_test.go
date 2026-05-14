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

package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	discovery "k8s.io/client-go/discovery"
	restclient "k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("ResourceStatus", func() {
	var (
		r   *AuthenticationReconciler
		ctx context.Context
	)

	getFakeServerForDiscovery := func() *httptest.Server {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var obj interface{}
			switch req.URL.Path {
			case "/api":
				obj = &metav1.APIVersions{
					Versions: []string{
						"v1",
					},
				}
			case "/apis":
				obj = &metav1.APIGroupList{
					Groups: []metav1.APIGroup{
						{
							Name: "route.openshift.io",
							Versions: []metav1.GroupVersionForDiscovery{
								{GroupVersion: "route.openshift.io/v1", Version: "v1"},
							},
						},
						{
							Name: "operator.ibm.com",
							Versions: []metav1.GroupVersionForDiscovery{
								{GroupVersion: "operator.ibm.com/v3", Version: "v3"},
								{GroupVersion: "operator.ibm.com/v1", Version: "v1"},
								{GroupVersion: "operator.ibm.com/v1alpha1", Version: "v1alpha1"},
							},
							PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: "operator.ibm.com/v3", Version: "v3"},
						},
					},
				}
			case "/apis/operator.ibm.com/v1alpha1":
				obj = &metav1.APIResourceList{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
					},
					GroupVersion: "operator.ibm.com/v1alpha1",
					APIResources: []metav1.APIResource{
						{
							Name:         "operandrequests",
							SingularName: "operandrequest",
							Namespaced:   true,
							Kind:         "OperandRequest",
							Verbs:        metav1.Verbs{"delete", "deletecollection", "get", "list", "patch", "create", "updated", "watch"},
							ShortNames:   []string{"opreq"},
						},
						{
							Name:       "operandrequests/status",
							Namespaced: true,
							Kind:       "OperandRequest",
							Verbs:      metav1.Verbs{"get", "patch", "update"},
						},
					},
				}
			case "/apis/route.openshift.io/v1":
				obj = &metav1.APIResourceList{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
					},
					GroupVersion: "route.openshift.io/v1",
					APIResources: []metav1.APIResource{
						{
							Name:         "routes",
							SingularName: "route",
							Namespaced:   true,
							Kind:         "Route",
							Verbs:        metav1.Verbs{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"},
							Categories:   []string{"all"},
						},
						{
							Name:         "routes/status",
							SingularName: "",
							Namespaced:   true,
							Kind:         "Route",
							Verbs:        metav1.Verbs{"get", "patch", "update"},
							Categories:   []string{"all"},
						},
					},
				}
			default:
				w.WriteHeader(http.StatusNotFound)
				return
			}
			output, err := json.Marshal(obj)
			Expect(err).ToNot(HaveOccurred())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(output)
			Expect(err).ToNot(HaveOccurred())
		}))
		return server
	}

	getReconciler := func(server *httptest.Server) *AuthenticationReconciler {
		scheme := runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(operatorv1alpha1.AddODLMEnabledToScheme(scheme)).To(Succeed())
		Expect(batchv1.AddToScheme(scheme)).To(Succeed())
		Expect(appsv1.AddToScheme(scheme)).To(Succeed())
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
		dc := discovery.NewDiscoveryClientForConfigOrDie(&restclient.Config{Host: server.URL})

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
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
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
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
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
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
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
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
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
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
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
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
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
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
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

		Context("with OperandRequest API available", func() {
			It("should add im-needs-database OperandRequest when datastore ConfigMap is not found", func() {
				server := getFakeServerForDiscovery()
				defer server.Close()
				r := getReconciler(server)
				defer server.Close()
				ctx = context.Background()
				authCR := &operatorv1alpha1.Authentication{}
				Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())

				// ConfigMap does not exist - should add im-needs-database
				status, err := r.getCurrentServiceStatus(ctx, r.Client, authCR)
				Expect(err).NotTo(HaveOccurred())

				// Check that im-needs-database OperandRequest status is included
				foundDBOperandRequest := false
				for _, managedResource := range status.ManagedResources {
					if managedResource.Kind == "OperandRequest" && managedResource.ObjectName == "im-needs-database" {
						foundDBOperandRequest = true
						break
					}
				}
				Expect(foundDBOperandRequest).To(BeTrue(), "im-needs-database OperandRequest should be included when ConfigMap not found")
			})

			It("should return error when datastore ConfigMap get fails with non-NotFound error", func() {
				server := getFakeServerForDiscovery()
				defer server.Close()
				r := getReconciler(server)
				ctx = context.Background()
				authCR := &operatorv1alpha1.Authentication{}
				Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())

				// Create a ConfigMap with invalid data that will cause an error during processing
				// Note: We can't easily simulate a Get error with the fake client, but we can test
				// the ParseBool error path which also returns an error
				cm := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      ctrlcommon.DatastoreEDBCMName,
						Namespace: "data-ns",
					},
					Data: map[string]string{
						"IS_EMBEDDED": "invalid-bool-value",
					},
				}
				Expect(r.Client.Create(ctx, cm)).To(Succeed())

				_, err := r.getCurrentServiceStatus(ctx, r.Client, authCR)
				Expect(err).To(HaveOccurred(), "should return error when IS_EMBEDDED has invalid boolean value")
			})

			It("should add im-needs-database OperandRequest when IS_EMBEDDED is true", func() {
				server := getFakeServerForDiscovery()
				defer server.Close()
				r := getReconciler(server)
				ctx = context.Background()
				authCR := &operatorv1alpha1.Authentication{}
				Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())

				cm := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      ctrlcommon.DatastoreEDBCMName,
						Namespace: "data-ns",
					},
					Data: map[string]string{
						"IS_EMBEDDED": "true",
					},
				}
				Expect(r.Client.Create(ctx, cm)).To(Succeed())

				status, err := r.getCurrentServiceStatus(ctx, r.Client, authCR)
				Expect(err).NotTo(HaveOccurred())

				// IS_EMBEDDED=true means ParseBool returns (true, nil), so isConfiguredForExternalDB returns (true, nil)
				// This means external DB is configured, so im-needs-database should NOT be added
				foundDBOperandRequest := false
				for _, managedResource := range status.ManagedResources {
					if managedResource.Kind == "OperandRequest" && managedResource.ObjectName == "im-needs-database" {
						foundDBOperandRequest = true
						break
					}
				}
				Expect(foundDBOperandRequest).To(BeTrue(), "im-needs-database OperandRequest should be included when IS_EMBEDDED=true")
			})

			It("should skip im-needs-database OperandRequest when IS_EMBEDDED is false", func() {
				server := getFakeServerForDiscovery()
				defer server.Close()
				r := getReconciler(server)
				ctx = context.Background()
				authCR := &operatorv1alpha1.Authentication{}
				Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())

				cm := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      ctrlcommon.DatastoreEDBCMName,
						Namespace: "data-ns",
					},
					Data: map[string]string{
						"IS_EMBEDDED": "false",
					},
				}
				Expect(r.Client.Create(ctx, cm)).To(Succeed())

				status, err := r.getCurrentServiceStatus(ctx, r.Client, authCR)
				Expect(err).NotTo(HaveOccurred())

				// IS_EMBEDDED=false means ParseBool returns (false, nil), so isConfiguredForExternalDB returns (false, nil)
				// This means embedded DB is needed, so im-needs-database SHOULD be added
				foundDBOperandRequest := false
				for _, managedResource := range status.ManagedResources {
					if managedResource.Kind == "OperandRequest" && managedResource.ObjectName == "im-needs-database" {
						foundDBOperandRequest = true
						break
					}
				}
				Expect(foundDBOperandRequest).To(BeFalse(), "im-needs-database OperandRequest should be skipped when IS_EMBEDDED=false")
			})

			It("should skip im-needs-database OperandRequest when IS_EMBEDDED field is missing", func() {
				server := getFakeServerForDiscovery()
				defer server.Close()
				r := getReconciler(server)
				ctx = context.Background()
				authCR := &operatorv1alpha1.Authentication{}
				Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())

				cm := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      ctrlcommon.DatastoreEDBCMName,
						Namespace: "data-ns",
					},
					Data: map[string]string{
						// IS_EMBEDDED field is missing
					},
				}
				Expect(r.Client.Create(ctx, cm)).To(Succeed())

				status, err := r.getCurrentServiceStatus(ctx, r.Client, authCR)
				Expect(err).NotTo(HaveOccurred())

				// When IS_EMBEDDED is missing, isConfiguredForExternalDB returns (true, nil) per user requirement
				// This means external DB is configured, so im-needs-database should NOT be added
				foundDBOperandRequest := false
				for _, managedResource := range status.ManagedResources {
					if managedResource.Kind == "OperandRequest" && managedResource.ObjectName == "im-needs-database" {
						foundDBOperandRequest = true
						break
					}
				}
				Expect(foundDBOperandRequest).To(BeFalse(), "im-needs-database OperandRequest should NOT be included when IS_EMBEDDED field is missing (external DB)")
			})

			It("should return error when IS_EMBEDDED has invalid boolean value", func() {
				server := getFakeServerForDiscovery()
				defer server.Close()
				r := getReconciler(server)
				ctx = context.Background()
				authCR := &operatorv1alpha1.Authentication{}
				Expect(r.Get(ctx, types.NamespacedName{Name: "example-authentication", Namespace: "data-ns"}, authCR)).To(Succeed())

				cm := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      ctrlcommon.DatastoreEDBCMName,
						Namespace: "data-ns",
					},
					Data: map[string]string{
						"IS_EMBEDDED": "not-a-boolean",
					},
				}
				Expect(r.Client.Create(ctx, cm)).To(Succeed())

				_, err := r.getCurrentServiceStatus(ctx, r.Client, authCR)
				Expect(err).To(HaveOccurred(), "should return ParseBool error when IS_EMBEDDED has invalid value")
			})
		})
	})

	Context("getServiceStatus", func() {
		It("should return Ready when service exists", func() {
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
			ctx = context.Background()
			svc := &corev1.Service{
				TypeMeta:   metav1.TypeMeta{APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "data-ns"},
			}
			Expect(r.Client.Create(ctx, svc)).To(Succeed())
			status := getServiceStatus(ctx, r.Client, types.NamespacedName{Name: "test-svc", Namespace: "data-ns"})
			Expect(status.Status).To(Equal(ResourceReadyState))
		})
	})

	Context("getDeploymentStatus", func() {
		It("should return Ready when deployment is available", func() {
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
			ctx = context.Background()
			deploy := &appsv1.Deployment{
				TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "test-deploy", Namespace: "data-ns"},
				Status: appsv1.DeploymentStatus{
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue},
					},
				},
			}
			Expect(r.Client.Create(ctx, deploy)).To(Succeed())
			status := getDeploymentStatus(ctx, r.Client, types.NamespacedName{Name: "test-deploy", Namespace: "data-ns"})
			Expect(status.Status).To(Equal(ResourceReadyState))
		})
	})

	Context("getRouteStatus", func() {
		It("should return Ready when route is admitted", func() {
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
			ctx = context.Background()
			route := &routev1.Route{
				TypeMeta:   metav1.TypeMeta{APIVersion: "route.openshift.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "data-ns"},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Conditions: []routev1.RouteIngressCondition{
								{Type: routev1.RouteAdmitted, Status: corev1.ConditionTrue},
							},
						},
					},
				},
			}
			Expect(r.Client.Create(ctx, route)).To(Succeed())
			status := getRouteStatus(ctx, r.Client, types.NamespacedName{Name: "test-route", Namespace: "data-ns"})
			Expect(status.Status).To(Equal(ResourceReadyState))
		})
	})

	Context("getJobStatus", func() {
		It("should return Ready when job is complete", func() {
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
			ctx = context.Background()
			job := &batchv1.Job{
				TypeMeta:   metav1.TypeMeta{APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "test-job", Namespace: "data-ns"},
				Status: batchv1.JobStatus{
					Conditions: []batchv1.JobCondition{
						{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
					},
				},
			}
			Expect(r.Client.Create(ctx, job)).To(Succeed())
			status := getJobStatus(ctx, r.Client, types.NamespacedName{Name: "test-job", Namespace: "data-ns"})
			Expect(status.Status).To(Equal(ResourceReadyState))
		})
	})

	Context("jobHasCompleted", func() {
		It("should return true when job has completion time", func() {
			now := metav1.NewTime(time.Now())
			job := &batchv1.Job{Status: batchv1.JobStatus{CompletionTime: &now}}
			Expect(jobHasCompleted(job)).To(BeTrue())
		})

		It("should return false when job has no completion time", func() {
			job := &batchv1.Job{}
			Expect(jobHasCompleted(job)).To(BeFalse())
		})
	})

	Context("jobHasFailed", func() {
		It("should return true when job has failed pods", func() {
			job := &batchv1.Job{Status: batchv1.JobStatus{Failed: 1}}
			Expect(jobHasFailed(job)).To(BeTrue())
		})

		It("should return false when job has no failed pods", func() {
			job := &batchv1.Job{}
			Expect(jobHasFailed(job)).To(BeFalse())
		})
	})

	Context("jobHasCompletelyFailed", func() {
		It("should return true when failed count equals backoff limit", func() {
			backoffLimit := int32(3)
			job := &batchv1.Job{
				Spec:   batchv1.JobSpec{BackoffLimit: &backoffLimit},
				Status: batchv1.JobStatus{Failed: 3},
			}
			Expect(jobHasCompletelyFailed(job)).To(BeTrue())
		})

		It("should use default backoff limit of 6", func() {
			job := &batchv1.Job{Status: batchv1.JobStatus{Failed: 6}}
			Expect(jobHasCompletelyFailed(job)).To(BeTrue())
		})
	})

	Context("setMigratedStatus", func() {
		It("should set complete condition when job is completed", func() {
			now := metav1.NewTime(time.Now())
			job := &batchv1.Job{Status: batchv1.JobStatus{CompletionTime: &now}}
			authCR := &operatorv1alpha1.Authentication{}
			setMigratedStatus(authCR, job)
			condition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrated)
			Expect(condition).ToNot(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionTrue))
		})

		It("should set failure condition when job has failed", func() {
			job := &batchv1.Job{Status: batchv1.JobStatus{Failed: 1}}
			authCR := &operatorv1alpha1.Authentication{}
			setMigratedStatus(authCR, job)
			condition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrated)
			Expect(condition).ToNot(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		})
	})

	Context("setMigrationsRunningStatus", func() {
		It("should set finished condition when job is completed", func() {
			now := metav1.NewTime(time.Now())
			job := &batchv1.Job{Status: batchv1.JobStatus{CompletionTime: &now}}
			authCR := &operatorv1alpha1.Authentication{}
			setMigrationsRunningStatus(authCR, job)
			condition := meta.FindStatusCondition(authCR.Status.Conditions, operatorv1alpha1.ConditionMigrationsRunning)
			Expect(condition).ToNot(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		})
	})

	Context("getOperandRequestStatus", func() {
		It("should return Ready when phase is Running", func() {
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
			ctx = context.Background()
			opReq := &operatorv1alpha1.OperandRequest{
				TypeMeta:   metav1.TypeMeta{APIVersion: "operator.ibm.com/v1alpha1"},
				ObjectMeta: metav1.ObjectMeta{Name: "im-needs-ui", Namespace: "data-ns"},
				Status:     operatorv1alpha1.OperandRequestStatus{Phase: operatorv1alpha1.ClusterPhaseRunning},
			}
			Expect(r.Client.Create(ctx, opReq)).To(Succeed())
			status := getOperandRequestStatus(ctx, r.Client, types.NamespacedName{Name: "im-needs-ui", Namespace: "data-ns"})
			Expect(status.Status).To(Equal(ResourceReadyState))
			Expect(status.Kind).To(Equal("OperandRequest"))
		})

		It("should return Ready when Ready condition is true", func() {
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
			ctx = context.Background()
			opReq := &operatorv1alpha1.OperandRequest{
				TypeMeta:   metav1.TypeMeta{APIVersion: "operator.ibm.com/v1alpha1"},
				ObjectMeta: metav1.ObjectMeta{Name: "im-needs-database", Namespace: "data-ns"},
				Status: operatorv1alpha1.OperandRequestStatus{
					Conditions: []operatorv1alpha1.Condition{
						{Type: operatorv1alpha1.ConditionReady, Status: corev1.ConditionTrue},
					},
				},
			}
			Expect(r.Client.Create(ctx, opReq)).To(Succeed())
			status := getOperandRequestStatus(ctx, r.Client, types.NamespacedName{Name: "im-needs-database", Namespace: "data-ns"})
			Expect(status.Status).To(Equal(ResourceReadyState))
		})

		It("should return NotReady when not ready", func() {
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
			ctx = context.Background()
			opReq := &operatorv1alpha1.OperandRequest{
				TypeMeta:   metav1.TypeMeta{APIVersion: "operator.ibm.com/v1alpha1"},
				ObjectMeta: metav1.ObjectMeta{Name: "im-needs-ui", Namespace: "data-ns"},
				Status:     operatorv1alpha1.OperandRequestStatus{Phase: operatorv1alpha1.ClusterPhaseCreating},
			}
			Expect(r.Client.Create(ctx, opReq)).To(Succeed())
			status := getOperandRequestStatus(ctx, r.Client, types.NamespacedName{Name: "im-needs-ui", Namespace: "data-ns"})
			Expect(status.Status).To(Equal(ResourceNotReadyState))
		})

		It("should return NotReady when does not exist", func() {
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
			ctx = context.Background()
			status := getOperandRequestStatus(ctx, r.Client, types.NamespacedName{Name: "nonexistent", Namespace: "data-ns"})
			Expect(status.Status).To(Equal(ResourceNotReadyState))
			Expect(status.APIVersion).To(Equal(UnknownAPIVersion))
		})
	})

	Context("getAllOperandRequestStatus", func() {
		It("should return status for all OperandRequests", func() {
			server := getFakeServerForDiscovery()
			defer server.Close()
			r := getReconciler(server)
			ctx = context.Background()
			opReq1 := &operatorv1alpha1.OperandRequest{
				TypeMeta:   metav1.TypeMeta{APIVersion: "operator.ibm.com/v1alpha1"},
				ObjectMeta: metav1.ObjectMeta{Name: "im-needs-ui", Namespace: "data-ns"},
				Status:     operatorv1alpha1.OperandRequestStatus{Phase: operatorv1alpha1.ClusterPhaseRunning},
			}
			opReq2 := &operatorv1alpha1.OperandRequest{
				TypeMeta:   metav1.TypeMeta{APIVersion: "operator.ibm.com/v1alpha1"},
				ObjectMeta: metav1.ObjectMeta{Name: "im-needs-database", Namespace: "data-ns"},
				Status:     operatorv1alpha1.OperandRequestStatus{Phase: operatorv1alpha1.ClusterPhaseCreating},
			}
			Expect(r.Client.Create(ctx, opReq1)).To(Succeed())
			Expect(r.Client.Create(ctx, opReq2)).To(Succeed())

			statuses := getAllOperandRequestStatus(ctx, r.Client, []string{"im-needs-ui", "im-needs-database"}, "data-ns")
			Expect(statuses).To(HaveLen(2))
			Expect(statuses[0].Status).To(Equal(ResourceReadyState))
			Expect(statuses[1].Status).To(Equal(ResourceNotReadyState))
		})
	})
})
