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

package operator

import (
	"context"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
)

// fakeClientWithSSAR wraps a fake client and intercepts SelfSubjectAccessReview creation
type fakeClientWithSSAR struct {
	client.Client
	allowAll      bool
	denyResources map[string]map[string]bool // resource -> verb -> deny
}

func (f *fakeClientWithSSAR) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if ssar, ok := obj.(*authorizationv1.SelfSubjectAccessReview); ok {
		resource := ssar.Spec.ResourceAttributes.Resource
		verb := ssar.Spec.ResourceAttributes.Verb

		// Default to allowed
		ssar.Status.Allowed = true

		// Check if we should deny this specific resource/verb combination
		if !f.allowAll && f.denyResources != nil {
			if verbs, exists := f.denyResources[resource]; exists {
				if deny, verbExists := verbs[verb]; verbExists && deny {
					ssar.Status.Allowed = false
					ssar.Status.Denied = true
					ssar.Status.Reason = "Denied by test"
				}
			}
		}

		return nil
	}
	return f.Client.Create(ctx, obj, opts...)
}

func setupTest(t *testing.T, existingObjs []client.Object, permissions *fakeClientWithSSAR) (*AuthenticationReconciler, ctrl.Request, string) {
	namespace := "test-namespace"

	authCR := &operatorv1alpha1.Authentication{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.ibm.com/v1alpha1",
			Kind:       "Authentication",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example-authentication",
			Namespace: namespace,
		},
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      authCR.Name,
			Namespace: authCR.Namespace,
		},
	}

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("Failed to add corev1 to scheme: %v", err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatalf("Failed to add rbacv1 to scheme: %v", err)
	}
	if err := operatorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("Failed to add operatorv1alpha1 to scheme: %v", err)
	}
	if err := authorizationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("Failed to add authorizationv1 to scheme: %v", err)
	}

	// Add authCR to existing objects
	allObjs := append([]client.Object{authCR}, existingObjs...)

	baseClient := fakeclient.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(allObjs...).
		Build()

	var cl client.Client
	if permissions != nil {
		permissions.Client = baseClient
		cl = permissions
	} else {
		cl = &fakeClientWithSSAR{
			Client:   baseClient,
			allowAll: true,
		}
	}

	r := &AuthenticationReconciler{
		Client: cl,
		Scheme: scheme,
	}

	return r, req, namespace
}

func TestCleanupOldRBAC_AllResourcesExist_FullPermissions(t *testing.T) {
	namespace := "test-namespace"
	crbName := "ibm-iam-operand-restricted-" + namespace

	existingObjs := []client.Object{
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ibm-iam-operand-restricted",
				Namespace: namespace,
			},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ibm-iam-operand-restricted",
				Namespace: namespace,
			},
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ibm-iam-operand-restricted",
				Namespace: namespace,
			},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: crbName,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "ibm-iam-operator",
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "ClusterRole",
				Name: "ibm-iam-operand-restricted",
			},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ibm-iam-operand-restricted",
			},
		},
	}

	r, req, _ := setupTest(t, existingObjs, nil)
	ctx := context.Background()

	result, err := r.cleanupOldRBAC(ctx, req)
	if err != nil {
		t.Fatalf("cleanupOldRBAC failed: %v", err)
	}
	if result != nil {
		t.Fatalf("Expected nil result, got: %v", result)
	}

	// Verify all resources are deleted
	rb := &rbacv1.RoleBinding{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted", Namespace: namespace}, rb)
	if !k8sErrors.IsNotFound(err) {
		t.Errorf("Expected RoleBinding to be deleted, but got error: %v", err)
	}

	role := &rbacv1.Role{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted", Namespace: namespace}, role)
	if !k8sErrors.IsNotFound(err) {
		t.Errorf("Expected Role to be deleted, but got error: %v", err)
	}

	sa := &corev1.ServiceAccount{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted", Namespace: namespace}, sa)
	if !k8sErrors.IsNotFound(err) {
		t.Errorf("Expected ServiceAccount to be deleted, but got error: %v", err)
	}

	crb := &rbacv1.ClusterRoleBinding{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: crbName}, crb)
	if !k8sErrors.IsNotFound(err) {
		t.Errorf("Expected ClusterRoleBinding to be deleted, but got error: %v", err)
	}

	cr := &rbacv1.ClusterRole{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted"}, cr)
	if !k8sErrors.IsNotFound(err) {
		t.Errorf("Expected ClusterRole to be deleted, but got error: %v", err)
	}
}

func TestCleanupOldRBAC_NoClusterRoleBindingDeletePermission(t *testing.T) {
	namespace := "test-namespace"
	crbName := "ibm-iam-operand-restricted-" + namespace

	existingObjs := []client.Object{
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: crbName,
			},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ibm-iam-operand-restricted",
			},
		},
	}

	permissions := &fakeClientWithSSAR{
		denyResources: map[string]map[string]bool{
			"clusterrolebindings": {"delete": true},
		},
	}

	r, req, _ := setupTest(t, existingObjs, permissions)
	ctx := context.Background()

	result, err := r.cleanupOldRBAC(ctx, req)
	if err != nil {
		t.Fatalf("cleanupOldRBAC failed: %v", err)
	}
	if result != nil {
		t.Fatalf("Expected nil result, got: %v", result)
	}

	// Verify ClusterRoleBinding still exists
	crb := &rbacv1.ClusterRoleBinding{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: crbName}, crb)
	if err != nil {
		t.Errorf("Expected ClusterRoleBinding to still exist, but got error: %v", err)
	}
}

func TestCleanupOldRBAC_MultipleClusterRoleBindings(t *testing.T) {
	namespace := "test-namespace"
	crbName := "ibm-iam-operand-restricted-" + namespace

	existingObjs := []client.Object{
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: crbName,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "ibm-iam-operator",
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "ClusterRole",
				Name: "ibm-iam-operand-restricted",
			},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ibm-iam-operand-restricted-other-namespace",
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "ibm-iam-operator",
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "ClusterRole",
				Name: "ibm-iam-operand-restricted",
			},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ibm-iam-operand-restricted",
			},
		},
	}

	r, req, _ := setupTest(t, existingObjs, nil)
	ctx := context.Background()

	result, err := r.cleanupOldRBAC(ctx, req)
	if err != nil {
		t.Fatalf("cleanupOldRBAC failed: %v", err)
	}
	if result != nil {
		t.Fatalf("Expected nil result, got: %v", result)
	}

	// Verify ClusterRole still exists (not deleted because multiple CRBs reference it)
	cr := &rbacv1.ClusterRole{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted"}, cr)
	if err != nil {
		t.Errorf("Expected ClusterRole to still exist, but got error: %v", err)
	}

	// Verify the specific ClusterRoleBinding for this namespace is deleted
	crb := &rbacv1.ClusterRoleBinding{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: crbName}, crb)
	if !k8sErrors.IsNotFound(err) {
		t.Errorf("Expected ClusterRoleBinding to be deleted, but got error: %v", err)
	}

	// Verify the other ClusterRoleBinding still exists
	otherCrb := &rbacv1.ClusterRoleBinding{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted-other-namespace"}, otherCrb)
	if err != nil {
		t.Errorf("Expected other ClusterRoleBinding to still exist, but got error: %v", err)
	}
}

func TestCleanupOldRBAC_NoListPermission(t *testing.T) {
	existingObjs := []client.Object{
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ibm-iam-operand-restricted",
			},
		},
	}

	permissions := &fakeClientWithSSAR{
		denyResources: map[string]map[string]bool{
			"clusterrolebindings": {"list": true},
		},
	}

	r, req, _ := setupTest(t, existingObjs, permissions)
	ctx := context.Background()

	result, err := r.cleanupOldRBAC(ctx, req)
	if err != nil {
		t.Fatalf("cleanupOldRBAC failed: %v", err)
	}
	if result != nil {
		t.Fatalf("Expected nil result, got: %v", result)
	}

	// Verify ClusterRole still exists (not deleted due to lack of list permission)
	cr := &rbacv1.ClusterRole{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted"}, cr)
	if err != nil {
		t.Errorf("Expected ClusterRole to still exist, but got error: %v", err)
	}
}

func TestCleanupOldRBAC_ZeroClusterRoleBindings(t *testing.T) {
	existingObjs := []client.Object{
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ibm-iam-operand-restricted",
			},
		},
	}

	r, req, _ := setupTest(t, existingObjs, nil)
	ctx := context.Background()

	result, err := r.cleanupOldRBAC(ctx, req)
	if err != nil {
		t.Fatalf("cleanupOldRBAC failed: %v", err)
	}
	if result != nil {
		t.Fatalf("Expected nil result, got: %v", result)
	}

	// Verify ClusterRole still exists (not deleted when count is 0)
	cr := &rbacv1.ClusterRole{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: "ibm-iam-operand-restricted"}, cr)
	if err != nil {
		t.Errorf("Expected ClusterRole to still exist, but got error: %v", err)
	}
}

func TestCleanupOldRBAC_ResourcesNotFound(t *testing.T) {
	r, req, _ := setupTest(t, []client.Object{}, nil)
	ctx := context.Background()

	result, err := r.cleanupOldRBAC(ctx, req)
	if err != nil {
		t.Fatalf("cleanupOldRBAC failed: %v", err)
	}
	if result != nil {
		t.Fatalf("Expected nil result, got: %v", result)
	}
}

// Made with Bob
