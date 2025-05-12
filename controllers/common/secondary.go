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
	"context"
	"fmt"
	"reflect"

	"github.com/opdev/subreconciler"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type Generator interface {
	Generate(context.Context, client.Object) error
}

// GenerateFn is a type of function used when a SecondaryReconciler supports
// creation of the secondary resource based upon various factors including
// settings on the primary resource, cluster observations, or other internal
// controller logic.
type GenerateFn[T client.Object] func(SecondaryReconciler, context.Context, T) error

type Modifier interface {
	Modify(context.Context, client.Object, client.Object) (bool, error)
}

// ModifyFn is a type of function used when a SecondaryReconciler supports
// modification of its secondary resource; this function is assumed to make
// modifications to the first of the two T arguments based upon the state in the
// second T argument and/or the behavior contained within the ModifyFn[T]
// itself.
type ModifyFn[T client.Object] func(SecondaryReconciler, context.Context, T, T) (bool, error)

type WriteResponder interface {
	OnWrite(context.Context) error
}

// OnWriteFn is a type of function used when a SecondaryReconciler either
// creates or updates its object on a cluster.
type OnWriteFn[T client.Object] func(SecondaryReconciler, context.Context) error

// Secondary is used to denote a relationship between a primary object/resource
// and a secondary one.
type Secondary interface {
	GetName() string               // returns the name of the implementer
	GetNamespace() string          // returns the namespace of the implementer
	GetEmptyObject() client.Object // returns an empty client.Object of the same type as the implementer
	GetPrimary() client.Object     // returns the object that is primary to this one
	GetKind() string               // returns the kind of the implementer
}

// ObjectKeyed is a convenience interface for deriving types.NamespacedNames,
// which are used as keys for Kubernetes client calls, from objects that already
// have their name and namespace set on them.
type ObjectKeyed interface {
	GetName() string
	GetNamespace() string
}

// GetObjectKey returns a types.NamespacedName from an ObjectKeyed.
func GetObjectKey(o ObjectKeyed) types.NamespacedName {
	return types.NamespacedName{Name: o.GetName(), Namespace: o.GetNamespace()}
}

// Subreconciler represents a unit of what makes up the reconciliation of a
// given primary resource.
type Subreconciler interface {
	Reconcile(context.Context) (result *ctrl.Result, err error) // Reconcile is a subreconciler.Fn
}

// SecondaryReconciler represents a secondary resource that needs to be
// created and/or modified alongside its related logic whenever its primary
// resource is being reconciled.
type SecondaryReconciler interface {
	Secondary
	Subreconciler
	GetClient() client.Client
	Generator
	Modifier
	WriteResponder
}

type secondaryReconciler[T client.Object] struct {
	client.Client                         // kubernetes client used for interacting with the cluster
	name          string                  // name of the secondary object this reconciles
	namespace     string                  // namespace of the secondary object this reconciles
	primary       client.Object           // primary object that triggers this secondary object's reconciliation
	gvk           schema.GroupVersionKind // group-version-kind of the object
	generate      GenerateFn[T]           // function that generates a new copy of this secondary object with calculated values
	modify        ModifyFn[T]             // function that makes modifications to an observed secondary object
	onWrite       OnWriteFn[T]            // function that is run after a write is made to this secondary object
}

func (s *secondaryReconciler[T]) GetName() string {
	return s.name
}

func (s *secondaryReconciler[T]) GetNamespace() string {
	return s.namespace
}

func (s *secondaryReconciler[T]) GetEmptyObject() client.Object {
	rType := reflect.TypeFor[T]().Elem()
	return reflect.New(rType).Interface().(T)
}

func (s *secondaryReconciler[T]) GetKind() string {
	gvk, _ := apiutil.GVKForObject(s.GetEmptyObject(), s.Scheme())
	return gvk.Kind
}

func (s *secondaryReconciler[T]) GetPrimary() client.Object {
	return s.primary
}

func (s *secondaryReconciler[T]) GetClient() client.Client {
	return s.Client
}

func (s *secondaryReconciler[T]) Generate(ctx context.Context, obj client.Object) (err error) {
	objT, ok := obj.(T)
	if !ok {
		panic("received a mismatched client.Object")
	} else if obj == nil {
		panic("expected non-nil client.Object")
	}

	return s.generate(s, ctx, objT)
}

func (s *secondaryReconciler[T]) Modify(ctx context.Context, observed, generated client.Object) (modified bool, err error) {
	if s.modify == nil {
		return
	}
	observedT, ok := observed.(T)
	if !ok {
		panic("received a mismatched client.Object")
	} else if observed == nil {
		panic("expected non-nil client.Object")
	}
	generatedT, ok := generated.(T)
	if !ok {
		panic("received a mismatched client.Object")
	} else if generated == nil {
		panic("expected non-nil client.Object")
	}

	return s.modify(s, ctx, observedT, generatedT)
}

func (s *secondaryReconciler[T]) OnWrite(ctx context.Context) (err error) {
	if s.onWrite == nil {
		return
	}
	return s.onWrite(s, ctx)
}

func (s *secondaryReconciler[T]) Reconcile(ctx context.Context) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx, "Object.Namespace", s.GetNamespace(), "Object.Kind", s.GetKind(), "Object.Name", s.GetName())
	debugLogger := logf.FromContext(ctx, "Object.Namespace", s.GetNamespace(), "Object.Kind", s.GetKind(), "Object.Name", s.GetName()).V(1)
	debugCtx := logf.IntoContext(ctx, debugLogger)
	var observed client.Object = s.GetEmptyObject()
	var generated client.Object = s.GetEmptyObject()
	if err = s.Generate(debugCtx, generated); err != nil {
		reqLogger.Error(err, "Failed to generate Object")
		return subreconciler.RequeueWithError(err)
	}
	objKey := types.NamespacedName{Name: s.GetName(), Namespace: s.GetNamespace()}
	if err = s.Get(ctx, objKey, observed); k8sErrors.IsNotFound(err) {
		if err := s.Create(debugCtx, generated); k8sErrors.IsAlreadyExists(err) {
			reqLogger.Info("Object was found while creating")
			return subreconciler.RequeueWithDelay(DefaultLowerWait)
		} else if err != nil {
			reqLogger.Info("Object could not be created for an unexpected reason", "msg", err.Error())
			return subreconciler.RequeueWithDelay(DefaultLowerWait)
		}
		reqLogger.Info("Object created")
		if err = s.OnWrite(debugCtx); err != nil {
			reqLogger.Info("Error occurred while performing post-create work", "reason", err.Error())
		}
		return subreconciler.RequeueWithDelay(DefaultLowerWait)
	}

	modified := false
	modified, err = s.Modify(debugCtx, observed, generated)
	if err != nil {
		reqLogger.Info("An issue was encountered while trying to identify necessary updates", "reason", err.Error())
		return subreconciler.RequeueWithError(err)
	} else if !modified {
		reqLogger.Info("No updates needed")
		return subreconciler.ContinueReconciling()
	}

	u := &unstructured.Unstructured{}
	u.Object, err = runtime.DefaultUnstructuredConverter.ToUnstructured(observed)
	if err != nil {
		reqLogger.Info("Failed to convert Object to unstructured", "reason", err.Error())
		return subreconciler.RequeueWithError(err)
	}

	reqLogger.Info("Updates found; updating the Object")
	if err = s.Update(ctx, u); err != nil {
		reqLogger.Info("Failed to update Object", "msg", err.Error())
		return subreconciler.RequeueWithDelay(DefaultLowerWait)
	}

	reqLogger.Info("Object updated successfully")
	if err = s.OnWrite(debugCtx); err != nil {
		reqLogger.Info("Error occurred while performing post-update work", "reason", err.Error())
	}

	return subreconciler.RequeueWithDelay(DefaultLowerWait)
}

type SecondaryReconcilerBuilder[T client.Object] struct {
	s *secondaryReconciler[T]
}

func NewSecondaryReconcilerBuilder[T client.Object]() *SecondaryReconcilerBuilder[T] {
	return &SecondaryReconcilerBuilder[T]{
		s: &secondaryReconciler[T]{},
	}
}

func (b *SecondaryReconcilerBuilder[T]) Build() (*secondaryReconciler[T], error) {
	if b.s.Client == nil {
		return nil, fmt.Errorf("failed to build secondary reconciler: no client defined")
	}
	gvk, err := apiutil.GVKForObject(b.s.GetEmptyObject(), b.s.Scheme())
	if err != nil {
		return nil, fmt.Errorf("failed to build secondary reconciler: %w", err)
	}
	b.s.gvk = gvk
	return b.s, nil
}

func (b *SecondaryReconcilerBuilder[T]) MustBuild() *secondaryReconciler[T] {
	if b.s.Client == nil {
		panic("failed to build secondary reconciler: no client defined")
	}
	gvk, err := apiutil.GVKForObject(b.s.GetEmptyObject(), b.s.Scheme())
	if err != nil {
		panic(fmt.Errorf("failed to build secondary reconciler: %w", err).Error())
	}
	b.s.gvk = gvk
	return b.s
}

func (b *SecondaryReconcilerBuilder[T]) WithName(name string) *SecondaryReconcilerBuilder[T] {
	b.s.name = name
	return b
}

func (b *SecondaryReconcilerBuilder[T]) WithNamespace(namespace string) *SecondaryReconcilerBuilder[T] {
	b.s.namespace = namespace
	return b
}

func (b *SecondaryReconcilerBuilder[T]) WithPrimary(primary client.Object) *SecondaryReconcilerBuilder[T] {
	b.s.primary = primary
	return b
}

func (b *SecondaryReconcilerBuilder[T]) WithClient(cl client.Client) *SecondaryReconcilerBuilder[T] {
	b.s.Client = cl
	return b
}

// WithGenerateFns defines the SecondaryReconciler's Generate as a single GenerateFn[T]
// composed of the provided GenerateFn[T] arguments in the order that they appear.
func (b *SecondaryReconcilerBuilder[T]) WithGenerateFns(fns ...GenerateFn[T]) *SecondaryReconcilerBuilder[T] {
	b.s.generate = func(s SecondaryReconciler, ctx context.Context, generated T) (err error) {
		for _, fn := range fns {
			err = fn(s, ctx, generated)
			if err != nil {
				return
			}
		}
		return
	}
	return b
}

// WithModifyFns defines the SecondaryReconciler's Modify as a single ModifyFn[T]
// composed of the provided ModifyFn[T] arguments in the order that they appear.
func (b *SecondaryReconcilerBuilder[T]) WithModifyFns(fns ...ModifyFn[T]) *SecondaryReconcilerBuilder[T] {
	b.s.modify = func(s SecondaryReconciler, ctx context.Context, observed, generated T) (modified bool, err error) {
		for _, fn := range fns {
			var subModified bool
			subModified, err = fn(s, ctx, observed, generated)
			modified = modified || subModified
			if err != nil {
				return
			}
		}
		return
	}

	return b
}

// WithWriteFns defines the SecondaryReconciler's OnWrite as a single OnWriteFn[T]
// composed of the provided OnWriteFn[T] arguments in the order that they appear.
func (b *SecondaryReconcilerBuilder[T]) WithOnWriteFns(fns ...OnWriteFn[T]) *SecondaryReconcilerBuilder[T] {
	b.s.onWrite = func(s SecondaryReconciler, ctx context.Context) (err error) {
		for _, fn := range fns {
			err = fn(s, ctx)
			if err != nil {
				return
			}
		}
		return
	}

	return b
}

// SecondaryReconcilerFn is an adapter so that subreconciler.Fn's implement Subreconciler.
type SecondaryReconcilerFn subreconciler.Fn

var _ Subreconciler = SecondaryReconcilerFn(func(ctx context.Context) (result *ctrl.Result, err error) { return })

func (f SecondaryReconcilerFn) Reconcile(ctx context.Context) (result *ctrl.Result, err error) {
	return f(ctx)
}

func NewSecondaryReconcilerFn(req ctrl.Request, fn subreconciler.FnWithRequest) SecondaryReconcilerFn {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		return fn(ctx, req)
	}
}
