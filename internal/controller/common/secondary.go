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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Generator is an interface that wraps the Generate method.
//
// It takes a context assumed to be scoped to the current reconcile loop and a
// client.Object that is the recipient of the new object state. It returns an
// error if something goes wrong over the course of performing this operation.
type Generator interface {
	Generate(context.Context, client.Object) error
}

// GenerateFn is a type of function used when a SecondaryReconciler supports
// creation of the secondary resource based upon various factors including
// settings on the primary resource, cluster observations, or other internal
// controller logic.
type GenerateFn[T client.Object] func(SecondaryReconciler, context.Context, T) error

// Modifier is an interface that wraps the Modify method.
//
// It takes a context assumed to be scoped to the current reconcile loop and two
// client.Object arguments - the first should be the observed object that
// represents what is on the cluster currently, and the second is what the
// reconciler determines should be installed on the cluster instead.
//
// If there are relevant differences between the two objects, the first is
// updated with the values from the second so that they are now the same in
// those relevant ways.
//
// Returns an bool representing whether a change was made to the first
// client.Object as well as an error if something goes wrong over the course of
// performing this operation.
type Modifier interface {
	Modify(context.Context, client.Object, client.Object) (bool, error)
}

// ModifyFn is a type of function used when a SecondaryReconciler supports
// modification of its secondary resource; this function is assumed to make
// modifications to the first of the two T arguments based upon the state in the
// second T argument and/or the behavior contained within the ModifyFn[T]
// itself.
type ModifyFn[T client.Object] func(SecondaryReconciler, context.Context, T, T) (bool, error)

// WriteResponder is an interface that wraps the OnWrite method.
//
// It takes a context assumed to be scoped to the current reconcile loop and
// performs any work that needs to be done after a write is performed.
//
// Returns an error if something goes wrong.
type WriteResponder interface {
	OnWrite(context.Context) error
}

// OnWriteFn is a type of function used when a SecondaryReconciler either
// creates or updates its object on a cluster.
type OnWriteFn[T client.Object] func(SecondaryReconciler, context.Context) error

// Finisher is an interface that wraps the OnFinished method.
//
// It takes a context assumed to be scoped to the current reconcile loop, the
// observed and generated client.Objects, and performs any work that needs to be
// done at the end of the subreconciler.
//
// Returns an error if something goes wrong.
type Finisher interface {
	OnFinished(context.Context, client.Object, client.Object) error
}

// Finisher is a type of function used when a SecondaryReconciler is about to
// finish running.
type OnFinishedFn[T client.Object] func(SecondaryReconciler, context.Context, T, T) error

// Secondary is used to denote a relationship between a primary object/resource
// and a secondary one.
type Secondary interface {
	GetName() string               // returns the name of the implementer
	GetNamespace() string          // returns the namespace of the implementer
	GetEmptyObject() client.Object // returns an empty client.Object of the same type as the implementer
	GetPrimary() client.Object     // returns the object that is primary to this one
	GetKind() string               // returns the kind of the implementer
}

type Named interface {
	GetName() string
}

type Namespaced interface {
	GetNamespace() string
}

// ObjectKeyed is a convenience interface for deriving types.NamespacedNames,
// which are used as keys for Kubernetes client calls, from objects that already
// have their name and namespace set on them.
type ObjectKeyed interface {
	Named
	Namespaced
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
	Finisher
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
	onFinished    OnFinishedFn[T]         // function that is run before returning from reconciliation
}

// GetName returns the name of the secondary object.
func (s *secondaryReconciler[T]) GetName() string {
	return s.name
}

// GetNamespace returns the namespace of the secondary object.
func (s *secondaryReconciler[T]) GetNamespace() string {
	return s.namespace
}

// GetEmptyObject returns an empty object of the same GVK as the secondary
// object.
func (s *secondaryReconciler[T]) GetEmptyObject() client.Object {
	rType := reflect.TypeFor[T]().Elem()
	return reflect.New(rType).Interface().(T)
}

// GetKind returns the kind of the secondary object.
func (s *secondaryReconciler[T]) GetKind() string {
	gvk, _ := apiutil.GVKForObject(s.GetEmptyObject(), s.Scheme())
	return gvk.Kind
}

// GetPrimary returns the primary object that triggers this secondary object's
// reconciliation.
func (s *secondaryReconciler[T]) GetPrimary() client.Object {
	return s.primary
}

// GetClient returns the client used for reconciling the secondary object.
func (s *secondaryReconciler[T]) GetClient() client.Client {
	return s.Client
}

// Generate creates a new instance of the secondary object with values derived
// from the secondaryReconciler's settings.
func (s *secondaryReconciler[T]) Generate(ctx context.Context, obj client.Object) (err error) {
	objT, ok := obj.(T)
	if !ok {
		panic("received a mismatched client.Object")
	} else if obj == nil {
		panic("expected non-nil client.Object")
	}

	return s.generate(s, ctx, objT)
}

// Modify compares observed and generated, and, if there are relevant
// qualities that differ between them, observed is updated to match generated in
// those qualities. Returns a boolean for whether observed was updated and an
// error if an error was encountered while attempting this operation.
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

// OnWrite is a function that is executed when any write is made to the cluster,
// e.g. an object is created or updated.
func (s *secondaryReconciler[T]) OnWrite(ctx context.Context) (err error) {
	if s.onWrite == nil {
		return
	}
	return s.onWrite(s, ctx)
}

// OnFinished is a function that is executed before the subreconciler returns.
func (s *secondaryReconciler[T]) OnFinished(ctx context.Context, observed, generated client.Object) (err error) {
	if s.onFinished == nil {
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

	return s.onFinished(s, ctx, observedT, generatedT)
}

// Reconcile performs reconciliation related to the creation or modification of
// the secondary object that the secondaryReconciler is targeted for.
func (s *secondaryReconciler[T]) Reconcile(ctx context.Context) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx, "Object.Namespace", s.GetNamespace(), "Object.Kind", s.GetKind(), "Object.Name", s.GetName())
	debugLogger := reqLogger.V(1)
	debugCtx := logf.IntoContext(ctx, debugLogger)
	var observed client.Object = s.GetEmptyObject()
	var generated client.Object = s.GetEmptyObject()
	defer s.OnFinished(ctx, observed, generated)
	debugLogger.Info("Generating desired Object")
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

	reqLogger.Info("Updates found; updating the Object")
	if err = s.Update(ctx, observed); err != nil {
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

// NewSecondaryReconcilerBuilder creates a new builder for a SecondaryReconciler.
func NewSecondaryReconcilerBuilder[T client.Object]() *SecondaryReconcilerBuilder[T] {
	return &SecondaryReconcilerBuilder[T]{
		s: &secondaryReconciler[T]{},
	}
}

// Build creates a new SecondaryReconciler using the configurations supplied by
// other builder functions. Returns an error if no client or GVK is configured
// on the SecondaryReconciler.
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

// MustBuild creates a new SecondaryReconciler using the configurations supplied
// by other builder functions. Panics if a client or GVK is not configured on
// the SecondaryReconciler.
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

// WithName sets the name of the secondary object that the
// SecondaryReconciler is targeting.
func (b *SecondaryReconcilerBuilder[T]) WithName(name string) *SecondaryReconcilerBuilder[T] {
	b.s.name = name
	return b
}

// WithName sets the namespace of the secondary object that the
// SecondaryReconciler is targeting.
func (b *SecondaryReconcilerBuilder[T]) WithNamespace(namespace string) *SecondaryReconcilerBuilder[T] {
	b.s.namespace = namespace
	return b
}

// WithPrimary sets the primary object for the secondary object that the
// SecondaryReconciler is targeting.
func (b *SecondaryReconcilerBuilder[T]) WithPrimary(primary client.Object) *SecondaryReconcilerBuilder[T] {
	b.s.primary = primary
	return b
}

// WithClient sets the client to be used for interacting with the cluster while
// reconciling the secondary object.
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

// WithOnFinishedFns defines the SecondaryReconciler's OnFinished as a single
// OnFinishedFn[T] composed of the provided OnFinishedFn[T] arguments in the
// order that they appear.
func (b *SecondaryReconcilerBuilder[T]) WithOnFinishedFns(fns ...OnFinishedFn[T]) *SecondaryReconcilerBuilder[T] {
	b.s.onFinished = func(s SecondaryReconciler, ctx context.Context, observed, generated T) (err error) {
		for _, fn := range fns {
			err = fn(s, ctx, observed, generated)
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

// Reconcile implements Subreconciler.
func (f SecondaryReconcilerFn) Reconcile(ctx context.Context) (result *ctrl.Result, err error) {
	return f(ctx)
}

// NewSecondaryReconcilerFn creates a new SecondaryReconcilerFn from a subreconciler.FnWithRequest.
func NewSecondaryReconcilerFn(req ctrl.Request, fn subreconciler.FnWithRequest) SecondaryReconcilerFn {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		return fn(ctx, req)
	}
}

// Subreconcilers implements Subreconciler
type Subreconcilers []Subreconciler

var _ Subreconciler = Subreconcilers{}

func (s Subreconcilers) Reconcile(ctx context.Context) (result *ctrl.Result, err error) {
	results := []*ctrl.Result{}
	errs := []error{}
	for _, reconciler := range s {
		result, err = reconciler.Reconcile(ctx)
		results = append(results, result)
		errs = append(errs, err)
	}
	return ReduceSubreconcilerResultsAndErrors(results, errs)
}

type subreconcilers struct {
	Subreconcilers
	strategy func(*subreconcilers, context.Context) (*ctrl.Result, error)
}

func (s *subreconcilers) Reconcile(ctx context.Context) (result *ctrl.Result, err error) {
	return s.strategy(s, ctx)
}

func NewStrictSubreconcilers(fns ...Subreconciler) *subreconcilers {
	return &subreconcilers{
		Subreconcilers: fns,
		strategy:       strictReconcile,
	}
}

func NewLazySubreconcilers(fns ...Subreconciler) *subreconcilers {
	return &subreconcilers{
		Subreconcilers: fns,
		strategy:       lazyReconcile,
	}
}

func strictReconcile(s *subreconcilers, ctx context.Context) (result *ctrl.Result, err error) {
	for _, reconciler := range s.Subreconcilers {
		result, err = reconciler.Reconcile(ctx)
		if err != nil {
			return
		}
	}
	return
}

func lazyReconcile(s *subreconcilers, ctx context.Context) (result *ctrl.Result, err error) {
	results := []*ctrl.Result{}
	errs := []error{}
	for _, reconciler := range s.Subreconcilers {
		result, err = reconciler.Reconcile(ctx)
		results = append(results, result)
		errs = append(errs, err)
	}
	return ReduceSubreconcilerResultsAndErrors(results, errs)
}
