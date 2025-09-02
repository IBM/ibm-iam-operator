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
	"bytes"
	"slices"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// matcherFunc[T] evaluates whether a given client.Object matches some criterion.
type matcherFunc[T client.Object] func(T) bool

// observedKeySet[T] returns a matcherFunc[T] that returns whether the
// observed ConfigMap or Secret has a key in its `.data` set.
func observedKeySet[T client.Object](key string) matcherFunc[T] {
	return func(observed T) bool {
		switch t := any(observed).(type) {
		case *corev1.ConfigMap:
			_, ok := t.Data[key]
			return ok
		case *corev1.Secret:
			_, ok := t.Data[key]
			return ok
		}
		return false
	}
}

// observedKeyValueSetTo[T] returns a matcherFunc[T] that returns whether the
// observed ConfigMap or Secret has a key in its `.data` set to the provided
// value.
func observedKeyValueSetTo[T client.Object](key string, value any) matcherFunc[T] {
	return func(observed T) bool {
		var observedValue []byte
		var v []byte
		var ok bool
		switch vT := value.(type) {
		case string:
			v = []byte(vT)
		case []byte:
			v = vT
		default:
			return false
		}
		switch t := any(observed).(type) {
		case *corev1.ConfigMap:
			var observedValueStr string
			observedValueStr, ok = t.Data[key]
			observedValue = []byte(observedValueStr)
		case *corev1.Secret:
			observedValue, ok = t.Data[key]
		}
		return ok && slices.Equal(v, observedValue)
	}
}

// not[T] returns a matcherFunc[T] that returns whether the provided
// matcherFunc[T] failed to find a match.
func not[T client.Object](isMatch matcherFunc[T]) matcherFunc[T] {
	return func(observed T) bool {
		return !isMatch(observed)
	}
}

// observedKeyValueContains[T] returns a matcherFunc[T] that returns whether the
// observed ConfigMap or Secret has a key in its `.data` that contains the
// provided value.
func observedKeyValueContains[T client.Object](key string, value any) matcherFunc[T] {
	return func(observed T) bool {
		var observedValue []byte
		var v []byte
		var ok bool
		switch vT := value.(type) {
		case string:
			v = []byte(vT)
		case []byte:
			v = vT
		default:
			return false
		}
		switch t := any(observed).(type) {
		case *corev1.ConfigMap:
			var observedValueStr string
			observedValueStr, ok = t.Data[key]
			observedValue = []byte(observedValueStr)
		case *corev1.Secret:
			observedValue, ok = t.Data[key]
		}
		return ok && bytes.Contains(observedValue, v)
	}
}

// updatesAlways[T] returns a function that always sets the keys from the  the first T argument
// with the key value pairs from the second T.
func updatesAlways[T client.Object](keys ...string) (fn func(T, T) bool) {
	return func(observed, updates T) bool {
		return updateFields(observed, updates, keys...)
	}
}

// updatesValuesWhen[T] returns a function that updates the first T argument with the
func updatesValuesWhen[T client.Object](matches matcherFunc[T], keys ...string) (fn func(T, T) bool) {
	return func(observed, updates T) bool {
		if matches(observed) {
			return updateFields(observed, updates, keys...)
		}
		return false
	}
}

// updateFields[T] updates the observed ConfigMap or Secret with the listed keys
// and corresponding values from the update ConfigMap or Secret. If no keys are
// given, no update will be made. Returns whether any changes were made to the
// observed ConfigMap or Secret If no keys are given, no update will be made.
// Returns whether any changes were made to the observed ConfigMap or Secret.
func updateFields[T client.Object](observed, update T, keys ...string) (updated bool) {
	switch o := any(observed).(type) {
	case *corev1.ConfigMap:
		u, ok := any(update).(*corev1.ConfigMap)
		if !ok {
			return
		}
		return updateConfigMapFields(o, u, keys...)
	case *corev1.Secret:
		u, ok := any(update).(*corev1.Secret)
		if !ok {
			return
		}
		return updateSecretFields(o, u, keys...)
	}

	return
}

func updateConfigMapFields(observed, update *corev1.ConfigMap, keys ...string) (updated bool) {
	for _, key := range keys {
		observedVal, ok := observed.Data[key]
		updateVal := update.Data[key]
		if !ok || observedVal != updateVal {
			observed.Data[key] = updateVal
			updated = true
		}
	}
	return
}

func updateSecretFields(observed, update *corev1.Secret, keys ...string) (updated bool) {
	for _, key := range keys {
		observedVal, ok := observed.Data[key]
		updateVal := update.Data[key]
		if !ok || !slices.Equal(observedVal, updateVal) {
			observed.Data[key] = updateVal
			updated = true
		}
	}
	return
}
