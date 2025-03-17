package operator

import (
	"strings"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

type matcherFunc func(*corev1.ConfigMap) bool

func observedKeySet(key string) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		_, ok := observed.Data[key]
		return ok
	}
}

func observedKeyValueSetTo(key, value string) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		observedValue, ok := observed.Data[key]
		if ok && value == observedValue {
			return true
		}
		return false
	}
}

func updatesAlways(keys ...string) (fn func(*corev1.ConfigMap, *corev1.ConfigMap) bool) {
	return func(observed, updates *corev1.ConfigMap) bool {
		return updateFields(observed, updates, keys...)
	}
}

func zenFrontDoorEnabled(authCR *operatorv1alpha1.Authentication) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		return authCR.Spec.Config.ZenFrontDoor
	}
}

func not(isMatch matcherFunc) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		return !isMatch(observed)
	}
}

func and(matchers ...matcherFunc) matcherFunc {
	return func(observed *corev1.ConfigMap) (matches bool) {
		if len(matchers) == 0 {
			return false
		}
		matches = true
		for _, isMatch := range matchers {
			if !isMatch(observed) {
				return false
			}
		}
		return
	}
}

func or(matchers ...matcherFunc) matcherFunc {
	return func(observed *corev1.ConfigMap) (matches bool) {
		matches = false
		for _, isMatch := range matchers {
			if isMatch(observed) {
				return true
			}
		}
		return
	}
}

func observedKeyValueContains(key, value string) matcherFunc {
	return func(observed *corev1.ConfigMap) bool {
		observedValue, ok := observed.Data[key]
		if ok && strings.Contains(observedValue, value) {
			return true
		}
		return false
	}
}

func updatesValuesWhen(matches matcherFunc, keys ...string) (fn func(*corev1.ConfigMap, *corev1.ConfigMap) bool) {
	return func(observed, updates *corev1.ConfigMap) bool {
		if matches(observed) {
			return updateFields(observed, updates, keys...)
		}
		return false
	}
}
