//
// Copyright 2022 IBM Corporation
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
	"fmt"
	"reflect"

	"github.com/opdev/subreconciler"
	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	ctrlcommon "github.com/IBM/ibm-iam-operator/controllers/common"
)

const ClusterInfoConfigmapName = "ibmcloud-cluster-info"
const PlatformAuthServiceName = "platform-auth-service"
const PlatformIdentityManagementServiceName = "platform-identity-management"
const PlatformIdentityProviderServiceName = "platform-identity-provider"
const DefaultHTTPBackendServiceName = "default-http-backend"

// These are the annotations that must be set on all Routes generated by this Operator
var commonRouteAnnotations map[string]string = map[string]string{
	"haproxy.router.openshift.io/timeout":                               "180s",
	"haproxy.router.openshift.io/pod-concurrent-connections":            "200",
	"haproxy.router.openshift.io/rate-limit-connections":                "true",
	"haproxy.router.openshift.io/rate-limit-connections.concurrent-tcp": "200",
	"haproxy.router.openshift.io/rate-limit-connections.rate-tcp":       "200",
	"haproxy.router.openshift.io/rate-limit-connections.rate-http":      "200",
	"haproxy.router.openshift.io/hsts_header":                           "max-age=31536000;includeSubDomains",
}

type reconcileRouteFields struct {
	Name              string
	Annotations       map[string]string
	RouteHost         string
	RoutePath         string
	RoutePort         int32
	ServiceName       string
	DestinationCAcert []byte
}

func (r *AuthenticationReconciler) handleRoutes(ctx context.Context, req ctrl.Request) (result *ctrl.Result, err error) {
	reqLogger := r.WithValues("subreconciler", "handleRoutes")
	handleRouteCtx := logf.IntoContext(ctx, reqLogger)

	authCR := &operatorv1alpha1.Authentication{}
	if result, err = r.getLatestAuthentication(ctx, req, authCR); subreconciler.ShouldHaltOrRequeue(result, err) {
		return
	}

	return r.reconcileAllRoutes(handleRouteCtx, authCR)
}

func (r *AuthenticationReconciler) reconcileAllRoutes(ctx context.Context, authCR *operatorv1alpha1.Authentication) (result *ctrl.Result, err error) {
	allRoutesFields := &map[string]*reconcileRouteFields{}
	if result, err = r.getAllRoutesFields(authCR, allRoutesFields)(ctx); subreconciler.ShouldRequeue(result, err) {
		return
	}

	allRouteReconcilers := make([]subreconciler.Fn, 0)
	for _, routeFields := range *allRoutesFields {
		allRouteReconcilers = append(allRouteReconcilers, r.reconcileRoute(authCR, routeFields))
	}

	results := []*ctrl.Result{}
	errs := []error{}
	for _, reconcileRoute := range allRouteReconcilers {
		result, err = reconcileRoute(ctx)
		results = append(results, result)
		errs = append(errs, err)
	}
	return ctrlcommon.ReduceSubreconcilerResultsAndErrors(results, errs)
}

func (r *AuthenticationReconciler) getAllRoutesFields(authCR *operatorv1alpha1.Authentication, allRoutesFields *map[string]*reconcileRouteFields) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		routeHost := ""
		wlpClientID := ""
		var (
			platformAuthCert               []byte
			platformIdentityManagementCert []byte
			platformIdentityProviderCert   []byte
		)

		fns := []subreconciler.Fn{
			r.getClusterAddress(authCR, &routeHost),
			r.getWlpClientID(authCR, &wlpClientID),
			r.getCertificateForService(PlatformAuthServiceName, authCR, &platformAuthCert),
			r.getCertificateForService(PlatformIdentityManagementServiceName, authCR, &platformIdentityManagementCert),
			r.getCertificateForService(PlatformIdentityProviderServiceName, authCR, &platformIdentityProviderCert),
		}

		for _, fn := range fns {
			if result, err = fn(ctx); subreconciler.ShouldRequeue(result, err) {
				return
			}
		}

		*allRoutesFields = map[string]*reconcileRouteFields{
			"id-mgmt": {
				Annotations: map[string]string{
					"haproxy.router.openshift.io/rewrite-target": "/",
				},
				Name:              "id-mgmt",
				RouteHost:         routeHost,
				RoutePath:         "/idmgmt/",
				RoutePort:         4500,
				ServiceName:       PlatformIdentityManagementServiceName,
				DestinationCAcert: platformIdentityManagementCert,
			},
			"platform-auth": {
				Annotations: map[string]string{
					"haproxy.router.openshift.io/rewrite-target": "/v1/auth/",
				},
				Name:              "platform-auth",
				RouteHost:         routeHost,
				RoutePath:         "/v1/auth/",
				RoutePort:         4300,
				DestinationCAcert: platformIdentityProviderCert,
				ServiceName:       PlatformIdentityProviderServiceName,
			},
			"platform-id-auth": {
				Annotations: map[string]string{
					"haproxy.router.openshift.io/balance":        "source",
					"haproxy.router.openshift.io/rewrite-target": "/",
				},
				Name:              "platform-id-auth",
				RouteHost:         routeHost,
				RoutePath:         "/idauth",
				RoutePort:         9443,
				DestinationCAcert: platformAuthCert,
				ServiceName:       PlatformAuthServiceName,
			},
			"platform-id-provider": {
				Annotations: map[string]string{
					"haproxy.router.openshift.io/rewrite-target": "/",
				},
				Name:              "platform-id-provider",
				RouteHost:         routeHost,
				RoutePath:         "/idprovider/",
				RoutePort:         4300,
				DestinationCAcert: platformIdentityProviderCert,
				ServiceName:       PlatformIdentityProviderServiceName,
			},
			"platform-login": {
				Annotations: map[string]string{
					"haproxy.router.openshift.io/rewrite-target": fmt.Sprintf("/v1/auth/authorize?client_id=%s&redirect_uri=https://%s/auth/liberty/callback&response_type=code&scope=openid+email+profile&orig=/login", wlpClientID, routeHost),
				},
				Name:              "platform-login",
				RouteHost:         routeHost,
				RoutePath:         "/login",
				RoutePort:         4300,
				DestinationCAcert: platformIdentityProviderCert,
				ServiceName:       PlatformIdentityProviderServiceName,
			},
			"platform-oidc": {
				Annotations: map[string]string{
					"haproxy.router.openshift.io/balance": "source",
				},
				Name:              "platform-oidc",
				RouteHost:         routeHost,
				RoutePath:         "/oidc",
				RoutePort:         9443,
				DestinationCAcert: platformAuthCert,
				ServiceName:       PlatformAuthServiceName,
			},
			"saml-ui-callback": {
				Annotations: map[string]string{
					"haproxy.router.openshift.io/balance":        "source",
					"haproxy.router.openshift.io/rewrite-target": "/ibm/saml20/defaultSP/acs",
				},
				Name:              "saml-ui-callback",
				RouteHost:         routeHost,
				RoutePath:         "/ibm/saml20/defaultSP/acs",
				RoutePort:         9443,
				ServiceName:       PlatformAuthServiceName,
				DestinationCAcert: platformAuthCert,
			},
			"social-login-callback": {
				Annotations: map[string]string{
					"haproxy.router.openshift.io/balance":        "source",
					"haproxy.router.openshift.io/rewrite-target": "/ibm/api/social-login",
				},
				Name:              "social-login-callback",
				RouteHost:         routeHost,
				RoutePath:         "/ibm/api/social-login",
				RoutePort:         9443,
				ServiceName:       PlatformAuthServiceName,
				DestinationCAcert: platformAuthCert,
			},
		}

		for _, routeFields := range *allRoutesFields {
			for annotation, value := range commonRouteAnnotations {
				routeFields.Annotations[annotation] = value
			}
		}
		return
	}
}

func (r *AuthenticationReconciler) reconcileRoute(authCR *operatorv1alpha1.Authentication, fields *reconcileRouteFields) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		namespace := authCR.Namespace
		reqLogger := r.WithValues("name", fields.Name, "namespace", namespace)

		reqLogger.Info("Reconciling route", "annotations", fields.Annotations, "routeHost", fields.RouteHost, "routePath", fields.RoutePath)

		fCtx := logf.IntoContext(ctx, reqLogger)
		if shouldNotHaveRoutes(authCR) {
			return r.ensureRouteDoesNotExist(fCtx, authCR, fields)
		}

		return r.ensureRouteExists(fCtx, authCR, fields)
	}
}

func (r *AuthenticationReconciler) ensureRouteDoesNotExist(ctx context.Context, authCR *operatorv1alpha1.Authentication, fields *reconcileRouteFields) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)
	reqLogger.Info("Determined Route should not exist; removing if present")
	observedRoute := &routev1.Route{}
	err = r.Get(ctx, types.NamespacedName{Name: fields.Name, Namespace: authCR.Namespace}, observedRoute)
	if k8sErrors.IsNotFound(err) {
		return subreconciler.ContinueReconciling()
	} else if err != nil {
		reqLogger.Error(err, "Failed to get existing route for reconciliation")
		return subreconciler.RequeueWithError(err)
	}
	err = r.Delete(ctx, observedRoute)
	if err != nil {
		reqLogger.Error(err, "Failed to delete the Route")
		return subreconciler.RequeueWithError(err)
	}
	reqLogger.Info("Successfully deleted the Route")

	return subreconciler.RequeueWithDelay(defaultLowerWait)
}

func (r *AuthenticationReconciler) ensureRouteExists(ctx context.Context, authCR *operatorv1alpha1.Authentication, fields *reconcileRouteFields) (result *ctrl.Result, err error) {
	reqLogger := logf.FromContext(ctx)
	calculatedRoute, err := r.newRoute(authCR, fields)
	if err != nil {
		reqLogger.Error(err, "Error creating desired route for reconcilition")
		return
	}

	observedRoute := &routev1.Route{}
	err = r.Get(ctx, types.NamespacedName{Name: fields.Name, Namespace: authCR.Namespace}, observedRoute)
	if k8sErrors.IsNotFound(err) {
		reqLogger.Info("Route not found - creating")

		err = r.Create(ctx, calculatedRoute)
		if err != nil {
			if k8sErrors.IsAlreadyExists(err) {
				// Route already exists from a previous reconcile
				reqLogger.Info("Route already exists")
				return subreconciler.ContinueReconciling()
			}
			// Failed to create a new route
			reqLogger.Error(err, "Failed to create new route")
			return subreconciler.RequeueWithError(err)
		}
		// Requeue after creating new route
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	} else if err != nil {
		reqLogger.Error(err, "Failed to get existing route for reconciliation")
		return
	}
	// Determine if current route has changed
	reqLogger.Info("Comparing current and desired routes")

	// Preserve custom annotation settings observed in the cluster; skip changes to rewrite-target
	for annotation, value := range observedRoute.Annotations {
		if annotation != "haproxy.router.openshift.io/rewrite-target" {
			calculatedRoute.Annotations[annotation] = value
		} else if calculatedRoute.Annotations[annotation] != value {
			// Log when a rewrite-target annotation change has been ignored
			reqLogger.Info("Attempted change to \"haproxy.router.openshift.io/rewrite-target\" prevented", "value", value)
		}
	}

	// if observed route contains a non-empty certificate, caCertificate, and key, these values must be
	// retained
	if observedRoute.Spec.TLS != nil && observedRoute.Spec.TLS.Key != "" && observedRoute.Spec.TLS.Certificate != "" && observedRoute.Spec.TLS.CACertificate != "" {
		reqLogger.Info("Keeping custom TLS key, certificate, and CA certificate from observed Route in calculated Route")
		calculatedRoute.Spec.TLS.Key = observedRoute.Spec.TLS.Key
		calculatedRoute.Spec.TLS.Certificate = observedRoute.Spec.TLS.Certificate
		calculatedRoute.Spec.TLS.CACertificate = observedRoute.Spec.TLS.CACertificate
	}

	//routeHost is immutable so it must be checked first and the route recreated if it has changed
	if observedRoute.Spec.Host != calculatedRoute.Spec.Host {
		err = r.Delete(ctx, observedRoute)
		if err != nil {
			reqLogger.Error(err, "Route host changed, unable to delete existing route for recreate")
			return subreconciler.RequeueWithError(err)
		}
		//Recreate the route
		err = r.Create(ctx, calculatedRoute)
		if err != nil {
			reqLogger.Error(err, "Route host changed, unable to create new route")
			return subreconciler.RequeueWithError(err)
		}
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}

	if !IsRouteEqual(calculatedRoute, observedRoute) {
		reqLogger.Info("Updating route")

		observedRoute.Name = calculatedRoute.Name
		observedRoute.Annotations = calculatedRoute.Annotations
		observedRoute.Spec = calculatedRoute.Spec

		err = r.Update(ctx, observedRoute)
		if err != nil {
			reqLogger.Error(err, "Failed to update route")
			return subreconciler.RequeueWithError(err)
		}
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
	return subreconciler.ContinueReconciling()
}

func shouldNotHaveRoutes(authCR *operatorv1alpha1.Authentication) bool {
	return authCR.Spec.Config.ZenFrontDoor
}

// Use DeepEqual to determine if 2 routes are equal.
// Check annotations and Spec.
// If there are any differences, return false. Otherwise, return true.
func IsRouteEqual(oldRoute, newRoute *routev1.Route) bool {
	//logger := log.WithValues("name", oldRoute.Name, "namespace", oldRoute.Namespace)

	if !reflect.DeepEqual(oldRoute.Name, newRoute.Name) {
		//logger.Info("Names not equal", "old", oldRoute.Name, "new", newRoute.Name)
		return false
	}

	if !reflect.DeepEqual(oldRoute.Annotations, newRoute.Annotations) {
		//logger.Info("Annotations not equal",
		//	"old", fmt.Sprintf("%v", oldRoute.Annotations),
		//	"new", fmt.Sprintf("%v", newRoute.Annotations))
		return false
	}

	if !reflect.DeepEqual(oldRoute.Spec, newRoute.Spec) {
		//	//ugly, but don't print the CA to the log
		//	var loggedValues []interface{}

		//	loggedValues = append(loggedValues, "oldHost", oldRoute.Spec.Host, "newHost", newRoute.Spec.Host)

		//	loggedValues = append(loggedValues, "oldPath", oldRoute.Spec.Path, "newHost", newRoute.Spec.Path)

		//	loggedValues = append(loggedValues, "oldWildcardPolicy", oldRoute.Spec.WildcardPolicy, "newWildcardPolicy", newRoute.Spec.WildcardPolicy)

		//	loggedValues = append(loggedValues, "oldPort")
		//	if oldRoute.Spec.Port != nil {
		//		loggedValues = append(loggedValues, fmt.Sprintf("%v", oldRoute.Spec.Port))
		//	} else {
		//		loggedValues = append(loggedValues, "unset")
		//	}
		//	loggedValues = append(loggedValues, "newPort")
		//	if oldRoute.Spec.Port != nil {
		//		loggedValues = append(loggedValues, fmt.Sprintf("%v", newRoute.Spec.Port))
		//	} else {
		//		loggedValues = append(loggedValues, "unset")
		//	}

		//	loggedValues = append(loggedValues, "oldToService", fmt.Sprintf("%v", oldRoute.Spec.To))
		//	loggedValues = append(loggedValues, "newToService", fmt.Sprintf("%v", newRoute.Spec.To))

		//	loggedValues = append(loggedValues, "old.tls.termination")
		//	if oldRoute.Spec.TLS != nil {
		//		loggedValues = append(loggedValues, oldRoute.Spec.TLS.Termination)
		//	} else {
		//		loggedValues = append(loggedValues, "unset")
		//	}
		//	loggedValues = append(loggedValues, "new.tls.termination")
		//	if newRoute.Spec.TLS != nil {
		//		loggedValues = append(loggedValues, newRoute.Spec.TLS.Termination)
		//	} else {
		//		loggedValues = append(loggedValues, "unset")
		//	}

		//	loggedValues = append(loggedValues, "old.tls.insecureEdgeTerminationPolicy")
		//	if oldRoute.Spec.TLS != nil {
		//		loggedValues = append(loggedValues, oldRoute.Spec.TLS.InsecureEdgeTerminationPolicy)
		//	} else {
		//		loggedValues = append(loggedValues, "unset")
		//	}
		//	loggedValues = append(loggedValues, "new.tls.insecureEdgeTerminationPolicy")
		//	if newRoute.Spec.TLS != nil {
		//		loggedValues = append(loggedValues, newRoute.Spec.TLS.InsecureEdgeTerminationPolicy)
		//	} else {
		//		loggedValues = append(loggedValues, "unset")
		//	}

		//	logger.Info("Specs not equal", loggedValues...)
		return false
	}

	//logger.Info("Routes are equal")

	return true
}

func (r *AuthenticationReconciler) newRoute(authCR *operatorv1alpha1.Authentication, fields *reconcileRouteFields) (*routev1.Route, error) {
	namespace := authCR.Namespace

	reqLogger := r.WithValues("name", fields.Name, "namespace", namespace)

	weight := int32(100)

	commonLabel := map[string]string{"app": "im"}
	routeLabels := ctrlcommon.MergeMap(commonLabel, authCR.Spec.Labels)

	route := &routev1.Route{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Route",
			APIVersion: routev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        fields.Name,
			Namespace:   namespace,
			Annotations: fields.Annotations,
			Labels:      routeLabels,
		},
		Spec: routev1.RouteSpec{
			Host: fields.RouteHost,
			Path: fields.RoutePath,
			Port: &routev1.RoutePort{
				TargetPort: intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: fields.RoutePort,
				},
			},
			To: routev1.RouteTargetReference{
				Name:   fields.ServiceName,
				Kind:   "Service",
				Weight: &weight,
			},
			WildcardPolicy: routev1.WildcardPolicyNone,
		},
	}

	if len(fields.DestinationCAcert) > 0 {
		route.Spec.TLS = &routev1.TLSConfig{
			Termination:                   routev1.TLSTerminationReencrypt,
			InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
			DestinationCACertificate:      string(fields.DestinationCAcert),
		}
	}

	err := controllerutil.SetControllerReference(authCR, route, r.Client.Scheme())
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for route")
		return nil, err
	}

	return route, nil
}

func (r *AuthenticationReconciler) getClusterAddress(authCR *operatorv1alpha1.Authentication, clusterAddress *string) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		clusterInfoConfigMap := &corev1.ConfigMap{}

		clusterAddressFieldName := "cluster_address"

		fns := []subreconciler.Fn{
			r.getClusterInfoConfigMap(authCR, clusterInfoConfigMap),
			r.verifyConfigMapHasCorrectOwnership(authCR, clusterInfoConfigMap),
			r.verifyConfigMapHasField(authCR, clusterAddressFieldName, clusterInfoConfigMap),
		}

		for _, fn := range fns {
			if result, err = fn(ctx); subreconciler.ShouldRequeue(result, err) {
				return
			}
		}

		*clusterAddress = clusterInfoConfigMap.Data[clusterAddressFieldName]

		return subreconciler.ContinueReconciling()
	}
}

func (r *AuthenticationReconciler) getClusterInfoConfigMap(authCR *operatorv1alpha1.Authentication, cm *corev1.ConfigMap) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := logf.FromContext(ctx)
		err = r.Get(ctx, types.NamespacedName{Name: ClusterInfoConfigmapName, Namespace: authCR.Namespace}, cm)
		if k8sErrors.IsNotFound(err) {
			reqLogger.Info("ConfigMap was not found",
				"ConfigMap.Name", ClusterInfoConfigmapName,
				"ConfigMap.Namespace", authCR.Namespace)
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		} else if err != nil {
			reqLogger.Error(err, "Failed to get ConfigMap",
				"ConfigMap.Name", ClusterInfoConfigmapName,
				"ConfigMap.Namespace", authCR.Namespace)
			return subreconciler.RequeueWithError(err)
		}

		reqLogger.Info("ConfigMap found",
			"ConfigMap.Name", cm.Name,
			"ConfigMap.Namespace", cm.Namespace)
		return subreconciler.ContinueReconciling()
	}
}

func (r *AuthenticationReconciler) verifyConfigMapHasCorrectOwnership(authCR *operatorv1alpha1.Authentication, cm *corev1.ConfigMap) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := logf.FromContext(ctx)
		gvk := schema.GroupVersionKind{
			Group:   "operator.ibm.com",
			Version: "v1alpha1",
			Kind:    "Authentication",
		}
		if !ctrlcommon.IsOwnerOf(gvk, authCR, cm) {
			reqLogger.Info("ConfigMap is not owned by this Authentication",
				"ConfigMap.Name", cm.Name,
				"ConfigMap.Namespace", cm.Namespace)
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		}

		return subreconciler.ContinueReconciling()
	}
}

func (r *AuthenticationReconciler) verifyConfigMapHasField(authCR *operatorv1alpha1.Authentication, fieldName string, cm *corev1.ConfigMap) (fn subreconciler.Fn) {
	return func(_ context.Context) (result *ctrl.Result, err error) {
		if cm.Data == nil || len(cm.Data[fieldName]) == 0 {
			err = fmt.Errorf("field %q is not set in ConfigMap %s", fieldName, ClusterInfoConfigmapName)
			return subreconciler.RequeueWithError(err)
		}

		return subreconciler.ContinueReconciling()
	}
}

func (r *AuthenticationReconciler) ensureConfigMapHasEqualFields(authCR *operatorv1alpha1.Authentication, fields map[string]string, cm *corev1.ConfigMap) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := logf.FromContext(ctx)
		changed := false
		if cm.Data == nil {
			cm.Data = fields
			changed = true
			goto update
		}
		for fieldName, desiredValue := range fields {
			if observedValue, ok := cm.Data[fieldName]; ok && observedValue == desiredValue {
				continue
			}
			cm.Data[fieldName] = desiredValue
			changed = true
		}
		if !changed {
			reqLogger.Info("No changes to ConfigMap data fields needed", "ConfigMap.Name", cm.Name, "ConfigMap.Namespace", cm.Namespace)
			return subreconciler.ContinueReconciling()
		}
	update:
		if err = r.Update(ctx, cm); err != nil {
			reqLogger.Error(err, "Failed to update ConfigMap data fields", "ConfigMap.Name", cm.Name, "ConfigMap.Namespace", cm.Namespace)
			return subreconciler.RequeueWithError(err)
		}
		reqLogger.Info("Updated ConfigMap data fields successfully", "ConfigMap.Name", cm.Name, "ConfigMap.Namespace", cm.Namespace)
		return subreconciler.RequeueWithDelay(defaultLowerWait)
	}
}

func (r *AuthenticationReconciler) getWlpClientID(authCR *operatorv1alpha1.Authentication, wlpClientID *string) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := logf.FromContext(ctx)

		PlatformOIDCCredentialsSecretName := "platform-oidc-credentials"
		secret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: PlatformOIDCCredentialsSecretName, Namespace: authCR.Namespace}, secret)

		if k8sErrors.IsNotFound(err) {
			reqLogger.Info("Secret was not found",
				"Secret.Name", PlatformOIDCCredentialsSecretName,
				"Secret.Namespace", authCR.Namespace)
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		} else if err != nil {
			reqLogger.Error(err, "Failed to get secret",
				"Secret.Name", PlatformOIDCCredentialsSecretName,
				"Secret.Namespace", authCR.Namespace)
			return subreconciler.RequeueWithError(err)
		}

		*wlpClientID = string(secret.Data["WLP_CLIENT_ID"][:])

		return subreconciler.ContinueReconciling()
	}
}

// getCertificateForService uses the provided Service name to determine which Secret contains the matching certificate
// data and returns it.
func (r *AuthenticationReconciler) getCertificateForService(serviceName string, authCR *operatorv1alpha1.Authentication, certificate *[]byte) (fn subreconciler.Fn) {
	return func(ctx context.Context) (result *ctrl.Result, err error) {
		reqLogger := r.WithValues("func", "getCertificateForService", "namespace", authCR.Namespace)
		secret := &corev1.Secret{}
		var secretName string
		switch serviceName {
		case PlatformAuthServiceName:
			secretName = "platform-auth-secret"
		case PlatformIdentityManagementServiceName:
			secretName = "platform-identity-management"
		case PlatformIdentityProviderServiceName:
			secretName = "identity-provider-secret"
		default:
			err = fmt.Errorf("Service %q does not have a certificate secret managed by this controller", serviceName)
			return subreconciler.RequeueWithError(err)
		}
		err = r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: authCR.Namespace}, secret)
		if k8sErrors.IsNotFound(err) {
			reqLogger.Info("unable to get Route destination certificate, Secret does exist. Requeue and try again", "secretName", secretName)
			return subreconciler.RequeueWithDelay(defaultLowerWait)
		} else if err != nil {
			reqLogger.Error(err, "failed to get Route destination certificate", "secretName", secretName)
			subreconciler.RequeueWithError(err)
		}

		caCrt, ok := secret.Data["ca.crt"]
		if !ok || len(caCrt) == 0 {
			err = fmt.Errorf("found Secret %q, but \"ca.crt\" was empty", secretName)
			return subreconciler.RequeueWithError(err)
		}
		*certificate = append(*certificate, caCrt...)
		return subreconciler.ContinueReconciling()
	}
}
