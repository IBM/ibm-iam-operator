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

	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	"github.com/IBM/ibm-iam-operator/controllers/common"
)

const ClusterInfoConfigmapName = "ibmcloud-cluster-info"
const PlatformAuthServiceName = "platform-auth-service"
const PlatformIdentityManagementServiceName = "platform-identity-management"
const PlatformIdentityProviderServiceName = "platform-identity-provider"
const DefaultHTTPBackendServiceName = "default-http-backend"

// getCertificateForService uses the provided Service name to determine which Secret contains the matching certificate
// data and returns it.
func (r *AuthenticationReconciler) getCertificateForService(ctx context.Context, serviceName string, instance *operatorv1alpha1.Authentication, needToRequeue *bool) (certificate []byte, err error) {
	reqLogger := log.WithValues("func", "getCertificateForService", "namespace", instance.Namespace)
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
		err = fmt.Errorf("service %q does not have a certificate secret managed by this controller", serviceName)
		return
	}
	err = r.Client.Get(ctx, types.NamespacedName{Name: secretName, Namespace: instance.Namespace}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("unable to get route destination certificate, secret does exist. Requeue and try again", "secretName", secretName)
			*needToRequeue = true
			err = nil
			return
		}
		reqLogger.Error(err, "failed to get route destination certificate", "secretName", secretName)
		return
	}
	certificate, ok := secret.Data["ca.crt"]
	if !ok || len(certificate) == 0 {
		err = fmt.Errorf("found secret %q, but \"ca.crt\" was empty", secretName)
	}
	return
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

func (r *AuthenticationReconciler) handleRoutes(ctx context.Context, instance *operatorv1alpha1.Authentication, needToRequeue *bool) (err error) {

	reqLogger := log.WithValues("func", "ReconcileRoutes", "namespace", instance.Namespace)

	//Get the destination cert for the route

	//Get the routehost from the ibmcloud-cluster-info configmap
	routeHost := ""
	clusterInfoConfigMap := &corev1.ConfigMap{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: ClusterInfoConfigmapName, Namespace: instance.Namespace}, clusterInfoConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			*needToRequeue = true
		}
		reqLogger.Error(err, "Failed to get cluster info configmap "+ClusterInfoConfigmapName, "requeueNeeded", needToRequeue)
		if errors.IsNotFound(err) {
			err = nil
		}
		return
	}

	// Check if the ibmcloud-cluster-info created by IM-Operator
	ownerRefs := clusterInfoConfigMap.OwnerReferences
	var ownRef string
	for _, ownRefs := range ownerRefs {
		ownRef = ownRefs.Kind
	}
	if ownRef != "Authentication" {
		reqLogger.Info("Reconcile Routes : Can't find ibmcloud-cluster-info Configmap created by IM operator , IM Route reconcilation may not proceed ", "Configmap.Namespace", clusterInfoConfigMap.Namespace, "ConfigMap.Name", "ibmcloud-cluster-info")
		*needToRequeue = true
		return
	}

	if clusterInfoConfigMap.Data == nil || len(clusterInfoConfigMap.Data["cluster_address"]) == 0 {
		err = fmt.Errorf("cluster_address is not set in configmap %s", ClusterInfoConfigmapName)
		return
	}

	PlatformOIDCCredentialsSecretName := "platform-oidc-credentials"
	secret := &corev1.Secret{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: PlatformOIDCCredentialsSecretName, Namespace: instance.Namespace}, secret)

	if err != nil {
		if errors.IsNotFound(err) {
			*needToRequeue = true
		}
		reqLogger.Error(err, "Failed to get secret", "secretName", PlatformOIDCCredentialsSecretName, "requeueNeeded", *needToRequeue)
		if errors.IsNotFound(err) {
			err = nil
		}
		return
	}

	routeHost = clusterInfoConfigMap.Data["cluster_address"]
	wlpClientID := string(secret.Data["WLP_CLIENT_ID"][:])

	var (
		platformAuthCert               []byte
		platformIdentityManagementCert []byte
		platformIdentityProviderCert   []byte
	)
	platformAuthCert, err = r.getCertificateForService(ctx, PlatformAuthServiceName, instance, needToRequeue)
	if err != nil {
		reqLogger.Info("Unable to get certificate for service", "serviceName", PlatformAuthServiceName, "requeueNeeded", *needToRequeue)
		return
	}
	platformIdentityManagementCert, err = r.getCertificateForService(ctx, PlatformIdentityManagementServiceName, instance, needToRequeue)
	if err != nil {
		reqLogger.Info("Unable to get certificate for service", "serviceName", PlatformIdentityManagementServiceName, "requeueNeeded", *needToRequeue)
		return
	}
	platformIdentityProviderCert, err = r.getCertificateForService(ctx, PlatformIdentityProviderServiceName, instance, needToRequeue)
	if err != nil {
		reqLogger.Info("Unable to get certificate for service", "serviceName", PlatformIdentityProviderServiceName, "requeueNeeded", *needToRequeue)
		return
	}

	allRoutesFields := map[string]*reconcileRouteFields{
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
	commonAnnotations := map[string]string{
		"haproxy.router.openshift.io/timeout":                               "180s",
		"haproxy.router.openshift.io/pod-concurrent-connections":            "200",
		"haproxy.router.openshift.io/rate-limit-connections":                "true",
		"haproxy.router.openshift.io/rate-limit-connections.concurrent-tcp": "200",
		"haproxy.router.openshift.io/rate-limit-connections.rate-tcp":       "200",
		"haproxy.router.openshift.io/rate-limit-connections.rate-http":      "200",
		"haproxy.router.openshift.io/hsts_header":                           "max-age=31536000;includeSubDomains",
	}

	for _, routeFields := range allRoutesFields {
		for annotation, value := range commonAnnotations {
			routeFields.Annotations[annotation] = value
		}
		err = r.reconcileRoute(ctx, instance, routeFields, needToRequeue)
		if err != nil {
			return
		}
	}

	return
}

func (r *AuthenticationReconciler) removeIdauth(ctx context.Context, instance *operatorv1alpha1.Authentication) (err error) {
	namespace := instance.Namespace
	reqLogger := log.WithValues("func", "ReconcileRoute", "namespace", namespace)
	reqLogger.Info("Determined platform-id-auth Route should not exist; removing if present")
	observedRoute := &routev1.Route{}
	err = r.Get(ctx, types.NamespacedName{Name: "platform-id-auth", Namespace: namespace}, observedRoute)
	if errors.IsNotFound(err) {
		return
	} else if err != nil {
		reqLogger.Error(err, "Failed to get existing platform-id-auth route for reconciliation")
		return 
	}
	err = r.Delete(ctx, observedRoute)
	if err != nil {
		reqLogger.Error(err, "Failed to delete platform-id-auth Route")
		return
	}
	reqLogger.Info("Successfully deleted platform-id-auth Route")
	return 
}

func (r *AuthenticationReconciler) reconcileRoute(ctx context.Context, instance *operatorv1alpha1.Authentication, fields *reconcileRouteFields, needToRequeue *bool) (err error) {

	namespace := instance.Namespace
	reqLogger := log.WithValues("func", "ReconcileRoute", "name", fields.Name, "namespace", namespace)

	reqLogger.Info("Reconciling route", "annotations", fields.Annotations, "routeHost", fields.RouteHost, "routePath", fields.RoutePath)

	err = r.removeIdauth(ctx, instance)
	if err != nil {
		reqLogger.Error(err, "Error deleting platform-id-auth Route")
		return
	}

	calculatedRoute, err := r.newRoute(instance, fields)
	if err != nil {
		reqLogger.Error(err, "Error creating desired route for reconcilition")
		return
	}

	observedRoute := &routev1.Route{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: fields.Name, Namespace: namespace}, observedRoute)
	if err != nil && !errors.IsNotFound(err) {
		reqLogger.Error(err, "Failed to get existing route for reconciliation")
		return
	}

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Route not found - creating")

		err = r.Client.Create(ctx, calculatedRoute)
		if err != nil {
			if errors.IsAlreadyExists(err) {
				// Route already exists from a previous reconcile
				reqLogger.Info("Route already exists")
				*needToRequeue = true
			} else {
				// Failed to create a new route
				reqLogger.Error(err, "Failed to create new route")
				return
			}
		} else {
			// Requeue after creating new route
			*needToRequeue = true
		}
	} else {
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
			err = r.Client.Delete(ctx, observedRoute)
			if err != nil {
				reqLogger.Error(err, "Route host changed, unable to delete existing route for recreate")
				return
			}
			//Recreate the route
			err = r.Client.Create(ctx, calculatedRoute)
			if err != nil {
				reqLogger.Error(err, "Route host changed, unable to create new route")
				return
			}
			*needToRequeue = true
			return
		}

		if !IsRouteEqual(calculatedRoute, observedRoute) {
			reqLogger.Info("Updating route")

			observedRoute.ObjectMeta.Name = calculatedRoute.ObjectMeta.Name
			observedRoute.ObjectMeta.Annotations = calculatedRoute.ObjectMeta.Annotations
			observedRoute.Spec = calculatedRoute.Spec

			err = r.Client.Update(ctx, observedRoute)
			if err != nil {
				reqLogger.Error(err, "Failed to update route")
				return
			}
			*needToRequeue = true
		}
	}
	return
}

// Use DeepEqual to determine if 2 routes are equal.
// Check annotations and Spec.
// If there are any differences, return false. Otherwise, return true.
func IsRouteEqual(oldRoute, newRoute *routev1.Route) bool {
	logger := log.WithValues("func", "IsRouteEqual", "name", oldRoute.Name, "namespace", oldRoute.Namespace)

	if !reflect.DeepEqual(oldRoute.ObjectMeta.Name, newRoute.ObjectMeta.Name) {
		logger.Info("Names not equal", "old", oldRoute.ObjectMeta.Name, "new", newRoute.ObjectMeta.Name)
		return false
	}

	if !reflect.DeepEqual(oldRoute.ObjectMeta.Annotations, newRoute.ObjectMeta.Annotations) {
		logger.Info("Annotations not equal",
			"old", fmt.Sprintf("%v", oldRoute.ObjectMeta.Annotations),
			"new", fmt.Sprintf("%v", newRoute.ObjectMeta.Annotations))
		return false
	}

	if !reflect.DeepEqual(oldRoute.Spec, newRoute.Spec) {
		//ugly, but don't print the CA to the log
		var loggedValues []interface{}

		loggedValues = append(loggedValues, "oldHost", oldRoute.Spec.Host, "newHost", newRoute.Spec.Host)

		loggedValues = append(loggedValues, "oldPath", oldRoute.Spec.Path, "newHost", newRoute.Spec.Path)

		loggedValues = append(loggedValues, "oldWildcardPolicy", oldRoute.Spec.WildcardPolicy, "newWildcardPolicy", newRoute.Spec.WildcardPolicy)

		loggedValues = append(loggedValues, "oldPort")
		if oldRoute.Spec.Port != nil {
			loggedValues = append(loggedValues, fmt.Sprintf("%v", oldRoute.Spec.Port))
		} else {
			loggedValues = append(loggedValues, "unset")
		}
		loggedValues = append(loggedValues, "newPort")
		if oldRoute.Spec.Port != nil {
			loggedValues = append(loggedValues, fmt.Sprintf("%v", newRoute.Spec.Port))
		} else {
			loggedValues = append(loggedValues, "unset")
		}

		loggedValues = append(loggedValues, "oldToService", fmt.Sprintf("%v", oldRoute.Spec.To))
		loggedValues = append(loggedValues, "newToService", fmt.Sprintf("%v", newRoute.Spec.To))

		loggedValues = append(loggedValues, "old.tls.termination")
		if oldRoute.Spec.TLS != nil {
			loggedValues = append(loggedValues, oldRoute.Spec.TLS.Termination)
		} else {
			loggedValues = append(loggedValues, "unset")
		}
		loggedValues = append(loggedValues, "new.tls.termination")
		if newRoute.Spec.TLS != nil {
			loggedValues = append(loggedValues, newRoute.Spec.TLS.Termination)
		} else {
			loggedValues = append(loggedValues, "unset")
		}

		loggedValues = append(loggedValues, "old.tls.insecureEdgeTerminationPolicy")
		if oldRoute.Spec.TLS != nil {
			loggedValues = append(loggedValues, oldRoute.Spec.TLS.InsecureEdgeTerminationPolicy)
		} else {
			loggedValues = append(loggedValues, "unset")
		}
		loggedValues = append(loggedValues, "new.tls.insecureEdgeTerminationPolicy")
		if newRoute.Spec.TLS != nil {
			loggedValues = append(loggedValues, newRoute.Spec.TLS.InsecureEdgeTerminationPolicy)
		} else {
			loggedValues = append(loggedValues, "unset")
		}

		logger.Info("Specs not equal", loggedValues...)
		return false
	}

	logger.Info("Routes are equal")

	return true
}

func (r *AuthenticationReconciler) newRoute(instance *operatorv1alpha1.Authentication, fields *reconcileRouteFields) (*routev1.Route, error) {
	namespace := instance.Namespace

	reqLogger := log.WithValues("func", "GetDesiredRoute", "name", fields.Name, "namespace", namespace)

	weight := int32(100)

	commonLabel := map[string]string{"app": "im"}
	routeLabels := common.MergeMap(commonLabel, instance.Spec.Labels)

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

	err := controllerutil.SetControllerReference(instance, route, r.Client.Scheme())
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for route")
		return nil, err
	}

	return route, nil
}
