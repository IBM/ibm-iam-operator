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

package authentication

import (
	"context"
	"fmt"
	"reflect"
  "time"

	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
)

const ClusterInfoConfigmapName = "ibmcloud-cluster-info"
const PlatformAuthServiceName = "platform-auth-service"
const PlatformIdentityManagementServiceName = "platform-identity-management"
const PlatformIdentityProviderServiceName = "platform-identity-provider"
const DefaultHTTPBackendServiceName = "default-http-backend"

// getCertificateForService uses the provided Service name to determine which Secret contains the matching certificate
// data and returns it.
func (r *ReconcileAuthentication) getCertificateForService(ctx context.Context, serviceName string, instance *operatorv1alpha1.Authentication) (certificate []byte, err error) {
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
    return nil, fmt.Errorf("service %q does not have a certificate secret managed by this controller", serviceName)
  }
  err = r.client.Get(ctx, types.NamespacedName{Name: secretName, Namespace: instance.Namespace}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("unable to get route destination certificate, secret does exist. Requeue and try again", "secretName", secretName)
			r.needToRequeue = true
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
  Name string
  Annotations map[string]string
  RouteHost string
  RoutePath string
  RoutePort int32
  ServiceName string
  DestinationCAcert []byte
}

// signalRequeueIfIsNotFound flags that the reconcile loop needs to be requeued if the error is a IsNotFound error from
// the Kubernetes controller runtime client. If the flag is set, the error is unset in order to avoid flowing down
// error-related paths.
func (r *ReconcileAuthentication) signalRequeueIfIsNotFound(err *error) {
  if errors.IsNotFound(*err) {
    r.needToRequeue = true
    *err = nil
  }
}

func (r *ReconcileAuthentication) reconcileRoutes(ctx context.Context, instance *operatorv1alpha1.Authentication) (err error) {

	reqLogger := log.WithValues("func", "ReconcileRoutes", "namespace", instance.Namespace)

	//Get the destination cert for the route

	//Get the routehost from the ibmcloud-cluster-info configmap
	routeHost := ""
	clusterInfoConfigMap := &corev1.ConfigMap{}
	err = r.client.Get(ctx, types.NamespacedName{Name: ClusterInfoConfigmapName, Namespace: instance.Namespace}, clusterInfoConfigMap)
	if err != nil {
    r.signalRequeueIfIsNotFound(&err)
		reqLogger.Error(err, "Failed to get cluster info configmap "+ClusterInfoConfigmapName, "requeueNeeded", r.needToRequeue)
		return
	}

	if clusterInfoConfigMap.Data == nil || len(clusterInfoConfigMap.Data["cluster_address"]) == 0 {
		return fmt.Errorf("cluster_address is not set in configmap %s", ClusterInfoConfigmapName)
	}

  PlatformOIDCCredentialsSecretName := "platform-oidc-credentials"
  secret := &corev1.Secret{}
  err = r.client.Get(ctx, types.NamespacedName{Name: PlatformOIDCCredentialsSecretName, Namespace: instance.Namespace}, secret)

	if err != nil {
    r.signalRequeueIfIsNotFound(&err)
		reqLogger.Error(err, "Failed to get secret", "secretName", PlatformOIDCCredentialsSecretName, "requeueNeeded", r.needToRequeue)
		return
	}

	routeHost = clusterInfoConfigMap.Data["cluster_address"]
  wlpClientID := string(secret.Data["WLP_CLIENT_ID"][:])

  now := time.Now().Unix()
  
  var (
    platformAuthCert []byte 
    platformIdentityManagementCert []byte
    platformIdentityProviderCert []byte
  )
  platformAuthCert, err = r.getCertificateForService(ctx, PlatformAuthServiceName, instance)
  if err != nil {
    r.signalRequeueIfIsNotFound(&err)
    reqLogger.Info("Unable to get certificate for service", "serviceName", PlatformAuthServiceName, "requeueNeeded", r.needToRequeue)
    return
  }
  platformIdentityManagementCert, err = r.getCertificateForService(ctx, PlatformIdentityManagementServiceName, instance)
  if err != nil {
    r.signalRequeueIfIsNotFound(&err)
    reqLogger.Info("Unable to get certificate for service", "serviceName", PlatformIdentityManagementServiceName, "requeueNeeded", r.needToRequeue)
    return
  }
  platformIdentityProviderCert, err = r.getCertificateForService(ctx, PlatformIdentityProviderServiceName, instance)
  if err != nil {
    reqLogger.Info("Unable to get certificate for service", "serviceName", PlatformIdentityProviderServiceName, "requeueNeeded", r.needToRequeue)
    r.signalRequeueIfIsNotFound(&err)
    return
  }

  //commonAnnotations := map[string]string{
  //  "haproxy.router.openshift.io/rate-limit-connections": "true",
  //  "haproxy.router.openshift.io/rate-limit-connections.rate-http": "200",
  //  "haproxy.router.openshift.io/rate-limit-connections.concurrent-tcp": "10",
  //  "haproxy.router.openshift.io/timeout": "300s",
  //}
  allRoutesFields := map[string]*reconcileRouteFields{
    "ibmid-ui-callback": {
      Annotations: map[string]string{
        "haproxy.router.openshift.io/rewrite-target": "/oidcclient/redirect/ICP_IBMID",
      },
      Name: "ibmid-ui-callback",
      RouteHost: routeHost,
      RoutePath: "/oidcclient/redirect/ICP_IBMID",
      RoutePort: 9443,
      ServiceName: PlatformAuthServiceName,
      DestinationCAcert: platformAuthCert,
    },
    "id-mgmt": {
      Annotations: map[string]string{
        "haproxy.router.openshift.io/rewrite-target": "/idmgmt/",
        "haproxy.router.openshift.io/hsts_header": "max-age=31536000;includeSubDomains",
      },
      Name: "id-mgmt",
      RouteHost: routeHost,
      RoutePath: "/idmgmt/",
      RoutePort: 4500,
      ServiceName: PlatformIdentityManagementServiceName,
      DestinationCAcert: platformIdentityManagementCert,
    },
    "idmgmt-v2-api": {
      Annotations: map[string]string{
        "haproxy.router.openshift.io/hsts_header": "max-age=31536000;includeSubDomains",
        "haproxy.router.openshift.io/rewrite-target": "/identity/api/v1/teams/resources",
      },
      Name: "idmgmt-v2-api",
      RouteHost: routeHost,
      RoutePath: "/idmgmt/identity/api/v2/teams/resources",
      RoutePort: 4500,
      ServiceName: PlatformIdentityManagementServiceName,
      DestinationCAcert: platformIdentityManagementCert,
    },
    "platform-auth": {
      Annotations: map[string]string{
        "haproxy.router.openshift.io/hsts_header": "max-age=31536000;includeSubDomains",
        "haproxy.router.openshift.io/rewrite-target": "/v1/auth/",
      },
      Name: "platform-auth",
      RouteHost: routeHost,
      RoutePath: "/v1/auth/",
      RoutePort: 4300,
      DestinationCAcert: platformIdentityProviderCert,
      ServiceName: PlatformIdentityProviderServiceName,
    },
    "platform-id-auth": {
      Annotations: map[string]string{
        "haproxy.router.openshift.io/hsts_header": "max-age=31536000;includeSubDomains",
        "haproxy.router.openshift.io/rewrite-target": "/",
      },
      Name: "platform-id-auth",
      RouteHost: routeHost,
      RoutePath: "/idauth",
      RoutePort: 9443,
      DestinationCAcert: platformAuthCert,
      ServiceName: PlatformAuthServiceName,
    },
    "platform-id-provider": {
      Annotations: map[string]string{
        "haproxy.router.openshift.io/hsts_header": "max-age=31536000;includeSubDomains",
        "haproxy.router.openshift.io/rewrite-target": "/",
      },
      Name: "platform-id-provider",
      RouteHost: routeHost,
      RoutePath: "/idprovider/",
      RoutePort: 4300,
      DestinationCAcert: platformIdentityProviderCert,
      ServiceName: PlatformIdentityProviderServiceName,
    },
    "platform-login": {
      Annotations: map[string]string{
        "haproxy.router.openshift.io/hsts_header": "max-age=31536000;includeSubDomains",
        "haproxy.router.openshift.io/rewrite-target": fmt.Sprintf("/v1/auth/authorize?client_id=%s&redirect_uri=https://%s/auth/liberty/callback&response_type=code&scope=openid+email+profile&state=%d&orig=/login", wlpClientID, routeHost, now),
      },
      Name: "platform-login",
      RouteHost: routeHost,
      RoutePath: "/login",
      RoutePort: 4300,
      DestinationCAcert: platformIdentityProviderCert,
      ServiceName: PlatformIdentityProviderServiceName,
    },
    "platform-oidc": {
      Annotations: map[string]string{
        "haproxy.router.openshift.io/hsts_header": "max-age=31536000;includeSubDomains",
      },
      Name: "platform-oidc",
      RouteHost: routeHost,
      RoutePath: "/oidc",
      RoutePort: 9443,
      DestinationCAcert: platformAuthCert,
      ServiceName: PlatformAuthServiceName,
    },
    "saml-ui-callback": {
      Annotations: map[string]string{
        "haproxy.router.openshift.io/hsts_header": "max-age=31536000;includeSubDomains",
        "haproxy.router.openshift.io/rewrite-target": "/",
      },
      Name: "saml-ui-callback",
      RouteHost: routeHost,
      RoutePath: "/ibm/saml20/defaultSP/acs",
      RoutePort: 9443,
      ServiceName: PlatformAuthServiceName,
      DestinationCAcert: platformAuthCert,
    },
  }

  for _, routeFields := range allRoutesFields {
    err = r.reconcileRoute(ctx, instance, routeFields)
    if err != nil {
      return err
    }
  }

	return
}

func (r *ReconcileAuthentication) reconcileRoute(ctx context.Context, instance *operatorv1alpha1.Authentication, fields *reconcileRouteFields) error {

	namespace := instance.Namespace
	reqLogger := log.WithValues("func", "ReconcileRoute", "name", fields.Name, "namespace", namespace)

	reqLogger.Info("Reconciling route", "annotations", fields.Annotations, "routeHost", fields.RouteHost, "routePath", fields.RoutePath)

	desiredRoute, err := r.newRoute(instance, fields)
	if err != nil {
		reqLogger.Error(err, "Error creating desired route for reconcilition")
		return err
	}

	route := &routev1.Route{}
	err = r.client.Get(ctx, types.NamespacedName{Name: fields.Name, Namespace: namespace}, route)
	if err != nil && !errors.IsNotFound(err) {
		reqLogger.Error(err, "Failed to get existing route for reconciliation")
		return err
	}

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Route not found - creating")

		err = r.client.Create(ctx, desiredRoute)
		if err != nil {
			if errors.IsAlreadyExists(err) {
				// Route already exists from a previous reconcile
				reqLogger.Info("Route already exists")
				r.needToRequeue = true
			} else {
				// Failed to create a new route
				reqLogger.Error(err, "Failed to create new route")
				return err
			}
		} else {
			// Requeue after creating new route
			r.needToRequeue = true
		}
	} else {
		// Determine if current route has changed
		reqLogger.Info("Comparing current and desired routes")

		//routeHost is immutable so it must be checked first and the route recreated if it has changed
		if route.Spec.Host != desiredRoute.Spec.Host {
			err = r.client.Delete(ctx, route)
			if err != nil {
				reqLogger.Error(err, "Route host changed, unable to delete existing route for recreate")
				return err
			}
			//Recreate the route
			err = r.client.Create(ctx, desiredRoute)
			if err != nil {
				reqLogger.Error(err, "Route host changed, unable to create new route")
				return err
			}
			r.needToRequeue = true
			return nil
		}

		if !IsRouteEqual(route, desiredRoute) {
			reqLogger.Info("Updating route")

			route.ObjectMeta.Name = desiredRoute.ObjectMeta.Name
			route.ObjectMeta.Annotations = desiredRoute.ObjectMeta.Annotations
			route.Spec = desiredRoute.Spec

			err = r.client.Update(ctx, route)
			if err != nil {
				reqLogger.Error(err, "Failed to update route")
				return err
			}
		}
	}
	return nil
}

// Use DeepEqual to determine if 2 routes are equal.
// Check annotations and Spec.
// If there are any differences, return false. Otherwise, return true.
func IsRouteEqual(oldRoute, newRoute *routev1.Route) bool {
	logger := log.WithValues("func", "IsRouteEqual")

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
		logger.Info("Specs not equal", "oldHost", oldRoute.Spec.Host, "newHost", newRoute.Spec.Host,
			"oldPath", oldRoute.Spec.Path, "newHost", newRoute.Spec.Path,
			"oldWildcardPolicy", oldRoute.Spec.WildcardPolicy, "newWildcardPolicy", newRoute.Spec.WildcardPolicy,
			"oldPort", fmt.Sprintf("%v", oldRoute.Spec.Port), "newPort", fmt.Sprintf("%v", newRoute.Spec.Port),
			"oldToService", fmt.Sprintf("%v", oldRoute.Spec.To), "newToService", fmt.Sprintf("%v", newRoute.Spec.To),
			"old.tls.termination", oldRoute.Spec.TLS.Termination, "new.tls.termination", newRoute.Spec.TLS.Termination,
			"old.tls.insecureEdgeTerminationPolicy", oldRoute.Spec.TLS.InsecureEdgeTerminationPolicy,
			"new.tls.insecureEdgeTerminationPolicy", newRoute.Spec.TLS.InsecureEdgeTerminationPolicy)
		return false
	}

	logger.Info("Routes are equal")

	return true
}


func (r *ReconcileAuthentication) newRoute(instance *operatorv1alpha1.Authentication, fields *reconcileRouteFields) (*routev1.Route, error) {
  namespace := instance.Namespace

	reqLogger := log.WithValues("func", "GetDesiredRoute", "name", fields.Name, "namespace", namespace)

	weight := int32(100)

	route := &routev1.Route{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Route",
			APIVersion: routev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        fields.Name,
			Namespace:   namespace,
			Annotations: fields.Annotations,
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

	err := controllerutil.SetControllerReference(instance, route, r.client.Scheme())
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for route")
		return nil, err
	}

	return route, nil
}
