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

	route "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
)

const CnRouteName = "common-web-ui"
const CnRoutePath = "/common-nav"

const CbRouteName = "common-web-ui-callback"
const CbRoutePath = "/auth/liberty/callback"
const UICertSecretName = "common-web-ui-cert" + ""
const ClusterInfoConfigmapName = "ibmcloud-cluster-info"
const ServiceName = "common-web-ui"

func ReconcileRoutes(ctx context.Context, client client.Client, instance *operatorv1alpha1.Authentication, needToRequeue *bool) error {

	reqLogger := log.WithValues("func", "ReconcileRoutes", "namespace", instance.Namespace)

	//Get the destination cert for the route
	secret := &corev1.Secret{}
	err := client.Get(ctx, types.NamespacedName{Name: UICertSecretName, Namespace: instance.Namespace}, secret)

	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Unable to get route destination certificate, secret does exist. Requeue and try again", "SecretName", UICertSecretName)
			*needToRequeue = true
			return nil
		}
		reqLogger.Error(err, "Failed to get route destination certificate "+UICertSecretName)
		return err
	}
	destinationCAcert := secret.Data["ca.crt"]

	//Get the routehost from the ibmcloud-cluster-info configmap
	routeHost := ""
	clusterInfoConfigMap := &corev1.ConfigMap{}
	err = client.Get(ctx, types.NamespacedName{Name: ClusterInfoConfigmapName, Namespace: instance.Namespace}, clusterInfoConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			//The ibmcloud-cluster-info configmap doesn't exist, reque and try again
			reqLogger.Info("Cluster info configmap was not found.  Requeue and try again", "configmapName", ClusterInfoConfigmapName)
			*needToRequeue = true
			return nil
		}

		reqLogger.Error(err, "Failed to get cluster info configmap "+ClusterInfoConfigmapName)
		return err
	}

	if clusterInfoConfigMap.Data == nil || len(clusterInfoConfigMap.Data["cluster_address"]) == 0 {
		return fmt.Errorf("cluster_address is not set in configmap %s", ClusterInfoConfigmapName)
	}

	routeHost = clusterInfoConfigMap.Data["cluster_address"]

	cnAnnotations := map[string]string{"haproxy.router.openshift.io/rewrite-target": CnRoutePath,
		"haproxy.router.openshift.io/timeout": "90s"}

	err = ReconcileRoute(ctx, client, instance, CnRouteName, cnAnnotations, routeHost, CnRoutePath, destinationCAcert, needToRequeue)
	if err != nil {
		return err
	}

	cbAnnotations := map[string]string{"haproxy.router.openshift.io/rewrite-target": CbRoutePath,
		"haproxy.router.openshift.io/timeout": "90s"}

	err = ReconcileRoute(ctx, client, instance, CbRouteName, cbAnnotations, routeHost, CbRoutePath, destinationCAcert, needToRequeue)
	if err != nil {
		return err
	}

	return nil
}

func ReconcileRoute(ctx context.Context, client client.Client, instance *operatorv1alpha1.Authentication,
	name string, annotations map[string]string, routeHost string, routePath string, destinationCAcert []byte, needToRequeue *bool) error {

	namespace := instance.Namespace
	reqLogger := log.WithValues("func", "ReconcileRoute", "name", name, "namespace", namespace)

	reqLogger.Info("Reconciling route", "annotations", annotations, "routeHost", routeHost, "routePath", routePath)

	desiredRoute, err := GetDesiredRoute(client, instance, name, namespace, annotations, routeHost, routePath, destinationCAcert)
	if err != nil {
		reqLogger.Error(err, "Error creating desired route for reconcilition")
		return err
	}

	route := &route.Route{}
	err = client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, route)
	if err != nil && !errors.IsNotFound(err) {
		reqLogger.Error(err, "Failed to get existing route for reconciliation")
		return err
	}

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Route not found - creating")

		err = client.Create(ctx, desiredRoute)
		if err != nil {
			if errors.IsAlreadyExists(err) {
				// Route already exists from a previous reconcile
				reqLogger.Info("Route already exists")
				*needToRequeue = true
			} else {
				// Failed to create a new route
				reqLogger.Error(err, "Failed to create new route")
				return err
			}
		} else {
			// Requeue after creating new route
			*needToRequeue = true
		}
	} else {
		// Determine if current route has changed
		reqLogger.Info("Comparing current and desired routes")

		//routeHost is immutable so it must be checked first and the route recreated if it has changed
		if route.Spec.Host != desiredRoute.Spec.Host {
			err = client.Delete(ctx, route)
			if err != nil {
				reqLogger.Error(err, "Route host changed, unable to delete existing route for recreate")
				return err
			}
			//Recreate the route
			err = client.Create(ctx, desiredRoute)
			if err != nil {
				reqLogger.Error(err, "Route host changed, unable to create new route")
				return err
			}
			*needToRequeue = true
			return nil
		}

		if !IsRouteEqual(route, desiredRoute) {
			reqLogger.Info("Updating route")

			route.ObjectMeta.Name = desiredRoute.ObjectMeta.Name
			route.ObjectMeta.Annotations = desiredRoute.ObjectMeta.Annotations
			route.Spec = desiredRoute.Spec

			err = client.Update(ctx, route)
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
func IsRouteEqual(oldRoute, newRoute *route.Route) bool {
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

func GetDesiredRoute(client client.Client, instance *operatorv1alpha1.Authentication, name string, namespace string,
	annotations map[string]string, routeHost string, routePath string, destinationCAcert []byte) (*route.Route, error) {

	reqLogger := log.WithValues("func", "GetDesiredRoute", "name", name, "namespace", namespace)

	weight := int32(100)

	r := &route.Route{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Route",
			APIVersion: route.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
		},
		Spec: route.RouteSpec{
			Host: routeHost,
			Path: routePath,
			Port: &route.RoutePort{
				TargetPort: intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: 3000,
				},
			},
			To: route.RouteTargetReference{
				Name:   ServiceName,
				Kind:   "Service",
				Weight: &weight,
			},
			WildcardPolicy: route.WildcardPolicyNone,
			TLS: &route.TLSConfig{
				Termination:                   route.TLSTerminationReencrypt,
				InsecureEdgeTerminationPolicy: route.InsecureEdgeTerminationPolicyRedirect,
				DestinationCACertificate:      string(destinationCAcert),
			},
		},
	}

	err := controllerutil.SetControllerReference(instance, r, client.Scheme())
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for route")
		return nil, err
	}

	return r, nil
}
