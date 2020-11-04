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

package authentication

import (
	"context"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *ReconcileAuthentication) handleService(instance *operatorv1alpha1.Authentication, currentService *corev1.Service, requeueResult *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: "platform-auth-service", Namespace: instance.Namespace}, currentService)
	if err != nil && errors.IsNotFound(err) {
		// Define a new service
		platformAuthService := r.platformAuthService(instance)
		reqLogger.Info("Creating a new Service", "Service.Namespace", instance.Namespace, "Service.Name", "platform-auth-service")
		err = r.client.Create(context.TODO(), platformAuthService)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Service", "Service.Namespace", instance.Namespace, "Service.Name", "platform-auth-service")
			return err
		}
		// Service created successfully - return and requeue
		*requeueResult = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return err
	}

	err = r.client.Get(context.TODO(), types.NamespacedName{Name: "platform-identity-provider", Namespace: instance.Namespace}, currentService)
	if err != nil && errors.IsNotFound(err) {
		// Define a new service
		identityProviderService := r.identityProviderService(instance)
		reqLogger.Info("Creating a new Service", "Service.Namespace", instance.Namespace, "Service.Name", "platform-identity-provider")
		err = r.client.Create(context.TODO(), identityProviderService)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Service", "Service.Namespace", instance.Namespace, "Service.Name", "platform-identity-provider")
			return err
		}
		// Service created successfully - return and requeue
		*requeueResult = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return err
	}

	err = r.client.Get(context.TODO(), types.NamespacedName{Name: "platform-identity-management", Namespace: instance.Namespace}, currentService)
	if err != nil && errors.IsNotFound(err) {
		// Define a new service
		identityManagementService := r.identityManagementService(instance)
		reqLogger.Info("Creating a new Service", "Service.Namespace", instance.Namespace, "Service.Name", "platform-identity-management")
		err = r.client.Create(context.TODO(), identityManagementService)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Service", "Service.Namespace", instance.Namespace, "Service.Name", "platform-identity-management")
			return err
		}
		// Service created successfully - return and requeue
		*requeueResult = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return err
	}

	err = r.client.Get(context.TODO(), types.NamespacedName{Name: "iam-token-service", Namespace: instance.Namespace}, currentService)
	if err != nil && errors.IsNotFound(err) {
		// Define a new service
		iamTokenService := r.iamTokenService(instance)
		reqLogger.Info("Creating a new Service", "Service.Namespace", instance.Namespace, "Service.Name", "iam-token-service")
		err = r.client.Create(context.TODO(), iamTokenService)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Service", "Service.Namespace", instance.Namespace, "Service.Name", "iam-token-service")
			return err
		}
		// Service created successfully - return and requeue
		*requeueResult = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return err
	}

	return nil

}

func (r *ReconcileAuthentication) platformAuthService(instance *operatorv1alpha1.Authentication) *corev1.Service {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var authPort int32 = 9443
	var dirPort int32 = 3100
	platformAuthService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-auth-service",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "p9443",
					Port: authPort,
				},
				{
					Name: "p3100",
					Port: dirPort,
				},
			},
			Selector: map[string]string{
				"k8s-app": "auth-idp",
			},
			Type:            "ClusterIP",
			SessionAffinity: corev1.ServiceAffinityClientIP,
		},
	}

	// Set Authentication instance as the owner and controller of the Service
	err := controllerutil.SetControllerReference(instance, platformAuthService, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Service")
		return nil
	}
	return platformAuthService

}

func (r *ReconcileAuthentication) identityManagementService(instance *operatorv1alpha1.Authentication) *corev1.Service {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var idmgmtPort int32 = 4500
	var redirectPort int32 = 443
	identityManagementService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-identity-management",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "p4500",
					Port: idmgmtPort,
				},
				{
					Name:     "p443",
					Port:     redirectPort,
					Protocol: corev1.ProtocolTCP,
					TargetPort: intstr.IntOrString{
						IntVal: idmgmtPort,
					},
				},
			},
			Selector: map[string]string{
				"k8s-app": "auth-idp",
			},
			Type:            "ClusterIP",
			SessionAffinity: corev1.ServiceAffinityClientIP,
		},
	}

	// Set Authentication instance as the owner and controller of the Service
	err := controllerutil.SetControllerReference(instance, identityManagementService, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Service")
		return nil
	}
	return identityManagementService

}

func (r *ReconcileAuthentication) identityProviderService(instance *operatorv1alpha1.Authentication) *corev1.Service {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var idproviderPort int32 = 4300
	var redirectPort int32 = 9443
	identityProviderService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-identity-provider",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "p4300",
					Port: idproviderPort,
				},
				{
					Name: "p9443",
					Port: redirectPort,
				},
			},
			Selector: map[string]string{
				"k8s-app": "auth-idp",
			},
			Type:            "ClusterIP",
			SessionAffinity: corev1.ServiceAffinityClientIP,
		},
	}

	// Set Authentication instance as the owner and controller of the Service
	err := controllerutil.SetControllerReference(instance, identityProviderService, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Service")
		return nil
	}
	return identityProviderService

}

func (r *ReconcileAuthentication) iamTokenService(instance *operatorv1alpha1.Authentication) *corev1.Service {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var managementIngressPort int32 = 8443
	var redirectPort int32 = 10443
	iamTokenService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "iam-token-service",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"component": "auth-idp"},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:     "p10443",
					Port:     redirectPort,
					Protocol: corev1.ProtocolTCP,
					TargetPort: intstr.IntOrString{
						IntVal: managementIngressPort,
					},
				},
			},
			Selector: map[string]string{
				"component": "management-ingress",
			},
			Type:            "ClusterIP",
			SessionAffinity: corev1.ServiceAffinityClientIP,
		},
	}

	// Set Authentication instance as the owner and controller of the Service
	err := controllerutil.SetControllerReference(instance, iamTokenService, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Service")
		return nil
	}
	return iamTokenService

}
