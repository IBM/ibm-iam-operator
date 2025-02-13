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

package operator

import (
	"context"
	"fmt"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *AuthenticationReconciler) handleService(instance *operatorv1alpha1.Authentication, currentService *corev1.Service, needToRequeue *bool) error {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: "platform-auth-service", Namespace: instance.Namespace}, currentService)
	if err != nil && errors.IsNotFound(err) {
		// Define a new service
		platformAuthService := r.platformAuthService(instance)
		reqLogger.Info("Creating a new Service", "Service.Namespace", instance.Namespace, "Service.Name", "platform-auth-service")
		err = r.Client.Create(context.TODO(), platformAuthService)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Service", "Service.Namespace", instance.Namespace, "Service.Name", "platform-auth-service")
			return err
		}
		// Service created successfully - return and requeue
		*needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return err
	} else {
		r.validateCP3PodSelectorAndLabel(currentService, needToRequeue)
	}

	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: "platform-identity-provider", Namespace: instance.Namespace}, currentService)
	if err != nil && errors.IsNotFound(err) {
		// Define a new service
		identityProviderService := r.identityProviderService(instance)
		reqLogger.Info("Creating a new Service", "Service.Namespace", instance.Namespace, "Service.Name", "platform-identity-provider")
		err = r.Client.Create(context.TODO(), identityProviderService)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Service", "Service.Namespace", instance.Namespace, "Service.Name", "platform-identity-provider")
			return err
		}
		// Service created successfully - return and requeue
		*needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return err
	} else {
		r.validateCP3PodSelectorAndLabel(currentService, needToRequeue)
	}

	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: "platform-identity-management", Namespace: instance.Namespace}, currentService)
	if err != nil && errors.IsNotFound(err) {
		// Define a new service
		identityManagementService := r.identityManagementService(instance)
		reqLogger.Info("Creating a new Service", "Service.Namespace", instance.Namespace, "Service.Name", "platform-identity-management")
		err = r.Client.Create(context.TODO(), identityManagementService)
		if err != nil {
			reqLogger.Error(err, "Failed to create new Service", "Service.Namespace", instance.Namespace, "Service.Name", "platform-identity-management")
			return err
		}
		// Service created successfully - return and requeue
		*needToRequeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return err
	} else {
		r.validateCP3PodSelectorAndLabel(currentService, needToRequeue)
	}

	return nil
}

// validateCP3ServicePodSelectorAndLabel takes a *Service and attempts to update that Service's selectors and
// labels if they do not match the desired CP3 values. Returns an error if the update fails or if the provided
// *Service is nil or lacks a name or namespace.
func (r *AuthenticationReconciler) validateCP3PodSelectorAndLabel(currentService *corev1.Service, needToRequeue *bool) (err error) {

	if currentService == nil || currentService.Name == "" || currentService.Namespace == "" {
		return fmt.Errorf("received invalid Service")
	}

	reqLogger := log.WithValues("Instance.Namespace", currentService.Namespace, "Instance.Name", currentService.Name)

	var cp2podselector bool = false
	var cp2podlabel bool = false
	podSelector := currentService.Spec.Selector
	value, ok := podSelector["k8s-app"]
	if ok && value != currentService.Name {
		currentService.Spec.Selector = map[string]string{"k8s-app": currentService.Name}
		cp2podselector = true
	}
	// Going to validate label for CP3 upgrade
	label := currentService.Labels
	value, ok = label["app"]
	if ok && value != currentService.Name {
		currentService.Labels = map[string]string{"app": currentService.Name}
		cp2podlabel = true
	}
	if cp2podselector || cp2podlabel {
		err = r.Client.Update(context.Background(), currentService)
		if err != nil {
			reqLogger.Error(err, "Upgrade check : Failed to update service podSelector , label details ", "Service.Namespace", currentService.Namespace, "Service.Name", currentService.Name, "Error.message", err)
			*needToRequeue = true
			return
		} else {
			reqLogger.Info("Upgrade check : Successfully updated service podSelector , label details ", "Service.Name", currentService.Name)
		}
	}
	return
}

func (r *AuthenticationReconciler) platformAuthService(instance *operatorv1alpha1.Authentication) *corev1.Service {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var authPort int32 = 9443
	var dirPort int32 = 3100
	platformAuthService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-auth-service",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
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
				"k8s-app": "platform-auth-service",
			},
			Type:            "ClusterIP",
			SessionAffinity: corev1.ServiceAffinityClientIP,
		},
	}

	// Set Authentication instance as the owner and controller of the Service
	err := controllerutil.SetControllerReference(instance, platformAuthService, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Service")
		return nil
	}
	return platformAuthService

}

func (r *AuthenticationReconciler) identityManagementService(instance *operatorv1alpha1.Authentication) *corev1.Service {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var idmgmtPort int32 = 4500
	var redirectPort int32 = 443
	identityManagementService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-identity-management",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-identity-management"},
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
				"k8s-app": "platform-identity-management",
			},
			Type:            "ClusterIP",
			SessionAffinity: corev1.ServiceAffinityClientIP,
		},
	}

	// Set Authentication instance as the owner and controller of the Service
	err := controllerutil.SetControllerReference(instance, identityManagementService, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Service")
		return nil
	}
	return identityManagementService

}

func (r *AuthenticationReconciler) identityProviderService(instance *operatorv1alpha1.Authentication) *corev1.Service {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var idproviderPort int32 = 4300
	identityProviderService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-identity-provider",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-identity-provider"},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "p4300",
					Port: idproviderPort,
				},
			},
			Selector: map[string]string{
				"k8s-app": "platform-identity-provider",
			},
			Type:            "ClusterIP",
			SessionAffinity: corev1.ServiceAffinityClientIP,
		},
	}

	// Set Authentication instance as the owner and controller of the Service
	err := controllerutil.SetControllerReference(instance, identityProviderService, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Service")
		return nil
	}
	return identityProviderService

}
