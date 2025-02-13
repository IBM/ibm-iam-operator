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
	"strings"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var ingressList []string = []string{
	"ibmid-ui-callback",
	"id-mgmt",
	"idmgmt-v2-api",
	"platform-auth",
	"platform-id-provider",
	"platform-login",
	"platform-oidc-block",
	"platform-oidc",
	"saml-ui-callback",
	"version-idmgmt",
	"social-login-callback",
}

func (r *AuthenticationReconciler) ReconcileRemoveIngresses(ctx context.Context, instance *operatorv1alpha1.Authentication, needToRequeue *bool) {
	reqLogger := log.WithValues("func", "ReconcileRemoveIngresses")

	//No error checking as we will just make a best attempt to remove the legacy ingresses
	//Do not fail based on inability to delete the ingresses
	//TODO Add ingress names here
	for _, iname := range ingressList {
		err := r.DeleteIngress(ctx, iname, instance.Namespace, needToRequeue)
		if err != nil {
			reqLogger.Info("Failed to delete legacy ingress " + iname)
		}
	}
}

func (r *AuthenticationReconciler) DeleteIngress(ctx context.Context, ingressName string, ingressNS string, needToRequeue *bool) error {
	reqLogger := log.WithValues("func", "deleteIngress", "Name", ingressName, "Namespace", ingressNS)

	ingress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ingressName,
			Namespace: ingressNS,
		},
	}

	err := r.Client.Get(ctx, types.NamespacedName{Name: ingress.Name, Namespace: ingress.Namespace}, ingress)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		reqLogger.Error(err, "Failed to get legacy ingress")
		return err
	}

	// Delete ingress if found
	err = r.Client.Delete(ctx, ingress)
	if err != nil {
		reqLogger.Error(err, "Failed to delete legacy ingress")
		return err
	}

	reqLogger.Info("Deleted legacy ingress")
	*needToRequeue = true
	return nil
}

func (r *AuthenticationReconciler) handleIngress(instance *operatorv1alpha1.Authentication, currentIngress *netv1.Ingress, needToRequeue *bool) error {
	functionList := []func(*operatorv1alpha1.Authentication, *runtime.Scheme) *netv1.Ingress{
		ibmidUiCallbackIngress,
		idMgmtIngress,
		idmgmtV2ApiIngress,
		platformAuthIngress,
		platformIdProviderIngress,
		platformLoginIngress,
		platformOidcBlockIngress,
		platformOidcIngress,
		samlUiCallbackIngress,
		versionIdmgmtIngress,
		socialLoginCallbackIngress,
	}

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	for index, ingress := range ingressList {
		err = r.Client.Get(context.TODO(), types.NamespacedName{Name: ingress, Namespace: instance.Namespace}, currentIngress)
		if err != nil && errors.IsNotFound(err) {
			// Define a new Ingress
			newIngress := functionList[index](instance, r.Scheme)
			reqLogger.Info("Creating a new Ingress", "Ingress.Namespace", instance.Namespace, "Ingress.Name", ingress)
			err = r.Client.Create(context.TODO(), newIngress)
			if err != nil {
				reqLogger.Error(err, "Failed to create new Ingress", "Ingress.Namespace", instance.Namespace, "Ingress.Name", ingress)
				return err
			}
			// Ingress created successfully - return and requeue, just sets the pointer to true
			*needToRequeue = true
		} else if err != nil {
			reqLogger.Error(err, "Failed to get Ingress")
			return err
		}
	}

	return nil

}

func ibmidUiCallbackIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *netv1.Ingress {
	pathType := netv1.PathType("ImplementationSpecific")
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ibmid-ui-callback",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/secure-backends": "true",
				"icp.management.ibm.com/upstream-uri":    "/oidcclient/redirect/ICP_IBMID",
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path:     "/oidcclient/redirect/ICP_IBMID",
									PathType: &pathType,
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{
											Name: "platform-auth-service",
											Port: netv1.ServiceBackendPort{
												Number: 9443,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, newIngress, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return newIngress

}

func idMgmtIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *netv1.Ingress {
	pathType := netv1.PathType("ImplementationSpecific")
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "id-mgmt",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-identity-management"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/authz-type":      "rbac",
				"icp.management.ibm.com/secure-backends": "true",
				"icp.management.ibm.com/configuration-snippet": `
					if ($request_uri ~* "/idmgmt/(.*)") {
						proxy_pass https://$proxy_upstream_name/$1;
					}
					`,
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path:     "/idmgmt/",
									PathType: &pathType,
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{
											Name: "platform-identity-management",
											Port: netv1.ServiceBackendPort{
												Number: 4500,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, newIngress, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return newIngress

}

func idmgmtV2ApiIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *netv1.Ingress {
	pathType := netv1.PathType("ImplementationSpecific")
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "idmgmt-v2-api",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-identity-management"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/secure-backends":   "true",
				"icp.management.ibm.com/upstream-uri":      "/identity/api/v1/teams/resources",
				"icp.management.ibm.com/location-modifier": "=",
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path:     "/idmgmt/identity/api/v2/teams/resources",
									PathType: &pathType,
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{
											Name: "platform-identity-management",
											Port: netv1.ServiceBackendPort{
												Number: 4500,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, newIngress, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return newIngress

}

func platformAuthIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *netv1.Ingress {
	pathType := netv1.PathType("ImplementationSpecific")
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-auth",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-identity-provider"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/secure-backends":   "true",
				"icp.management.ibm.com/proxy-buffer-size": "64k",
				"icp.management.ibm.com/configuration-snippet": `
					add_header 'Access-Control-Allow-Origin' 'https://127.0.0.1';
					add_header 'Access-Control-Allow-Credentials' 'false' always;
					add_header 'Access-Control-Allow-Methods' 'GET, POST, HEAD' always;
					add_header 'Access-Control-Allow-Headers' 'Accept,Authorization,Cache-Control,Content-Type,DNT,If-Modified-Since,Keep-Alive,Origin,User-Agent,X-Requested-With' always;
					if ($request_uri !~ .*call_proxy.*) {
						error_page 401 @401;
					}
					proxy_intercept_errors on;
					`,
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path:     "/v1/auth/",
									PathType: &pathType,
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{
											Name: "platform-identity-provider",
											Port: netv1.ServiceBackendPort{
												Number: 4300,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, newIngress, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return newIngress

}

func platformIdProviderIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *netv1.Ingress {
	pathType := netv1.PathType("ImplementationSpecific")
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-id-provider",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-identity-provider"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":                  "ibm-icp-management",
				"icp.management.ibm.com/secure-backends":       "true",
				"icp.management.ibm.com/rewrite-target":        "/",
				"icp.management.ibm.com/authz-type":            "rbac",
				"icp.management.ibm.com/configuration-snippet": "\n            limit_req zone=management-ingress-rps-100 burst=20 nodelay;",
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path:     "/idprovider/",
									PathType: &pathType,
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{
											Name: "platform-identity-provider",
											Port: netv1.ServiceBackendPort{
												Number: 4300,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, newIngress, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return newIngress

}

func platformLoginIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *netv1.Ingress {
	pathType := netv1.PathType("ImplementationSpecific")
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-login",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/secure-backends":   "true",
				"icp.management.ibm.com/proxy-buffer-size": "64k",
				"icp.management.ibm.com/upstream-uri":      "/v1/auth/authorize?client_id=$oauth_client_id&redirect_uri=https://$http_host/auth/liberty/callback&response_type=code&scope=openid+email+profile&state=$expires_time&orig=$request_uri",
				"icp.management.ibm.com/configuration-snippet": `
					add_header 'X-Frame-Options' 'SAMEORIGIN' always;
					set_by_lua $expires_time 'return ngx.time()';
					set_by_lua $oauth_client_id 'return os.getenv("WLP_CLIENT_ID")';
					set_by_lua $oauth_auth_redirector 'return os.getenv("OAUTH_AUTH_REDIRECTOR")';
					`,
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path:     "/login",
									PathType: &pathType,
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{
											Name: "platform-identity-provider",
											Port: netv1.ServiceBackendPort{
												Number: 4300,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, newIngress, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return newIngress

}

func platformOidcBlockIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *netv1.Ingress {
	pathType := netv1.PathType("ImplementationSpecific")
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-oidc-block",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/location-modifier": "=",
				"icp.management.ibm.com/configuration-snippet": `
										add_header 'X-XSS-Protection' '1' always;
										add_header 'X-Content-Type-Options' 'nosniff';
									`,
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path:     "/oidc/endpoint",
									PathType: &pathType,
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{
											Name: "default-http-backend",
											Port: netv1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, newIngress, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return newIngress

}

func platformOidcIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *netv1.Ingress {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var xframeDomain string
	if instance.Spec.Config.XFrameDomain != "" {
		xframeDomain = strings.Join([]string{"'ALLOW-FROM ", instance.Spec.Config.XFrameDomain, "'"}, "")
	} else {
		xframeDomain = "'SAMEORIGIN'"
	}
	pathType := netv1.PathType("ImplementationSpecific")
	newIngress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-oidc",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/secure-backends":   "true",
				"icp.management.ibm.com/proxy-buffer-size": "64k",
				"icp.management.ibm.com/configuration-snippet": `
				   add_header 'Access-Control-Allow-Origin' 'https://127.0.0.1';
				   add_header 'Access-Control-Allow-Credentials' 'false' always;
				   add_header 'Access-Control-Allow-Methods' 'GET, POST, HEAD' always;
				   add_header 'X-Frame-Options' ` + xframeDomain + ` always;
				   add_header 'X-Content-Type-Options' 'nosniff' always;
				   add_header 'X-XSS-Protection' '1' always;
				   add_header 'Access-Control-Allow-Headers' 'Accept,Authorization,Cache-Control,Content-Type,DNT,If-Modified-Since,Keep-Alive,Origin,User-Agent,X-Requested-With' always;
				   if ($request_uri !~ .*call_proxy.*) {
				      error_page 401 @401;
				   }
				   proxy_intercept_errors on;
                    `,
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path:     "/oidc",
									PathType: &pathType,
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{
											Name: "platform-auth-service",
											Port: netv1.ServiceBackendPort{
												Number: 9443,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, newIngress, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return newIngress

}

func samlUiCallbackIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *netv1.Ingress {
	pathType := netv1.PathType("ImplementationSpecific")
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "saml-ui-callback",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/upstream-uri":    "/ibm/saml20/defaultSP/acs",
				"icp.management.ibm.com/secure-backends": "true",
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path:     "/ibm/saml20/defaultSP/acs",
									PathType: &pathType,
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{
											Name: "platform-auth-service",
											Port: netv1.ServiceBackendPort{
												Number: 9443,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, newIngress, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return newIngress

}

func versionIdmgmtIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *netv1.Ingress {
	pathType := netv1.PathType("ImplementationSpecific")
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "version-idmgmt",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-identity-management"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/upstream-uri":      "/identity/api/v1/",
				"icp.management.ibm.com/secure-backends":   "true",
				"icp.management.ibm.com/location-modifier": "=",
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path:     "/idmgmt/identity/api/v1/",
									PathType: &pathType,
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{
											Name: "platform-identity-management",
											Port: netv1.ServiceBackendPort{
												Number: 4500,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, newIngress, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return newIngress

}

func socialLoginCallbackIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *netv1.Ingress {
	pathType := netv1.PathType("ImplementationSpecific")
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "social-login-callback",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "platform-auth-service"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/upstream-uri":    "/ibm/api/social-login",
				"icp.management.ibm.com/secure-backends": "true",
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path:     "/ibm/api/social-login",
									PathType: &pathType,
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{
											Name: "platform-auth-service",
											Port: netv1.ServiceBackendPort{
												Number: 9443,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set Authentication instance as the owner and controller of the Ingress
	err := controllerutil.SetControllerReference(instance, newIngress, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Ingress")
		return nil
	}
	return newIngress

}
