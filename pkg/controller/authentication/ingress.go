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
	net "k8s.io/api/networking/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *ReconcileAuthentication) handleIngress(instance *operatorv1alpha1.Authentication, currentIngress *net.Ingress, requeueResult *bool) error {

	ingressList := []string{"api-key", "explorer-idmgmt", "iam-token-redirect", "ibmid-ui-callback", "id-mgmt", "idmgmt-v2-api", "platform-auth-dir",
		"platform-auth", "platform-id-auth-block", "platform-id-auth", "platform-id-provider", "platform-login", "platform-oidc-block", "platform-oidc", "platform-oidc-introspect",
		"platform-oidc-keys", "platform-oidc-token-2", "platform-oidc-token", "service-id", "token-service-version", "saml-ui-callback", "version-idmgmt"}

	functionList := []func(*operatorv1alpha1.Authentication, *runtime.Scheme) *net.Ingress{apiKeyIngress, explorerIdmgmtIngress, iamTokenRedirectIngress, ibmidUiCallbackIngress, idMgmtIngress, idmgmtV2ApiIngress, platformAuthDirIngress,
		platformAuthIngress, platformIdAuthBlockIngress, platformIdAuthIngress, platformIdProviderIngress, platformLoginIngress, platformOidcBlockIngress, platformOidcIngress, platformOidcIntrospectIngress,
		platformOidcKeysIngress, platformOidcToken2Ingress, platformOidcTokenIngress, serviceIdIngress, tokenServiceVersionIngress, samlUiCallbackIngress, versionIdmgmtIngress}

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	for index, ingress := range ingressList {
		err = r.client.Get(context.TODO(), types.NamespacedName{Name: ingress, Namespace: instance.Namespace}, currentIngress)
		if err != nil && errors.IsNotFound(err) {
			// Define a new Ingress
			newIngress := functionList[index](instance, r.scheme)
			reqLogger.Info("Creating a new Ingress", "Ingress.Namespace", instance.Namespace, "Ingress.Name", ingress)
			err = r.client.Create(context.TODO(), newIngress)
			if err != nil {
				reqLogger.Error(err, "Failed to create new Ingress", "Ingress.Namespace", instance.Namespace, "Ingress.Name", ingress)
				return err
			}
			// Ingress created successfully - return and requeue
			*requeueResult = true
		} else if err != nil {
			reqLogger.Error(err, "Failed to get Ingress")
			return err
		}

	}

	return nil

}

func apiKeyIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-key",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/secure-backends": "true",
				"icp.management.ibm.com/rewrite-target":  "/apikeys",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/apikeys",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 9443,
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

func explorerIdmgmtIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "explorer-idmgmt",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/secure-backends": "true",
				"icp.management.ibm.com/configuration-snippet": `
										if ($request_uri ~* "/idmgmt/(.*)") {
											proxy_pass https://$proxy_upstream_name/$1;
										}
										`,
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/idmgmt/explorer/",
									Backend: net.IngressBackend{
										ServiceName: "platform-identity-management",
										ServicePort: intstr.IntOrString{
											IntVal: 4500,
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

func iamTokenRedirectIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "iam-token-redirect",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/secure-backends": "true",
				"icp.management.ibm.com/rewrite-target":  "/iam/oidc",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/iam-token/oidc/",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 9443,
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

func ibmidUiCallbackIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ibmid-ui-callback",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/secure-backends": "true",
				"icp.management.ibm.com/upstream-uri":    "/oidcclient/redirect/ICP_IBMID",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/oidcclient/redirect/ICP_IBMID",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 9443,
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

func idMgmtIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "id-mgmt",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
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
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/idmgmt/",
									Backend: net.IngressBackend{
										ServiceName: "platform-identity-management",
										ServicePort: intstr.IntOrString{
											IntVal: 4500,
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

func idmgmtV2ApiIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "idmgmt-v2-api",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/secure-backends":   "true",
				"icp.management.ibm.com/upstream-uri":      "/identity/api/v1/teams/resources",
				"icp.management.ibm.com/location-modifier": "=",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/idmgmt/identity/api/v2/teams/resources",
									Backend: net.IngressBackend{
										ServiceName: "platform-identity-management",
										ServicePort: intstr.IntOrString{
											IntVal: 4500,
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

func platformAuthDirIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-auth-dir",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/secure-backends": "true",
				"icp.management.ibm.com/rewrite-target":  "/",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/authdir/",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 3100,
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

func platformAuthIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-auth",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
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
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/v1/auth/",
									Backend: net.IngressBackend{
										ServiceName: "platform-identity-provider",
										ServicePort: intstr.IntOrString{
											IntVal: 4300,
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

func platformIdAuthBlockIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-id-auth-block",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/location-modifier": "=",
				"icp.management.ibm.com/configuration-snippet": `
										add_header 'X-XSS-Protection' '1' always;
									`,
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/idauth/oidc/endpoint",
									Backend: net.IngressBackend{
										ServiceName: "default-http-backend",
										ServicePort: intstr.IntOrString{
											IntVal: 80,
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

func platformIdAuthIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-id-auth",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/secure-backends": "true",
				"icp.management.ibm.com/rewrite-target":  "/",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/idauth",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 9443,
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

func platformIdProviderIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-id-provider",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/secure-backends": "true",
				"icp.management.ibm.com/rewrite-target":  "/",
				"icp.management.ibm.com/authz-type":      "rbac",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/idprovider/",
									Backend: net.IngressBackend{
										ServiceName: "platform-identity-provider",
										ServicePort: intstr.IntOrString{
											IntVal: 4300,
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

func platformLoginIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-login",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
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
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/login/",
									Backend: net.IngressBackend{
										ServiceName: "platform-identity-provider",
										ServicePort: intstr.IntOrString{
											IntVal: 4300,
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

func platformOidcBlockIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-oidc-block",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/location-modifier": "=",
				"icp.management.ibm.com/configuration-snippet": `
										add_header 'X-XSS-Protection' '1' always;
									`,
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/oidc/endpoint",
									Backend: net.IngressBackend{
										ServiceName: "default-http-backend",
										ServicePort: intstr.IntOrString{
											IntVal: 80,
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

func platformOidcIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-oidc",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/secure-backends":   "true",
				"icp.management.ibm.com/proxy-buffer-size": "64k",
				"icp.management.ibm.com/upstream-uri":      "/v1/auth/authorize?client_id=$oauth_client_id&redirect_uri=https://$http_host/auth/liberty/callback&response_type=code&scope=openid+email+profile&state=$expires_time&orig=$request_uri",
				"icp.management.ibm.com/configuration-snippet": `
											add_header 'Access-Control-Allow-Origin' 'https://127.0.0.1';
											add_header 'Access-Control-Allow-Credentials' 'false' always;
											add_header 'Access-Control-Allow-Methods' 'GET, POST, HEAD' always;
											add_header 'X-Frame-Options' 'SAMEORIGIN' always;
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
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/oidc",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 9443,
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

func platformOidcIntrospectIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-oidc-introspect",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/location-modifier": "=",
				"icp.management.ibm.com/upstream-uri":      "/iam/oidc/introspect/",
				"icp.management.ibm.com/secure-backends":   "true",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/oidc/introspect",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 9443,
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

func platformOidcKeysIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-oidc-keys",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/location-modifier": "=",
				"icp.management.ibm.com/upstream-uri":      "/iam/oidc/keys/",
				"icp.management.ibm.com/secure-backends":   "true",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/oidc/keys",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 9443,
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

func platformOidcToken2Ingress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-oidc-token-2",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/upstream-uri":    "/iam/oidc/token/",
				"icp.management.ibm.com/secure-backends": "true",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/oidc/token",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 9443,
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

func platformOidcTokenIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "platform-oidc-token",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/upstream-uri":      "/iam/oidc/token/",
				"icp.management.ibm.com/secure-backends":   "true",
				"icp.management.ibm.com/location-modifier": "=",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/oidc/token",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 9443,
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

func serviceIdIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service-id",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/rewrite-target":  "/serviceids",
				"icp.management.ibm.com/secure-backends": "true",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/serviceids",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 9443,
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

func tokenServiceVersionIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "token-service-version",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/rewrite-target":  "/v1",
				"icp.management.ibm.com/secure-backends": "true",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/v1",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 9443,
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

func samlUiCallbackIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "saml-ui-callback",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":            "ibm-icp-management",
				"icp.management.ibm.com/upstream-uri":    "/ibm/saml20/defaultSP/acs",
				"icp.management.ibm.com/secure-backends": "true",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/ibm/saml20/defaultSP/acs",
									Backend: net.IngressBackend{
										ServiceName: "platform-auth-service",
										ServicePort: intstr.IntOrString{
											IntVal: 9443,
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

func versionIdmgmtIngress(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme) *net.Ingress {

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	newIngress := &net.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "version-idmgmt",
			Namespace: instance.Namespace,
			Labels:    map[string]string{"app": "auth-idp"},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":              "ibm-icp-management",
				"icp.management.ibm.com/upstream-uri":      "/identity/api/v1/",
				"icp.management.ibm.com/secure-backends":   "true",
				"icp.management.ibm.com/location-modifier": "=",
			},
		},
		Spec: net.IngressSpec{
			Rules: []net.IngressRule{
				{
					IngressRuleValue: net.IngressRuleValue{
						HTTP: &net.HTTPIngressRuleValue{
							Paths: []net.HTTPIngressPath{
								{
									Path: "/idmgmt/identity/api/v1/",
									Backend: net.IngressBackend{
										ServiceName: "platform-identity-management",
										ServicePort: intstr.IntOrString{
											IntVal: 4500,
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
