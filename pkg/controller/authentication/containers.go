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
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/pkg/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"os"
	"strconv"
)

func buildInitContainers(mongoDBImage string, resources *corev1.ResourceRequirements) []corev1.Container {
	return []corev1.Container{
		{
			Name:            "init-mongodb",
			Image:           mongoDBImage,
			ImagePullPolicy: corev1.PullAlways,
			Command: []string{
				"bash",
				"-c",
				"until </dev/tcp/mongodb/27017 ; do sleep 5; done;",
			},
			SecurityContext: &corev1.SecurityContext{
				Privileged:               &falseVar,
				RunAsNonRoot:             &trueVar,
				ReadOnlyRootFilesystem:   &trueVar,
				AllowPrivilegeEscalation: &falseVar,
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			},
			Resources: *resources,
		},
	}
}

func buildAuditContainer(auditImage string, journalPath string, resources *corev1.ResourceRequirements) corev1.Container {

	return corev1.Container{
		Name:            "icp-audit-service",
		Image:           auditImage,
		ImagePullPolicy: corev1.PullAlways,
		Env: []corev1.EnvVar{
			{
				Name:  "AUDIT_DIR",
				Value: "/var/log/audit",
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "shared",
				MountPath: "/var/log/audit",
			},
			{
				Name:      "journal",
				MountPath: journalPath,
			},
			{
				Name:      "logrotate",
				MountPath: "/etc/logrotate.d/audit",
				SubPath:   "audit",
			},
			{
				Name:      "logrotate-conf",
				MountPath: "/etc/logrotate.conf",
				SubPath:   "logrotate.conf",
			},
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged:               &falseVar,
			RunAsNonRoot:             &trueVar,
			ReadOnlyRootFilesystem:   &trueVar,
			AllowPrivilegeEscalation: &falseVar,
			RunAsUser:                &user,
			SELinuxOptions: &corev1.SELinuxOptions{
				Type: "spc_t",
			},
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		},
		Resources: *resources,
	}

}

func buildAuthServiceContainer(instance *operatorv1alpha1.Authentication, authServiceImage string) corev1.Container {

	resources := instance.Spec.AuthService.Resources

	envVars := []corev1.EnvVar{
		{
			Name:  "MONGO_DB_NAME",
			Value: "platform-db",
		},
		{
			Name:  "MONGO_COLLECTION",
			Value: "iam",
		},
		{
			Name: "MONGO_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "icp-mongodb-admin",
					},
					Key: "user",
				},
			},
		},
		{
			Name: "MONGO_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "icp-mongodb-admin",
					},
					Key: "password",
				},
			},
		},
		{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "metadata.name",
				},
			},
		},
		{
			Name: "POD_NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "metadata.namespace",
				},
			},
		},
		{
			Name:  "MONGO_HOST",
			Value: "mongodb",
		},
		{
			Name:  "MONGO_PORT",
			Value: "27017",
		},

		{
			Name:  "MONGO_AUTHSOURCE",
			Value: "admin",
		},
		{
			Name: "WLP_CLIENT_ID",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "WLP_CLIENT_ID",
				},
			},
		},
		{
			Name: "WLP_CLIENT_SECRET",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "WLP_CLIENT_SECRET",
				},
			},
		},
		{
			Name: "WLP_SCOPE",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "WLP_SCOPE",
				},
			},
		},
		{
			Name: "OAUTH2_CLIENT_REGISTRATION_SECRET",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "OAUTH2_CLIENT_REGISTRATION_SECRET",
				},
			},
		},
		{
			Name: "IBMID_CLIENT_SECRET",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "IBMID_CLIENT_SECRET",
				},
			},
		},
		{
			Name: "DEFAULT_ADMIN_USER",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp-credentials",
					},
					Key: "admin_username",
				},
			},
		},
		{
			Name: "DEFAULT_ADMIN_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp-credentials",
					},
					Key: "admin_password",
				},
			},
		},
	}

	idpEnvVarList := []string{"NODE_ENV", "MASTER_HOST", "IDENTITY_PROVIDER_URL", "HTTP_ONLY", "SESSION_TIMEOUT", "LDAP_RECURSIVE_SEARCH", "LDAP_ATTR_CACHE_SIZE", "LDAP_ATTR_CACHE_TIMEOUT", "LDAP_ATTR_CACHE_ENABLED", "LDAP_ATTR_CACHE_SIZELIMIT",
		"LDAP_SEARCH_CACHE_SIZE", "LDAP_SEARCH_CACHE_TIMEOUT", "IDENTITY_PROVIDER_URL", "IDENTITY_MGMT_URL", "LDAP_SEARCH_CACHE_ENABLED", "LDAP_SEARCH_CACHE_SIZELIMIT", "IDTOKEN_LIFETIME", "IBMID_CLIENT_ID", "IBMID_CLIENT_ISSUER",
		"SAML_NAMEID_FORMAT", "FIPS_ENABLED", "LOGJAM_DHKEYSIZE_2048_BITS_ENABLED", "LOG_LEVEL_AUTHSVC", "LIBERTY_DEBUG_ENABLED", "NONCE_ENABLED", "OIDC_ISSUER_URL",
	"MONGO_READ_TIMEOUT", "MONGO_MAX_STALENESS", "MONGO_READ_PREFERENCE", "MONGO_CONNECT_TIMEOUT", "MONGO_SELECTION_TIMEOUT", "MONGO_WAIT_TIME", "MONGO_POOL_MIN_SIZE", "MONGO_POOL_MAX_SIZE"}
	idpEnvVars := buildIdpEnvVars(idpEnvVarList)

	envVars = append(envVars, idpEnvVars...)

	if instance.Spec.Config.EnableImpersonation == true {
		impersonationVars := []corev1.EnvVar{
			{
				Name:  "ENABLE_IMPERSONATION",
				Value: "true",
			},
			{
				Name:  "KUBE_APISEVER_HOST",
				Value: "icp-management-ingress",
			},
			{
				Name:  "KUBERNETES_SERVICE_HOST",
				Value: "icp-management-ingress",
			},
		}

		envVars = append(envVars, impersonationVars...)

	}

	return corev1.Container{
		Name:            "platform-auth-service",
		Image:           authServiceImage,
		ImagePullPolicy: corev1.PullAlways,
		SecurityContext: &corev1.SecurityContext{
			Privileged:               &falseVar,
			RunAsNonRoot:             &trueVar,
			ReadOnlyRootFilesystem:   &falseVar,
			AllowPrivilegeEscalation: &falseVar,
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		},
		Resources: *resources,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "auth-key",
				MountPath: "/certs/platform-auth",
			},
			{
				Name:      "ibmid-jwk-cert",
				MountPath: "/certs/ibmid/jwk",
			},
			{
				Name:      "ibmid-ssl-cert",
				MountPath: "/certs/ibmid/ssl",
			},
			{
				Name:      "ldaps-ca-cert",
				MountPath: "/opt/ibm/ldaps",
			},
			{
				Name:      "mongodb-ca-cert",
				MountPath: "/certs/mongodb-ca",
			},
			{
				Name:      "mongodb-client-cert",
				MountPath: "/certs/mongodb-client",
			},
			{
				Name:      "router-certs",
				MountPath: "/certs/router-certs",
			},
		},
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/iam/oidc/keys",
					Port: intstr.IntOrString{
						IntVal: authServicePort,
					},
					Scheme: "HTTPS",
				},
			},
			InitialDelaySeconds: 60,
			PeriodSeconds:       30,
			FailureThreshold:    6,
		},
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/iam/oidc/keys",
					Port: intstr.IntOrString{
						IntVal: authServicePort,
					},
					Scheme: "HTTPS",
				},
			},
			InitialDelaySeconds: 180,
			PeriodSeconds:       30,
			FailureThreshold:    6,
		},
		Env: envVars,
	}

}

func buildIdentityProviderContainer(instance *operatorv1alpha1.Authentication, identityProviderImage string) corev1.Container {
	
	icpConsoleURL := os.Getenv("ICP_CONSOLE_URL")
	resources := instance.Spec.IdentityProvider.Resources
	envVars := []corev1.EnvVar{
		{
			Name:  "MONGO_DB_NAME",
			Value: "platform-db",
		},
		{
			Name:  "SERVICE_NAME",
			Value: "platform-identity-provider",
		},
		{
			Name: "AUDIT_ENABLED",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp",
					},
					Key: "AUDIT_ENABLED_IDPROVIDER",
				},
			},
		},
		{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "metadata.name",
				},
			},
		},
		{
			Name: "POD_NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "metadata.namespace",
				},
			},
		},
		{
			Name: "ENCRYPTION_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp-encryption",
					},
					Key: "ENCRYPTION_KEY",
				},
			},
		},
		{
			Name: "algorithm",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp-encryption",
					},
					Key: "algorithm",
				},
			},
		},
		{
			Name: "inputEncoding",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp-encryption",
					},
					Key: "inputEncoding",
				},
			},
		},
		{
			Name: "outputEncoding",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp-encryption",
					},
					Key: "outputEncoding",
				},
			},
		},
		{
			Name:  "MONGO_COLLECTION",
			Value: "iam",
		},
		{
			Name: "MONGO_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "icp-mongodb-admin",
					},
					Key: "user",
				},
			},
		},
		{
			Name: "MONGO_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "icp-mongodb-admin",
					},
					Key: "password",
				},
			},
		},

		{
			Name:  "MONGO_HOST",
			Value: "mongodb",
		},
		{
			Name:  "MONGO_PORT",
			Value: "27017",
		},

		{
			Name:  "MONGO_AUTHSOURCE",
			Value: "admin",
		},
		{
			Name:  "OPENSHIFT_URL",
			Value: "https://kubernetes.default:443",
		},
		{
			Name:  "IS_OPENSHIFT_ENV",
			Value: strconv.FormatBool(instance.Spec.Config.IsOpenshiftEnv),
		},
		{
			Name: "roksClientId",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "WLP_CLIENT_ID",
				},
			},
		},
		{
			Name: "roksClientSecret",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "WLP_CLIENT_SECRET",
				},
			},
		},
		{
			Name: "wlpClientId",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "WLP_CLIENT_ID",
				},
			},
		},
		{
			Name: "wlpClientSecret",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "WLP_CLIENT_SECRET",
				},
			},
		},
		{
			Name:  "IDMGMT_KUBEDNS_NAME",
			Value: "127.0.0.1",
		},
		{
			Name: "OAUTH2_CLIENT_REGISTRATION_SECRET",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "OAUTH2_CLIENT_REGISTRATION_SECRET",
				},
			},
		},
		{
			Name: "DEFAULT_ADMIN_USER",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp-credentials",
					},
					Key: "admin_username",
				},
			},
		},
		{
			Name: "DEFAULT_ADMIN_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp-credentials",
					},
					Key: "admin_password",
				},
			},
		},
		{
			Name:  "IAM_PAP_URL",
			Value: "https://iam-pap:39001",
		},
		{
			Name:  "IAM_OIDC_TOKEN_SERVICE_URL",
			Value: "https://127.0.0.1:9443/iam",
		},
		{
			Name:  "MASTER_HOST",
			Value: icpConsoleURL,
		},
	}

	idpEnvVarList := []string{"NODE_ENV", "LOG_LEVEL_IDPROVIDER", "LOG_LEVEL_MW", "IDTOKEN_LIFETIME", "ROKS_ENABLED", "ROKS_URL", "OS_TOKEN_LENGTH", "LIBERTY_TOKEN_LENGTH",
		"IDENTITY_PROVIDER_URL", "BASE_AUTH_URL", "BASE_OIDC_URL", "OIDC_ISSUER_URL", "HTTP_ONLY"}

	idpEnvVars := buildIdpEnvVars(idpEnvVarList)

	envVars = append(envVars, idpEnvVars...)

	if instance.Spec.Config.EnableImpersonation == true {
		impersonationVars := []corev1.EnvVar{
			{
				Name:  "ENABLE_IMPERSONATION",
				Value: "true",
			},
			{
				Name:  "KUBE_APISEVER_HOST",
				Value: "icp-management-ingress",
			},
			{
				Name:  "KUBERNETES_SERVICE_HOST",
				Value: "icp-management-ingress",
			},
		}

		envVars = append(envVars, impersonationVars...)

	}

	return corev1.Container{
		Name:            "platform-identity-provider",
		Image:           identityProviderImage,
		ImagePullPolicy: corev1.PullAlways,
		SecurityContext: &corev1.SecurityContext{
			Privileged:               &falseVar,
			RunAsNonRoot:             &trueVar,
			ReadOnlyRootFilesystem:   &trueVar,
			AllowPrivilegeEscalation: &falseVar,
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		},
		Resources: *resources,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "auth-key",
				MountPath: "/opt/ibm/identity-provider/server/boot/auth-key",
			},
			{
				Name:      "shared",
				MountPath: "/var/log/audit",
			},
			{
				Name:      "identity-provider-cert",
				MountPath: "/opt/ibm/identity-provider/certs",
			},
			{
				Name:      "mongodb-ca-cert",
				MountPath: "/certs/mongodb-ca",
			},
			{
				Name:      "mongodb-client-cert",
				MountPath: "/certs/mongodb-client",
			},
		},
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/",
					Port: intstr.IntOrString{
						IntVal: identityProviderPort,
					},
					Scheme: "HTTPS",
				},
			},
		},
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/",
					Port: intstr.IntOrString{
						IntVal: identityProviderPort,
					},
					Scheme: "HTTPS",
				},
			},
		},
		Env: envVars,
	}

}

func buildIdentityManagerContainer(instance *operatorv1alpha1.Authentication, identityManagerImage string) corev1.Container {
	
	//@posriniv - find a better solution
	replicaCount := int(instance.Spec.Replicas)
	resources := instance.Spec.IdentityManager.Resources
	masterNodesList := ""
	baseIp := "10.0.0."
	for i := 1; i <= replicaCount; i++{
		masterNodesList += baseIp + strconv.Itoa(i)
		if i != replicaCount{
			masterNodesList += " "
		}
	}

	envVars := []corev1.EnvVar{
		{
			Name:  "MONGO_DB_NAME",
			Value: "platform-db",
		},
		{
			Name:  "SERVICE_NAME",
			Value: "platform-identity-management",
		},
		{
			Name: "AUDIT_ENABLED",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp",
					},
					Key: "AUDIT_ENABLED_IDMGMT",
				},
			},
		},
		{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "metadata.name",
				},
			},
		},
		{
			Name: "POD_NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "metadata.namespace",
				},
			},
		},
		{
			Name: "IBMID_PROFILE_CLIENT_SECRET",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "IBMID_PROFILE_CLIENT_SECRET",
				},
			},
		},
		{
			Name:  "MONGO_COLLECTION",
			Value: "iam",
		},
		{
			Name: "MONGO_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "icp-mongodb-admin",
					},
					Key: "user",
				},
			},
		},
		{
			Name: "MONGO_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "icp-mongodb-admin",
					},
					Key: "password",
				},
			},
		},

		{
			Name:  "MONGO_HOST",
			Value: "mongodb",
		},
		{
			Name:  "MONGO_PORT",
			Value: "27017",
		},

		{
			Name:  "MONGO_AUTHSOURCE",
			Value: "admin",
		},
		{
			Name:  "OPENSHIFT_URL",
			Value: "https://kubernetes.default:443",
		},
		{
			Name:  "IS_OPENSHIFT_ENV",
			Value: strconv.FormatBool(instance.Spec.Config.IsOpenshiftEnv),
		},
		{
			Name: "roksClientId",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "WLP_CLIENT_ID",
				},
			},
		},
		{
			Name: "roksClientSecret",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "WLP_CLIENT_SECRET",
				},
			},
		},
		{
			Name: "DEFAULT_ADMIN_USER",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp-credentials",
					},
					Key: "admin_username",
				},
			},
		},
		{
			Name: "DEFAULT_ADMIN_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp-credentials",
					},
					Key: "admin_password",
				},
			},
		},
		{
			Name:  "IDPROVIDER_KUBEDNS_NAME",
			Value: "https://127.0.0.1",
		},
		{
			Name:  "IAM_TOKEN_SERVICE_URL",
			Value: "https://127.0.0.1:9443",
		},
		{
			Name:  "MASTER_NODES_LIST",
			Value: masterNodesList,
		},
		{
			Name: "LOCAL_NODE_IP",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "status.hostIP",
				},
			},
		},
		{
			Name: "LOCAL_POD_IP",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "status.podIP",
				},
			},
		},
		{
			Name: "WLP_CLIENT_ID",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "WLP_CLIENT_ID",
				},
			},
		},
		{
			Name: "WLP_CLIENT_SECRET",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "WLP_CLIENT_SECRET",
				},
			},
		},
		{
			Name: "WLP_SCOPE",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-oidc-credentials",
					},
					Key: "WLP_SCOPE",
				},
			},
		},
	}

	idpEnvVarList := []string{"NODE_ENV", "LOG_LEVEL_IDMGMT", "LOG_LEVEL_MW", "IBMID_PROFILE_URL", "IBMID_PROFILE_CLIENT_ID", "IBMID_PROFILE_FIELDS", "AUDIT_DETAIL",
		"ROKS_ENABLED", "ROKS_USER_PREFIX", "IDENTITY_AUTH_DIRECTORY_URL", "OIDC_ISSUER_URL", "CLUSTER_NAME", "HTTP_ONLY", "LDAP_SEARCH_SIZE_LIMIT", "LDAP_SEARCH_TIME_LIMIT",
		"LDAP_SEARCH_CN_ATTR_ONLY", "LDAP_SEARCH_ID_ATTR_ONLY", "LDAP_SEARCH_EXCLUDE_WILDCARD_CHARS", "IGNORE_LDAP_FILTERS_VALIDATION", "MASTER_HOST"}

	idpEnvVars := buildIdpEnvVars(idpEnvVarList)

	envVars = append(envVars, idpEnvVars...)

	if instance.Spec.Config.EnableImpersonation == true {
		impersonationVars := []corev1.EnvVar{
			{
				Name:  "ENABLE_IMPERSONATION",
				Value: "true",
			},
			{
				Name:  "KUBE_APISEVER_HOST",
				Value: "icp-management-ingress",
			},
			{
				Name:  "KUBERNETES_SERVICE_HOST",
				Value: "icp-management-ingress",
			},
		}

		envVars = append(envVars, impersonationVars...)

	} else {
		newVar := corev1.EnvVar{
			Name:  "KUBE_APISERVER_HOST",
			Value: "kubernetes.default",
		}
		envVars = append(envVars, newVar)
	}

	return corev1.Container{
		Name:            "platform-identity-manager",
		Image:           identityManagerImage,
		ImagePullPolicy: corev1.PullAlways,
		SecurityContext: &corev1.SecurityContext{
			Privileged:               &falseVar,
			RunAsNonRoot:             &trueVar,
			ReadOnlyRootFilesystem:   &falseVar,
			AllowPrivilegeEscalation: &falseVar,
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		},
		Resources: *resources,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "cluster-ca",
				MountPath: "/opt/ibm/identity-mgmt/certs",
			},
			{
				Name:      "platform-identity-management",
				MountPath: "/opt/ibm/identity-mgmt/server/certs",
			},
			{
				Name:      "shared",
				MountPath: "/var/log/audit",
			},
			{
				Name:      "mongodb-ca-cert",
				MountPath: "/certs/mongodb-ca",
			},
			{
				Name:      "mongodb-client-cert",
				MountPath: "/certs/mongodb-client",
			},
		},
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/",
					Port: intstr.IntOrString{
						IntVal: identityManagerPort,
					},
					Scheme: "HTTPS",
				},
			},
		},
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/",
					Port: intstr.IntOrString{
						IntVal: identityManagerPort,
					},
					Scheme: "HTTPS",
				},
			},
		},
		Env: envVars,
	}

}

func buildContainers(instance *operatorv1alpha1.Authentication, auditImage string, authServiceImage string, identityProviderImage string, identityManagerImage string, journalPath string) []corev1.Container {

    auditResources := instance.Spec.AuditService.Resources
	auditContainer := buildAuditContainer(auditImage, journalPath,auditResources)
	authServiceContainer := buildAuthServiceContainer(instance, authServiceImage)
	identityProviderContainer := buildIdentityProviderContainer(instance, identityProviderImage)
	identityManagerContainer := buildIdentityManagerContainer(instance, identityManagerImage)

	return []corev1.Container{auditContainer, authServiceContainer, identityProviderContainer, identityManagerContainer}
}

func buildIdpEnvVars(envVarList []string) []corev1.EnvVar {

	envVars := []corev1.EnvVar{}
	for _, varName := range envVarList {
		envVar := corev1.EnvVar{
			Name: varName,
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp",
					},
					Key: varName,
				},
			},
		}
		envVars = append(envVars, envVar)

	}
	return envVars
}
