// Copyright 2020, 2021 IBM Corporation
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
	"strconv"
	"strings"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	ctrlCommon "github.com/IBM/ibm-iam-operator/controllers/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func buildInitContainers(initImage string) []corev1.Container {
	psqlEnvList := []string{"DATABASE_RW_ENDPOINT", "DATABASE_PORT"}
	envVars := buildInitContainerEnvVars(psqlEnvList, ctrlCommon.DatastoreEDBCMName)
	return []corev1.Container{
		{
			Name:            "init-db",
			Image:           initImage,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command: []string{
				"bash",
				"-c",
				"until </dev/tcp/$DATABASE_RW_ENDPOINT/$DATABASE_PORT ; do sleep 5; done;",
			},
			Env: envVars,
			SecurityContext: &corev1.SecurityContext{
				Privileged:               &falseVar,
				RunAsNonRoot:             &trueVar,
				ReadOnlyRootFilesystem:   &trueVar,
				AllowPrivilegeEscalation: &falseVar,
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			},
			Resources: corev1.ResourceRequirements{
				Limits: map[corev1.ResourceName]resource.Quantity{
					corev1.ResourceCPU:    *cpu100,
					corev1.ResourceMemory: *memory128},
				Requests: map[corev1.ResourceName]resource.Quantity{
					corev1.ResourceCPU:              *cpu100,
					corev1.ResourceMemory:           *memory128,
					corev1.ResourceEphemeralStorage: *memory178,
				},
			},
		},
	}
}

func buildInitForMngrAndProvider(initImage string) []corev1.Container {
	psqlEnvList := []string{"DATABASE_RW_ENDPOINT", "DATABASE_PORT"}
	envVars := buildInitContainerEnvVars(psqlEnvList, ctrlCommon.DatastoreEDBCMName)
	return []corev1.Container{
		{
			Name:            "init-db",
			Image:           initImage,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command: []string{
				"bash",
				"-c",
				"until </dev/tcp/$DATABASE_RW_ENDPOINT/$DATABASE_PORT && curl -k https://platform-auth-service:9443/oidc/endpoint/OP/.well-known/openid-configuration; do sleep 5; done",
			},
			Env: envVars,
			SecurityContext: &corev1.SecurityContext{
				Privileged:               &falseVar,
				RunAsNonRoot:             &trueVar,
				ReadOnlyRootFilesystem:   &trueVar,
				AllowPrivilegeEscalation: &falseVar,
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			},
			Resources: corev1.ResourceRequirements{
				Limits: map[corev1.ResourceName]resource.Quantity{
					corev1.ResourceCPU:    *cpu100,
					corev1.ResourceMemory: *memory128},
				Requests: map[corev1.ResourceName]resource.Quantity{
					corev1.ResourceCPU:              *cpu100,
					corev1.ResourceMemory:           *memory128,
					corev1.ResourceEphemeralStorage: *memory178,
				},
			},
		},
	}
}

// This function divides the memory request of auth-service container in MB by 2
// and returns it to liberty in the format that it accepts
func convertToLibertyFormat(memory string) string {

	libertyMemory := ""

	if strings.HasSuffix(memory, "Gi") {
		memString := strings.TrimSuffix(memory, "Gi")
		memVal, _ := strconv.Atoi(memString)
		memVal *= 1024 // Converting to MB
		memVal /= 2    // Allocate 50% of the remaning memory for java heap
		libertyMemory = strconv.Itoa(memVal) + "m"

	} else if strings.HasSuffix(memory, "Mi") {
		memString := strings.TrimSuffix(memory, "Mi")
		memVal, _ := strconv.Atoi(memString)
		memVal /= 2 // Allocate 50% of the remaning memory for jave heap
		libertyMemory = strconv.Itoa(memVal) + "m"
	}

	return libertyMemory

}

func buildAuthServiceContainer(instance *operatorv1alpha1.Authentication, authServiceImage string) corev1.Container {

	resources := instance.Spec.AuthService.Resources

	if resources == nil {
		resources = &corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:              *cpu1000,
				corev1.ResourceMemory:           *memory1024,
				corev1.ResourceEphemeralStorage: *memory650,
			},
			Requests: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:              *cpu100,
				corev1.ResourceMemory:           *memory350,
				corev1.ResourceEphemeralStorage: *memory400,
			},
		}
	}

	memoryQuantity := resources.Requests[corev1.ResourceMemory]
	memory := memoryQuantity.String()
	libertyMemory := convertToLibertyFormat(memory)

	envVars := []corev1.EnvVar{
		{
			Name:  "MEMORY",
			Value: libertyMemory,
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
		{
			Name: "SCIM_ADMIN_USER",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-scim-credentials",
					},
					Key: "scim_admin_username",
				},
			},
		},
		{
			Name: "SCIM_ADMIN_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-scim-credentials",
					},
					Key: "scim_admin_password",
				},
			},
		},
	}

	idpEnvVarList := []string{"NODE_ENV", "MASTER_HOST", "IDENTITY_PROVIDER_URL", "HTTP_ONLY", "SESSION_TIMEOUT", "LDAP_RECURSIVE_SEARCH", "LDAP_ATTR_CACHE_SIZE", "LDAP_ATTR_CACHE_TIMEOUT", "LDAP_ATTR_CACHE_ENABLED", "LDAP_ATTR_CACHE_SIZELIMIT",
		"LDAP_SEARCH_CACHE_SIZE", "LDAP_SEARCH_CACHE_TIMEOUT", "LDAP_CTX_POOL_INITSIZE", "LDAP_CTX_POOL_MAXSIZE", "LDAP_CTX_POOL_TIMEOUT", "LDAP_CTX_POOL_WAITTIME", "LDAP_CTX_POOL_PREFERREDSIZE", "IDENTITY_PROVIDER_URL", "IDENTITY_MGMT_URL", "LDAP_SEARCH_CACHE_ENABLED", "LDAP_SEARCH_CACHE_SIZELIMIT", "IDTOKEN_LIFETIME", "IBMID_CLIENT_ID", "IBMID_CLIENT_ISSUER",
		"SAML_NAMEID_FORMAT", "FIPS_ENABLED", "LOGJAM_DHKEYSIZE_2048_BITS_ENABLED", "LOG_LEVEL_AUTHSVC", "LIBERTY_DEBUG_ENABLED", "NONCE_ENABLED", "CLAIMS_SUPPORTED", "CLAIMS_MAP", "SCOPE_CLAIM", "OIDC_ISSUER_URL",
		"DB_CONNECT_TIMEOUT", "DB_IDLE_TIMEOUT", "DB_CONNECT_MAX_RETRIES", "DB_POOL_MIN_SIZE", "DB_POOL_MAX_SIZE"}
	idpEnvVars := buildIdpEnvVars(idpEnvVarList)

	envVars = append(envVars, idpEnvVars...)

	if instance.Spec.Config.EnableImpersonation {
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
		ImagePullPolicy: corev1.PullIfNotPresent,
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
				Name:      "saml-cert",
				MountPath: "/certs/saml-certs",
			},
			{
				Name:      "pgsql-ca-cert",
				MountPath: "/certs/pgsql-ca",
			},
			{
				Name:      "pgsql-client-cert",
				MountPath: "/certs/pgsql-client",
			},
			{
				Name:      "pgsql-client-cred",
				MountPath: "/pgsql/clientinfo",
			},
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/oidc/endpoint/OP/.well-known/openid-configuration",
					Port: intstr.IntOrString{
						IntVal: authServicePort,
					},
					Scheme: "HTTPS",
				},
			},
			InitialDelaySeconds: 40,
			TimeoutSeconds:      10,
			PeriodSeconds:       10,
			FailureThreshold:    15,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/oidc/endpoint/OP/.well-known/openid-configuration",
					Port: intstr.IntOrString{
						IntVal: authServicePort,
					},
					Scheme: "HTTPS",
				},
			},
			InitialDelaySeconds: 50,
			TimeoutSeconds:      10,
			PeriodSeconds:       10,
			FailureThreshold:    15,
		},
		Env: envVars,
	}

}

func buildIdentityProviderContainer(instance *operatorv1alpha1.Authentication, identityProviderImage string, icpConsoleURL string, saasCRNId string) corev1.Container {

	resources := instance.Spec.IdentityProvider.Resources
	if resources == nil {
		resources = &corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:              *cpu1000,
				corev1.ResourceMemory:           *memory1024,
				corev1.ResourceEphemeralStorage: *memory550,
			},
			Requests: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:              *cpu50,
				corev1.ResourceMemory:           *memory150,
				corev1.ResourceEphemeralStorage: *memory300,
			},
		}
	}
	envVars := []corev1.EnvVar{
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
			Name: "ENCRYPTION_IV",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp-encryption",
					},
					Key: "ENCRYPTION_IV",
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
			Name:  "service_crn_id",
			Value: saasCRNId,
		},
		{
			Name:  "OPENSHIFT_URL",
			Value: "https://kubernetes.default:443",
		},
		{
			Name: "IS_OPENSHIFT_ENV",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp",
					},
					Key: "IS_OPENSHIFT_ENV",
				},
			},
			//Value: strconv.FormatBool(instance.Spec.Config.IsOpenshiftEnv),
		},
		{
			Name:  "roksClientId",
			Value: "system:serviceaccount:" + instance.Namespace + ":ibm-iam-operand-restricted",
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
			Value: "platform-identity-management",
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
			Value: "https://platform-auth-service:9443/iam",
		},
		{
			Name:  "MASTER_HOST",
			Value: icpConsoleURL,
		},
	}

	idpEnvVarList := []string{"NODE_ENV", "LOG_LEVEL_IDPROVIDER", "LOG_LEVEL_MW", "PROVIDER_ISSUER_URL",
		"PREFERRED_LOGIN", "IDTOKEN_LIFETIME", "SAAS_CLIENT_REDIRECT_URL", "IBM_CLOUD_SAAS", "ROKS_ENABLED", "ROKS_URL",
		"ROKS_USER_PREFIX", "OS_TOKEN_LENGTH", "LIBERTY_TOKEN_LENGTH", "IDENTITY_PROVIDER_URL", "BASE_AUTH_URL",
		"BASE_OIDC_URL", "SCOPE_CLAIM", "OIDC_ISSUER_URL", "HTTP_ONLY", "IGNORE_LDAP_FILTERS_VALIDATION",
		"LDAP_ATTR_CACHE_SIZE", "LDAP_ATTR_CACHE_TIMEOUT", "LDAP_ATTR_CACHE_ENABLED", "LDAP_ATTR_CACHE_SIZELIMIT",
		"LDAP_SEARCH_CACHE_SIZE", "LDAP_SEARCH_CACHE_TIMEOUT", "LDAP_CTX_POOL_INITSIZE", "LDAP_CTX_POOL_MAXSIZE",
		"LDAP_CTX_POOL_TIMEOUT", "LDAP_CTX_POOL_WAITTIME", "LDAP_CTX_POOL_PREFERREDSIZE", "LDAP_SEARCH_CACHE_ENABLED",
		"LDAP_SEARCH_CACHE_SIZELIMIT", "LDAP_SEARCH_EXCLUDE_WILDCARD_CHARS", "LDAP_SEARCH_SIZE_LIMIT",
		"LDAP_SEARCH_TIME_LIMIT", "LDAP_SEARCH_CN_ATTR_ONLY", "LDAP_SEARCH_ID_ATTR_ONLY",
		"DB_CONNECT_TIMEOUT", "DB_IDLE_TIMEOUT", "DB_CONNECT_MAX_RETRIES", "DB_POOL_MIN_SIZE", "DB_POOL_MAX_SIZE", "SEQL_LOGGING"}
	idpEnvVars := buildIdpEnvVars(idpEnvVarList)

	envVars = append(envVars, idpEnvVars...)

	if instance.Spec.Config.EnableImpersonation {
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
		ImagePullPolicy: corev1.PullIfNotPresent,
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
				MountPath: "/opt/ibm/identity-provider/server/boot/auth-key",
			},
			{
				Name:      "identity-provider-cert",
				MountPath: "/opt/ibm/identity-provider/certs",
			},
			{
				Name:      "saml-cert",
				MountPath: "/certs/saml-certs",
			},
			{
				Name:      "pgsql-ca-cert",
				MountPath: "/certs/pgsql-ca",
			},
			{
				Name:      "pgsql-client-cert",
				MountPath: "/certs/pgsql-client",
			},
			{
				Name:      "pgsql-client-cred",
				MountPath: "/pgsql/clientinfo",
			},
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"curl", "-k", "https://platform-auth-service:9443/oidc/endpoint/OP/.well-known/openid-configuration"},
				},
			},
			InitialDelaySeconds: 20,
			PeriodSeconds:       15,
			TimeoutSeconds:      10,
			SuccessThreshold:    1,
			FailureThreshold:    5,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/",
					Port: intstr.IntOrString{
						IntVal: identityProviderPort,
					},
					Scheme: "HTTPS",
				},
			},
			TimeoutSeconds: 10,
		},
		Env: envVars,
	}

}

func buildIdentityManagerContainer(instance *operatorv1alpha1.Authentication, identityManagerImage string, icpConsoleURL string) corev1.Container {

	replicaCount := int(instance.Spec.Replicas)
	resources := instance.Spec.IdentityManager.Resources
	if resources == nil {
		resources = &corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:              *cpu1000,
				corev1.ResourceMemory:           *memory1024,
				corev1.ResourceEphemeralStorage: *memory550,
			},
			Requests: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:              *cpu50,
				corev1.ResourceMemory:           *memory150,
				corev1.ResourceEphemeralStorage: *memory300,
			},
		}
	}
	masterNodesList := ""
	baseIp := "10.0.0."
	for i := 1; i <= replicaCount; i++ {
		masterNodesList += baseIp + strconv.Itoa(i)
		if i != replicaCount {
			masterNodesList += " "
		}
	}

	envVars := []corev1.EnvVar{
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
			Name:  "AUTHZ_DISABLED",
			Value: "true",
		},
		{
			Name:  "OPENSHIFT_URL",
			Value: "https://kubernetes.default:443",
		},
		{
			Name: "IS_OPENSHIFT_ENV",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-idp",
					},
					Key: "IS_OPENSHIFT_ENV",
				},
			},
			//Value: strconv.FormatBool(instance.Spec.Config.IsOpenshiftEnv),
		},
		{
			Name:  "roksClientId",
			Value: "system:serviceaccount:" + instance.Namespace + ":ibm-iam-operand-restricted",
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
			Name: "SCIM_ADMIN_USER",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-scim-credentials",
					},
					Key: "scim_admin_username",
				},
			},
		},
		{
			Name: "SCIM_ADMIN_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "platform-auth-scim-credentials",
					},
					Key: "scim_admin_password",
				},
			},
		},
		{
			Name:  "IDPROVIDER_KUBEDNS_NAME",
			Value: "https://platform-identity-provider",
		},
		{
			Name:  "IAM_TOKEN_SERVICE_URL",
			Value: "https://platform-auth-service:9443",
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
		{
			Name:  "MASTER_HOST",
			Value: icpConsoleURL,
		},
	}

	idpEnvVarList := []string{"NODE_ENV", "LOG_LEVEL_IDMGMT", "LOG_LEVEL_MW", "IBM_CLOUD_SAAS", "IBMID_PROFILE_URL", "IBMID_PROFILE_CLIENT_ID", "IBMID_PROFILE_FIELDS", "AUDIT_DETAIL",
		"ROKS_ENABLED", "ROKS_USER_PREFIX", "IDENTITY_AUTH_DIRECTORY_URL", "OIDC_ISSUER_URL", "BOOTSTRAP_USERID", "CLUSTER_NAME", "HTTP_ONLY", "LDAP_SEARCH_SIZE_LIMIT", "LDAP_SEARCH_TIME_LIMIT",
		"LDAP_SEARCH_CN_ATTR_ONLY", "LDAP_SEARCH_ID_ATTR_ONLY", "LDAP_SEARCH_EXCLUDE_WILDCARD_CHARS", "IGNORE_LDAP_FILTERS_VALIDATION", "AUTH_SVC_LDAP_CONFIG_TIMEOUT",
		"SCIM_LDAP_SEARCH_SIZE_LIMIT", "SCIM_LDAP_SEARCH_TIME_LIMIT", "SCIM_ASYNC_PARALLEL_LIMIT", "SCIM_GET_DISPLAY_FOR_GROUP_USERS", "ATTR_MAPPING_FROM_CONFIG", "SCIM_AUTH_CACHE_MAX_SIZE", "SCIM_AUTH_CACHE_TTL_VALUE",
		"DB_CONNECT_TIMEOUT", "DB_IDLE_TIMEOUT", "DB_CONNECT_MAX_RETRIES", "DB_POOL_MIN_SIZE", "DB_POOL_MAX_SIZE", "SEQL_LOGGING"}

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
		Name:            "platform-identity-management",
		Image:           identityManagerImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
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
				Name:      "scim-ldap-attributes-mapping",
				MountPath: "/opt/ibm/identity-mgmt/config/scim-config",
			},
			{
				Name:      "pgsql-ca-cert",
				MountPath: "/certs/pgsql-ca",
			},
			{
				Name:      "pgsql-client-cert",
				MountPath: "/certs/pgsql-client",
			},
			{
				Name:      "pgsql-client-cred",
				MountPath: "/pgsql/clientinfo",
			},
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"curl", "-k", "https://platform-auth-service:9443/oidc/endpoint/OP/.well-known/openid-configuration"},
				},
			},
			InitialDelaySeconds: 20,
			PeriodSeconds:       15,
			TimeoutSeconds:      10,
			SuccessThreshold:    1,
			FailureThreshold:    5,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/",
					Port: intstr.IntOrString{
						IntVal: identityManagerPort,
					},
					Scheme: "HTTPS",
				},
			},
			TimeoutSeconds: 10,
		},
		Env: envVars,
	}

}

func buildContainers(instance *operatorv1alpha1.Authentication, authServiceImage string) []corev1.Container {

	authServiceContainer := buildAuthServiceContainer(instance, authServiceImage)
	//identityProviderContainer := buildIdentityProviderContainer(instance, identityProviderImage, icpConsoleURL, saasCrnId)
	//identityManagerContainer := buildIdentityManagerContainer(instance, identityManagerImage, icpConsoleURL)

	return []corev1.Container{authServiceContainer}
}

func buildManagerContainers(instance *operatorv1alpha1.Authentication, identityManagerImage string, icpConsoleURL string) []corev1.Container {

	identityManagerContainer := buildIdentityManagerContainer(instance, identityManagerImage, icpConsoleURL)

	return []corev1.Container{identityManagerContainer}
}

func buildProviderContainers(instance *operatorv1alpha1.Authentication, identityProviderImage string, icpConsoleURL string, saasCrnId string) []corev1.Container {

	identityProviderContainer := buildIdentityProviderContainer(instance, identityProviderImage, icpConsoleURL, saasCrnId)

	return []corev1.Container{identityProviderContainer}
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

func buildInitContainerEnvVars(envVarList []string, configmapName string) []corev1.EnvVar {

	envVars := []corev1.EnvVar{}
	for _, varName := range envVarList {
		envVar := corev1.EnvVar{
			Name: varName,
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: configmapName,
					},
					Key: varName,
				},
			},
		}
		envVars = append(envVars, envVar)

	}
	return envVars
}
