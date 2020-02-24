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

package pap

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var cpu10 = resource.NewMilliQuantity(10, resource.DecimalSI)            // 10m
var cpu20 = resource.NewMilliQuantity(20, resource.DecimalSI)            // 20m
var cpu50 = resource.NewMilliQuantity(50, resource.DecimalSI)            // 50m
var cpu100 = resource.NewMilliQuantity(100, resource.DecimalSI)          // 100m
var cpu200 = resource.NewMilliQuantity(200, resource.DecimalSI)          // 200m
var cpu1000 = resource.NewMilliQuantity(1000, resource.DecimalSI)        // 1000m
var memory20 = resource.NewQuantity(20*1024*1024, resource.BinarySI)     // 20Mi
var memory32 = resource.NewQuantity(32*1024*1024, resource.BinarySI)     // 32Mi
var memory100 = resource.NewQuantity(100*1024*1024, resource.BinarySI)   // 100Mi
var memory128 = resource.NewQuantity(128*1024*1024, resource.BinarySI)   // 128Mi
var memory200 = resource.NewQuantity(200*1024*1024, resource.BinarySI)   // 200Mi
var memory256 = resource.NewQuantity(256*1024*1024, resource.BinarySI)   // 256Mi
var memory512 = resource.NewQuantity(512*1024*1024, resource.BinarySI)   // 512Mi
var memory1024 = resource.NewQuantity(1024*1024*1024, resource.BinarySI) // 1024Mi
var memory2560 = resource.NewQuantity(2560*1024*1024, resource.BinarySI) // 2560Mi

func buildAuditContainer(auditImage string, journalPath string) corev1.Container {

	return corev1.Container{
		Name:            "icp-audit-service",
		Image:           auditImage,
		ImagePullPolicy: corev1.PullAlways,
		Env: []corev1.EnvVar{
			{
				Name:  "AUDIT_DIR",
				Value: "/app/audit",
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "shared",
				MountPath: "/app/audit",
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
		Resources: corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    *cpu200,
				corev1.ResourceMemory: *memory200},
			Requests: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    *cpu20,
				corev1.ResourceMemory: *memory20},
		},
	}

}

func buildPapContainer(papImage string) corev1.Container {

	return corev1.Container{
		Name:            "auth-pap",
		Image:           papImage,
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
		Resources: corev1.ResourceRequirements{
			Limits: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    *cpu1000,
				corev1.ResourceMemory: *memory1024},
			Requests: map[corev1.ResourceName]resource.Quantity{
				corev1.ResourceCPU:    *cpu50,
				corev1.ResourceMemory: *memory200},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "mongodb-ca-cert",
				MountPath: "/certs/mongodb-ca",
			},
			{
				Name:      "pap-cert",
				MountPath: "/certs/pap",
			},
			{
				Name:      "cluster-ca",
				MountPath: "/certs/cluster-ca",
			},
			{
				Name:      "shared",
				MountPath: "/app/audit",
			},
			{
				Name:      "mongodb-client-cert",
				MountPath: "/certs/mongodb-client",
			},
		},
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/v1/health",
					Port: intstr.IntOrString{
						IntVal: iamPapServiceValues.Port,
					},
					Scheme: "HTTPS",
				},
			},
			InitialDelaySeconds: 60,
			PeriodSeconds:       30,
		},
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/v1/health",
					Port: intstr.IntOrString{
						IntVal: iamPapServiceValues.Port,
					},
					Scheme: "HTTPS",
				},
			},
			InitialDelaySeconds: 75,
			PeriodSeconds:       30,
		},
		Env: []corev1.EnvVar{
			{
				Name:  "APP_ENVIRONMENT",
				Value: "production",
			},
			{
				Name:  "BABEL_DISABLE_CACHE",
				Value: "1",
			},
			{
				Name:  "NODE_EXTRA_CA_CERTS",
				Value: "/certs/cluster-ca/ca.crt",
			},
			{
				Name:  "CHECK_BUILD_TEST",
				Value: "ENABLE",
			},
			{
				Name:  "MONGO_DB",
				Value: "platform-db",
			},
			{
				Name:  "MONGO_COLLECTION",
				Value: "iam",
			},
			{
				Name:  "AUDIT_LOG_PATH",
				Value: "/app/audit/pap-audit.log",
			},
			{
				Name:  "SERVICE_NAME",
				Value: "iam-policy-administration",
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
				Name: "AUDIT_ENABLED",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "auth-pap",
						},
						Key: "AUDIT_ENABLED",
					},
				},
			},
			{
				Name: "AUDIT_DETAIL",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "auth-pap",
						},
						Key: "AUDIT_DETAIL",
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
				Name:  "DB_NAME",
				Value: "platform-db",
			},
			{
				Name:  "IAM_USER",
				Value: "iam",
			},
			{
				Name:  "PDP_URL",
				Value: "https://iam-pdp:7998",
			},
			{
				Name:  "PLATFORM",
				Value: "container",
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
				Name:  "IDENTITY_PROVIDER_URL",
				Value: "https://platform-identity-provider:4300",
			},
			{
				Name:  "IDENTITY_MGMT_URL",
				Value: "https://platform-identity-management:4500",
			},
			{
				Name:  "IAM_TOKEN_SERVICE_URL",
				Value: "https://iam-token-service:10443",
			},
		},
	}

}

func buildContainers(auditImage string, papImage string, journalPath string) []corev1.Container {

	auditContainer := buildAuditContainer(auditImage, journalPath)
	papContainer := buildPapContainer(papImage)

	return []corev1.Container{auditContainer, papContainer}
}
