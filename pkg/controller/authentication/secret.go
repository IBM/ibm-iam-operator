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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var secretData map[string]map[string][]byte

func generateSecretData(instance *operatorv1alpha1.Authentication) {
	secretData = map[string]map[string][]byte{
		"platform-auth-idp-credentials": map[string][]byte{
			"admin_username": []byte(instance.Spec.Config.DefaultAdminUser),
			"admin_password": []byte(instance.Spec.Config.DefaultAdminPassword),
		},
		"platform-auth-idp-encryption": map[string][]byte{
			//@posriniv - get back
			"ENCRYPTION_KEY": []byte("encryption_key"),
			"algorithm":      []byte("aes256"),
			"inputEncoding":  []byte("utf8"),
			"outputEncoding": []byte("hex"),
		},
		"platform-oidc-credentials": map[string][]byte{
			"WLP_CLIENT_ID":                     []byte(instance.Spec.Config.WLPClientID),
			"WLP_CLIENT_SECRET":                 []byte(instance.Spec.Config.WLPClientSecret),
			"WLP_SCOPE":                         []byte("openid+profile+email"),
			"OAUTH2_CLIENT_REGISTRATION_SECRET": []byte(instance.Spec.Config.WLPClientRegistrationSecret),
		},
		"platform-auth-ibmid-jwk": map[string][]byte{
			"cert": []byte(`-----BEGIN CERTIFICATE-----
										  			MIIG0DCCBbigAwIBAgIQDyDiN8JrsjRvvfSx1fvrzDANBgkqhkiG9w0BAQsFADBN
										  			MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E
										  			aWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTgwODMxMDAwMDAwWhcN
										  			MjAxMTAzMTIwMDAwWjCBmzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCENvbG9yYWRv
										  			MRAwDgYDVQQHEwdCb3VsZGVyMTQwMgYDVQQKEytJbnRlcm5hdGlvbmFsIEJ1c2lu
										  			ZXNzIE1hY2hpbmVzIENvcnBvcmF0aW9uMRUwEwYDVQQLEwxJQk0gU2VjdXJpdHkx
										  			GjAYBgNVBAMTEWlkYWFzLmlhbS5pYm0uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
										  			AQ8AMIIBCgKCAQEAtbLV6yge386z4xvlRAuX76/Uj1Ef/98JQSIFN0CqqzwF4KT/
										  			4o1jsdaPNp+kJdkPaOkBHe7n9faIXuT+gN4SiWQodh2y0xsj31luJF0WnLjmdkDc
										  			DRSm/d1TcnAst8DA/0MkhRKBYcXA9YEpAveaaPOq9O+0wyPsccuIsxMez9ix4Njk
										  			IEds8q6VvWYOnUfF+vxbi/aVXRN7JRV8k8XV0ipcaLO5oNnENMzQKAkyhuUw3HkR
										  			ChbtW5uD7StyIn58J6o6ux2aNJwjtga1ZnQ703YLci20ahRex2T33IgmrxJNORGF
										  			y/MJd+Nxm3IoXCLwEBoOou0HjQ0dX8V45kLbPwIDAQABo4IDWzCCA1cwHwYDVR0j
										  			BBgwFoAUD4BhHIIxYdUvKOeNRji0LOHG2eIwHQYDVR0OBBYEFHBl2tNrvbbjGvvV
										  			3h8cfgwdcA77MBwGA1UdEQQVMBOCEWlkYWFzLmlhbS5pYm0uY29tMA4GA1UdDwEB
										  			/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwawYDVR0fBGQw
										  			YjAvoC2gK4YpaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NzY2Etc2hhMi1nNi5j
										  			cmwwL6AtoCuGKWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zc2NhLXNoYTItZzYu
										  			Y3JsMEwGA1UdIARFMEMwNwYJYIZIAYb9bAEBMCowKAYIKwYBBQUHAgEWHGh0dHBz
										  			Oi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCAYGZ4EMAQICMHwGCCsGAQUFBwEBBHAw
										  			bjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEYGCCsGAQUF
										  			BzAChjpodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyU2Vj
										  			dXJlU2VydmVyQ0EuY3J0MAwGA1UdEwEB/wQCMAAwggF/BgorBgEEAdZ5AgQCBIIB
										  			bwSCAWsBaQB3AKS5CZC0GFgUh7sTosxncAo8NZgE+RvfuON3zQ7IDdwQAAABZZBg
										  			vFQAAAQDAEgwRgIhAJ8CONXhOfIK3P2b1D9t3q/YT7aWrXns4DVS6ezNpz+iAiEA
										  			gaUPsI5txfuUWuYm25k44R+7yBW9wlLd08F+Sqx0fxIAdgCHdb/nWXz4jEOZX73z
										  			bv9WjUdWNv9KtWDBtOr/XqCDDwAAAWWQYL0hAAAEAwBHMEUCIQD2KfB5/aNd7iu7
										  			5umr+rc/0L62pinug8jcVY8DAoaR4wIgI9f/ch17zu7Y48H5e9sgtiVjB9GKk0Mc
										  			Ppe5u0vR+TQAdgC72d+8H4pxtZOUI5eqkntHOFeVCqtS6BqQlmQ2jh7RhQAAAWWQ
										  			YLyEAAAEAwBHMEUCIQCXJKNUE2eqRpaJ4sqI6Aae+vnQtmJoeCG9nqo1rp9YsAIg
										  			SdDIP2Os9jr+9o9M0c5x9TluUETYNWlIEQBpa3xQ/CowDQYJKoZIhvcNAQELBQAD
										  			ggEBADCzSEGKMQSFsv2Swe2MiE4kiVFerb06a8H5JcU26wSt3IsTDsn2WyvqB1Qj
										  			QaTSDmR1tO1zPXlWJ/REcdWi1JyxDBLLUd1yOZLazrUkImcmcucbTJfHzwakJ98f
										  			nBLc8k78etFbnopOqYpB+PYEKM56O+ILbJUcVKkYBLb6lHBOiU5WPkB/fPbX21/p
										  			i2OCF0H5u4Ov4xxGytAarlSgcNG4eZz88gqFedOMEdUMJTT97F2T8emMVJvofktK
										  			41RMreIrVhJ93toFm60qvFTpTSW7HkNcM3ADOYFAFaOkZIaK4cfU2EG4UM+iSh2T
										  			dkFT7dsc3V09lnpkGMSkqAs8VA0=
										  			-----END CERTIFICATE-----`),
		},
		"platform-auth-ibmid-sslchain": map[string][]byte{
			"cert": []byte(`-----BEGIN CERTIFICATE-----
													MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
													MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
													d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
													QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
													MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
													b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
													9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
													CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
													nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
													43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
													T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
													gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
													BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
													TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
													DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
													hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
													06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
													PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
													YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
													CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
													-----END CERTIFICATE-----
													-----BEGIN CERTIFICATE-----
													MIIElDCCA3ygAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADBh
													MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
													d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
													QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaME0xCzAJBgNVBAYTAlVT
													MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg
													U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
													ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83
													nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd
													KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f
													/ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX
													kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0
													/RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8C
													AQAwDgYDVR0PAQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY
													aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6
													Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1
													oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RD
													QS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v
													d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFA+AYRyCMWHVLyjnjUY4tCzh
													xtniMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA0GCSqGSIb3DQEB
													CwUAA4IBAQAjPt9L0jFCpbZ+QlwaRMxp0Wi0XUvgBCFsS+JtzLHgl4+mUwnNqipl
													5TlPHoOlblyYoiQm5vuh7ZPHLgLGTUq/sELfeNqzqPlt/yGFUzZgTHbO7Djc1lGA
													8MXW5dRNJ2Srm8c+cftIl7gzbckTB+6WohsYFfZcTEDts8Ls/3HB40f/1LkAtDdC
													2iDJ6m6K7hQGrn2iWZiIqBtvLfTyyRRfJs8sjX7tN8Cp1Tm5gr8ZDOo0rwAhaPit
													c+LJMto4JQtV05od8GiG7S5BNO98pVAdvzr508EIDObtHopYJeS4d60tbvVS3bR0
													j6tJLp07kzQoH3jOlOrHvdPJbRzeXDLz
													-----END CERTIFICATE-----`),
		},
	}
}

func (r *ReconcileAuthentication) handleSecret(instance *operatorv1alpha1.Authentication, currentSecret *corev1.Secret, requeueResult *bool) error {

	generateSecretData(instance)

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	for secret, _ := range secretData {
		err = r.client.Get(context.TODO(), types.NamespacedName{Name: secret, Namespace: instance.Namespace}, currentSecret)
		if err != nil && errors.IsNotFound(err) {
			// Define a new Secret
			newSecret := generateSecretObject(instance, r.scheme, secret)
			reqLogger.Info("Creating a new Secret", "Secret.Namespace", instance.Namespace, "Secret.Name", secret)
			err = r.client.Create(context.TODO(), newSecret)
			if err != nil {
				reqLogger.Error(err, "Failed to create new Secret", "Secret.Namespace", instance.Namespace, "Secret.Name", secret)
				return err
			}
			// Secret created successfully - return and requeue
			*requeueResult = true
		} else if err != nil {
			reqLogger.Error(err, "Failed to get Secret")
			return err
		}

	}

	return nil

}

func generateSecretObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, secretName string) *corev1.Secret {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name, "Secret.Name", secretName)
	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: instance.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData[secretName],
	}

	// Set Authentication instance as the owner and controller of the Secret
	err := controllerutil.SetControllerReference(instance, newSecret, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Secret")
		return nil
	}
	return newSecret
}
