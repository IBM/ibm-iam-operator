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
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"time"
)



func generateSecretData(instance *operatorv1alpha1.Authentication) map[string]map[string][]byte {
	secretData := map[string]map[string][]byte{
		"platform-auth-ldaps-ca-cert": map[string][]byte{
			"certificate": []byte(""),
		},
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
			"IBMID_CLIENT_SECRET":               []byte("903305fb599c8328a4d86d4cbdd07368"),
			"IBMID_PROFILE_CLIENT_SECRET":       []byte("C1bR0rO7kE0cE3xM2tV1gI0mG1cH3jK4dD7iQ8rW6pF1aF4mQ5"),
		},
		//This is a dummy cert which has to be replaced by the user
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
		"platform-auth-ibmid-ssl-chain": map[string][]byte{
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
		//@posriniv - get back and remove these dummy certs, hardcoded for testing purpose
		"cluster-ca-cert": map[string][]byte{
			"tls.crt": []byte(`
			-----BEGIN CERTIFICATE-----
			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
			neyWMGYln+Yy1ws=
			-----END CERTIFICATE-----`),
			"tls.key": []byte(`
			-----BEGIN RSA PRIVATE KEY-----
			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
			-----END RSA PRIVATE KEY-----`),
		},
		"icp-serviceid-apikey-secret": map[string][]byte{
			"ICP_API_KEY": []byte(`mBGr2btxpejjJmKouHLxi-xLeBqRJJ-16MEsiLEfhD_e`),
		},
		"icp-management-ingress-tls-secret": map[string][]byte{
			"ca.crt": []byte(`
			-----BEGIN CERTIFICATE-----
			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
			neyWMGYln+Yy1ws=
			-----END CERTIFICATE-----`),
			"tls.crt": []byte(`
			-----BEGIN CERTIFICATE-----
			MIIFHzCCAwegAwIBAgIQd2MDpRhZSfgzy8egOOAR0DANBgkqhkiG9w0BAQsFADBj
			MQswCQYDVQQGEwJVUzERMA8GA1UECAwITmV3IFlvcmsxDzANBgNVBAcMBkFybW9u
			azEaMBgGA1UECgwRSUJNIENsb3VkIFByaXZhdGUxFDASBgNVBAMMC3d3dy5pYm0u
			Y29tMB4XDTIwMDEwMzA5MTIyNVoXDTIwMDQwMjA5MTIyNVowNDEVMBMGA1UEChMM
			Y2VydC1tYW5hZ2VyMRswGQYDVQQDExJtYW5hZ2VtZW50LWluZ3Jlc3MwggEiMA0G
			CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQZ0+yWURz9ClHkZ2RdDOoMxXGGmq/
			9JAbEtllr47qHDPayJItX7yrlfqwVQYd3O90hHr3ZOIBKil//8xA/xNa7iEWmPa1
			2VW4effJMpvcoENxhwgsl+5cLmORfAdwpYgRgUQTXjeU0NnFt2fqsQpNIrXGIoC2
			beVzADd3aY8bZZvV1lhFVDKqpuOjB39x0tmXkRgAot9/nYVTVrGn5oPU3jOhh/+8
			CjGZWC7sadEIOOr/k6gmluf3XTnFaVcFQSgTMQNUXqBL3ymxqHR+7seDYWvFjov4
			ZyF9301r0c6aVsc2kxSndl8kQT+PUiJXfMcn2XmPBpSJlL5r/Sk9E8utAgMBAAGj
			gf0wgfowEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAfBgNVHSME
			GDAWgBTC2HAEUByjL3UNq5Aw9wwpzSQmZzCBswYDVR0RBIGrMIGoghJtYW5hZ2Vt
			ZW50LWluZ3Jlc3OCKGljcC1jb25zb2xlLmFwcHMuY29yb25hbC5vcy5meXJlLmli
			bS5jb22CImljcC1tYW5hZ2VtZW50LWluZ3Jlc3Mua3ViZS1zeXN0ZW2CJmljcC1t
			YW5hZ2VtZW50LWluZ3Jlc3Mua3ViZS1zeXN0ZW0uc3ZjghZpY3AtbWFuYWdlbWVu
			dC1pbmdyZXNzhwR/AAABMA0GCSqGSIb3DQEBCwUAA4ICAQAMAd/HutsFiOVlqh2t
			ybryBcXXbLcETCL798rTKCisjMkiN2q2K8tbFt4yoNlc0kcqTwecMuw6DoplpT/6
			k9fxYLYBPHY1BOBqMf3c9kP552TgQBtg0C4tbWNN/cnh6uLEdn6/UriEVW2SXnk3
			hSxeobqHC3w/sttd1ZHCFIOjO0DUKTbmayaFEQabxIpi7gniZ/f29XsrnMtgfXwC
			l2PMGXj3jxr3NhSzE/DlnyYMZJY0nOJKiVopiSOyFrjAyx4NlROT/ivql3ZX3OcP
			EuRORtxHjPoSMxMMt4hlu3aQQn8pkhbt+VazR68rdibsucc19prsKOWBqsklhSH4
			ELuBX+/SxTemQUKzi6/rUDATRo3+m+hPoygIVdVqWR+2vf/ROzOrrwyi9gpDqI8q
			anfqx+ICs4pzBp4mzx7EOFehrMDsqkWtSvs+Rz3rPkhOOo7249z1uBiEXNrW18z9
			87kVu3MAEbAtV7u7IKmTtAW0GXZ8hVU6QghOAsmwOrGk8NieRK6elGJ7Oa4UiQzq
			0DYoWr5CN1FG5YnfH7OzoPYG38welPxwQnIePma1Wu8yXO5xvIdiT+C24nr0tOqH
			QeQsO1ZfrCk6MQJZVKUZeZXfW+BNxCFeDTC5/bhD3HTK+9CcK63ftd3ouQZCInz/
			W663EOCQddSsHG+8Fn8ms+gdpw==
			-----END CERTIFICATE-----`),
			"tls.key": []byte(`
			-----BEGIN RSA PRIVATE KEY-----
			MIIEowIBAAKCAQEA0GdPsllEc/QpR5GdkXQzqDMVxhpqv/SQGxLZZa+O6hwz2siS
			LV+8q5X6sFUGHdzvdIR692TiASopf//MQP8TWu4hFpj2tdlVuHn3yTKb3KBDcYcI
			LJfuXC5jkXwHcKWIEYFEE143lNDZxbdn6rEKTSK1xiKAtm3lcwA3d2mPG2Wb1dZY
			RVQyqqbjowd/cdLZl5EYAKLff52FU1axp+aD1N4zoYf/vAoxmVgu7GnRCDjq/5Oo
			Jpbn9105xWlXBUEoEzEDVF6gS98psah0fu7Hg2FrxY6L+Gchfd9Na9HOmlbHNpMU
			p3ZfJEE/j1IiV3zHJ9l5jwaUiZS+a/0pPRPLrQIDAQABAoIBAHSHX+vEuF7xxmcr
			R+S+Cehh8CneOZRtxmotBvwxxwKmlGQgRIQ0hQWYjh0s3YezMv1+2lccxLaMAbp9
			qJMrTYJJppzBGSojhSfqox+QOdCKmEuRioOMzI4kri36IRrepA/NrOf7ha6jfTFt
			1SBIsA7jeqp4PmpDVsoP8/PERW22RxGuHFwj8tIf2/Qyvd+nvNlFteUZJ7/8Sf9M
			PCy9e6peICa8q01AwXFVjX0eCe+qOrLrJvQfG8rWtsmsy7euyXwngrzoVrJl/QWw
			ErsDkA4v8iRcqiDtM5lMV1bmRG68f2M6DKFX3j5fEzuBnOUykhWljYEK5af2vVFb
			Dyv1U6ECgYEA1zeJAMvVk7dZZ4oIvSIbv1zJeaoPGEvKH+hK0L31ZNPdwYFZPJTF
			PpF4Qfg/b+7Bgw/5CNwjvaW1GHCW4vvwCJDYVxbtXTC8I5AxH2/9YF68Ra2e+5gP
			tGSL1fhz44tInMD7ukUm39CBnCkP05nB7NHxUVXa9BY52lfj+iC5dEUCgYEA9+VA
			CH8odqerBqnZ0uZ18OaTAZT2Hs/tLKc6jGJRsSakuw2PM/oa04Jxc3o6qcT0zuTP
			zqAsibn128M3h7n3jFDQ6J+ksgfbmMEIDqOxU8s3zziaeoxQ0+hZFflcLScfViFi
			9Z97pPrO61f5TTgyf8vTP0QLc5vZjRiIJSYPVEkCgYEAq5jOFeJwMk04bcOzYAn4
			EcZLpkQfsQGM8Y/nRzSOmowK/iTCH/mGo3KdbgwfmIHHrVZo+9V6cdXT5N6wj97M
			7id/N0FClNEs0TZA1I4YemROvUfHwVbm/rBEhqCI1l7R0JpWm5hTfJTlIrvisJah
			9s8WGAHaiE/IZP06+s5oz/kCgYBqqtKq1UxsAimtbFi2T0RgrFaFT7u39nBvzmV7
			ErNkLuSjOGpuSyhP6sk2j1m+w2kzvXFNz85aVRJdxdqXJIZIcl3yOv97O7ZaPHVj
			FzyuebtCB3ExWj9Nb6Ult27aXwM05JjYaA+kJefzjJ9RguT36JS1nGnxDRbHh87N
			bVsbQQKBgB1bjabPQp5Zl0Jh0fWATDFYYDiDJfCxszkRhXXYm/geYJYwIZdgh74k
			0vobPxM3TLBe8ZaKdqMgprhA/ojs86V4HwQZRIa0hBG4XtSzOo5EWVZdjucwkSlg
			AZbXTR4ZlkpFBdF6YYYVwv942ed6c359BV/fxJHMM/sAPqekPLj/
			-----END RSA PRIVATE KEY-----`),
		},
		"auth-pdp-secret": map[string][]byte{
			"ca.crt": []byte(commonCaCert),
			"tls.crt": []byte(pdpCert),
			"tls.key": []byte(pdpKey),
		},
		"iam-pap-secret": map[string][]byte{
			"ca.crt": []byte(commonCaCert),
			"tls.crt": []byte(papCert),
			"tls.key": []byte(papKey),
		},
		"identity-provider-secret": map[string][]byte{
			"ca.crt": []byte(commonCaCert),
			"tls.crt": []byte(providerCert),
			"tls.key": []byte(providerKey),
		},
		"platform-auth-secret": map[string][]byte{
			"ca.crt": []byte(commonCaCert),
			"tls.crt": []byte(authCert),
			"tls.key": []byte(authKey),
		},
		"platform-identity-management": map[string][]byte{
			"ca.crt": []byte(commonCaCert),
			"tls.crt": []byte(mgmtCert),
			"tls.key": []byte(mgmtKey),
		},
	}
	return secretData
}

func (r *ReconcileAuthentication) handleSecret(instance *operatorv1alpha1.Authentication, currentSecret *corev1.Secret, requeueResult *bool) error {

	secretData := generateSecretData(instance)

	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	for secret, _ := range secretData {
		err = r.client.Get(context.TODO(), types.NamespacedName{Name: secret, Namespace: instance.Namespace}, currentSecret)
		if err != nil && errors.IsNotFound(err) {
			// Define a new Secret
			newSecret := generateSecretObject(instance, r.scheme, secret, secretData[secret])
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

func (r *ReconcileAuthentication) handleMongoSecrets(instance *operatorv1alpha1.Authentication, mongoSecret *corev1.Secret, requeueResult *bool) error {

	mongoSecretNames := []string{"icp-mongodb-admin", "icp-mongodb-client-cert"}
	mongoSecretData := r.generateMongoData(mongoSecretNames)
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	var err error

	for _, secret := range mongoSecretNames {
		err = r.client.Get(context.TODO(), types.NamespacedName{Name: secret, Namespace: instance.Namespace}, mongoSecret)
		if err != nil && errors.IsNotFound(err) {
			// Define a new Secret
			newSecret := generateSecretObject(instance, r.scheme, secret, mongoSecretData[secret])
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

func (r *ReconcileAuthentication) generateMongoData(mongoSecretNames []string) map[string]map[string][]byte {
	reqLogger := log.WithValues("Generating Secrets", mongoSecretNames)
	mongoSecretData := map[string]map[string][]byte{}
	mongodbNamespace := "ibm-mongodb-operator"
	var mongoSecret *corev1.Secret

	// creates the in-cluster config
	config, err := config.GetConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	for _, secret := range mongoSecretNames {

		for {
			mongoSecret, err = clientset.CoreV1().Secrets(mongodbNamespace).Get(secret, metav1.GetOptions{})

			if err == nil {
				break
			}
			reqLogger.Error(err, "Failed to get mongodb secret in the", mongodbNamespace, "namespace, retry after some time")
			time.Sleep(2 * time.Second)
		}

		mongoSecretData[secret] = mongoSecret.Data

	}

	return mongoSecretData

}

func generateSecretObject(instance *operatorv1alpha1.Authentication, scheme *runtime.Scheme, secretName string, secretData map[string][]byte) *corev1.Secret {
	reqLogger := log.WithValues("Instance.Namespace", instance.Namespace, "Instance.Name", instance.Name, "Secret.Name", secretName)
	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: instance.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}

	// Set Authentication instance as the owner and controller of the Secret
	err := controllerutil.SetControllerReference(instance, newSecret, scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to set owner for Secret")
		return nil
	}
	return newSecret
}
