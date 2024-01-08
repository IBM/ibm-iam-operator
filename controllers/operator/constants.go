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

const (
	// ClusterConfigName ... ibmcloud-cluster-info
	ClusterAddr          string = "cluster_address"
	ClusterEP            string = "cluster_endpoint"
	RouteHTTPPort        string = "cluster_router_http_port"
	RouteHTTPSPort       string = "cluster_router_https_port"
	RouteHTTPPortValue   string = "80"
	RouteHTTPSPortValue  string = "443"
	ClusterName          string = "cluster_name"
	ClusterNameValue     string = "mycluster"
	ClusterAPIServerHost string = "cluster_kube_apiserver_host"
	ClusterAPIServerPort string = "cluster_kube_apiserver_port"
	ClusterSecretName    string = "ibmcloud-cluster-ca-cert"
	ProxyAddress         string = "proxy_address"
	ProviderSVC          string = "im_idprovider_endpoint"
	IDMgmtSVC            string = "im_idmgmt_endpoint"
)

var ArchList = []string{
	"amd64",
	"ppc64le",
	"s390x",
}

const registerClientScript = `#!/bin/sh
HTTP_CODE=""
while true
do
  HTTP_CODE=$(curl -k -o /dev/null -I  -w "%{http_code}"  -X GET -u oauthadmin:$WLP_CLIENT_REGISTRATION_SECRET -H "Content-Type: application/json" https://platform-auth-service:9443/oidc/endpoint/OP/registration/$WLP_CLIENT_ID)
  if [ $HTTP_CODE = "404" -o $HTTP_CODE = "200" ] ; then
	 break;
  fi
done
if [ $HTTP_CODE = "404" ]
then
  echo "Running new client id registration"
  cp /jsons/platform-oidc-registration.json platform-oidc-registration.json
  until curl -i -k -X POST -u oauthadmin:$WLP_CLIENT_REGISTRATION_SECRET \
   -H "Content-Type: application/json" \
   --data @platform-oidc-registration.json \
   https://platform-auth-service:9443/oidc/endpoint/OP/registration | grep '201 Created'; do sleep 1; done;
else
  echo "Running update client id registration."
  cp /jsons/platform-oidc-registration.json platform-oidc-registration.json
  until curl -i -k -X PUT -u oauthadmin:$WLP_CLIENT_REGISTRATION_SECRET \
   -H "Content-Type: application/json" \
   --data @platform-oidc-registration.json \
   https://platform-auth-service:9443/oidc/endpoint/OP/registration/$WLP_CLIENT_ID | grep '200 OK'; do sleep 1; done;
fi
`

var registrationJson string = `{
  "token_endpoint_auth_method": "client_secret_basic",
  "client_id": {{printf "%q" .WLPClientID}},
  "client_secret": {{printf "%q" .WLPClientSecret}},
  "scope": "openid profile email",
  "grant_types": [
    "authorization_code",
    "client_credentials",
    "password",
    "implicit",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:jwt-bearer"
  ],
  "response_types": [
    "code",
    "token",
    "id_token token"
  ],
  "application_type": "web",
  "subject_type": "public",
  "post_logout_redirect_uris": ["https://{{.ICPConsoleURL}}/console/logout"],
  "preauthorized_scope": "openid profile email general",
  "introspect_tokens": true,
  "functional_user_groupIds": ["Administrator"],
  "trusted_uri_prefixes": ["https://{{.ICPConsoleURL}}"],
  "redirect_uris": [{{ range $_, $url := .ICPRegistrationConsoleURIs}}{{printf "%q" $url}}{{", "}}{{end}}"https://127.0.0.1:443/idauth/oidc/endpoint/OP"]
}`

var scimLdapAttributesMapping string = `{
    "default": {
        "user": {
            "id": "dn",
            "userName": "uid",
            "principalName": "uid",
            "displayName": "cn",
            "givenName": "cn",
            "familyName": "sn",
            "fullName": "cn",
            "externalId": "dn",
            "emails": "mail",
            "created": "createTimestamp",
            "lastModified": "modifyTimestamp",
            "phoneNumbers": [{
                    "value": "mobile",
                    "type": "mobile"
                },
                {
                    "value": "telephoneNumber",
                    "type": "work"
                }],
            "objectClass": "person",
            "groups": "memberOf"
        },
        "group": {
            "id": "dn",
            "name": "cn",
            "principalName": "cn",
            "displayName": "cn",
            "externalId": "dn",
            "created": "createTimestamp",
            "lastModified": "modifyTimestamp",
            "objectClass": "groupOfUniqueNames",
            "members": "uniqueMember"
        }
    }
}
`
