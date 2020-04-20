# ibm-iam-operator
Operator used to install the cloud pak common iam services.


# Procedure to install


## Add the operator source on your openshift cluster

- Click the + button at the top right hand side corner of the Openshift console and add the operator source
```
apiVersion: operators.coreos.com/v1
kind: OperatorSource
metadata:
  name: opencloud-operators
  namespace: openshift-marketplace
spec:
  authorizationToken: {}
  displayName: IBMCS Operators
  endpoint: https://quay.io/cnr
  publisher: IBM
  registryNamespace: opencloudio
  type: appregistry
```

- Create an image pull secret for INTEGRATION on the openshift cluster in the `ibm-common-services` namespace

`oc -n ibm-common-services create secret docker-registry myintegrationkey --docker-server=hyc-cloud-private-integration-docker-local.artifactory.swg-devops.com --docker-username=USERID --docker-password=PASSWORD --docker-email=EMAILID`

- Install the ODLM Operator 

- Edit the Operand Config of the ODLM Operator and set the management ingress routeHost according to your Openshift Cluster
```
 - name: ibm-commonui-operator
      spec:
        commonWebUI: {}
        legacyHeader: {}
    - name: ibm-management-ingress-operator
      spec:
        managementIngress:
          routeHost: cp-console.apps.basked.os.fyre.ibm.com
        image:
          repository: hyc-cloud-private-integration-docker-local.artifactory.swg-devops.com/ibmcom/icp-management-ingress-ARCH
          tag: 2.5.1
    - name: ibm-ingress-nginx-operator
      spec:
        nginxIngress: {}
```

- Create the Operand Request through the ODLM operator

- Assign the image pull secret to the service accounts for services to download images from integration
```
oc -n ibm-common-services patch serviceaccount default -p '{"imagePullSecrets": [{"name": "myintegrationkey"}]}'
oc -n ibm-common-services patch serviceaccount cert-manager -p '{"imagePullSecrets": [{"name": "myintegrationkey"}]}'
oc -n ibm-common-services patch serviceaccount management-ingress -p '{"imagePullSecrets": [{"name": "myintegrationkey"}]}'
```

- Create the CA Cert and Cluter Issuers
```
apiVersion: certmanager.k8s.io/v1alpha1
kind: Issuer
metadata:
  name: cs-ss-issuer
  namespace: ibm-common-services
spec:
  selfSigned: {}
---
apiVersion: certmanager.k8s.io/v1alpha1
kind: Certificate
metadata:
  name: cs-ca-certificate
  namespace: ibm-common-services
spec:
  issuerRef:
    name: cs-ss-issuer
    kind: Issuer
  secretName: cs-ca-certificate-secret
  commonName: ca-certificate
  isCA: true
---
apiVersion: certmanager.k8s.io/v1alpha1
kind: ClusterIssuer
metadata:
  name: cs-ca-clusterissuer
spec:
  ca:
    secretName: cs-ca-certificate-secret
```

- Delete the `ibm-management-ingress-operator-xxxx` pod if you don't see any `management-ingress-xxx` pod in the `ibm-common-services` namespace

## SecurityContextConstraints Requirements

The IAM operator service supports running under the OpenShift Container Platform default restricted security context constraints.
