# ibm-iam-operator
Operator used to install the cloud pak common iam services.

**Important:** Do not install this operator directly. Only install this operator using the IBM Common Services Operator. For more information about installing this operator and other Common Services operators, see [Installer documentation](http://ibm.biz/cpcs_opinstall) (https://www.ibm.com/support/knowledgecenter/SSHKN6/kc_welcome_cs.html).

If you are using this operator as part of an IBM Cloud Pak, see the documentation for that IBM Cloud Pak to learn more about how to install and use the operator service. For more information about IBM Cloud Paks, see [IBM Cloud Paks that use Common Services](http://ibm.biz/cpcs_cloudpaks).

```
You can use the ibm-iam-operator to install the authentication and authorization services for the IBM Cloud Platform Common Services.

With these services, you can configure security for IBM Cloud Platform Common Services, IBM Certified Containers (IBM products), or IBM Cloud Paks that are installed.
```

For more information about the available IBM Cloud Platform Common Services, see the [IBM Knowledge Center](http://ibm.biz/cpcsdocs).

## Supported platforms

```
 - Red Hat OpenShift Container Platform 4.2 or newer installed on one of the following platforms:

   - Linux x86_64
   - Linux on Power (ppc64le)
   - Linux on IBM Z and LinuxONE
```

## Operator versions

```
- 3.5.0
- 3.6.0
  - With this version, support for OpenShift 4.3 is added.
```

## Prerequisites

Before you install this operator, you need to first install the operator dependencies and prerequisites:

- For the list of operator dependencies, see the IBM Knowledge Center [Common Services dependencies documentation](http://ibm.biz/cpcs_opdependencies).

- For the list of prerequisites for installing the operator, see the IBM Knowledge Center [Preparing to install services documentation](http://ibm.biz/cpcs_opinstprereq).

## Documentation

To install the operator with the IBM Common Services Operator follow the the installation and configuration instructions within the IBM Knowledge Center.

- If you are using the operator as part of an IBM Cloud Pak, see the documentation for that IBM Cloud Pak [IBM Cloud Paks that use Common Services](http://ibm.biz/cpcs_cloudpaks).
- If you are using the operator with an IBM Containerized Software, see the IBM Cloud Platform Common Services Knowledge Center [Installer documentation](http://ibm.biz/cpcs_opinstall).

## (Optional) Developer guide

If, as a developer, you are looking to build and test this operator to try out and learn more about the operator and its capabilities, you can use the following developer guide. This guide provides commands for a quick install and initial validation for running the operator.

**Important:** The following developer guide is provided as-is and only for trial and education purposes. IBM and IBM Support does not provide any support for the usage of the operator with this developer guide. For the official supported install and usage guide for the operator, see the the IBM Knowledge Center documentation for your IBM Cloud Pak or for IBM Cloud Platform Common Services.

### Quick start guide

- These steps are based on [Operator Framework: Getting Started](https://github.com/operator-framework/getting-started#getting-started)
  and [Creating an App Operator](https://github.com/operator-framework/operator-sdk#create-and-deploy-an-app-operator).

- Repositories
  - https://github.com/IBM/ibm-iam-operator

- Set the Go environment variables.

  `export GOPATH=/home/<username>/go`  
  `export GO111MODULE=on`  
  `export GOPRIVATE="github.ibm.com"`


- Create the operator skeleton.
  - `cd /home/ibmadmin/workspace/cs-operators`
  - `operator-sdk new iam-operator --repo github.com/ibm/iam-operator`
  - the main program for the operator, `cmd/manager/main.go`, initializes and runs the Manager
  - the Manager will automatically register the scheme for all custom resources defined under `pkg/apis/...`
    and run all controllers under `pkg/controller/...`
  - the Manager can restrict the namespace that all controllers will watch for resources

- Create the API definition ("Kind") which is used to create the CRD
  - `cd /home/ibmadmin/workspace/cs-operators/iam-operator`
  - create `hack/boilerplate.go.txt`
	- contains copyright for generated code
  - `operator-sdk add api --api-version=operator.ibm.com/v1alpha1 --kind=IAM`
	- generates `pkg/apis/operator/v1alpha1/<kind>_types.go`
	  - example: `pkg/apis/operator/v1alpha1/authentications.go`
    - generates `deploy/crds/operator.ibm.com_<kind>s_crd.yaml`
      - example: `deploy/crds/operator.ibm.com_authentications_crd.yaml`
    - generates `deploy/crds/operator.ibm.com_v1alpha1_<kind>_cr.yaml`
      - example: `deploy/crds/operator.ibm.com_v1alpha1_authentications_cr.yaml`
  - the operator can manage more than 1 Kind

- Edit `<kind>_types.go` and add the fields that will be exposed to the user. Then regenerate the CRD.
  - edit `<kind>_types.go` and add fields to the `<Kind>Spec` struct
  - `operator-sdk generate k8s`
	- updates `zz_generated.deepcopy.go`
  - "Operator Framework: Getting Started" says to run `operator-sdk generate openapi`. That command is deprecated, so run the next 2 commands instead.
    - `operator-sdk generate crds`
	  - updates `operator.ibm.com_authentications_crd.yaml`
    - `openapi-gen --logtostderr=true -o "" -i ./pkg/apis/operator/v1alpha1 -O zz_generated.openapi -p ./pkg/apis/operator/v1alpha1 -h hack/boilerplate.go.txt -r "-"`
      - creates `zz_generated.openapi.go`
      - if you need to build `openapi-gen`, follow these steps. The binary will be built in `$GOPATH/bin`.
        ```
        git clone https://github.com/kubernetes/kube-openapi.git
        cd kube-openapi
        go mod tidy
        go build -o ./bin/openapi-gen k8s.io/kube-openapi/cmd/openapi-gen
        ```
  - anytime you modify `<kind>_types.go`, run `generate k8s`, `generate crds`, and `openapi-gen` again to update the CRD and the generated code

- Create the controller. It will create resources like Deployments, DaemonSets, etc.
  - `operator-sdk add controller --api-version=operator.ibm.com/v1alpha1 --kind=Metering`
  - there is 1 controller for each Kind/CRD
  - the controller will watch and reconcile the resources owned by the CR
  - for information about the Go types that implement Deployments, DaemonSets, etc, go to https://godoc.org/k8s.io/api/apps/v1
  - for information about the Go types that implement Pods, VolumeMounts, etc, go to https://godoc.org/k8s.io/api/core/v1
  - for information about the Go types that implement Ingress, etc, go to https://godoc.org/k8s.io/api/networking/v1beta1

## Testing
- Create the CRD. Do this one time before starting the operator.
  - `cd /home/ibmadmin/workspace/cs-operators/iam-operator`
  - `oc login...`
  - `kubectl create -f deploy/crds/operator.ibm.com_authentications_crd.yaml`
  - `kubectl get crd meterings.operator.ibm.com`
  - delete and create again if the CRD changes
    - `kubectl delete crd authentications.operator.ibm.com`

- Run the operator locally
  - `cd /home/ibmadmin/workspace/cs-operators/iam-operator`
  - `oc login...`
  - `export OPERATOR_NAME=iam-operator`
  - `operator-sdk up local --namespace=<namespace>`

- Create a CR which is an instance of the CRD
  - edit `deploy/crds/operator.ibm.com_v1alpha1_authentications_cr.yaml`
  - `kubectl create -f deploy/crds/operator.ibm.com_v1alpha1_authentications_cr.yaml`

- Delete the CR and the associated resources that were created
  - `kubectl delete authentications example-authentication`
```

### End-to-End testing

For more instructions on how to run end-to-end testing with the Operand Deployment Lifecycle Manager, see [ODLM guide](https://github.com/IBM/operand-deployment-lifecycle-manager/blob/master/docs/install/common-service-integration.md#end-to-end-test).


## SecurityContextConstraints Requirements

The IAM operator service does not support running under the OpenShift Container Platform default restricted security context constraints.

## PodSecurityPolicy Requirements

The IAM operator does not define any specific pod security requirements.
