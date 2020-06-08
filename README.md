# ibm-iam-operator

The `ibm-iam-operator` installs the IBM Cloud Platform Common Services Identity and access management (IAM) service.

**Important:** Do not install this operator directly. Install this operator only by using the IBM Common Service Operator. For more information about installing the IBM Common Service Operator operator, see [Installer documentation](http://ibm.biz/cpcs_opinstall) (https://www.ibm.com/support/knowledgecenter/SSHKN6/kc_welcome_cs.html).

If you are using the operator as part of an IBM Cloud Pak, see the documentation for that IBM Cloud Pak to learn more about how to install and use the operator service. For more information about IBM Cloud Paks, see [IBM Cloud Paks that use Common Services](http://ibm.biz/cpcs_cloudpaks).

You can use the `ibm-iam-operator` to install the authentication and authorization services for the IBM Cloud Platform Common Services.

With these services, you can configure security for IBM Cloud Platform Common Services, IBM Certified Containers (IBM products), or IBM Cloud Paks that are installed.

For more information about the available IBM Cloud Platform Common Services, see the [IBM Knowledge Center](http://ibm.biz/cpcsdocs).

## Supported platforms

 - Red Hat OpenShift Container Platform 4.2 or newer installed on one of the following platforms:

   - Linux x86_64
   - Linux on Power (ppc64le)
   - Linux on IBM Z and LinuxONE

## Operator versions
- 3.6.2 
  - stable v1 on 6/6/2020
- 3.6.1
  - Beta release
- 3.6.0
  - With this version, support for OpenShift 4.3 is added.
- 3.5.0

## Prerequisites

Before you install this operator, you need to first install the operator dependencies and prerequisites:

- For the list of operator dependencies, see the IBM Knowledge Center [Common Services dependencies documentation](http://ibm.biz/cpcs_opdependencies).

- For the list of prerequisites for installing the operator, see the IBM Knowledge Center [Preparing to install services documentation](http://ibm.biz/cpcs_opinstprereq).

## Documentation

To install the operator by using the IBM Common Services Operator, follow the installation and configuration instructions that are in the IBM Knowledge Center.

- If you are using the operator as part of an IBM Cloud Pak, see the documentation for that IBM Cloud Pak [IBM Cloud Paks that use Common Services](http://ibm.biz/cpcs_cloudpaks).
- If you are using the operator with an IBM Containerized Software, see the IBM Cloud Platform Common Services Knowledge Center [Installer documentation](http://ibm.biz/cpcs_opinstall).

### End-to-End testing

For more instructions about how to run end-to-end testing with the Operand Deployment Lifecycle Manager, see [ODLM guide](https://github.com/IBM/operand-deployment-lifecycle-manager/blob/master/docs/install/common-service-integration.md#end-to-end-test).

### Quick start guide

These steps are based on the [Operator Framework: Getting Started](https://github.com/operator-framework/getting-started#getting-started) and [Creating an App Operator](https://github.com/operator-framework/operator-sdk#create-and-deploy-an-app-operator).

- Repositories
  - https://github.com/IBM/ibm-iam-operator

Complete the following steps:

1. Set the Go environment variables.
  `export GOPATH=/home/<username>/go`  
  `export GO111MODULE=on`  
  `export GOPRIVATE="github.ibm.com"`

2. Create the operator skeleton.
  - `cd /home/ibmadmin/workspace/cs-operators`
  - `operator-sdk new iam-operator --repo github.com/ibm/iam-operator`
  
  The main program for the operator, `cmd/manager/main.go`, initializes and runs the Manager. The Manager completes the following tasks:
  - Automatically registers the scheme for all custom resources that are defined under `pkg/apis/...`.
  - Runs all controllers under `pkg/controller/...`. 
  - Restrict the namespace that all controllers watch for resources.

3. Create the API definition ("Kind") that is used to create the CRD.
  a. `cd /home/ibmadmin/workspace/cs-operators/iam-operator`.
  b. Create `hack/boilerplate.go.txt` that contains the copyright information for the generated code.
  c. Create the API definition ("Kind") by running the following command:
     `operator-sdk add api --api-version=operator.ibm.com/v1alpha1 --kind=IAM`
     The command complete the following tasks:
       - Generates `pkg/apis/operator/v1alpha1/<kind>_types.go`. For example, `pkg/apis/operator/v1alpha1/authentications.go`.
       - Generates `deploy/crds/operator.ibm.com_<kind>s_crd.yaml`. For example, `deploy/crds/operator.ibm.com_authentications_crd.yaml`.
       - Generates `deploy/crds/operator.ibm.com_v1alpha1_<kind>_cr.yaml`. For example, `deploy/crds/operator.ibm.com_v1alpha1_authentications_cr.yaml`.
       
     The operator can manage more than one `Kind` API resource.
     
4. Edit `<kind>_types.go` and add the fields that are exposed to the user. Then, regenerate the CRD.
  a. Edit `<kind>_types.go` and add fields to the `<Kind>Spec` struct. Then, run the following command:
     `operator-sdk generate k8s`
     The command updates `zz_generated.deepcopy.go`.
  b. Generate CRDs.
     **Note:** The **Operator Framework: Getting Started** provides the `operator-sdk generate openapi` command to generate CRD. However, the command is deprecated. You can run the following commands instead:
     - `operator-sdk generate crds`
	  - The command updates `operator.ibm.com_authentications_crd.yaml`.
     - `openapi-gen --logtostderr=true -o "" -i ./pkg/apis/operator/v1alpha1 -O zz_generated.openapi -p ./pkg/apis/operator/v1alpha1 -h hack/boilerplate.go.txt -r "-"`
          - The command creates `zz_generated.openapi.go`. 
            If you need to build `openapi-gen`, follow these steps. The binary is built in `$GOPATH/bin`.
            ```
            git clone https://github.com/kubernetes/kube-openapi.git
            cd kube-openapi
            go mod tidy
            go build -o ./bin/openapi-gen k8s.io/kube-openapi/cmd/openapi-gen
            ```
    **Note:** Every time you modify `<kind>_types.go`, run `generate k8s`, `generate crds`, and `openapi-gen` to update the CRD and the generated code.

5. Create the controller, which creates resources such as Deployments, DaemonSets, and other resources.
  `operator-sdk add controller --api-version=operator.ibm.com/v1alpha1 --kind=IAM`
  
  **Notes:**
  - There is one controller for each Kind/CRD.
  - The controller watches and reconciles the resources that are owned by the CR.
  - For information about the Go types that implement Deployments, DaemonSets, and other resources, see https://godoc.org/k8s.io/api/apps/v1.
  - For information about the Go types that implement Pods, VolumeMounts, and other resources, see https://godoc.org/k8s.io/api/core/v1.
  - For information about the Go types that implement Ingress and other resources, see https://godoc.org/k8s.io/api/networking/v1beta1.

#### Running locally

1. Create the CRD. Do this one time before you start the operator.
  a. `cd /home/ibmadmin/workspace/cs-operators/iam-operator`
  b. `oc login`
  c. `kubectl create -f deploy/crds/operator.ibm.com_authentications_crd.yaml`
  d. `kubectl get crd authentications.operator.ibm.com`
  
  If the CRD changes, delete and create again: 
    - `kubectl delete crd authentications.operator.ibm.com`

2. Run the operator locally.
  a. `cd /home/ibmadmin/workspace/cs-operators/iam-operator`
  b. `oc login`
  c. `export OPERATOR_NAME=iam-operator`
  d. `operator-sdk up local --namespace=<namespace>`

3. Create a CR, which is an instance of the CRD.
  1. Edit `deploy/crds/operator.ibm.com_v1alpha1_authentications_cr.yaml`.
  2. `kubectl create -f deploy/crds/operator.ibm.com_v1alpha1_authentications_cr.yaml`

4. Delete the CR and the associated resources that were created.
  - `kubectl delete authentications example-authentication`

## SecurityContextConstraints Requirements

The IAM operator service does not support running under the OpenShift Container Platform default restricted security context constraints.

## PodSecurityPolicy Requirements

The IAM operator does not define any specific pod security requirements.
