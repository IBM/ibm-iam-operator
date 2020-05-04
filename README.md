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


## SecurityContextConstraints Requirements

The IAM operator service does not support running under the OpenShift Container Platform default restricted security context constraints.

## PodSecurityPolicy Requirements

The IAM operator does not define any specific pod security requirements.
