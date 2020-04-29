# ibm-iam-operator
Operator used to install the cloud pak common iam services.


# Procedure to install


## Add the operator source on your openshift cluster

- Follow the instructions in the Knowledge Center link:
```
https://www.ibm.com/support/knowledgecenter/SSHKN6/kc_welcome_cs.html
```

## SecurityContextConstraints Requirements

The IAM operator service does not support running under the OpenShift Container Platform default restricted security context constraints.

## PodSecurityPolicy Requirements

The IAM operator does not define any specific pod security requirements.
