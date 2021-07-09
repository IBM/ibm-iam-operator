module github.com/IBM/ibm-iam-operator

go 1.13

require (
	github.com/Azure/go-autorest/autorest v0.11.18 // indirect
	github.com/google/gxui v0.0.0-20151028112939-f85e0a97b3a4 // indirect
	github.com/openshift/api v3.9.1-0.20190924102528-32369d4db2ad+incompatible
	github.com/operator-framework/operator-sdk v0.19.0
	github.com/spf13/pflag v1.0.5
	github.com/zach-klippenstein/goregen v0.0.0-20160303162051-795b5e3961ea
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.21.2
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/kube-openapi v0.0.0-20200805222855-6aeccd4b50c6
	//k8s.io/kube-openapi v0.0.0-20200805222855-6aeccd4b50c6
	//github.com/googleapis/gnostic v0.5.1
	//k8s.io/kube-openapi v0.0.0-20200805222855-6aeccd4b50c6
	sigs.k8s.io/controller-runtime v0.8.0
)

// Pinned to kubernetes-1.16.2
replace (
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.5.1
	github.com/prometheus-operator/prometheus-operator => github.com/prometheus-operator/prometheus-operator v0.38.0 // indirect
	k8s.io/api => k8s.io/api v0.19.10
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.10
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.10
	k8s.io/apiserver => k8s.io/apiserver v0.19.10
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.19.10
	//k8s.io/client-go => k8s.io/client-go v0.20.0
	k8s.io/client-go => github.com/kubernetes/client-go v0.19.10
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.19.10
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.19.10
	k8s.io/code-generator => k8s.io/code-generator v0.19.10
	k8s.io/component-base => k8s.io/component-base v0.19.10
	k8s.io/cri-api => k8s.io/cri-api v0.19.10
	//k8s.io/kube-openapi => k8s.io/kube-openapi v0.19.10
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.19.10
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.19.10
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.19.10
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.19.10
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.19.10
	k8s.io/kube-state-metrics => k8s.io/kube-state-metrics v1.7.2
	k8s.io/kubectl => k8s.io/kubectl v0.19.10
	k8s.io/kubelet => k8s.io/kubelet v0.19.10
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.19.10
	//k8s.io/metrics => k8s.io/metrics v0.19.10
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.19.10
)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm
