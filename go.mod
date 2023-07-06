module github.com/IBM/ibm-iam-operator

go 1.18

require (
	github.com/Azure/go-autorest/autorest v0.11.28 // indirect
	github.com/google/gxui v0.0.0-20151028112939-f85e0a97b3a4 // indirect
	github.com/openshift/api v0.0.0-20221013123533-341d389bd4a7
	github.com/operator-framework/operator-sdk v0.19.0
	github.com/spf13/pflag v1.0.5
	github.com/zach-klippenstein/goregen v0.0.0-20160303162051-795b5e3961ea
	k8s.io/api v0.26.0
	k8s.io/apimachinery v0.26.0
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/kube-openapi v0.0.0-20221207184640-f3cff1453715
	//k8s.io/kube-openapi v0.0.0-20200805222855-6aeccd4b50c6
	//k8s.io/kube-openapi v0.0.0-20200805222855-6aeccd4b50c6
	sigs.k8s.io/controller-runtime v0.14.1
)

require (
	github.com/cert-manager/cert-manager v1.11.0
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-logr/zapr v1.2.3 // indirect
)

require gopkg.in/yaml.v2 v2.4.0

require (
	cloud.google.com/go v0.99.0 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.21 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/coreos/prometheus-operator v0.38.1-0.20200424145508-7e176fda06cc // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emicklei/go-restful v2.9.5+incompatible // indirect
	github.com/emicklei/go-restful/v3 v3.9.0 // indirect
	github.com/evanphx/json-patch v5.6.0+incompatible // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.20.0 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.4.3 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/gnostic v0.5.5 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.14.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/crypto v0.5.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/oauth2 v0.4.0 // indirect
	golang.org/x/sys v0.9.0 // indirect
	golang.org/x/term v0.9.0 // indirect
	golang.org/x/text v0.10.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	gomodules.xyz/jsonpatch/v2 v2.2.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apiextensions-apiserver v0.26.0 // indirect
	k8s.io/component-base v0.26.0 // indirect
	k8s.io/klog v1.0.0 // indirect
	k8s.io/klog/v2 v2.80.1 // indirect
	k8s.io/kube-state-metrics v1.7.2 // indirect
	k8s.io/utils v0.0.0-20221128185143-99ec85e7a448 // indirect
	sigs.k8s.io/gateway-api v0.6.0 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

// Pinned to kubernetes-1.16.2
replace (
	github.com/dgrijalva/jwt-go => github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1
	github.com/emicklei/go-restful => github.com/emicklei/go-restful/v3 v3.8.0
	github.com/golang/protobuf => github.com/golang/protobuf v1.5.2
	//github.com/go-logr/logr => github.com/go-logr/logr v0.4.0 // indirect
	//github.com/go-logr/zapr v0.4.0 => github.com/go-logr/zapr v0.4.0 // indirect
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.5.5
	github.com/operator-framework/operator-sdk => github.com/operator-framework/operator-sdk v0.19.0
	github.com/prometheus-operator/prometheus-operator => github.com/prometheus-operator/prometheus-operator v0.38.0 // indirect
	golang.org/x/crypto => golang.org/x/crypto v0.10.0 //v0.0.0-20201216223049-8b5274cf687f
	//google.golang.org/protobuf => google.golang.org/protobuf v1.26.1-0.20210525005349-febffdd88e85
	k8s.io/api => k8s.io/api v0.23.0
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.17-rc.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.22.0
	k8s.io/apiserver => k8s.io/apiserver v0.19.10
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.19.10
	k8s.io/client-go => k8s.io/client-go v0.22.0
	//k8s.io/client-go => github.com/kubernetes/client-go v0.19.3
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.19.10
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.19.10
	k8s.io/code-generator => k8s.io/code-generator v0.19.10
	k8s.io/component-base => k8s.io/component-base v0.19.10
	k8s.io/cri-api => k8s.io/cri-api v0.19.10
	//k8s.io/kube-openapi => k8s.io/kube-openapi v0.19.10
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.19.10
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.19.10
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.19.10
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.19.10
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.19.10
	k8s.io/kube-state-metrics => k8s.io/kube-state-metrics v1.7.2
	k8s.io/kubectl => k8s.io/kubectl v0.19.10
	k8s.io/kubelet => k8s.io/kubelet v0.19.10
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.19.10
	//k8s.io/metrics => k8s.io/metrics v0.19.10
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.19.10
	//k8s.io/utils/clock => k8s.io/apimachinery/pkg/util/clock
	k8s.io/utils => k8s.io/utils v0.0.0-20210930125809-cb0fa318a74b
	//k8s.io/utils => k8s.io/utils v0.0.0-20200729134348-d5654de09c73
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.11.0
)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm
