#!/bin/bash
#
# Copyright 2020, 2023 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.DEFAULT_GOAL:=help
# Specify whether this repo is build locally or not, default values is '1';
# If set to 1, then you need to also set 'DOCKER_USERNAME' and 'DOCKER_PASSWORD'
# environment variables before build the repo.
BUILD_LOCALLY ?= 1

# The namespace that operator will be deployed in
NAMESPACE=ibm-common-services
GIT_COMMIT_ID=$(shell git rev-parse --short HEAD)
GIT_REMOTE_URL=$(shell git config --get remote.origin.url)
IMAGE_BUILD_OPTS=--build-arg "VCS_REF=$(GIT_COMMIT_ID)" --build-arg "VCS_URL=$(GIT_REMOTE_URL)"

# Image URL to use all building/pushing image targets;
# Use your own docker registry and image name for dev/test by overridding the IMG and REGISTRY environment variable.
IMG ?= ibm-iam-operator
REGISTRY ?= "docker-na-public.artifactory.swg-devops.com/hyc-cloud-private-integration-docker-local/ibmcom"
CONTAINER_CLI ?= docker

MARKDOWN_LINT_WHITELIST=https://quay.io/cnr

ifeq ($(BUILD_LOCALLY),0)
    export CONFIG_DOCKER_TARGET = config-docker
endif

TESTARGS_DEFAULT := "-v"
export TESTARGS ?= $(TESTARGS_DEFAULT)
VERSION ?= $(shell cat ./version/version.go | grep "Version =" | awk '{ print $$3}' | tr -d '"')

LOCAL_OS := $(shell uname)
LOCAL_ARCH := $(shell uname -m)
ifeq ($(LOCAL_OS),Linux)
    TARGET_OS ?= linux
    XARGS_FLAGS="-r"
	STRIP_FLAGS=
else ifeq ($(LOCAL_OS),Darwin)
    TARGET_OS ?= darwin
    XARGS_FLAGS=
	STRIP_FLAGS="-x"
else
    $(error "This system's OS $(LOCAL_OS) isn't recognized/supported")
endif

include common/Makefile.common.mk

# CHANNELS define the bundle channels used in the bundle.
# Add a new line here if you would like to change its default config. (E.g CHANNELS = "candidate,fast,stable")
# To re-generate a bundle for other specific channels without changing the standard setup, you can:
# - use the CHANNELS as arg of the bundle target (e.g make bundle CHANNELS=candidate,fast,stable)
# - use environment variables to overwrite this value (e.g export CHANNELS="candidate,fast,stable")
ifneq ($(origin CHANNELS), undefined)
BUNDLE_CHANNELS := --channels=$(CHANNELS)
endif

# DEFAULT_CHANNEL defines the default channel used in the bundle.
# Add a new line here if you would like to change its default config. (E.g DEFAULT_CHANNEL = "stable")
# To re-generate a bundle for any other default channel without changing the default setup, you can:
# - use the DEFAULT_CHANNEL as arg of the bundle target (e.g make bundle DEFAULT_CHANNEL=stable)
# - use environment variables to overwrite this value (e.g export DEFAULT_CHANNEL="stable")
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNELS) $(BUNDLE_DEFAULT_CHANNEL)

# IMAGE_TAG_BASE defines the docker.io namespace and part of the image name for remote images.
# This variable is used to construct full image tags for bundle and catalog images.
#
# For example, running 'make bundle-build bundle-push catalog-build catalog-push' will build and push both
# icr.io/cpopen/ibm-iam-operator-bundle:$VERSION and icr.io/cpopen/ibm-iam-operator-catalog:$VERSION.
IMAGE_TAG_BASE ?= icr.io/cpopen/ibm-iam-operator

# BUNDLE_IMG defines the image:tag used for the bundle.
# You can use it as an arg. (E.g make bundle-build BUNDLE_IMG=<some-registry>/<project-name-bundle>:<tag>)
BUNDLE_IMG ?= $(IMAGE_TAG_BASE)-bundle:v$(VERSION)

# BUNDLE_GEN_FLAGS are the flags passed to the operator-sdk generate bundle command
BUNDLE_GEN_FLAGS ?= -q --overwrite --version $(VERSION) $(BUNDLE_METADATA_OPTS)

BUNDLE_DOCKERFILE ?= bundle.Dockerfile

MODE ?= prod

ifeq ($(MODE), dev)
	BUNDLE_DOCKERFILE = bundle-dev.Dockerfile
	BUNDLE_GEN_FLAGS += --output-dir=bundle-dev
endif

# USE_IMAGE_DIGESTS defines if images are resolved via tags or digests
# You can enable this value if you would like to use SHA Based Digests
# To enable set flag to true
USE_IMAGE_DIGESTS ?= false
ifeq ($(USE_IMAGE_DIGESTS), true)
	BUNDLE_GEN_FLAGS += --use-image-digests
endif

# Image URL to use all building/pushing image targets
IMG ?= controller:latest
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.26.0

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUSTOMIZE ?= $(LOCALBIN)/kustomize
YQ ?= $(LOCALBIN)/yq
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest

## Tool Versions
KUSTOMIZE_VERSION ?= v3.8.9
CONTROLLER_TOOLS_VERSION ?= v0.11.4
YQ_VERSION ?= v4.40.5
GO_VERSION ?= 1.21.7

# This pinned version of go has its version pinned to its name, so order of operations is inverted here.
GO ?= $(LOCALBIN)/go$(GO_VERSION)

.PHONY: go
go: $(GO) ## Install pinned version of go
$(GO): $(LOCALBIN) # https://go.dev/doc/manage-install#installing-multiple
ifeq (,$(shell which go 2>/dev/null))
	@{ \
		echo '"go" not found in PATH; install go before attempting again'; \
		exit 1; \
	}
endif
	test -s $(LOCALBIN)/go$(GO_VERSION) && $(LOCALBIN)/go$(GO_VERSION) version | grep -q $(GO_VERSION) || \
	GOSUMDB=sum.golang.org GOBIN=$(LOCALBIN) go install golang.org/dl/go$(GO_VERSION)@latest && $(LOCALBIN)/go$(GO_VERSION) download

KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary. If wrong version is installed, it will be removed before downloading.
$(KUSTOMIZE): $(LOCALBIN) go
	@if test -x $(LOCALBIN)/kustomize && ! $(LOCALBIN)/kustomize version | grep -q $(KUSTOMIZE_VERSION); then \
		echo "$(LOCALBIN)/kustomize version is not expected $(KUSTOMIZE_VERSION). Removing it before installing."; \
		rm -rf $(LOCALBIN)/kustomize; \
	fi
	test -s $(LOCALBIN)/kustomize || { curl -Ss $(KUSTOMIZE_INSTALL_SCRIPT) | bash -s -- $(subst v,,$(KUSTOMIZE_VERSION)) $(LOCALBIN); }

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary. If wrong version is installed, it will be overwritten.
$(CONTROLLER_GEN): $(LOCALBIN) go
	test -s $(LOCALBIN)/controller-gen && $(LOCALBIN)/controller-gen --version | grep -q $(CONTROLLER_TOOLS_VERSION) || \
	GOSUMDB=sum.golang.org GOBIN=$(LOCALBIN) $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: yq
yq: $(YQ)
$(YQ): $(LOCALBIN) go
	@if test -x $(LOCALBIN)/yq && ! $(LOCALBIN)/yq --version | grep -q $(YQ_VERSION); then \
		echo "$(LOCALBIN)/yq version is not expected $(YQ_VERSION). Removing it before installing."; \
		rm -rf $(LOCALBIN)/yq; \
	fi
	test -s $(LOCALBIN)/yq || GOSUMDB=sum.golang.org GOBIN=$(LOCALBIN) $(GO) install github.com/mikefarah/yq/v4@$(YQ_VERSION)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN) go
	test -s $(LOCALBIN)/setup-envtest || GOSUMDB=sum.golang.org GOBIN=$(LOCALBIN) $(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

.PHONY: opm
OPM = ./bin/opm
opm: ## Download opm locally if necessary.
ifeq (,$(wildcard $(OPM)))
ifeq (,$(shell which opm 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPM)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPM) https://github.com/operator-framework/operator-registry/releases/download/v1.23.0/$${OS}-$${ARCH}-opm ;\
	chmod +x $(OPM) ;\
	}
else
OPM = $(shell which opm)
endif
endif


##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration and ClusterRole objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role webhook paths="./..."

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: dev-overlays
dev-overlays:
	hack/create_dev_overlays

.PHONY: bundle
bundle: manifests kustomize yq ## Build the bundle manifests
ifeq ($(MODE), dev)
	hack/create_dev_overlays
endif
	operator-sdk generate kustomize manifests -q
ifeq ($(MODE), dev)
	cd config/manager/overlays/dev && $(KUSTOMIZE) edit set image controller=$(IMAGE_TAG_BASE):$(VERSION)
	cp bundle.Dockerfile bundle.Dockerfile.bk
	$(KUSTOMIZE) build config/manifests/overlays/dev | operator-sdk generate bundle $(BUNDLE_GEN_FLAGS)
	cp bundle.Dockerfile bundle-dev.Dockerfile
	mv bundle.Dockerfile.bk bundle.Dockerfile
	hack/patch-built-bundle "dev"
else
	$(KUSTOMIZE) build config/manifests/overlays/prod | operator-sdk generate bundle $(BUNDLE_GEN_FLAGS)
	operator-sdk bundle validate ./bundle
	hack/patch-built-bundle
endif


.PHONY: fmt
fmt: go ## Run go fmt against code.
	test -s $(LOCALBIN)/gofmt 2>&1 || $(GO) build -o $(LOCALBIN)/gofmt ${HOME}/sdk/go1.21.7/src/cmd/gofmt
	$(GO) fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test ./... -coverprofile cover.out

.PHONY: update-version
update-version: manifests kustomize yq ## Update the Operator SemVer across the project
	./hack/update_operator_version


##@ Build

.PHONY: build
build: go manifests generate fmt vet ## Build manager binary.
	@echo "Building the manager binary"
	@CGO_ENABLED=0 $(GO) build -o build/_output/bin/manager main.go
	@strip $(STRIP_FLAGS) build/_output/bin/manager

.PHONY: run
run: go manifests generate fmt vet ## Run a controller from your host.
	$(GO) run ./main.go

# Build a catalog image by adding bundle images to an empty catalog using the operator package manager tool, 'opm'.
# This recipe invokes 'opm' in 'semver' bundle add mode. For more information on add modes, see:
# https://github.com/operator-framework/community-operators/blob/7f1438c/docs/packaging-operator.md#updating-your-existing-operator
.PHONY: catalog-build
catalog-build: opm ## Build a catalog image.
	$(OPM) index add --container-tool docker --mode semver --tag $(CATALOG_IMG) --bundles $(BUNDLE_IMGS) $(FROM_INDEX_OPT)

.PHONY: bundle-build
bundle-build: ## Build the bundle image.
	docker build -f $(BUNDLE_DOCKERFILE) -t $(BUNDLE_IMG) .

build-image-amd64: $(GO) $(CONFIG_DOCKER_TARGET) ## Build the Operator for Linux on amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -a -o build/_output/bin/manager main.go
	$(CONTAINER_CLI) run --rm --privileged docker.io/multiarch/qemu-user-static:register --reset
	$(CONTAINER_CLI) build ${IMAGE_BUILD_OPTS} -t $(REGISTRY)/$(IMG)-amd64:$(GIT_COMMIT_ID) -f build/Dockerfile.amd64 .
	@\rm -f build/_output/bin/manager
	@if [ $(BUILD_LOCALLY) -ne 1 ]; then $(CONTAINER_CLI) push $(REGISTRY)/$(IMG)-amd64:$(GIT_COMMIT_ID); fi

build-image-ppc64le: $(GO) $(CONFIG_DOCKER_TARGET) ## Build the Operator for Linux on ppc64le
	CGO_ENABLED=0 GOOS=linux GOARCH=ppc64le $(GO) build -a -o build/_output/bin/manager main.go
	$(CONTAINER_CLI) run --rm --privileged docker.io/multiarch/qemu-user-static:register --reset
	$(CONTAINER_CLI) build ${IMAGE_BUILD_OPTS} -t $(REGISTRY)/$(IMG)-ppc64le:$(GIT_COMMIT_ID) -f build/Dockerfile.ppc64le .
	@\rm -f build/_output/bin/manager
	@if [ $(BUILD_LOCALLY) -ne 1 ]; then $(CONTAINER_CLI) push $(REGISTRY)/$(IMG)-ppc64le:$(GIT_COMMIT_ID); fi

build-image-s390x: $(GO) $(CONFIG_DOCKER_TARGET) ## Build the Operator for Linux on s390x
	CGO_ENABLED=0 GOOS=linux GOARCH=s390x $(GO) build -a -o build/_output/bin/manager main.go
	$(CONTAINER_CLI) run --rm --privileged docker.io/multiarch/qemu-user-static:register --reset
	$(CONTAINER_CLI) build ${IMAGE_BUILD_OPTS} -t $(REGISTRY)/$(IMG)-s390x:$(GIT_COMMIT_ID) -f build/Dockerfile.s390x .
	@\rm -f build/_output/bin/manager
	@if [ $(BUILD_LOCALLY) -ne 1 ]; then $(CONTAINER_CLI) push $(REGISTRY)/$(IMG)-s390x:$(GIT_COMMIT_ID); fi

images: $(CONFIG_DOCKER_TARGET) build-image-amd64 build-image-ppc64le build-image-s390x ## Build the multi-arch manifest
	@MAX_PULLING_RETRY=20 RETRY_INTERVAL=30 common/scripts/multiarch_image.sh $(REGISTRY) $(IMG) $(GIT_COMMIT_ID) $(VERSION)

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -
	- oc apply -f config/samples/bases/operator_v1alpha1_authentication.yaml -n ${NAMESPACE}

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	- oc delete -f config/samples/bases/operator_v1alpha1_authentication.yaml -n ${NAMESPACE}
	$(KUSTOMIZE) build config/default | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

build-dev-image: ## Build local 
	@echo "Building ibm-iam-operator dev image for $(LOCAL_ARCH)"
	$(CONTAINER_CLI) build ${IMAGE_BUILD_OPTS} -t $(REGISTRY)/$(IMG)-$(LOCAL_ARCH):$(VERSION) -f Dockerfile .
	@if [ $(BUILD_LOCALLY) -ne 1 ]; then $(CONTAINER_CLI) push $(REGISTRY)/$(IMG)-$(LOCAL_ARCH):$(GIT_COMMIT_ID); fi

.PHONY: bundle-push
bundle-push: ## Push the bundle image.
	$(MAKE) docker-push IMG=$(BUNDLE_IMG)

# A comma-separated list of bundle images (e.g. make catalog-build BUNDLE_IMGS=example.com/operator-bundle:v0.1.0,example.com/operator-bundle:v0.2.0).
# These images MUST exist in a registry and be pull-able.
BUNDLE_IMGS ?= $(BUNDLE_IMG)

# The image tag given to the resulting catalog image (e.g. make catalog-build CATALOG_IMG=example.com/operator-catalog:v0.2.0).
CATALOG_IMG ?= $(IMAGE_TAG_BASE)-catalog:v$(VERSION)

# Set CATALOG_BASE_IMG to an existing catalog image tag to add $BUNDLE_IMGS to that image.
ifneq ($(origin CATALOG_BASE_IMG), undefined)
FROM_INDEX_OPT := --from-index $(CATALOG_BASE_IMG)
endif

# Push the catalog image.
.PHONY: catalog-push
catalog-push: ## Push a catalog image.
	$(MAKE) docker-push IMG=$(CATALOG_IMG)


all: check test coverage build images

##@ Cleanup
clean: ## Clean build and bin directories
	rm -f build/_output/bin/*
	chmod -R +w bin/
	rm -rf bin/*

.PHONY: all build run check install uninstall code-dev test test-e2e coverage images csv clean help
