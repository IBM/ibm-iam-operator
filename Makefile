#!/bin/bash
#
# Copyright 2020 IBM Corporation
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
TARGET_GOOS=linux
TARGET_GOARCH=amd64

# The namespcethat operator will be deployed in
NAMESPACE=ibm-common-services
GIT_COMMIT_ID=$(shell git rev-parse --short HEAD)
GIT_REMOTE_URL=$(shell git config --get remote.origin.url)
IMAGE_BUILD_OPTS=--build-arg "VCS_REF=$(GIT_COMMIT_ID)" --build-arg "VCS_URL=$(GIT_REMOTE_URL)"

# Image URL to use all building/pushing image targets;
# Use your own docker registry and image name for dev/test by overridding the IMG and REGISTRY environment variable.
IMG ?= ibm-iam-operator
REGISTRY ?= "docker-na-public.artifactory.swg-devops.com/hyc-cloud-private-integration-docker-local/ibmcom"
CONTAINER_CLI ?= docker

CSV_VERSION ?= 4.0.0

QUAY_USERNAME ?=
QUAY_PASSWORD ?=

MARKDOWN_LINT_WHITELIST=https://quay.io/cnr

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

##@ Application

install: ## Install all resources (CR/CRD's, RBCA and Operator)
	@echo ....... Set environment variables ......
	- export DEPLOY_DIR=deploy/crds
	- export WATCH_NAMESPACE=${NAMESPACE}
	@echo ....... Creating namespace .......
	- oc create namespace ${NAMESPACE}
	@echo ....... Applying CRDS and Operator .......
	- oc apply -f deploy/crds/operator.ibm.com_authentications_crd.yaml
	- oc apply -f deploy/crds/oidc.security.ibm.com_clients_crd.yaml
	@echo ....... Applying RBAC .......
	- oc apply -f deploy/service_account.yaml -n ${NAMESPACE}
	- oc apply -f deploy/role.yaml -n ${NAMESPACE}
	- oc apply -f deploy/role_binding.yaml -n ${NAMESPACE}
	@echo ....... Applying Operator .......
	- oc apply -f deploy/operator.yaml -n ${NAMESPACE}
	@echo ....... Creating the Instance .......
	- oc apply -f deploy/crds/operator.ibm.com_v1alpha1_authentication_cr.yaml -n ${NAMESPACE}

uninstall: ## Uninstall all that all performed in the $ make install
	@echo ....... Uninstalling .......
	@echo ....... Deleting CR .......
	- oc delete -f deploy/crds/operator.ibm.com_v1alpha1_authentication_cr.yaml -n ${NAMESPACE}
	@echo ....... Deleting Operator .......
	- oc delete -f deploy/operator.yaml -n ${NAMESPACE}
	@echo ....... Deleting CRDs.......
	- oc delete -f deploy/crds/operator.ibm.com_authentications_crd.yaml
	- oc delete -f deploy/crds/oidc.security.ibm.com_clients_crd.yaml
	@echo ....... Deleting Roles and Service Account .......
	- oc delete -f deploy/role_binding.yaml -n ${NAMESPACE}
	- oc delete rolebinding ibm-iam-operand-restricted
	- oc delete clusterrolebinding ibm-iam-operand-restricted
	- oc delete -f deploy/service_account.yaml -n ${NAMESPACE}
	- oc delete -f deploy/role.yaml -n ${NAMESPACE}
	- oc delete clusterrole ibm-iam-operand-restricted
	@echo ....... Deleting namespace ${NAMESPACE}.......
	#- oc delete namespace ${NAMESPACE}

##@ Development

check: lint-all ## Check all files lint error
	CSV_VERSION=$(CSV_VERSION) ./common/scripts/lint-csv.sh

code-dev: ## Run the default dev commands which are the go tidy, fmt, vet then execute the $ make code-gen
	@echo Running the common required commands for developments purposes
	- make code-tidy
	- make code-fmt
	- make code-vet
	- make code-gen
	@echo Running the common required commands for code delivery
	- make check
	- make test
	- make build

run: ## Run against the configured Kubernetes cluster in ~/.kube/config
	go run ./cmd/manager/main.go

ifeq ($(BUILD_LOCALLY),0)
    export CONFIG_DOCKER_TARGET = config-docker
endif

##@ Build

build: ## Build the Operator binary for the host OS and architecture
	@echo "Building the ibm-iam-operator binary"
	@CGO_ENABLED=0 go build -o build/_output/bin/$(IMG) ./cmd/manager
	@strip $(STRIP_FLAGS) build/_output/bin/$(IMG)

build-image: build $(CONFIG_DOCKER_TARGET) ## Build the Operator for Linux on amd64
	$(eval ARCH := $(shell uname -m|sed 's/x86_64/amd64/'))
	$(CONTAINER_CLI) build ${IMAGE_BUILD_OPTS}  -t $(REGISTRY)/$(IMG)-$(ARCH):$(VERSION) -f build/Dockerfile .
	@\rm -f build/_output/bin/ibm-iam-operator
	@if [ $(BUILD_LOCALLY) -ne 1 ] && [ "$(ARCH)" = "amd64" ]; then $(CONTAINER_CLI) push $(REGISTRY)/$(IMG)-$(ARCH):$(VERSION); fi

build-image-amd64: build $(CONFIG_DOCKER_TARGET) ## Build the Operator for Linux on amd64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/_output/bin/ibm-iam-operator-amd64 ./cmd/manager
	$(CONTAINER_CLI) run --rm --privileged multiarch/qemu-user-static:register --reset
	$(CONTAINER_CLI) build ${IMAGE_BUILD_OPTS}  -t $(REGISTRY)/$(IMG)-amd64:$(VERSION) -f build/Dockerfile.amd64 .
	@\rm -f build/_output/bin/ibm-iam-operator-amd64
	@if [ $(BUILD_LOCALLY) -ne 1 ]; then $(CONTAINER_CLI) push $(REGISTRY)/$(IMG)-amd64:$(VERSION); fi

# runs on amd64 machine
build-image-ppc64le: $(CONFIG_DOCKER_TARGET) ## Build the Operator for Linux on ppc64le
	GOOS=linux GOARCH=ppc64le CGO_ENABLED=0 go build -o build/_output/bin/ibm-iam-operator-ppc64le ./cmd/manager
	$(CONTAINER_CLI) run --rm --privileged multiarch/qemu-user-static:register --reset
	$(CONTAINER_CLI) build ${IMAGE_BUILD_OPTS}  -t $(REGISTRY)/$(IMG)-ppc64le:$(VERSION) -f build/Dockerfile.ppc64le .
	@\rm -f build/_output/bin/ibm-iam-operator-ppc64le
	@if [ $(BUILD_LOCALLY) -ne 1 ]; then $(CONTAINER_CLI) push $(REGISTRY)/$(IMG)-ppc64le:$(VERSION); fi

# runs on amd64 machine
build-image-s390x: $(CONFIG_DOCKER_TARGET) ## Build the Operator for Linux on s390x
	GOOS=linux GOARCH=s390x CGO_ENABLED=0 go build -o build/_output/bin/ibm-iam-operator-s390x ./cmd/manager
	$(CONTAINER_CLI) run --rm --privileged multiarch/qemu-user-static:register --reset
	$(CONTAINER_CLI) build ${IMAGE_BUILD_OPTS}  -t $(REGISTRY)/$(IMG)-s390x:$(VERSION) -f build/Dockerfile.s390x .
	@\rm -f build/_output/bin/ibm-iam-operator-s390x
	@if [ $(BUILD_LOCALLY) -ne 1 ]; then $(CONTAINER_CLI) push $(REGISTRY)/$(IMG)-s390x:$(VERSION); fi

##@ Test

test: ## Run unit test
	@go test ${TESTARGS} ./pkg/...

test-e2e: ## Run integration e2e tests with different options.
	@echo ... Running the same e2e tests with different args ...
	@echo ... Running locally ...
	- operator-sdk test local ./test/e2e --verbose --up-local --namespace=${NAMESPACE}
	# @echo ... Running with the param ...
	# - operator-sdk test local ./test/e2e --namespace=${NAMESPACE}

scorecard: ## Run scorecard test
	@echo ... Running the scorecard test
	- operator-sdk scorecard --verbose

##@ Release

images: build-image build-image-ppc64le build-image-s390x
	@curl -L -o /tmp/manifest-tool https://github.com/estesp/manifest-tool/releases/download/v1.0.3/manifest-tool-$(TARGET_OS)-amd64
	@chmod +x /tmp/manifest-tool
	/tmp/manifest-tool push from-args --platforms linux/amd64,linux/ppc64le,linux/s390x --template $(REGISTRY)/$(IMG)-ARCH:$(VERSION) --target $(REGISTRY)/$(IMG) --ignore-missing
	/tmp/manifest-tool push from-args --platforms linux/amd64,linux/ppc64le,linux/s390x --template $(REGISTRY)/$(IMG)-ARCH:$(VERSION) --target $(REGISTRY)/$(IMG):$(VERSION) --ignore-missing

csv: ## Push CSV package to the catalog
	@RELEASE=${CSV_VERSION} common/scripts/push-csv.sh

all: check test coverage build images

##@ Cleanup
clean: ## Clean build binary
	rm -f build/_output/bin/$(IMG)

##@ Help
help: ## Display this help
	@echo "Usage:\n  make \033[36m<target>\033[0m"
	@awk 'BEGIN {FS = ":.*##"}; \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: all build run check install uninstall code-dev test test-e2e coverage images csv clean help