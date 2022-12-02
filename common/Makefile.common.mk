# Copyright 2019 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

############################################################
# install git hooks
############################################################
INSTALL_HOOKS := $(shell find .git/hooks -type l -exec rm {} \; && \
                         find common/scripts/.githooks -type f -exec ln -sf ../../{} .git/hooks/ \; )

############################################################
# GKE section
############################################################
PROJECT ?= oceanic-guard-191815
ZONE    ?= us-east5-c
CLUSTER ?= bedrock-prow

activate-serviceaccount:
ifdef GOOGLE_APPLICATION_CREDENTIALS
	@gcloud auth activate-service-account --key-file="$(GOOGLE_APPLICATION_CREDENTIALS)"
endif

get-cluster-credentials: activate-serviceaccount
	@gcloud container clusters get-credentials "$(CLUSTER)" --project="$(PROJECT)" --zone="$(ZONE)"

config-docker: get-cluster-credentials
	@common/scripts/config_docker.sh

############################################################
# lint section
############################################################

FINDFILES=find . \( -path ./.git -o -path ./.github \) -prune -o -type f
XARGS = xargs -0 ${XARGS_FLAGS}
CLEANXARGS = xargs ${XARGS_FLAGS}

lint-dockerfiles:
	@${FINDFILES} -name 'Dockerfile*' -print0 | ${XARGS} hadolint -c ./common/config/.hadolint.yml

lint-scripts:
	@${FINDFILES} -name '*.sh' -print0 | ${XARGS} shellcheck --exclude=SC2086,SC2027,SC1078,SC2219,SC1079,SC1011,SC2046,SC2162,SC2026

lint-yaml:
	@${FINDFILES} \( -name '*.yml' -o -name '*.yaml' \) -print0 | ${XARGS} grep -L -e "{{" | ${CLEANXARGS} yamllint -c ./common/config/.yamllint.yml

lint-helm:
	@${FINDFILES} -name 'Chart.yaml' -print0 | ${XARGS} -L 1 dirname | ${CLEANXARGS} helm lint

lint-copyright-banner:
	@${FINDFILES} \( -name '*.go' -o -name '*.cc' -o -name '*.h' -o -name '*.proto' -o -name '*.py' -o -name '*.sh' \) \( ! \( -name '*.gen.go' -o -name '*.pb.go' -o -name '*_pb2.py' \) \) -print0 |\
		${XARGS} common/scripts/lint_copyright_banner.sh

lint-go:
	@${FINDFILES} -name '*.go' \( ! \( -name '*.gen.go' -o -name '*.pb.go' \) \) -print0 | ${XARGS} common/scripts/lint_go.sh

lint-python:
	@${FINDFILES} -name '*.py' \( ! \( -name '*_pb2.py' \) \) -print0 | ${XARGS} autopep8 --max-line-length 160 --exit-code -d

lint-markdown:
	@${FINDFILES} -name '*.md' -print0 | ${XARGS} mdl --ignore-front-matter --style common/config/mdl.rb
ifdef MARKDOWN_LINT_WHITELIST
	@${FINDFILES} -name '*.md' -print0 | ${XARGS} awesome_bot --skip-save-results --allow_ssl --allow-timeout --allow-dupe --allow-redirect --white-list ${MARKDOWN_LINT_WHITELIST}
else
	@${FINDFILES} -name '*.md' -print0 | ${XARGS} awesome_bot --skip-save-results --allow_ssl --allow-timeout --allow-dupe --allow-redirect
endif

lint-sass:
	@${FINDFILES} -name '*.scss' -print0 | ${XARGS} sass-lint -c common/config/sass-lint.yml --verbose

lint-typescript:
	@${FINDFILES} -name '*.ts' -print0 | ${XARGS} tslint -c common/config/tslint.json

lint-protos:
	@$(FINDFILES) -name '*.proto' -print0 | $(XARGS) -L 1 prototool lint --protoc-bin-path=/usr/bin/protoc

#lint-all: lint-dockerfiles lint-scripts lint-yaml lint-helm lint-copyright-banner lint-go int-python lint-markdown lint-sass lint-typescript lint-protos

lint-all: lint-dockerfiles lint-scripts lint-yaml lint-helm lint-copyright-banner

format-go:
	@${FINDFILES} -name '*.go' \( ! \( -name '*.gen.go' -o -name '*.pb.go' \) \) -print0 | ${XARGS} goimports -w -local "github.com/IBM"

format-python:
	@${FINDFILES} -name '*.py' -print0 | ${XARGS} autopep8 --max-line-length 160 --aggressive --aggressive -i

format-protos:
	@$(FINDFILES) -name '*.proto' -print0 | $(XARGS) -L 1 prototool format -w

csv-gen:
	@echo Updating the CSV files with the changes in the CRD
	operator-sdk generate csv --csv-version ${CSV_VERSION} --update-crds

bundle:
	@echo --- Updating the bundle directory with latest yamls from olm-catalog ---
	rm -rf bundle/*
	cp -r deploy/olm-catalog/ibm-iam-operator/${CSV_VERSION}/* bundle/
	cp deploy/olm-catalog/ibm-iam-operator/ibm-iam-operator.package.yaml bundle/
	zip bundle/ibm-iam-metadata bundle/*.yaml

install-operator-courier:
	@echo --- Installing Operator Courier ---
	pip3 install operator-courier

verify-bundle:
	@echo --- Verify Bundle is Redhat Certify ready ---
	operator-courier --verbose verify --ui_validate_io bundle/

redhat-certify-ready: bundle install-operator-courier verify-bundle

.PHONY: lint-dockerfiles lint-scripts lint-yaml lint-copyright-banner lint-go lint-python lint-helm lint-markdown lint-sass lint-typescript lint-protos lint-all format-go format-python format-protos csv-gen bundle install-operator-courier verify-bundle redhat-certify-ready config-docker
