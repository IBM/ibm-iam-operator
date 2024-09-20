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
#

FROM docker-na-public.artifactory.swg-devops.com/hyc-cloud-private-edge-docker-local/build-images/ubi9-minimal:latest

ARG VCS_REF
ARG VCS_URL

LABEL org.label-schema.vendor="IBM" \
    org.label-schema.name="ibm-iam-operator" \
    org.label-schema.description="IBM IAM Operator" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url=$VCS_URL \
    org.label-schema.license="Licensed Materials - Property of IBM" \
    org.label-schema.schema-version="1.0" \
    name="ibm-iam-operator" \
    vendor="IBM" \
    description="IBM IM Operator" \
    summary="IBM IM Operator"

ENV OPERATOR=/usr/local/bin/ibm-iam-operator \
    USER_UID=1001 \
    USER_NAME=ibm-iam-operator

WORKDIR /

COPY build/_output/bin/manager ${OPERATOR}

COPY licenses /

USER ${USER_UID}

ENTRYPOINT ["/usr/local/bin/ibm-iam-operator"]
