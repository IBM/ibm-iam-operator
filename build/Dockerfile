FROM registry.access.redhat.com/ubi8/ubi-minimal:8.3-298

LABEL org.label-schema.vendor="IBM" \
    org.label-schema.name="ibm-iam-operator" \
    org.label-schema.description="IBM IAM Operator" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url=$VCS_URL \
    org.label-schema.license="Licensed Materials - Property of IBM" \
    org.label-schema.schema-version="1.0" \
    name="ibm-iam-operator" \
    vendor="IBM" \
    description="IBM IAM Operator" \
    summary="IBM IAM Operator"

ENV OPERATOR=/usr/local/bin/ibm-iam-operator \
    USER_UID=1001 \
    USER_NAME=ibm-iam-operator

# install operator binary
COPY build/_output/bin/ibm-iam-operator ${OPERATOR}

COPY build/bin /usr/local/bin
RUN  /usr/local/bin/user_setup

# copy licenses
RUN mkdir /licenses
COPY LICENSE /licenses

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER ${USER_UID}
