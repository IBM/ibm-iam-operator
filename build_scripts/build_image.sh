#!/usr/bin/env bash
set -e

export DOCKER_REGISTRY="$(get_env DOCKER_REGISTRY || echo docker-na-public.artifactory.swg-devops.com/hyc-cloud-private-scratch-docker-local/ibmcom)"
export IMAGE_NAME="$(get_env IMAGE_NAME || echo ibm-iam-operator)"
export TAG="$(get_env TAG || cat RELEASE_VERSION | tr -s '\n' ' ')"

DOCKERFILE="Dockerfile"
[ "$ARCH" != "amd64" ] && DOCKERFILE="Dockerfile.${ARCH}"

IMAGE="${DOCKER_REGISTRY}/${IMAGE_NAME}-${ARCH}:${TAG}"

echo "Building and pushing ${IMAGE} using ${DOCKERFILE}"

docker buildx build --platform linux/${ARCH} -f ${DOCKERFILE} -t ${IMAGE} --output type=docker .
docker push ${IMAGE}

