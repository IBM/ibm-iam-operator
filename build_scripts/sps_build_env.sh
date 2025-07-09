#!/usr/bin/env bash

SWITCH_WORKSPACE="${SWITCH_WORKSPACE:-false}"


echo "Setting up build parameters for component builds"
echo "Ensure we're located in the source app repo"
cd "$WORKSPACE/$(load_repo app-repo path)"
echo "Current directory : $(pwd)"


export GITHUB_TOKEN="$(get_env GITHUB_TOKEN)"
export GITHUB_USER="$(get_env GITHUB_USER)"
export ARTIFACTOTY_USERNAME="$(get_env ARTIFACTOTY_USERNAME)"
export ARTIFACTORY_TOKEN="$(get_env ARTIFACTORY_TOKEN)"

export GIT_BRANCH="$(get_env branch)"
export TRIGGER_NAME=$(get_env TRIGGER_NAME)
export BUILDKIT_IMAGE="$(get_env BUILDKIT_IMAGE)"
export DOCKER_REGISTRY="$(get_env DOCKER_REGISTRY || echo docker-na-public.artifactory.swg-devops.com/hyc-cloud-private-scratch-docker-local/ibmcom)"
export TAG="$(get_env TAG || cat RELEASE_VERSION | tr -s '\n' ' ')"

git config --global --add safe.directory $WORKSPACE/$(load_repo app-repo path)

echo "Current directory : $(pwd)"
echo "Trigger name: $TRIGGER_NAME"
echo "Current branch : $(git rev-parse --abbrev-ref HEAD)"
export GIT_COMMIT="$(git rev-parse HEAD)"



# Copy all content of workspace to a different directory before build to run in parallel
if [ "$SWITCH_WORKSPACE" == "true" ]; then

    # Copy all content of workspace to a different directory before build
    export ARCH_BUILD_PATH="${WORKSPACE}/${ARCH}-build-path"
    mkdir -p ${ARCH_BUILD_PATH}
    cp -a $WORKSPACE/$(load_repo app-repo path)/. ${ARCH_BUILD_PATH}/
    cd ${ARCH_BUILD_PATH}
    chmod +x build_scripts/build_image.sh
fi

SETUP_BUILDX="${SETUP_BUILDX:-true}"

if [ "$SETUP_BUILDX" == "true" ]; then

    # Configure buildx
    docker buildx version
    docker buildx create --name multiarch-builder --use --driver-opt=image="${BUILDKIT_IMAGE}"
    docker buildx inspect --bootstrap

fi


DIND_ENABLED="${DIND_ENABLED:-true}"

if [ "$DIND_ENABLED" == "true" ]; then
    make init
    echo "Doing docker login to $DOCKER_REGISTRY"
    make docker:login docker-na-public.artifactory.swg-devops.com DOCKER_USER=$ARTIFACTOTY_USERNAME DOCKER_PASS=$ARTIFACTORY_TOKEN
fi