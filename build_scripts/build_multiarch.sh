#!/usr/bin/env bash
set -e

export REGISTRY="$(get_env DOCKER_REGISTRY || echo docker-na-public.artifactory.swg-devops.com/hyc-cloud-private-scratch-docker-local/ibmcom)"

make images