#!/usr/bin/env bash
set -e

export REGISTRY="$(get_env DOCKER_REGISTRY || echo docker-na-public.artifactory.swg-devops.com/hyc-cloud-private-scratch-docker-local/ibmcom)"
GO_VERSION=1.24.1

echo "Installing Go $GO_VERSION"
curl -sSL "https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o go.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go.tar.gz

export PATH=$PATH:/usr/local/go/bin

echo "Go installed: $(go version)"
make images