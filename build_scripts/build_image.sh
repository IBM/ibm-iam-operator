#!/bin/bash
#
# Copyright 2026 IBM Corporation
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

export BUILD_LOCALLY=0

echo "***************** Install go *****************"

GO_VERSION="1.26.1"
curl -sLO "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
rm "go${GO_VERSION}.linux-amd64.tar.gz"

grep -q '/usr/local/go/bin' ~/.bashrc || echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc
# shellcheck disable=SC1090
source ~/.bashrc
go version

echo "**************** Building images ****************"

make images
