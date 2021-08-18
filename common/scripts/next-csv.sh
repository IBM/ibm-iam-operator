#!/usr/bin/env bash

#
# Copyright 2021 IBM Corporation
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

# This script needs to inputs
# The CSV version that is currently in dev

CURRENT_DEV_CSV=$1
let NEW_DEV_CSV_Z=$(echo "$CURRENT_DEV_CSV" | cut -d '.' -f3)+1
NEW_DEV_CSV=$(echo "$CURRENT_DEV_CSV" | gsed "s/\.[0-9][0-9]*$/\.$NEW_DEV_CSV_Z/")
let PREVIOUS_DEV_CSV_Z=$(echo "$CURRENT_DEV_CSV" | cut -d '.' -f3)-1
PREVIOUS_DEV_CSV=$(echo "$CURRENT_DEV_CSV" | gsed "s/\.[0-9][0-9]*$/\.$PREVIOUS_DEV_CSV_Z/")

CSV_PATH=deploy/olm-catalog/ibm-iam-operator/
echo "$NEW_DEV_CSV:
# Make new z level release directory
mkdir $CSV_PATH/"$NEW_DEV_CSV"
echo "Made new directory"
#read
# Copy Current CSV directory to new one
cp $CSV_PATH/"$CURRENT_DEV_CSV"/* $CSV_PATH/$NEW_DEV_CSV/
echo "Copied current csv to new directory"
#read

# Change to new CSV Version
mv $CSV_PATH/$NEW_DEV_CSV/ibm-iam-operator.v$CURRENT_DEV_CSV.clusterserviceversion.yaml $CSV_PATH/$NEW_DEV_CSV/ibm-iam-operator.v"$NEW_DEV_CSV".clusterserviceversion.yaml
echo "Changed file name csv in new directory"
#read

# Update New CSV
# replace old CSV value with new one
gsed -i "s/$CURRENT_DEV_CSV/$NEW_DEV_CSV/g" $CSV_PATH/"$NEW_DEV_CSV"/ibm-iam-operator.v"$NEW_DEV_CSV".clusterserviceversion.yaml
TIME_STAMP="$(date "'"+%Y-%m-%dT%H:%M:%S"'"Z)
gsed -i "s/2[0-9]*-[0-9]*-[0-9]*T[0-9]*:[0-9]*:[0-9]*Z/$TIME_STAMP/g" $CSV_PATH/$NEW_DEV_CSV/ibm-iam-operator.v"$NEW_DEV_CSV".clusterserviceversion.yaml
echo "Updated New file with new CSV version"
gsed -i "s/$PREVIOUS_DEV_CSV/$CURRENT_DEV_CSV/g" $CSV_PATH/"$NEW_DEV_CSV"/ibm-iam-operator.v$NEW_DEV_CSV.clusterserviceversion.yaml
echo "Updated the replaces version line"
#read

#Update version.go to new dev version
gsed -i "s/$CURRENT_DEV_CSV/$NEW_DEV_CSV/" version/version.go
#Update lint-csv version
gsed -i "s/$CURRENT_DEV_CSV/$NEW_DEV_CSV/" common/scripts/lint-csv.sh
echo "Updated the lint-csv.sh"
gsed -i "s/$CURRENT_DEV_CSV/$NEW_DEV_CSV/" Makefile
echo "Updated the version.go and Makefile with new version (Push Enter when done): "
#read

# Push CSV package yaml to quay
# common/scripts/push-csv.sh
# echo "Pushed CSV to quay "
# read
