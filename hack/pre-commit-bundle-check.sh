#!/bin/bash
# Copyright 2026 IBM Corporation.
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

set -e

# This script validates that the OLM bundle is up-to-date by:
# 1. Running `make bundle` to generate a fresh bundle
# 2. Comparing the generated bundle with the staged/HEAD version
# 3. Ignoring differences in the createdAt timestamp field
# 4. Failing if any other differences are found

TEMP_DIR=$(mktemp -d)
BUNDLE_FILES=(
    "bundle/manifests/ibm-iam-operator.clusterserviceversion.yaml"
    "bundle/manifests/operator.ibm.com_authentications.yaml"
    "bundle/manifests/oidc.security.ibm.com_clients.yaml"
)

# shellcheck disable=SC2329
cleanup() {
    rm -rf "${TEMP_DIR}"
}
trap cleanup EXIT

# Save original bundle files before running make bundle
echo "Saving original bundle files..."
for bundle_file in "${BUNDLE_FILES[@]}"; do
    if [ -f "$bundle_file" ]; then
        cp "$bundle_file" "${TEMP_DIR}/$(basename "$bundle_file").backup"
    fi
done

echo "Running 'make bundle' to generate fresh bundle manifests..."
make bundle > /dev/null 2>&1

# Function to normalize files by removing createdAt timestamp
normalize_file() {
    local input_file="$1"
    local output_file="$2"
    
    # Remove the createdAt line using sed
    sed '/^[[:space:]]*createdAt:/d' "${input_file}" > "${output_file}"
}

HAS_DIFFERENCES=0

# Check each bundle file
for bundle_file in "${BUNDLE_FILES[@]}"; do
    if [ ! -f "$bundle_file" ]; then
        continue
    fi
    
    # Get the HEAD version of the file
    git show HEAD:"${bundle_file}" > "${TEMP_DIR}/original.yaml" 2>/dev/null || {
        echo "Warning: Could not get HEAD version of ${bundle_file}"
        echo "This might be a new file. Checking staged version..."
        git show :"${bundle_file}" > "${TEMP_DIR}/original.yaml" 2>/dev/null || {
            echo "Warning: Could not get staged version of ${bundle_file}"
            echo "Skipping this file..."
            continue
        }
    }
    
    # Normalize both versions
    normalize_file "${TEMP_DIR}/original.yaml" "${TEMP_DIR}/original_normalized.yaml"
    normalize_file "${bundle_file}" "${TEMP_DIR}/generated_normalized.yaml"
    
    # Compare the normalized versions
    if ! diff -q "${TEMP_DIR}/original_normalized.yaml" "${TEMP_DIR}/generated_normalized.yaml" > /dev/null 2>&1; then
        if [ $HAS_DIFFERENCES -eq 0 ]; then
            echo "✗ Bundle manifests are out of sync!"
            echo ""
            HAS_DIFFERENCES=1
        fi
        
        echo "Differences found in: ${bundle_file}"
        echo "---"
        diff -u "${TEMP_DIR}/original_normalized.yaml" "${TEMP_DIR}/generated_normalized.yaml" | head -30 || true
        echo ""
    fi
done

if [ $HAS_DIFFERENCES -eq 0 ]; then
    # Restore original files to avoid "files were modified by this hook" error
    echo "Restoring original bundle files..."
    for bundle_file in "${BUNDLE_FILES[@]}"; do
        backup_file="${TEMP_DIR}/$(basename "$bundle_file").backup"
        if [ -f "$backup_file" ]; then
            cp "$backup_file" "$bundle_file"
        fi
    done
    echo "✓ Bundle manifests are up-to-date"
    exit 0
else
    echo "To fix this issue:"
    echo "  1. Run: make bundle"
    echo "  2. Review and stage the changes: git add api/ bundle/"
    echo "  3. Commit again"
    exit 1
fi

# Made with Bob
