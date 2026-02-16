#!/bin/bash

###############################################################################
# Script: build_custom_catalog.sh
# Description: Build custom operator catalog for IBM Secure Pipeline Service
# This script installs prerequisites (catutil, skopeo) and builds a custom
# operator catalog by merging a bundle image with an existing catalog.
###############################################################################

set -e  # Exit on error
set -o pipefail  # Exit on pipe failure

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

###############################################################################
# Configuration - Environment Variables with Defaults
###############################################################################

# Registry and image configuration
export REGISTRY="${REGISTRY:-docker-na-public.artifactory.swg-devops.com/hyc-cloud-private-scratch-docker-local/tmannaru}"
export TAG="${TAG:-v4.9.0}"
export CATALOG_TO_CUSTOMIZE="${CATALOG_TO_CUSTOMIZE:-docker-na-public.artifactory.swg-devops.com/hyc-cloud-private-daily-docker-local/ibmcom/ibm-common-service-catalog:cd}"

# Derived variables
export BUNDLE_IMAGE="${BUNDLE_IMAGE:-$REGISTRY/ibm-iam-operator-bundle:$TAG}"
export CATALOG_IMAGE="${CATALOG_IMAGE:-$REGISTRY/ibm-common-service-catalog:$TAG}"
export FBC_DIR="${FBC_DIR:-$HOME/fbc_catalog_$TAG}"

# Tool versions
CATUTIL_VERSION="${CATUTIL_VERSION:-v0.1.0}"
SKOPEO_VERSION="${SKOPEO_VERSION:-1.14.0}"

# Architecture
ARCH="${ARCH:-amd64}"

# Artifactory credentials (must be provided via environment)
ARTIFACTORY_USERNAME="${ARTIFACTORY_USERNAME:-}"
ARTIFACTORY_TOKEN="${ARTIFACTORY_TOKEN:-}"

###############################################################################
# Display Configuration
###############################################################################

display_config() {
    log_info "==================================================================="
    log_info "Custom Operator Catalog Build Configuration"
    log_info "==================================================================="
    log_info "REGISTRY:              $REGISTRY"
    log_info "TAG:                   $TAG"
    log_info "BUNDLE_IMAGE:          $BUNDLE_IMAGE"
    log_info "CATALOG_TO_CUSTOMIZE:  $CATALOG_TO_CUSTOMIZE"
    log_info "CATALOG_IMAGE:         $CATALOG_IMAGE"
    log_info "FBC_DIR:               $FBC_DIR"
    log_info "CATUTIL_VERSION:       $CATUTIL_VERSION"
    log_info "SKOPEO_VERSION:        $SKOPEO_VERSION"
    log_info "ARCH:                  $ARCH"
    log_info "==================================================================="
}

###############################################################################
# Check Prerequisites
###############################################################################

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if running on Linux (required for amd64 binaries)
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        log_warn "This script is optimized for Linux. Current OS: $OSTYPE"
    fi
    
    # Check for required commands
    local required_commands=("docker" "curl" "tar")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command '$cmd' not found. Please install it first."
            exit 1
        fi
    done
    
    # Check for Artifactory credentials
    if [[ -z "$ARTIFACTORY_USERNAME" ]] || [[ -z "$ARTIFACTORY_TOKEN" ]]; then
        log_error "ARTIFACTORY_USERNAME and ARTIFACTORY_TOKEN must be set as environment variables"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

###############################################################################
# Install catutil
###############################################################################

install_catutil() {
    log_info "Installing catutil..."
    
    if command -v catutil &> /dev/null; then
        log_info "catutil is already installed: $(catutil --version 2>&1 || echo 'version unknown')"
        return 0
    fi
    
    local install_dir="/usr/local/bin"
    local temp_dir=$(mktemp -d)
    
    # catutil is from IBM internal GitHub Enterprise
    # URL format: https://github.ibm.com/CloudPakOpenContent/catalog-utils/releases/download/VERSION/catutil-linux-amd64
    local catutil_url="https://github.ibm.com/CloudPakOpenContent/catalog-utils/releases/download/${CATUTIL_VERSION}/catutil-linux-${ARCH}"
    
    log_info "Downloading catutil from IBM GitHub Enterprise: $catutil_url"
    
    # Download catutil binary
    if ! curl -L -f -o "$temp_dir/catutil" "$catutil_url"; then
        log_error "Failed to download catutil from $catutil_url"
        log_error "Please ensure you have access to IBM GitHub Enterprise (github.ibm.com)"
        log_error "Or install catutil manually from: https://github.ibm.com/CloudPakOpenContent/catalog-utils/releases"
        rm -rf "$temp_dir"
        exit 1
    fi
    
    # Make executable
    chmod +x "$temp_dir/catutil"
    
    # Install
    if [[ -w "$install_dir" ]]; then
        mv "$temp_dir/catutil" "$install_dir/catutil"
    else
        log_info "Installing catutil with sudo..."
        sudo mv "$temp_dir/catutil" "$install_dir/catutil"
    fi
    
    rm -rf "$temp_dir"
    
    if command -v catutil &> /dev/null; then
        log_info "catutil installed successfully: $(catutil --version 2>&1 || echo 'installed')"
    else
        log_error "Failed to install catutil"
        exit 1
    fi
}

###############################################################################
# Install skopeo
###############################################################################

install_skopeo() {
    log_info "Installing skopeo..."
    
    if command -v skopeo &> /dev/null; then
        log_info "skopeo is already installed: $(skopeo --version)"
        return 0
    fi
    
    log_info "Installing skopeo via package manager..."
    
    # Detect OS and install accordingly
    if [[ -f /etc/redhat-release ]]; then
        # RHEL/CentOS/Fedora
        log_info "Detected RHEL-based system, installing via yum/dnf..."
        if command -v dnf &> /dev/null; then
            sudo dnf install -y skopeo
        else
            sudo yum install -y skopeo
        fi
    elif [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu
        log_info "Detected Debian-based system, installing via apt..."
        sudo apt-get update
        sudo apt-get install -y skopeo
    elif [[ -f /etc/alpine-release ]]; then
        # Alpine
        log_info "Detected Alpine Linux, installing via apk..."
        sudo apk add skopeo
    else
        log_warn "Unknown OS. Attempting to install via package manager..."
        # Try common package managers
        if command -v dnf &> /dev/null; then
            sudo dnf install -y skopeo
        elif command -v yum &> /dev/null; then
            sudo yum install -y skopeo
        elif command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y skopeo
        elif command -v apk &> /dev/null; then
            sudo apk add skopeo
        else
            log_error "Could not find a suitable package manager to install skopeo"
            log_error "Please install skopeo manually: https://github.com/containers/skopeo/blob/main/install.md"
            exit 1
        fi
    fi
    
    if command -v skopeo &> /dev/null; then
        log_info "skopeo installed successfully: $(skopeo --version)"
    else
        log_error "Failed to install skopeo"
        log_error "Please install manually: https://github.com/containers/skopeo/blob/main/install.md"
        exit 1
    fi
}

###############################################################################
# Build Bundle Image
###############################################################################

build_bundle_image() {
    log_info "Building bundle image: $BUNDLE_IMAGE"
    
    if [[ ! -f "bundle.Dockerfile" ]]; then
        log_error "bundle.Dockerfile not found in current directory"
        exit 1
    fi
    
    if ! docker build -f bundle.Dockerfile -t "$BUNDLE_IMAGE" .; then
        log_error "Failed to build bundle image"
        exit 1
    fi
    
    log_info "Bundle image built successfully: $BUNDLE_IMAGE"
}

###############################################################################
# Create FBC Catalog Directory
###############################################################################

create_fbc_directory() {
    log_info "Creating FBC catalog directory: $FBC_DIR"
    
    if [[ -d "$FBC_DIR" ]]; then
        log_warn "FBC directory already exists. Removing it..."
        rm -rf "$FBC_DIR"
    fi
    
    mkdir -p "$FBC_DIR"
    log_info "FBC directory created: $FBC_DIR"
}

###############################################################################
# Merge Bundle with Catalog
###############################################################################

merge_bundle_catalog() {
    log_info "Merging bundle with catalog using catutil..."
    
    if ! catutil merge-bundle \
        --platform all \
        --format-file yaml \
        --format-layout schema \
        --input "$BUNDLE_IMAGE" \
        --target "$CATALOG_TO_CUSTOMIZE" \
        --output "$FBC_DIR"; then
        log_error "Failed to merge bundle with catalog"
        exit 1
    fi
    
    log_info "Bundle merged successfully into: $FBC_DIR"
}

###############################################################################
# Push Catalog Image
###############################################################################

push_catalog_image() {
    log_info "Pushing catalog image to registry: $CATALOG_IMAGE"
    
    if ! skopeo copy \
        --format v2s2 \
        --all \
        --dest-creds "$ARTIFACTORY_USERNAME:$ARTIFACTORY_TOKEN" \
        "oci:/$FBC_DIR/manifest-list" \
        "docker://$CATALOG_IMAGE"; then
        log_error "Failed to push catalog image"
        exit 1
    fi
    
    log_info "Catalog image pushed successfully: $CATALOG_IMAGE"
}

###############################################################################
# Cleanup
###############################################################################

cleanup() {
    if [[ "${CLEANUP_FBC_DIR:-true}" == "true" ]]; then
        log_info "Cleaning up FBC directory: $FBC_DIR"
        rm -rf "$FBC_DIR"
    else
        log_info "Skipping cleanup. FBC directory preserved: $FBC_DIR"
    fi
}

###############################################################################
# Main Execution
###############################################################################

main() {
    log_info "Starting custom operator catalog build process..."
    
    # Display configuration
    display_config
    
    # Check prerequisites
    check_prerequisites
    
    # Install tools
    install_catutil
    install_skopeo
    
    # Build and push catalog
    build_bundle_image
    create_fbc_directory
    merge_bundle_catalog
    push_catalog_image
    
    # Cleanup
    cleanup
    
    log_info "==================================================================="
    log_info "Custom operator catalog build completed successfully!"
    log_info "Catalog Image: $CATALOG_IMAGE"
    log_info "==================================================================="
}

# Trap errors and cleanup
trap 'log_error "Script failed at line $LINENO"' ERR

# Run main function
main "$@"

# Made with Bob
