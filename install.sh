#!/bin/bash
set -e

# Configuration
REPO_OWNER="picogrid"
REPO_NAME="legion-system-auth"
BINARY_NAME="legion-auth"
INSTALL_DIR="/usr/local/bin"

# Detect OS and Arch
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l) ARCH="armv7" ;;
esac

# Map macOS arm64 to proper arch if needed (Go usually uses arm64 for Apple Silicon)
if [ "$OS" = "darwin" ] && [ "$ARCH" = "arm64" ]; then
    ARCH="arm64"
fi

ASSET_NAME="legion-auth-${OS}-${ARCH}"

echo "Detected platform: $OS $ARCH"
echo "Looking for asset: $ASSET_NAME"

# Get the download URL for the latest release
# This uses the GitHub API to find the asset URL for the latest release
RELEASE_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed. Please install jq:"
    echo "  macOS: brew install jq"
    echo "  Linux: sudo apt-get install jq (Debian/Ubuntu) or sudo yum install jq (RHEL/CentOS)"
    exit 1
fi

# Use GitHub token if available to increase rate limits (5000/hour vs 60/hour)
AUTH_HEADER=""
if [ -n "$GITHUB_TOKEN" ]; then
    AUTH_HEADER="-H \"Authorization: token $GITHUB_TOKEN\""
fi

DOWNLOAD_URL=$(curl -sL ${GITHUB_TOKEN:+-H "Authorization: token $GITHUB_TOKEN"} "$RELEASE_URL" | jq -r ".assets[] | select(.name | contains(\"$ASSET_NAME\")) | .browser_download_url" | head -1)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "Error: Could not find a release asset for your platform ($ASSET_NAME)."
    echo "Please check the releases page: https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
    exit 1
fi

echo "Downloading from: $DOWNLOAD_URL"

# Create a temporary directory
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Download the binary
curl -sL "$DOWNLOAD_URL" -o "$TMP_DIR/$BINARY_NAME"

# Verify download succeeded and file is not empty
if [ ! -s "$TMP_DIR/$BINARY_NAME" ]; then
    echo "Error: Downloaded binary is empty or download failed."
    exit 1
fi

# Optional: Verify checksum if available
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"
if curl -sL ${GITHUB_TOKEN:+-H "Authorization: token $GITHUB_TOKEN"} "$CHECKSUM_URL" -o "$TMP_DIR/${BINARY_NAME}.sha256" 2>/dev/null; then
    echo "Verifying checksum..."
    if command -v sha256sum &> /dev/null; then
        (cd "$TMP_DIR" && sha256sum -c "${BINARY_NAME}.sha256") || { echo "Error: Checksum verification failed"; exit 1; }
    elif command -v shasum &> /dev/null; then
        (cd "$TMP_DIR" && shasum -a 256 -c "${BINARY_NAME}.sha256") || { echo "Error: Checksum verification failed"; exit 1; }
    else
        echo "Warning: Neither sha256sum nor shasum found, skipping checksum verification"
    fi
else
    echo "Warning: No checksum file found, skipping verification"
fi

# Install
echo "Installing to $INSTALL_DIR..."

if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
else
    echo "Sudo permissions required to install to $INSTALL_DIR"
    sudo mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
fi

echo "Installation complete!"
echo "Run '$BINARY_NAME setup' to configure."
