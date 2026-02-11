#!/bin/bash
set -e

# Configuration
REPO_OWNER="picogrid"
REPO_NAME="legion-system-auth"
BINARY_NAME="legion-auth"
INSTALL_DIR="/usr/local/bin"

# Glyphs
CHECKMARK="✓"
CROSS="✗"
ARROW="→"
PACKAGE="📦"
LOCK="🔒"
ROCKET="🚀"

# Spinner animation
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while ps -p $pid > /dev/null 2>&1; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

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

echo ""
echo "════════════════════════════════════════════════"
echo "  $PACKAGE  Legion System Auth Installer"
echo "════════════════════════════════════════════════"
echo ""
echo "$ARROW Detected platform: $OS $ARCH"
echo "$ARROW Looking for asset: $ASSET_NAME"

# Get the download URL for the latest release
# This uses the GitHub API to find the asset URL for the latest release
RELEASE_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo ""
    echo "$CROSS Error: jq is required but not installed. Please install jq:"
    echo "  macOS: brew install jq"
    echo "  Linux: sudo apt-get install jq (Debian/Ubuntu) or sudo yum install jq (RHEL/CentOS)"
    exit 1
fi

# Use GitHub token if available to increase rate limits (5000/hour vs 60/hour)
AUTH_HEADER=""
if [ -n "$GITHUB_TOKEN" ]; then
    AUTH_HEADER="-H \"Authorization: token $GITHUB_TOKEN\""
fi

echo ""
echo "$ARROW Fetching latest release information..."
DOWNLOAD_URL=$(curl -sL ${GITHUB_TOKEN:+-H "Authorization: token $GITHUB_TOKEN"} "$RELEASE_URL" | jq -r ".assets[] | select(.name | contains(\"$ASSET_NAME\")) | .browser_download_url" | head -1)

if [ -z "$DOWNLOAD_URL" ]; then
    echo ""
    echo "$CROSS Error: Could not find a release asset for your platform ($ASSET_NAME)."
    echo "  Please check the releases page: https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
    exit 1
fi

echo "$CHECKMARK Release found"
echo ""
echo "$ARROW Downloading binary..."
echo "  Source: $DOWNLOAD_URL"

# Create a temporary directory
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Download the binary with its original asset name
curl -sL "$DOWNLOAD_URL" -o "$TMP_DIR/$ASSET_NAME" &
spinner $!
wait $!

# Verify download succeeded and file is not empty
if [ ! -s "$TMP_DIR/$ASSET_NAME" ]; then
    echo ""
    echo "$CROSS Error: Downloaded binary is empty or download failed."
    exit 1
fi

echo "$CHECKMARK Download complete"

# Verify checksum with retry (handles GitHub CDN propagation delays)
echo ""
echo "$ARROW Verifying integrity..."
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

verify_checksum() {
    if command -v sha256sum &> /dev/null; then
        (cd "$TMP_DIR" && sha256sum -c "${ASSET_NAME}.sha256" 2>&1 | grep -q "OK")
    elif command -v shasum &> /dev/null; then
        (cd "$TMP_DIR" && shasum -a 256 -c "${ASSET_NAME}.sha256" 2>&1 | grep -q "OK")
    else
        echo "⚠  Warning: Neither sha256sum nor shasum found, skipping checksum verification"
        return 0
    fi
}

MAX_RETRIES=3
RETRY_DELAY=2

for attempt in $(seq 1 $MAX_RETRIES); do
    # Download checksum file (fresh each attempt to handle CDN propagation)
    if ! curl -sL ${GITHUB_TOKEN:+-H "Authorization: token $GITHUB_TOKEN"} "$CHECKSUM_URL" -o "$TMP_DIR/${ASSET_NAME}.sha256" 2>/dev/null; then
        echo "⚠  Warning: No checksum file found, skipping verification"
        break
    fi

    if verify_checksum; then
        echo "$LOCK Checksum verified"
        break
    else
        if [ $attempt -lt $MAX_RETRIES ]; then
            echo "  Checksum mismatch, retrying in ${RETRY_DELAY}s... (attempt $attempt/$MAX_RETRIES)"
            sleep $RETRY_DELAY
            # Re-download binary on retry (CDN may have been serving stale content)
            curl -sL "$DOWNLOAD_URL" -o "$TMP_DIR/$ASSET_NAME" 2>/dev/null
            RETRY_DELAY=$((RETRY_DELAY * 2))
        else
            echo ""
            echo "$CROSS Error: Checksum verification failed after $MAX_RETRIES attempts"
            echo "  This may indicate a corrupted download or CDN cache issue."
            echo "  Please try again in a few minutes."
            exit 1
        fi
    fi
done

# Install (rename to generic binary name during installation)
echo ""
echo "$ARROW Installing to $INSTALL_DIR..."

if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP_DIR/$ASSET_NAME" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
else
    echo "  🔑 Sudo permissions required"
    sudo mv "$TMP_DIR/$ASSET_NAME" "$INSTALL_DIR/$BINARY_NAME"
    sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
fi

echo ""
echo "════════════════════════════════════════════════"
echo "  $ROCKET Installation complete!"
echo "════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Run '$BINARY_NAME login' to authenticate"
echo "  2. Run '$BINARY_NAME install --user' to install as service"
echo ""
