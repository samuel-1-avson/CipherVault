#!/usr/bin/env bash
# CipherVault — Automated Linux & macOS Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/master/dist/scripts/install.sh | bash

set -euo pipefail

REPO="samuel-1-avson/CipherVault"
TAG="v0.1.0-beta.2"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    linux)
        case "$ARCH" in
            x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
            aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
            *) echo "Unsupported Linux architecture: $ARCH" >&2; exit 1 ;;
        esac
        ;;
    darwin)
        case "$ARCH" in
            x86_64) TARGET="x86_64-apple-darwin" ;;
            arm64) TARGET="aarch64-apple-darwin" ;;
            *) echo "Unsupported macOS architecture: $ARCH" >&2; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported operating system: $OS" >&2
        exit 1
        ;;
esac

PKG_NAME="ciphervault-${TAG}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${PKG_NAME}"

echo "======================================================="
echo "  Installing CipherVault ${TAG} (${OS} ${ARCH})"
echo "======================================================="

# Choose installation directory
if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "${INSTALL_DIR}"
    if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
        echo "Note: Ensure ${INSTALL_DIR} is in your PATH (e.g. in ~/.bashrc or ~/.zshrc)"
    fi
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "Downloading ${DOWNLOAD_URL}..."
if curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/${PKG_NAME}"; then
    tar -xzf "${TMP_DIR}/${PKG_NAME}" -C "${TMP_DIR}"
    cp "${TMP_DIR}"/bin/ciphervault* "${INSTALL_DIR}/"
    chmod +x "${INSTALL_DIR}"/ciphervault*
else
    echo "Pre-built binary not found for ${TAG}. Attempting cargo install..."
    cargo install --path apps/cli --force --root "${INSTALL_DIR}/.."
fi

echo ""
echo "✓ CipherVault installed successfully to ${INSTALL_DIR}!"
echo ""
echo "Quickstart:"
echo "  ciphervault init                    # Initialize vault in current repository"
echo "  ciphervault track .env              # Track confidential files"
echo "  ciphervault push -m 'Initial'       # Encrypt and replicate snapshot"
echo "  ciphervault ui                      # Launch local web dashboard"
echo ""
