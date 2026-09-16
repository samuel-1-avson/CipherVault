#!/usr/bin/env bash
# CipherVault — Automated Linux & macOS Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.sh | bash

set -euo pipefail

REPO="samuel-1-avson/CipherVault"
TAG="v1.0.0"

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
INSTALLED=false

if curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/${PKG_NAME}"; then
    tar -xzf "${TMP_DIR}/${PKG_NAME}" -C "${TMP_DIR}"
    find "${TMP_DIR}" -type f -name "ciphervault*" -exec cp {} "${INSTALL_DIR}/" \;
    chmod +x "${INSTALL_DIR}"/ciphervault*
    INSTALLED=true
fi

if [ "$INSTALLED" = "false" ]; then
    echo "Release archive not yet attached or failed. Checking standalone release binary..."
    STANDALONE_URL="https://github.com/${REPO}/releases/download/${TAG}/ciphervault-${TARGET}"
    if curl -fsSL "${STANDALONE_URL}" -o "${INSTALL_DIR}/ciphervault"; then
        chmod +x "${INSTALL_DIR}/ciphervault"
        INSTALLED=true
    fi
fi

if [ "$INSTALLED" = "false" ]; then
    echo "Pre-built binary not found for ${TAG}. Attempting cargo install from GitHub..."
    if command -v cargo >/dev/null 2>&1; then
        cargo install --locked --git "https://github.com/${REPO}.git" ciphervault-cli --root "${INSTALL_DIR}/.."
        INSTALLED=true
    else
        echo "Error: Could not download pre-built binary and cargo is not installed." >&2
        echo "Please install Rust (https://rustup.rs) or download a release from https://github.com/${REPO}/releases" >&2
        exit 1
    fi
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
