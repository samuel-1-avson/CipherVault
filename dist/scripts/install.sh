#!/usr/bin/env bash
# CipherVault - verified Linux & macOS installer/updater
# Usage: curl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.sh | bash
set -euo pipefail

REPO="samuel-1-avson/CipherVault"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$OS:$ARCH" in
  linux:x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
  linux:aarch64|linux:arm64) TARGET="aarch64-unknown-linux-gnu" ;;
  darwin:x86_64) TARGET="x86_64-apple-darwin" ;;
  darwin:arm64) TARGET="aarch64-apple-darwin" ;;
  *) echo "Unsupported platform: $OS/$ARCH" >&2; exit 1 ;;
esac

command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
TAG="$(curl -fsSL -H 'Accept: application/vnd.github+json' -H 'User-Agent: CipherVault-Installer' "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
[ -n "$TAG" ] || { echo "GitHub did not return a latest CipherVault release" >&2; exit 1; }
PKG_NAME="ciphervault-${TAG}-${TARGET}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${TAG}"

if [ -w /usr/local/bin ]; then INSTALL_DIR=/usr/local/bin; else INSTALL_DIR="${HOME}/.local/bin"; mkdir -p "$INSTALL_DIR"; fi
TMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TMP_DIR"' EXIT
curl -fsSL "$BASE/$PKG_NAME" -o "$TMP_DIR/$PKG_NAME"
curl -fsSL "$BASE/SHA256SUMS.txt" -o "$TMP_DIR/SHA256SUMS.txt"
EXPECTED="$(awk -v name="$PKG_NAME" '$2==name || $2=="*"name {print $1; exit}' "$TMP_DIR/SHA256SUMS.txt")"
[ -n "$EXPECTED" ] || { echo "Release checksum does not list $PKG_NAME" >&2; exit 1; }
ACTUAL="$(sha256sum "$TMP_DIR/$PKG_NAME" | awk '{print $1}')"
[ "$EXPECTED" = "$ACTUAL" ] || { echo "Release checksum mismatch" >&2; exit 1; }
tar -xzf "$TMP_DIR/$PKG_NAME" -C "$TMP_DIR"
BINARY="$(find "$TMP_DIR" -type f -name ciphervault -perm -u+x | head -n1)"
[ -n "$BINARY" ] || { echo "Verified release archive has no ciphervault binary" >&2; exit 1; }
install -m 0755 "$BINARY" "$INSTALL_DIR/ciphervault"
echo "CipherVault $TAG installed to $INSTALL_DIR/ciphervault"
echo "Run 'ciphervault --help'. To update later, run 'ciphervault update' or rerun this installer."

