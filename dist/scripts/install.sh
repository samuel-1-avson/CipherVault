#!/usr/bin/env bash
# CipherVault - verified Linux & macOS installer/updater
# Usage: curl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.sh | bash
# Optional env knobs: CIPHERVAULT_VERSION=v1.0.9 (pin, skips the
# API call), CIPHERVAULT_INSTALL_DIR=/opt/cv-bin (override bindir),
# CIPHERVAULT_ROLE=developer|node|full (default full; developer = CLI+agent,
# node = CLI+operator+maintenance for guided `ciphervault node setup`).
set -euo pipefail

REPO="samuel-1-avson/CipherVault"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$OS" in
  mingw*|msys*|cygwin*)
    echo "Windows detected: run the PowerShell installer instead:" >&2
    echo "  irm https://raw.githubusercontent.com/${REPO}/main/dist/scripts/install.ps1 | iex" >&2
    exit 1
    ;;
esac
MUSL=0
if [ "$OS" = "linux" ]; then
  if [ -f /etc/alpine-release ] || ldd --version 2>&1 | grep -qi musl; then MUSL=1; fi
fi
case "$OS:$ARCH" in
  linux:x86_64) if [ "$MUSL" = 1 ]; then TARGET="x86_64-unknown-linux-musl"; else TARGET="x86_64-unknown-linux-gnu"; fi ;;
  linux:aarch64|linux:arm64) TARGET="aarch64-unknown-linux-gnu" ;;
  darwin:x86_64) TARGET="x86_64-apple-darwin" ;;
  darwin:arm64) TARGET="aarch64-apple-darwin" ;;
  *) echo "Unsupported platform: $OS/$ARCH" >&2; exit 1 ;;
esac

command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
CV_TOKEN="${CIPHERVAULT_GITHUB_TOKEN:-${GH_TOKEN:-${GITHUB_TOKEN:-}}}"
PRIVATE_HINT="If the repo is private, export CIPHERVAULT_GITHUB_TOKEN (a token with Contents: read) and re-run."
cv_curl() {
  if [ -n "$CV_TOKEN" ]; then curl -fsSL -H "Authorization: Bearer $CV_TOKEN" "$@";
  else curl -fsSL "$@"; fi
}
if command -v sha256sum >/dev/null; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null; then
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
elif command -v openssl >/dev/null; then
  sha256_file() { openssl dgst -sha256 "$1" | awk '{print $NF}'; }
else
  echo "a SHA-256 tool is required (sha256sum, shasum, or openssl)" >&2; exit 1
fi

TAG="${CIPHERVAULT_VERSION:-}"
if [ -z "$TAG" ]; then
  API_URL="https://api.github.com/repos/${REPO}/releases/latest"
else
  API_URL="https://api.github.com/repos/${REPO}/releases/tags/${TAG}"
fi
if ! RELEASE_JSON="$(cv_curl -H 'Accept: application/vnd.github+json' -H 'User-Agent: CipherVault-Installer' "$API_URL")"; then
  echo "Could not read the release feed. $PRIVATE_HINT" >&2; exit 1
fi
if [ -z "$TAG" ]; then
  TAG="$(printf '%s' "$RELEASE_JSON" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  [ -n "$TAG" ] || { echo "GitHub did not return a latest CipherVault release. $PRIVATE_HINT" >&2; exit 1; }
fi
PKG_NAME="ciphervault-${TAG}-${TARGET}.tar.gz"
SUMS_NAME="SHA256SUMS.txt"
# Assets download through the API asset endpoint (Accept: octet-stream):
# the browser-download redirector does not honor tokens on private repos.
asset_id() {
  printf '%s' "$RELEASE_JSON" | tr -d '\n' | sed -n 's/.*"id":[[:space:]]*\([0-9][0-9]*\)[^}]*"name":[[:space:]]*"'"$1"'"[^}]*}.*/\1/p'
}
PKG_ID="$(asset_id "$PKG_NAME")"
[ -n "$PKG_ID" ] || { echo "Release $TAG has no $TARGET archive ($PKG_NAME)." >&2; exit 1; }
SUMS_ID="$(asset_id "$SUMS_NAME")"
[ -n "$SUMS_ID" ] || { echo "Release $TAG has no $SUMS_NAME." >&2; exit 1; }

if [ -n "${CIPHERVAULT_INSTALL_DIR:-}" ]; then
  INSTALL_DIR="$CIPHERVAULT_INSTALL_DIR"; mkdir -p "$INSTALL_DIR"
elif [ -w /usr/local/bin ]; then INSTALL_DIR=/usr/local/bin
else INSTALL_DIR="${HOME}/.local/bin"; mkdir -p "$INSTALL_DIR"
fi
TMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TMP_DIR"' EXIT
ASSETS="https://api.github.com/repos/${REPO}/releases/assets"
cv_curl -H 'Accept: application/octet-stream' "$ASSETS/$PKG_ID" -o "$TMP_DIR/$PKG_NAME" || { echo "Could not download $PKG_NAME. $PRIVATE_HINT" >&2; exit 1; }
cv_curl -H 'Accept: application/octet-stream' "$ASSETS/$SUMS_ID" -o "$TMP_DIR/SHA256SUMS.txt" || { echo "Could not download SHA256SUMS.txt. $PRIVATE_HINT" >&2; exit 1; }
# Same rule as the in-app updater: first field is the hex digest, second
# (minus an optional '*' binary marker) is the file name.
EXPECTED="$(awk -v name="$PKG_NAME" '{entry=$2; sub(/^\*/, "", entry); if (entry==name) {print $1; exit}}' "$TMP_DIR/SHA256SUMS.txt")"
[ -n "$EXPECTED" ] || { echo "Release checksum does not list $PKG_NAME" >&2; exit 1; }
ACTUAL="$(sha256_file "$TMP_DIR/$PKG_NAME")"
[ "$EXPECTED" = "$ACTUAL" ] || { echo "Release checksum mismatch for $PKG_NAME" >&2; exit 1; }
tar -xzf "$TMP_DIR/$PKG_NAME" -C "$TMP_DIR"
ROLE="${CIPHERVAULT_ROLE:-full}"
case "$ROLE" in
  developer) WANT="ciphervault ciphervault-agent" ;;
  node) WANT="ciphervault ciphervault-operator ciphervault-maintenance" ;;
  full) WANT="ciphervault ciphervault-operator ciphervault-agent ciphervault-maintenance" ;;
  *) echo "Unknown CIPHERVAULT_ROLE '$ROLE'. Use developer, node, or full." >&2; exit 1 ;;
esac
for name in $WANT; do
  BINARY="$(find "$TMP_DIR" -type f -name "$name" | head -n 1)"
  [ -n "$BINARY" ] || { echo "Verified release archive has no $name binary" >&2; exit 1; }
  install -m 0755 "$BINARY" "$INSTALL_DIR/$name"
done
echo "CipherVault $TAG ($ROLE) installed to $INSTALL_DIR"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "NOTE: $INSTALL_DIR is not on PATH. Add: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
if [ "$ROLE" = "node" ]; then
  echo "Next: 'ciphervault node setup' for guided node onboarding."
else
  echo "Next: 'ciphervault init' (new vault), 'ciphervault --help' (command groups), or bare 'ciphervault' (guided TUI)."
fi
echo "To update later, run 'ciphervault update' or rerun this installer."
