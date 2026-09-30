#!/usr/bin/env bash
# CipherVault - verified Linux & macOS installer/updater
# Usage: curl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.sh | bash
# Optional env knobs: CIPHERVAULT_VERSION=v1.0.26 (pin, skips the
# API call), CIPHERVAULT_INSTALL_DIR=/opt/cv-bin (override bindir),
# CIPHERVAULT_ROLE=developer|node|full (default full; developer = CLI+agent,
# node = CLI+operator+maintenance for guided `ciphervault node setup`).
set -euo pipefail

# Verification uses an independently installed OpenSSL; release downloads are
# never executed to authenticate themselves. Keep these roots aligned with update.rs.
verify_release_signature() {
  local sums="$1" envelope="$2" expected_tag="$3" scratch="$4"
  command -v openssl >/dev/null || { echo "OpenSSL 3 with Ed25519 support is required; install it from your trusted OS package manager and retry." >&2; return 1; }
  local openssl_version
  openssl_version="$(openssl version)"
  [[ "$openssl_version" =~ ^OpenSSL\ ([3-9]|[1-9][0-9]+)\. ]] || { echo "OpenSSL 3 or newer is required for Ed25519 release verification; install it from your trusted OS package manager and retry." >&2; return 1; }
  [[ "$expected_tag" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || { echo "Invalid release tag" >&2; return 1; }
  [ "$(awk 'END {print NR}' "$envelope")" = 4 ] || { echo "Malformed release signature envelope" >&2; return 1; }
  local version tagline keyline sigline key_id signature public_key
  version="$(sed -n '1p' "$envelope")"
  tagline="$(sed -n '2p' "$envelope")"
  keyline="$(sed -n '3p' "$envelope")"
  sigline="$(sed -n '4p' "$envelope")"
  [ "$tagline" = "tag: $expected_tag" ] || { echo "Release signature tag mismatch" >&2; return 1; }
  key_id="${keyline#key-id: }"; signature="${sigline#signature: }"
  [ "$keyline" = "key-id: $key_id" ] && [ "$sigline" = "signature: $signature" ] || { echo "Malformed release signature fields" >&2; return 1; }
  [[ "$key_id" =~ ^[0-9a-f]{16}$ && "$signature" =~ ^[0-9a-f]{128}$ ]] || { echo "Malformed release signature hex" >&2; return 1; }
  case "$key_id" in
    b625994c0c3f53a6) public_key=b625994c0c3f53a6c40b0eadebe7ba1f5199e9f829a4bf20e064ae7aaab22c1e ;;
    *) echo "Untrusted release signing key" >&2; return 1 ;;
  esac
  case "$version" in
    CIPHERVAULT-RELEASE-SIG-V2)
      { printf 'CIPHERVAULT-RELEASE-SIG-V2\ntag: %s\n' "$expected_tag"; cat "$sums"; } > "$scratch/release-message.bin" ;;
    CIPHERVAULT-RELEASE-SIG-V1)
      [ "${CIPHERVAULT_ALLOW_LEGACY_RELEASE_SIGNATURE:-}" = 1 ] && [ -n "${CIPHERVAULT_VERSION:-}" ] || { echo "V1 signatures require an explicitly pinned historical CIPHERVAULT_VERSION and CIPHERVAULT_ALLOW_LEGACY_RELEASE_SIGNATURE=1." >&2; return 1; }
      cp "$sums" "$scratch/release-message.bin" ;;
    *) echo "Unsupported release signature version" >&2; return 1 ;;
  esac
  # RFC 8410 Ed25519 SubjectPublicKeyInfo DER header followed by the pinned key.
  hex_to_bytes() {
    local value="$1"
    while [ -n "$value" ]; do printf '%b' "\\x${value:0:2}"; value="${value:2}"; done
  }
  hex_to_bytes "302a300506032b6570032100$public_key" > "$scratch/release-public-key.der"
  hex_to_bytes "$signature" > "$scratch/release-signature.bin"
  openssl pkeyutl -verify -pubin -inkey "$scratch/release-public-key.der" -keyform DER -rawin \
    -in "$scratch/release-message.bin" -sigfile "$scratch/release-signature.bin" >/dev/null 2>&1 || { echo "Release signature verification failed; refusing installation." >&2; return 1; }
}

if [ "${CIPHERVAULT_INSTALLER_VERIFY_ONLY:-}" = 1 ]; then
  verify_release_signature "$CIPHERVAULT_VERIFY_SUMS" "$CIPHERVAULT_VERIFY_SIGNATURE" "$CIPHERVAULT_VERIFY_TAG" "$CIPHERVAULT_VERIFY_SCRATCH"
  exit
fi

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
[[ "$TAG" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || { echo "Invalid release tag" >&2; exit 1; }
PKG_NAME="ciphervault-${TAG}-${TARGET}.tar.gz"
SUMS_NAME="SHA256SUMS.txt"
SIG_NAME="SHA256SUMS.txt.sig"
# Assets download through the API asset endpoint (Accept: octet-stream):
# the browser-download redirector does not honor tokens on private repos.
asset_id() {
  printf '%s' "$RELEASE_JSON" | tr -d '\n' | sed -n 's/.*"id":[[:space:]]*\([0-9][0-9]*\)[^}]*"name":[[:space:]]*"'"$1"'"[^}]*}.*/\1/p'
}
PKG_ID="$(asset_id "$PKG_NAME")"
[ -n "$PKG_ID" ] || { echo "Release $TAG has no $TARGET archive ($PKG_NAME)." >&2; exit 1; }
SUMS_ID="$(asset_id "$SUMS_NAME")"
[ -n "$SUMS_ID" ] || { echo "Release $TAG has no $SUMS_NAME." >&2; exit 1; }
SIG_ID="$(asset_id "$SIG_NAME")"
[ -n "$SIG_ID" ] || { echo "Release $TAG is unsigned (missing $SIG_NAME)." >&2; exit 1; }

if [ -n "${CIPHERVAULT_INSTALL_DIR:-}" ]; then
  INSTALL_DIR="$CIPHERVAULT_INSTALL_DIR"; mkdir -p "$INSTALL_DIR"
elif [ -w /usr/local/bin ]; then INSTALL_DIR=/usr/local/bin
else INSTALL_DIR="${HOME}/.local/bin"; mkdir -p "$INSTALL_DIR"
fi
TMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TMP_DIR"' EXIT
ASSETS="https://api.github.com/repos/${REPO}/releases/assets"
cv_curl -H 'Accept: application/octet-stream' "$ASSETS/$PKG_ID" -o "$TMP_DIR/$PKG_NAME" || { echo "Could not download $PKG_NAME. $PRIVATE_HINT" >&2; exit 1; }
cv_curl -H 'Accept: application/octet-stream' "$ASSETS/$SUMS_ID" -o "$TMP_DIR/SHA256SUMS.txt" || { echo "Could not download SHA256SUMS.txt. $PRIVATE_HINT" >&2; exit 1; }
cv_curl -H 'Accept: application/octet-stream' "$ASSETS/$SIG_ID" -o "$TMP_DIR/SHA256SUMS.txt.sig" || { echo "Could not download release signature. $PRIVATE_HINT" >&2; exit 1; }
verify_release_signature "$TMP_DIR/SHA256SUMS.txt" "$TMP_DIR/SHA256SUMS.txt.sig" "$TAG" "$TMP_DIR"
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
