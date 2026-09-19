#!/usr/bin/env bash
# Verify a CipherVault web deployment uses the signed immutable images produced
# by the release workflow. This script intentionally does not accept secrets or
# modify the deployment; run promotion separately after every check succeeds.
set -euo pipefail

INSTANCE_NAME="${INSTANCE_NAME:-cv-web-ui}"
ZONE="${ZONE:-us-east1-b}"
DOMAIN="${DOMAIN:-vault.cipherv.online}"
DASHBOARD_IMAGE="${CIPHERVAULT_DASHBOARD_IMAGE:-}"
ACCOUNT_IMAGE="${CIPHERVAULT_ACCOUNT_IMAGE:-}"
COSIGN_IDENTITY_REGEX="${COSIGN_CERTIFICATE_IDENTITY_REGEX:-}"
COSIGN_OIDC_ISSUER="${COSIGN_CERTIFICATE_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

require_digest_image() {
    local image="$1"
    [[ "$image" == ghcr.io/*@sha256:???????????????????????????????????????????????????????????????? ]] \
        || fail "image must be a GHCR digest reference: $image"
}

command -v gcloud >/dev/null 2>&1 || fail "gcloud is required"
command -v docker >/dev/null 2>&1 || fail "docker is required for local digest verification"
command -v cosign >/dev/null 2>&1 || fail "cosign is required for signature verification"
[[ -n "$COSIGN_IDENTITY_REGEX" ]] || fail "COSIGN_CERTIFICATE_IDENTITY_REGEX is required"
require_digest_image "$DASHBOARD_IMAGE"
require_digest_image "$ACCOUNT_IMAGE"

echo "Verifying release signatures..."
for image in "$DASHBOARD_IMAGE" "$ACCOUNT_IMAGE"; do
    cosign verify \
        --certificate-identity-regexp "$COSIGN_IDENTITY_REGEX" \
        --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
        "$image" >/dev/null
    docker pull "$image" >/dev/null
    local_digest="$(docker image inspect "$image" --format '{{index .RepoDigests 0}}')"
    [[ "$local_digest" == "$image" ]] || fail "local digest mismatch for $image ($local_digest)"
done

echo "Verifying the cloud instance and its running image digests..."
gcloud compute ssh "$INSTANCE_NAME" --zone="$ZONE" --command \
    "set -eu; test -f /opt/ciphervault-ui/docker-compose.yml; \
     sudo docker compose -f /opt/ciphervault-ui/docker-compose.yml ps --status running; \
     ui_id=\"\$(sudo docker compose -f /opt/ciphervault-ui/docker-compose.yml ps -q ciphervault-ui)\"; \
     acct_id=\"\$(sudo docker compose -f /opt/ciphervault-ui/docker-compose.yml ps -q account)\"; \
     test -n \"\$ui_id\"; test -n \"\$acct_id\"; \
     test \"\$(sudo docker inspect --format '{{.Config.Image}}' \"\$ui_id\")\" = '$DASHBOARD_IMAGE'; \
     test \"\$(sudo docker inspect --format '{{.Config.Image}}' \"\$acct_id\")\" = '$ACCOUNT_IMAGE'; \
     test \"\$(sudo docker inspect --format '{{.Config.User}}' \"\$ui_id\")\" = ciphervault; \
     test \"\$(sudo docker inspect --format '{{.Config.User}}' \"\$acct_id\")\" = ciphervault"

echo "Verifying the public contracts..."
curl --fail --silent --show-error "https://${DOMAIN}/api/vault" >/dev/null
curl --fail --silent --show-error "https://${DOMAIN}/api/operators" >/dev/null
curl --fail --silent --show-error "https://${DOMAIN}/api/account/capabilities" >/dev/null
if curl --fail --silent --show-error "https://${DOMAIN}/api/account/session" >/dev/null; then
    fail "anonymous account session unexpectedly succeeded"
fi

echo "Immutable image, runtime identity, health, and public contract checks passed."
