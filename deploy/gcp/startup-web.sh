#!/usr/bin/env bash
# CipherVault immutable web release bootstrap for Compute Engine.
#
# A release promotion stages the reviewed Compose and Caddy files beneath
# /opt/ciphervault-ui/release before this script is installed as instance
# metadata. This script never checks out Git and never builds application
# images. It pulls only digest-pinned images specified by instance metadata.
set -euo pipefail

readonly APP_DIR=/opt/ciphervault-ui
readonly RELEASE_DIR="$APP_DIR/release"
readonly SECRETS_DIR="$APP_DIR/secrets"
readonly ENV_FILE="$APP_DIR/.env"
readonly TOTP_KEY_FILE="$SECRETS_DIR/account-totp-key"

metadata_value() {
    local key="$1"
    local fallback="${2:-}"
    local value
    value=$(curl --fail --silent --show-error --connect-timeout 2 \
        -H 'Metadata-Flavor: Google' \
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$key" \
        2>/dev/null || true)
    printf '%s' "${value:-$fallback}"
}

require_digest_image() {
    local name="$1"
    local image="$2"
    if [[ ! "$image" =~ ^ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]; then
        echo "$name must be a lowercase GHCR image pinned by sha256 digest" >&2
        exit 1
    fi
}

install_docker() {
    export DEBIAN_FRONTEND=noninteractive
    if ! command -v docker >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y --no-install-recommends ca-certificates curl gnupg
        install -m 0755 -d /etc/apt/keyrings
        curl --fail --silent --show-error https://download.docker.com/linux/ubuntu/gpg \
            -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc
        . /etc/os-release
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" \
            > /etc/apt/sources.list.d/docker.list
        apt-get update -y
        apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-compose-plugin
    fi
    if ! command -v jq >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y --no-install-recommends jq
    fi
}

fetch_totp_key() {
    local project_id="$1"
    local secret_name="$2"
    local token response_file key_file
    token=$(curl --fail --silent --show-error -H 'Metadata-Flavor: Google' \
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
        | jq -er '.access_token')
    response_file=$(mktemp)
    key_file=$(mktemp)
    trap 'rm -f "$response_file" "$key_file"' RETURN
    curl --fail --silent --show-error \
        -H "Authorization: Bearer $token" \
        "https://secretmanager.googleapis.com/v1/projects/$project_id/secrets/$secret_name/versions/latest:access" \
        > "$response_file"
    jq -er '.payload.data' "$response_file" | base64 --decode | tr -d '\r\n' > "$key_file"
    if ! grep -Eq '^[[:xdigit:]]{64}$' "$key_file"; then
        echo 'The account TOTP wrapping secret must contain exactly 32 hex bytes' >&2
        exit 1
    fi
    install -d -m 0700 "$SECRETS_DIR"
    install -o 10001 -g 10001 -m 0400 "$key_file" "$TOTP_KEY_FILE"
}

install_docker
mkdir -p "$APP_DIR" "$APP_DIR/caddy_data" "$APP_DIR/caddy_config"

if [[ ! -f "$RELEASE_DIR/docker-compose.yml" || ! -f "$RELEASE_DIR/Caddyfile" ]]; then
    echo 'No staged CipherVault release configuration exists; refusing to start a mutable deployment' >&2
    exit 1
fi

readonly DASHBOARD_IMAGE="$(metadata_value ciphervault-dashboard-image)"
readonly ACCOUNT_IMAGE="$(metadata_value ciphervault-account-image)"
readonly OPERATORS="$(metadata_value operator-endpoints)"
readonly TRUSTED_OPERATOR_IDENTITIES="$(metadata_value trusted-operator-identities | tr ';' ',')"
readonly WEB_DOMAIN="$(metadata_value web-domain vault.example.com)"
readonly ACME_EMAIL="$(metadata_value acme-email admin@example.com)"
readonly WEBAUTHN_RP_ID="$(metadata_value webauthn-rp-id "$WEB_DOMAIN")"
readonly WEBAUTHN_ORIGIN="$(metadata_value webauthn-origin "https://$WEB_DOMAIN")"
readonly ACCOUNT_ALLOWED_ORIGINS="$(metadata_value account-allowed-origins "$WEBAUTHN_ORIGIN")"
readonly TOTP_SECRET_NAME="$(metadata_value account-totp-secret ciphervault-account-totp-key)"
readonly PROJECT_ID="$(metadata_value project-id)"

require_digest_image CIPHERVAULT_DASHBOARD_IMAGE "$DASHBOARD_IMAGE"
require_digest_image CIPHERVAULT_ACCOUNT_IMAGE "$ACCOUNT_IMAGE"
if [[ -z "$OPERATORS" ]]; then
    echo 'operator-endpoints metadata must list private operator endpoints' >&2
    exit 1
fi
if [[ -z "$PROJECT_ID" || ! "$TOTP_SECRET_NAME" =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo 'project-id or account-totp-secret metadata is invalid' >&2
    exit 1
fi

fetch_totp_key "$PROJECT_ID" "$TOTP_SECRET_NAME"
install -o root -g root -m 0644 "$RELEASE_DIR/docker-compose.yml" "$APP_DIR/docker-compose.yml"
install -o root -g root -m 0644 "$RELEASE_DIR/Caddyfile" "$APP_DIR/Caddyfile"
umask 077
cat > "$ENV_FILE" <<EOF
WEB_DOMAIN=$WEB_DOMAIN
ACME_EMAIL=$ACME_EMAIL
CIPHERVAULT_DASHBOARD_IMAGE=$DASHBOARD_IMAGE
CIPHERVAULT_ACCOUNT_IMAGE=$ACCOUNT_IMAGE
CIPHERVAULT_OPERATORS=$OPERATORS
CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES=$TRUSTED_OPERATOR_IDENTITIES
CIPHERVAULT_WEBAUTHN_RP_ID=$WEBAUTHN_RP_ID
CIPHERVAULT_WEBAUTHN_ORIGIN=$WEBAUTHN_ORIGIN
CIPHERVAULT_ACCOUNT_ALLOWED_ORIGINS=$ACCOUNT_ALLOWED_ORIGINS
CIPHERVAULT_ACCOUNT_COOKIE_SECURE=true
CIPHERVAULT_ACCOUNT_TOTP_KEY_FILE=$TOTP_KEY_FILE
CIPHERVAULT_ACCOUNT_REQUIRE_TOTP_KEY=true
EOF
chmod 0600 "$ENV_FILE"

cat > /etc/systemd/system/ciphervault-ui.service <<'EOF'
[Unit]
Description=CipherVault immutable web dashboard release
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=/opt/ciphervault-ui
ExecStartPre=/usr/bin/docker compose pull --quiet
ExecStart=/usr/bin/docker compose up --force-recreate --remove-orphans
ExecStop=/usr/bin/docker compose down
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ciphervault-ui.service
