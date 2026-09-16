#!/usr/bin/env bash
# CipherVault operator runtime bootstrap.  The operator image is staged by the
# signed promotion process; this script never clones source or builds images.
set -euo pipefail

readonly APP_DIR=/opt/ciphervault
readonly COMPOSE_FILE="$APP_DIR/docker-compose.yml"

if ! command -v docker >/dev/null 2>&1; then
    echo 'Docker is required before starting the staged operator image' >&2
    exit 1
fi
if [[ ! -f "$COMPOSE_FILE" || ! -s "$APP_DIR/.env" ]]; then
    echo 'No staged operator compose or service-token environment exists' >&2
    exit 1
fi
if ! docker image inspect ciphervault-operator:gcp >/dev/null 2>&1; then
    echo 'The staged ciphervault-operator:gcp image is missing; refusing a source build' >&2
    exit 1
fi

cd "$APP_DIR"
docker compose --env-file "$APP_DIR/.env" -f "$COMPOSE_FILE" up -d --force-recreate --remove-orphans
