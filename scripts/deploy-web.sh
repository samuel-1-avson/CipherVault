#!/usr/bin/env bash
# =============================================================================
# CipherVault web deploy pipeline — deploy-web.sh
# One-command, billing-independent deploys for the public web surfaces.
# Runs ON the web box (e.g. cv-web-ui over SSH). No GitHub Actions required.
#
#   sudo bash scripts/deploy-web.sh status
#   sudo bash scripts/deploy-web.sh landing [--ref main] [--expect v1.0.30]
#   sudo bash scripts/deploy-web.sh dashboard --allow-unsigned [--ref main]
#
# Design rules (do not weaken):
#   - Never touches secrets: the box .env is read, never rewritten, except
#     the dashboard flow which backs it up first and restores on failure.
#   - Verify before swap: structural marker checks on every fetched bundle.
#   - Validate before reload: `caddy validate` gates every Caddy change.
#   - Health-check after every change, automatic rollback on failure.
#   - Timestamped backups, last 5 kept. Nothing is deleted without a backup.
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/samuel-1-avson/CipherVault"
LANDING_DIR="/var/www/ciphervault-landing"
BACKUP_ROOT="/var/www/backups"
COMPOSE_DIR="/opt/ciphervault-ui"
CADDYFILE="${COMPOSE_DIR}/Caddyfile"
TMP_ROOT="/tmp/cv-deploy"

log()  { printf '[deploy-web] %s\n' "$*"; }
fail() { printf '[deploy-web] ERROR: %s\n' "$*" >&2; exit 1; }

need_root() {
  [ "$(id -u)" = "0" ] || fail "run as root (sudo bash scripts/deploy-web.sh ...)"
}

compose() { docker compose --project-directory "${COMPOSE_DIR}" "$@"; }

health_landing_local() {
  # Local Host-header check that never leaves the box (no DNS involved).
  python3 - "$@" <<'PY'
import sys, urllib.request
host = "cipherv.online"
req = urllib.request.Request("http://127.0.0.1/", headers={"Host": host})
body = urllib.request.urlopen(req, timeout=15).read().decode("utf-8", "replace")
import re
versions = sorted(set(re.findall(r"v1\.0\.\d+", body)))
print("landing_local_bytes=%d versions=%s" % (len(body), ",".join(versions) or "NONE"))
sys.exit(0 if versions else 1)
PY
}

health_dashboard_local() {
  curl -fsS --max-time 15 -o /dev/null -w "dashboard_local:%{http_code}\n" \
    "http://127.0.0.1:8080/api/context"
}

cmd_status() {
  log "--- landing (local, Host: cipherv.online) ---"
  health_landing_local || log "landing: UNHEALTHY (no version markers)"
  log "--- dashboard (local :8080 /api/context) ---"
  health_dashboard_local || log "dashboard: UNHEALTHY"
  log "--- dashboard build_version (public) ---"
  curl -fsS --max-time 15 "https://vault.cipherv.online/api/context" 2>/dev/null \
    | python3 -c "import json,sys; print('build_version=' + json.load(sys.stdin).get('build_version','?'))" \
    || log "dashboard public API: unreachable"
}

fetch_landing() {
  # Sparse checkout of apps/landing at $ref (single source: main branch).
  # Falls back to a full tarball if git is unavailable.
  local ref="$1" dest="$2"
  rm -rf "${dest}"; mkdir -p "${dest}"
  if command -v git >/dev/null 2>&1; then
    log "fetching apps/landing @ ${ref} via sparse checkout"
    git clone --depth 1 --branch "${ref}" --filter=blob:none --sparse \
      "${REPO_URL}.git" "${dest}/repo" >&2
    ( cd "${dest}/repo" && git sparse-checkout set apps/landing >&2 )
    cp -r "${dest}/repo/apps/landing/." "${dest}/landing/"
    rm -rf "${dest}/repo"
  else
    log "git missing; falling back to full tarball"
    curl -fsSL -o "${dest}/repo.tgz" "${REPO_URL}/archive/refs/heads/${ref}.zip" \
      || fail "tarball download failed"
    python3 - "${dest}/repo.tgz" "${dest}" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
top = z.namelist()[0].split("/")[0]
z.extractall(sys.argv[2] + "/raw")
import shutil
shutil.move(sys.argv[2] + "/raw/" + top + "/apps/landing", sys.argv[2] + "/landing")
PY
  fi
  # Structural verification before anything is swapped.
  for f in index.html script.js styles.css CNAME; do
    [ -f "${dest}/landing/${f}" ] \
      || fail "fetched bundle missing ${f}; refusing to deploy"
  done
  grep -q "cipherv.online" "${dest}/landing/index.html" \
    || fail "fetched index.html has no cipherv.online markers; refusing to deploy"
  log "bundle verified: $(ls "${dest}/landing" | tr '\n' ' ')"
}

cmd_landing() {
  local ref="main" expect="" dry=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --ref)     ref="$2"; shift 2;;
      --expect)  expect="$2"; shift 2;;
      --dry-run) dry=1; shift;;
      *) fail "unknown flag: $1";;
    esac
  done
  need_root
  local work="${TMP_ROOT}/landing-$(date +%Y%m%d-%H%M%S)"
  fetch_landing "${ref}" "${work}"
  if [ -n "${expect}" ]; then
    grep -q "${expect}" "${work}/landing/index.html" \
      || fail "bundle lacks expected marker ${expect}; refusing to deploy"
    log "expected marker ${expect} present"
  fi
  if [ "${dry}" = "1" ]; then
    log "dry-run ok; bundle staged at ${work}/landing (nothing swapped)"
    return 0
  fi
  mkdir -p "${BACKUP_ROOT}"
  if [ -d "${LANDING_DIR}" ]; then
    local backup="${BACKUP_ROOT}/landing-$(date +%Y%m%d-%H%M%S)"
    log "backing up current site to ${backup}"
    cp -a "${LANDING_DIR}" "${backup}"
    # Keep last 5 backups.
    ls -dt "${BACKUP_ROOT}"/landing-* 2>/dev/null | tail -n +6 | xargs -r rm -rf
  fi
  mkdir -p "${LANDING_DIR}"
  log "swapping in new bundle"
  cp -r "${work}/landing/." "${LANDING_DIR}/"
  rm -rf "${work}"
  if ! health_landing_local; then
    log "health check FAILED after swap; rolling back"
    local latest
    latest="$(ls -dt "${BACKUP_ROOT}"/landing-* 2>/dev/null | head -n 1 || true)"
    [ -n "${latest}" ] || fail "no backup available; manual recovery needed"
    rm -rf "${LANDING_DIR}"
    cp -a "${latest}" "${LANDING_DIR}"
    compose restart caddy >/dev/null
    fail "rolled back to ${latest}; new bundle NOT live"
  fi
  # Caddy serves static files directly; no reload needed for content swaps.
  # Reload only if the Caddyfile itself changed (it did not in this flow).
  log "landing deployed and healthy"
}

cmd_dashboard() {
  local allow=0 ref="main"
  while [ $# -gt 0 ]; do
    case "$1" in
      --allow-unsigned) allow=1; shift;;
      --ref) ref="$2"; shift 2;;
      *) fail "unknown flag: $1";;
    esac
  done
  need_root
  [ "${allow}" = "1" ] || fail \
    "refusing: local image builds bypass the signed GHCR digests (supply-chain posture). Re-run with --allow-unsigned if you accept that."
  command -v docker >/dev/null || fail "docker not found"
  command -v git >/dev/null || fail "git is required for dashboard builds"
  local work="${TMP_ROOT}/dash-$(date +%Y%m%d-%H%M%S)"
  log "cloning @ ${ref} for local image build"
  git clone --depth 1 --branch "${ref}" "${REPO_URL}.git" "${work}/src" >&2
  ( cd "${work}/src" && git rev-parse --short HEAD )
  log "building dashboard image locally (takes several minutes)"
  docker build -f "${work}/src/deploy/docker/Dockerfile.dashboard" \
    -t "ciphervault-dashboard:local-$(date +%Y%m%d-%H%M%S)" "${work}/src" >&2
  local tag
  tag="$(docker images --format '{{.Repository}}:{{.Tag}}' \
    | grep '^ciphervault-dashboard:local-' | sort | tail -n 1)"
  [ -n "${tag}" ] || fail "local image build produced no tag"
  log "built ${tag}"
  # Swap ONLY the image pin in .env, with backup + restore on failure.
  local envf="${COMPOSE_DIR}/.env"
  local envbak="${envf}.bak-$(date +%Y%m%d-%H%M%S)"
  cp -a "${envf}" "${envbak}"
  log ".env backed up to ${envbak}"
  rollback_dashboard() {
    log "restoring .env and recreating previous containers"
    cp -a "${envbak}" "${envf}"
    ( cd "${COMPOSE_DIR}" && docker compose up -d --force-recreate ciphervault-ui account >/dev/null )
  }
  sed -i "s|^CIPHERVAULT_DASHBOARD_IMAGE=.*|CIPHERVAULT_DASHBOARD_IMAGE=${tag}|" "${envf}"
  ( cd "${COMPOSE_DIR}" && docker compose up -d --force-recreate ciphervault-ui account )
  sleep 15
  if health_dashboard_local && curl -fsS --max-time 15 "http://127.0.0.1:8080/api/context" \
      | grep -q '"build_version"'; then
    log "dashboard healthy on ${tag}"
    rm -rf "${work}"
    log "NOTE: this box now runs a locally-built (unsigned) image. Re-pin to a signed GHCR digest after CI is available."
  else
    rollback_dashboard
    fail "dashboard unhealthy on ${tag}; rolled back"
  fi
}

case "${1:-}" in
  status)    shift; cmd_status "$@";;
  landing)   shift; cmd_landing "$@";;
  dashboard) shift; cmd_dashboard "$@";;
  *) cat >&2 <<'EOF'
usage: sudo bash scripts/deploy-web.sh <status|landing|dashboard> [flags]
  status                              show live versions of landing + dashboard
  landing [--ref main] [--expect vX.Y.Z] [--dry-run]
                                      fetch, verify, swap + health-check the landing
  dashboard --allow-unsigned [--ref main]
                                      locally rebuild + swap dashboard images
EOF
     exit 2;;
esac
