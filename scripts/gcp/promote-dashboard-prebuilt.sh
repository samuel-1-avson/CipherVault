#!/usr/bin/env bash
# =============================================================================
# Web VM dashboard promotion from a checksum-pinned release CLI (no CI).
# Runs ON cv-web-ui as root:
#
#   sudo bash promote-dashboard-prebuilt.sh <stage> <sha256> <version> <revision>
#
# <stage> holds `ciphervault` (Linux x86_64 release asset), the two
# entrypoint scripts and Dockerfile.dashboard.prebuilt. Steps: verify the
# binary hash and --version, build the image, back up .env, pin ONLY
# CIPHERVAULT_DASHBOARD_IMAGE, recreate ONLY the dashboard service, then
# require /api/context build_version == <version> plus healthy
# /api/operators and /api/explorer/overview. Any failure restores the
# .env backup and the previously RUNNING image (read from the live
# container, not from .env). The account service is never touched.
# =============================================================================
set -euo pipefail
STAGE="${1:?stage}"; WANT_SHA="${2:?sha256}"; VERSION="${3:?version}"; REV="${4:?revision}"
DIR=/opt/ciphervault-ui; ENVF="$DIR/.env"; SVC=ciphervault-ui
TS="$(date -u +%Y%m%dT%H%M%SZ)"; NEW="ciphervault-dashboard:${VERSION}-${REV}"
log() { printf '[web %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { log "FAIL: $*"; exit 1; }
compose() { docker compose --project-directory "$DIR" "$@"; }

check_live() {
  local ctx
  ctx="$(curl -fsS --max-time 15 http://127.0.0.1:8080/api/context)" || return 1
  echo "$ctx" | python3 -c 'import json,sys; c=json.load(sys.stdin); print("build_version=%s mode=%s" % (c.get("build_version"), c.get("mode"))); sys.exit(0 if c.get("build_version")==sys.argv[1] else 1)' "$1" || return 1
  curl -fsS --max-time 30 http://127.0.0.1:8080/api/operators >/dev/null || return 1
  curl -fsS --max-time 30 http://127.0.0.1:8080/api/explorer/overview >/dev/null || return 1
}

got="$(sha256sum "$STAGE/ciphervault" | cut -d' ' -f1)"
[ "$got" = "$WANT_SHA" ] || die "binary sha256 $got != pinned $WANT_SHA"
chmod 0755 "$STAGE/ciphervault"
"$STAGE/ciphervault" --version | grep -qx "ciphervault $VERSION" || die "staged CLI is not $VERSION"
log "building $NEW"
docker build -q -f "$STAGE/Dockerfile.dashboard.prebuilt" \
  --build-arg SOURCE_REVISION="$REV" --build-arg BINARY_SHA256="$WANT_SHA" -t "$NEW" "$STAGE" >/dev/null
log "image $(docker image inspect "$NEW" --format '{{.Id}}')"

running="$(docker inspect "$(compose ps -q $SVC)" --format '{{.Config.Image}}')"
cp -a "$ENVF" "$ENVF.bak-$TS"
log "rollback image (live): $running; .env backup $ENVF.bak-$TS"

rollback() {
  log "ROLLBACK to $running"
  cp -a "$ENVF.bak-$TS" "$ENVF"
  CIPHERVAULT_DASHBOARD_IMAGE="$running" compose up -d --no-deps "$SVC" >/dev/null 2>&1 || true
}
trap 'rc=$?; [ $rc -eq 0 ] || rollback; exit $rc' EXIT

sed -i "s|^CIPHERVAULT_DASHBOARD_IMAGE=.*|CIPHERVAULT_DASHBOARD_IMAGE=${NEW}|" "$ENVF"
grep -q "^CIPHERVAULT_DASHBOARD_IMAGE=${NEW}$" "$ENVF" || die ".env pin not written"
compose up -d --no-deps "$SVC" >/dev/null
ok=0
for i in $(seq 1 24); do
  sleep 5
  if check_live "$VERSION"; then ok=1; break; fi
done
[ "$ok" = 1 ] || die "dashboard did not serve $VERSION"
trap - EXIT
log "DONE: dashboard on $NEW. Rollback: cp $ENVF.bak-$TS $ENVF && CIPHERVAULT_DASHBOARD_IMAGE=$running docker compose --project-directory $DIR up -d --no-deps $SVC"
