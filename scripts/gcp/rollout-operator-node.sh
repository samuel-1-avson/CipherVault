#!/usr/bin/env bash
# =============================================================================
# One-node operator promotion from a staged, checksum-pinned binary
# (DEPLOYMENT_RUNBOOK.md R5c). Runs ON the operator box, as root.
#
#   sudo bash rollout-operator-node.sh <stage-dir> <sha256> <version> <build-sha>
#
# <stage-dir> holds `ciphervault-operator` (Linux x86_64) and
# `Dockerfile.operator.prebuilt`. Steps, stopping on the first red check:
#   1. pre-health gate on the local /healthz
#   2. verify the binary SHA-256 and `--version`, build the image
#   3. snapshot compose/.env, tag the running image as the rollback image
#   4. stop the node, back up the whole data dir (stopped = consistent)
#   5. print the transparency-log and witness keys with the new image
#      (creates witness/witness.key on first run; nothing is served)
#   6. retag the new image onto the compose tag, recreate, health-gate,
#      and assert `--version` plus /v1/info binary_version/build_sha
# Any failure after step 4 rolls back to the previous image automatically.
# Secrets are never printed; backups stay on this box.
# =============================================================================
set -euo pipefail

STAGE="${1:?stage dir}"; WANT_SHA="${2:?sha256}"; VERSION="${3:?version}"; BUILD_SHA="${4:?build sha}"
CV=/opt/ciphervault
COMPOSE="$CV/docker-compose.yml"
TAG=ciphervault-operator:gcp
NEW="ciphervault-operator:${VERSION}-${BUILD_SHA}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOCAL=http://127.0.0.1:8201

log() { printf '[rollout %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { log "FAIL: $*"; exit 1; }

wait_ready() {
  local i
  for i in $(seq 1 36); do
    if curl -fsS --max-time 5 "$LOCAL/healthz" 2>/dev/null | grep -q '"status":"ready"'; then
      return 0
    fi
    sleep 5
  done
  return 1
}

operator_id="$(docker inspect ciphervault-operator --format '{{json .Config.Cmd}}' \
  | python3 -c 'import json,sys; c=json.load(sys.stdin); print(c[c.index("--operator-id")+1])')"
log "node $operator_id, target $NEW"

log "1. pre-health"
wait_ready || die "node not ready before the promote"

log "2. verify binary + build image"
got="$(sha256sum "$STAGE/ciphervault-operator" | cut -d' ' -f1)"
[ "$got" = "$WANT_SHA" ] || die "binary sha256 $got != pinned $WANT_SHA"
chmod 0755 "$STAGE/ciphervault-operator"
"$STAGE/ciphervault-operator" --version | grep -qx "ciphervault-operator $VERSION" \
  || die "staged binary is not $VERSION: $("$STAGE/ciphervault-operator" --version)"
docker build -q -f "$STAGE/Dockerfile.operator.prebuilt" -t "$NEW" "$STAGE" >/dev/null
docker run --rm --entrypoint ciphervault-operator "$NEW" --version | grep -qx "ciphervault-operator $VERSION" \
  || die "image does not run $VERSION"
log "image $NEW = $(docker image inspect "$NEW" --format '{{.Id}}')"

log "3. snapshots"
prev_id="$(docker image inspect "$TAG" --format '{{.Id}}')"
prev_ver="$(docker exec ciphervault-operator ciphervault-operator --version | awk '{print $2}')"
ROLLBACK="ciphervault-operator:rollback-${prev_ver}"
docker tag "$TAG" "$ROLLBACK"
cp -a "$COMPOSE" "$COMPOSE.pre-$VERSION-$TS"
cp -a "$CV/.env" "$CV/.env.pre-$VERSION-$TS"
log "rollback image $ROLLBACK = $prev_id"

rollback() {
  log "ROLLBACK to $ROLLBACK"
  docker tag "$ROLLBACK" "$TAG"
  docker compose -f "$COMPOSE" up -d operator >/dev/null 2>&1 || true
  if wait_ready; then log "rolled back and ready on $prev_ver"; else log "ROLLBACK NOT READY: investigate now"; fi
}

log "4. stop + data backup"
docker compose -f "$COMPOSE" stop operator >/dev/null
trap 'rc=$?; [ $rc -eq 0 ] || rollback; exit $rc' EXIT
mkdir -p "$CV/backups"
chmod 0700 "$CV/backups"
tar -C "$CV" -czf "$CV/backups/data-pre-$VERSION-$TS.tgz" data
log "data backup $(du -h "$CV/backups/data-pre-$VERSION-$TS.tgz" | cut -f1) at $CV/backups/data-pre-$VERSION-$TS.tgz"

log "5. log + witness keys (new image, node stopped)"
docker run --rm --user 10001:10001 -v "$CV/data:/var/lib/ciphervault" "$NEW" \
  --data-dir /var/lib/ciphervault --operator-id "$operator_id" --print-log-key | grep -E '^(origin|verifier_key)='
docker run --rm --user 10001:10001 -v "$CV/data:/var/lib/ciphervault" "$NEW" \
  --data-dir /var/lib/ciphervault --operator-id "$operator_id" --print-witness-key | sed 's/^/witness_/'

log "6. promote"
docker tag "$NEW" "$TAG"
docker compose -f "$COMPOSE" up -d operator >/dev/null
wait_ready || die "new image never became ready"
reported="$(docker exec ciphervault-operator ciphervault-operator --version)"
[ "$reported" = "ciphervault-operator $VERSION" ] || die "running $reported"
info="$(curl -fsS --max-time 10 "$LOCAL/v1/info")"
echo "$info" | python3 -c '
import json,sys
i=json.load(sys.stdin); v,s=sys.argv[1],sys.argv[2]
print("v1/info binary_version=%s build_sha=%s operator=%s" % (i.get("binary_version"), i.get("build_sha"), i.get("operator_id")))
sys.exit(0 if i.get("binary_version")==v and i.get("build_sha")==s else 1)' "$VERSION" "$BUILD_SHA" \
  || die "/v1/info does not report $VERSION/$BUILD_SHA"
trap - EXIT
log "DONE: $operator_id on $VERSION ($BUILD_SHA). Rollback: docker tag $ROLLBACK $TAG && docker compose -f $COMPOSE up -d operator"
