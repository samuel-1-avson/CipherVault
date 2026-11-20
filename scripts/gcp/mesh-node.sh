#!/usr/bin/env bash
# =============================================================================
# CipherVault fleet routing mesh, target-local (OPERATOR_PLAYBOOKS.md §2).
#
# Runs ON one operator box. Fetches each peer's public, self-signed
# /v1/peers/self descriptor over HTTPS and announces it to THIS node only,
# using this node's own service token. Service tokens are per node on the
# public fleet, so `ciphervault peers --mesh` (one token for every target)
# cannot mesh it; run this on every box instead.
#
#   sudo bash mesh-node.sh https://op2.cipherv.online https://op3.cipherv.online
#
# The token is read from the box .env and passed to curl through a 0600
# header file, so it never appears on a command line, in `ps`, or in output.
# Safe to re-run: an announce replaces the peer's entry with a fresher one.
# From 1.0.38 verified heartbeats keep routes alive, so a mesh is needed
# only after membership changes or a node is down for more than 24 h.
# =============================================================================
set -euo pipefail

ENV_FILE="${CIPHERVAULT_ENV_FILE:-/opt/ciphervault/.env}"
LOCAL="${CIPHERVAULT_LOCAL_OPERATOR:-http://127.0.0.1:8201}"

[ "$#" -ge 1 ] || { echo "usage: mesh-node.sh <peer https url>..." >&2; exit 2; }
[ -r "$ENV_FILE" ] || { echo "cannot read $ENV_FILE (run with sudo)" >&2; exit 1; }

token="$(sed -n 's/^CIPHERVAULT_OPERATOR_SERVICE_TOKEN=//p' "$ENV_FILE" | tail -n 1)"
[ "${#token}" -ge 32 ] || { echo "service token missing or shorter than 32 chars" >&2; exit 1; }

umask 077
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf 'X-CipherVault-Service-Token: %s\n' "$token" > "$work/auth"
unset token

self_id="$(curl -fsS --max-time 10 "$LOCAL/v1/peers/self" | python3 -c 'import json,sys; print(json.load(sys.stdin)["operator_id"])')"
echo "local node: $self_id ($LOCAL)"

failures=0
for peer in "$@"; do
  peer="${peer%/}"
  if ! curl -fsS --max-time 15 "$peer/v1/peers/self" -o "$work/desc.json"; then
    echo "FAIL fetch $peer/v1/peers/self"; failures=$((failures + 1)); continue
  fi
  pid="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["operator_id"], d["signing_pk_hex"][:16])' "$work/desc.json")"
  code="$(curl -sS --max-time 15 -o "$work/resp" -w '%{http_code}' \
    -H @"$work/auth" -H 'Content-Type: application/json' \
    --data-binary @"$work/desc.json" "$LOCAL/v1/peers/announce")"
  if [ "$code" = "200" ]; then
    echo "OK   announced $pid from $peer"
  else
    echo "FAIL announce $pid from $peer: HTTP $code $(head -c 300 "$work/resp")"
    failures=$((failures + 1))
  fi
done

echo "--- routing membership on $self_id"
if curl -fsS --max-time 10 -H @"$work/auth" "$LOCAL/v1/peers/membership" -o "$work/members.json"; then
  python3 -c 'import json,sys
for v in json.load(open(sys.argv[1])):
    print("  %-16s %-10s key=%s last_seen=%s" % (v["operator_id"], v["status"], v["signing_pk_hex"][:16], v.get("last_seen_utc")))' "$work/members.json"
else
  echo "  (membership listing unavailable on this build)"
fi
[ "$failures" -eq 0 ] || { echo "$failures announce(s) failed" >&2; exit 1; }
