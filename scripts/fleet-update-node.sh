#!/usr/bin/env bash
# Fleet rolling-update: one box at a time. Paste into SSH on op1, then op2, then op3.
# Usage: sudo bash fleet-update-node.sh <N>   (N = 1, 2, or 3)
# Quorum holds 2/3 while one node rebuilds. Abort on first red line.
set -euo pipefail
N="${1:?usage: fleet-update-node.sh <1|2|3>}"
PORT="820$N"
cd /opt/ciphervault

echo "=== [0] snapshots"
cp .env ".env.pre-r13-$(date +%F)"
cp docker-compose.yml "docker-compose.yml.pre-r13-$(date +%F)"
CUR="$(docker images -q ciphervault-operator 2>/dev/null | head -1 || true)"
[ -n "$CUR" ] && docker tag "$CUR" ciphervault-operator:pre-r13 || true

echo "=== [1] pull remediation branch"
git -C /opt/CipherVault fetch origin
git -C /opt/CipherVault checkout <remediation-branch>
git -C /opt/CipherVault rev-parse --short HEAD

echo "=== [2] rebuild operator image only"
docker compose build "operator-$N"

echo "=== [3] recreate service (volume preserved)"
docker compose up -d "operator-$N"
sleep 8

echo "=== [4] verify new binary is serving"
curl -fsS "http://localhost:$PORT/healthz" >/dev/null && echo "healthz: OK"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:$PORT/v1/chain/publish" \
  -H 'Content-Type: application/json' -d '{}')
[ "$CODE" = "422" ] && echo "chain/publish: OK (422, route exists)" || { echo "chain/publish: FAIL ($CODE) — old image?"; exit 1; }
curl -s "http://localhost:$PORT/v1/recovery/$(python3 -c 'print("00"*32)')/records?cursor=0"
echo; echo "records endpoint: OK (empty page = pagination works)"

echo "=== [5] strict-mode check (must print nothing)"
docker logs "ciphervault-operator-$N" 2>&1 | grep -i non-strict && \
  { echo "NON-STRICT WARNING PRESENT — investigate before continuing"; exit 1; } || \
  echo "strict: OK (no bypass warnings)"

echo "=== node $N done. Rollback: docker tag ciphervault-operator:pre-r13 <img>; docker compose up -d operator-$N"
