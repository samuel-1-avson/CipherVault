#!/usr/bin/env bash
# NAT hole-punch drill runner (DON Phase 2 exit gate).
#
# Builds the operator image, places a relay/rendezvous seed and two operators
# on isolated bridge networks, proves the isolation, reserves a relay circuit
# for operator B, and has operator A dial B's circuit address and run an
# operator RPC over it. Exits 0 with a PASS summary, non-zero with the failing
# step and the last 30 log lines of the relevant container.
#
# Usage: bash scripts/drill/nat-holepunch.sh [--keep]
#   --keep  leave containers and networks behind for debugging (default: clean up)
#
# First run takes a while: the image build compiles the release binary.
set -euo pipefail

KEEP=0
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

IMAGE="ciphervault-operator:drill"
NET_A="op-net-a"
NET_B="op-net-b"
SEED="drill-seed"
OP_A="drill-a"
OP_B="drill-b"
TOKEN="drill-token"

fail() {
    echo "DRILL FAIL: $*" >&2
    exit 1
}

wait_for_log() {
    # wait_for_log <container> <fixed-string> <timeout-secs>
    local name="$1" pattern="$2" timeout="$3" waited=0
    while ! docker logs "$name" 2>&1 | grep -qF "$pattern"; do
        if docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q false; then
            echo "--- $name exited early; last 30 lines ---" >&2
            docker logs "$name" 2>&1 | tail -30 >&2
            return 1
        fi
        sleep 2
        waited=$((waited + 2))
        if [ "$waited" -ge "$timeout" ]; then
            echo "--- timeout after ${timeout}s waiting for [$pattern]; last 30 lines ---" >&2
            docker logs "$name" 2>&1 | tail -30 >&2
            return 1
        fi
    done
}

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        echo "--keep: leaving containers and networks behind"
        return
    fi
    docker rm -f "$OP_A" "$OP_B" "$SEED" >/dev/null 2>&1 || true
    docker network rm "$NET_A" "$NET_B" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> build $IMAGE"
docker build -t "$IMAGE" -f deploy/docker/Dockerfile.operator .

echo "==> networks"
docker network create "$NET_A" >/dev/null 2>&1 || true
docker network create "$NET_B" >/dev/null 2>&1 || true
docker rm -f "$OP_A" "$OP_B" "$SEED" >/dev/null 2>&1 || true

echo "==> seed (relay + rendezvous, multi-homed)"
docker run -d --name "$SEED" --network "$NET_A" \
    -e CIPHERVAULT_OPERATOR_SERVICE_TOKEN="$TOKEN" \
    -e CIPHERVAULT_SWARM_DEBUG=1 \
    "$IMAGE" --operator-id drill-seed --data-dir /data --port 8201 \
    --enable-p2p --p2p-tcp-port 9101 --p2p-quic-port 9102 \
    --p2p-relay-server --p2p-rendezvous-server \
    --p2p-advertise-addr /dns/drill-seed/tcp/9101 >/dev/null
docker network connect "$NET_B" "$SEED"
wait_for_log "$SEED" "P2P Peer ID:" 60 || fail "seed never booted"
wait_for_log "$SEED" "StatusChanged" 90 || fail "relay HOP never enabled (need advertise-addr/AutoNAT)"
SEED_PEER=$(docker logs "$SEED" 2>&1 | grep -F "P2P Peer ID:" | head -1 | awk '{print $NF}')
[ -n "$SEED_PEER" ] || fail "could not parse seed peer ID"
SEED_ADDR="/dns/drill-seed/tcp/9101/p2p/$SEED_PEER"
echo "    seed peer: $SEED_PEER"

echo "==> operator B (bootstrap + relay reservation)"
docker run -d --name "$OP_B" --network "$NET_B" \
    -e CIPHERVAULT_OPERATOR_SERVICE_TOKEN="$TOKEN" \
    -e CIPHERVAULT_SWARM_DEBUG=1 \
    "$IMAGE" --operator-id drill-b --data-dir /data --port 8201 \
    --enable-p2p --p2p-bootstrap "$SEED_ADDR" --p2p-relay-reserve "$SEED_ADDR" >/dev/null
wait_for_log "$OP_B" "P2P relay circuit:" 90 || fail "B never reserved a circuit"
B_PEER=$(docker logs "$OP_B" 2>&1 | grep -F "P2P Peer ID:" | head -1 | awk '{print $NF}')
B_CIRCUIT=$(docker logs "$OP_B" 2>&1 | grep -F "P2P relay circuit:" | head -1 | awk '{print $NF}')
[ -n "$B_PEER" ] || fail "could not parse B peer ID"
[ -n "$B_CIRCUIT" ] || fail "could not parse B circuit addr"
echo "    B peer: $B_PEER"
echo "    B circuit: $B_CIRCUIT"

echo "==> operator A (bootstrap seed + B circuit, probe B)"
docker run -d --name "$OP_A" --network "$NET_A" \
    -e CIPHERVAULT_OPERATOR_SERVICE_TOKEN="$TOKEN" \
    -e CIPHERVAULT_SWARM_DEBUG=1 \
    "$IMAGE" --operator-id drill-a --data-dir /data --port 8201 \
    --enable-p2p --p2p-bootstrap "$SEED_ADDR" --p2p-bootstrap "$B_CIRCUIT" \
    --p2p-probe-peer "$B_PEER" >/dev/null
wait_for_log "$OP_A" "Listening on:" 60 || fail "A never booted"

echo "==> isolation probes (from A: seed reachable, B unreachable)"
docker exec "$OP_A" curl -fsS http://drill-seed:8201/healthz >/dev/null \
    || fail "A cannot reach the seed HTTP"
B_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$OP_B")
[ -n "$B_IP" ] || fail "could not read B container IP"
if docker exec "$OP_A" curl -fsS -m 5 "http://$B_IP:8201/healthz" >/dev/null 2>&1; then
    fail "A REACHES B directly ($B_IP) — networks not isolated, drill proves nothing"
fi
echo "    isolation holds (A cannot reach $B_IP)"

echo "==> relayed RPC gate"
wait_for_log "$OP_A" "P2P probe $B_PEER: OK operator=drill-b" 120 \
    || fail "probe RPC never succeeded"
docker logs "$SEED" 2>&1 | grep -qF "ReservationReqAccepted" \
    || echo "    (note: ReservationReqAccepted line not found in seed logs)"

echo "==> seed kill: static HTTP must survive"
docker kill "$SEED" >/dev/null
sleep 2
docker exec "$OP_A" curl -fsS http://localhost:8201/healthz >/dev/null \
    || fail "A HTTP down after seed kill"
docker exec "$OP_B" curl -fsS http://localhost:8201/healthz >/dev/null \
    || fail "B HTTP down after seed kill"

echo ""
echo "DRILL PASS: relayed operator RPC across isolated networks, static HTTP survives seed loss"
