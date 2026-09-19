#!/usr/bin/env bash
# 10-node chaos drill runner (DON Phase 4 slice 4 exit gate).
#
# Builds the operator image and runs the containerized chaos harness in
# services/operator/tests/chaos.rs: ten nodes on one bridge network, routing
# tables meshed over HTTP, then three gates — kill 3/10 mid-write, a 45s
# partition-heal, and repair bandwidth bounds. Exits 0 with a PASS summary,
# non-zero with the failing gate and container logs left behind (--keep).
#
# Usage: bash scripts/drill/chaos-10node.sh [--keep]
#   --keep  leave containers and networks behind for debugging (default: clean up)
#
# First run takes a while: the image build compiles the release binary, and
# the gates run ~10 minutes against default repair timing (30s interval).
set -euo pipefail

KEEP=0
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

IMAGE="ciphervault-operator:chaos"

echo "==> build $IMAGE"
docker build -t "$IMAGE" -f deploy/docker/Dockerfile.operator .

echo "==> chaos gates (services/operator/tests/chaos.rs)"
export CIPHERVAULT_CHAOS=1
if [ "$KEEP" -eq 1 ]; then
    export CIPHERVAULT_CHAOS_KEEP=1
fi
cargo test --locked -p ciphervault-operator --test chaos -- --ignored --nocapture
