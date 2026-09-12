#!/usr/bin/env bash
# CipherVault — Docker Staging Cluster Verification Drill (Linux / macOS)
# Usage: ./scripts/verify-cluster.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CLI_BIN="${ROOT_DIR}/dist/bin/ciphervault"

echo "======================================================="
echo "  CipherVault Container Cluster Verification Drill"
echo "======================================================="

# 1. Probe the 3 containerized operator endpoints
for port in 8201 8202 8203; do
    echo -n "Probing Operator on port ${port}... "
    info=$(curl -sf "http://127.0.0.1:${port}/v1/info")
    echo "[ONLINE] - ${info}"
done

echo
echo "All 3 container operators are healthy!"
echo "Run complete!"
