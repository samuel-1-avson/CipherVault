#!/usr/bin/env bash
# ==============================================================================
# CipherVault — Google Cloud Platform (GCP) VPS Operator Cluster Decommissioner
# ==============================================================================
# Usage:
#   bash scripts/gcp/teardown-operators.sh [--delete-firewall]
# ==============================================================================
set -euo pipefail

PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null || echo '')}"
PREFIX="${PREFIX:-cv-operator}"
ZONES=("us-central1-a" "us-central1-b" "us-central1-c")
DELETE_FIREWALL=false

if [ "${1:-}" == "--delete-firewall" ]; then
    DELETE_FIREWALL=true
fi

echo "======================================================="
echo "  CipherVault GCP VPS Storage Operator Teardown"
echo "======================================================="
echo "Active Project: $PROJECT"

for i in "${!ZONES[@]}"; do
    NODE_NUM=$((i + 1))
    VM_NAME="$PREFIX-$NODE_NUM"
    ZONE="${ZONES[$i]}"

    echo -n "Checking $VM_NAME in $ZONE... "
    if gcloud compute instances list --project="$PROJECT" --filter="name=$VM_NAME AND zone:$ZONE" --format="value(name)" | grep -q "$VM_NAME"; then
        echo "Deleting..."
        gcloud compute instances delete "$VM_NAME" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null
        echo "  ✓ Deleted $VM_NAME!"
    else
        echo "[NOT FOUND]"
    fi
done

if [ "$DELETE_FIREWALL" = true ]; then
    echo "Deleting firewall rule ciphervault-allow-ingress..."
    gcloud compute firewall-rules delete ciphervault-allow-ingress --project="$PROJECT" --quiet 2>/dev/null || true
    echo "  ✓ Deleted firewall rule!"
fi

echo "Teardown complete!"
