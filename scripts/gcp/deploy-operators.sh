#!/usr/bin/env bash
# ==============================================================================
# CipherVault — Google Cloud Platform (GCP) VPS Operator Cluster Provisioner
# ==============================================================================
# Usage:
#   bash scripts/gcp/deploy-operators.sh
# ==============================================================================
set -euo pipefail

PROJECT="${1:-$(gcloud config get-value project 2>/dev/null || echo '')}"
MACHINE_TYPE="${MACHINE_TYPE:-e2-small}"
DISK_SIZE="${DISK_SIZE:-20GB}"
PREFIX="${PREFIX:-cv-operator}"
ZONES=("us-central1-a" "us-central1-b" "us-central1-c")

echo "======================================================="
echo "  CipherVault GCP VPS Storage Operator Provisioner"
echo "======================================================="

if [ -z "$PROJECT" ]; then
    echo "ERROR: No active GCP project configured. Run 'gcloud config set project <ID>'." >&2
    exit 1
fi
echo "Active GCP Project: $PROJECT"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
STARTUP_SCRIPT="$ROOT_DIR/deploy/gcp/startup.sh"

# 1. Cloud Firewall Rule
FIREWALL_RULE="ciphervault-allow-ingress"
echo "Checking firewall rule '$FIREWALL_RULE'..."
if ! gcloud compute firewall-rules list --project="$PROJECT" --filter="name=$FIREWALL_RULE" --format="value(name)" | grep -q "$FIREWALL_RULE"; then
    echo "Creating firewall rule..."
    gcloud compute firewall-rules create "$FIREWALL_RULE" \
        --project="$PROJECT" \
        --direction=INGRESS \
        --priority=1000 \
        --network=default \
        --action=ALLOW \
        --rules=tcp:80,tcp:443 \
        --source-ranges=0.0.0.0/0 \
        --target-tags=ciphervault-operator >/dev/null
    echo "Firewall rule created!"
else
    echo "Firewall rule already exists."
fi

# 2. Provision Compute Engine VPS Instances
ENDPOINTS=()

for i in "${!ZONES[@]}"; do
    NODE_NUM=$((i + 1))
    VM_NAME="$PREFIX-$NODE_NUM"
    ZONE="${ZONES[$i]}"

    echo "Deploying $VM_NAME in zone $ZONE ($MACHINE_TYPE, $DISK_SIZE)..."

    if gcloud compute instances list --project="$PROJECT" --filter="name=$VM_NAME AND zone:$ZONE" --format="value(name)" | grep -q "$VM_NAME"; then
        echo "  Instance $VM_NAME already exists in $ZONE. Reusing."
    else
        gcloud compute instances create "$VM_NAME" \
            --project="$PROJECT" \
            --zone="$ZONE" \
            --machine-type="$MACHINE_TYPE" \
            --network-interface=network-tier=PREMIUM,subnet=default \
            --metadata-from-file="startup-script=$STARTUP_SCRIPT" \
            --tags=ciphervault-operator,http-server,https-server \
            --boot-disk-size="$DISK_SIZE" \
            --boot-disk-type=pd-balanced \
            --image-family=ubuntu-2404-lts-amd64 \
            --image-project=ubuntu-os-cloud >/dev/null
        echo "  ✓ Instance $VM_NAME launched!"
    fi

    EXT_IP=$(gcloud compute instances describe "$VM_NAME" --project="$PROJECT" --zone="$ZONE" --format="value(networkInterfaces[0].accessConfigs[0].natIP)")
    ENDPOINTS+=("https://$EXT_IP")
    echo "  -> External IP: $EXT_IP"
done

echo "======================================================="
echo "  GCP STORAGE OPERATOR CLUSTER PROVISIONED"
echo "======================================================="
echo ""
echo "Ready-to-use CipherVault Client Initialization Command:"
echo "ciphervault init --operators ${ENDPOINTS[*]}"
echo ""
