#!/usr/bin/env bash
# ==============================================================================
# CipherVault Web Dashboard GCP Provisioner (Linux / macOS)
# ==============================================================================
set -euo pipefail

DOMAIN_NAME="${1:-}"
ACME_EMAIL="${2:-admin@example.com}"
ZONE="${3:-us-central1-a}"
MACHINE_TYPE="e2-micro"
BOOT_DISK_SIZE="20GB"
WEBAUTHN_RP_ID="${WEBAUTHN_RP_ID:-$DOMAIN_NAME}"
WEBAUTHN_ORIGIN="${WEBAUTHN_ORIGIN:-https://$DOMAIN_NAME}"
ACCOUNT_ALLOWED_ORIGINS="${ACCOUNT_ALLOWED_ORIGINS:-$WEBAUTHN_ORIGIN}"

if [ -z "$DOMAIN_NAME" ]; then
    echo "Usage: ./deploy-web-ui.sh <subdomain.domain.com> [acme_email] [zone]"
    echo "Example: ./deploy-web-ui.sh vault.mysecuritydomain.com"
    exit 1
fi

echo "======================================================="
echo "  CipherVault Web Dashboard GCP Provisioner (Bash)     "
echo "======================================================="
echo "Target Domain:  $DOMAIN_NAME"
echo "Machine Type:   $MACHINE_TYPE (GCP Always-Free eligible)"
echo "Zone:           $ZONE"

# 1. Firewall Ingress
if ! gcloud compute firewall-rules describe allow-ciphervault-web-ui &>/dev/null; then
    echo "Creating firewall rule allow-ciphervault-web-ui..."
    gcloud compute firewall-rules create allow-ciphervault-web-ui \
        --allow=tcp:80,tcp:443 \
        --target-tags=ciphervault-web-ui \
        --description="Allow public HTTP/HTTPS ingress for CipherVault Web Dashboard" \
        --quiet
fi

# 2. Provision VM
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STARTUP_PATH="$SCRIPT_DIR/../../deploy/gcp/startup-web.sh"

INSTANCE_NAME="cv-web-ui"
if ! gcloud compute instances describe "$INSTANCE_NAME" --zone="$ZONE" &>/dev/null; then
    echo "Provisioning new VM $INSTANCE_NAME..."
    gcloud compute instances create "$INSTANCE_NAME" \
        --zone="$ZONE" \
        --machine-type="$MACHINE_TYPE" \
        --image-family=ubuntu-2404-lts-amd64 \
        --image-project=ubuntu-os-cloud \
        --boot-disk-size="$BOOT_DISK_SIZE" \
        --boot-disk-type="pd-balanced" \
        --tags="ciphervault-web-ui,http-server,https-server" \
        --metadata-from-file="startup-script=$STARTUP_PATH" \
        --metadata="web-domain=$DOMAIN_NAME,acme-email=$ACME_EMAIL,webauthn-rp-id=$WEBAUTHN_RP_ID,webauthn-origin=$WEBAUTHN_ORIGIN,account-allowed-origins=$ACCOUNT_ALLOWED_ORIGINS" \
        --quiet
else
    echo "Updating existing VM metadata..."
    gcloud compute instances add-metadata "$INSTANCE_NAME" \
        --zone="$ZONE" \
        --metadata="web-domain=$DOMAIN_NAME,acme-email=$ACME_EMAIL,webauthn-rp-id=$WEBAUTHN_RP_ID,webauthn-origin=$WEBAUTHN_ORIGIN,account-allowed-origins=$ACCOUNT_ALLOWED_ORIGINS" \
        --metadata-from-file="startup-script=$STARTUP_PATH" \
        --quiet
fi

# 3. Retrieve Public IP
EXTERNAL_IP=$(gcloud compute instances describe "$INSTANCE_NAME" \
    --zone="$ZONE" \
    --format="value(networkInterfaces[0].accessConfigs[0].natIP)")

echo "======================================================="
echo "           GODADDY DNS CONFIGURATION GUIDE              "
echo "======================================================="
echo "Add an 'A' Record in your GoDaddy DNS settings:"
echo "  Type:  A"
echo "  Name:  $(echo "$DOMAIN_NAME" | cut -d'.' -f1)"
echo "  Value: $EXTERNAL_IP"
echo "  TTL:   1/2 Hour (or 600s)"
echo ""
echo "Once saved, access your dashboard securely at:"
echo "  https://$DOMAIN_NAME"
echo "======================================================="
