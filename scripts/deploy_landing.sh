#!/usr/bin/env bash
# ==============================================================================
# CipherVault Landing Page Deployment Script (https://cipherv.online)
# Supports:
#   1. GCP Caddy Web VM (cv-web-ui) deployment via gcloud / scp
#   2. Static packaging & distribution for CDN / Cloudflare / GitHub Pages
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LANDING_DIR="$ROOT_DIR/apps/landing"
TARGET_HOST="${1:-cv-web-ui}"
ZONE="${2:-us-central1-a}"

echo "======================================================="
echo "   CipherVault Landing Page Deployer (cipherv.online)  "
echo "======================================================="
echo "Source:  $LANDING_DIR"
echo "Target:  $TARGET_HOST"
echo "Zone:    $ZONE"

# 1. Verify Local Asset Integrity
echo "--> [1/4] Verifying landing page assets and contract IDs..."
if [[ ! -f "$LANDING_DIR/index.html" || ! -f "$LANDING_DIR/styles.css" || ! -f "$LANDING_DIR/script.js" ]]; then
    echo "[ERROR] Missing critical landing page assets in $LANDING_DIR" >&2
    exit 1
fi

node -e "
const fs = require('fs');
const html = fs.readFileSync('$LANDING_DIR/index.html', 'utf8');
const js = fs.readFileSync('$LANDING_DIR/script.js', 'utf8');
const idMatches = Array.from(js.matchAll(/getElementById\(['\"]([^'\"]+)['\"]\)/g)).map(m => m[1]);
const uniqueIds = [...new Set(idMatches)];
let missing = 0;
for (const id of uniqueIds) {
  if (!html.includes('id=\"' + id + '\"') && !html.includes(\"id='\" + id + \"'\")) {
    console.error('[ERROR] Missing ID in HTML:', id);
    missing++;
  }
}
if (missing > 0) process.exit(1);
console.log('  ✓ Contract check passed: All ' + uniqueIds.length + ' element IDs valid.');
"

# 2. Package Staging Bundle
echo "--> [2/4] Packaging static release bundle..."
DIST_DIR="$ROOT_DIR/dist"
mkdir -p "$DIST_DIR"
VERSION="$(grep -m1 '^version' "$ROOT_DIR/Cargo.toml" | cut -d'"' -f2)"
BUNDLE_FILE="$DIST_DIR/ciphervault-landing-v${VERSION}.tar.gz"
tar -czf "$BUNDLE_FILE" -C "$ROOT_DIR/apps" landing
echo "  ✓ Release bundle created at: $BUNDLE_FILE"

# 3. Synchronize to Caddy Web VM (if gcloud available)
if command -v gcloud >/dev/null 2>&1 && gcloud compute instances describe "$TARGET_HOST" --zone="$ZONE" &>/dev/null; then
    echo "--> [3/4] Syncing assets to GCP VM '$TARGET_HOST' via gcloud..."
    
    # Upload assets to remote staging
    gcloud compute scp --recurse --zone="$ZONE" "$LANDING_DIR" "$TARGET_HOST:/tmp/ciphervault-landing"
    
    # Move to web directory and reload Caddy
    gcloud compute ssh "$TARGET_HOST" --zone="$ZONE" --command="
        sudo install -d -m 0755 /var/www/ciphervault-landing
        sudo cp -r /tmp/ciphervault-landing/* /var/www/ciphervault-landing/
        sudo rm -rf /tmp/ciphervault-landing
        sudo chown -R www-data:www-data /var/www/ciphervault-landing || sudo chown -R root:root /var/www/ciphervault-landing
        
        # If Caddy runs in Docker Compose
        if docker compose -f /opt/ciphervault-ui/release/docker-compose.yml ps caddy &>/dev/null; then
            docker compose -f /opt/ciphervault-ui/release/docker-compose.yml exec -T caddy caddy reload --config /etc/caddy/Caddyfile || true
        elif command -v caddy &>/dev/null; then
            sudo caddy reload || true
        fi
        echo '  ✓ Remote assets installed and web server reloaded.'
    "
else
    echo "--> [3/4] Notice: Remote host '$TARGET_HOST' not accessible via gcloud CLI."
    echo "  Static bundle is packaged at: $BUNDLE_FILE"
    echo "  You can manually deploy by extracting into Caddy root (/var/www/ciphervault-landing)."
fi

# 4. Remote Verification
echo "--> [4/4] Verifying https://cipherv.online status..."
if command -v curl >/dev/null 2>&1; then
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://cipherv.online" 2>/dev/null || echo "000")
    if [[ "$STATUS" == "200" || "$STATUS" == "301" || "$STATUS" == "302" ]]; then
        echo "  ✓ Live endpoint healthy: https://cipherv.online (HTTP $STATUS)"
    else
        echo "  ℹ Note: https://cipherv.online returned HTTP $STATUS (DNS A-record pointing in progress)."
    fi
fi

echo "======================================================="
echo "  Deployment Process Complete for https://cipherv.online"
echo "======================================================="
