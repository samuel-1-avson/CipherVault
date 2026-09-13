#!/usr/bin/env bash
# ==============================================================================
# CipherVault Web Dashboard GCP VPS Automated Startup Script
# ==============================================================================
set -euo pipefail

echo "======================================================="
echo "  Starting CipherVault Web Dashboard Provisioning (GCP)"
echo "======================================================="

# 1. Update OS Packages & Prerequisites
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends ca-certificates curl gnupg lsb-release git jq ufw

# 2. Configure Swap Space (Prevents OOM during Rust compilation on small instances)
if [ ! -f /swapfile ]; then
    echo "Configuring 4GB swap space for compilation headroom..."
    fallocate -l 4G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=4096
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# 3. Install Docker Engine if not present
if ! command -v docker &> /dev/null; then
    echo "Installing Docker Engine..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc || \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    DISTRO=$(. /etc/os-release && echo "$ID")
    CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$DISTRO $CODENAME stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

# 4. Setup Directories
mkdir -p /opt/ciphervault-ui
mkdir -p /opt/ciphervault-ui/caddy_data
mkdir -p /opt/ciphervault-ui/caddy_config

# 5. Clone / Fetch Repository
echo "Fetching CipherVault repository..."
if [ ! -d "/opt/ciphervault-ui/repo" ]; then
    git clone --depth 1 https://github.com/samuel-1-avson/CipherVault.git /opt/ciphervault-ui/repo
else
    git -C /opt/ciphervault-ui/repo pull || true
fi

# 6. Extract Custom Domain from GCP Instance Metadata (or fallback)
WEB_DOMAIN=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/web-domain" 2>/dev/null || echo "vault.example.com")
ACME_EMAIL=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/acme-email" 2>/dev/null || echo "admin@example.com")

echo "Configured Web Domain: $WEB_DOMAIN"
echo "Configured ACME Email: $ACME_EMAIL"

# 7. Copy Compose & Caddy configuration
cp /opt/ciphervault-ui/repo/deploy/gcp/docker-compose.web.yml /opt/ciphervault-ui/docker-compose.yml
cp /opt/ciphervault-ui/repo/deploy/gcp/Caddyfile.web.gcp /opt/ciphervault-ui/Caddyfile

# Write environment file
cat <<EOF > /opt/ciphervault-ui/.env
WEB_DOMAIN=${WEB_DOMAIN}
ACME_EMAIL=${ACME_EMAIL}
CIPHERVAULT_OPERATORS=http://10.128.0.39 http://10.128.0.40 http://10.142.0.2
EOF

# 8. Build Production Dashboard Image
echo "Building ciphervault-ui container image..."
cd /opt/ciphervault-ui/repo
docker build -t ciphervault-ui:gcp -f deploy/docker/Dockerfile.dashboard .

# 9. Create and Enable Systemd Service
cat <<'EOF' > /etc/systemd/system/ciphervault-ui.service
[Unit]
Description=CipherVault Web Dashboard & Caddy Reverse Proxy
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=/opt/ciphervault-ui
ExecStart=/usr/bin/docker compose up
ExecStop=/usr/bin/docker compose down
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ciphervault-ui.service

# 10. Configure Host Firewall (Allow 80, 443, 22)
if command -v ufw &> /dev/null; then
    ufw allow 22/tcp || true
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true
    ufw --force enable || true
fi

echo "======================================================="
echo " CipherVault Web Dashboard Provisioning Complete!      "
echo " Listening on ports 80 & 443 with automated TLS.       "
echo "======================================================="
