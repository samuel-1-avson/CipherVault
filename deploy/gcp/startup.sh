#!/usr/bin/env bash
# ==============================================================================
# CipherVault GCP Compute Engine VPS Automated Startup Script
# ==============================================================================
set -euo pipefail

echo "======================================================="
echo "  Starting CipherVault Operator Provisioning on GCP VPS"
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

# 4. Setup Persistent Storage Layout (chown 10001 for non-root ciphervault container user)
mkdir -p /opt/ciphervault/data
mkdir -p /opt/ciphervault/caddy_data
mkdir -p /opt/ciphervault/caddy_config
chown -R 10001:10001 /opt/ciphervault/data

# 5. Clone / Fetch Repository
echo "Fetching CipherVault repository..."
if [ ! -d "/opt/ciphervault/repo" ]; then
    git clone --depth 1 https://github.com/samuel-1-avson/CipherVault.git /opt/ciphervault/repo
else
    git -C /opt/ciphervault/repo pull || true
fi

# 6. Extract GCP Instance Metadata
HOSTNAME=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/name" 2>/dev/null || hostname)
OPERATOR_ID=${HOSTNAME:-operator-gcp}
echo "Configuring Operator ID: $OPERATOR_ID"

# 7. Build Production Operator Image
echo "Building ciphervault-operator container image..."
cd /opt/ciphervault/repo
docker build -t ciphervault-operator:gcp -f deploy/docker/Dockerfile.operator .

# 8. Setup Production Caddyfile
cat <<'EOF' > /opt/ciphervault/Caddyfile
{
    admin off
    auto_https disable_redirects
}

(operator_security) {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }
    request_body {
        max_size 5MB
    }
}

:80 {
    import operator_security
    reverse_proxy 127.0.0.1:8201 {
        transport http {
            keepalive 30s
        }
    }
}

:443 {
    import operator_security
    tls internal
    reverse_proxy 127.0.0.1:8201 {
        transport http {
            keepalive 30s
        }
    }
}
EOF

# 9. Create & Launch Local Docker Compose Stack
cat <<EOF > /opt/ciphervault/docker-compose.yml
services:
  operator:
    image: ciphervault-operator:gcp
    container_name: ciphervault-operator
    restart: always
    network_mode: host
    environment:
      - CIPHERVAULT_OPERATOR_STRICT_AUTH=\${CIPHERVAULT_OPERATOR_STRICT_AUTH:-true}
      - CIPHERVAULT_OPERATOR_SERVICE_TOKEN=\${CIPHERVAULT_OPERATOR_SERVICE_TOKEN:-}
    command: ["--port", "8201", "--data-dir", "/var/lib/ciphervault", "--operator-id", "$OPERATOR_ID"]
    volumes:
      - /opt/ciphervault/data:/var/lib/ciphervault
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:8201/healthz || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 6
      start_period: 10s

  caddy:
    image: caddy:2-alpine
    container_name: ciphervault-caddy
    restart: always
    network_mode: host
    volumes:
      - /opt/ciphervault/Caddyfile:/etc/caddy/Caddyfile:ro
      - /opt/ciphervault/caddy_data:/data
      - /opt/ciphervault/caddy_config:/config
    depends_on:
      - operator
EOF

cd /opt/ciphervault
docker compose down 2>/dev/null || true
docker compose up -d

echo "======================================================="
echo "✓ CipherVault Operator $OPERATOR_ID is ONLINE on GCP!"
echo "======================================================="
