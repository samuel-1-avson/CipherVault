#!/bin/bash
set -euo pipefail

echo "Setting up CipherVault Web Dashboard configuration..."
mkdir -p /opt/ciphervault-ui/caddy_data /opt/ciphervault-ui/caddy_config

# 1. Setup Caddyfile
cat << 'EOF' > /opt/ciphervault-ui/Caddyfile
{
    admin off
    email samuelavson360@gmail.com
}

(security_headers) {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }
}

vault.cipherv.online, cipherv.online {
    import security_headers
    encode zstd gzip

    reverse_proxy 127.0.0.1:8080 {
        header_up Host {host}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
        flush_interval -1
        transport http {
            keepalive 60s
        }
    }
}
EOF

# 2. Setup Compose & Env
cp /opt/ciphervault-ui/repo/deploy/gcp/docker-compose.web.yml /opt/ciphervault-ui/docker-compose.yml

cat << 'EOF' > /opt/ciphervault-ui/.env
WEB_DOMAIN=vault.cipherv.online
ACME_EMAIL=samuelavson360@gmail.com
CIPHERVAULT_OPERATORS=http://10.128.0.39 http://10.128.0.40 http://10.142.0.2
EOF

# 3. Setup Systemd Service
cat << 'EOF' > /etc/systemd/system/ciphervault-ui.service
[Unit]
Description=CipherVault Web Dashboard and Caddy Reverse Proxy
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

# 4. Open Host Firewall
if command -v ufw &> /dev/null; then
    ufw allow 22/tcp || true
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true
    ufw --force enable || true
fi

echo "SETUP_SUCCESS"
