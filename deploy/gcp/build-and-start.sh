#!/bin/bash
set -euo pipefail

echo "Updating Caddyfile configuration..."
cp /opt/ciphervault-ui/repo/deploy/gcp/Caddyfile.web.gcp /opt/ciphervault-ui/Caddyfile

cd /opt/ciphervault-ui/repo

echo "Building ciphervault-ui container image..."
docker build -t ciphervault-ui:gcp -f deploy/docker/Dockerfile.dashboard .

echo "Enabling and starting ciphervault-ui.service..."
systemctl daemon-reload
systemctl enable ciphervault-ui.service
systemctl restart ciphervault-ui.service

echo "Waiting for services to initialize..."
sleep 10

docker compose -f /opt/ciphervault-ui/docker-compose.yml ps
echo "DEPLOY_COMPLETE"

