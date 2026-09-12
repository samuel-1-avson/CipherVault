#!/bin/bash
set -e

OPERATORS=${CIPHERVAULT_OPERATORS:-"http://operator-1:8201 http://operator-2:8202 http://operator-3:8203"}

# If vault is not initialized, initialize and populate sample state
if [ ! -d ".ciphervault" ]; then
    echo "======================================================="
    echo " Initializing Containerized CipherVault & Inspector    "
    echo "======================================================="
    ciphervault init -o $OPERATORS

    mkdir -p secrets
    cat << 'EOF' > secrets/.env.production
APP_ENVIRONMENT=production
INTERNAL_API_ENDPOINT=https://internal-api.cluster.local:8443
CACHE_HOST_URL=rediss://cache.cluster.local:6380
EOF

    cat << 'EOF' > secrets/credentials.json
{
  "service": "ciphervault-cluster",
  "cluster_identifier": "mock-cluster-node-east",
  "region": "us-east-1"
}
EOF

    ciphervault track secrets/.env.production secrets/credentials.json

    echo "Pushing initial encrypted snapshot across operators..."
    ciphervault push -m "Cluster deployment initial configuration" || true

    echo "Anchoring initial snapshot head commitment to Arbitrum..."
    ciphervault anchor || true
fi

echo "======================================================="
echo " Starting CipherVault Web Dashboard on 0.0.0.0:8080    "
echo "======================================================="
exec ciphervault ui --host 0.0.0.0 --port 8080 --no-browser
