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
DATABASE_URL=postgres://cluster_admin:secr3t_pass@prod-db.internal:5432/app
STRIPE_SECRET_KEY=sk_live_51M0cluster_token_demo_key
CACHE_REDIS_URL=redis://default:token_cluster@redis.internal:6379
EOF

    cat << 'EOF' > secrets/credentials.json
{
  "service": "ciphervault-cluster",
  "key_id": "AKIAIOSFODNN7CLUSTER",
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
