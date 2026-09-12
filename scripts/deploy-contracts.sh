#!/usr/bin/env bash
# ==============================================================================
# CipherVault Smart Contract Deployer (Linux / macOS)
# ==============================================================================
set -euo pipefail

NETWORK="${1:-arbitrum_sepolia}"
VERIFY="${2:-false}"

echo "=========================================================="
echo "  CipherVault Smart Contract Deployer"
echo "=========================================================="
echo "Target Network: $NETWORK"

if [ "$NETWORK" = "arbitrum_one" ]; then
    RPC_URL="${ARBITRUM_ONE_RPC:-https://arb1.arbitrum.io/rpc}"
    CHAIN_ID=42161
    EXPLORER="https://arbiscan.io"
    VERIFIER_URL="https://api.arbiscan.io/api"
else
    RPC_URL="${ARBITRUM_SEPOLIA_RPC:-https://sepolia-rollup.arbitrum.io/rpc}"
    CHAIN_ID=421614
    EXPLORER="https://sepolia.arbiscan.io"
    VERIFIER_URL="https://api-sepolia.arbiscan.io/api"
fi

echo "RPC Endpoint:   $RPC_URL"
echo "Chain ID:       $CHAIN_ID"

if [ -z "${PRIVATE_KEY:-}" ]; then
    echo -n "Enter deployer private key (0x...): "
    read -s PRIVATE_KEY
    echo
    export PRIVATE_KEY
fi

if [ -z "${PRIVATE_KEY:-}" ]; then
    echo "Error: PRIVATE_KEY is required to sign transactions." >&2
    exit 1
fi

if ! command -v forge &> /dev/null; then
    echo "Warning: Foundry ('forge') is not installed." >&2
    echo "Install with: curl -L https://foundry.paradigm.xyz | bash && foundryup" >&2
    exit 1
fi

echo "Compiling contracts with Foundry..."
forge build

EXTRA_ARGS=()
if [ "$VERIFY" = "true" ] || [ "$VERIFY" = "--verify" ]; then
    if [ -n "${ARBISCAN_API_KEY:-}" ]; then
        EXTRA_ARGS+=(--verify --verifier-url "$VERIFIER_URL" --etherscan-api-key "$ARBISCAN_API_KEY")
    else
        echo "Warning: ARBISCAN_API_KEY not set. Skipping verification." >&2
    fi
fi

echo "Broadcasting deployment transaction to $NETWORK..."
forge script contracts/script/DeployRegistry.s.sol:DeployRegistry \
    --rpc-url "$RPC_URL" \
    --broadcast \
    "${EXTRA_ARGS[@]}"

echo "Deployment complete! Review transaction on $EXPLORER"
echo "Set deployed contract in your environment:"
echo "  export CIPHERVAULT_REGISTRY_CONTRACT=\"0x<DEPLOYED_ADDRESS>\""
