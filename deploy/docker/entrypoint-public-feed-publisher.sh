#!/usr/bin/env sh
set -eu

# This worker publishes only signed, verified checkpoint metadata. The private
# signing key is read from the container environment and is never printed.
: "${CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX:?CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX must be configured}"
FEED_OUTPUT="${CIPHERVAULT_PUBLIC_FEED_OUTPUT:-/var/lib/ciphervault-ui/public-checkpoint-feed.json}"
FEED_NETWORK="${CIPHERVAULT_PUBLIC_FEED_NETWORK:-Arbitrum One}"
INTERVAL_SECS="${CIPHERVAULT_PUBLIC_FEED_INTERVAL_SECS:-60}"

echo "Starting CipherVault signed public checkpoint publisher"
echo "Feed output: ${FEED_OUTPUT}"
echo "Publish interval: ${INTERVAL_SECS}s"

while :; do
  if ciphervault publish-public-feed --output "${FEED_OUTPUT}" --network "${FEED_NETWORK}"; then
    echo "Public checkpoint feed refreshed"
  else
    echo "Public checkpoint feed refresh failed; retaining the last valid feed" >&2
  fi
  sleep "${INTERVAL_SECS}"
done
