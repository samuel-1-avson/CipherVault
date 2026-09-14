#!/usr/bin/env bash
set -euo pipefail

# This image hosts the public, read-only explorer. It must not initialize a
# vault or generate/track demonstration files: doing so turns the server's
# state into an apparent visitor vault and leaves misleading sample data on a
# persistent volume. Private vault work belongs in `ciphervault ui --local`.
echo "======================================================="
echo " Starting CipherVault Public Explorer on 0.0.0.0:8080  "
echo "======================================================="
exec ciphervault ui --serve --host 0.0.0.0 --port 8080 --no-browser
