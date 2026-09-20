#!/usr/bin/env bash
# Friendly node onboarding: answers three questions, then starts your
# storage node. Uses the CLI bundled next to this script. Advanced users
# run `ciphervault node setup` after installing to PATH.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$HERE/../bin/ciphervault" node setup
