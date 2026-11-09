#!/bin/sh
# Review stills + a contact sheet:  sh tools/stills.sh <prefix> [--q cut=H] t1 t2 …   → out/sheet_<prefix>.jpg
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd); LIB=${LIB:-$HOME/lemo-opuscar}; export LIB
P=$1; shift
Q=""; if [ "$1" = "--q" ]; then Q="--q $2"; shift 2; fi
cd "$HERE"
node tools/render.mjs stills $Q --out out/stills --prefix "${P}_" "$@"
FILES=""; for t in "$@"; do FILES="$FILES $HERE/out/stills/${P}_$t.jpg"; done
"$LIB/.venv/bin/python" "$LIB/core/render/sheet.py" "$HERE/out/sheet_$P.jpg" $FILES --cols 3 --w 640
echo "sheet: $HERE/out/sheet_$P.jpg"
