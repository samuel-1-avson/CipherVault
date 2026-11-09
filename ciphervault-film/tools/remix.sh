#!/bin/sh
# Audio-only rebuild (picture unchanged): re-export cues, re-score, re-master onto the existing out/video_<cut>.mp4.
#   sh tools/remix.sh [F|H]
set -e
LIB=${LIB:-$HOME/lemo-opuscar}; export LIB
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
for C in ${1:-F H}; do
  [ "$C" = F ] && NAME=ciphervault-film || NAME=ciphervault-film-90s
  node tools/render.mjs export --q cut=$C --out out/events_$C.json --subs out/subs_$C.json
  "$LIB/.venv/bin/python" sound.py $C
  sh "$LIB/core/render/mux.sh" out/video_$C.mp4 out/mix_$C.wav $NAME.mp4 30 0
  "$LIB/.venv/bin/python" "$LIB/core/render/srt.py" out/subs_$C.json $NAME.srt
done
