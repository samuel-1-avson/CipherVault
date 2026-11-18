#!/bin/sh
# CipherVault — "Sealed": rebuild both cuts from source.
#   sh build.sh [--vo] [F|H]     (--vo re-synthesises and re-checks the voice; default builds both cuts)
# Needs the Lemo-Opuscar library with its core, voice and music tiers and the salamander, karoryfer, vcsl and
# freepats sample packs (sh $LIB/plugin/skills/lemo-opuscar/scripts/setup.sh deps voice music;
# sh $LIB/tools/fetch.sh instruments <lib>), Node 20+, ffmpeg 7+.
set -e
LIB=${LIB:-$HOME/lemo-opuscar}; export LIB
HERE=$(cd "$(dirname "$0")" && pwd); cd "$HERE"
PY="$LIB/.venv/bin/python"
[ -f "$LIB/core/render/mux.sh" ] || { echo "set LIB to the Lemo-Opuscar library folder"; exit 1; }
sh tools/fonts.sh
if [ "$1" = "--vo" ]; then sh tools/vo.sh; shift; elif [ ! -f voices/L01.wav ]; then sh tools/vo.sh; fi   # voice takes are not in git
CUTS=${1:-"F H"}
for C in $CUTS; do
  [ "$C" = F ] && NAME=ciphervault-film || NAME=ciphervault-film-90s
  node tools/render.mjs export --q cut=$C --out out/events_$C.json --subs out/subs_$C.json   # DUR + every cue → the mixer
  "$PY" sound.py $C                                                                     # score + foley + voice → out/mix_$C.wav
  node tools/render.mjs video --q cut=$C --fps 30 --workers 5 --out out/video_$C.mp4      # 1920×1080, 30 fps (STYLE.md §5)
  sh "$LIB/core/render/mux.sh" out/video_$C.mp4 out/mix_$C.wav $NAME.mp4 30 0          # two-pass loudnorm −14 LUFS, no grain (vector UI)
  "$PY" "$LIB/core/render/srt.py" out/subs_$C.json $NAME.srt
done
node tools/render.mjs stills --q cut=F\&nosubs=1 --out out/stills --prefix po_ 57.2 && cp out/stills/po_57.2.jpg poster.jpg
echo "built: $(ls -1 ciphervault-film*.mp4 | tr '\n' ' ')"
