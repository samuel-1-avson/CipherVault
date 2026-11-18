#!/bin/sh
# Review a finished cut: contact sheet (a frame every 4 s), duration, black frames, loudness, Whisper on the final mix.
#   sh tools/review.sh ciphervault-film.mp4
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd); LIB=${LIB:-$HOME/lemo-opuscar}; cd "$HERE"
F=$1; N=$(basename "$F" .mp4); mkdir -p out/review
ffprobe -v error -show_entries format=duration:stream=codec_name,width,height,r_frame_rate -of compact "$F"
rm -f out/review/${N}_*.jpg
ffmpeg -v error -i "$F" -vf "fps=1/4,scale=480:-1" out/review/${N}_%03d.jpg
"$LIB/.venv/bin/python" "$LIB/core/render/sheet.py" out/review/${N}_sheet.jpg $(ls out/review/${N}_[0-9]*.jpg) --cols 6 --w 320
echo "--- black frames (none expected except the final fade):"
ffmpeg -v info -i "$F" -vf "blackdetect=d=0.25:pix_th=0.06" -an -f null - 2>&1 | grep -o "black_start[^ ]* black_end[^ ]* black_duration[^ ]*" || echo "none"
echo "--- loudness:"
ffmpeg -v info -i "$F" -af ebur128 -f null - 2>&1 | grep -E "^\s+(I|LRA|Peak):" | head -3
echo "--- whisper on the final mix:"
ffmpeg -v error -y -i "$F" -ac 1 -ar 16000 out/review/${N}.wav
HF_HUB_DISABLE_SYMLINKS_WARNING=1 "$LIB/.venv/bin/python" - "$HERE/out/review/${N}.wav" <<'EOF'
import sys
from faster_whisper import WhisperModel
m = WhisperModel('base.en', device='cpu', compute_type='int8')
segs, _ = m.transcribe(sys.argv[1], beam_size=5, language='en')
for s in segs: print(f"{s.start:7.2f} {s.end:7.2f} {s.text.strip()}")
EOF
