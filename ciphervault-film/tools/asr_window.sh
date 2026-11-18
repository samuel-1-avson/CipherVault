#!/bin/sh
# Transcribe a window of a finished cut with a chosen Whisper model:  sh tools/asr_window.sh film.mp4 start dur [model]
HERE=$(cd "$(dirname "$0")/.." && pwd); LIB=${LIB:-$HOME/lemo-opuscar}; cd "$HERE"; mkdir -p out/review
ffmpeg -v error -y -ss "$2" -t "$3" -i "$1" -ac 1 -ar 16000 out/review/win.wav
HF_HUB_DISABLE_SYMLINKS_WARNING=1 "$LIB/.venv/bin/python" - "$HERE/out/review/win.wav" "${4:-base.en}" <<'EOF'
import sys
from faster_whisper import WhisperModel
m = WhisperModel(sys.argv[2], device='cpu', compute_type='int8')
segs, _ = m.transcribe(sys.argv[1], beam_size=5, language='en')
print(sys.argv[2], '|', ' '.join(s.text.strip() for s in segs))
EOF
