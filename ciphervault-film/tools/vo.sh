#!/bin/sh
# Voice: Kokoro TTS for every line, then the Whisper check (writes voices/words.json for word-anchored timing).
#   sh tools/vo.sh     (LIB = the Lemo-Opuscar library; default ~/lemo-opuscar)
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd); LIB=${LIB:-$HOME/lemo-opuscar}
export HF_HUB_DISABLE_SYMLINKS_WARNING=1
cd "$LIB"
.venv/bin/python core/tts/tts.py "$HERE/lines.json" "$HERE/voices"
.venv/bin/python core/tts/asr_check.py "$HERE/lines.json" "$HERE/voices" --lang en
