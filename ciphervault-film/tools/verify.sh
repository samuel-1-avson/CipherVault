#!/bin/sh
# Final checks on both delivered cuts: format, black frames, loudness, Whisper transcript of the final mix.
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
for f in ciphervault-film.mp4 ciphervault-film-90s.mp4; do
  echo "=== $f"
  sh tools/review.sh "$f" 2>&1 | grep -vE '^ +[0-9.]+ +[0-9.]+ +\.$|out/review'
done
