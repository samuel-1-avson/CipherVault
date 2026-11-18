#!/bin/sh
# Fonts for the film (SIL Open Font License 1.1, named in ../CREDITS), fetched into ../fonts/ from pinned commits.
# Files already there are kept; FORCE=1 fetches them again. build.sh runs this first.
set -e
D=$(cd "$(dirname "$0")/.." && pwd)/fonts; mkdir -p "$D"
GF=https://raw.githubusercontent.com/google/fonts/86aced91de05cd4f96a06838124cca45be337b2b
get() {
  [ -s "$D/$1" ] && [ -z "$FORCE" ] && return 0
  curl -fsSL -g --retry 2 -o "$D/download.part" "$2" ||
    { rm -f "$D/download.part"; echo "could not fetch fonts/$1 from $2" >&2; exit 1; }
  mv "$D/download.part" "$D/$1"; echo "fonts/$1"
}
get Inter.ttf "$GF/ofl/inter/Inter[opsz,wght].ttf"
get JetBrainsMono-var.ttf "https://raw.githubusercontent.com/JetBrains/JetBrainsMono/19371302b95d218af43299bce79ddbddd0bc364d/fonts/variable/JetBrainsMono[wght].ttf"
