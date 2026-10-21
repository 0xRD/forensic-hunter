#!/usr/bin/env bash
# Downloads public sample logs used by the worked examples. Nothing is
# committed to the repository.
#
#   fetch-samples.sh [DIR]     (default: ./samples)
#
# - EVTX-ATTACK-SAMPLES by @sbousseaden (GPL-3.0):
#   https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
#   Pinned to a commit (git verifies object hashes).
set -euo pipefail
DIR="${1:-samples}"
REPO="https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES"
COMMIT="${EVTX_ATTACK_SAMPLES_COMMIT:-4ceed2f4706daf601c212a8f91c113dd85349a2c}"
mkdir -p "$DIR"
if [ ! -d "$DIR/EVTX-ATTACK-SAMPLES/.git" ]; then
  git clone --quiet --depth 1 "$REPO" "$DIR/EVTX-ATTACK-SAMPLES"
fi
if [ -n "$COMMIT" ]; then
  git -C "$DIR/EVTX-ATTACK-SAMPLES" fetch --quiet --depth 1 origin "$COMMIT"
  git -C "$DIR/EVTX-ATTACK-SAMPLES" checkout --quiet "$COMMIT"
fi
echo "EVTX-ATTACK-SAMPLES at $(git -C "$DIR/EVTX-ATTACK-SAMPLES" rev-parse HEAD) (GPL-3.0, not redistributed)"
find "$DIR/EVTX-ATTACK-SAMPLES" -name '*.evtx' | wc -l | xargs echo "evtx files:"
