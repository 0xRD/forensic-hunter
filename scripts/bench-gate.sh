#!/usr/bin/env bash
# Performance regression gate: counts the instructions `forhunt` executes on a
# fixed synthetic corpus (valgrind/callgrind, single thread) for the current
# checkout and a base revision, and fails if the current one is more than
# THRESHOLD_PCT percent slower. Instruction counts are stable on shared CI
# runners, unlike wall-clock time.
#
# usage: scripts/bench-gate.sh [BASE_REV]
set -euo pipefail

THRESHOLD_PCT="${THRESHOLD_PCT:-3}"
BASE="${1:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$ROOT/target/bench-gate}"
mkdir -p "$WORK"
cd "$ROOT"

command -v valgrind >/dev/null || { echo "valgrind is required" >&2; exit 2; }

# Deterministic input: ~32 MiB of synthetic logs.
if [ ! -d "$WORK/corpus" ]; then
  cargo run --release --locked -q -p evtx-gen -- corpus --out "$WORK/corpus" --size 32M --file-size 16M --seed 7 >/dev/null
fi

count() { # binary label
  local out="$WORK/$2.callgrind"
  local total=0
  for args in "parse -q -t 1 -o /dev/null $WORK/corpus" \
              "search -q -t 1 -o /dev/null -e 4624,4688 -f LogonType=3 $WORK/corpus" \
              "stats -q -t 1 -o /dev/null $WORK/corpus"; do
    # shellcheck disable=SC2086
    valgrind --tool=callgrind --callgrind-out-file="$out" "$1" $args 2>"$WORK/$2.log" >/dev/null
    local n
    n=$(grep -E '^summary:' "$out" | awk '{print $2}')
    total=$((total + n))
  done
  echo "$total"
}

cargo build --release --locked -q -p forhunt
cp target/release/forhunt "$WORK/forhunt-head"
HEAD_N=$(count "$WORK/forhunt-head" head)
echo "head: $HEAD_N instructions"

if [ -z "$BASE" ] || ! git cat-file -e "$BASE^{commit}" 2>/dev/null; then
  echo "no base revision to compare with; recording head only"
  exit 0
fi

rm -rf "$WORK/base-src"
git worktree add -f --detach "$WORK/base-src" "$BASE" >/dev/null 2>&1
trap 'git worktree remove --force "$WORK/base-src" >/dev/null 2>&1 || true' EXIT
if ! (cd "$WORK/base-src" && cargo build --release -q -p forhunt --target-dir "$WORK/base-target" 2>/dev/null); then
  echo "base revision does not build forhunt; skipping comparison"
  exit 0
fi
BASE_N=$(count "$WORK/base-target/release/forhunt" base)
echo "base: $BASE_N instructions ($BASE)"

python3 - "$BASE_N" "$HEAD_N" "$THRESHOLD_PCT" <<'PY'
import sys
base, head, thr = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
delta = (head - base) * 100.0 / base
print(f"change: {delta:+.2f}% (threshold +{thr}%)")
if delta > thr:
    print("performance regression detected", file=sys.stderr)
    sys.exit(1)
PY
