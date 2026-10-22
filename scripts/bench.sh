#!/usr/bin/env bash
# End-to-end benchmarks with hyperfine on a synthetic corpus.
#
#   scripts/bench.sh [--size 2G] [--out bench-results] [--runs 5]
#
# Compares forhunt with, when available:
#   evtx_dump  (omerbenamram/evtx; `cargo install evtx` or $EVTX_DUMP)
#   EvtxECmd   (Eric Zimmerman; needs `dotnet` and $EVTXECMD pointing to EvtxECmd.dll)
#   Hayabusa   (`hayabusa` on PATH or $HAYABUSA; detection work, shown for reference)
# Writes results.md (table: wall time, MiB/s, events/s, peak RSS) and the raw
# hyperfine JSON into the output directory.
set -euo pipefail
SIZE=2G; OUT=bench-results; RUNS=5
while [ $# -gt 0 ]; do
  case "$1" in
    --size) SIZE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
command -v hyperfine >/dev/null || { echo "hyperfine is required (cargo install hyperfine)" >&2; exit 2; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
CORPUS="$ROOT/corpus/bench-$SIZE"

cargo build --release --locked -q -p forhunt -p evtx-gen
FH="$ROOT/target/release/forhunt"
if [ ! -d "$CORPUS" ]; then
  "$ROOT/target/release/evtx-gen" corpus --out "$CORPUS" --size "$SIZE" --file-size 256M --seed 1 2>/dev/null
fi
BYTES=$(find "$CORPUS" -name '*.evtx' -printf '%s\n' | awk '{s+=$1} END {print s}')
EVENTS=$("$FH" stats -q -F json "$CORPUS" | python3 -c 'import json,sys; print(json.load(sys.stdin)["events"])')
CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu)
echo "corpus: $CORPUS ($((BYTES >> 20)) MiB, $EVENTS events), $CORES cores"

EVTX_DUMP="${EVTX_DUMP:-$(command -v evtx_dump || true)}"
HAYABUSA="${HAYABUSA:-$(command -v hayabusa || true)}"
EVTXECMD="${EVTXECMD:-}"

declare -a NAMES CMDS
add() { NAMES+=("$1"); CMDS+=("$2"); }
add "forhunt parse jsonl (all cores)" "$FH parse -q $CORPUS -o /dev/null"
add "forhunt parse jsonl (1 thread)" "$FH parse -q -t 1 $CORPUS -o /dev/null"
add "forhunt parse csv (all cores)" "$FH parse -q -F csv $CORPUS -o /dev/null"
add "forhunt search filtered (all cores)" "$FH search -q $CORPUS -e 4624 -f LogonType=3 -n 0 -F jsonl -o /dev/null"
add "forhunt stats (all cores)" "$FH stats -q $CORPUS -o /dev/null"
add "forhunt timeline jsonl, full sort (all cores)" "$FH timeline -q $CORPUS -F jsonl -n 0 -o /dev/null"
if [ -n "$EVTX_DUMP" ]; then
  add "evtx_dump jsonl (all cores)" "sh -c 'for f in $CORPUS/*.evtx; do $EVTX_DUMP -o jsonl \"\$f\" >/dev/null; done'"
  add "evtx_dump jsonl (1 thread)" "sh -c 'for f in $CORPUS/*.evtx; do $EVTX_DUMP -t 1 -o jsonl \"\$f\" >/dev/null; done'"
fi
if [ -n "$EVTXECMD" ] && command -v dotnet >/dev/null; then
  add "EvtxECmd json" "dotnet $EVTXECMD -d $CORPUS --json $OUT/evtxecmd --jsonf out.json"
fi
if [ -n "$HAYABUSA" ]; then
  add "Hayabusa dfir-timeline jsonl (detections)" "$HAYABUSA dfir-timeline -d $CORPUS -t jsonl -w -q -K -N -C -O -o $OUT/hayabusa.jsonl"
fi

args=()
for i in "${!NAMES[@]}"; do args+=(-n "${NAMES[$i]}" "${CMDS[$i]}"); done
hyperfine -N --warmup 1 --runs "$RUNS" --export-json "$OUT/hyperfine.json" "${args[@]}" 2>&1 | tee "$OUT/hyperfine.txt"

python3 - "$OUT/hyperfine.json" "$BYTES" "$EVENTS" "$CORES" "$SIZE" > "$OUT/results.md" <<'PY'
import json, platform, sys
d = json.load(open(sys.argv[1]))
mib = int(sys.argv[2]) / 2**20
events = int(sys.argv[3])
print(f"Corpus: synthetic `evtx-gen corpus --size {sys.argv[5]}` = {mib:,.0f} MiB, {events:,} events. "
      f"Machine: {platform.machine()}, {sys.argv[4]} cores, {platform.system()}.\n")
print("| Task | Wall time (mean ± σ) | MiB/s | Events/s | Peak RSS |")
print("|---|---|---|---|---|")
for r in d["results"]:
    if "summary" in r:  # hyperfine >= 2
        w = r["summary"]["time_wall_clock"]
        m, s = w["mean"], w.get("stddev") or 0
        rss = r["summary"].get("memory_peak_resident", {}).get("max", 0) / 2**20
    else:  # hyperfine 1.x
        m, s = r["mean"], r.get("stddev") or 0
        rss = max(r.get("memory_usage_byte") or [0]) / 2**20
    name = r.get("name") or r["command"]
    print(f"| {name} | {m:.2f} s ± {s:.2f} | {mib/m:,.0f} | {events/m:,.0f} | {rss:,.0f} MiB |")
PY
cat "$OUT/results.md"
