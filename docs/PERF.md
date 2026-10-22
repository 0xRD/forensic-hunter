# Performance log

Every optimisation with its measured effect. Machine for numbers below unless
noted: 4-core Intel Xeon @ 2.8 GHz (cloud VM, noisy: expect +-10%), Linux,
release profile (fat LTO, codegen-units=1, mimalloc).
Reference input: `security_big_sample.evtx` (30.1 MiB, 62,031 events) from the
`evtx` crate's samples (not committed; `skill/scripts/fetch-samples.sh`).

## Baselines

| Tool | Threads | Wall time | Throughput |
|------|---------|-----------|------------|
| `evtx_dump -o jsonl` (evtx 0.12.3) | 1 | 117 ms | 257 MiB/s |
| `evtx_dump -o jsonl` | 4 | 57 ms | 528 MiB/s |
| evtx public chunk API, render to JSON only (probe) | 1 | 107 ms | 281 MiB/s |

## Log

| # | Change | Before | After | Gain |
|---|--------|--------|-------|------|
| P-001 | First end-to-end `forhunt parse` (jsonl), serde visitor decoder | - | 320 ms (1 t), 130 ms (4 t) | baseline |
| P-002 | Hand-written JSON scanner instead of serde visitors; UTF-8 validated once per record | 2.78 G instr | 2.92 G instr (memchr per string costs more instructions) | none on wall time: decode was not dominated by serde dispatch |
| P-003 | SWAR search for `"`/`\` instead of `memchr2` per string (strings are short) | 2.92 G instr, 313 ms | 2.39 G instr, 288 ms (1 t), 93 ms (4 t) | -18% instructions, -8% wall |

| P-004 | Positional reads instead of mmap (D-021); 2 GiB corpus, 4 threads | 4.21 s, 2.0 GiB RSS | same speed, 25 MiB RSS | memory bounded |
| P-005 | Fast path: template plans + direct value decoding, nested EventData (D-022) | 290 ms (1 t, security_big_sample) | 166 ms | 1.75x |
| P-006 | Fast path value formatting without `fmt` (itoa, hex tables, ASCII UTF-16 fast path) | 1.52 G instr, 166 ms | 1.33 G instr, 153 ms | -12% instructions |
| P-007 | Per-record template lookup by linear scan; cheap hash for the plan cache (bytes compared on hit) | SipHash 8% of instructions | removed | ~-8% instructions |

| P-008 | Plan cache keyed by a canonical template form (names resolved, offsets dropped), so plans are reused across chunks; per-chunk payload plan lookup | 1.33 G instr (real), 757 M (synthetic slice) | 1.15 G, 679 M | -13% / -10% |
| P-009 | Value text built in a byte buffer (validated once per record), two-digit itoa, reused per-thread chunk read buffer (no 64 KiB zeroing) | 1.15 G instr, 153 ms | 1.04 G instr, 134 ms (1 t), 45 ms (4 t) | -10% |

Cumulative on security_big_sample, 1 thread: 2.78 G -> 1.04 G instructions,
320 ms -> 134 ms. All cores: 130 ms -> 45 ms (evtx_dump: 57 ms with 4 threads).

All cores, security_big_sample after P-007: 50 ms (608 MiB/s) vs evtx_dump 57 ms.

Profile after P-003 (callgrind, 1 thread): evtx render+IR build ~42%, our
JSON scanner ~34%, jsonl writer ~14%, allocation ~6%.

## Ideas not yet done

- Fast path coverage: UserData payloads, unnamed `<Data>` and ANSI strings
  still use the JSON path (45-60% of chunks in public attack samples are fast).
- Timeline full sort is bound by the single consumer thread; sort runs per
  unit in the workers and merge.
- Keep JSON-escaped strings borrowed (re-escape on output only when needed)
  to avoid allocating for every Windows path.

## P-010 — event-id pre-check before value decoding (2026-10-22)

The fast path decoded every substitution value (timestamps, GUIDs, SIDs,
strings) before the filter saw the event, so `search -e ...` paid the full
decode cost for records it then dropped. The EventID is now read straight
from the record bytes (integer substitution or template text) and offered to
the sink (`Sink::want_event_id`) first.

256 MiB synthetic Security log, 1 thread: `search -e 99999` 0.57 s -> 0.23 s;
`search -e 4688,4625` 0.23 s. Output is unchanged (checked against
`--slow-decoder`, which does not use the pre-check).

Known gap: on the synthetic corpus `evtx_dump -t 1 -o jsonl` is ~1.6x faster
than `forhunt parse -t 1` (Security 256 MiB: 0.49 s vs 0.81 s), although all
chunks take the fast path. forhunt builds the normalised event (field map,
stable id, source path) and writes it through the filter/writer pipeline;
profiling shows `decode_value` (~35% with its allocations) and record
scanning as the main costs. With all cores the gap is ~10% (1.87 s vs
1.70 s on 2 GiB). Next step: decode values lazily, only for fields the
writer or filter reads.

## P-011 — NTFS sources (2026-10-22)

Synthetic volume: `evtx-gen ntfs-corpus --records 1000000` = 976 MiB `$MFT`
(1M records, ~8% directories, 5% deleted) and a 170 MiB `$J` (2M records).
4 cores, hyperfine, 3 runs.

| Task | Wall time | Peak RSS |
|---|---|---|
| `parse $MFT` jsonl, all cores (4.0M events) | 2.19 s ± 0.23 | 94 MiB |
| `parse $MFT` jsonl, 1 thread | 7.31 s ± 0.42 | 47 MiB |
| `parse $MFT` csv, all cores | 5.28 s (1 run) | |
| `parse $J` jsonl, all cores (2.0M events; includes the sibling `$MFT` path table) | 0.80 s ± 0.10 | 118 MiB |
| `search` both, `-c UsnJrnl -e 2` | 0.53 s ± 0.07 | 157 MiB |
| `timeline` both, one-day window | 0.75 s (1 run) | |
| `timeline` both, full sort of 6.0M events | 41.9 s (1 run) | |
| `mft_dump -o csv` (mft 0.7.0, one row per record, 1 thread) | 16.2 s (1 run) | |

- The directory path table is built by a parallel pre-pass that decodes only
  directory records (~0.3 s for 1M records), then every path is one lookup.
- Every event of a record borrows text built once per record (paths, the
  eight timestamps, flags); per-event cost is the field list and the writer.
- Profile of a no-match search: timestamp formatting (12%) and the filter;
  `--field Name~text` now finds candidates with `memchr2` on the needle's
  first byte instead of comparing every window (no-match search, 1 thread:
  3.81 s -> 2.88 s; benefits EVTX searches too).
- Full-sort timelines of millions of MFT events are slow (spill to disk of
  ~1 KB events); timelines are meant for windows. Lazy timestamp fields
  (formatted only when written) would cut both costs: next step.

## Perf gate fix (2026-10-22)

The CI gate reported ~13M instructions for parse + search + stats: the
rust-cache restore had left `target/bench-gate/corpus` as an empty directory,
so the corpus was never regenerated and the gate measured start-up only. The
NTFS commit then "regressed" by +5.3% (larger field map to parse at start-up,
~0.6M instructions). `bench-gate.sh` now checks the corpus by content and
refuses to compare without it. With the corpus: 2.249G instructions, NTFS
changes within +0.3% of the commit before them.
