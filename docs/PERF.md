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
