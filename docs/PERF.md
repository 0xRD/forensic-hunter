# Performance log

Every optimisation with its measured effect. Machine for numbers below unless
noted: 4-core Intel Xeon @ 2.8 GHz (cloud VM, noisy: expect +-10%), Linux,
release profile (fat LTO, codegen-units=1, mimalloc).
Reference input: `security_big_sample.evtx` (30.1 MiB, 62,031 events) from the
`evtx` crate's samples (not committed; `scripts/fetch-samples.sh`).

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

Profile after P-003 (callgrind, 1 thread): evtx render+IR build ~42%, our
JSON scanner ~34%, jsonl writer ~14%, allocation ~6%.

## Ideas not yet done

- Skip the JSON round trip: map template substitution values
  (`EvtxRecord::template_instances`) to field names once per template and read
  typed values directly. Estimated 2x single-thread; large change.
- Keep JSON-escaped strings borrowed (re-escape on output only when needed)
  to avoid allocating for every Windows path.
