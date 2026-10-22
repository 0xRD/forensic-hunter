# Status

Last update: 2026-10-21 (session 1)

## Done
- Spec review, PLAN.md, DECISIONS.md (D-001..D-024), BLOCKERS.md (B-001..B-004)
- forhunt-core: event model, Artifact/Source traits, EVTX source (positional
  reads, per-chunk panic isolation, truncated-tail recovery, damaged string
  table retry), fast template-value decoder + JSON fallback (byte-identical),
  JSON scanner, filters, field maps, input expansion, ordered parallel engine
- forhunt-output: csv, jsonl, llm writers
- CLI: parse, stats, search, timeline (top-N heap / external merge sort),
  show (JSON/XML/llm, EventRecordID fallback), hayabusa normaliser
- tools/evtx-gen: synthetic EVTX writer, fixtures (valid/corrupt/truncated,
  attack scenario), multi-GB corpus
- Tests: unit + 16 end-to-end CLI tests (incl. fast/slow parity); CI green on
  Linux/macOS/Windows with fmt, clippy -D warnings, cargo deny, perf gate,
  fixture reproducibility, checklist schema
- Release workflow (5 static targets, SHA-256, tap job gated on secret)
- Skill: SKILL.md, references (forhunt, hayabusa, report template, attack
  path, event ids, logon types), 12 checklists / 242 checks, verifier pass
  (80 verified), INDEX with coverage matrix and blind spots, status template,
  install scripts (bash/PowerShell, pinned Hayabusa hashes), sample fetcher

## In progress
- Benchmarks on 2 GiB corpus -> README table
- Worked example on EVTX-ATTACK-SAMPLES (report + Mermaid attack path)

## Next
- Perf analyst and fresh-eyes reviewer subagents
- Tag v0.1.0, verify release assets, test install.sh end to end
- Homebrew tap (deferred, B-002)
