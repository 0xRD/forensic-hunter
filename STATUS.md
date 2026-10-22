# Status

Last update: 2026-10-22 (session 1)

## Done
- Spec review, PLAN.md, DECISIONS.md (D-001..D-034), BLOCKERS.md (B-001..B-004)
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

- `forhunt checklist` sweep, `hayabusa -g` grouping
- Worked examples: insecurebank.local (EVTX-ATTACK-SAMPLES) with report,
  timeline, Mermaid + HTML attack path; offline synthetic example

- Timeline Explorer CSV (EvtxECmd layout), `-O DIR --split file|host`,
  `parse --computer` (D-027, D-028)
- Fresh-eyes review (REVIEW.md): all must-fixes applied (D-029..D-034)
- install.sh tested end to end against a local mirror of the release assets
  (checksums verified, tampered archive refused)

## In progress
- Final benchmarks -> README table
- Release dry run (workflow_dispatch without tag), then tag v0.1.0

## Next
- install.sh against the real release once the repository is public
- Homebrew tap (deferred, B-002)
- Review lower-priority items: Command and Control checklist, symlinked
  inputs, option-value errors exit 1 (docs say 2), refuse `-o` inside the
  evidence tree, `--max-value-len` counts bytes, Mermaid from CDN in the HTML
  attack path, forhunt checksums served by the same release
- Perf analyst report was lost to a container restart; not re-run
