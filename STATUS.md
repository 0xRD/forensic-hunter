# Status

Last update: 2026-10-24 (session 2)

## Done
- Session 2 (2026-10-24, on a Mac): repository public; authors rewritten to
  the owner; v0.1.0 recreated on the rewritten tag (same tree, same
  archives, Intel macOS dropped, D-042); Homebrew formula in the tap
  (`brew install 0xrd/tap/forhunt`, audit and `brew test` pass), tap job
  switched to a deploy key (D-043); `install.sh` "latest" resolution tested
  against the public release (forhunt + Hayabusa, checksums ok); full local
  gate green on macOS arm64; 800 mutated EVTX files: no crash, no hang.
- Spec review, PLAN.md, DECISIONS.md (D-001..D-041), BLOCKERS.md (B-001..B-004)
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

- Final benchmarks in README (2 GiB corpus); P-010 event-id pre-check
- Release dry run: all 5 targets built and packaged

- v0.1.0 released (2026-10-22): 5 archives + .sha256 + SHA256SUMS, tag on
  833e577, CI green on that commit

- NTFS: `$MFT` and `$UsnJrnl:$J` sources (D-036..D-041), differential checks
  against mft_dump (13k real records) and USN-Journal-Parser, fuzzed, synthetic
  fixtures for the WS-07 scenario, filesystem checklist (10 checks), P-011
- NTFS hunting guide `skill/references/ntfs-hunting.md` and 21 more
  filesystem checks (FH-FS-011..031; research subagent, reviewed)

## In progress
- (none)

## Next
- NTFS follow-ups: MFTECmd-layout CSV option, `$I30` / `$LogFile`, hard links
  (one event set per name), attribute lists (names in extension records),
  host name from the SYSTEM hive once registry support exists, lazy
  timestamp fields (P-011)
- Binary features the NTFS checks would use: `$J` first/last time and USN
  discontinuities in `stats` (journal reset, FH-FS-031); time bucketing for
  burst detection; numeric comparisons (`FileSize>N`); per-file grouping
  (`EntryNumber`+`SequenceNumber`); a `Name!~text` operator
- ATT&CK: some checks keep revoked ids next to their replacements
  (T1070.001/T1685.005, T1562.x/T1685/T1686, T1574.002/T1574.001), as noted
  in each check; drop the legacy ids at the next checklist revision
- Review lower-priority items: Command and Control checklist, symlinked
  inputs, option-value errors exit 1 (docs say 2), refuse `-o` inside the
  evidence tree, `--max-value-len` counts bytes, Mermaid from CDN in the HTML
  attack path, forhunt checksums served by the same release
- Perf analyst report was lost to a container restart; not re-run
