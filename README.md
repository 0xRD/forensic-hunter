# Forensic Hunter

**`forhunt`**: a very fast, single-binary Windows forensic toolkit for event
logs (EVTX) and NTFS metadata (`$MFT`, `$UsnJrnl:$J`), built to be driven by
an LLM with a limited context window, plus a
**Claude skill** that turns Claude into a systematic, checklist-driven Windows
forensic analyst.

- **Fast**: 64 KiB chunks read with positional I/O and processed in parallel across
  files and directories, purpose-built decoder, streaming output.
  See [benchmarks](#benchmarks).
- **One static binary** for Linux (musl), macOS and Windows. No runtime.
- **LLM-friendly output**: compact `llm` JSONL with short stable keys, value
  truncation markers, stable event ids, deterministic order, a default cap of
  200 events and a final summary line with suggested filters to narrow.
- **Robust**: corrupt or truncated logs never crash it; bad chunks and records
  are counted and reported (`--strict` makes them fatal).
- **Forensically sound**: inputs are only opened read-only, never modified.
- **NTFS timeline**: `$MFT` records become timestamp events with full paths,
  MACB flags, timestomp indicators, deleted records and download origin
  (Zone.Identifier); `$J` change-journal entries become create / rename /
  delete events. Both merge with event logs in one timeline.
- **Extensible**: an `Artifact`/`Source` abstraction ready for registry,
  prefetch, LNK, jump lists, shellbags and amcache.

## Install

```bash
# skill installer (forhunt + Hayabusa, SHA-256 verified)
bash skill/scripts/install.sh            # Windows: skill/scripts/install.ps1

# or from source
cargo install --git https://github.com/0xRD/forensic-hunter forhunt
```

Release archives with SHA-256 checksums: [Releases](https://github.com/0xRD/forensic-hunter/releases)
(x86_64/aarch64 Linux musl, x86_64/aarch64 macOS, x86_64 Windows).
Homebrew (`brew install 0xRD/tap/forhunt`) is coming.

## Usage

```bash
forhunt stats   ./evidence                           # triage summary (start here)
forhunt search  ./evidence -e 4625 -f IpAddress=203.0.113.50
forhunt search  ./evidence -c sysmon -e 1 -r 'CommandLine=-enc\s'
forhunt timeline ./evidence --since 2024-03-11T10:00:00Z --until 2024-03-11T10:30:00Z
forhunt show 4a2aa2ed:53413 -p ./evidence -F xml     # one event in full
forhunt parse   ./evidence -F csv -o all.csv         # full export, all hosts in one file
forhunt parse   ./evidence -F csv --computer WS-07 -o ws07.csv   # one host only
forhunt parse   ./evidence -F csv -O out/ --split host   # one file per host (or --split file)
forhunt hayabusa hayabusa.jsonl -p ./evidence        # normalise Hayabusa detections
forhunt search  ./evidence -c MFT -e 16 -f SiLtFn=true   # timestomped files ($MFT)
forhunt search  ./evidence -c UsnJrnl -e 2               # file deletions ($J)
```

Filters: `--event-id 4624,4720-4738`, `--channel Security|Sysmon|PS|...`,
`--since/--until` (ISO 8601, UTC), `--field Name=value` (case-insensitive,
hex-aware), `Name!=value`, `Name~substring`, `--regex [Name=]REGEX`,
`--computer HOST`, `--limit N`. Common options: `--threads`, `--no-progress`,
`--tz Europe/Paris` (display only), `--strict`, `--checksums`, `-q`.
Paths may be files, directories (recursive) or globs; any number of them, from
any number of endpoints. Results are concatenated into one output by default
(each row/line carries its source file and computer); `-O DIR --split file|host`
writes one output file per input file or per computer instead.

CSV output (`-F csv`) uses EvtxECmd's column layout (`TimeCreated`, `EventId`,
`MapDescription`, `PayloadData1..6`, `ExecutableInfo`, `Payload`...) plus a
`ForhuntId` column, so it opens directly in Timeline Explorer and similar tools.

Example `llm` output:

```json
{"id":"4a2aa2ed:53413","t":"2024-03-11T10:10:02.000000Z","h":"WS-07.contoso.local","ch":"Sec","eid":4624,"ti":"Logon success","d":{"user":"administrator","dom":"CONTOSO","lt":10,"ip":"203.0.113.50","port":"49732","auth":"NTLM","lproc":"NtLmSsp ","lid":"0x8a3f21","elev":"%%1842","lm":"NTLM V2","keylen":128}}
{"summary":{"cmd":"search","matches":1,"shown":1,"truncated":false,"scanned":2548,"files":1,...}}
```

Exit codes: 0 ok, 1 error, 2 usage, 3 no readable input, 4 corrupt input with `--strict`.
Full reference: [skill/references/forhunt.md](skill/references/forhunt.md).

## Claude skill

[`skill/`](skill/) packages the analysis method:
[SKILL.md](skill/SKILL.md) (workflow and rules),
install scripts for forhunt and [Hayabusa](https://github.com/Yamato-Security/hayabusa)
(checksum-verified downloads; Hayabusa is GPL-3.0 and never bundled),
detection checklists per ATT&CK tactic written like Sigma rules
([index, coverage matrix and blind spots](skill/references/checklists/INDEX.md)),
event id and logon type references, a report template, attack path
visualisation, and [worked examples](skill/examples/).

Workflow: hash and protect the evidence, `stats` first, Hayabusa detections,
walk every checklist with targeted `search` and pivots (each check ends as
HIT, NO_HIT, NOT_APPLICABLE or LOG_SOURCE_MISSING), `timeline` on suspicious
windows, then a report with a full chronological timeline, ATT&CK mapping,
IOCs, coverage and gaps.

## Benchmarks

Corpus: synthetic `evtx-gen corpus --size 2G` = 2,048 MiB, 3,016,365 events. Machine: x86_64, 4 cores, Linux (cloud VM); 3 runs each with [hyperfine](https://github.com/sharkdp/hyperfine), 2026-10-22, forhunt 0.1.0.

| Task | Wall time (mean ± σ) | MiB/s | Events/s | Peak RSS |
|---|---|---|---|---|
| forhunt parse jsonl (all cores) | 1.84 s ± 0.05 | 1,111 | 1,636,110 | 89 MiB |
| forhunt parse jsonl (1 thread) | 5.87 s ± 0.25 | 349 | 513,832 | 21 MiB |
| forhunt parse csv (all cores) | 2.86 s ± 0.10 | 716 | 1,054,841 | 78 MiB |
| forhunt search filtered (all cores) | 0.70 s ± 0.06 | 2,945 | 4,337,778 | 105 MiB |
| forhunt stats (all cores) | 1.47 s ± 0.07 | 1,393 | 2,051,722 | 36 MiB |
| forhunt timeline jsonl, full sort (all cores) | 5.92 s ± 0.68 | 346 | 509,267 | 381 MiB |
| evtx_dump jsonl (all cores) | 1.72 s ± 0.03 | 1,189 | 1,750,414 | 7 MiB |
| evtx_dump jsonl (1 thread) | 3.80 s ± 0.06 | 540 | 794,789 | 4 MiB |

- `search filtered` is `-e 4624 -f LogonType=3`: records whose event id does
  not match are skipped before their values are decoded.
- `evtx_dump` (evtx 0.12.3, the parser forhunt builds on) is faster at a plain
  dump, especially single-threaded (~1.5x): it only renders JSON, while
  forhunt also normalises each event (field map, stable id, source path) for
  filtering and output. Closing that gap is the next optimisation
  ([docs/PERF.md](docs/PERF.md), P-010).
- Timeline sorts everything in memory up to `--mem-budget` (default 256 MiB),
  then spills sorted runs to temporary files; peak RSS includes buffers on top
  of the budget.
- EvtxECmd (needs .NET) and Hayabusa (rule evaluation, a different workload:
  12+ minutes on this corpus, D-024) are not in the table.

Reproduce: `scripts/bench.sh --size 2G` (generates the synthetic corpus with
`tools/evtx-gen`; set `EVTX_DUMP`, `HAYABUSA`, `EVTXECMD` to include other
tools). Micro-benchmarks: `cargo bench -p forhunt-core`. CI runs an
instruction-count regression gate on every push and pull request
([scripts/bench-gate.sh](scripts/bench-gate.sh)). Optimisation log:
[docs/PERF.md](docs/PERF.md).

## Development

```bash
cargo test --workspace                     # unit + end-to-end tests
cargo run -p evtx-gen -- fixtures          # regenerate fixtures/synthetic
cargo deny check                           # licences and advisories
python3 scripts/gen-checklist-index.py     # regenerate checklist index
```

Layout: `crates/forhunt-core` (event model, EVTX source, decoder, filters,
field maps, engine), `crates/forhunt-output` (writers), `crates/forhunt`
(CLI), `tools/evtx-gen` (synthetic EVTX), `skill/` (Claude skill).
Design decisions: [DECISIONS.md](DECISIONS.md). Test data is synthetic or
downloaded by script; no real logs are committed.

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option. Hayabusa (GPL-3.0) and its rules (DRL 1.1) are downloaded
separately and are not part of this project. EVTX parsing builds on the
[`evtx`](https://github.com/omerbenamram/evtx) crate (MIT/Apache-2.0).
