# Forensic Hunter

**`forhunt`**: a very fast, single-binary Windows event log (EVTX) toolkit for
DFIR, built to be driven by an LLM with a limited context window, plus a
**Claude skill** that turns Claude into a systematic, checklist-driven Windows
forensic analyst.

- **Fast**: memory-mapped input, 64 KiB chunks processed in parallel across
  files and directories, purpose-built decoder, streaming output.
  See [benchmarks](#benchmarks).
- **One static binary** for Linux (musl), macOS and Windows. No runtime.
- **LLM-friendly output**: compact `llm` JSONL with short stable keys, value
  truncation markers, stable event ids, deterministic order, a default cap of
  200 events and a final summary line with suggested filters to narrow.
- **Robust**: corrupt or truncated logs never crash it; bad chunks and records
  are counted and reported (`--strict` makes them fatal).
- **Forensically sound**: inputs are only read (read-only mmap).
- **Extensible**: an `Artifact`/`Source` abstraction ready for MFT, registry,
  prefetch, LNK, jump lists, shellbags and amcache.

## Install

```bash
# Homebrew (macOS, Linux)
brew install 0xRD/tap/forhunt

# or the skill installer (forhunt + Hayabusa, SHA-256 verified)
bash skill/scripts/install.sh            # Windows: skill/scripts/install.ps1

# or from source
cargo install --git https://github.com/0xRD/forensic-hunter forhunt
```

Release archives with SHA-256 checksums: [Releases](https://github.com/0xRD/forensic-hunter/releases)
(x86_64/aarch64 Linux musl, x86_64/aarch64 macOS, x86_64 Windows).

## Usage

```bash
forhunt stats   ./evidence                           # triage summary (start here)
forhunt search  ./evidence -e 4625 -f IpAddress=203.0.113.50
forhunt search  ./evidence -c sysmon -e 1 -r 'CommandLine=-enc\s'
forhunt timeline ./evidence --since 2024-03-11T10:00:00Z --until 2024-03-11T10:30:00Z
forhunt show 4a2aa2ed:53413 -p ./evidence -F xml     # one event in full
forhunt parse   ./evidence -F csv -o all.csv         # full export (jsonl, csv)
forhunt hayabusa hayabusa.jsonl -p ./evidence        # normalise Hayabusa detections
```

Filters: `--event-id 4624,4720-4738`, `--channel Security|Sysmon|PS|...`,
`--since/--until` (ISO 8601, UTC), `--field Name=value` (case-insensitive,
hex-aware), `Name!=value`, `Name~substring`, `--regex [Name=]REGEX`,
`--computer HOST`, `--limit N`. Common options: `--threads`, `--no-progress`,
`--tz Europe/Paris` (display only), `--strict`, `--checksums`, `-q`.
Paths may be files, directories (recursive) or globs.

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

BENCHMARK_TABLE

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
