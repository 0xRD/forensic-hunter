> **Resolution (2026-10-22).** Must-fix 1 -> D-029, 2 -> D-030, 3 -> D-033,
> 4 -> D-031, 6 -> suffix path matching in `forhunt hayabusa`, 7 -> D-032,
> 8 -> installer fixes (`--help`, latest-release check, `--no-forhunt`,
> `FORHUNT_PREFIX`, PS 5.1 byte[] body), 9 -> no empty `--channel`, 10 -> D-034,
> 11 -> docs fixed. Item 5 was a transient state of the working tree (CI lint
> was green on every pushed commit). Lower-priority items are tracked in
> STATUS.md.

# Fresh-eyes review of Forensic Hunter

Scope: the repository at the state found on 2026-10-22, audited against the specification and definition of done in the brief.
Toolchain used: rustc 1.97.0 stable, Linux x86_64, 4 cores, hyperfine 2.0.0, cargo-deny, valgrind, Hayabusa 4.2.0 (linux x64 zip, SHA-256 equals the pin).
Nothing in the repository was modified except this file. Test artefacts are in
`/tmp/claude-0/-home-user-forensic-hunter/8751da07-3fd9-575a-a8e8-35d169c0bd4e/scratchpad/rv/`.

Legend: met / partly / not met. "Verified" means I ran it.

## 1. Definition of done

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 1 | Builds with no clippy warnings | **not met** | `cargo build --release` ok, `cargo test --workspace` all pass (43 tests). `cargo clippy --workspace --all-targets -- -D warnings` fails: `crates/forhunt-core/benches/decode.rs:6` `doc_lazy_continuation`. `cargo fmt --all --check` also fails (`crates/forhunt-output/src/csv.rs`, `crates/forhunt/src/cmd/dump.rs`, `crates/forhunt-core/benches/decode.rs:56`). Lib/bin/test targets are clippy-clean. The CI `lint` job (`ci.yml`, `cargo fmt --all --check` then clippy `-D warnings`, toolchain "stable") would be red. STATUS.md claims "CI green". |
| 2 | parse/stats/search/timeline/show on valid, corrupt, truncated EVTX | **partly** | Verified on fixtures (valid, `corrupt.evtx`, `truncated.evtx`, empty, 25-byte junk), all 28 `.evtx` files of the `evtx` crate samples, EVTX-ATTACK-SAMPLES (278 files, 37,357 events, 0.1 s), and 270 fuzzed mutants (120 random, 150 chunk-header-targeted): no crash, bad chunks/records counted, `--strict` gives exit 4. But: one mutant makes forhunt loop forever (D1), a corrupt copy of a file is silently dropped as a "duplicate" and `--strict` does not notice (D2). |
| 3 | `llm` format meets the spec | **met** (minor defects) | Compact JSONL, short stable keys, ids `<file key>:<record id>` that `show` resolves (all 47 ids quoted in README/skill/docs resolve except the placeholder `a1b2c3d4:4821`), deterministic (sha256 identical for `-t 1` vs `-t 8`, directory vs `**` glob, for parse/stats/search/timeline), cap 200 (201 lines incl. summary), explicit marker `…[+N chars]`, summary line with total, shown, truncated, `narrow` suggestions. Defects: D9 (invalid `narrow` suggestion), D14 (`--max-value-len` is bytes, help says characters). |
| 4 | Benchmarks in README, CI detects regressions | **partly** | README table is the known placeholder. CI gate is real: `scripts/bench-gate.sh` ran end to end here (head: 2,626,598,231 instructions, no base). `scripts/bench.sh` is complete (hyperfine 2 JSON shape handled), criterion bench builds. Measured here: 2.1 GiB corpus parse 2.1 s (79 MiB peak RSS), stats 1.7 s (35 MiB), filtered search 1.5 s (89 MiB), full-sort timeline 13 s (261 MiB, while another job was using the CPUs). docs/PERF.md shows forhunt at 1 thread (134 ms) is slower than `evtx_dump` at 1 thread (117 ms) on the reference file; the "very fast" claim rests on multi-core scaling and richer output. |
| 5 | Checklists cover all tactics, with sources and verified flags | **partly** | 12 files, 242 checks, schema complete for every check (id pattern, all required keys, unique ids, ATT&CK id format), `checklists.json` identical to the YAML, `gen-checklist-index.py --check` passes, 80 verified, every verified check lists several sources and a VERIFIED note. Gaps: no Command and Control tactic file (beaconing, ingress tool transfer, remote-access tools), and INDEX.md does not say that Reconnaissance, Resource Development and C2 are out of scope or only partly visible in EVTX (D13). All verification rests on GitHub-hosted sources (B-001): no Microsoft Learn page was opened. |
| 6 | Skill installs forhunt and Hayabusa via checksum-verified scripts | **partly** | Hayabusa: the zip layout and the pinned hash for linux-x64 match what I downloaded; bash logic reads correctly; the hash file has all 6 platforms. forhunt: cannot be tested, `https://github.com/0xRD/forensic-hunter/releases/latest` returns 404 today (no release, repo not public). Defects in the scripts: D8, D12, D15, D16. forhunt is verified only against a `SHA256SUMS` served from the same release (integrity, not authenticity); no pinned `checksums/forhunt-<ver>.sha256` is shipped although both scripts support it. |
| 7 | Worked example gives a full timeline report and a Mermaid attack path | **partly** | I rebuilt the 18-file case from EVTX-ATTACK-SAMPLES and reproduced: 149 events, 2 hosts, `present` map, top hosts, 4 log clears, Hayabusa 92 detections (4 critical/37 high/51 medium), 20 `HIT?` with the exact per-tactic table, the 18-match 5136 burst, timeline `matches: 88`. All event ids resolve and the quoted rows are real (spot-checked 10). Defects: the copy command contains a literal `…` instead of the 18 file names so the example cannot be replayed as written; "28 groups" is 27 groups plus the summary line; the evidence table in the report is elided ("… 15 more", "(see hashes-before.txt)"); file names in the hash listing use underscores where the real files have spaces; the Mermaid source and the HTML page were not rendered (no mermaid-cli); the "self-contained" HTML loads Mermaid from a CDN (D13b). Synthetic example (`synthetic-ws07.md`) runs offline and matches. |
| 8 | Release workflow publishes all platform binaries and updates the Homebrew tap | **partly** | `release.yml` reads correctly: 5 targets, SHA-256 per archive plus `SHA256SUMS`, archive layout matches `install.sh`/`install.ps1` and the formula; `render-formula.sh` verified with fake sums (all four placeholders replaced). Tap job is skipped without `HOMEBREW_TAP_TOKEN` (B-002, accepted). Not verifiable here and never exercised: `cargo zigbuild` for the two musl targets (a local musl build fails for lack of `x86_64-linux-musl-gcc`; mimalloc needs a C compiler), macOS and Windows jobs. There is no pre-release dry run and no CI job that builds a musl or Windows release binary (D10). |
| 9 | DECISIONS.md and BLOCKERS.md current | **partly** | Both are detailed and consistent with the code (D-021 mmap -> pread, D-002 unwind). STATUS.md is stale ("In progress" items are done; "16 tests" is 17; "CI green" is contradicted by item 1). README, `skill/references/forhunt.md` and PLAN.md still say memory-mapped (D11). |

## 2. Specification sections

| Section | Status | Evidence |
|---|---|---|
| Single static binary, platforms, extensible workspace | **partly** | `forhunt` is one binary; `Artifact`/`Source` traits in `forhunt-core::artifact`; positional reads work on Unix and Windows (`cfg` branches present). Static musl and Windows builds unverified here (item 8). |
| Performance: bounded memory, streaming, parallelism, filters pushed early | **met** | RSS 35-89 MiB on 2.1 GiB for all but timeline; timeline spills to disk (261 MiB with `--mem-budget 256`); chunk-level parallelism across files; byte-identical output at any thread count. Exception: unbounded `--threads` (D3). |
| Release profile | **met** | fat LTO, 1 CGU, opt 3, strip, mimalloc, `panic = "unwind"` per D-002. |
| Determinism | **met** | See item 3. Dedup of "identical" inputs is deterministic but wrong in a corner case (D2). |
| Corrupt/truncated never crash; `--strict` fatal | **partly** | No crash or panic in 270 mutants; but one infinite loop (D1) and a `--strict` bypass (D2). |
| Never reimplement Hayabusa, licence notice | **met** | External binary only; notice and source link in README, `hayabusa.md`, both install scripts. `deny.toml` bans copyleft in the binary; `cargo deny check advisories licenses bans sources` passes. |
| Tools only read evidence | **partly** | Inputs opened read-only, `chmod 555` directory works. Nothing stops `-o` pointing inside the evidence directory (D17); symlinked `.evtx` files in a directory are silently ignored (D7). |
| Never commit real logs | **met** | `.gitignore` excludes `*.evtx` except `fixtures/**`; fixtures are generated; `corpus/` (2.1 GiB, ignored) is local. |
| CLI: parse, stats, search, timeline, show, hayabusa normaliser | **met** | Every flag listed in README/`forhunt.md` exists and behaves as written, including `--tz`, `--since` date forms, globs, unicode paths, broken pipe (exit 0), `-o` errors (exit 1). Extra command `checklist` is documented. |
| Search filters | **partly** | `--event-id --channel --since --until --field --regex --computer --limit` all work. `--regex` mis-parses base64 patterns (D4). |
| Exit codes | **partly** | 0/1/2/3/4 verified. Bad `--since`, bad regex, bad `--tz`, bad event id exit 1, README says 2 for usage errors (clap errors do give 2). |
| stats | **met** | Per-channel/event-id presence, days, hours, hosts, accounts, IPs, logon types, log tampering (1102/104/1100/4719), record-id gaps, quiet periods, per-file ranges (llm output omits uneventful files; `-F json` has all). |
| Skill: SKILL.md, trigger, workflow, report template, attack path, status template | **met** | Description is 672 characters and specific; every command shown in SKILL.md exists; `checklist` sweep produces the documented table. |
| Install scripts bash + PowerShell, SHA-256, no embedded binaries | **partly** | See item 6. PowerShell could not be executed here (no `pwsh`). |
| Checklists schema and verification | **partly** | See item 5. |
| Distribution: CI matrix, release, tap, README, licences | **partly** | CI runs fmt, clippy, tests (3 OSes), fixtures reproducibility, benches compile, schema, cargo deny, perf gate. LICENSE-MIT and LICENSE-APACHE present, Cargo `MIT OR Apache-2.0`. Tap deferred. Repo URL `0xRD/forensic-hunter` returns 404 today, so every install line in README is untestable until publication. |

## 3. Defects

### 3.1 Must fix before release

**D1. A corrupt chunk makes forhunt loop forever (hang, 100 % CPU) - violates "corrupt EVTX never crash".**
- Repro: `forhunt stats -q <scratch>/rv/fz99/c10.evtx` (single hostile chunk; the same file inside `rv/fz/m099.evtx`, both generated by flipping 300 bits of `fixtures/synthetic/Security.evtx` or `Sysmon.evtx`). Never returns (checked 60 s; also with `-t 1`, `--slow-decoder`; memory stays flat at 12 MiB).
- gdb backtrace (profiling build): `evtx::string_cache::populate` -> `binxml::name::from_cursor` -> `utf16` loop, called from `crates/forhunt-core/src/evtx/mod.rs:263` (`parse_raw`) / `:219` (`parse_chunk`). A cyclic name-offset chain in the chunk string table is followed forever in `evtx 0.12.3`. `catch_unwind` cannot help.
- Expected: chunk counted as bad, run continues. Actual: process never finishes; a directory scan stalls on one bad file.
- Fix: validate the string-table offset chains in forhunt before handing the chunk to `evtx` (bounded hop count), or run the parse under a per-chunk watchdog/deadline (kill the worker's result and count the chunk bad), or patch/upgrade `evtx`. Add the 64 KiB chunk as a regression fixture (it is a mutated synthetic file, no real data).

**D2. Distinct files with the same 32-bit sampled key are silently dropped; `--strict` is bypassed.**
- Code: `crates/forhunt/src/common.rs:114-121` (dedup by `s.key()`); key in `crates/forhunt-core/src/id.rs` is 32 bits of BLAKE3 over size + first/last 68 KiB (D-005).
- Repro: `mkdir d; cp fixtures/synthetic/corrupt.evtx fixtures/synthetic/Security.evtx d/; forhunt stats --strict d -q; echo $?` prints 0, `bad_chunks: 0`, 2548 events. `corrupt.evtx` has the same size and same first/last chunks as `Security.evtx` but a damaged middle. Without `-q` the only trace is a warning "same content as ..., skipped". `forhunt stats --strict corrupt.evtx Security.evtx` also exits 0.
- Impact: a damaged or tampered copy of a log (same size, intact ends) is reported as clean, bad chunks are not counted, and event ids `4a2aa2ed:N` become ambiguous between two files (`show` picks the first). With 32 bits, accidental collisions among thousands of files are also possible (~0.1 % at 3,000 files).
- Expected: only skip when content is really identical (compare full-file hash or all chunk checksums; or compare lengths plus a cheap full-content hash only for key collisions), never skip silently under `--strict`, and give distinct keys to distinct files (extend to 64 bits, keep 8 hex digits only if collisions are detected and resolved with a suffix).

**D3. `--threads` is unbounded: `-t 99999` spawns 99,999 threads (1.4 GB RSS, runs for minutes).**
- Code: `crates/forhunt-core/src/engine.rs:121-130` (`build_pool` uses the value as is).
- Repro: `forhunt search fixtures/synthetic/Security.evtx -t 99999 -n1 -q` (had to be killed after >6 min CPU).
- Fix: clamp to a sane maximum (for example `4 x logical cores`, and never more than the number of units), or reject above that with exit 2.

**D4. `--regex` silently mis-parses patterns ending in base64 padding or containing `word=`; result is a false "no match".**
- Code: `crates/forhunt-core/src/filter.rs:124-127` (`split_once('=')`; any left part that looks like an identifier becomes a field name).
- Repro: Sysmon fixture event 1 has a command line ending `ApAA==`. `forhunt search fixtures/synthetic/Sysmon.evtx -r 'pAA==$' -q` -> 0 matches (parsed as field `pAA`, pattern `=$`); `-r '(?:)pAA==$'` and `-r 'CommandLine=pAA==$'` -> 1 match.
- Expected: either an explicit syntax (for example `-r Name=REGEX` only when `Name` is a field that exists in the field map or the data, or a separate `--regex-field Name REGEX`), or a warning when the named field is absent from every scanned event. As is, hunting for encoded payloads by their suffix, the most common use of `--regex`, silently misses.

**D5. CI lint job is red on stable 1.97 (clippy and rustfmt).** See item 1. Fix: add a blank `//!` line or indent at `crates/forhunt-core/benches/decode.rs:6`, run `cargo fmt --all`, and pin the toolchain in `rust-toolchain.toml` (it says `channel = "stable"`, so the first new stable can break CI again) or accept that and keep a scheduled build.

**D6. `forhunt hayabusa` loses every forhunt id when the Hayabusa output was produced on Windows (backslash paths).**
- Code: `crates/forhunt/src/cmd/hayabusa.rs:229-232`. On Linux/macOS `Path::new("C:\\Cases\\x\\a.evtx").file_name()` returns the whole string, so the `rsplit(['\\','/'])` fallback is never reached and the by-name lookup fails.
- Repro: take `hb/out.jsonl` and rewrite `EvtxFile` to `C:\\Cases\\AutomatedTestingTools\\Malware\\X.evtx` (file `rv/hbwin2.jsonl`): `forhunt hayabusa rv/hbwin2.jsonl -p EVTX-ATTACK-SAMPLES --min-level high -q` -> `"with_forhunt_id":0` (with `/` separators it is 636). Expected 636.
- Fix: always take the last component after splitting on both `\` and `/` before the by-name lookup. The common DFIR flow (Hayabusa on a Windows workstation, analysis on Linux) hits this.

**D7. Checklist sweep reports `NO_HIT` for two checks because their queries contain placeholder values.**
- `skill/references/checklists/initial-access.yaml` FH-INIT-002 (`TargetUserName=jdoe`) and FH-INIT-005 (`IpAddress=203.0.113.10`, twice). The sweep (`forhunt checklist`, `crates/forhunt/src/cmd/checklist.rs`) runs them literally.
- Repro: `forhunt checklist <fixtures Security/System/Sysmon/PowerShell> -k skill/references/checklists/checklists.json -q | grep -E 'FH-INIT-00[25]'` -> both `NO_HIT`, although the built-in scenario contains 25 failed logons for one account (`administrator`) and a successful logon from the same address (203.0.113.50) right after (`4a2aa2ed:53413`). A `NO_HIT` from a sweep is the worst outcome: SKILL.md tells the analyst to review `HIT?` rows, not to re-derive `NO_HIT` rows.
- Fix: make the sweep run only queries that are runnable as written; for correlation checks (queries with example values) emit `REVIEW` and print the query, or turn them into value-free aggregations. Add a test that fails on documentation-range IPs or `jdoe` in `forhunt:` lines. (Four lines in total are affected; FH-AD-007 `ObjectClass=server` is legitimate.)

**D8. Installer failure modes that print nothing useful or run on bad data.**
- `skill/scripts/install.sh:31` `--help` prints `sed -n '2,20p'`, which includes code lines (`set -euo pipefail`, `FORHUNT_REPO=...`); the header ends at line 15.
- `install.sh:60-62`: with no release, `latest` resolution fails inside a command substitution under `set -e`, so the script exits with only curl's own message and no `install:` line; if the repository has releases but `/releases/latest` redirects to `/releases` (for example only pre-releases), `sed 's#.*/tag/##'` leaves the whole URL as "version" and a garbage download URL is tried. Check that the result matches `^v[0-9]`.
- There is no way to install Hayabusa alone (`--no-forhunt` missing); the only way to test the Hayabusa half is a published forhunt release.
- `skill/scripts/hayabusa.sha256:4` refers to `scripts/pin-hayabusa.sh`, which does not exist.
- `install.sh:23` and the docs use an environment variable named `PREFIX`, which is commonly exported by build environments (nix, Homebrew `brew install` helper shells, autotools); the script then installs into and `rm -rf`s `$PREFIX/hayabusa-<ver>`. Rename to `FORENSIC_HUNTER_PREFIX`.

**D9. `narrow` suggestions can be uncopyable.**
- `crates/forhunt/src/facets.rs:231` builds `--channel {} --event-id {id}` from the channel alias; for events with no channel (ETW-style records in EVTX-ATTACK-SAMPLES) the output is `"add":"--channel  --event-id 6"`.
- Repro: `forhunt search EVTX-ATTACK-SAMPLES -q | tail -1` -> first `narrow` entry. Also `top_eid` shows `":6"` and `stats` `present` has a `""` channel key.
- Fix: omit `--channel` when empty and label such events (for example `(none)`) in `top_eid`/`present`.

**D10. The first release is a blind shot.** No CI job builds the musl (zig) or Windows `crt-static` release binaries before a tag; a failure appears only after pushing the tag (and a failed tag run cannot be repeated without `workflow_dispatch` on an existing tag). Add a `build` job on pull requests (matrix of the 5 targets with `--locked`, no upload) or a `workflow_dispatch` dry run. Also check in `release.yml` that `${TAG#v}` equals the `Cargo.toml` version (otherwise `forhunt --version` and the Homebrew `test do` block disagree), and mark `-rc` tags as pre-releases (the tag filter `v[0-9]+.[0-9]+.[0-9]+*` accepts them and would push them to the tap).

**D11. Documentation says "memory-mapped" after D-021 replaced mmap.**
- `README.md:8` ("memory-mapped input") and `:17` ("read-only mmap"), `skill/references/forhunt.md:3`, `PLAN.md:21`. The code uses `pread`/`seek_read`. Fix the four lines; the forensic claim "inputs are only read" stays true.
- Also `docs/PERF.md:7` and `skill/examples/README.md:7` cite `scripts/fetch-samples.sh`; the file is `skill/scripts/fetch-samples.sh`. `forhunt hayabusa --help` still says "json-timeline output" (Hayabusa 4 uses `dfir-timeline`). The README `llm` sample is hand-edited (real 4624 output has `lm` before `lproc` and extra keys) - say "abridged".

**D12. PowerShell installer: likely failure reading `SHA256SUMS` (not executed here, no `pwsh`).**
- `skill/scripts/install.ps1:70`: `(Invoke-WebRequest ...).Content -split "`n"`. On Windows PowerShell 5.1, `.Content` of a response served as `application/octet-stream` (GitHub release assets without a known extension) is a `byte[]`; `-split` then yields a string of numbers and `Find-Sum` throws "no checksum listed". Decode explicitly (`[Text.Encoding]::UTF8.GetString`) when the type is `byte[]`, or download to a file and `Get-Content` it. Please test on Windows PowerShell 5.1 and PowerShell 7 after the first release. CI only syntax-checks the bash scripts (`bash -n`); add a PowerShell parse check (`[System.Management.Automation.Language.Parser]::ParseFile`).

### 3.2 Later (should fix, not blocking)

- **D13. Coverage statement.** INDEX.md should state which ATT&CK tactics are intentionally absent (Reconnaissance, Resource Development) and add a Command and Control file (Sysmon 3/22 beacons, ingress tool transfer, remote-management tools). Its first table lists "tactics" that are not ATT&CK tactics (`remote-access`, `active-directory`); add a mapping from ATT&CK tactic to file. VERIFICATION.md should say plainly that "Microsoft docs" confirmation came from GitHub mirrors, as B-001 does.
- **D13b. Worked example polish.** Replace the `…` in the `cp` command with the 18 names (or generate the list with a command); fix "28 groups" to 27; complete the evidence table; use the real file names; render the Mermaid with `mmdc` once and check it (not done here); call the HTML "needs network for Mermaid" instead of "self-contained" in `SKILL.md`/`attack-path.md` or inline the script, and add SRI to the CDN import. `T1685` appears in the report as "current ATT&CK" and is explained only in VERIFICATION.md; keep one consistent sentence.
- **D14. `--max-value-len`** counts bytes (`crates/forhunt-output/src/llm.rs`, `s.len() > max`, cut on a char boundary) but the help says characters and the marker says `chars`; a tiny limit can save only a few characters (`[+3 chars]`). Use character counts or rename.
- **D7b. Symlinks.** `input.rs` `walk` uses `follow_links(false)` and tests `file_type().is_file()`, so a symlinked `.evtx` inside a directory (common for mounted images or case folders) is ignored: `ln -s .../Security.evtx sl/link.evtx; forhunt stats sl` -> "no input files found". Accept symlinks to regular files (and warn).
- **D15. Exit codes for bad option values.** `--since garbage`, `--tz Nowhere/Land`, bad regex, bad event id exit 1; README and D-012 promise 2 for usage errors. Return 2 for argument validation.
- **D16. Weak forhunt authenticity chain.** forhunt checksums come from the same release that serves the archive; ship `skill/scripts/checksums/forhunt-<ver>.sha256` with each release commit (both scripts already support it) or document the trust model. `forhunt checklist --tactic bogus` returns an empty table with exit 0; reject unknown tactics. `--since` later than `--until` returns zero matches silently; warn.
- **D17. Output next to evidence.** Refuse `-o` (and the `timeline` spill directory) inside an input directory, or at least warn; today `forhunt parse evidence/ -o evidence/out.jsonl` writes into the evidence tree.
- **D18. CSV output is not neutralised for spreadsheet formula injection** (`=`, `+`, `-`, `@` at the start of a value). Fidelity matters for forensics, so this should be an opt-in `--csv-safe`, but document it.
- **D19. STATUS.md** is out of date (see item 9). Add a note in README/forhunt.md that `stats` in `llm` format omits uneventful files (`files_omitted`) and that `-F json` lists all.
- **D20. Hayabusa wrapper** (`bin/hayabusa`, `bin/hayabusa.cmd`) `cd`s into the install directory, so relative `-d`, `-o` arguments break; this is documented in the install output but not in `SKILL.md` step 3, which uses `$CASE` paths (absolute) only because `CASE=~/cases/...`. Resolve relative arguments in the wrapper or state "absolute paths only" in `hayabusa.md`.
- **D21. Performance claim.** Put the measured table (including the single-thread `evtx_dump` comparison from PERF.md, where forhunt is 15 % slower at one thread) into the README once generated, and describe forhunt as fast per core-count, not per thread. Also record peak RSS in `bench.sh` output for `timeline` separately: it is the only command with a 261 MiB footprint.

## 4. What I checked and found correct

- Every documented command in README, `skill/references/forhunt.md`, `SKILL.md`, `examples/*.md` exists with the flags used; all example outputs I re-ran have the same numbers.
- All 461 checklist queries run (the `checklist` sweep executed all of them, exit 0); SCHEMA conformance for all 242 checks.
- `render-formula.sh` output; archive naming consistent between `release.yml`, `install.sh`, `install.ps1`, formula template.
- `fetch-samples.sh` clones and checks out the pinned commit `4ceed2f...` (278 files); Hayabusa 4.2.0 `dfir-timeline -t jsonl -p verbose -O -w -q -K -N -C` works with the documented flags and `forhunt hayabusa -g` consumes it.
- Robustness: empty directory, nonexistent path, glob matching nothing (exit 3 with a message), unicode paths and globs, `| head` (exit 0), unwritable `-o` (exit 1), huge `--limit` (u64 max accepted; larger rejected by clap), timestamps with offsets/fractions/spaces, `--tz` display conversion, read-only evidence directory, 28 sample files from the `evtx` crate (dirty, bad-chunk, no-CRC, bad string cache) without a crash.
