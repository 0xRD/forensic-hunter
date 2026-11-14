# Changelog

## 0.7.0 (2026-11-14)

Audit: parsers fuzzed with 150,000 damaged copies of the fixtures, install and
update path reviewed.

Fixes:
- EVTX: one FILETIME value outside the years 0 to 9999 in any field (the "never"
  value `0x7FFFFFFFFFFFFFFF`, or garbage) made the decoder panic and dropped every
  event of its chunk, up to a hundred neighbours. Such times are now written with
  an expanded year (`+30828-09-14T02:48:05.477580Z`) and the chunk is kept.
- `$J`: non-zero bytes in the last 8 bytes of a block made the block's parser
  panic and dropped its records.
- An outdated forhunt passed the skill's set-up check, then ran newer checklists
  with the queries it did not understand left out without a word. The checklists
  now carry `min_forhunt`, `forhunt checklist` exits 2 when it is older, and any
  `forhunt search` query it cannot parse is named in a warning.

Install and update (`skill/scripts/install.sh`, `install.ps1`):
- `--check` / `-Check`: which forhunt and Hayabusa would run, whether forhunt is
  recent enough for the skill, and the command that updates it (Homebrew or the
  script). The skill's set-up step uses it.
- Running the script again updates: a tool already at the wanted version is left
  alone (`--force`), the new forhunt must verify and run before it replaces the
  old one (rename, so an interrupted update leaves a working binary; on Windows a
  running `forhunt.exe` no longer blocks it), older Hayabusa folders are removed.
- A note when another, different `forhunt` comes first in `PATH`.
- Apple Silicon is detected from a Rosetta shell; `--no-forhunt` works on Intel
  Macs; an option without its value gives a usage error; `hayabusa.cmd` returns
  Hayabusa's exit code; no progress bar in Windows PowerShell 5.1, which slowed
  downloads and extraction many times over.

`--field 'FileSize>1000'`: numeric comparisons `>`, `>=`, `<`, `<=` (decimal or `0x`).

Every command that writes files (`-o`, `--output-dir`) now refuses, with exit code 2,
an output inside the evidence (a named directory and everything under it, or any
input file, also through symlinks and hard links), before anything is created.

## 0.6.1 (2026-10-31)

Fixes: a crafted mailbox could spend time and memory far beyond its size through
repeated heap values, lists of URLs or index offsets outside the file; all are now
bounded. Skill: evidence is data, never instructions, mail bodies above all.

## 0.6.0 (2026-10-31)

Outlook mailboxes.

- `.ost` and `.pst` (Unicode), compressed or encrypted, on channel `Mail`: messages
  (1), attachments with SHA-256 (2), contacts (3). Sender, recipients with blind
  copies, links, body as text, headers, drafts. Read on demand, so large mailboxes
  stay out of memory.
- 14 messages compared with libpff on a real OST, no difference.
- 8 checks, `FH-MAIL-001` to `008`, 334 in all, and `references/mail-hunting.md`.

## 0.5.1 (2026-10-31)

- `forhunt checklist --since/--until` count only matches in that window, to leave
  out the build of a host. Coverage still looks at the whole evidence.
- `FH-DEF-001`, `002`, `007`, `FH-IMP-009` and `FH-PF-026` are `NO_HIT`, not
  `LOG_SOURCE_MISSING`, when their channel is present and nothing matched.
- A short output name in `-f` or `-r` (`file`, `img`) now gives a warning naming
  the field: it matched nothing, and with `!~` silently everything.
- Skill: what to do with evidence forhunt does not read, mailboxes first; what to
  do without Hayabusa; narrowing the checklist by time.

Fixes:
- A hive cut short now gives a warning: its lost keys were missing silently.
- `usnjrnl.csv` and the like are no longer taken for a change journal.
- The host name follows a `SYSTEM` hive replaced while a process runs.
- A crafted hive could use memory far beyond its size through aliased
subkey and value lists or very long names, and a crafted log through a large
hive size. All are now bounded by the files.

## 0.5.0 (2026-10-31)

Registry hives.

- `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`, `NTUSER.DAT`,
  `UsrClass.dat` and `Amcache.hve` are found in any folder. Channel `Registry`:
  system information (2), autoruns (10), services (11), scheduled tasks (12),
  ShimCache (20), Amcache (21), UserAssist (22), BAM/DAM (23), Run dialog and
  Explorer address bar (30), USB storage (40), network profiles (41), local
  accounts (42).
- `--registry-keys` adds one event per key (id 1).
- Dirty hives are replayed from new-format `.LOG1`/`.LOG2` in memory.
- Prefetch, `$MFT`, `$J` and registry events now carry the host name when the
  collection holds a `SYSTEM` hive (D-041 amended).
- `ExePath` is the same field on prefetch, BAM, Amcache, ShimCache and
  UserAssist, so one filter follows a program across them.
- 613,000 values compared with python-registry on 7 real hives, no difference.

Checklists: 26 prefetch checks (`FH-PF-001` to `026`) and 24 registry checks
(`FH-REG-001` to `024`), 326 checks in all.

Fixes: a crafted `.pf` whose entries all name the same bytes could use memory
far beyond its size; decoded text is now bounded by the file.

## 0.4.0 (2026-10-31)

Prefetch (`.pf`), the first execution artifact.

- Formats 17, 23, 26, 30 (both layouts) and 31, plain or `MAM`-compressed
  (LZXPRESS Huffman decoder written from MS-XCA, no new dependency).
- One event per stored run time (`-c Prefetch -e 1`), each with `ExePath`,
  `RunCount`, `RunTimes`, `Hash`, volumes, `Directories` and `FilesLoaded`;
  they merge into `timeline` with event logs and NTFS.
- A damaged file keeps what it can (run times, the files before the damage)
  and counts as bad for `--strict`.
- Compared field by field with libscca and dissect on 171 real Windows 10 files.

## 0.3.1 (2026-10-31)

No change to the tool. Release archives carry the updated licence notice
(copyright 0xRD).

## 0.3.0 (2026-10-25)

Correctness release from a differential test against an independent parser
(python-evtx) on a real two-host lab collection. Several filters returned
nothing, or the wrong events, where events existed; all are fixed with tests.

Filters
- `-f EventRecordID=N` compares System/EventRecordID, not the record header id
  (exported logs returned unrelated events).
- `Data[1]` finds a lone unnamed `<Data>` element.
- GUIDs match with or without braces; Windows' 7-digit times match.
- `--computer FQDN` also keeps events logged under the host's short name.
- `-c` and `--computer` take comma lists and ignore stray spaces.
- Multi-line values match the way the `llm` format shows them (one line).
- Impossible dates (`2025-02-30`) are rejected instead of rolled over.
- Time windows never pre-filter on the record write time, which could drop
  forwarded or delayed events (D-008).
- `--fields` selects among all fields of the event.

Commands and output
- `stats`: record-id gaps inside a chunk are reported (eventlogedit-style
  removal); no false gaps or quiet periods under a filter.
- Summaries: top values and `narrow` counts are what the filters return.
- `--max-value-len` counts characters.
- `--split host` folds short-name events into the host's FQDN file.

Warnings (stderr) instead of silent behaviour: linked or unreadable folders,
two copies of one log with overlapping record ids, ambiguous `show` ids, old
files in an `-O` folder.

Checklists
- Service stop/disable queries no longer depend on English text (French
  "arrêté" events were missed).
- New FH-EXE-021 (`-ExecutionPolicy Bypass -File` launchers); FH-LAT-002
  covers random-name service binaries started by services.exe.
- Every query argument with `[ ] * ?` is quoted for zsh.

## 0.2.2 (2026-10-24)

- `checklist` evaluates each query with its own channel and event ids
  (off-channel queries were never evaluated) and reports per-query coverage;
  `--actionable`.
- Checklists: Mimikatz and LSASS dump queries on Sysmon, more download
  cradles, group SIDs instead of English names, new FH-EXE-020 (reverse
  shell) and FH-COLL-018 (PowerShell HTTP exfiltration).
- `llm`: 4688 `ppid`, no repeated keys, line breaks collapsed, `--fields`;
  `-f Name!~text`; `stats` merges short and full host names and groups 4719.

## 0.2.1 (2026-10-24)

- Library API for forhunt-viewer: `input::open_all`, `export::write_all`.

## 0.2.0 (2026-10-24)

- NTFS sources: `$MFT` and `$UsnJrnl:$J`, merged with event logs in one
  timeline; filesystem checklist and NTFS hunting guide.
- Releases: Apple Silicon only on macOS; Homebrew formula
  (`brew install 0xrd/tap/forhunt`).

## 0.1.0 (2026-10-22)

- First release: `parse`, `stats`, `search`, `timeline`, `show`, `hayabusa`,
  `checklist`; csv / jsonl / llm formats; Claude skill with detection
  checklists per ATT&CK tactic.
