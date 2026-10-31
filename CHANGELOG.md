# Changelog

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
