# Roadmap

Open work, roughly by priority.

## Artifacts
- LNK, jump lists, shellbags (the `Artifact`/`Source` traits are ready for them).
- Mail: ANSI PST (Outlook 2002 and earlier), RTF-only bodies, messages attached
  to messages, contact addresses through the name-to-id map, deleted items, and
  searching attachments' contents.
- Registry: deleted keys and values from slack, old-format (`DIRT`) log replay,
  ShimCache before Windows 10, scheduled task actions, ShellBags in
  `UsrClass.dat`, SID to account name, control sets other than the current one.
- Prefetch: MFT references of loaded files.
- NTFS: MFTECmd-layout CSV option, `$I30` / `$LogFile`, hard links (one event
  set per name), attribute lists (names in extension records).

## Commands
- `stats`: `$J` first/last time and USN discontinuities (journal reset,
  FH-FS-031); time bucketing for burst detection.
- Numeric comparisons in filters (`FileSize>N`); per-file grouping
  (`EntryNumber` + `SequenceNumber`).
- Option-value errors exit 1 where the docs say 2; refuse `-o` inside the
  evidence tree.

## Checklists
- Re-verify the checks against Microsoft Learn and other sources that were
  unreachable from the original build environment (most checks rest on
  GitHub-hosted sources: SigmaHQ, Hayabusa, Chainsaw, Sysmon docs, MITRE CTI).
- Drop revoked ATT&CK ids kept next to their replacements
  (T1070.001/T1685.005, T1562.x/T1685/T1686, T1574.002/T1574.001).
- A Command and Control checklist.
- `forhunt checklist --explain <id>`: the matching events of one check in compact
  form, so a `HIT?` needs no separate search.
- Registry checks that need `--registry-keys` (LSA packages, RDP settings):
  `forhunt checklist` does not read id 1 events.

## Packaging and benchmarks
- Notarized macOS binaries (needs an Apple Developer account).
- forhunt checksums are served by the same release as the archives; publish
  them somewhere independent.
- EvtxECmd column in the benchmark table (needs .NET:
  `EVTXECMD=/path/EvtxECmd.dll scripts/bench.sh`).
- The HTML attack path loads Mermaid from a CDN; offer an offline variant.
