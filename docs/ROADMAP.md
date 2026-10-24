# Roadmap

Open work, roughly by priority.

## Artifacts
- Registry hives, prefetch, LNK, jump lists, shellbags, amcache (the
  `Artifact`/`Source` traits are ready for them).
- NTFS: MFTECmd-layout CSV option, `$I30` / `$LogFile`, hard links (one event
  set per name), attribute lists (names in extension records), host name from
  the SYSTEM hive once registry support exists.

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

## Packaging and benchmarks
- Notarized macOS binaries (needs an Apple Developer account).
- forhunt checksums are served by the same release as the archives; publish
  them somewhere independent.
- EvtxECmd column in the benchmark table (needs .NET:
  `EVTXECMD=/path/EvtxECmd.dll scripts/bench.sh`).
- The HTML attack path loads Mermaid from a CDN; offer an offline variant.
