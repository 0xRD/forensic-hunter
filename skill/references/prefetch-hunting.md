# Prefetch hunting

Analyst guide for `.pf` files in forhunt. Syntax and fields are in `forhunt.md`
(section "Prefetch"); the ready-made checks are `checklists/prefetch.yaml`
(FH-PF-001..026). Items marked **[K]** are analyst knowledge that was not
checked against a source in the session that wrote this file; treat them as
leads.

## What it proves

A `.pf` file says a program started on this host, from which folder, how many
times, and what it touched in about its first ten seconds **[K]**. It does not
say who ran it, with which arguments, or whether it succeeded.

## Triage

```bash
forhunt checklist E -k references/checklists/checklists.json --tactic prefetch -o work/pf.md   # FH-PF-*
forhunt search E -c Prefetch -r 'ExePath=\\(USERS|PROGRAMDATA|PERFLOGS|TEMP)\\'   # odd locations
forhunt search E -c Prefetch -r 'ExePath=\\WINDOWS\\TEMP\\'
forhunt search E -c Prefetch -f RunCount=1 --since <incident start>            # new, once
forhunt search E -c Prefetch -r 'ExecutableName=^(PSEXESVC|WMIC|VSSADMIN|BITSADMIN|CERTUTIL|RCLONE|7Z|PROCDUMP)'
forhunt search E -c Prefetch -f FilesLoaded~<tool or DLL>                       # what touched it
forhunt timeline E --since <t> --until <t>                                      # merged with logs and NTFS
```

The checklist reads a result as follows. Every query selects one event per file
(`RunIndex=1`), so a `HIT?` count is a number of programs, not of runs. Most name
checks only show that a tool ran: ask the logs for its arguments. A renamed tool
is found only by its location (FH-PF-001 to FH-PF-006, FH-PF-025) or by what it
loaded (FH-PF-011, FH-PF-013, FH-PF-024). FH-PF-026 (`NoRunTime`) comes out as
`LOG_SOURCE_MISSING` when no such file exists: record it as `NO_HIT`.

## Reading it

- Each event is one stored run. `RunTimes` lists them all and `RunCount` is the
  real total: above 8 (or above 1 on Windows 7 and earlier) older runs are gone.
- `ExecutableName` stops at 29 characters; `ExePath` gives the whole name. Two
  values in `ExePath` mean the name exists in two loaded folders: the file does
  not say which one ran, so check `Directories` and the hash in the file name.
- Same name, several `.pf`: different folders, or for hosting programs
  (`SVCHOST`, `DLLHOST`, `RUNDLL32`, `MMC`) a different command line **[K]**.
- `FilesLoaded` also lists data files. An attacker's document or script path in
  a program's list ties that program to it.
- `VolumeNames` with a second volume, or `-` in `VolumeCreated`, points to
  removable or mounted media (seen on `SETUP.EXE` from a mounted image).
- A file with `NoRunTime=true` is timestamped 1970: filter it out of windows, not
  out of the analysis.

## Where it misleads

- The stored time can run some seconds after the real start **[K]**: compare
  with 4688 or Sysmon 1 rather than matching to the second.
- Windows keeps a limited number of `.pf` files (1024 on 8+ **[K]**) and evicts
  old ones; a missing file proves nothing. Mass deletion shows in `$J`
  (FH-FS-007, FH-FS-024).
- Prefetch can be disabled (commonly on servers **[K]**): an empty folder is
  `LOG_SOURCE_MISSING`, not `NO_HIT`.
- Windows names and paths are upper-case here; filters are case-insensitive.
