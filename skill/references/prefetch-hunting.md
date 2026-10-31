# Prefetch hunting

Analyst guide for `.pf` files in forhunt. Syntax and fields are in `forhunt.md`
(section "Prefetch"). Items marked **[K]** are analyst knowledge that was not
checked against a source in the session that wrote this file; treat them as
leads.

## What it proves

A `.pf` file says a program started on this host, from which folder, how many
times, and what it touched in about its first ten seconds **[K]**. It does not
say who ran it, with which arguments, or whether it succeeded.

## Triage

```bash
forhunt search E -c Prefetch -r 'ExePath=\\(USERS|PROGRAMDATA|PERFLOGS|TEMP)\\'   # odd locations
forhunt search E -c Prefetch -r 'ExePath=\\WINDOWS\\TEMP\\'
forhunt search E -c Prefetch -f RunCount=1 --since <incident start>            # new, once
forhunt search E -c Prefetch -r 'ExecutableName=^(PSEXESVC|WMIC|VSSADMIN|BITSADMIN|CERTUTIL|RCLONE|7Z|PROCDUMP)'
forhunt search E -c Prefetch -f FilesLoaded~<tool or DLL>                       # what touched it
forhunt timeline E --since <t> --until <t>                                      # merged with logs and NTFS
```

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
