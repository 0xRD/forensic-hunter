# NTFS hunting: `$MFT` and `$UsnJrnl:$J`

Analyst guide for file-system evidence in forhunt. Command syntax, channels and
fields are in `forhunt.md` (section "NTFS"); the ready-made checks are
`checklists/filesystem.yaml` (FH-FS-001..031). This file says what to look
for, how to read it and where it misleads.

Conventions: `E` = the host's evidence folder (never `--computer`, NTFS has no
host name). Paths look like `.\Windows\System32\cmd.exe`. Regexes are
case-insensitive. Items marked **[K]** are analyst knowledge that was not checked
against a source in the session that wrote this file; treat them as leads.

## 1. What each source tells you

| Source | Strong at | Weak at |
|---|---|---|
| `$MFT` event 16 (`$SI` times) | Names, sizes, flags, ADS names, Zone.Identifier text, deleted-but-not-reused records | The `$SI` times can be set by user-mode code (timestomping) |
| `$MFT` event 48 (`$FN` times) | Creation / move time that a user-mode tool cannot set directly; name kept for deleted files | One name per hard link; updated only at some events (rename, move) |
| `$J` (UsnJrnl 1..6) | Sequence of creates, renames, deletes, stream and attribute changes with exact times, including for files whose MFT record was reused | Retention window (hours to weeks); no process, user or content; reasons merge |
| Event logs | Who and which process | Often cleared, missing or not logging file operations |

Rule of thumb: the journal answers "what happened and when", the MFT answers
"what is there and what did it look like", the event logs answer "who".

Collect `$MFT` and `$Extend\$J` together (KAPE `!SANS_Triage`, Velociraptor).
With an `$MFT` beside the journal forhunt resolves journal paths; without it
you only get `FileName` and parent numbers.

## 2. Triage order (about 10 commands)

```bash
forhunt stats E -q                                 # time range of $J and $MFT, event counts
forhunt checklist E -k references/checklists/checklists.json --tactic filesystem -o work/fs.md
forhunt search E -c MFT -e 16 -f SiLtFn=true -f uSecZeros=true            # FH-FS-012
forhunt search E -c MFT -e 48 -f ZoneIdContents~HostUrl                   # downloads, FH-FS-004
forhunt search E -c UsnJrnl -e 2 -r 'FileName=\.(exe|dll|ps1|bat|dmp|zip|7z|rar)$'   # cleanup
forhunt search E -c UsnJrnl -e 1 -r 'Path=^\.\\(users\\public|programdata|windows\\temp|perflogs)\\'   # staging
```

Then take every interesting file to one entry:

```bash
forhunt search E -f EntryNumber=1259 -F jsonl     # MFT ($SI, $FN) + journal for one file; add -f SequenceNumber=N if the entry was reused
forhunt timeline E --since 2024-03-11T10:14:00Z --until 2024-03-11T10:26:00Z -n 60
```

Check the `$J` range from `stats` first. If the journal starts after the first
suspicious event, say so in the gaps section; the absence of a delete record
then means nothing.

## 3. Reading `$MFT` timestamps

One `MFT` event exists per distinct timestamp of a record. `MACB` shows which
of Modified, Accessed, record Changed, Born share the event time.

| Pattern in `$SI` (event 16) | Usually means |
|---|---|
| One event `MACB` | Created and never touched since (typical dropped file written in one go) |
| `...B` then later `MAC.` (seconds apart) | Created, then content written and closed: normal download or tool output |
| Created (B) later than Modified (M) (`Copied=true`) | File copied: the copy gets a new creation time and keeps the old modification time; also archive extraction that restores times |
| Created old, Modified old, record change (C) recent | Times may have been set back; many tools leave C at the real action time (not all: some APIs can set it **[K]**), so C near the real creation hints at timestomping (see section 4) |
| Moved on the same volume | Created and Modified unchanged, record-change time updated, new parent; `$FN` times unchanged or updated depending on the move [K] |
| Renamed in place | Record-change time updated; journal shows RenameOldName / RenameNewName pair |
| Accessed (A) only changes | Last-access updates may be disabled or delayed (default on modern Windows is not to update on every read) [K]: never use A as proof of reading |
| `Deleted=true` | Record is free but not reused: name, size and times still readable; reuse bumps `SequenceNumber` |

Compare copy vs move vs download with the journal for the same `EntryNumber`:

| Operation | Journal for the file | MFT |
|---|---|---|
| Browser download | FileCreate, DataExtend, NamedDataExtend (stream), Close | `ZoneIdContents` with `HostUrl=`, B = download time |
| Copy to the volume | FileCreate, DataExtend, Close; possibly BasicInfoChange (times set to the source's) | M older than B (`Copied`) |
| Move (same volume) | RenameOldName in the old folder, RenameNewName in the new one; no create, no data | Same EntryNumber, new parent |
| Move (other volume) | Create on target, Delete on source | Copy pattern on target |
| Extraction (zip, 7z) | FileCreate per file, data close; times often set afterwards | Whole-second times (zero sub-seconds) and old M |
| Created by a script / tool | Short burst of FileCreate + DataExtend + Close | MACB equal, sub-second parts present |

## 4. Timestomping in depth

`$STANDARD_INFORMATION` (shown in Explorer) can be written by user-mode APIs;
`$FILE_NAME` times are managed by the kernel and change mainly on create,
rename and move. A tool that sets `$SI` therefore leaves the `$FN` times as the
real creation time.

| Indicator | forhunt | What it proves |
|---|---|---|
| `$SI` created earlier than `$FN` created | `-f SiLtFn=true` | Strong lead: the file claims to be older than the moment the kernel first saw it |
| Zero sub-second part on `$SI` times | `-f uSecZeros=true` | Weak alone: many tools write whole seconds. Strong together with SiLtFn |
| Both | `-f SiLtFn=true -f uSecZeros=true` (FH-FS-012) | Best precision |
| `$SI` modified before `$SI` created | `-f Copied=true` | Copy or extraction, not timestomping by itself |
| Journal BasicInfoChange shortly after FileCreate | `-c UsnJrnl -f Reason~BasicInfoChange` (FH-FS-011) | A time or attribute was set; read the surrounding records |
| `$SI` older than the volume or OS install date, or than the files in the same folder | compare `Created0x10` to neighbours | Anomalous age |
| `$SI` created before the file's first journal record | compare `Created0x10` to the FileCreate time of that EntryNumber | The recorded creation is earlier than the journal says the file appeared |

Double timestomping (setting both attributes, for instance by copying the file
through a rename trick) defeats the SiLtFn flag. Then rely on: the journal
(creation time of the EntryNumber), neighbours created in the same minute
(`Created0x30` of the toolkit), `$LogFile` if available [K], and event logs.

Order hits by `Created0x30` (event 48), not by `Created0x10`, when you want the
true timeline.

False positives of the `$SI < $FN` family:

- Files copied or restored with original times (robocopy `/COPY:T`, backup
  restore, xcopy `/K`), installers and MSI/CAB payloads: many hits in one
  minute, all with old versions of vendor files.
- OS install and feature-update files: all hits share the install date.
- Archive extraction (zip/7z): whole-second times.
- Sync clients (OneDrive, Dropbox) restoring modified times.

Judge by cluster: one hit in a folder of ordinary files is a lead; hundreds
sharing a minute are a deployment.

## 5. Reading the journal (`$J`)

### Reason flags

`Reason` is a union of flags written between open and close of a file, so one
record can carry several. Event id 1..6 is forhunt's class of the record.

| Flag | Meaning for a hunter |
|---|---|
| FileCreate | New file or directory |
| FileDelete | File deleted (the record normally also has Close) |
| DataExtend / DataOverwrite / DataTruncation | Content written, replaced or cut |
| NamedData* | Same for a named stream (Zone.Identifier writes show as NamedDataExtend on the main file) |
| StreamChange | A named stream was added, removed or renamed |
| BasicInfoChange | Attributes (hidden, read-only...) or time stamps changed |
| RenameOldName / RenameNewName | Two records per rename or move: old name + old parent, new name + new parent |
| SecurityChange | ACL or owner changed |
| EaChange, ReparsePointChange, HardLinkChange, ObjectIdChange | Extended attributes, symlink/junction, hard link, object id |
| Close | The handle closed; this is the final record of an operation |

Practical reading:

- A burst `FileCreate` -> `DataExtend|FileCreate` -> `DataExtend|FileCreate|Close`
  is one file being written. Group by `EntryNumber` + `SequenceNumber`.
- Repeated changes of the same kind between open and close are written once, so
  record counts do not equal operation counts.
- `Usn` is the record's position in the journal **[K]**; sorting by `Usn` gives
  record order even when the clock changed.
- `FileAttributes` tell hidden/system/temporary files; `SourceInfo` marks
  changes made by background operations rather than by a user program **[K]**.

### Retention and gaps

The journal is a size-limited log: NTFS trims it at checkpoints when it exceeds
its maximum size plus the allocation delta. Busy volumes keep days, quiet
servers weeks. Therefore:

- Never conclude "file never existed" from the journal alone; compare the first
  `$J` record time with the incident window.
- Deleting the journal (`fsutil usn deletejournal`) resets the USN of every file
  to zero and removes the journal; the new journal starts at small USNs
  (FH-FS-031). Signals: `$J` starts late, MFT `Usn` of recently created files is
  0, `fsutil.exe` Prefetch/execution events, a quiet period in the activity
  histogram of `stats` (`days` / `hours_utc`).

## 6. Deleted-but-not-reused records

A deleted file keeps its MFT record (`Deleted=true`) until NTFS reuses the entry;
reuse bumps `SequenceNumber`. Such a record still shows `FileName`, `FileSize`,
parent, `$SI`/`$FN` times and often `ZoneIdContents`. Practical rules:

- `FileSize` of a deleted record tells how big a dump or archive was (lsass dump:
  tens of MB; NTDS: hundreds of MB).
- The journal delete (event 2) gives the exact time; the MFT record gives the
  name when the journal has rolled over, and vice versa.
- Orphan paths (`.\[orphan 0x..-..]\name`) mean the parent directory record was
  reused: the file may have lived in a folder that was also deleted (tool folders
  removed as a whole).
- Large churn of free entries reused within hours (Temp folders) makes older
  deletions unrecoverable: the answer "not present" depends on volume activity.

```bash
forhunt search E -c MFT -e 16 -f Deleted=true -r 'Path=\.(exe|dll|ps1|bat|dmp|zip|7z|rar)$'
```

## 7. What to hunt, by tactic

Check ids refer to `checklists/filesystem.yaml`. Always read the check's
`false_positives` before judging.

### Staging and tools

| Look for | Where | Check |
|---|---|---|
| Executables, scripts, DLLs created in `Users\Public`, `ProgramData`, `Windows\Temp`, `PerfLogs`, user Temp | UsnJrnl 1, MFT 48 | FH-FS-003 |
| Offensive tool names: mimikatz, Rubeus, SharpHound, procdump, nanodump, LaZagne, Kekeo, Certify, Inveigh, crackmapexec / netexec | names in MFT 48 + journal | FH-FS-013 |
| SharpHound output: `<timestamp>_BloodHound.zip` and per-object json files | journal | FH-FS-013 |
| Remote access and tunnelling: AnyDesk, TeamViewer, ScreenConnect, Atera, Splashtop, RustDesk, MeshAgent, ngrok, chisel, plink, cloudflared | names + AnyDesk `user.conf`/`system.conf` | FH-FS-014 |
| Cobalt Strike default artefacts: default pipe/service/payload names are mostly in memory, registry and event logs, rarely distinctive on disk; on disk expect random-name DLL/EXE in `Windows\Temp` or `ProgramData`, 8-letter service exes, `.bin` and beacon-loader dll names **[K]** | Temp + `\Windows` creates | FH-FS-003, FH-FS-016 |
| Webshells: `aspx`, `ashx`, `asp`, `php`, `jsp` under `inetpub\wwwroot`, Exchange `aspnet_client`, `FrontEnd\HttpProxy\owa\auth` | journal + MFT | FH-FS-017 |
| Executable lures: `invoice.pdf.exe`, right-to-left override characters | journal | FH-FS-030 |
| Renamed tool (`m.exe` -> `WinUpdate.exe`) | RenameOldName in staging path | FH-FS-030 |

### Persistence

| Look for | Check |
|---|---|
| Script / binary / lnk in `...\Start Menu\Programs\Startup` (user and all-users) | FH-FS-018 |
| New files directly in `Windows\System32\Tasks` (task name = file name, XML content) and `Windows\Tasks\*.job` | FH-FS-019 |
| New service binaries: exe in `\Windows`, `System32`, `ProgramData` created just before 7045; random-name 8-letter exe | FH-FS-010, FH-FS-016 |
| WMI repository writes (`wbem\Repository\OBJECTS.DATA`, `INDEX.BTR`) and `.mof` files | FH-FS-020 (weak) |
| Driver files dropped in user folders, `spool\drivers\color` | FH-FS-021 |
| DLL next to a signed executable in a user-writable folder; trailing-space folders (`C:\Windows \System32`) | FH-FS-022 |
| Registry-based persistence is not visible here: use event logs / hives | n/a |

### Credential access

| Look for | Check |
|---|---|
| `lsass.dmp`, `*.dmp` outside WER / CrashDumps; `lsass_YYMMDDhhmmss.dmp` style names (procdump default); `nanodump`, `proc_*.dmp` **[K for the last two]** | FH-FS-005 |
| `ntds.dit` outside `Windows\NTDS` (ntdsutil IFM writes `Active Directory\ntds.dit` and `registry\SYSTEM`) | FH-FS-023 |
| `SAM`, `SYSTEM`, `SECURITY` copies (`.save`, `.hive`, `sam.export`) in user/Temp folders | FH-FS-023 |
| Browser credential databases copied out of the profile (`Login Data`, `Local State`, `key4.db`, `logins.json`) | FH-FS-023 |
| Kerberos ticket files `*.kirbi` | FH-FS-013 |

Size matters: use `FileSize` of the deleted MFT record to judge a dump.

### Collection and exfiltration

| Look for | Check |
|---|---|
| `.7z .rar .zip` created in `Users\Public`, `ProgramData`, `Temp`, `inetpub`; sort by `FileSize` | FH-FS-015 |
| rclone binary or `.config\rclone\rclone.conf` under a user profile | FH-FS-015 |
| Cloud sync clients and file-transfer tools (MEGAsync, WinSCP, pscp) | FH-FS-014 |
| Archive creation followed by deletion within minutes | FH-FS-006 |

### Defence evasion and anti-forensics

| Look for | Check |
|---|---|
| Timestomping | FH-FS-001, 002, 011, 012 |
| Deletion of tools / dumps / archives | FH-FS-006 |
| Deletion of `.evtx`, `.pf`, PSReadLine history, IIS logs, backups | FH-FS-007, FH-FS-025 |
| Tool Prefetch for `fsutil`, `wevtutil`, `vssadmin`, `wbadmin`, `bcdedit`, `cipher`, `sdelete` | FH-FS-024 |
| SDelete renames (`AAAAAAAA.AAA` ... `ZZZZZZZZ.ZZZ`) before delete | FH-FS-024 |
| `cipher /w` free-space wipe creating a folder `EFSTMPWP` at the volume root **[K]** | `-f Path~efstmpwp` |
| Journal reset or late start | FH-FS-031 |
| ADS other than Zone.Identifier (executables hidden in streams) | FH-FS-027 |
| Mark-of-the-Web removed (StreamChange / NamedDataTruncation on a downloaded file) | FH-FS-026 |
| System-process names outside system folders | FH-FS-009 |
| Executables at the volume root or in fake `$RECYCLER.BIN` style folders **[K]** | search `Path=^\.\\[^\\]+\.(exe|dll|bat|ps1|vbs)$` |

Deletion bursts (cleanup scripts, wipers): count deletes per minute.

```bash
forhunt search E -c UsnJrnl -e 2 -F jsonl -n 0 -q | python3 -I -c '
import sys, json, collections
c = collections.Counter(json.loads(l)["timestamp"][:16] for l in sys.stdin if l.startswith("{\"id\""))
for k, v in c.most_common(8): print(k, v)'
```
Separate Temp churn (hundreds per minute, `tmp*.tmp`, `*.log`) from a burst of
documents, hives or logs in one directory tree.

### Ransomware

| Look for | Check |
|---|---|
| Mass RenameNewName with one new extension; `top_values` of `FileName` in the summary line | FH-FS-008 |
| Known document extension followed by another (`report.docx.locked`) | FH-FS-028 |
| Ransom notes (`readme`, `decrypt`, `restore`, `how_to` ... `.txt/.html/.hta`) created in many folders | FH-FS-008 |
| Backup / shadow copy tampering before: `vssadmin`, `wbadmin`, `bcdedit`, `diskshadow` Prefetch; backup files deleted | FH-FS-024, FH-FS-025 |
| Encryptor drop: unknown exe in Temp/ProgramData/share, then rename storm; first rename minute = start | FH-FS-003, FH-FS-028 |

Count renames per minute with the same recipe as the deletion bursts but
`-e 3 -f Reason~RenameNewName`; the first minute above background is the
start, the `Path` roots show spread across shares.

### Lateral movement (target side)

| Look for | Check |
|---|---|
| Exe copied to ADMIN$ (`\Windows`) or `\Windows\Temp` shortly before a 7045 / 4697 service install | FH-FS-010, FH-FS-016 |
| PsExec, PAExec, RemCom, CSExec service binaries | FH-FS-010 |
| wmiexec output `\Windows\__<epoch>.<n>` or `C:\__<epoch>.<n>`; impacket `sessionresume_<8 letters>` | FH-FS-016 |
| Scheduled-task files created remotely | FH-FS-019 |
| Files written into Startup by `mstsc.exe` (RDP drive redirection / tsclient) | FH-FS-018 |
| RDP client use from this host: `Terminal Server Client\Cache` bitmap cache **[K]**, `.rdp` files | FH-FS-029 |
| Tools staged on the target through SMB | FH-FS-003, 013, 014 |

## 8. Correlating with event logs

forhunt `timeline` merges event logs and NTFS events when you give it the host
folder. Typical pairs:

| File event | Event-log event to look for in the same minute |
|---|---|
| FileCreate of an exe in `\Windows` or `\Windows\Temp` | System 7045 / Security 4697 (service), Security 5145 (ADMIN$), 4624 type 3 |
| FileCreate in `System32\Tasks` | Security 4698, TaskScheduler 106/129 |
| FileCreate of `u.ps1`, `x.exe` in `Users\Public` | Sysmon 1 / Security 4688 for the same path, Sysmon 11 if file-create logging is on |
| `lsass.dmp` create then delete | Sysmon 10 on lsass, PowerShell / rundll32 `comsvcs.dll` command lines |
| Prefetch of `fsutil` / `wevtutil` / `vssadmin` | 4688 command line; Security 1102 / System 104 when logs were cleared |
| Webshell create | IIS log requests, `w3wp.exe` children |
| `ZoneIdContents` `HostUrl=` | Proxy / DNS logs for that host, Sysmon 22, browser history |
| Many renames or deletes | 4688 of the starting process, 4624 of the account |

Method:

1. Identify the file's EntryNumber from a check hit, pull its journal
   sequence and MFT times: `forhunt search E -f EntryNumber=N -F jsonl`.
2. Take the earliest FileCreate as the "file appeared" time.
3. `forhunt timeline E --since T-5min --until T+10min` over the host folder (NTFS
   and EVTX together; with a multi-host tree pass the host's folder only, since
   NTFS rows cannot be filtered with `--computer`).
4. Find the process (4688 / Sysmon 1), the logon (4624, LogonId) and the network
   source.
5. Write down what the file system proved (time, name, size, parent) and what
   the logs add (user, process, source IP).

## 9. Common false positives

| Source | Noise | How to tell |
|---|---|---|
| Windows Update / servicing | `WinSxS`, `SoftwareDistribution`, `$WINDOWS.~BT`, `servicing` in `Windows`; thousands of creates; `$SI < $FN` on install dates | Parent folders, time clusters, files signed by Microsoft |
| Defender | `ProgramData\Microsoft\Windows Defender` scans, `Quarantine`, `MpCmdRun` logs, temp dumps | Path under Defender folders |
| Installers / updaters | Exe, DLL, MSI in `Temp`; `.tmp` folders with random names; Chrome/Edge/Teams/Zoom updaters in AppData | Created and deleted together, in one process tree |
| Windows Error Reporting | `.dmp`, `.wer` in `ProgramData\Microsoft\Windows\WER`, `CrashDumps` | Path under WER (FH-FS-005 excludes) |
| Temp churn | `tmpXXXX.tmp`, `*.tmp`, `~$*.docx`, `*.log` created and deleted within seconds | Names, short lifetime, no executable extension |
| Browser caches | Creating and deleting thousands of files in cache directories | Path under browser profile |
| Backup / sync | Mass renames, archive creation, BasicInfoChange | One process, regular schedule |
| Prefetch | Housekeeping deletes old `.pf` one at a time | Only mass deletion is a signal |
| Admin tools | `fsutil`, `vssadmin`, PsExec by administrators | Confirm with the admin and with approvals |

## 10. Pitfalls

- No host name or user in NTFS data: never attribute to an account from the file
  system alone.
- Times are UTC. Journal and MFT times are in the volume's recorded clock; if the
  clock was changed, order by `Usn` in the journal.
- `Path` of journal events is the path at collection time when resolved with the
  MFT; renamed/deleted parents may show as orphans. The MFTECmd project's `-m`
  mode "rewinds" the journal to give the path at the time of the record
  (see its README); forhunt resolves against the MFT you provide.
- One MFT event per distinct timestamp: filtering on `FileName` returns several
  events per file. Count files by `EntryNumber`, not by event.
- Regexes cannot use lookaround: express "not in System32" by reading the result
  or by anchoring to the folders you want (`^\.\\(users|programdata|windows\\temp)\\`).
- A miss never proves absence: renamed tools, different drives, rolled-over
  journal, reused records.
- `ZoneIdContents` is only read when the stream is resident (small files are
  fine). Files fetched by PowerShell, curl or certutil usually carry none.
- Do not run `--since/--until` inside checklist queries; the sweep skips them.
- Evidence is read-only: all of the above only reads.

## 11. Reporting snippets

- File-system finding template: *Observed* (name, path, EntryNumber, times from
  event ids, size, deleted state) / *Inferred* (action and why) / Confidence.
- Always cite the `$FN` time next to the `$SI` time when you present a creation
  time of a suspect file.
- State journal coverage ("`$J` covers X to Y") in the evidence section and
  every gap in the gaps section.

## Sources

Read for this file or for the checks it points to (2026-10-22, via GitHub):

- MFTECmd source: https://github.com/EricZimmerman/MFTECmd/blob/master/MFTECmd/Program.cs
  (definitions of the SI<FN, uSecZeros and Copied flags) and README
  https://github.com/EricZimmerman/MFTECmd (journal path "rewind" technique,
  `-m` option, `$J` handling)
- Usnjrnl rewind: https://github.com/CyberCX-DFIR/usnjrnl_rewind
- Microsoft change journal docs (GitHub source of the Learn pages):
  https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/FileIO/change-journal-records.md,
  https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/FileIO/change-journals.md,
  https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/FileIO/creating-modifying-and-deleting-a-change-journal.md,
  https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/FileIO/master-file-table.md,
  https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/FileIO/file-streams.md,
  https://github.com/MicrosoftDocs/sdk-api/blob/docs/sdk-api-src/content/winioctl/ns-winioctl-usn_record_v2.md
- MITRE ATT&CK data (techniques T1070.006, T1070.004, T1564.004 and id validity of the
  other technique ids used): https://github.com/mitre/cti
- SigmaHQ rule files (read for file names and locations only; nothing is copied;
  rules are DRL-licensed), all under
  https://github.com/SigmaHQ/sigma/tree/master/rules/windows/file/ :
  `file_event/` anydesk_artefact, bloodhound_collection, cred_dump_tools_dropped_files,
  csexec_service, dll_sideloading_space_path, dump_file_susp_creation,
  exchange_webshell_drop, hktl_hivenightmare_file_exports, hktl_mimikatz_files,
  impacket_file_indicators, lsass_default_dump_file_names, ntds_dit_creation, ntds_exfil_tools,
  perflogs_susp_files, rclone_config_files, rdp_file_susp_creation, remcom_service,
  remote_access_tools_screenconnect_artefact, sam_dump, startup_folder_file_write,
  susp_lnk_double_extension, susp_recycle_bin_fake_exec, susp_right_to_left_override_extension_spoofing,
  susp_spool_drivers_color_drop, susp_startup_folder_persistence, susp_task_write,
  sysinternals_procexp_driver_susp_creation, sysinternals_psexec_service, tsclient_filewrite_startup,
  webshell_creation_detect, wmi_persistence_script_event_consumer_write, wmiexec_default_filename;
  `file_delete/` delete_backup_file, delete_event_log_files, delete_iis_access_logs,
  delete_powershell_command_history, delete_prefetch, sysinternals_sdelete_file_deletion,
  zone_identifier_ads_uncommon; `file_rename/` file_rename_win_ransomware

Not reachable from the writing environment (not read): learn.microsoft.com,
attack.mitre.org, SANS posters and blogs, The DFIR Report, vendor write-ups.
Their content is not claimed here.
