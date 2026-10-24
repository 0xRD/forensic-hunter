# forhunt reference

`forhunt <command> <paths...> [options]`. Paths are files, directories
(recursive) or globs, from any number of hosts. Directories are searched for
`*.evtx`, `$MFT` and `$J` / `*UsnJrnl*` files. Inputs are only read (opened
read-only, positional reads).

| Command | Purpose | Default format |
|---|---|---|
| `stats` | triage summary: volumes, coverage, accounts, hosts, IPs, logon types, log tampering, record-id gaps, quiet periods | `llm` |
| `search` | events matching filters, in file/record order | `llm`, cap 200 |
| `timeline` | events from all inputs merged by time | `llm`, cap 200 (earliest first) |
| `show <id>... -p <paths>` | one event in full (`-F json|xml|llm`; `xml`/`raw` is the native record: EVTX XML, hex dump for NTFS) | `json` |
| `parse` | every event (machine use only) | `jsonl` |
| `hayabusa <file>` | normalise Hayabusa JSON/JSONL output, attach forhunt ids (`-p <evtx dir>`); `-g` groups per rule and host | `llm`, cap 200 |
| `checklist <paths> -k checklists.json` | one-pass sweep of every detection check: log source coverage, query hits, pre-filled status file (`-F md|json`, `--tactic`, `--actionable` for HIT?/REVIEW rows only); per query: source events, covered events (tested fields present), matches | markdown |

## Filters (search, timeline, stats)

| Option | Meaning |
|---|---|
| `-e, --event-id 4624,4625,4720-4738` | event ids (comma list, ranges; repeatable) |
| `-c, --channel Security` | channel name (comma list; repeatable), alias (`Sec`, `Sys`, `Sysmon`, `PS`, `PSClassic`, `WMI`, `Task`, `TS-LSM`, `TS-RCM`, `RdpCoreTS`, `WinRM`, `Defender`, `BITS`, `Firewall`, `NTLM`, `DS`) or `*` glob |
| `--since T`, `--until T` | ISO 8601, both inclusive, on the event's `TimeCreated` (never the record write time); no offset means UTC; `2024-03-11` means midnight UTC; impossible dates are rejected |
| `-f, --field Name=value` | case-insensitive equality; numeric when hex (`0x17` = `0x00000017` = `23`); GUIDs with or without braces (`{42e0bcd9-...}` = `42E0BCD9-...`); timestamps at microsecond precision (Windows' 7 digits match) |
| `-f Name!=value` | not equal (also true when the field is absent) |
| `-f Name~text` | case-insensitive substring (a GUID value also contains its braces) |
| `-f Name!~text` | does not contain (also true when the field is absent); repeat to drop noise, e.g. `-f Image!~\\MsMpEng.exe` |
| `-r, --regex [Name=]REGEX` | case-insensitive regex on one field, or on every value |
| `--computer HOST` | exact host, or short name of an FQDN; an FQDN also keeps events logged under its short name; comma list, repeatable |

`-e`, `-c` and `--computer` values are ORed, whether given as a comma list or
by repeating the option (`-c Sec -c Sysmon` = either channel); different
options, and repeated `-f` / `-r`, are ANDed. Field names are those Windows
writes in EventData/UserData (`TargetUserName`, `LogonType`, `IpAddress`,
`CommandLine`, `ServiceName`...); `Computer`, `Channel`, `Provider`,
`EventID`, `EventRecordID` (the System value, not the record header id) work
too. Several unnamed `<Data>` elements are `Data[1]`, `Data[2]`...; a lone one
is printed as `Data`, and `Data[1]` finds it too. Quote arguments holding
`[ ] * ?` (`-f 'Data[3]~x'`): zsh stops on an unmatched glob.

Multi-line values (script blocks, privilege lists) are printed by `llm` with
line breaks and tabs collapsed to one space; `=`, `~`, `!=` and `!~` also
match them that way, so a snippet copied from `llm` output finds its event.
`-r` stays literal (use `\s+`).

Other options: `-n, --limit N` (0 = no cap), `-F, --format llm|jsonl|csv`,
`--max-value-len N` (characters, default 256), `--all-fields`, `--fields a,b,c`
(`llm`: show only these fields in `d`, short or full names, chosen among all
the event's fields, not only the mapped ones), `--tz Europe/Paris`
(display only), `-t, --threads N`, `--strict`, `--checksums`, `-q`.
`parse` takes `--computer HOST` too (no other filters).

## Multiple inputs and output files

All inputs are concatenated into one output (stdout or `-o FILE`); JSONL lines
carry `source_file`, CSV rows `SourceFile` and `Computer`. To get one file per
input or per host instead (`parse` and `search`, not `timeline`):

```bash
forhunt parse ./collection -F csv -O out/ --split file   # out/HOST1__Security.csv ...
forhunt parse ./collection -F csv -O out/ --split host   # out/ws-07.contoso.local.csv ...
```

Per-file names are the input path relative to the common input directory,
with separators replaced by `__`. With `--split host`, events logged under a
short host name go into the file of the single FQDN extending it (appended at
its end, with a warning). Files already in the directory that the run did not
write are listed in a warning. The summary line still goes to stdout.

## CSV (Timeline Explorer)

`-F csv` writes RFC 4180 UTF-8 with EvtxECmd's column names and order:
`RecordNumber, EventRecordId, TimeCreated, EventId, Level, Provider, Channel,
ProcessId, ThreadId, Computer, UserId, MapDescription, UserName, RemoteHost,
PayloadData1..6, ExecutableInfo, HiddenRecord, SourceFile, Keywords, Payload`,
then `ForhuntId`. `TimeCreated` is `yyyy-MM-dd HH:mm:ss.fffffff` (UTC unless
`--tz`; microsecond precision, the 7th digit is always 0); `PayloadData*` hold the event's key fields as `Name: value`;
`Payload` holds every field as JSON. CSV values are never truncated (`--max-value-len` applies to `llm` only).

## NTFS: `$MFT` and `$UsnJrnl:$J`

Same commands, filters and output formats as event logs; merge them with
EVTX in `timeline` to see what happened on disk around each event.

| Channel | Event id | Event |
|---|---|---|
| `MFT` | 16 | timestamps of `$STANDARD_INFORMATION` (what Explorer shows; can be faked) |
| `MFT` | 48 | timestamps of `$FILE_NAME` (set by the kernel; hard to fake) |
| `UsnJrnl` | 1 / 2 / 3 | file created / deleted / renamed |
| `UsnJrnl` | 4 / 5 / 6 | data changed / metadata changed (attributes, security, streams) / closed |

- **One `MFT` event per distinct timestamp** of a record: `MACB` says which of
  Modified, Accessed, record Changed, Born (created) share the event time
  (`M..B`, `.AC.`, ...). Fields: `Path` (`.\` = volume root; no drive letter),
  `FileName`, `FileSize`, `EntryNumber`, `SequenceNumber`, parent numbers,
  `Deleted` (record not in use: deleted file still described), `IsDirectory`,
  `SiFlags`, `AdsNames`, `ZoneIdContents` (download origin: `HostUrl=`), all
  eight timestamps (`Created0x10` ... `LastAccess0x30`), `Usn`.
- **Timestomp indicators** (present only when true): `SiLtFn` ($SI created
  earlier than $FN created), `uSecZeros` ($SI created has no sub-second part),
  `Copied` ($SI created after $SI modified: copied file).
- **Journal events**: `Reason` (`FileCreate|DataExtend|Close`), `FileName`,
  `Path` (resolved when an `$MFT` sits in the journal's folder or its parent,
  as in KAPE / Velociraptor collections), entry and parent numbers, `Usn`,
  `FileAttributes`. The journal only covers its retention window (often days).
- **No host name** is stored in NTFS metadata: `--computer` drops these
  events. Scope by the host's evidence folder instead
  (`forhunt timeline evidence/WS-07 ...`).
- Orphans (parent directory reused or missing) show as `.\[orphan 0x<entry>-<seq>]\name`.
- Ids are `<file key>:<entry*8+n>` for `$MFT` and `<file key>:<byte offset>`
  for `$J`; `show` accepts them like EVTX ids.

```bash
forhunt search E -c MFT -e 16 -f SiLtFn=true -r 'Path=\.(exe|dll|ps1)$'     # timestomped binaries
forhunt search E -c UsnJrnl -e 2 -r 'FileName=\.(exe|ps1|zip|dmp)$'          # deleted tools
forhunt search E -c MFT -e 48 -f ZoneIdContents~HostUrl                      # downloaded files
forhunt timeline evidence/WS-07 --since 2024-03-11T10:10:00Z --until 2024-03-11T10:35:00Z
```

## `llm` format

One JSON object per line:

```json
{"id":"4a2aa2ed:53413","t":"2024-03-11T10:10:02.000000Z","h":"WS-07.contoso.local","ch":"Sec","eid":4624,"ti":"Logon success","d":{"user":"administrator","dom":"CONTOSO","lt":10,"ip":"203.0.113.50","auth":"NTLM"}}
```

| Key | Meaning |
|---|---|
| `id` | stable event id `<file key>:<record id>`; use with `show` |
| `t` | event time (`TimeCreated`), UTC |
| `h` | computer |
| `ch` | channel (alias) |
| `eid` | event id |
| `ti` | title, for known events |
| `d` | key fields with short names (known events) or all non-blank fields |

Common short names: `user`/`dom`/`sid` (target), `s_user`/`s_dom`/`s_lid`
(subject), `lt` logon type, `ip`, `port`, `wks`, `auth`, `lid` logon id,
`img`/`pimg` process/parent image, `cmd`/`pcmd` command lines, `svc`,
`svc_path`, `task`, `share`, `target`, `enc` ticket encryption, `status`,
`substatus`, `script`, `key`/`value` (registry), `dst`/`dport`, `query`.
Values longer than the limit end with `…[+N chars]`: use `show` for the full value.

The last line is the summary:

```json
{"summary":{"cmd":"search","matches":37,"shown":37,"truncated":false,"scanned":16145,"files":7,
 "first":"...","last":"...","filter":"--event-id 4625","top_eid":[["Sec:4625",37]],
 "top_host":[["WS-07.contoso.local",37]],"top_values":[["IpAddress","203.0.113.50",37]],
 "narrow":[{"add":"--field TargetUserName=administrator","matches":25}]}}
```
`narrow` lists filters to add when the output was capped, with how many
matches each would keep.

## Warnings (stderr)

forhunt never drops input silently; it warns (unless `-q`) about: unreadable
or non-artifact files, folders it cannot search (permissions, link loops),
byte-identical duplicates (opened once), two different files holding the same
log with overlapping EventRecordIDs (likely two collections: shared events
counted twice), truncated or corrupt chunks, and `show` ids whose record
header id and System/EventRecordID differ (exported logs; the warning gives
the forhunt id of the other reading).

## Exit codes

0 ok (including zero matches), 1 error, 2 usage, 3 no readable input,
4 corrupt input with `--strict`. Corrupt chunks and records are otherwise
counted (`bad_chunks`, `bad_records`) and parsing continues.

PowerShell 4104: long scripts are split into numbered blocks
(`MessageNumber` of `MessageTotal`); `-f MessageNumber=1` keeps the first
block of each, which is enough to see what ran and keeps module code out.
