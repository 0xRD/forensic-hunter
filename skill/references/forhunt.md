# forhunt reference

`forhunt <command> <paths...> [options]`. Paths are files, directories
(recursive, `*.evtx`) or globs. Inputs are only read (memory-mapped, read-only).

| Command | Purpose | Default format |
|---|---|---|
| `stats` | triage summary: volumes, coverage, accounts, hosts, IPs, logon types, log tampering, record-id gaps, quiet periods | `llm` |
| `search` | events matching filters, in file/record order | `llm`, cap 200 |
| `timeline` | events from all inputs merged by time | `llm`, cap 200 (earliest first) |
| `show <id>... -p <paths>` | one event in full (`-F json|xml|llm`) | `json` |
| `parse` | every event (machine use only) | `jsonl` |
| `hayabusa <file>` | normalise Hayabusa JSON/JSONL output, attach forhunt ids (`-p <evtx dir>`); `-g` groups per rule and host | `llm`, cap 200 |
| `checklist <paths> -k checklists.json` | one-pass sweep of every detection check: log source coverage, query hits, pre-filled status file (`-F md|json`, `--tactic`) | markdown |

## Filters (search, timeline, stats)

| Option | Meaning |
|---|---|
| `-e, --event-id 4624,4625,4720-4738` | event ids (repeatable) |
| `-c, --channel Security` | channel name, alias (`Sec`, `Sys`, `Sysmon`, `PS`, `PSClassic`, `WMI`, `Task`, `TS-LSM`, `TS-RCM`, `RdpCoreTS`, `WinRM`, `Defender`, `BITS`, `Firewall`, `NTLM`, `DS`) or `*` glob |
| `--since T`, `--until T` | ISO 8601; no offset means UTC; `2024-03-11` means midnight UTC |
| `-f, --field Name=value` | case-insensitive equality; numeric when hex (`0x17` = `0x00000017`) |
| `-f Name!=value` | not equal (also true when the field is absent) |
| `-f Name~text` | case-insensitive substring |
| `-r, --regex [Name=]REGEX` | case-insensitive regex on one field, or on every value |
| `--computer HOST` | exact host, or short name of an FQDN |

Repeated options are ANDed; values of one `--event-id` list are ORed. Field
names are those Windows writes in EventData/UserData (`TargetUserName`,
`LogonType`, `IpAddress`, `CommandLine`, `ServiceName`...); `Computer`,
`Channel`, `Provider`, `EventID` work too. Unnamed `<Data>` elements are
`Data[1]`, `Data[2]`...

Other options: `-n, --limit N` (0 = no cap), `-F, --format llm|jsonl|csv`,
`--max-value-len N` (default 256), `--all-fields`, `--tz Europe/Paris`
(display only), `-t, --threads N`, `--strict`, `--checksums`, `-q`.

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

## Exit codes

0 ok (including zero matches), 1 error, 2 usage, 3 no readable input,
4 corrupt input with `--strict`. Corrupt chunks and records are otherwise
counted (`bad_chunks`, `bad_records`) and parsing continues.
