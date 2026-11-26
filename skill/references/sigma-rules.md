# Sigma rules with forhunt

`forhunt sigma` runs Sigma and Hayabusa rules over the evidence with
forhunt's own engine, in one parallel pass: no Hayabusa binary. It reads the
same rule files Hayabusa does, plus rules you write, and works on every
forhunt artifact (event logs, `$MFT`, `$J`, prefetch, registry, mail).

## Licence and credit

The rule set the installer downloads is Yamato Security's
[hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules): their own
rules and a curated copy of [SigmaHQ](https://github.com/SigmaHQ/sigma)'s,
under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
It allows using the rules on any data on one condition: a message based on a
match keeps the rule's author. forhunt puts it in `auth` on every detection;
when a report finding rests on a rule, name the rule and its author. Do not
copy rule files into reports or repositories (that is sharing them, which
needs the author, a link and the licence).

## Running

```bash
forhunt sigma EVIDENCE --min-level medium -g          # overview: one line per rule and host
forhunt sigma EVIDENCE --rule-id RID -n 50            # one rule, detection by detection
forhunt sigma EVIDENCE -R "$CASE/rules"               # only your rules
forhunt sigma EVIDENCE -R ~/.local/share/forensic-hunter/rules -R "$CASE/rules"   # both
forhunt sigma EVIDENCE --since 2024-03-11T10:00:00Z --until 2024-03-11T12:00:00Z
forhunt sigma EVIDENCE -R "$CASE/rules" --list-rules  # what loaded (JSONL)
forhunt sigma EVIDENCE -F jsonl -n 0 -o "$CASE/work/sigma.jsonl"   # every detection with its full event
```

| Option | Meaning |
|---|---|
| `-R DIR` | rule folders or files, repeatable. Default: `$FORHUNT_RULES`, else `<prefix>/rules` (holds `hayabusa-rules/` and `custom/`) |
| `--min-level L` | informational, low (default), medium, high, critical |
| `--noisy` / `--deprecated` | also run `noisy_rules.txt` rules / deprecated and unsupported rules |
| `--rule-id ID` | only these rules (repeatable) |
| `-g` | group per (rule, host): `n`, `first`, `last`, `eid`, up to 5 `ids` |
| `-n N` | cap (default 200; the most severe detections are kept) |

`llm` keys: `id` (forhunt id for `show`), `t`, `h`, `ch`, `eid`, `rec`
(EventRecordID), `lvl`, `rule`, `rid` (rule id), `mitre`, `auth`, `d` (the
rule's `details` template filled in, else the event's key fields). Summary:
`detections`, `rules`, `rules_hit`, `rules_not_loaded`, `levels`,
`top_rules`, `top_hosts`.

stderr gives the load summary: rules loaded, rules skipped by design
(deprecated, unsupported, noisy, excluded, below the level, correlation rules,
`count()` aggregations, `expand` placeholders without values) and rules that
did not compile, with the reason. Nothing is dropped silently.

## Writing a rule

```yaml
title: Rclone Upload to Cloud Storage          # short, specific
id: 6f0c2c1e-5a1b-4c3e-9d1f-0a8b7c6d5e4f       # a new UUID (uuidgen)
status: experimental
description: rclone copying data to a cloud remote (exfiltration).
author: <analyst or case id>
date: 2026-11-26
tags:
    - attack.exfiltration
    - attack.t1567.002
logsource:                                     # documentation only for forhunt
    product: windows
    category: process_creation
detection:
    process:                                   # ALWAYS name Channel and EventID
        - Channel: Security
          EventID: 4688
        - Channel: Microsoft-Windows-Sysmon/Operational
          EventID: 1
    selection_img:
        - NewProcessName|endswith: '\rclone.exe'     # Security 4688 name
        - Image|endswith: '\rclone.exe'              # Sysmon 1 name
        - CommandLine|contains: ' --config '
    selection_cmd:
        CommandLine|contains:
            - ' copy '
            - ' sync '
    filter_local:
        CommandLine|contains: ' C:\Backup\'
    condition: process and 1 of selection_img and selection_cmd and not filter_local
details: 'Cmdline: %CommandLine% ¦ User: %SubjectUserName%'
level: high
falsepositives:
    - Backup jobs that use rclone
```

Rules of thumb:
- **Name `Channel` and `EventID`.** forhunt picks the rules to try for each
  event from them, and skips decoding events no rule can match. A rule without
  them is tried on every event of every log.
- Give each selection literal text to look for (`contains`, `endswith`,
  equality): forhunt only evaluates a rule on events where one of its
  literals appears. A rule made only of regexes or `not` runs on every
  candidate event.
- Prefer `endswith: '\name.exe'` to `contains: 'name'`, and lists to regexes.
- Security 4688 and Sysmon 1 name fields differently (`NewProcessName` /
  `Image`, `ParentProcessName` / `ParentImage`, `SubjectUserName` / `User`):
  cover both, as above, or write one rule per source.
- Levels: `critical` (near-certain compromise), `high`, `medium`, `low`,
  `informational` (context, not suspicious by itself).

## Matching (what forhunt does)

- Values match **case-insensitively** unless `|cased`; whole value by default.
- Wildcards: `*` (any run), `?` (one character). `\*`, `\?` and `\\` are
  escapes: `C:\Windows\*.exe` is the literal text `C:\Windows*.exe`; write
  `C:\Windows\\*.exe` for "a file under C:\Windows". Other backslashes are
  plain (`C:\Users\`).
- A list of values is OR; `|all` makes it AND. A map is AND of its fields; a
  list of maps is OR. A list of strings (no field) is a keyword search over
  every value of the event.
- `Field: null` holds when the field is absent or empty; `Field: ''` too
  (Hayabusa's reading); `Field|exists: false` only when absent.
- Modifiers: `contains`, `startswith`, `endswith`, `all`, `cased`, `re` (with
  `i`, `m`, `s`; Rust regex syntax: no look-around or back-references),
  `windash` (`-` / `/` / en dash / em dash / horizontal bar as option dash),
  `cidr` (IPv4, IPv6; `::ffff:10.0.0.5` is `10.0.0.5`), `base64`,
  `base64offset`, `wide` / `utf16le` / `utf16be` / `utf16` (with base64),
  `fieldref` (`equalsfield`, `endswithfield`), `exists`, `gt` / `gte` / `lt` /
  `lte` (numbers, `0x` hex too), `expand` (`%name%` from
  `config/expand/name.txt` next to your rules, one value per line).
- Conditions: `and`, `or`, `not`, parentheses, `1 of sel*`, `all of sel*`,
  `1 of them`, `all of them` (`them` leaves out selections named `_...`), or
  a list of conditions (OR).
- Not supported (reported at load): correlation rules (`correlation:`) and
  `| count()` aggregations. For counts, use `forhunt stats` / `search` and
  judge thresholds yourself.
- Values are compared as written in the rule (`0x1410` stays text; YAML does
  not turn it into a number).

## Field names

A field is found by its name in the event (exact, then ignoring case). Look
at real names first: `forhunt search EVIDENCE -c <channel> -e <id> -n 1 -F jsonl`
(or `forhunt show <id>`) prints every field.

Event logs:
- `System` values: `Channel`, `EventID`, `Provider_Name`, `Computer`,
  `Level` (number), `Keywords`, `SecurityUserID`, `ExecutionProcessID`,
  `EventRecordID`.
- `EventData`: each `<Data Name="X">` is `X`. Unnamed `<Data>` items: `Data`
  matches any of them (`Data[1]`, `Data[2]`... in forhunt output).
- `UserData`: the leaf element names (`SubjectUserName` of a 1102, `Param1`
  of TS 1149). Hayabusa's alias names (`eventkey_alias.txt`, e.g.
  `LogFileClearedSubjectUserName`) work with the hayabusa-rules config.

forhunt artifacts (no `Provider_Name`; `Computer` is set from the `SYSTEM`
hive of the collection when there is one):

| Channel | EventID | Fields |
|---|---|---|
| `Prefetch` | 1 | `ExecutableName`, `ExePath`, `Hash`, `RunCount`, `RunIndex`, `RunTimes`, `VolumeNames`, `Directories`, `FilesLoaded` |
| `MFT` | 16 / 48 | `$SI` / `$FILE_NAME` timestamps: `MACB`, `Path`, `FileName`, `FileSize`, and when they apply `Deleted`, `SiLtFn`, `uSecZeros`, `ZoneIdContents` (`references/ntfs-hunting.md`) |
| `UsnJrnl` | 1-6 | `Reason`, `FileName`, `Path`, `FileAttributes` (`references/ntfs-hunting.md`) |
| `Registry` | 2, 10-12, 20-23, 30, 40-42 | as in `references/forhunt.md` (Registry): e.g. 10 `KeyPath`, `Name`, `Command`; 11 `ServiceName`, `ImagePath`; 21 `ExePath`, `Sha1` |
| `Mail` | 1 / 2 / 3 | message (`User`, `Mailbox`, `Folder`, `From`, `To`, `Subject`, `Urls`, `Body`, `Headers`...), attachment (`FileName`, `Sha256`...), contact (`Name`, `Email`) |

Example, a prefetch rule (tools run from a user profile):

```yaml
detection:
    selection:
        Channel: Prefetch
        EventID: 1
        ExePath|contains: '\USERS\'
        ExecutableName|endswith:
            - '.EXE'
    filter:
        ExePath|contains: '\APPDATA\LOCAL\MICROSOFT\TEAMS\'
    condition: selection and not filter
```

## Test loop (always)

1. Write the rule to `$CASE/rules/<name>.yml` (never inside the evidence).
2. Check it loads: `forhunt sigma "$CASE/evidence" -R "$CASE/rules" --list-rules`.
   stderr names any rule that did not compile and why.
3. Positive check: run it on the evidence (or the event you wrote it for:
   `--since`/`--until` around it) and confirm the hits with `forhunt show`.
4. Negative check: `-g` on the whole evidence; a rule that fires on hundreds
   of benign events needs a `filter_*` selection, not a higher level.
5. When the rule is worth keeping beyond the case, copy it to
   `~/.local/share/forensic-hunter/rules/custom/` (Windows:
   `%LOCALAPPDATA%\forensic-hunter\rules\custom\`): it then runs with every
   `forhunt sigma`, and forhunt-viewer can load the same folder (Settings >
   Detection rules > Add folder).
