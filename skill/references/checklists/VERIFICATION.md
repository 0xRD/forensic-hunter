# Checklist verification report

Date of the re-check: 2026-10-21. Scope: the 12 YAML checklists in this directory (242 checks).
The checks were written by other agents; this pass re-opened every cited source class independently,
corrected factual errors and recomputed every `verified` flag. Each check now starts its `notes`
field with a `VERIFIED 2026-10-21` or `NOT VERIFIED 2026-10-21` line (what was confirmed by which source
class, and what is still open), followed by the original author's notes after `|| Original notes:`.

## Method

1. **Indexed real logs.** Every `.evtx` file of two public sample sets was parsed with
   `target/release/forhunt parse` and indexed by (channel, EventID) -> field names and observed values.
   Channel strings, provider names, field spelling (for example `url` vs `Url`, `SourceProcessGUID`
   in Sysmon 10) and value formats (hex padding and case, `%%NNNN` message tokens, NT device paths in 5156)
   were compared with what each check claims.
2. **Indexed rule projects.** All Sigma `rules/`, the Hayabusa rule repository, and the Chainsaw rules/mappings
   were parsed (about 7,600 rule files). For each (channel, EventID) pair and each field name it was
   recorded whether a rule uses it. Rule bodies are NOT copied into the checklists; the checks describe
   behaviour in their own words and cite the rule file URL only.
3. **Other source classes.** MITRE CTI `x-mitre-data-component` log sources (`EventCode=N` entries), the
   Sysmon documentation (event list and field names), Microsoft Windows Server documentation (event id
   mentions in the AD DS "Appendix L - Events to Monitor", the advanced audit policy page and the
   RC4/Kerberos pages), and the JPCERT tool analysis sheets (informational, tool-keyword matching).
4. **Decision rule for `verified: true`.** A check is true only when
   - every listed (channel, event id) pair is confirmed by at least **two independent source classes**
     (real sample log, rule project [Sigma/Hayabusa/Chainsaw count as ONE class because they derive from
     each other], MITRE CTI data component, Microsoft/Sysmon documentation), and
   - every field name used in `logic` is seen in a real log, or confirmed by two non-sample classes, and
   - the literal values used (hex codes, `%%` tokens, GUIDs, file names, pipe names) were found in at least
     one opened source, and
   - the detection logic is what a published rule/source describes, not a wider analyst design
     (thresholds that are explicitly flagged as tunable are accepted; correlations/joins, extended parent-child
     lists and analyst-chosen filters are not).
   Otherwise `verified: false` and `notes` states what is open.
5. **Queries.** All 461 `forhunt:` commands were executed against the sample sets and against
   `fixtures/synthetic/dc01` (placeholder `<paths>` replaced): all exit with code 0.
   Field names used in `--field/--regex` were compared against the fields really present in the sampled events.
6. **ATT&CK ids.** Checked against `mitre/cti` `enterprise-attack/enterprise-attack.json` (spec 2.0 bundle):
   revoked techniques and their `revoked-by` replacement were extracted, see below.

### Sources used

| Source | URL / repo path | Used for |
|---|---|---|
| EVTX-ATTACK-SAMPLES (sbousseaden, GPL-3.0, not copied) | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES | real events: 278 files, channels Security, Sysmon, System, Application, PowerShell, BITS, RDP, WinRM, Defender |
| EVTX-to-MITRE-Attack (mdecrevoisier, CC0) | https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack | real events: 293 files, adds AD CS 4886/4887, DNS Server 150/770/771, 4616, 4662, 4674, 4704, 4738 `%%2096`, ESENT, firewall, print service |
| Sysmon docs | https://github.com/MicrosoftDocs/sysinternals (`sysinternals/downloads/sysmon.md`) | Sysmon event ids 1-29, 255 and tags |
| Windows Server docs | https://github.com/MicrosoftDocs/windowsserverdocs (`WindowsServerDocs/identity/ad-ds/plan/Appendix-L--Events-to-Monitor.md`, `.../security-best-practices/advanced-audit-policy-configuration.md`, `security/kerberos/detect-remediate-rc4-kerberos.md`, `administration/windows-commands/dnscmd.md`) | event id mentions for Security/System events |
| MITRE CTI | https://github.com/mitre/cti (`enterprise-attack/enterprise-attack.json`) | log-source event codes per data component; revoked technique ids |
| SigmaHQ | https://github.com/SigmaHQ/sigma | rule semantics and field names (one class with Hayabusa/Chainsaw) |
| Hayabusa rules | https://github.com/Yamato-Security/hayabusa-rules | same class as Sigma |
| Chainsaw | https://github.com/WithSecureLabs/chainsaw | same class as Sigma |
| JPCERT/CC tool sheets | https://github.com/JPCERTCC/ToolAnalysisResultSheet | informational (tool to event id correlation) |
| awesome-event-ids | https://github.com/stuhli/awesome-event-ids | only a pointer repository; not used as a source |

**Not reachable:** `learn.microsoft.com`, `attack.mitre.org`, and the per-event Microsoft Learn security-auditing pages
(`MicrosoftDocs/windows-itpro-docs` -> `windows/security/threat-protection/auditing/event-NNNN.md`): the clone failed
(repository not publicly readable) and `raw.githubusercontent.com` returned 404 on `live`, `public`, `main` and `master`;
`MicrosoftDocs/windows-docs`, `windows-security` and `windows-itpro-docs-pr` were also not clonable. The per-event Microsoft
pages therefore could not be used as a source class; Microsoft evidence is limited to the Windows Server
docs and the Sysmon docs listed above, and the `ms` evidence for Security/System events means "the event id is
documented/listed there", not "the field table was read".

## Per-file counts

| File | Checks | verified true before | false before | true after | false after |
|---|---|---|---|---|---|
| active-directory.yaml | 30 | 14 | 16 | 13 | 17 |
| collection-exfiltration.yaml | 17 | 3 | 14 | 3 | 14 |
| credential-access.yaml | 21 | 9 | 12 | 10 | 11 |
| defense-evasion.yaml | 23 | 7 | 16 | 5 | 18 |
| discovery.yaml | 17 | 2 | 15 | 3 | 14 |
| execution.yaml | 19 | 3 | 16 | 4 | 15 |
| impact.yaml | 19 | 4 | 15 | 4 | 15 |
| initial-access.yaml | 16 | 4 | 12 | 4 | 12 |
| lateral-movement.yaml | 22 | 11 | 11 | 13 | 9 |
| persistence.yaml | 23 | 10 | 13 | 8 | 15 |
| privilege-escalation.yaml | 15 | 7 | 8 | 9 | 6 |
| remote-access.yaml | 20 | 7 | 13 | 4 | 16 |
| **total** | **242** | **81** | **161** | **80** | **162** |

Overall 81 true / 161 false before; 80 true / 162 false after (15 flipped true to false, 14 flipped false to true, 66 true checks kept).
Reasons for the 162 false checks: 94 have confirmed event/field facts but logic that is analyst-designed or wider than any
published rule (values, thresholds, correlations, extended parent/child lists); 51 contain at least one
(channel, event id) pair with fewer than two independent confirmations (channels absent from both sample sets such as
TaskScheduler/Operational, WMI-Activity/Operational, TerminalServices-LocalSessionManager, RDPClient, SMBServer,
DriverFrameworks, PrintService 307, Directory Service 1644, NTLM/Operational, WinRM 80-82/134/142/143/161); 16 depend on a
field or value seen in one source only; 1 other.

### Flipped true to false (15)

| Check | Reason |
|---|---|
| FH-AD-024 | event 5141 only listed in docs (no sample, no rule); attribute `gPCFileSysPath` not found in any opened source |
| FH-AD-025 | 4707 and 4716 only listed in docs; no sample or rule |
| FH-DEF-011 | 1009, 1013, 1015 supported by the rule projects only |
| FH-DEF-012 | Sysmon 255 `Description` field seen only in a rule |
| FH-DEF-016 | Sysmon 25 `Type` field seen only in a rule; no sample of event 25 |
| FH-DEF-018 | the check lists event 4104 (a PowerShell/Operational event) with `ScriptBlockText`; that pair and field are not confirmed by two classes |
| FH-INIT-007 | 1149 is an RCM event (channel `...RemoteConnectionManager/Operational`), not Security; the mixed-channel check cannot be confirmed pair by pair |
| FH-LAT-006 | the 4698 + 4624 logon-id join is an analyst correlation (no rule, JPCERT lab had no 4698) |
| FH-LAT-021 | `HostProcess` field of WMI-Activity 5857 not seen in a sample or rule; channel has no sample |
| FH-PER-007 | TaskScheduler 140/141 and `TaskName` supported by a rule only |
| FH-PER-016 | WMI-Activity 5859 and fields `PossibleCause`, `Query` supported by a rule only |
| FH-RMT-002 | LocalSessionManager 21/22/25 and `Address` supported by a rule only |
| FH-RMT-011 | RDPClient 1024/1102 by a rule only; 1025/1026/1029 not found anywhere |
| FH-RMT-012 | WinRM 81/82/134 not found in any source |
| FH-RMT-013 | WinRM 80/143 not found in any source |

Overrides: FH-AD-020 and FH-AD-026 stay TRUE although one list value each (privileged group names such as DnsAdmins; pipe name FssagentRpc) was not found in any opened source; this is stated in their notes.

### Flipped false to true (14)

FH-AD-006, FH-CRED-007, FH-DEF-006, FH-DEF-015, FH-DISC-016, FH-EXE-019, FH-INIT-003, FH-LAT-004, FH-LAT-005, FH-LAT-009,
FH-LAT-010, FH-PRV-007, FH-PRV-015, FH-RMT-010. In each case the logic is the same as one published rule (checked by reading the
rule) and the event id, channel and field names are present in a real log; the justification is in each check's notes.

## Corrections made (factual errors)

| Check(s) | Error | Fix |
|---|---|---|
| FH-LAT-004, FH-LAT-005, FH-LAT-018 (+ one forhunt query) | `AccessList\|contains: WriteData`: 5145 `AccessList` holds message tokens (`%%4417` = WriteData/AddFile), never the word; 0 of 60 sampled events match `WriteData` | value `%%4417`; query `--field AccessList~%%4417` |
| FH-CRED-008 | ESENT Application events 216/325/326/327 have no field `Data`; they carry `Data[1..8]` (path in `Data[5]` for 325-327, `Data[4]` for 216) | logic now `Data[5]` / `Data[4]` with two selections; two verified queries added |
| FH-EXE-005, FH-EXE-006 | classic PowerShell 400/600 blob is in `Data[3]`, not `Data` | logic and queries use `Data[3]` |
| FH-DEF-002, FH-CRED-008, FH-PER-001, FH-PER-003 | `Provider_Name` is the Sigma spelling; forhunt exposes `Provider` (`--field Provider_Name=` matched 0 rows, `Provider=` matched 2) | logic key and queries use `Provider` |
| FH-PER-018 | BITS-Client 59/60 field is `url`, not `Url` | corrected |
| FH-PER-003, FH-PER-006 | pseudo key `note` inside `logic` (not an event field) | removed, text moved to `notes` |
| FH-AD-011 | two `forhunt:` entries were YAML mappings (unquoted `: `) and so not runnable strings | rewritten as strings |
| FH-COLL-003 | unbalanced quoting `~"\PerfLogs\"` made the query fail to parse | single-quoted |
| FH-DEF-021, FH-INIT-002, FH-INIT-005, FH-INIT-010 | placeholders such as `<start>`, `<ip>`, `<account>` made commands unparseable | example values (2024-05-01T10:00:00Z, 203.0.113.10, jdoe) |
| 26 checks with revoked ATT&CK ids | see next section | current id first, legacy kept |

Other value-format observations (no change needed, recorded for users): 4768 `TicketEncryptionType` is rendered `0x17` in the
samples (regexes with optional zero padding stay valid); 4625 `Status/SubStatus` are lower-case hex in the samples
(forhunt matching is case-insensitive); 5156 `Application` is an NT device path (`\device\harddiskvolume1\...`), so only
`endswith` filters work; `Direction` `%%14592` inbound / `%%14593` outbound; 4662 `ObjectType`
is `%{GUID}`; Sysmon 10 spells `SourceProcessGUID` while Sysmon 8 spells `SourceProcessGuid`; 5145 `ShareName`
is `\\*\IPC$`.

## ATT&CK id changes (mitre/cti enterprise-attack, current bundle)

| Legacy id (revoked) | Replacement id | Checks edited |
|---|---|---|
| T1070.001 Clear Windows Event Logs | T1685.005 | FH-DEF-001, 002, 003, 021, FH-IMP-009 |
| T1562.001 Disable or Modify Tools | T1685 | FH-DEF-007..013, 019, FH-IMP-006..008, 011, 012, FH-EXE-008, FH-PER-003 |
| T1562.002 Disable Windows Event Logging | T1685.001 | FH-DEF-004, 005 |
| T1562.004 Disable or Modify System Firewall | T1686 (Windows host case: T1686.003, which was already listed first) | FH-DEF-014, 015 |
| T1562.006 Indicator Blocking | T1685 (already listed) | FH-DEF-013, 020 |
| T1574.002 DLL Side-Loading | T1574.001 (DLL) | FH-AD-021 |

In every case the replacement id precedes the legacy id in `attack`, and the notes say so. All other ids in the 12 files exist
and are not revoked/deprecated in the bundle.

## Remaining open questions

- Microsoft Learn per-event field tables could not be read (not reachable, `windows-itpro-docs` not clonable). Re-check the
  hex/token meaning of `%%` values and the 4738 `UserAccountControl` tokens against Learn when network access allows.
- Channels with no sample in either dataset and a single rule source (NTLM/Operational 8001-8004, DriverFrameworks 2003/2100,
  PrintService 307, TaskScheduler 106/129/140/141/200, WMI-Activity 5857-5861, LocalSessionManager 21-25, RDPClient 1024-1102,
  SMBServer/SMBClient security events, Directory Service 1644, TerminalServices-Gateway) need a real log to confirm field names.
- The `ms` evidence for Security/System events is the presence of the event id in Windows Server docs, which is weaker than reading
  the Learn event page; the `cti` evidence is the presence of an `EventCode` in a data-component log source.
- Sysmon events 24, 25, 255 and the fields `Contents` (event 15), `Description` (255) and `Type` (25) have no real sample.
- Checks marked false because of analyst-designed correlation (golden/silver ticket, join of 4698 and 4624, 4624/4672 logon-id
  join, scan/spray thresholds) remain heuristics; thresholds stay tunables, not published values.
- FH-RMT-004 also claims logon types 7 and 12 on reconnect; only type 10 is source-backed.
- FH-INIT-007 and a few other checks put events from several channels under one `channel` value; the schema allows one channel
  per check, so pairs are judged by the channel the event really belongs to.
