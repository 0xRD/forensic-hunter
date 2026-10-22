# Worked example: insecurebank.local

A complete session following `SKILL.md`, on the 18 files of the public
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
dataset (GPL-3.0, commit `4ceed2f`) recorded in the `insecurebank.local` lab
domain (DC `DC1`, workstation `alice`). The dataset is a set of separate
technique captures made between March and November 2019, not one intrusion:
the analysis treats it as one case to show the method, and the report states
this limitation. Commands are real; outputs are trimmed (`…`).

Tools: forhunt 0.1.0, Hayabusa 4.2.0 (rules bundled with the release).

## a. Evidence intake

```bash
bash skill/scripts/fetch-samples.sh ~/samples
CASE=~/cases/insecurebank; mkdir -p $CASE/{evidence,work}
cd ~/samples/EVTX-ATTACK-SAMPLES
# the 18 files recorded on insecurebank.local hosts
find . -name '*.evtx' | sort | while IFS= read -r f; do
  forhunt search "$f" -q -F jsonl -n 1 -f 'Computer~insecurebank.local' | grep -q . && cp -a "$f" $CASE/evidence/
done
chmod -R a-w $CASE/evidence
(cd $CASE/evidence && find . -name '*.evtx' -exec sha256sum {} + | sort -k2) > $CASE/work/hashes-before.txt
```
```text
b058ae02bbed9692…3dce36c  ./4624_LT3_AnonymousLogon_Localhost_-_JuicyPotato.evtx
f09f993909deb7ac…a3dce36c  ./ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx
…  (18 files)
```

## b. Triage

```bash
forhunt stats $CASE/evidence -q > $CASE/work/stats.jsonl
```
```json
{"stats":{"files":18,"events":149,"first":"2019-03-25T09:09:14.916619Z","last":"2019-11-26T23:55:02.000000Z","hosts":2,"bad_chunks":0,"bad_records":0}}
{"present":{"App":{"325":1,"326":1,"327":2},"Sysmon":{"1":11,"3":11,"10":8,"11":8,"12":3,"13":1,"18":3},"WinRM":{"91":1},"Sec":{"1102":4,"4624":1,"4634":1,"4662":32,"4702":4,"4719":8,"4738":5,"4742":4,"5136":40}}}
{"top_hosts":[["DC1.insecurebank.local",118],["alice.insecurebank.local",31]],"top_accounts":[["bob",63],["DC1$",15],["NT AUTHORITY\\SYSTEM",11],["insecurebank\\Administrator",11],…]}
{"log_tampering":[{"id":"792dbe0a:1","t":"2019-03-25T09:09:14.916619Z","ch":"Sec","eid":1102,"user":"bob"}, … {"id":"aceceead:1","t":"2019-11-15T08:19:02.298512Z","ch":"Sec","eid":1102,"user":"bob"}]}
```

Analyst notes:
- Only Security, Sysmon, Application and WinRM/Operational exist. No System,
  PowerShell, TaskScheduler, TerminalServices or Defender logs: every check on
  those is `LOG_SOURCE_MISSING`. Security has no 4688, 4625, 4768/4769/4776,
  5140/5145: logon, Kerberos and share activity is largely invisible.
- Four Security log clears (1102) by `bob` and `administrator`.
- `bob` (a regular user by name) dominates DC1 Security activity.

## c. Detections

```bash
hayabusa dfir-timeline -d $CASE/evidence -t jsonl -p verbose -O -w -q -K -N -C -o $CASE/work/hayabusa.jsonl
forhunt hayabusa $CASE/work/hayabusa.jsonl -p $CASE/evidence --min-level medium -g
```
```json
{"rule":"HackTool - Dumpert Process Dumper Execution","lvl":"critical","h":"alice.insecurebank.local","n":1,"first":"2019-06-21T07:35:37.185149Z",…,"ids":["0bc6e267:1"]}
{"rule":"HackTool - Dumpert Process Dumper Default File","lvl":"critical","h":"alice.insecurebank.local","n":3,…,"ids":["0bc6e267:3",…]}
{"rule":"Log Cleared","lvl":"high","h":"DC1.insecurebank.local","n":3,"first":"2019-03-25T09:09:14.916619Z","last":"2019-05-08T03:00:11.778188Z","eid":[1102],…}
{"rule":"Powerview Add-DomainObjectAcl DCSync AD Extend Right","lvl":"high","h":"DC1.insecurebank.local","n":18,"first":"2019-03-25T21:28:45.022631Z",…,"ids":["ab178b42:11",…]}
{"rule":"Hijack Legit RDP Session to Move Laterally","lvl":"high","h":"alice.insecurebank.local","n":1,…,"ids":["6088c057:2"]}
{"rule":"RottenPotato Like Attack Pattern","lvl":"high","h":"alice.insecurebank.local","n":1,…,"ids":["aceceead:2"]}
{"rule":"Windows Default Domain GPO Modification","lvl":"medium","h":"DC1.insecurebank.local","n":22,…}
{"rule":"Active Directory Replication from Non Machine Account - DcSync Indicator","lvl":"medium","h":"DC1.insecurebank.local","n":4,…}
{"rule":"Possible DC Shadow Attack","lvl":"medium","h":"DC1.insecurebank.local","n":2,…,"ids":["4662e471:3","4662e471:5"]}
…  (27 groups)
{"summary":{"cmd":"hayabusa","detections":92,"shown":92,"below_min_level":84,"with_forhunt_id":92,"levels":{"critical":4,"high":37,"medium":51},…}}
```
`-g` collapses 92 detections into 28 lines; every group carries forhunt ids
for `forhunt show`.

## d. Checklist walk

The sweep evaluates all 242 checks in one pass and pre-fills the status file:

```bash
forhunt checklist $CASE/evidence -k skill/references/checklists/checklists.json -o $CASE/work/checklist-status.md
```
```text
| Tactic | HIT? | NO_HIT | NOT_APPLICABLE | LOG_SOURCE_MISSING | REVIEW |
| initial-access | 0 | 8 | 0 | 8 | 0 |
| persistence | 3 | 9 | 0 | 11 | 0 |
| defense-evasion | 4 | 1 | 0 | 18 | 0 |
| credential-access | 1 | 5 | 0 | 15 | 0 |
| active-directory | 6 | 9 | 0 | 15 | 0 |
…
```

Each `HIT?` is then reviewed. Examples of the reasoning:

**FH-AD-005 (DCSync, 4662)**: the sweep reports matches in two files.
```bash
forhunt search $CASE/evidence -c Security -e 4662 -r 'Properties=1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c'
```
```json
{"id":"792dbe0a:2","t":"2019-03-25T10:05:30.695604Z","h":"DC1.insecurebank.local","eid":4662,"d":{"s_user":"DC1$",…,"props":"%%7688\r\n\t\t{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}…"}}
{"id":"85641d06:3","t":"2019-05-08T02:10:43.487217Z","h":"DC1.insecurebank.local","eid":4662,"d":{"s_user":"Administrator",…,"props":"%%7688\r\n\t\t{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}…"}}
```
The `DC1$` events are the DC's own replication (expected: false positive per
the check). `Administrator` exercising *DS-Replication-Get-Changes-All*
(`1131f6ad…`) is a user account requesting replication: **HIT** (DCSync),
High confidence for the fact, Medium that it was malicious (lab context).

**FH-AD-006 (DCSync rights granted, 5136)**: the sweep's 18 matches, then
the `narrow` suggestion of a broader search led to the right window:
```bash
forhunt search $CASE/evidence -e 5136 --since 2019-03-25T21:00:00Z --until 2019-03-25T21:59:59Z -n 3
```
```json
{"id":"ab178b42:11","t":"2019-03-25T21:28:45.022631Z","h":"DC1.insecurebank.local","eid":5136,"d":{"s_user":"bob","dn":"DC=insecurebank,DC=local","class":"domainDNS","attr":"nTSecurityDescriptor","attr_val":"O:BAG:BAD:AI(OA;CIIO;RP;…[+3142 chars]","op":"%%14675"}}
```
`bob` rewrote the domain root's security descriptor 18 times within 4 ms,
34 s after clearing the Security log (`ab178b42:1`): **HIT**.

**FH-AD-024 (GPO tampering)**: 22 `versionNumber` changes on the two default
GPOs by `bob` between 10:33 and 12:33 on 2019-03-25: **HIT** (the change
content itself is in SYSVOL, not in EVTX: blind spot).

**FH-DEF-005 (audit policy, 4719)**: 8 events, all by `DC1$` within seconds
after `bob`'s GPO edits: consistent with policy application. Downgraded to
**NO_HIT** with that reason (Medium confidence).

**FH-AD-028 (NTLMv1)** and **FH-PRV-015 (RottenPotato)** point at the same
event `aceceead:2`: an ANONYMOUS LOGON type 3 from 127.0.0.1 with NTLM V1 on
`alice`, 14 s after a log clear: **HIT** for FH-PRV-015; FH-AD-028 is
downgraded to **NO_HIT** (the only NTLM V1 logon is this loopback artefact,
not domain NTLMv1 use).

All other rows were confirmed or downgraded the same way; rows for missing
sources stay `LOG_SOURCE_MISSING`. The final table is in the report.

## e. Timeline

```bash
forhunt timeline $CASE/evidence -e 1,3,10,11,12,13,18,91,325,326,327,1102,4624,4662,4742 -f 'SubjectUserName!=DC1$' -n 80
```
```json
{"id":"0bc6e267:1","t":"2019-06-21T07:35:37.185149Z","h":"alice.insecurebank.local","ch":"Sysmon","eid":1,"ti":"Process created","d":{"user":"insecurebank\\Administrator","img":"C:\\Users\\administrator\\Desktop\\x64\\Outflank-Dumpert.exe",…}}
{"id":"0bc6e267:2","t":"2019-06-21T07:35:37.329185Z","h":"alice.insecurebank.local","ch":"Sysmon","eid":10,"ti":"Process accessed","d":{"src_img":"…\\Outflank-Dumpert.exe","dst_img":"C:\\Windows\\system32\\lsass.exe","access":"0x1fffff",…}}
{"id":"0bc6e267:3","t":"2019-06-21T07:35:37.329185Z","h":"alice.insecurebank.local","ch":"Sysmon","eid":11,"ti":"File created","d":{"img":"…\\Outflank-Dumpert.exe","file":"C:\\Windows\\Temp\\dumpert.dmp"}}
…
```

## f. Report

Integrity re-check before reporting:
```bash
(cd $CASE/evidence && find . -name '*.evtx' -exec sha256sum {} + | sort -k2) > $CASE/work/hashes-after.txt
cmp $CASE/work/hashes-before.txt $CASE/work/hashes-after.txt && echo "hashes match"
```
```text
hashes match
```

The final report, written from `references/report-template.md`, is
[insecurebank-report.md](insecurebank-report.md); the attack path as a
self-contained page is [insecurebank-attack-path.html](insecurebank-attack-path.html).
