# Windows logon types (Security 4624 / 4625 `LogonType`)

Reference for reading `LogonType` when walking the lateral-movement, remote-access and
initial-access checklists. Read it together with `LogonProcessName`,
`AuthenticationPackageName`, `IpAddress`, `WorkstationName` and `ProcessName` from the same event.

**Confidence tags.** `[S]` = observed or stated in a source I actually read (see Sources at the
bottom). `[M]` = analyst knowledge not confirmed by any source I could open. Microsoft Learn
(the 4624 documentation page) was not reachable from the research environment (egress policy),
so every definition below that is not tagged `[S]` should be checked against Microsoft's
4624 page before it is used in a report.

## Table of logon types

| Type | Name | Meaning | Typical source | Credentials cached on the target host? | Forensic notes |
|---|---|---|---|---|---|
| 0 | System | Logon by the OS itself, at boot, before a user session | Boot / system start `[S]` (Hayabusa: "happens when the computer boots up") | n/a | Not a human logon; expect SYSTEM, no `IpAddress`. |
| 1 | (not used) | No defined meaning in 4624 | n/a | n/a | Do not expect it. `[M]` |
| 2 | Interactive | Logon at the local console (keyboard) | Console, hypervisor console, `runas` for a full logon, local `su`-style tools | Yes: plaintext/hash-equivalents in LSASS memory `[S]` (Hayabusa) | `IpAddress` is `-` or `127.0.0.1`. A type 2 on a server nobody sits at, or with `LogonProcessName` User32 plus a remote `WorkstationName`, deserves a look (console/virtualization access, or tools that fake it). |
| 3 | Network | Access to a resource over the network without a session: SMB shares, RPC, WMI, WinRM, remote service/task management, IIS integrated auth | Every remote administration tool that does not create a desktop. `[S]` JPCERT: PsExec, WMI (`wmic`, `wmiexec.vbs`), WinRM/WinRS, `schtasks`, Mimikatz/WCE remote login all produced type 3 on the target | No: a network logon does not leave reusable credentials in the target's LSASS (key property of network logons; widely documented, `[M]` for this wording) | The workhorse of lateral movement. Read the pair `LogonProcessName`/`AuthenticationPackageName`: `NtLmSsp`/`NTLM` (JPCERT: PsExec, schtasks, pass-the-hash tools) versus `Kerberos`/`Kerberos` (JPCERT: WinRM, WinRS, WMI in a domain). `KeyLength` was `128` for NTLM in all JPCERT lab runs including pass-the-hash, so `KeyLength 0` is not a reliable PtH marker (see FH-LAT-012). Anonymous (`ANONYMOUS LOGON`) type 3 is common and noisy. Many type 3 events are machine accounts (`$`). |
| 4 | Batch | Run as a scheduled task / batch job on behalf of a user | Task Scheduler running a task under a user account with stored credentials `[M]` | Credentials are retrieved from the LSA secret store and live in memory for the job `[M]` | Chainsaw and Hayabusa have a rule for type 4 `[S]` but without semantics. A remote `schtasks /create` produces a type 3 on the target at creation time `[S]` (JPCERT), then a type 4 (or a SYSTEM-session task with no 4624) when it runs `[M]`. |
| 5 | Service | A service started under its configured account | Service Control Manager; `LogonProcessName` Advapi `[S]` (JPCERT saw it for the WMI host process) | The service account's credentials are in LSA secrets and in memory while the service runs `[M]` | Frequent for SYSTEM/NETWORK SERVICE/LOCAL SERVICE; services under a named domain account produce one per start. A new service account logon right after a 7045 is the "service actually started" signal. LocalSystem service starts may reuse the existing SYSTEM logon session and not generate a fresh 4624 `[M]`. |
| 6 | (not used) | Not defined for 4624 | n/a | n/a | Do not expect it. `[M]` |
| 7 | Unlock | Workstation unlock / reconnect to a locked session | Console unlock; RDP reconnect can log it `[M]` | Uses the credentials already in the session: yes, cached in memory `[M]` | Hayabusa and Chainsaw have type 7 rules `[S]`. For RDP reconnects look for 4778 and LocalSessionManager 25 `[S]` rather than relying on the type; JPCERT's mstsc sheet shows 4778/25 for reconnect but its type 7/10 value for the reconnect event was not stated. |
| 8 | NetworkCleartext | Network logon where the password reaches the server in a form that can be validated in cleartext by the auth package, typically IIS Basic authentication | IIS Basic auth, some POP/IMAP/mail relay, some scripts `[S]` Hayabusa: "despite the naming, the password is not sent over the network in cleartext. Usually IIS Basic Authentication" | Possibly retained in memory on the server for the session `[M]` | Appears in web-based brute force (`LogonType 8` in 4625 for IIS Basic) and with legacy WDigest-style behaviour. Not used by RDP/SMB/WinRM. |
| 9 | NewCredentials | Process keeps the current identity locally but uses *different* credentials for outbound network connections | `runas /netonly`, Mimikatz `sekurlsa::pth`, Cobalt Strike `make_token`, tools that call `LogonUser` with `LOGON32_LOGON_NEW_CREDENTIALS` `[S]` (Sigma/Hayabusa) | Yes, but on the host where it was created: the alternate credentials sit in that host's LSASS for outbound use `[S]` (Hayabusa: creds in memory) | `LogonProcessName seclogo` with `AuthenticationPackageName Negotiate` is the signature `[S]`. This event is logged on the *source* machine, not the one being attacked. `TargetUserName` is the alternate identity. Benign: admins using `runas /netonly`. Follow with 4648 and a type 3 on the remote host. |
| 10 | RemoteInteractive | Interactive desktop session over Remote Desktop Services (RDP, RD Gateway), also Remote Assistance | RDP client (mstsc, FreeRDP, xfreerdp, rdesktop, and any RDP-based tool) `[S]` (JPCERT mstsc: type 10, `User32`, Negotiate) | Yes: plaintext/hash-equivalent credentials are in LSASS on the target unless Restricted Admin or Remote Credential Guard is used `[S]` for "creds in memory" (Hayabusa), `[M]` for the exceptions | `IpAddress` is the RDP client (or the gateway/jump host). `127.0.0.1`/`::1` suggests tunnelling `[S]` (Sigma). Pair with RemoteConnectionManager 1149 and LocalSessionManager 21/22. With Restricted Admin the session is a network-type logon with no reusable credentials `[M]`. Failed RDP guesses may appear as type 3 (NLA) or 10 (no NLA) in 4625 `[M]`. |
| 11 | CachedInteractive | Interactive logon validated against locally cached domain credentials (domain controller unreachable) | Laptops off the corporate network; console | Yes, and cached verifiers (MSCache) exist on disk `[S]` for "creds in memory" (Hayabusa) | A cached logon on a server that is online may mean DC trouble or an unusual path. `IpAddress` is usually `-`. |
| 12 | CachedRemoteInteractive | RDP session validated against cached credentials | RDP from/to a host that cannot reach a DC | Yes `[S]` (Hayabusa) | Same as type 10 but with the DC unreachable; rare enough to review. |
| 13 | CachedUnlock | Unlock of a session using cached credentials | Console unlock without DC contact | Yes `[S]` (Hayabusa) | Rare; informational. |

## Which logon types to expect per remote technique

Observations tagged `[S]` come from the JPCERT/CC Tool Analysis Result Sheet lab runs
(`details/*.htm`, destination host, Windows 7/2008-era domain) and Sigma/Hayabusa/Chainsaw
rule definitions; everything else is `[M]`. Newer Windows builds may differ, and the lab
environments define Kerberos vs NTLM: confirm on your own samples.

| Technique | Source host logon | Target host logon (4624) | Notes |
|---|---|---|---|
| RDP (mstsc) | 4648 for explicit creds `[S]` | Type 10, `User32`, Negotiate `[S]`; reconnect: 4778 / LSM 25 `[S]`, 4624 type 7 `[M]` | Restricted Admin: type 3 `[M]`. Exposed RDP with NLA: failures as 4625 type 3 `[M]`. |
| PsExec | None special; 4648 only if `-u` used `[M]` | Type 3 `NtLmSsp` / NTLM `[S]` (JPCERT, password-based, NTLM, `KeyLength 128`); then a service start (7045, SYSTEM) | PsExec `-u` starting the child as another user may add a further logon `[M]`. Impacket `psexec.py` also type 3 `[M]`. |
| WMI (`wmic /node`, `wmiexec`) | 4648 with `wmic` as `ProcessName` `[S]` | Type 3 Kerberos or NTLM `[S]`; the WMI host process also shows a type 5 (Advapi/Negotiate) `[S]` | Processes then run under `WmiPrvSE.exe`. |
| WinRM / PowerShell remoting / WinRS | 4648 `[S]` | Type 3, Kerberos in a domain `[S]` (`KeyLength 0` for Kerberos) | WinRM/Operational 169 and process `wsmprovhost.exe` (Sigma) accompany it `[S]`. |
| SMB share access (`net use`, `\\host\C$`) | None special | Type 3 (NTLM or Kerberos); 5140 / 5145 follow `[S]` | JPCERT's `net use` sheet records 5140 on the destination; the 4624 type was not extracted. |
| `runas /netonly` | Type 9 `seclogo` / Negotiate on the *source* `[S]` | Type 3 on the remote host when the process connects `[S]` | Same pattern as pass-the-hash tools using `sekurlsa::pth`. |
| Remote scheduled task (`schtasks /s`, `atexec`) | 4648 `[S]` | Type 3 `NtLmSsp` / NTLM at creation `[S]`; task executes later under its principal (type 4 batch, or no new 4624 for SYSTEM) `[M]` | 4698, TaskScheduler 106/200/201 `[S]`. |
| Remote service (`sc \\host`, smbexec, PsExec) | None special | Type 3 for the SCM RPC `[S]`; service start type 5 when it runs under a named account, none or SYSTEM-session for LocalSystem `[M]` | 7045 / 4697 `[S]`. |
| DCOM (MMC20 etc.) | 4648 possible `[M]` | Type 3 `[M]` | No DCOM-specific log; process tree is the evidence. |
| Pass-the-hash / overpass-the-hash tooling | Type 9 `seclogo` on the host running the tool `[S]` | Type 3, NTLM (PtH) or Kerberos (overpass) `[S]` for the Mimikatz/WCE sheets | WCE and Mimikatz PtH showed `KeyLength 128` on NTLM `[S]`. |

## Reading tips

- `LogonType` alone never identifies a technique. Always pair it with `LogonProcessName`,
  `AuthenticationPackageName`, `ProcessName`, `IpAddress`, `WorkstationName` and the next events
  on the same host.
- `TargetLogonId` of a 4624 is the join key to later events in that session (4672 `SubjectLogonId`,
  4688 `SubjectLogonId`, 5140/5145 `SubjectLogonId`, 4634 `TargetLogonId`).
- 4625 contains the same field, but the logon type in a failure is the *attempted* type.
- Remote logons where `IpAddress` is `-` are not necessarily local: some auth paths do not populate it
  (check `WorkstationName` and `LogonProcessName`).

## Sources (files actually read)

- https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon (per-type 4624 rules: 0, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13; "creds in memory" notes; type 8 note; type 9 token-impersonation rule)
- https://github.com/WithSecureLabs/chainsaw/tree/master/rules/evtx/lateral_movement (type 2, 3, 4, 5, 7, 10 rule definitions)
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_overpass_the_hash.yml (type 9 + seclogo + Negotiate)
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_pass_the_hash_2.yml (type 3 NtLmSsp KeyLength 0; type 9 seclogo)
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_rdp_localhost_login.yml (type 10 from loopback)
- https://github.com/JPCERTCC/ToolAnalysisResultSheet/tree/master/details (PsExec.htm, WinRM.htm, WinRS.htm, wmic.htm, schtasks.htm, mstsc.htm, wmiexec-vbs.htm, RemoteLogin-Mimikatz.htm, RemoteLogin-WCE.htm, net-use.htm: observed 4624 LogonType / LogonProcessName / AuthenticationPackageName / KeyLength per tool)
- Not readable from the research environment: Microsoft Learn event 4624 page, the Microsoft "Mitigating Pass-the-Hash" paper. Check `[M]` cells against them.
