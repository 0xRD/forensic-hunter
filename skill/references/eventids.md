# Forensic event id reference

Columns: Channel | EventID | Name | Key fields | Required audit policy / config | Forensic use.

Provenance warning: Microsoft Learn, MITRE ATT&CK, The DFIR Report, CISA and the JPCERT HTML sheet were
not reachable from the authoring environment. Sysmon names (1-29, 255) were confirmed from the
Microsoft Sysinternals Sysmon documentation source. Windows Defender 5001/5013/1013, Security 1102,
4661, 4662, 4799, 5145, 6416 were seen in opened Sigma rules or the EVTX-to-MITRE catalog (see
"Sources" at the bottom). Everything else is analyst knowledge and is marked `(k)`: treat `(k)` rows as
unverified until checked against a Microsoft page or a real sample. Field names are as rendered in the
event (EventData/UserData).

## Security (Microsoft-Windows-Security-Auditing unless noted)

| Channel | EventID | Name | Key fields | Required audit policy / config | Forensic use |
|---|---|---|---|---|---|
| Security | 1100 (k) | Event logging service shut down | (system only) | Always logged (Provider Microsoft-Windows-Eventlog) | Gap in logging; may be a normal shutdown or tampering |
| Security | 1102 | Audit log cleared | SubjectUserName, SubjectDomainName, SubjectLogonId | Always logged (Provider Microsoft-Windows-Eventlog) | Anti-forensics; pivot SubjectLogonId to 4624 |
| Security | 4616 (k) | System time changed | PreviousTime, NewTime, ProcessName, SubjectUserName | Audit Security State Change | Timestomping / time skew affecting log correlation |
| Security | 4624 (k) | Successful logon | TargetUserName, TargetLogonId, LogonType, IpAddress, WorkstationName, LogonProcessName, AuthenticationPackageName, ElevatedToken | Audit Logon (Success) | Backbone of timeline; type 3 network, 10 RDP, 2 interactive, 9 NewCredentials |
| Security | 4625 (k) | Failed logon | TargetUserName, Status, SubStatus, LogonType, IpAddress | Audit Logon (Failure) | Brute force and spraying; Status/SubStatus give the reason |
| Security | 4634 (k) | Logoff | TargetUserName, TargetLogonId, LogonType | Audit Logoff | Session duration with 4624 |
| Security | 4647 (k) | User-initiated logoff | TargetUserName, TargetLogonId | Audit Logoff | Interactive/RDP logoff |
| Security | 4648 (k) | Logon with explicit credentials | SubjectUserName, TargetUserName, TargetServerName, ProcessName, IpAddress | Audit Logon | runas, lateral movement, PsExec -u |
| Security | 4656 (k) | Handle to an object requested | ObjectName, ObjectType, AccessMask, ProcessName | Audit Handle Manipulation / File System + SACL | Access to sensitive files, LSASS handle requests |
| Security | 4657 (k) | Registry value modified | ObjectName, ObjectValueName, OldValue, NewValue, ProcessName | Audit Registry + SACL | Persistence and defence-evasion registry edits |
| Security | 4661 | Handle to an object requested (SAM/AD) | ObjectType (SAM_USER, SAM_GROUP...), ObjectName, AccessMask, SubjectUserName | Audit SAM (high volume) / Kernel Object | AD/SAM enumeration (net user /domain, RID brute force) |
| Security | 4662 | Operation performed on an object | ObjectType (schema GUID), ObjectName, AccessMask, Properties, SubjectUserName | Audit Directory Service Access + SACL on objects | BloodHound/LDAP read bursts, DCSync (replication GUIDs in Properties) |
| Security | 4663 (k) | Attempt to access an object | ObjectName, AccessMask, ProcessName, SubjectUserName | Audit File System / Removable Storage + SACL | File reads/writes on audited files; removable media copying |
| Security | 4672 (k) | Special privileges assigned to new logon | SubjectUserName, PrivilegeList | Audit Special Logon | Admin-level logons; pivot to 4624 by SubjectLogonId |
| Security | 4673 (k) | Privileged service called | PrivilegeList, ProcessName | Audit Sensitive Privilege Use | Use of privileges like SeDebugPrivilege/SeMachineAccountPrivilege |
| Security | 4688 (k) | Process created | NewProcessName, CommandLine, ParentProcessName, TokenElevationType, SubjectLogonId | Audit Process Creation + "Include command line in process creation events" GPO | Execution evidence when Sysmon is absent |
| Security | 4689 (k) | Process exited | ProcessName, Status | Audit Process Termination | Process lifetime |
| Security | 4697 (k) | Service installed on the system | ServiceName, ServiceFileName, ServiceType, ServiceStartType, SubjectLogonId | Audit Security System Extension | Remote execution (PsExec, SMBexec), persistence |
| Security | 4698 (k) | Scheduled task created | TaskName, TaskContent (XML), SubjectUserName | Audit Other Object Access Events | Persistence, remote task execution |
| Security | 4699 (k) | Scheduled task deleted | TaskName | Audit Other Object Access Events | Cleanup after task-based execution |
| Security | 4700 (k) | Scheduled task enabled | TaskName | Audit Other Object Access Events | Task reactivation |
| Security | 4701 (k) | Scheduled task disabled | TaskName | Audit Other Object Access Events | Disabling security tasks |
| Security | 4702 (k) | Scheduled task updated | TaskName, TaskContentNew | Audit Other Object Access Events | Task hijack |
| Security | 4703 (k) | Token right adjusted | EnabledPrivilegeList, TargetUserName, ProcessName | Audit Token Right Adjusted | Privilege enabling (e.g. SeDebug, SeBackup) |
| Security | 4719 (k) | System audit policy changed | CategoryId, SubcategoryGuid, AuditPolicyChanges | Audit Audit Policy Change | Defence evasion (auditing turned off) |
| Security | 4720 (k) | User account created | TargetUserName, SubjectUserName | Audit User Account Management | Backdoor accounts |
| Security | 4722 (k) | User account enabled | TargetUserName | Audit User Account Management | Re-enabled dormant/guest accounts |
| Security | 4723 (k) | Password change attempted | TargetUserName, SubjectUserName | Audit User Account Management | Self-service change; mass changes |
| Security | 4724 (k) | Password reset attempted | TargetUserName, SubjectUserName | Audit User Account Management | Admin reset; mass resets (lockout of users) |
| Security | 4725 (k) | User account disabled | TargetUserName | Audit User Account Management | Denial of access, impact |
| Security | 4726 (k) | User account deleted | TargetUserName | Audit User Account Management | Cleanup, impact |
| Security | 4728 (k) | Member added to security-enabled global group | MemberName, MemberSid, TargetUserName (group) | Audit Security Group Management | Domain Admins changes |
| Security | 4732 (k) | Member added to security-enabled local group | MemberSid, TargetUserName (group), TargetSid | Audit Security Group Management | Local Administrators / RDP users additions |
| Security | 4738 (k) | User account changed | TargetUserName, UserAccountControl, SidHistory, flags | Audit User Account Management | AS-REP roast enablement, password-never-expires, SID history |
| Security | 4740 (k) | User account locked out | TargetUserName, CallerComputerName | Audit Account Lockout | Spray/brute-force source host |
| Security | 4741 (k) | Computer account created | TargetUserName, SubjectUserName | Audit Computer Account Management | Rogue machine accounts (RBCD, noPac) |
| Security | 4742 (k) | Computer account changed | TargetUserName, AllowedToDelegateTo, ServicePrincipalNames | Audit Computer Account Management | Delegation abuse |
| Security | 4756 (k) | Member added to security-enabled universal group | MemberName, TargetUserName | Audit Security Group Management | Enterprise Admins etc. |
| Security | 4765 (k) | SID history added to an account | TargetUserName, SourceSid | Audit User Account Management | SID history injection |
| Security | 4767 (k) | User account unlocked | TargetUserName | Audit User Account Management | Attacker or helpdesk unlock |
| Security | 4768 (k) | Kerberos TGT requested | TargetUserName, IpAddress, TicketEncryptionType, PreAuthType, Status | Audit Kerberos Authentication Service on DCs | AS-REP roasting, password spray via Kerberos, golden ticket anomalies |
| Security | 4769 (k) | Kerberos service ticket requested | ServiceName, TargetUserName, IpAddress, TicketEncryptionType, Status | Audit Kerberos Service Ticket Operations on DCs | Kerberoasting (0x17), host enumeration bursts |
| Security | 4771 (k) | Kerberos pre-authentication failed | TargetUserName, IpAddress, Status | Audit Kerberos Authentication Service (Failure) | Spraying and brute force |
| Security | 4776 (k) | NTLM credential validation | TargetUserName, Workstation, Status | Audit Credential Validation | NTLM spraying and source workstation |
| Security | 4778 (k) | Session reconnected | AccountName, ClientName, ClientAddress, SessionName | Audit Other Logon/Logoff Events | RDP reconnect source |
| Security | 4779 (k) | Session disconnected | AccountName, ClientName, ClientAddress | Audit Other Logon/Logoff Events | RDP disconnect source |
| Security | 4794 (k) | DSRM administrator password set attempt | SubjectUserName, Workstation | Audit User Account Management on DCs | DSRM backdoor |
| Security | 4798 | User's local group membership enumerated | TargetUserName, CallerProcessName, SubjectUserName | Audit User Account Management | Discovery; very noisy, use for corroboration |
| Security | 4799 | Security-enabled local group membership enumerated | TargetUserName (group), CallerProcessName, SubjectUserName | Audit Security Group Management | Remote local-admin enumeration (SharpHound-style) |
| Security | 4886 (k) | Certificate Services received a certificate request | Requester, RequestId, Attributes | Audit Certification Services on CA | ADCS abuse (ESC attacks) |
| Security | 4887 (k) | Certificate Services approved and issued a certificate | Requester, RequestId, Disposition | Audit Certification Services on CA | Rogue certificate issuance |
| Security | 5136 | Directory service object modified | ObjectDN, AttributeLDAPDisplayName, AttributeValue, OperationType | Audit Directory Service Changes + SACL | AD tampering (SPN, RBCD, GPO, AdminSDHolder) |
| Security | 5137 (k) | Directory service object created | ObjectDN, ObjectClass | Audit Directory Service Changes | New AD objects (GPOs, accounts, trusts) |
| Security | 5140 (k) | Network share accessed | ShareName, IpAddress, SubjectUserName | Audit File Share | Share access, lateral movement, share discovery |
| Security | 5145 | Network share object checked for access | ShareName, RelativeTargetName, IpAddress, AccessMask, SubjectUserName | Audit Detailed File Share (high volume) | Named pipe use (srvsvc, samr, svcctl), admin share writes |
| Security | 5156 (k) | WFP allowed a connection | Application, SourceAddress, DestAddress, DestPort, Direction, ProcessID | Audit Filtering Platform Connection (very high volume) | Network flows by process without Sysmon |
| Security | 5157 (k) | WFP blocked a connection | Application, DestAddress, DestPort | Audit Filtering Platform Connection (Failure) | Scan and blocked C2 attempts |
| Security | 6416 | New external device recognised | DeviceId, DeviceDescription, ClassName, SubjectUserName | Audit PNP Activity | USB mass storage use |

## System

| Channel | EventID | Name | Key fields | Required audit policy / config | Forensic use |
|---|---|---|---|---|---|
| System | 104 (k) | Event log cleared (non-Security logs) | UserData: SubjectUserName, Channel | Always logged (Provider Microsoft-Windows-Eventlog) | Anti-forensics |
| System | 7034 (k) | Service crashed unexpectedly | param1 service, param2 count | Default | Crashing security tools, exploitation |
| System | 7036 (k) | Service entered running/stopped state | param1 service name, param2 state | Default | Service stops of AV/backup/SQL; bursts pre-ransomware |
| System | 7040 (k) | Service start type changed | param1 service, param2 old type, param3 new type | Default | Services disabled |
| System | 7045 (k) | A new service was installed | ServiceName, ImagePath, ServiceType, StartType, AccountName | Default (Service Control Manager) | PsExec/SMBexec, persistence; no user SID in some builds |
| System | 1074 (k) | System shutdown/restart initiated | param1 process, param2 computer, param3 reason, param5 action, param7 user | Default (Provider User32) | Initiator of reboots/shutdown |
| System | 6005 (k) | Event log service started | (system only) | Default (Provider EventLog) | Boot time marker |
| System | 6006 (k) | Event log service stopped | (system only) | Default (Provider EventLog) | Clean shutdown marker |
| System | 6008 (k) | Unexpected shutdown | (time of previous shutdown) | Default (Provider EventLog) | Crash/power-off; forced kill |

## Sysmon (Microsoft-Windows-Sysmon/Operational)

Event names confirmed by the Microsoft Sysinternals Sysmon documentation. Key-fields column lists field names commonly seen; semantics of individual fields follow the Sysmon schema.

| Channel | EventID | Name | Key fields | Required audit policy / config | Forensic use |
|---|---|---|---|---|---|
| Sysmon | 1 | Process creation | Image, CommandLine, ParentImage, ParentCommandLine, User, Hashes, ProcessGuid, OriginalFileName | Sysmon config rule for ProcessCreate | Primary execution evidence with hashes and parent |
| Sysmon | 2 | File creation time changed | Image, TargetFilename, CreationUtcTime, PreviousCreationUtcTime | Config rule | Timestomping |
| Sysmon | 3 | Network connection | Image, SourceIp, DestinationIp, DestinationPort, Initiated, ProcessGuid | Disabled by default; config rule | C2, lateral movement, scans; no byte counts |
| Sysmon | 4 | Sysmon service state changed | State, Version | Cannot be filtered | Sysmon stopped/started: tamper signal |
| Sysmon | 5 | Process terminated | Image, ProcessGuid | Config rule | Process lifetime |
| Sysmon | 6 | Driver loaded | ImageLoaded, Hashes, Signed, Signature | Config rule | BYOVD, rootkit drivers |
| Sysmon | 7 | Image loaded | Image, ImageLoaded, Hashes, Signed | Disabled by default (-l); very high volume | DLL side-loading, injected DLLs |
| Sysmon | 8 | CreateRemoteThread | SourceImage, TargetImage, StartAddress, StartModule | Config rule | Process injection |
| Sysmon | 9 | RawAccessRead | Image, Device | Config rule | Raw disk reads (NTDS/locked files) |
| Sysmon | 10 | ProcessAccess | SourceImage, TargetImage, GrantedAccess, CallTrace | Config rule (filter heavily) | LSASS access / credential theft |
| Sysmon | 11 | FileCreate | Image, TargetFilename | Config rule | Dropped files, staging, ransom notes, PST |
| Sysmon | 12 | Registry object create/delete | EventType, TargetObject | Config rule | Persistence keys |
| Sysmon | 13 | Registry value set | TargetObject, Details | Config rule | Run keys, service Start, Defender policies |
| Sysmon | 14 | Registry key/value rename | TargetObject, NewName | Config rule | Registry evasion |
| Sysmon | 15 | FileCreateStreamHash | TargetFilename, Hash, Contents | Config rule | Mark-of-the-Web / ADS |
| Sysmon | 16 | Sysmon configuration change | Configuration, ConfigurationFileHash | Cannot be filtered | Config tampering |
| Sysmon | 17 | Pipe created | PipeName, Image | Config rule | C2 named pipes (PsExec, Cobalt Strike) |
| Sysmon | 18 | Pipe connected | PipeName, Image | Config rule | Pipe client side |
| Sysmon | 19 | WmiEventFilter | EventNamespace, Name, Query | Config rule | WMI persistence |
| Sysmon | 20 | WmiEventConsumer | Name, Type, Destination | Config rule | WMI persistence |
| Sysmon | 21 | WmiEventConsumerToFilter | Consumer, Filter | Config rule | WMI persistence binding |
| Sysmon | 22 | DNS query | QueryName, QueryResults, Image | Config rule; Windows 8.1+ | C2 domains, DNS exfil, cloud storage |
| Sysmon | 23 | FileDelete (archived) | Image, TargetFilename, Hashes, IsExecutable, Archived | Config rule; archives copies in ArchiveDirectory | Recover deleted tools/data; wipe/ransomware deletes |
| Sysmon | 24 | ClipboardChange | Image, Session, ClientInfo, Hashes | Config rule | Clipboard capture (contents archived) |
| Sysmon | 25 | ProcessTampering | Image, Type | Config rule | Hollowing, herpaderping |
| Sysmon | 26 | FileDeleteDetected | Image, TargetFilename | Config rule | File deletions without copy |
| Sysmon | 27 | FileBlockExecutable | Image, TargetFilename | Config rule (blocks) | Blocked PE creation |
| Sysmon | 28 | FileBlockShredding | Image, TargetFilename | Config rule (blocks) | SDelete-style shredding |
| Sysmon | 29 | FileExecutableDetected | Image, TargetFilename, Hashes | Config rule | New PE files written |
| Sysmon | 255 | Sysmon error | ID, Description | Always | Sysmon dropped events/failed rules |

## Windows PowerShell (classic, channel "Windows PowerShell") and PowerShell/Operational

| Channel | EventID | Name | Key fields | Required audit policy / config | Forensic use |
|---|---|---|---|---|---|
| Windows PowerShell | 400 (k) | Engine state changed to Available (engine start) | HostApplication, EngineVersion, HostName | Default | Downgrade attacks (EngineVersion 2.0), host that launched PowerShell |
| Windows PowerShell | 403 (k) | Engine state changed to Stopped | HostApplication | Default | Session end |
| Windows PowerShell | 600 (k) | Provider lifecycle (e.g. WSMan, Registry started) | ProviderName, HostApplication | Default | Which providers loaded; AD-module use |
| Windows PowerShell | 800 (k) | Pipeline execution details | CommandLine, UserId, HostApplication | Module Logging / Pipeline Execution Details GPO | Legacy command tracing |
| Microsoft-Windows-PowerShell/Operational | 4103 (k) | Module/pipeline execution | Payload (command and parameter bindings), User | Module Logging GPO | Per-cmdlet execution with arguments |
| Microsoft-Windows-PowerShell/Operational | 4104 | Script block logging | ScriptBlockText, ScriptBlockId, MessageNumber, MessageTotal, Path | Turn on PowerShell Script Block Logging | De-obfuscated script content; reassemble by ScriptBlockId |

## WMI-Activity/Operational (Microsoft-Windows-WMI-Activity/Operational)

| Channel | EventID | Name | Key fields | Required audit policy / config | Forensic use |
|---|---|---|---|---|---|
| WMI-Activity/Operational | 5857 (k) | Provider started | ProviderName, ProviderPath/HostProcess | Operational log (default on) | Unusual provider DLLs loaded |
| WMI-Activity/Operational | 5858 (k) | Query/operation failure | ClientMachine, User, Operation, ResultCode | Default | Remote WMI use (ClientMachine = source), failures reveal attempts |
| WMI-Activity/Operational | 5859 (k) | Event filter registered (temporary subscription) | Namespace, Query, PossibleCause | Default | WMI subscription activity |
| WMI-Activity/Operational | 5860 (k) | Temporary event consumer registered | Namespace, Query, ClientProcessId | Default | Temporary subscriptions |
| WMI-Activity/Operational | 5861 (k) | Permanent subscription (filter-to-consumer) registered | Namespace, PossibleCause (filter/consumer text) | Default | WMI persistence (ActiveScript/CommandLine consumers) |

## TaskScheduler/Operational (Microsoft-Windows-TaskScheduler/Operational)

| Channel | EventID | Name | Key fields | Required audit policy / config | Forensic use |
|---|---|---|---|---|---|
| TaskScheduler/Operational | 106 (k) | Task registered | TaskName, UserContext | Log is disabled by default; enable it | Task persistence creation |
| TaskScheduler/Operational | 140 (k) | Task updated | TaskName, UserName | Same | Task modification |
| TaskScheduler/Operational | 141 (k) | Task deleted | TaskName, UserName | Same | Cleanup |
| TaskScheduler/Operational | 200 (k) | Action started | TaskName, ActionName, TaskInstanceId | Same | Execution of the task action (path) |
| TaskScheduler/Operational | 201 (k) | Action completed | TaskName, ActionName, ResultCode | Same | Execution result |

## Terminal Services and RDP

| Channel | EventID | Name | Key fields | Required audit policy / config | Forensic use |
|---|---|---|---|---|---|
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | 21 (k) | Session logon succeeded | User, SessionID, Address (source) | Default | RDP/console logon with source address |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | 22 (k) | Shell start notification | User, SessionID, Address | Default | Shell started in session |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | 23 (k) | Session logoff succeeded | User, SessionID | Default | Logoff time |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | 24 (k) | Session disconnected | User, SessionID, Address | Default | Disconnect |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | 25 (k) | Session reconnection succeeded | User, SessionID, Address | Default | Reconnect from (possibly new) source |
| Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | 1149 (k) | User authentication succeeded (network-level) | Param1 user, Param2 domain, Param3 source IP | Default | RDP source IP even where 4624 is missing; does not prove a session started |
| Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational | 131 | Connection accepted / transport established | ClientIP (source) | Default on servers | RDP source address before auth; discovery across hosts |

## WinRM (Microsoft-Windows-WinRM/Operational)

| Channel | EventID | Name | Key fields | Required audit policy / config | Forensic use |
|---|---|---|---|---|---|
| WinRM/Operational | 6 (k) | Creating WSMan session (client side) | connection string | Default | Outbound PowerShell remoting target |
| WinRM/Operational | 91 (k) | Creating WSMan shell on server | ResourceUri, shell id | Default | Inbound remoting session |
| WinRM/Operational | 168 (k) | Authenticating the user | user name, authentication mechanism | Default | Remoting user identity |

## Windows Defender (Microsoft-Windows-Windows Defender/Operational)

| Channel | EventID | Name | Key fields | Required audit policy / config | Forensic use |
|---|---|---|---|---|---|
| Windows Defender/Operational | 1006 (k) | Malware detected (older engine event) | Threat Name, Path, Detection User | Defender active | Early detection record |
| Windows Defender/Operational | 1116 (k) | Malware/PUA detected | Threat Name, Severity, Path, Process Name, Detection User | Defender active | Detection timeline; first sign of tooling |
| Windows Defender/Operational | 1117 (k) | Action taken to protect | Threat Name, Action, Path | Defender active | Quarantine/remove outcome |
| Windows Defender/Operational | 1118 (k) | Action failed (non-critical) | Threat Name, Error Code | Defender active | Files left in place |
| Windows Defender/Operational | 1119 (k) | Action failed (critical error) | Threat Name, Error Code | Defender active | Files left in place |
| Windows Defender/Operational | 5001 | Real-time protection disabled | (no user) | Defender active | Defence impairment; initiator not recorded |
| Windows Defender/Operational | 5007 (k) | Configuration changed | Old Value, New Value | Defender active | Exclusions and setting changes |
| Windows Defender/Operational | 5010 (k) | Scanning for malware/spyware disabled | (none) | Defender active | Defence impairment |
| Windows Defender/Operational | 5012 (k) | Scanning for viruses disabled | (none) | Defender active | Defence impairment |
| Windows Defender/Operational | 5013 | Tamper protection blocked a change | Value (registry path), Current Value | Tamper Protection on | Attempted disabling blocked |
| Windows Defender/Operational | 1013 | Detection history deleted | (none) | Defender active | Cover-up of detections |

## Other channels

| Channel | EventID | Name | Key fields | Required audit policy / config | Forensic use |
|---|---|---|---|---|---|
| Microsoft-Windows-Bits-Client/Operational | 3 (k) | BITS job created | jobTitle, jobOwner, url | Default operational log | Download/upload jobs, persistence |
| Microsoft-Windows-Bits-Client/Operational | 59 (k) | Transfer started | name, url, bytesTotal | Default | Source URL of transfer (also upload) |
| Microsoft-Windows-Bits-Client/Operational | 60 (k) | Transfer stopped/error | url, hr | Default | Failed/completed transfer |
| Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | 2004 (k) | Firewall rule added | RuleName, ApplicationPath, Direction, Action, ModifyingApplication | Default | Opened ports for C2/RDP |
| Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | 2005 (k) | Firewall rule modified | RuleName, ModifyingApplication | Default | Rule tampering |
| Microsoft-Windows-Windows Firewall With Advanced Security/Firewall | 2006 (k) | Firewall rule deleted | RuleName | Default | Rule tampering |
| Directory Service | 1644 (k) | Expensive/inefficient LDAP search | Client, Filter, Entries visited/returned | Registry "15 Field Engineering" diagnostics set to 5 on DCs | BloodHound/AdFind LDAP enumeration |
| Directory Service | 2889 (k) | Client made unsigned LDAP bind | IP address, identity | LDAP interface events diagnostics >= 2 | Weak LDAP binds, NTLM relay prep |
| Security (Certification Services) | 4886, 4887 (k) | Request received / certificate issued | Requester, RequestId | Audit Certification Services; CA auditing configured | ADCS abuse; see Security table |
| Microsoft-Windows-NTLM/Operational | 8001 (k) | Outgoing NTLM authentication audited | target server, process | "Network security: Restrict NTLM: Audit outgoing NTLM traffic" | NTLM usage by process |
| Microsoft-Windows-NTLM/Operational | 8002 (k) | Incoming NTLM authentication audited | user, workstation | "Restrict NTLM: Audit incoming NTLM traffic" | NTLM relay / legacy auth |
| Microsoft-Windows-NTLM/Operational | 8004 (k) | DC NTLM authentication audited | user, workstation, server | "Audit NTLM authentication in this domain" on DCs | Domain-wide NTLM sources |
| Microsoft-Windows-CodeIntegrity/Operational | 3033 (k) | Image failed signing-level requirement | file name, process, required level | Code integrity logging (default) | Unsigned DLL load blocked |
| Microsoft-Windows-CodeIntegrity/Operational | 3076 (k) | WDAC audit-mode would-block | file name, policy name | WDAC audit policy | Unapproved binaries in audit mode |
| Microsoft-Windows-CodeIntegrity/Operational | 3077 (k) | WDAC enforced block | file name, policy name | WDAC enforced policy | Blocked execution |
| Microsoft-Windows-AppLocker/EXE and DLL | 8002 (k) | Allowed | FilePath, User, RuleName | AppLocker policy configured | Allowed execution record |
| Microsoft-Windows-AppLocker/EXE and DLL | 8003 (k) | Would be blocked (audit mode) | FilePath, User | AppLocker audit-only | Tuning and finding unapproved binaries |
| Microsoft-Windows-AppLocker/EXE and DLL | 8004 (k) | Blocked | FilePath, User | AppLocker enforce mode | Blocked execution attempts |
| Microsoft-Windows-AppLocker/MSI and Script | 8005, 8006, 8007 (k) | Allowed / audit / blocked for scripts and installers | FilePath, User | AppLocker policy | Script execution control |
| Microsoft-Windows-DriverFrameworks-UserMode/Operational | 2003, 2100 (k) | Device activity | device instance, driver | Log disabled by default | USB history |
| Microsoft-Windows-Partition/Diagnostic | 1006 (k) | Disk/partition information at connection | Manufacturer, Model, SerialNumber, Capacity | Default | USB serial/model identification |
| Microsoft-Windows-PrintService/Operational | 307 (k) | Document printed | Param2 document, Param3 user, Param5 printer, Param7 bytes, Param8 pages | Log disabled by default | Print exfiltration |

## Sources

Opened and used:
- https://raw.githubusercontent.com/MicrosoftDocs/sysinternals/main/sysinternals/downloads/sysmon.md (Sysmon event names 1-29, 255)
- https://raw.githubusercontent.com/stuhli/awesome-event-ids/master/README.md (index only; confirms 4104 Script Block Logging recommendation)
- https://raw.githubusercontent.com/mdecrevoisier/EVTX-to-MITRE-Attack/master/README.md (event id mappings for 4661, 4662, 4799, 5145, 131, 4769, 4698 and others)
- Sigma rules (read, not copied): win_security_audit_log_cleared (1102), win_security_susp_net_recon_activity (4661), win_security_ad_user_enumeration (4662), win_security_external_device (6416), win_security_smb_file_creation_admin_shares (5145), win_defender_real_time_protection_disabled (5001), win_defender_tamper_protection_trigger (5013), win_defender_history_delete (1013). Full URLs are in sources/impact-discovery-exfil.md.

Rows marked `(k)` come from analyst knowledge, not from a source opened in this session. Verify them against Microsoft Learn (Windows security auditing event pages, Defender AV event ids page, Sysmon docs) before treating as authoritative.
