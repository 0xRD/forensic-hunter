# Checklist status

Copy to the case working directory. Every row must end with one status:
`HIT`, `NO_HIT`, `NOT_APPLICABLE` or `LOG_SOURCE_MISSING`. Evidence: event ids
for HIT; the query and scope for NO_HIT; the missing source or reason otherwise.

Case: <name>  Evidence: <path>  Analyst: <name>  Started: <UTC time>

## Initial Access and Brute Force

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-INIT-001 | Password spraying - many distinct accounts failing from one source address | Security 4625 |  |  |
| FH-INIT-002 | Brute force against a single account | Security 4625 |  |  |
| FH-INIT-003 | Username enumeration - failures for accounts that do not exist | Security 4625 |  |  |
| FH-INIT-004 | Account lockout (4740) and the callers behind it | Security 4740 |  |  |
| FH-INIT-005 | Successful logon after a failure burst from the same source (guess succeeded) | Security 4625,4624 |  |  |
| FH-INIT-006 | Failed logons from public IP addresses (RDP / SMB / WinRM exposed to the internet) | Security 4625 |  |  |
| FH-INIT-007 | Successful interactive or network logon from a public IP (valid accounts, external remote services) | Security 4624,21,1149 |  |  |
| FH-INIT-008 | NTLM validation failures on a domain controller (4776) - spray and guessing from one workstation | Security 4776 |  |  |
| FH-INIT-009 | Kerberos pre-authentication failures (4771, Status 0x18) from one address | Security 4771 |  |  |
| FH-INIT-010 | Valid-account misuse signals - logons rejected for restriction reasons, and activity outside the account's normal hours | Security 4625,4776,4624 |  |  |
| FH-INIT-011 | Phishing payload execution chain - Office, Outlook or other document hosts spawning script hosts and LOLBins | Microsoft-Windows-Sysmon/Operational 1,4688 |  |  |
| FH-INIT-012 | Downloaded payloads - Zone.Identifier (Mark-of-the-Web) streams created outside browsers | Microsoft-Windows-Sysmon/Operational 15,11 |  |  |
| FH-INIT-013 | Exploitation of public-facing applications - web server worker spawning shells and recon tools | Microsoft-Windows-Sysmon/Operational 1,4688 |  |  |
| FH-INIT-014 | SQL Server spawning command interpreters (xp_cmdshell abuse after SQL injection) | Microsoft-Windows-Sysmon/Operational 1,4688 |  |  |
| FH-INIT-015 | Windows Remote Access / VPN server logons (RRAS) and RD Gateway sessions - external remote services visible in EVTX | Microsoft-Windows-TerminalServices-Gateway/Operational 302,303,20250,20274 |  |  |
| FH-INIT-016 | Tool-default workstation names on NTLM logons (Metasploit, Ruler, Rdesktop-style clients) | Security 4624,4625,4776 |  |  |

## Execution

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-EXE-001 | Office application spawning a shell, script host or LOLBin (Sysmon 1) | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-EXE-002 | Office application spawning a shell, script host or LOLBin (Security 4688) | Security 4688 |  |  |
| FH-EXE-003 | PowerShell started with an encoded command (Sysmon 1) | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-EXE-004 | PowerShell started with an encoded command (Security 4688) | Security 4688 |  |  |
| FH-EXE-005 | PowerShell engine started as version 2 while the host is newer (downgrade) - classic 400 | Windows PowerShell 400 |  |  |
| FH-EXE-006 | Classic PowerShell provider start (600) revealing host application and engine version | Windows PowerShell 600 |  |  |
| FH-EXE-007 | PowerShell script block containing a download cradle (4104) | Microsoft-Windows-PowerShell/Operational 4104 |  |  |
| FH-EXE-008 | AMSI bypass strings in script blocks (4104) | Microsoft-Windows-PowerShell/Operational 4104 |  |  |
| FH-EXE-009 | PowerShell module logging (4103) showing suspicious cmdlet invocations | Microsoft-Windows-PowerShell/Operational 4103 |  |  |
| FH-EXE-010 | Mshta executing remote content, inline script or non-HTA file types | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-EXE-011 | Regsvr32 loading scriptlets, URLs or launched from script hosts | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-EXE-012 | Rundll32 invoked without arguments, with script protocols, or loading odd DLL extensions | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-EXE-013 | Certutil used to download or decode files | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-EXE-014 | Bitsadmin command line creating or running transfer jobs | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-EXE-015 | WMIC creating processes, remote execution or XSL script processing | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-EXE-016 | Processes spawned by WmiPrvSE.exe (WMI-based remote execution) | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-EXE-017 | Wscript/cscript running scripts with non-script extensions or spawning shells | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-EXE-018 | Msbuild, InstallUtil or csc launched by unusual parent or with remote content | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-EXE-019 | AMSI DLL loaded into a LOLBin that does not normally scan content | Microsoft-Windows-Sysmon/Operational 7 |  |  |

## Persistence

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-PER-001 | New service installed with a suspicious ImagePath (System 7045) | System 7045 |  |  |
| FH-PER-002 | Service installed - Security 4697 (service file name check) | Security 4697 |  |  |
| FH-PER-003 | Service start type changed (System 7040) and unexpected service state changes (7036) | System 7040,7036 |  |  |
| FH-PER-004 | Scheduled task created - Security 4698 | Security 4698 |  |  |
| FH-PER-005 | Scheduled task deleted, enabled, disabled or modified - Security 4699/4700/4701/4702 | Security 4699,4700,4701,4702 |  |  |
| FH-PER-006 | Scheduled task registered - TaskScheduler/Operational 106 | Microsoft-Windows-TaskScheduler/Operational 106 |  |  |
| FH-PER-007 | Scheduled task updated or deleted - TaskScheduler/Operational 140/141 | Microsoft-Windows-TaskScheduler/Operational 140,141 |  |  |
| FH-PER-008 | Scheduled task running a program from a user-writable path - TaskScheduler/Operational 129/200 | Microsoft-Windows-TaskScheduler/Operational 129,200 |  |  |
| FH-PER-009 | Run / RunOnce autorun value written (Sysmon 12/13) | Microsoft-Windows-Sysmon/Operational 12,13 |  |  |
| FH-PER-010 | Executable or script dropped into a Startup folder (Sysmon 11) | Microsoft-Windows-Sysmon/Operational 11 |  |  |
| FH-PER-011 | Winlogon Shell / Userinit / Notify values modified, or userinit spawning a non-explorer shell | Microsoft-Windows-Sysmon/Operational 12,13 |  |  |
| FH-PER-012 | Image File Execution Options Debugger / accessibility-feature (sethc, utilman) backdoor | Microsoft-Windows-Sysmon/Operational 12,13 |  |  |
| FH-PER-013 | AppInit_DLLs or AppCertDlls registry modification | Microsoft-Windows-Sysmon/Operational 12,13 |  |  |
| FH-PER-014 | COM hijacking via InprocServer32 / LocalServer32 / TreatAs changes | Microsoft-Windows-Sysmon/Operational 12,13 |  |  |
| FH-PER-015 | Netsh helper DLL registered | Microsoft-Windows-Sysmon/Operational 1,13 |  |  |
| FH-PER-016 | Permanent WMI event subscription registered - WMI-Activity/Operational 5861 (and 5859/5860) | Microsoft-Windows-WMI-Activity/Operational 5861,5859,5860 |  |  |
| FH-PER-017 | WMI filter, consumer and binding created (Sysmon 19/20/21) | Microsoft-Windows-Sysmon/Operational 19,20,21 |  |  |
| FH-PER-018 | BITS job created or started (Bits-Client/Operational 3, 59, 60) and notify-command persistence | Microsoft-Windows-Bits-Client/Operational 3,59,60 |  |  |
| FH-PER-019 | Local account created - Security 4720 (incl. hidden '$' accounts) | Security 4720 |  |  |
| FH-PER-020 | Account enabled or modified for persistence - Security 4722 / 4738 | Security 4722,4738 |  |  |
| FH-PER-021 | Logon script / UserInitMprLogonScript registry persistence | Microsoft-Windows-Sysmon/Operational 13 |  |  |
| FH-PER-022 | Service DLL / ImagePath registry tampering and sc.exe service creation | Microsoft-Windows-Sysmon/Operational 1,13 |  |  |
| FH-PER-023 | WMI event consumer created through wbemcons.dll load or wmic/PowerShell command | Microsoft-Windows-Sysmon/Operational 7,1 |  |  |

## Privilege Escalation

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-PRV-001 | Special privileges (4672) assigned to an unexpected account | Security 4672 |  |  |
| FH-PRV-002 | Sensitive privilege use (4673) by an unknown or unexpected process | Security 4673 |  |  |
| FH-PRV-003 | Privileged object operation (4674): service DACL change or SC manager ownership | Security 4674 |  |  |
| FH-PRV-004 | Member added to local Administrators (4732) | Security 4732 |  |  |
| FH-PRV-005 | Member added to privileged domain groups (4728 / 4732 / 4756) | Security 4728,4732,4756 |  |  |
| FH-PRV-006 | User right assigned (4704) - dangerous privilege granted | Security 4704 |  |  |
| FH-PRV-007 | GPO modified to push user-rights assignment (5136 gPCMachineExtensionNames) | Security 5136 |  |  |
| FH-PRV-008 | UAC bypass via registry hijack (eventvwr mscfile, ms-settings, sdclt) - Sysmon 13 | Microsoft-Windows-Sysmon/Operational 13 |  |  |
| FH-PRV-009 | UAC bypass auto-elevated binary spawning a child (fodhelper, ComputerDefaults, cmstp) | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-PRV-010 | Service installed (7045) with cmd / PowerShell / script-host ImagePath | System 7045 |  |  |
| FH-PRV-011 | getsystem-style service: named-pipe echo or rundll32 ImagePath (7045 / 4688) | System 7045,4688 |  |  |
| FH-PRV-012 | Service creation with suspicious binary path via sc.exe / New-Service (4688 / Sysmon 1) | Security 4688,1 |  |  |
| FH-PRV-013 | Named-pipe impersonation tooling (potato / PrintSpoofer / Cobalt Strike pipes) - Sysmon 17/18 | Microsoft-Windows-Sysmon/Operational 17,18 |  |  |
| FH-PRV-014 | Access-token abuse: logon type 9 with Impersonation level (4624) | Security 4624 |  |  |
| FH-PRV-015 | RottenPotato-like loopback ANONYMOUS LOGON (4624 type 3) | Security 4624 |  |  |

## Defense Evasion and Log Tampering

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-DEF-001 | Security log cleared (1102) | Security 1102 |  |  |
| FH-DEF-002 | Any event log cleared (System 104) | System 104 |  |  |
| FH-DEF-003 | Log clearing / configuration tampering command lines (wevtutil cl, Clear-EventLog, WMI) | Security 4688,1,4104 |  |  |
| FH-DEF-004 | EventLog service stopped or disabled (6006 / 7040 / 1100) | System 6006,7040,7036,1100 |  |  |
| FH-DEF-005 | Audit policy disabled or changed (4719) and object SACL changed (4907) | Security 4719,4907 |  |  |
| FH-DEF-006 | System time changed (4616) | Security 4616 |  |  |
| FH-DEF-007 | Defender real-time or scanning protection disabled (5001 / 5010 / 5012) | Microsoft-Windows-Windows Defender/Operational 5001,5010,5012 |  |  |
| FH-DEF-008 | Defender configuration change: exclusions added, protection values altered, tamper protection blocks (5007 / 5013) | Microsoft-Windows-Windows Defender/Operational 5007,5013 |  |  |
| FH-DEF-009 | Defender exclusion or disable via PowerShell / registry (4688, Sysmon 1, Sysmon 13, 4104) | Security 4688,1,13,4104 |  |  |
| FH-DEF-010 | Security / logging service stopped or disabled (7036 / 7040, net stop, sc) | System 7036,7040,4688 |  |  |
| FH-DEF-011 | Defender detections and history deletion (1116 / 1117 / 1013 / 1015) | Microsoft-Windows-Windows Defender/Operational 1116,1117,1015,1013,1009 |  |  |
| FH-DEF-012 | Sysmon service stopped, config changed, or erroring (Sysmon 4 / 16 / 255) | Microsoft-Windows-Sysmon/Operational 4,16,255 |  |  |
| FH-DEF-013 | Sysmon / EDR sensor tampering: fltMC unload, WINEVT channel disabled in registry | Security 4688,1,4657,4663 |  |  |
| FH-DEF-014 | Windows Firewall rule added, changed, deleted or reset (MPSSVC 2004 / 2005 / 2006 / 2032 / 2033) | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall 2004,2005,2006,2032,2033,2071,2052,2059,2060,2097 |  |  |
| FH-DEF-015 | Firewall disabled or broadly opened via netsh | Security 4688,1 |  |  |
| FH-DEF-016 | Process image tampering: hollowing / herpaderping (Sysmon 25) | Microsoft-Windows-Sysmon/Operational 25 |  |  |
| FH-DEF-017 | File deletion of logs, tools or Sysmon-tracked paths (Sysmon 26 / 23) | Microsoft-Windows-Sysmon/Operational 26,23 |  |  |
| FH-DEF-018 | Timestomping: file creation time changed (Sysmon 2) and PowerShell timestamp edits (4104) | Microsoft-Windows-Sysmon/Operational 2,4104 |  |  |
| FH-DEF-019 | PowerShell AMSI bypass in script blocks (4104) | Microsoft-Windows-PowerShell/Operational 4104 |  |  |
| FH-DEF-020 | ETW tampering: .NET ETW disabled via registry or environment variable (4657 / Sysmon 13) and script text | Security 4657,13,4104 |  |  |
| FH-DEF-021 | Event log gaps: record-id discontinuities and silent intervals | Security 1102,104,1100,4616 |  |  |
| FH-DEF-022 | Process masquerading as svchost.exe (wrong path or no service arguments) | Microsoft-Windows-Sysmon/Operational 1,4688 |  |  |
| FH-DEF-023 | rundll32.exe launched without arguments | Microsoft-Windows-Sysmon/Operational 1,4688 |  |  |

## Credential Access

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-CRED-001 | LSASS memory access with dump-capable access mask and debug-library call trace (Sysmon 10) | Microsoft-Windows-Sysmon/Operational 10 |  |  |
| FH-CRED-002 | LSASS read-access masks 0x1010 / 0x1410 / 0x1400 from non-system, non-security processes (Sysmon 10) | Microsoft-Windows-Sysmon/Operational 10 |  |  |
| FH-CRED-003 | comsvcs.dll MiniDump via rundll32 against LSASS (Sysmon 10 call trace) | Microsoft-Windows-Sysmon/Operational 10 |  |  |
| FH-CRED-004 | LSASS dumping tool command lines: procdump, comsvcs MiniDump, rundll32 (4688 / Sysmon 1) | Security 4688,1 |  |  |
| FH-CRED-005 | Handle request to lsass.exe with suspicious access mask (Security 4656 / 4663) | Security 4656,4663 |  |  |
| FH-CRED-006 | Defender ASR blocked credential stealing from LSASS (1121) | Microsoft-Windows-Windows Defender/Operational 1121 |  |  |
| FH-CRED-007 | Registry hive dumping: reg save/export of SAM, SECURITY, SYSTEM (4688 / Sysmon 1) | Security 4688,1 |  |  |
| FH-CRED-008 | NTDS.dit extraction: ntdsutil snapshot/ifm, ESENT events, esentutl copy (4688 / Sysmon 1 / Application) | Security 4688,1,216,325,326,327 |  |  |
| FH-CRED-009 | DPAPI domain backup key retrieval (4662 BCKUPKEY) and master key backup (4692) | Security 4662,4692,4693,4695 |  |  |
| FH-CRED-010 | Credential Manager reads (5379) and vault enumeration (5381 / 5382) | Security 5379,5381,5382 |  |  |
| FH-CRED-011 | Password guessing against one account: repeated 4625 with SubStatus 0xC000006A | Security 4625 |  |  |
| FH-CRED-012 | Password spraying / user enumeration: many accounts failing from one source (4625 0xC000006A / 0xC0000064) | Security 4625 |  |  |
| FH-CRED-013 | Account lockout and disabled-account logon failures (4625 0xC0000234 and related) | Security 4625,4740 |  |  |
| FH-CRED-014 | Kerberos pre-authentication failures (4771) and NTLM credential validation failures (4776) on DCs | Security 4771,4776 |  |  |
| FH-CRED-015 | Kerberoasting: RC4 service ticket requests (4769, TicketEncryptionType 0x17) | Security 4769 |  |  |
| FH-CRED-016 | AS-REP roasting: TGT request without pre-authentication (4768 PreAuthType 0) | Security 4768 |  |  |
| FH-CRED-017 | Rubeus-style logon process registration (4611 User32LogonProcesss) | Security 4611 |  |  |
| FH-CRED-018 | Mimikatz execution traces: command-line modules and credential-dumper services | Security 4688,1,7045,4104 |  |  |
| FH-CRED-019 | WDigest cleartext credential caching enabled (Sysmon 13 UseLogonCredential = 1) | Microsoft-Windows-Sysmon/Operational 13 |  |  |
| FH-CRED-020 | Browser credential store theft: access to Login Data / logins.json / key4.db by non-browser process (Sysmon 11 / 10) | Microsoft-Windows-Sysmon/Operational 11,10 |  |  |
| FH-CRED-021 | Defender detection of credential-theft tooling (1116 / 1117) | Microsoft-Windows-Windows Defender/Operational 1116,1117,1015 |  |  |

## Discovery

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-DISC-001 | Account and group enumeration with net.exe / net1.exe | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-DISC-002 | Domain controller and trust discovery with nltest | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-DISC-003 | Burst of discovery utilities from one session (whoami, systeminfo, ipconfig, arp, route, netstat, quser, qwinsta, tasklist) | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-DISC-004 | AdFind Active Directory query tool | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-DISC-005 | BloodHound/SharpHound LDAP enumeration - read-property bursts on AD user objects (4662) | Security 4662 |  |  |
| FH-DISC-006 | SAM enumeration via handle requests on SAM_USER / SAM_GROUP objects (4661) | Security 4661 |  |  |
| FH-DISC-007 | SMB named-pipe enumeration (srvsvc, samr, lsarpc, wkssvc) across many hosts (5145) | Security 5145 |  |  |
| FH-DISC-008 | Remote enumeration of local group membership (4799) | Security 4799 |  |  |
| FH-DISC-009 | Local group membership of a user enumerated (4798) | Security 4798 |  |  |
| FH-DISC-010 | PowerView / AD PowerShell enumeration in script blocks | Microsoft-Windows-PowerShell/Operational 4104 |  |  |
| FH-DISC-011 | SPN enumeration and Kerberos TGS burst from a single source (setspn, SharpHound) | Security 4769 |  |  |
| FH-DISC-012 | Host-based port scan (Sysmon 3 fan-out) | Microsoft-Windows-Sysmon/Operational 3 |  |  |
| FH-DISC-013 | Host-based port scan seen by Windows Filtering Platform (5156 / 5157) | Security 5156,5157 |  |  |
| FH-DISC-014 | Network share discovery - one source touching many shares (5140) | Security 5140 |  |  |
| FH-DISC-015 | Security software discovery (WMI SecurityCenter2, Get-MpComputerStatus, product queries) | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-DISC-016 | Installed-software discovery via registry Uninstall keys in script blocks | Microsoft-Windows-PowerShell/Operational 4104 |  |  |
| FH-DISC-017 | RDP service discovery - one client connecting to many hosts (RdpCoreTS 131) | Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational 131 |  |  |

## Lateral Movement

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-LAT-001 | PsExec service installed on target (PSEXESVC) | System 7045 |  |  |
| FH-LAT-002 | PsExec clones and Impacket-style remote service install (random names, known clone names) | System 7045,4697 |  |  |
| FH-LAT-003 | Named-pipe traffic of PsExec and clones over IPC$ (stdin/stdout/stderr pipes) | Security 5145 |  |  |
| FH-LAT-004 | Remote service control over the svcctl pipe (sc.exe \\host, smbexec, PsExec) | Security 5145 |  |  |
| FH-LAT-005 | Remote scheduled task creation over the atsvc pipe (atexec, schtasks /s) | Security 5145 |  |  |
| FH-LAT-006 | Remote scheduled task - 4698 plus network logon from the same source | Security 4698,4624 |  |  |
| FH-LAT-007 | WMI remote execution - WmiPrvSE.exe spawning command interpreters | Security 4688 |  |  |
| FH-LAT-008 | Impacket exec family - cmd /Q /c with output redirected to \\127.0.0.1\ADMIN$ or C$ | Microsoft-Windows-Sysmon/Operational 1,4688,11 |  |  |
| FH-LAT-009 | PowerShell remoting / WinRM - wsmprovhost.exe host process and its children | Security 4688 |  |  |
| FH-LAT-010 | Inbound WinRM connections via Windows Filtering Platform (5156 to 5985/5986) | Security 5156 |  |  |
| FH-LAT-011 | DCOM lateral movement - MMC20.Application, ShellWindows/ShellBrowserWindow, Excel/Office DCOM | Security 4688 |  |  |
| FH-LAT-012 | Pass-the-hash heuristic - NTLM network logon with null subject SID and KeyLength 0 | Security 4624 |  |  |
| FH-LAT-013 | Logon type 9 NewCredentials with seclogo (runas /netonly, Mimikatz sekurlsa::pth, overpass-the-hash) | Security 4624 |  |  |
| FH-LAT-014 | Explicit-credential logons (4648) toward remote servers | Security 4648 |  |  |
| FH-LAT-015 | Overpass-the-hash - RC4 TGT request from a host whose account normally uses AES | Security 4768,4769 |  |  |
| FH-LAT-016 | Pass-the-ticket tooling - Kerberos traffic to KDC from a non-LSASS process | Security 5156,4611 |  |  |
| FH-LAT-017 | Administrative share access from remote hosts (5140 on ADMIN$, C$, IPC$) | Security 5140 |  |  |
| FH-LAT-018 | File drops to admin shares (5145 write access to ADMIN$/C$ of executables and scripts) | Security 5145 |  |  |
| FH-LAT-019 | RDP session hijacking with tscon.exe | Security 4688 |  |  |
| FH-LAT-020 | Impacket smbexec service pattern (BTOBTO / batch file with __output redirection) | System 7045,4697 |  |  |
| FH-LAT-021 | WMI-Activity provider activity on target (5857/5860/5861) alongside remote logon | Microsoft-Windows-WMI-Activity/Operational 5857,5860,5861 |  |  |
| FH-LAT-022 | Privileged network logon on a non-server host (4624 type 3 followed by 4672 with the same logon id) | Security 4624,4672 |  |  |

## Remote Access Services (RDP, WinRM, SMB)

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-RMT-001 | RDP network authentication succeeded (RemoteConnectionManager 1149) with source address | Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational 1149 |  |  |
| FH-RMT-002 | RDP session logon, shell start and reconnect (LocalSessionManager 21, 22, 25) | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational 21,22,25 |  |  |
| FH-RMT-003 | RDP disconnect and logoff (LocalSessionManager 23, 24, 39, 40) | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational 23,24,39,40 |  |  |
| FH-RMT-004 | RDP logon in the Security log (4624 LogonType 10, and 7 / 12 on reconnect) | Security 4624 |  |  |
| FH-RMT-005 | RDP session reconnect and disconnect in the Security log (4778, 4779) | Security 4778,4779 |  |  |
| FH-RMT-006 | RDP through a tunnel - logon or flow from loopback | Security 4624,5156 |  |  |
| FH-RMT-007 | RDP enabled via registry (fDenyTSConnections set to 0) | Microsoft-Windows-Sysmon/Operational 13,4688,1 |  |  |
| FH-RMT-008 | RDP security weakened - NLA disabled or security layer changed | Microsoft-Windows-Sysmon/Operational 13 |  |  |
| FH-RMT-009 | Firewall opened for RDP (netsh / Windows Firewall rule add for 3389) | Security 4688,1,2004 |  |  |
| FH-RMT-010 | RDP shadowing (mstsc /shadow with noConsentPrompt) | Security 4688,1 |  |  |
| FH-RMT-011 | RDP client use on the source host (RDPClient 1024 and 1102) | Microsoft-Windows-TerminalServices-RDPClient/Operational 1024,1102,1025,1026,1029 |  |  |
| FH-RMT-012 | WinRM session established - server side (WinRM/Operational 169, 81, 82, 134) | Microsoft-Windows-WinRM/Operational 169,81,82,134 |  |  |
| FH-RMT-013 | WinRM client activity on the source host (WinRM/Operational 6, 80, 143) | Microsoft-Windows-WinRM/Operational 6,80,143 |  |  |
| FH-RMT-014 | WinRM authentication or operation failures (WinRM/Operational 161, 142) | Microsoft-Windows-WinRM/Operational 161,142 |  |  |
| FH-RMT-015 | RDP TCP-level connection events (RdpCoreTS 131 and 98) | Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational 131,98 |  |  |
| FH-RMT-016 | Network share created, modified or deleted (5142, 5143, 5144) | Security 5142,5143,5144 |  |  |
| FH-RMT-017 | One source touching shares or admin shares on many hosts (5140/5145 fan-out) | Security 5140,5145 |  |  |
| FH-RMT-018 | SMB server authentication failures (SMBServer/Security 551) | Microsoft-Windows-SMBServer/Security 551 |  |  |
| FH-RMT-019 | SMB client events - rejected guest logons (SMBClient/Security 31017) | Microsoft-Windows-SmbClient/Security 31017 |  |  |
| FH-RMT-020 | Unsigned or unencrypted SMB sessions to admin shares (SMBServer/Connectivity 4000) | Microsoft-Windows-SMBServer/Connectivity 4000 |  |  |

## Active Directory Attacks

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-AD-001 | Kerberoasting - RC4 service ticket requests for user-account SPNs | Security 4769 |  |  |
| FH-AD-002 | Kerberoasting - burst of distinct service ticket requests by one requester | Security 4769 |  |  |
| FH-AD-003 | AS-REP roasting - TGT issued without pre-authentication | Security 4768 |  |  |
| FH-AD-004 | Account flagged "Do not require Kerberos preauthentication" (4738) | Security 4738 |  |  |
| FH-AD-005 | DCSync - directory replication rights exercised by a non-DC account (4662) | Security 4662 |  |  |
| FH-AD-006 | DCSync rights granted - ACL change on the domain root (5136) | Security 5136 |  |  |
| FH-AD-007 | DCShadow - rogue DC registration (GC/ SPN and server object in Configuration) | Security 4742,5136,5137,5141 |  |  |
| FH-AD-008 | Password reset on privileged account, krbtgt or DSRM (4724 / 4723) | Security 4724,4723 |  |  |
| FH-AD-009 | Golden ticket - Kerberos logon/service ticket for an account that does not exist or lacks a prior TGT request | Security 4624,4769,4768,4672 |  |  |
| FH-AD-010 | Silver ticket - Kerberos service logon with no matching service ticket request on any DC | Security 4624,4769,4672 |  |  |
| FH-AD-011 | AD CS certificate request with attacker-supplied SAN (ESC1/ESC6 style) | Security 4886,4887 |  |  |
| FH-AD-012 | Certificate-based Kerberos logon (PKINIT) and KDC certificate mapping warnings | Security 4768 |  |  |
| FH-AD-013 | AD CS template and CA configuration changes (4898/4899/4900, CA permissions) | Security 4898,4899,4900,4882,4890,4891,4892,4870 |  |  |
| FH-AD-014 | Zerologon (CVE-2020-1472) - Netlogon secure-channel enforcement events | System 5827,5828,5829,5830,5831,5805 |  |  |
| FH-AD-015 | Zerologon aftermath - DC machine account password changed by ANONYMOUS LOGON (4742) | Security 4742,4624 |  |  |
| FH-AD-016 | noPac / sAMAccountName spoofing - machine account renamed to a DC name without the trailing $ | Security 4741,4781,4742,4768,4769 |  |  |
| FH-AD-017 | Machine account quota abuse - computer account created by a non-admin user (4741) | Security 4741,4673 |  |  |
| FH-AD-018 | RBCD and shadow credentials - writes to msDS-AllowedToActOnBehalfOfOtherIdentity / msDS-KeyCredentialLink (5136) | Security 5136 |  |  |
| FH-AD-019 | Delegation changes - constrained or unconstrained delegation enabled (4738/4742) | Security 4738,4742,5136 |  |  |
| FH-AD-020 | Membership added to privileged AD groups (4728/4732/4756 and removals) | Security 4728,4729,4732,4733,4756,4757 |  |  |
| FH-AD-021 | DNSAdmins abuse - ServerLevelPluginDll loaded by the DNS service (DNS Server 150/770) | DNS Server 150,770,771 |  |  |
| FH-AD-022 | AdminSDHolder object modified (5136) - SDProp persistence | Security 5136 |  |  |
| FH-AD-023 | SID History added to an account (4765 / 4766 / 4738 SidHistory) | Security 4765,4766,4738 |  |  |
| FH-AD-024 | Group Policy object tampering (5136 on groupPolicyContainer, SYSVOL writes in 5145) | Security 5136,5137,5141,5145 |  |  |
| FH-AD-025 | New domain or forest trust created or modified (4706 / 4707 / 4716 / 4865) | Security 4706,4707,4716,4865 |  |  |
| FH-AD-026 | Authentication coercion - RPC pipes (lsarpc, efsrpc, spoolss, netdfs ...) accessed over IPC$ on a DC (5145) | Security 5145 |  |  |
| FH-AD-027 | Machine-account NTLM network logon from a remote host (relay of coerced authentication) | Security 4624 |  |  |
| FH-AD-028 | NTLMv1 authentication (4624 LmPackageName 'NTLM V1') | Security 4624 |  |  |
| FH-AD-029 | NTLM Operational log - audited NTLM use, outgoing and incoming (8001 / 8002 / 8003 / 8004) | Microsoft-Windows-NTLM/Operational 8001,8002,8003,8004 |  |  |
| FH-AD-030 | Expensive or inefficient LDAP queries (Directory Service 1644) and LDAP reconnaissance blind spot | Directory Service 1644 |  |  |

## Collection and Exfiltration

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-COLL-001 | Archive creation with a password via 7-Zip, WinRAR or rar | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-COLL-002 | Archive creation with PowerShell Compress-Archive or .NET ZipFile | Microsoft-Windows-PowerShell/Operational 4104 |  |  |
| FH-COLL-003 | Archives or data dumps written to common staging directories (Sysmon 11) | Microsoft-Windows-Sysmon/Operational 11 |  |  |
| FH-COLL-004 | rclone (cloud sync tool) execution | Microsoft-Windows-Sysmon/Operational 1,11 |  |  |
| FH-COLL-005 | DNS lookups for MEGA user storage | Microsoft-Windows-Sysmon/Operational 22 |  |  |
| FH-COLL-006 | DNS lookups for file-sharing / cloud storage domains by non-browser processes | Microsoft-Windows-Sysmon/Operational 22,3 |  |  |
| FH-COLL-007 | Upload or transfer tooling by command line (WinSCP, curl, bitsadmin, MEGAcmd, pscp, ftp) | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-COLL-008 | DNS tunnelling / exfil - long or high-entropy query names (Sysmon 22) | Microsoft-Windows-Sysmon/Operational 22 |  |  |
| FH-COLL-009 | Outbound connections by archive/transfer tools or from staging hosts (Sysmon 3) - volume is not visible | Microsoft-Windows-Sysmon/Operational 3 |  |  |
| FH-COLL-010 | Clipboard capture (Sysmon 24 and PowerShell Get-Clipboard) | Microsoft-Windows-Sysmon/Operational 24 |  |  |
| FH-COLL-011 | Screen capture and input capture via PowerShell or tools | Microsoft-Windows-PowerShell/Operational 4104 |  |  |
| FH-COLL-012 | Outlook mail store (PST/OST) created or copied (Sysmon 11) | Microsoft-Windows-Sysmon/Operational 11 |  |  |
| FH-COLL-013 | USB mass storage connected (Security 6416) | Security 6416 |  |  |
| FH-COLL-014 | USB device activity in DriverFrameworks-UserMode/Operational (2003, 2100) | Microsoft-Windows-DriverFrameworks-UserMode/Operational 2003,2100 |  |  |
| FH-COLL-015 | File copy to removable media (Security 4663 with Removable Storage auditing) | Security 4663 |  |  |
| FH-COLL-016 | Printing as exfil (PrintService/Operational 307) | Microsoft-Windows-PrintService/Operational 307 |  |  |
| FH-COLL-017 | Bulk copy of files by robocopy / xcopy to staging or network location | Microsoft-Windows-Sysmon/Operational 1 |  |  |

## Impact

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-IMP-001 | Shadow copy deletion via vssadmin, wmic or diskshadow command line | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-IMP-002 | Shadow copy deletion via PowerShell Win32_ShadowCopy | Microsoft-Windows-PowerShell/Operational 4104 |  |  |
| FH-IMP-003 | Backup catalog or system state backup deletion with wbadmin | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-IMP-004 | Boot recovery disabled with bcdedit | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-IMP-005 | Shadow storage shrunk to force deletion of snapshots (vssadmin resize shadowstorage) | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-IMP-006 | Defender real-time protection disabled (5001) | Microsoft-Windows-Windows Defender/Operational 5001 |  |  |
| FH-IMP-007 | Tamper Protection blocked a Defender setting change (5013) | Microsoft-Windows-Windows Defender/Operational 5013 |  |  |
| FH-IMP-008 | Defender detection history deleted (1013) | Microsoft-Windows-Windows Defender/Operational 1013 |  |  |
| FH-IMP-009 | Event log cleared as precursor (Security 1102, System 104) | Security 1102,104 |  |  |
| FH-IMP-010 | Backup, AV or database service stopped (System 7036 / command line) | System 7036 |  |  |
| FH-IMP-011 | Service start type changed to disabled (System 7040) or sc config disabled | System 7040 |  |  |
| FH-IMP-012 | Service or process kill of security/backup tooling via taskkill, net stop or Stop-Service | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-IMP-013 | Mass file creation or rename burst with ransom-note style names (Sysmon 11) | Microsoft-Windows-Sysmon/Operational 11 |  |  |
| FH-IMP-014 | Mass file deletion burst (Sysmon 23 / 26) | Microsoft-Windows-Sysmon/Operational 23,26 |  |  |
| FH-IMP-015 | Secure deletion / free-space wipe (sdelete, cipher /w, Sysmon 28) | Microsoft-Windows-Sysmon/Operational 1,28 |  |  |
| FH-IMP-016 | Mass password changes or resets (4723 / 4724 burst) and many account lockouts (4740) | Security 4723,4724,4740 |  |  |
| FH-IMP-017 | Safe-mode boot forced or system rebooted by script (bcdedit safeboot, shutdown) | Microsoft-Windows-Sysmon/Operational 1 |  |  |
| FH-IMP-018 | System shutdown or restart initiated (1074), unexpected shutdown (6008), log stop/start (6006/6005) | System 1074,6006,6008,6005 |  |  |
| FH-IMP-019 | Defacement or ransom wallpaper (web root writes, wallpaper registry change) | Microsoft-Windows-Sysmon/Operational 11,13 |  |  |

## File System (NTFS $MFT and $UsnJrnl)

| Id | Check | Source | Status | Evidence / reason |
|---|---|---|---|---|
| FH-FS-001 | Timestomping - $STANDARD_INFORMATION created before $FILE_NAME created | MFT 16 |  |  |
| FH-FS-002 | Timestamps with zero sub-seconds on executables | MFT 16 |  |  |
| FH-FS-003 | Executables or scripts created in user-writable staging folders | UsnJrnl 1 |  |  |
| FH-FS-004 | Files downloaded from the internet (Zone.Identifier with a URL) | MFT 16,48 |  |  |
| FH-FS-005 | Memory dump files (credential dumping output) | UsnJrnl 1,2 |  |  |
| FH-FS-006 | Executables, scripts or archives deleted (cleanup) | UsnJrnl 2 |  |  |
| FH-FS-007 | Event log files or Prefetch files deleted | UsnJrnl 2 |  |  |
| FH-FS-008 | Mass renames to one new extension or ransom notes (ransomware) | UsnJrnl 3,1 |  |  |
| FH-FS-009 | Windows process names outside their system folders (masquerading) | MFT 48 |  |  |
| FH-FS-010 | Remote execution service binaries dropped in the Windows folder | MFT 48 |  |  |
| FH-FS-011 | Timestamp or attribute change on an executable (journal BasicInfoChange) | UsnJrnl 5,4,1 |  |  |
| FH-FS-012 | Both timestomp indicators on the same file (any extension) | MFT 16 |  |  |
| FH-FS-013 | Offensive and credential-theft tool names or output files | MFT 48,1 |  |  |
| FH-FS-014 | Remote access, tunnelling and file-transfer tool binaries | MFT 48,1 |  |  |
| FH-FS-015 | Archives in staging folders and rclone traces (collection, exfiltration) | UsnJrnl 1 |  |  |
| FH-FS-016 | Remote-execution tool output files and random-named service binaries in \Windows | UsnJrnl 1 |  |  |
| FH-FS-017 | Script or page files written to web roots (webshells) | UsnJrnl 1 |  |  |
| FH-FS-018 | Scripts, binaries or shortcuts written to Startup folders | UsnJrnl 1 |  |  |
| FH-FS-019 | New scheduled task definition files in the Tasks folder | UsnJrnl 1 |  |  |
| FH-FS-020 | WMI repository writes and MOF files (WMI persistence) | UsnJrnl 4,1 |  |  |
| FH-FS-021 | Driver files dropped in user-writable folders and spool\drivers\color | UsnJrnl 1 |  |  |
| FH-FS-022 | DLL side-loading staging (trailing-space folders, DLLs in AppData and ProgramData) | UsnJrnl 1 |  |  |
| FH-FS-023 | Credential store copies (SAM, SYSTEM, SECURITY hives, ntds.dit, IFM, browser databases) | MFT 48,1 |  |  |
| FH-FS-024 | Anti-forensic and recovery-inhibiting tools (Prefetch), SDelete rename names | UsnJrnl 1,2,3,4 |  |  |
| FH-FS-025 | Shell history, web server logs or backup files deleted | UsnJrnl 2 |  |  |
| FH-FS-026 | Mark-of-the-Web removed (Zone.Identifier stream deleted or truncated) | UsnJrnl 5,4 |  |  |
| FH-FS-027 | Alternate data streams other than Zone.Identifier | MFT 48 |  |  |
| FH-FS-028 | Documents renamed with an appended extension (ransomware rename pattern) | UsnJrnl 3 |  |  |
| FH-FS-029 | RDP client artefacts (bitmap cache, .rdp files) on a source host | UsnJrnl 1 |  |  |
| FH-FS-030 | Executables renamed in staging folders and lure-style file names | UsnJrnl 3,1 |  |  |
| FH-FS-031 | USN journal reset or late start (journal deleted) | MFT 16 |  |  |

## Summary

| Tactic | HIT | NO_HIT | NOT_APPLICABLE | LOG_SOURCE_MISSING |
|---|---|---|---|---|
| initial-access |  |  |  |  |
| execution |  |  |  |  |
| persistence |  |  |  |  |
| privilege-escalation |  |  |  |  |
| defense-evasion |  |  |  |  |
| credential-access |  |  |  |  |
| discovery |  |  |  |  |
| lateral-movement |  |  |  |  |
| remote-access |  |  |  |  |
| active-directory |  |  |  |  |
| collection-exfiltration |  |  |  |  |
| impact |  |  |  |  |
| filesystem |  |  |  |  |
