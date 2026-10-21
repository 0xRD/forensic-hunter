# Sources: impact, discovery, collection and exfiltration

Only URLs actually opened (HTTP 200 and content read) are listed.

## Opened
- https://raw.githubusercontent.com/MicrosoftDocs/sysinternals/main/sysinternals/downloads/sysmon.md - Microsoft Sysmon documentation source; confirmed event names and purposes for ids 1-29 and 255 (incl. 22 DNS, 23/26 file delete, 24 clipboard, 28 shredding block).
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml - shadow copy deletion via vssadmin/wmic/diskshadow/PowerShell, wbadmin delete catalog, vssadmin resize shadowstorage.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.yml - bcdedit recoveryenabled no / bootstatuspolicy ignoreallfailures.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_nltest_recon.yml - nltest discovery flags (dclist, domain_trusts, dsgetdc, etc.).
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_ad_user_enumeration.yml - 4662 read-property on user class GUID; requires "Read all properties" SACL for Everyone.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_susp_net_recon_activity.yml - 4661 SAM_USER/SAM_GROUP, AccessMask 0x2d, RID -500/-512; notes Audit SAM / Kernel Object volume.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_7zip_password_compression.yml - 7-Zip with -p and a/u verbs.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_pua_rclone_execution.yml - rclone command-line markers.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_pua_adfind_susp_usage.yml - AdFind flag list.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/dns_query/dns_query_win_mega_nz.yml - Sysmon 22 QueryName for MEGA user storage.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_real_time_protection_disabled.yml - Defender 5001.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_tamper_protection_trigger.yml - Defender 5013 with Value registry path.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_history_delete.yml - Defender 1013.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_audit_log_cleared.yml - 1102 (Provider Microsoft-Windows-Eventlog) and legacy 517.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_external_device.yml - Security 6416 with ClassName DiskDrive / USB Mass Storage Device.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_smb_file_creation_admin_shares.yml - 5145 field names ShareName, AccessMask, IpAddress, SubjectUserName.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_susp_ldap_dataexchange.yml - 5136 requires Audit Directory Service Changes and SACLs.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/powershell/powershell_script/posh_ps_software_discovery.yml - 4104 ScriptBlockText and Script Block Logging prerequisite; installed software discovery.
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/file/file_event/file_event_win_perflogs_susp_files.yml - archive/executable files in C:\PerfLogs are suspicious.
- https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1490/T1490.md - vssadmin/wmic/wbadmin/bcdedit/Win32_Shadowcopy command forms.
- https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1485/T1485.md - cipher /w (read via filtered output).
- https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1489/T1489.md - taskkill service/process stop (read via filtered output).
- https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1529/T1529.md - shutdown /s /r forms (filtered output).
- https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1486/T1486.md - ransom note file names, 7z -p encryption example (filtered output).
- https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1560.001/T1560.001.md - rar/7z a -p; bitsadmin used for download (filtered output).
- https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1567.002/T1567.002.md - rclone with a mega remote (filtered output).
- https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1115/T1115.md - Get-Clipboard / clip examples (filtered output).
- https://raw.githubusercontent.com/mdecrevoisier/EVTX-to-MITRE-Attack/master/README.md - catalog mapping techniques to event ids: 4661/4662/4799/5145/4769/131 for discovery, 4104/1/4688 for VSS deletion, 4723/4724.
- https://raw.githubusercontent.com/stuhli/awesome-event-ids/master/README.md - index; confirmed only that 4104 is recommended and that Sysmon/Defender resources are linked (no id tables).
- https://raw.githubusercontent.com/JPCERTCC/ToolAnalysisResultSheet/master/README.md - repository readme only; the per-tool HTML sheet was not readable.

## Not reachable (attempted)
learn.microsoft.com (DNS failure), attack.mitre.org, jpcertcc.github.io, thedfirreport.com, redcanary.com, nsa.gov, cisa.gov (proxy 403 or DNS failure). GitHub raw paths for MicrosoftDocs audit-event pages returned 404.

## Open questions
1. Microsoft Learn was unreachable: field names and audit subcategories for 4798, 4799, 4661, 4662, 5145, 5156/5157, 6416 and all `(k)` rows in eventids.md are not confirmed from the primary vendor page, so most checks stay verified: false.
2. Process-start telemetry: confirm Security 4688 field mapping (NewProcessName/CommandLine) versus Sysmon 1 for each command-line check, and whether Sigma's ATT&CK renumbering (it used t1685 for defence impairment) reflects a newer ATT&CK version than the T1562.001 ids used here.
3. Ransom note names, extension bursts, DNS tunnelling length thresholds, Sysmon 3 fan-out and file-burst thresholds are heuristics without a citable source; they need validation on real ransomware EVTX samples (DFIR Report, CISA #StopRansomware advisories).
4. USB/print events (DriverFrameworks 2003/2100, Partition/Diagnostic 1006, PrintService 307, Removable Storage 4663 semantics) are from analyst knowledge only.
5. 1074/7036/7040 parameter layouts (param1..param7) and Defender 1118/1119 naming need confirmation.
