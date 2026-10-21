# Sources: privilege escalation, credential access, defense evasion

Research scope: checklists `privilege-escalation.yaml`, `credential-access.yaml`, `defense-evasion.yaml`. Every URL below was actually fetched and read (GitHub raw content). Nothing was copied; rule logic was re-expressed in the checklists in new words.

## Access limits during research

The sandbox egress proxy allowed `raw.githubusercontent.com` only. These hosts were tried and refused (403 CONNECT or DNS failure), so they are NOT cited anywhere and nothing from them is claimed:
learn.microsoft.com (Windows security auditing event pages, Sysinternals Sysmon page, Defender event ids), attack.mitre.org, jpcertcc.github.io, ultimatewindowssecurity.com, redcanary.com, thedfirreport.com, www.nsa.gov, github.com (HTML pages, archives, API).

Consequences: no check could be confirmed against Microsoft Learn, so `verified: true` rests on two community sources (SigmaHQ and Hayabusa rules, written independently by different maintainers) or a community rule plus the TrustedSec Sysmon guide. Checks marked `verified: false` have only one source or contain analyst-knowledge elements; the `notes` field of each says which.

## URLs read

### SigmaHQ rules (raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/...)

- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_user_couldnt_call_priv_service_lsaregisterlogonprocess.yml - 4673 Service LsaRegisterLogonProcess() failures
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_scm_database_privileged_operation.yml - 4674 SC_MANAGER OBJECT servicesactive SeTakeOwnershipPrivilege
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_user_added_to_local_administrators.yml - 4732 TargetSid S-1-5-32-544
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml - 4728 (global group member added)
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_susp_group_policy_abuse_privilege_addition.yml - 5136 gPCMachineExtensionNames GUIDs (rights assignment through GPO)
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/registry/registry_set/registry_set_bypass_uac_using_eventviewer.yml - Sysmon 13 mscfile\shell\open\command
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/registry/registry_set/registry_set_uac_bypass_eventvwr.yml - Sysmon 13 mscfile\shell\open\command (second rule)
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/registry/registry_set/registry_set_uac_bypass_sdclt.yml - Sysmon 13 sdclt isolatedCommand / SymbolicLinkValue
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_uac_bypass_fodhelper.yml - children of fodhelper.exe
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_uac_bypass_computerdefaults.yml - ComputerDefaults.exe at High/System integrity with unexpected parent
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/system/service_control_manager/win_system_hack_smbexec.yml - 7045 smbexec service name and ImagePath patterns
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/system/service_control_manager/win_system_cobaltstrike_service_installs.yml - 7045 ImagePath patterns (ADMIN$, %COMSPEC% start powershell)
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/system/service_control_manager/win_system_meterpreter_or_cobaltstrike_getsystem_service_installation.yml - 7045 getsystem ImagePath patterns (pipe echo, rundll32, ADMIN$)
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_susp_service_creation.yml - sc/New-Service with suspicious binary paths
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_sc_create_service.yml - sc create binPath
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/pipe_created/pipe_created_hktl_coercedpotato.yml - Sysmon 17/18 \coerced\ pipe
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/pipe_created/pipe_created_hktl_efspotato.yml - Sysmon 17/18 EfsPotato pipe; notes Sysmon config requirement
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/pipe_created/pipe_created_hktl_cobaltstrike.yml - Sysmon 17/18 Cobalt Strike pipe-name patterns
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/account_management/win_security_access_token_abuse.yml - 4624 LogonType 9, LogonProcessName Advapi, ImpersonationLevel %%1833
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/account_management/win_security_susp_rottenpotato.yml - 4624 type 3 ANONYMOUS LOGON from loopback with WorkstationName -
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_access/proc_access_win_lsass_memdump.yml - Sysmon 10 GrantedAccess masks and CallTrace modules; deliberately omits 0x1010/0x1410 for FPs
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_susp_lsass_dump_generic.yml - 4656/4663 on lsass.exe, AccessMask and AccessList values (4484, 4416), long filter list
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml - Sysmon 10 rundll32 -> lsass with comsvcs.dll in CallTrace
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_sysinternals_procdump_lsass.yml - procdump -ma/-mm/-mp with ls/keyiso/samss
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml - Mimikatz module and function names in command lines
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_lsass_access_non_system_account.yml - 4656/4663 lsass.exe access masks and Program Files filters
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_asr_lsass_access.yml - Defender event 1121 ASR block on lsass.exe, fields Path / ProcessName
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_reg_dumping_sensitive_hives.yml - reg save/export of hklm system/sam/security
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_sam_registry_hive_handle_request.yml - 4656 ObjectType Key, ObjectName ending \SAM
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_ntdsutil_susp_usage.yml - ntdsutil snapshot mount / activate instance ntds patterns
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/application/esent/win_esent_ntdsutil_abuse.yml - Application/ESENT events 216/325/326/327 with ntds.dit in the data (ntdsutil abuse on a DC)
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_esentutl_params.yml - esentutl ... /p pattern ("gather credentials")
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_dpapi_domain_backupkey_extraction.yml - 4662 SecretObject BCKUPKEY, AccessMask 0x2
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_dpapi_domain_masterkey_backup_attempt.yml - 4692 DPAPI master key backup
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_susp_failed_logon_reasons.yml - 4625/4776 Status and SubStatus restricted-account codes (0xC0000072, 0xC000006F, ...)
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/account_management/win_security_susp_failed_logon_source.yml - 4625 with IpAddress as source field
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_susp_kerberos_manipulation.yml - 4768/4769/4771 Status code list
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_kerberoasting_activity.yml - 4769 Status 0x0, TicketEncryptionType 0x17, krbtgt/$ exclusions
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml - 4769 TicketOptions 0x40810000 with RC4
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml - 4768 PreAuthType 0, TicketEncryptionType 0x17, ServiceName krbtgt
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_register_new_logon_process_by_rubeus.yml - 4611 LogonProcessName User32LogonProcesss
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/system/service_control_manager/win_system_mal_creddumper.yml - 7045 ImagePath containing credential dumper names
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/registry/registry_set/registry_set_wdigest_enable_uselogoncredential.yml - Sysmon 13 WDigest UseLogonCredential DWORD 1
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_threat.yml - 1006/1015/1116/1117 detections
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_audit_log_cleared.yml - 1102 in Security, provider Microsoft-Windows-Eventlog (and legacy 517)
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/system/microsoft_windows_eventlog/win_system_eventlog_cleared.yml - System 104, provider Microsoft-Windows-Eventlog, filter on other channels
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/system/microsoft_windows_eventlog/win_system_susp_eventlog_cleared.yml - System 104 for important channels (Security, System, Sysmon, PowerShell, Windows PowerShell)
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.yml - wevtutil cl/sl, Clear-EventLog, ClearLog and WMI clear patterns
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/wmi/win_wmi_activity_nteventlogfile_cleareventlog.yml - WMI-Activity 5858 failed Win32_NTEventlogFile ClearEventLog
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_disable_event_auditing.yml - 4719 AuditPolicyChanges %%8448/%%8450 and SubcategoryGuid values
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_disable_event_auditing_critical.yml - 4719 high-value audit subcategory GUIDs
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_susp_time_modification.yml - 4616 with Audit Security State Change requirement
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_real_time_protection_disabled.yml - 5001 real-time protection disabled
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_virus_scan_disabled.yml - 5012 virus scanning disabled
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_malware_and_pua_scan_disabled.yml - 5010 scanning disabled
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_config_change_exclusion_added.yml - 5007 NewValue containing Defender Exclusions
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_suspicious_features_tampering.yml - 5007 values for DisableAntiSpyware, SpyNet, scan features
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_tamper_protection_trigger.yml - 5013 tamper protection blocked change, field Value
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_config_change_exploit_guard_tamper.yml - 5007 Controlled Folder Access changes (OldValue/NewValue)
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_powershell_defender_exclusion.yml - Add/Set-MpPreference exclusion parameters
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/registry/registry_set/registry_set_defender_exclusions.yml - Sysmon 13 Defender Exclusions registry
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/system/service_control_manager/win_system_defender_disabled.yml - 7036 Windows Defender Antivirus Service stopped, params param1/param2, localised
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_net_stop_service.yml - net stop pattern
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_history_delete.yml - 1013 history deleted
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/windefend/win_defender_restored_quarantine_file.yml - 1009 item restored from quarantine
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/sysmon/sysmon_config_modification.yml - Sysmon event 16
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/sysmon/sysmon_config_modification_status.yml - Sysmon 4 State Stopped / config state changed
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/sysmon/sysmon_config_modification_error.yml - Sysmon 255 Description strings
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_fltmc_unload_driver_sysmon.yml - fltMC unload sysmon
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_sysmon_channel_reference_deletion.yml - 4657/4663 on WINEVT Sysmon channel/publisher keys
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/firewall_as/win_firewall_as_add_rule.yml - firewall-as service; add-rule ids 2004/2071/2097; fields ModifyingApplication, ApplicationPath, Action
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/firewall_as/win_firewall_as_delete_rule.yml - ids 2006/2052 rule deleted
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/firewall_as/win_firewall_as_delete_all_rules.yml - ids 2033/2059 all rules deleted
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/firewall_as/win_firewall_as_reset_config.yml - ids 2032/2060 firewall reset to defaults
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_netsh_fw_disable.yml - netsh firewall opmode disable / advfirewall state off
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_netsh_fw_set_rule.yml - netsh firewall set rule enabling groups
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_tampering/proc_tampering_susp_process_hollowing.yml - Sysmon 25 Type "Image is replaced" with filters
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/powershell/powershell_script/posh_ps_timestomp.yml - 4104 timestamp assignment strings
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/powershell/powershell_script/posh_ps_amsi_bypass_pattern_nov22.yml - 4104 AMSI reflection bypass strings
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/security/win_security_dot_net_etw_tamper.yml - 4657 ETWEnabled / COMPlus_ETWEnabled set to 0
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_svchost_masqueraded_execution.yml - svchost.exe outside System32/SysWOW64 or with different OriginalFileName
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_svchost_execution_with_no_cli_flags.yml - bare svchost.exe command line
- https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_rundll32_no_params.yml - rundll32 with no arguments

### Hayabusa rules (raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/...)

- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/LogonLogoff/SpecialLogon/Sec_4672_Info_AdminLogon.yml - 4672 with system/machine account filters
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/PrivilegeUse/Sec_4673_Med_PrivSvcCalled_UnknownProcUsedHighPriv.yml - 4673 allow-list of common processes
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/PrivilegeUse/Sec_4674_Med_OpAttemptOnPrivObj_PossibleHiddenSvcCreationAttempt.yml - 4674 SERVICE OBJECT, AccessMask %%1539 (WRITE_DAC), ProcessName services.exe
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/AccountManagement/SecurityGroupManagement/Sec_4732_High_MemberAddedToLocalGrp_Administrators.yml - 4732 TargetUserName Administrators
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/AccountManagement/SecurityGroupManagement/Sec_4728_High_MemberAddedToGlobalGrp_DomainAdmins.yml - 4728 Domain Admins, filters machine-account actors
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/AccountManagement/SecurityGroupManagement/Sec_4732_High_MemberAddedToLocalGrp_DomainAdmins.yml - 4732 TargetUserName Domain Admins
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/System/Sys_7045_High_ServiceInstalled_SuspiciousServicePath.yml - 7045 ImagePath patterns (powershell, cmd, base64)
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/DetailedTracking/ProcessCreation/Sec_4688_Med_ProcExec_MeterpreterGetSystem.yml - 4688 cmd.exe with \pipe in command line
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/sysmon/Sysmon_17_PipeCreated_RuleAlert.yml - Sysmon 17 channel/event
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4624_Med_Logon-Type9-NewInteractive_PossibleTokenImpersonation.yml - 4624 type 9, ImpersonationLevel %%1833, SubjectUserName = TargetUserName
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/sysmon/Sysmon_10_High_ProcessAccess_RuleAlert.yml - Sysmon 10 channel and RuleName concept
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/Default/Sec_5397_Low_CredentialManagerAccessed.yml - 5379 ReadOperation %%8099 Credential Manager read
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml - 4625 0xc000006a correlation rule
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Low_LogonFail_WrongPW.yml - 4625 SubStatus 0xc000006a (wrong password)
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml - 4625 0xc0000064 correlation rule
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Low_LogonFail_NonExistantUser.yml - 4625 SubStatus 0xc0000064 (user does not exist)
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4648_Med_ExplicitLogon_PW-Spray_Correlation.yml - 4648 volume as spray indicator
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/AccountLogon/CredentialValidation/Sec_4776_Info_NTLM-Auth.yml - 4776 logged for NTLM validation; clients as well as DCs
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/AccountLogon/KerberosAuthenticationService/Sec_4769_Med_KerberosTGT-Request_PossibleKerberoasting.yml - 4769 TicketEncryptionType 0x17
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/AccountLogon/KerberosAuthenticationService/Sec_4768_Med_KrbTGT-Req_PossibleAS-REP-Roasting.yml - 4768 TicketEncryptionType 0x17 + PreAuthType 0
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/System/SecuritySystemExtension/Sec_4611_High_AbnormalLogonProcessRegisteredWithLSA.yml - 4611 from non-SYSTEM/non-machine accounts
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/WindowsDefender/Defender_1116_High_Alert.yml - Defender operational channel, 1116, SeverityID
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/Security/Default/Sec_1102_High_SecLogCleared.yml - 1102 Security channel
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/System/Sys_104_High_ImportantLogCleared.yml - System 104 with LogFileClearedChannel list
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/System/Sys_104_Med_LogCleared.yml - System 104 for other channels
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/System/Sys_7040_Med_EventLogServiceStartupDisabled.yml - 7040 param1 Windows Event Log, param3 disabled
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/builtin/System/Sys_6006_Info_EventLogSvcStopped.yml - 6006 EventLog service stopped
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/sysmon/Sysmon_16_Info_SysmonConfigChange.yml - Sysmon 16
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/sysmon/Sysmon_255_Low_Error.yml - Sysmon 255
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/sysmon/Sysmon_4_Info_SvcStateChanged.yml - Sysmon 4
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/sysmon/Sysmon_25_Med_ProcessTampering.yml - Sysmon 25
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/sysmon/Sysmon_26_Med_FileDeleted_RuleAlert.yml - Sysmon 26
- https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/hayabusa/sysmon/Sysmon_2_Low_PossibleTimestomping.yml - Sysmon 2

### TrustedSec Sysmon Community Guide

- https://raw.githubusercontent.com/trustedsec/SysmonCommunityGuide/master/chapters/registry-actions.md - Sysmon 13 TargetObject / Details / EventType
- https://raw.githubusercontent.com/trustedsec/SysmonCommunityGuide/master/chapters/process-creation.md - Sysmon 1 fields (OriginalFileName, IntegrityLevel, ParentImage, CommandLine)
- https://raw.githubusercontent.com/trustedsec/SysmonCommunityGuide/master/chapters/named-pipes.md - Sysmon 17/18 PipeName / Image fields
- https://raw.githubusercontent.com/trustedsec/SysmonCommunityGuide/master/chapters/process-access.md - Sysmon 10 GrantedAccess literal comparison, CallTrace, masks 0x1010 / 0x1F1FFF
- https://raw.githubusercontent.com/trustedsec/SysmonCommunityGuide/master/chapters/file-create.md - Sysmon 11 Image / TargetFilename fields
- https://raw.githubusercontent.com/trustedsec/SysmonCommunityGuide/master/chapters/configuration.md - event 16 generated on sysmon -c config changes; registry edits do not log
- https://raw.githubusercontent.com/trustedsec/SysmonCommunityGuide/master/chapters/process-tampering.md - Sysmon 25 Type values, 13.0+
- https://raw.githubusercontent.com/trustedsec/SysmonCommunityGuide/master/chapters/file_delete_detected.md - Sysmon 26 file delete without archiving (13.10+)
- https://raw.githubusercontent.com/trustedsec/SysmonCommunityGuide/master/chapters/file-delete.md - Sysmon 23 file delete with archiving
- https://raw.githubusercontent.com/trustedsec/SysmonCommunityGuide/master/chapters/file-create-time-change.md - Sysmon 2 CreationUtcTime / PreviousCreationUtcTime

### Other

- https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json - ATT&CK STIX bundle (v20): verified technique ids, names, tactics; found Defense Evasion split into Stealth / Defense Impairment and revocation of T1070.001, T1562.* in favour of T1685.x / T1686.x
- https://raw.githubusercontent.com/Yamato-Security/EnableWindowsLogSettings/main/README.md - Yamato guide: recommended logging (4688 or Sysmon 1, PowerShell, retention); used for prerequisites context only

### Other URLs read (not cited by individual checks)

- https://raw.githubusercontent.com/stuhli/awesome-event-ids/master/README.md - awesome-event-ids index: confirmed it points to Microsoft security auditing docs, Ultimate Windows Security, Sysmon docs, NSA Spotting the Adversary, and Windows logging cheat sheets; none of these targets could be opened here
- https://raw.githubusercontent.com/trustedsec/SysmonCommunityGuide/master/chapters/what-is-sysmon.md - Sysmon event id table: 4 = service state change, 16 config change
- https://raw.githubusercontent.com/trustedsec/SysmonCommunityGuide/master/README.md - Chapter index of the guide

## Findings worth knowing

- Current MITRE ATT&CK data (v20 in attack-stix-data) no longer has a Defense Evasion tactic: it is split into Stealth and Defense Impairment, and T1070.001, T1562.001, T1562.002, T1562.004, T1562.006 are revoked (replaced by T1685.005, T1685, T1685.001, T1686, T1685). The checks list new and legacy ids together. Recent SigmaHQ rules already tag `attack.stealth`.
- SigmaHQ deliberately excludes GrantedAccess 0x1010 / 0x1410 from its Sysmon LSASS rule because of false positives, while keeping them in the Security 4656/4663 variant. The checklist therefore splits LSASS access into a high-confidence and a baseline-dependent check.
- Sysmon compares GrantedAccess as a literal string, not a bitmask (TrustedSec guide).
- Sysmon event 2 only detects creation-time changes; event 26 is file-delete without archiving, 23 archives.

## Open questions

1. Microsoft Learn confirmation: field names and semantics for 4672, 4673, 4674, 4704, 4756, 4907, 4692/4693/4695, 5381/5382, 1100 and the Defender ids (5001, 5007, 5010, 5012, 5013) were not checked against the vendor pages. Re-verify when egress to learn.microsoft.com is available.
2. EVTX field naming for event 104 (cleared channel is in UserData as `Channel`, which collides with System `Channel`; Hayabusa maps it to LogFileClearedChannel) and for Defender 1116 (the threat name element may be rendered as "Threat Name"). Both need a look at a real EVTX before forhunt `--field` queries are trusted.
3. Event-log gap detection: whether EventRecordID resets after a Security log clear, how rotation affects the first id, and what thresholds `forhunt stats` should use are not defined by any source read.
4. Windows Firewall operational channel: exact channel path and provider name, and whether 2005 (rule changed) is used on current builds; Sigma only lists add/delete/reset ids (including Windows 11 variants 2071, 2052, 2059, 2060, 2097).
5. Kerberoasting RC4 baselines: recent Windows Server hardening of Kerberos default encryption types may reduce legitimate RC4 or change how 0x17 appears; thresholds for count-per-requester are analyst starting points.
6. PrintSpoofer / other potato pipe names, ms-settings (fodhelper) registry hijack, comsvcs command lines, browser credential file artefacts and 4104 Mimikatz / AMSI / ETW strings are analyst knowledge: no read source covered them.
7. JPCERT/CC Tool Analysis Result Sheet, NSA Spotting the Adversary, Red Canary and DFIR Report were not reachable; consider a follow-up pass for tool-specific event traces (mimikatz, procdump, wmiexec, psexec).
