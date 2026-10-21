# Sources: execution and persistence checklists

Research environment note: the session's egress proxy allowed only GitHub hosts (git clone and raw.githubusercontent.com). learn.microsoft.com, attack.mitre.org, jpcertcc.github.io, ultimatewindowssecurity.com, thedfirreport.com, redcanary.com and similar sites were unreachable (DNS/403). Every URL below was read as file content from a git checkout (or raw fetch) of the named GitHub repository on 2026-10-21. No rule text was copied; checks are written in my own words.

## Microsoft documentation (read from the MicrosoftDocs source repositories)
- https://github.com/MicrosoftDocs/sysinternals/blob/main/sysinternals/downloads/sysmon.md - Confirmed Sysmon event meanings: 1 (process creation), 7 (image loaded, disabled by default, noisy), 11 (file create; useful for Startup folder), 12/13/14 (registry create/delete, value set, rename; useful for autostart keys; HKLM/HKU abbreviations), 19/20/21 (WMI filter, consumer, consumer-to-filter binding). It does not list the per-event field tables or the channel name.
- https://github.com/MicrosoftDocs/PowerShell-Docs/blob/main/reference/7.5/Microsoft.PowerShell.Core/About/about_Logging_Windows.md - Confirmed script block logging produces event 4104 in an Operational channel (PowerShell 7 page: PowerShellCore/Operational) and module logging exists; says nothing on 4103 field names or the Windows PowerShell 5.1 channel.

## MITRE ATT&CK
- https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack/enterprise-attack.json - Used only to confirm technique IDs and names (T1047, T1053.005, T1059.001/.003/.005/.007, T1098, T1105, T1127.001, T1136.001/.002, T1140, T1197, T1204.002, T1218 and .001/.003/.004/.005/.010/.011, T1220, T1027, T1059, T1070, T1569.002 (T1562.001 was NOT found as an active technique in this ATT&CK release; used in FH-EXE-008 and FH-PER-003 from older knowledge), T1543.003, T1546.003/.007/.008/.009/.010/.012/.015, T1547.001/.004, T1037.001, T1574.011). The data-source/detection text in this release format was not usable.

## SigmaHQ (read, cited, not copied) - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/
Paths below are relative to that URL. Each file body was opened unless stated.
- process_creation/proc_creation_win_office_susp_child_processes.yml - Office parent processes and LOLBin child list; field names ParentImage, Image, OriginalFileName.
- process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml - Encoded PowerShell matching idea (-e prefix plus base64 starts).
- process_creation/proc_creation_win_powershell_downgrade_attack.yml - Downgrade via -Version 2 command-line forms.
- process_creation/proc_creation_win_mshta_susp_execution.yml - Mshta with non-HTA file extensions / vbscript.
- process_creation/proc_creation_win_regsvr32_susp_parent.yml - Regsvr32 started by script hosts/shells.
- process_creation/proc_creation_win_certutil_download.yml - Certutil urlcache/verifyctl with http.
- process_creation/proc_creation_win_bitsadmin_potential_persistence.yml - Bitsadmin /SetNotifyCmdLine and /Addfile with URL.
- process_creation/proc_creation_win_wmic_eventconsumer_creation.yml - Wmic creating ActiveScriptEventConsumer.
- process_creation/proc_creation_win_wscript_cscript_uncommon_extension_exec.yml - Script hosts running files with non-script extensions.
- process_creation/proc_creation_win_msbuild_susp_parent_process.yml - Msbuild by uncommon parent.
- process_creation/proc_creation_win_netsh_helper_dll_persistence.yml - netsh add helper command line.
- process_creation/proc_creation_win_sc_create_service.yml - sc create binPath, Dropbox installer filter.
- process_creation/proc_creation_win_net_user_add.yml - Net user /add.
- powershell/powershell_classic/posh_pc_downgrade_attack.yml - EngineVersion=2 without HostVersion=2 in classic engine start data.
- powershell/powershell_script/posh_ps_susp_download.yml, posh_ps_amsi_null_bits_bypass.yml, posh_ps_wmi_persistence.yml - Script block (ScriptBlockText) ideas; "Script Block Logging must be enabled".
- powershell/powershell_module/posh_pm_susp_download.yml - Module logging rule keyed on ContextInfo.
- image_load/image_load_dll_amsi_suspicious_process.yml, image_load/image_load_wmi_persistence_commandline_event_consumer.yml - amsi.dll in uncommon hosts; wbemcons.dll in WmiPrvSE.
- file/file_event/file_event_win_startup_folder_file_write.yml - Sysmon 11 TargetFilename path for the Startup folder.
- registry/registry_set/registry_set_susp_run_key_img_folder.yml - Run key TargetObject/Details fields.
- registry/registry_set/registry_set_winlogon_notify_key.yml - Winlogon Notify key.
- registry/registry_event/registry_event_stickykey_like_backdoor.yml - IFEO Debugger paths for sethc/utilman/osk/Magnify/Narrator/DisplaySwitch/atbroker/HelpPane.
- registry/registry_event/registry_event_new_dll_added_to_appinit_dlls_registry_key.yml - AppInit_DLLs paths and "(Empty)" filter.
- registry/registry_set/registry_set_persistence_com_hijacking_builtin.yml - COM hijack via InprocServer32/LocalServer32 default value.
- registry/registry_set/registry_set_netsh_helper_dll_potential_persistence.yml - HKLM\SOFTWARE\Microsoft\NetSh values with .dll.
- registry/registry_set/registry_set_persistence_logon_scripts_userinitmprlogonscript.yml - UserInitMprLogonScript.
- wmi_event/sysmon_wmi_event_subscription.yml, wmi_event/sysmon_wmi_susp_scripting.yml - Sysmon 19/20/21 and Destination field.
- builtin/wmi/win_wmi_persistence.yml - WMI-Activity events 5859/5861, PossibleCause/Query/User/Provider, "needs Windows 10 / 2012+".
- builtin/system/service_control_manager/win_system_service_install_susp.yml, win_system_susp_service_installation_folder.yml, win_system_susp_service_installation_script.yml - System 7045, Provider_Name "Service Control Manager", ImagePath.
- builtin/security/win_security_powershell_script_installed_as_service.yml - Security 4697, ServiceFileName, needs System Security Extension auditing.
- builtin/security/win_security_susp_scheduled_task_creation.yml, win_security_susp_scheduled_task_update.yml - 4698 TaskContent, 4702 TaskContentNew, needs Other Object Access Events.
- builtin/taskscheduler/win_taskscheduler_execution_from_susp_locations.yml, win_taskscheduler_susp_schtasks_delete_or_disable.yml - TaskScheduler/Operational disabled by default; 129 with Path; 141/142 with TaskName/UserName.
- builtin/bits_client/win_bits_client_new_job_via_bitsadmin.yml, win_bits_client_new_transfer_saving_susp_extensions.yml - Bits-Client event 3 (processPath) and 16403 (LocalName/RemoteName).
- builtin/security/win_security_user_creation.yml, win_security_hidden_user_creation.yml, win_security_alert_ad_user_backdoors.yml - 4720 (TargetUserName), 4738 (AllowedToDelegateTo).

Only file names were seen in directory listings (bodies NOT opened, therefore not cited as sources in any check): rundll32_* family, wmic_remote_execution, wmic_xsl_script_processing, wmiprvse_spawning_process, certutil_decode, bitsadmin_download, installutil_download, mshta_http, regsvr32_network_pattern, wscript_cscript_susp_child_processes, posh_ps_download_com_cradles, posh_ps_amsi_bypass_pattern_nov22, registry_set_powershell_in_run_keys, registry_set_treatas_persistence, registry_set_persistence_globalflags, registry_set_servicedll_hijack, registry_set_asep_reg_keys_modification_currentversion_nt, proc_creation_win_registry_install_reg_debugger_backdoor, posh_pc_tamper_windows_defender_set_mp (matched by grep only).

## Hayabusa rules (cited, not copied) - https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/
- builtin/System/Sys_7045_Info_SvcInstalled.yml - System 7045 and ServiceName/ImagePath/AccountName/StartType fields.
- builtin/Security/System/SecuritySystemExtension/Sec_4697_Info_SvcInstalled.yml - Security 4697 sample message (ServiceName, ServiceFileName, ServiceType, ServiceStartType).
- builtin/Security/ObjectAccess/OtherObjectAccessEvents/Sec_4698_Info_TaskCreated.yml, Sec_4699_Info_TaskDeleted.yml - 4698/4699 sample messages (TaskName, TaskContent); "Other Object Access Events needs to be turned on".
- builtin/TaskScheduler_Op/TaskSch_106_Info_TaskCreated.yml, TaskSch_140_Info_TaskUpdated.yml, TaskSch_141_Info_TaskDeleted.yml, TaskSch_200_Info_TaskExecuted.yml - Task Scheduler Operational 106/140/141/200 and TaskName/UserContext/UserName/ActionName.
- builtin/WMI-Activity_Op/WMI_5857_Info_ProviderStarted.yml, WMI_5860_Info_TempEventConsumerRegistered.yml, WMI_5861_Info_PermEventConsumerRegistered.yml - WMI-Activity/Operational 5857/5860/5861 and their meaning; "default in 10 / 2012-R2+".
- builtin/BitsClient_Op/BitsCli_59_Info_BitsJobCreated.yml - Bits-Client 59 with JobTitle/Url (labelled "job created" by Hayabusa).
- sysmon/Sysmon_19_Info_WmiEventFilterActivity.yml, Sysmon_20_Info_WmiEventConsumerActivity.yml, Sysmon_21_Info_WmiEventConsumerToFilterActivity.yml - Sysmon channel name Microsoft-Windows-Sysmon/Operational and events 19/20/21.

## Chainsaw rules (cited, not copied) - https://github.com/WithSecureLabs/chainsaw/blob/master/rules/evtx/
- persistence/T1053.005 - Scheduled Task was Created.yml - TaskScheduler/Operational 106 with TaskName/UserContext.
- persistence/T1547.004 - Winlogon System Shell Changed.yml - 4688 with SubjectUserName, ParentProcessName, NewProcessName, CommandLine; userinit.exe child other than explorer.exe.
- powershell/eid_400_powershell_engine_state_available.yml - Event 400 Data blob with HostName/HostVersion/EngineVersion.
- powershell/eid_4104_powershell_script_executed.yml - 4104 in Microsoft-Windows-PowerShell/Operational, Path field.
- account_tampering/new_user_created.yml - 4720 TargetUserName/TargetSid.

## Community index
- https://github.com/stuhli/awesome-event-ids - README read (partly via keyword search): links to Microsoft command-line process auditing (4688 command line) and Script Block Logging (4104); lists Sysmon, SwiftOnSecurity and sysmon-modular configs.

## Open questions
1. Microsoft Learn security-auditing pages (4688, 4697, 4698-4702, 4720, 4722, 4738, 7045 equivalents) and the ATT&CK, JPCERT/CC Tool Analysis, SANS poster, NSA, ANSSI, Red Canary and DFIR Report pages could not be opened. Nearly all `verified` flags therefore rest on Sigma/Hayabusa/Chainsaw agreement, not on Microsoft primary docs; re-verify field semantics when egress allows.
2. Bits-Client event semantics: Sigma uses 3 for a new job (processPath) and 16403 for a transfer to disk; Hayabusa labels 59 as "job created" with Url. Need Microsoft/Bits-Client manifest confirmation of 3, 59, 60, 61 and their fields.
3. Event 600 (classic PowerShell provider start), 4700/4701 (task enabled/disabled), 7036/7040 parameter layout, and TaskScheduler 129 vs 200/201 field names (Path vs ActionName) were not confirmed in a source I opened.
4. WMI-Activity 5861 UserData field names differ between tools (PossibleCause vs Consumer/Namespace); confirm the exact element names on a real EVTX and what forhunt exposes.
5. Not covered because no rule/source was read: accessibility-feature file replacement (cmd.exe copied over sethc/utilman) beyond the IFEO route, AppCertDlls registry path confirmation, and Sysmon event 14 rename use.
6. Whether forhunt's `--field` accepts values containing spaces/backslashes without extra escaping is untested; queries quote them.
7. ATT&CK T1562.001 is cited in FH-EXE-008 and FH-PER-003 but was not found in the ATT&CK data release I read (the technique may have been renamed or restructured); update those ids.
