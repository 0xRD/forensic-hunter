# Sources - Active Directory checklist

Access note: from this environment learn.microsoft.com, support.microsoft.com, attack.mitre.org, adsecurity.org,
jpcertcc.github.io, thedfirreport.com, elastic.co and ultimatewindowssecurity.com all returned proxy 403 / DNS failure.
Only GitHub content was readable (shallow clones into a scratch directory, files read locally). Sample EVTX files
from two public repositories were parsed with python-evtx to confirm real field names and values. No Microsoft Learn
page was opened, so `verified: true` in the checklist means "confirmed by an independent rule project AND a real sample
EVTX (or two independent rule projects)", not "confirmed by Microsoft documentation".

## Detection rules read (cited only, not copied)

- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_kerberoasting_activity.yml - 4769, RC4 0x17, Status 0x0, aggregation idea (many services in ~5 s); threshold left to analyst
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml - 4769 RC4 with TicketOptions 0x40810000, filter on ServiceName ending $
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml - 4768 PreAuthType 0, RC4, ServiceName krbtgt
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml - 4662 DCSync GUIDs incl. 9923a32a Synchronize; requires domain-root SACL and Directory Service Access; filters $ and MSOL_
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml - 5136 nTSecurityDescriptor containing replication GUIDs on non-DNS objects
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_possible_dc_shadow.yml - 4742 ServicePrincipalNames and 5136 servicePrincipalName starting GC/
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_add_sid_history.yml - 4765/4766 and 4738 SidHistory logic
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_add_domain_trust.yml - 4706 trust creation
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_possible_shadow_credentials_added.yml - 5136 msDS-KeyCredentialLink, FP from Entra Connect/ADFS
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_computer_name.yml - sam-the-admin default name pattern only (CVE-2021-42278/42287)
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_petitpotam_network_share.yml - 5145 lsarpc over IPC$ by ANONYMOUS LOGON; needs Detailed File Share
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_dce_rpc_smb_spoolss_named_pipe.yml - 5145 spoolss over IPC$
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_adcs_certificate_template_configuration_vulnerability.yml - 4898/4899 TemplateContent / NewTemplateContent with ENROLLEE_SUPPLIES_SUBJECT
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_default_domain_gpo_modification.yml - 5136 groupPolicyContainer, default policy GUIDs
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_group_policy_startup_script_added_to_gpo.yml - 5136/5145 gPC*ExtensionNames and SYSVOL scripts.ini
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_net_ntlm_downgrade.yml - 4657 LmCompatibilityLevel registry changes (not a 4624 LmPackageName rule)
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_ad_user_enumeration.yml - 4662 user-class read enumeration; high FP
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/netlogon/win_system_vul_cve_2020_1472.yml - System 5829, provider NetLogon; cites KB4557222
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/netlogon/win_system_possible_zerologon_exploitation_using_wellknown_tools.yml - System 5805/5723 with tool names
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/microsoft_windows_kerberos_key_distribution_center/win_system_kdcsvc_cert_use_no_strong_mapping.yml - KDC System events 39/41 for weak certificate mapping
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/dns_server/win_dns_server_susp_server_level_plugin_dll.yml - DNS Server 150/770/771
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/ntlm/win_susp_ntlm_auth.yml - Microsoft-Windows-NTLM/Operational, event 8002 requirement
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/ntlm/win_susp_ntlm_brute_force.yml - NTLM Operational channel usage
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/ldap/win_ldap_recon.yml - LDAP search filters only in Microsoft-Windows-LDAP-Client ETW (EventID 30): the EVTX blind spot
- https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_dcsync_replication_rights.toml - 4662, AccessMask 0x100, GUID names and values, excludes $ and MSOL_
- https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_kerberos_service_ticket_rc4.toml - 4769 RC4 Status 0x0 with new requester/service pairs
- https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_disable_kerberos_preauth.toml - 4738 with decoded UAC flag USER_DONT_REQUIRE_PREAUTH
- https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_ad_adminsdholder.toml - 5136 on CN=AdminSDHolder,CN=System
- https://github.com/elastic/detection-rules/blob/main/rules/windows/privilege_escalation_samaccountname_spoofing_attack.toml - 4781 OldTargetUserName ends with $ and new name does not
- https://github.com/elastic/detection-rules/blob/main/rules/windows/privilege_escalation_suspicious_dnshostname_update.toml - 4742 DnsHostName set to a DC FQDN (CVE-2022-26923 prep)
- https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_shadow_credentials.toml - 5136 msDS-KeyCredentialLink, value prefix B:828, excludes MSOL_
- https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_msds_alloweddelegateto_krbtgt.toml - 4738 AllowedToDelegateTo containing krbtgt
- https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_dollar_account_relay_ntlm.toml - 5145 coercion pipe list followed by 4624 NTLM type 3 of a machine account from another IP within 5 s
- https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_adcs_certificate_identity_transposition.toml - parsing of the 4887 Attributes block (CertificateTemplate, SAN)
- https://github.com/splunk/security_content/blob/develop/detections/endpoint/windows_steal_authentication_certificates___esc1_authentication.yml - 4887 with Attributes containing SAN upn= and CertificateTemplate (ESC1)
- https://github.com/splunk/security_content/blob/develop/detections/endpoint/windows_ad_suspicious_attribute_modification.yml - 5136 on msDS-AllowedToDelegateTo / msDS-AllowedToActOnBehalfOfOtherIdentity with OperationType %%14674
- https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/Security/AccountLogon/KerberosAuthenticationService/Sec_4768_Med_KrbTGT-Req_PossibleAS-REP-Roasting.yml - 4768 PreAuthType 0 + RC4
- https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/Security/AccountLogon/KerberosAuthenticationService/Sec_4769_Med_KerberosTGT-Request_PossibleKerberoasting.yml - 4769 RC4
- https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/Security/AccountManagement/SecurityGroupManagement/Sec_4728_High_MemberAddedToGlobalGrp_DomainAdmins.yml - 4728 TargetUserName Domain Admins, SubjectUserName not machine
- https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/Security/AccountManagement/UserAccountManagement/Sec_4724_Med_AcctPassword_OtherChanged.yml - 4724 password reset rule (file confirmed to exist and match event id; body not read in detail)
- https://github.com/WithSecureLabs/chainsaw/tree/master/rules/evtx/credential_access - kerberoasting_administrator.yml (4769 ServiceSid *-500) and weak_kerberos_ticket.yml (0x17/0x18, Status 0x0)
- https://github.com/WithSecureLabs/chainsaw/tree/master/rules/evtx/account_tampering - group addition rules (4728/4732/4756)

## Real-event sample corpora (EVTX parsed locally for field names/values)

- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack - README (rule/event-id table) and samples: golden ticket 4624/4769, Kerberoast/AS-REP 4768/4769, 4662 DCSync (Mimikatz), 4738 preauth flag, 4742 SPN/delegation (DCShadow, constrained), 5136 RBCD, 5137 fake DC, 5136 AdminSDHolder, 5136 domain-root ACL, 5136 GPO versionNumber, 4765 SID history, 4706/4865 trust, 4886/4887 ESC1, KDC 39 ESC1, 4882 ESC7, DNS Server 150/770, 4724/5145 setNTLM, 4728/4756/4732 group changes, 4673 SeMachineAccountPrivilege
- https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES - samples: noPac/sAMAccountName spoofing on a DC (4741, 4724, 4742, 4781, 4768/4769), Zerologon (4742 by ANONYMOUS LOGON with 4624, and System NETLOGON 5805), SpoolSample 5145

## Not opened

- Microsoft Learn event pages (4662, 4738, 4742, 4768, 4769, 4886-4900, 4706), KB4557222, ADCS auditing, MITRE ATT&CK, SpecterOps "Certified Pre-Owned", ANSSI, adsecurity.org, JPCERT/CC, The DFIR Report, Ultimate Windows Security, NSA guidance: unreachable (proxy). The Elastic prebuilt-rule page for DCSync (elastic.co) appeared in a web search summary only and was not opened; it is not cited.
- The awesome-event-ids repository was cloned but contains only an SMB document, so nothing was taken from it.

## Open questions

- Microsoft's own wording for 4768 PreAuthType values (0, 2, 15, 16), TicketEncryptionType values and Status codes, and for 4723 vs 4724, were not read. Needed to upgrade 4768 PKINIT (FH-AD-012) and the password-reset check (FH-AD-008).
- Netlogon events 5827, 5828, 5830, 5831 (KB4557222): meanings used in FH-AD-014 are from memory; only 5829 and 5805 were corroborated.
- ADCS audit events 4870, 4890-4892, 4900 and the exact `Attributes`/`TemplateContent` rendering across Windows Server versions (FH-AD-013). SpecterOps whitepaper ESC1-ESC8 detection guidance is unread.
- Whether 4742/4738 UserAccountControl numeric fields can be trusted for delegation or pre-auth flag detection: sample EVTX values (e.g. 0x210 to 0x10210 for the "no preauth" sample) contradict the documented bit values. Tokens (%%2096, %%2064, %%2093, %%2098) were used instead and their definitions in the message tables should be checked.
- 4768/4769 numeric formatting (0x17 vs 0x00000017) by OS build: samples show the padded form; rule projects assume the unpadded form. Which Windows versions emit which?
- Golden/silver ticket heuristics (FH-AD-009, FH-AD-010) have no published, tested event signature in the sources I could open; the lowercase-domain-name hint is from one sample only.
- Event 1644 (Directory Service) configuration and field layout, and NTLM/Operational 8001-8004 semantics and field names (FH-AD-029, FH-AD-030), were not confirmed against an opened source.
- The SPN `GC/<guid>` form used by DCShadow (E3514235-4B06-11D1-AB04-00C04FC2DCD2) was not seen in any source I opened.
