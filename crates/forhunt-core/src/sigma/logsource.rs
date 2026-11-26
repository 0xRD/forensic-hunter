//! Sigma `logsource` -> the Windows event logs (and forhunt artifacts) that
//! hold such events.
//!
//! Generic Sigma rules (SigmaHQ and most public repositories) say *what*
//! they look at (`category: process_creation`, `service: security`), not
//! where: a log source maps to one or more *variants*, each a channel, event
//! ids and, for Windows' own logs, the field names (and a few values) that
//! differ from Sysmon's. A rule is compiled once per variant and matches if
//! any variant does (D-067).
//!
//! Written from Microsoft's and Sysmon's documentation of the events and
//! checked against Yamato Security's conversions of the same rules (their
//! `hayabusa-rules/sigma` keeps the original rule id in `related`).

/// One place a log source's events are found.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Variant {
    pub channels: &'static [&'static str],
    /// Empty: any event id of the channels.
    pub eids: &'static [u32],
    /// Sigma field -> field of these events.
    pub renames: &'static [(&'static str, &'static str)],
    /// Sigma field -> (value as Sigma writes it, value in these events).
    pub values: &'static [(&'static str, &'static [(&'static str, &'static str)])],
    /// Extra condition: field equals one of these values.
    pub extra: Option<(&'static str, &'static [&'static str])>,
    /// Sigma fields whose values these events write as device paths
    /// (`\device\harddiskvolume2\windows\...` for `C:\Windows\...`): a
    /// `C:\...` equality becomes "ends with `\...`".
    pub device_paths: &'static [&'static str],
}

const fn v(channels: &'static [&'static str], eids: &'static [u32]) -> Variant {
    Variant {
        channels,
        eids,
        renames: &[],
        values: &[],
        extra: None,
        device_paths: &[],
    }
}

const SYSMON: &[&str] = &["Microsoft-Windows-Sysmon/Operational"];
const SECURITY: &[&str] = &["Security"];
const PS: &[&str] = &[
    "Microsoft-Windows-PowerShell/Operational",
    "PowerShellCore/Operational",
];
const PS_CLASSIC: &[&str] = &["Windows PowerShell"];
const DEFENDER: &[&str] = &["Microsoft-Windows-Windows Defender/Operational"];

const INTEGRITY: &[(&str, &str)] = &[
    ("Untrusted", "S-1-16-0"),
    ("Low", "S-1-16-4096"),
    ("Medium", "S-1-16-8192"),
    ("High", "S-1-16-12288"),
    ("System", "S-1-16-16384"),
];

/// Security 4688 (process creation auditing): what Sysmon 1 calls `Image`
/// is `NewProcessName`. Fields 4688 does not have (OriginalFileName,
/// Hashes, ParentCommandLine...) are absent, so tests on them do not hold.
const PROC_4688: Variant = Variant {
    channels: SECURITY,
    eids: &[4688],
    renames: &[
        ("Image", "NewProcessName"),
        ("ParentImage", "ParentProcessName"),
        ("IntegrityLevel", "MandatoryLabel"),
        ("LogonId", "SubjectLogonId"),
        ("ProcessId", "NewProcessId"),
        ("ParentProcessId", "ProcessId"),
    ],
    values: &[("IntegrityLevel", INTEGRITY)],
    extra: None,
    device_paths: &[],
};

/// Security 4657 (registry auditing): `ObjectName`, `NewValue`.
const REG_4657: Variant = Variant {
    channels: SECURITY,
    eids: &[4657],
    renames: &[
        ("TargetObject", "ObjectName"),
        ("Details", "NewValue"),
        ("Image", "ProcessName"),
    ],
    values: &[],
    extra: None,
    device_paths: &[],
};

/// Security 5156 (Windows Filtering Platform connection allowed).
const NET_5156: Variant = Variant {
    channels: SECURITY,
    eids: &[5156],
    renames: &[
        ("DestinationIp", "DestAddress"),
        ("DestinationPort", "DestPort"),
        ("SourceIp", "SourceAddress"),
        ("SourcePort", "SourcePort"),
        ("Image", "Application"),
        ("Initiated", "Direction"),
    ],
    values: &[("Initiated", &[("true", "%%14593"), ("false", "%%14592")])],
    extra: None,
    device_paths: &["Image"],
};

/// Variants of a category (Sysmon first).
fn category(c: &str) -> Option<Vec<Variant>> {
    // Spellings seen in public repositories.
    let c = match c {
        "file_creation" => "file_event",
        "image_loaded" => "image_load",
        "registry_modification" => "registry_set",
        c => c,
    };
    Some(match c {
        "process_creation" => vec![v(SYSMON, &[1]), PROC_4688],
        "file_change" => vec![v(SYSMON, &[2])],
        "network_connection" => vec![v(SYSMON, &[3]), NET_5156],
        "sysmon_status" => vec![v(SYSMON, &[4, 16])],
        "process_termination" => vec![v(SYSMON, &[5])],
        "driver_load" => vec![v(SYSMON, &[6])],
        "image_load" => vec![v(SYSMON, &[7])],
        "create_remote_thread" => vec![v(SYSMON, &[8])],
        "raw_access_thread" => vec![v(SYSMON, &[9])],
        "process_access" => vec![v(SYSMON, &[10])],
        "file_event" => vec![v(SYSMON, &[11])],
        "registry_add" => vec![Variant {
            extra: Some(("EventType", &["CreateKey"])),
            ..v(SYSMON, &[12])
        }],
        "registry_delete" => vec![Variant {
            extra: Some(("EventType", &["DeleteKey", "DeleteValue"])),
            ..v(SYSMON, &[12])
        }],
        "registry_set" => vec![v(SYSMON, &[13]), REG_4657],
        "registry_rename" => vec![v(SYSMON, &[14])],
        "registry_event" => vec![v(SYSMON, &[12, 13, 14]), REG_4657],
        "create_stream_hash" => vec![v(SYSMON, &[15])],
        "pipe_created" => vec![v(SYSMON, &[17, 18])],
        "wmi_event" => vec![v(SYSMON, &[19, 20, 21])],
        "dns_query" => vec![v(SYSMON, &[22])],
        "file_delete" => vec![v(SYSMON, &[23, 26])],
        "clipboard_capture" => vec![v(SYSMON, &[24])],
        "process_tampering" => vec![v(SYSMON, &[25])],
        "file_delete_detected" => vec![v(SYSMON, &[26])],
        "file_block_executable" => vec![v(SYSMON, &[27])],
        "file_block_shredding" => vec![v(SYSMON, &[28])],
        "file_executable_detected" => vec![v(SYSMON, &[29])],
        "sysmon_error" => vec![v(SYSMON, &[255])],
        "ps_module" => vec![v(PS, &[4103])],
        "ps_script" => vec![v(PS, &[4104])],
        "ps_classic_start" => vec![v(PS_CLASSIC, &[400])],
        "ps_classic_provider_start" => vec![v(PS_CLASSIC, &[600])],
        "ps_classic_script" => vec![v(PS_CLASSIC, &[800])],
        // Generic antivirus fields, as Defender names them.
        "antivirus" => vec![Variant {
            renames: &[("Signature", "Threat Name"), ("Filename", "Path")],
            ..v(
                DEFENDER,
                &[
                    1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116,
                ],
            )
        }],
        _ => return None,
    })
}

/// Channels of a Windows service.
fn service(s: &str) -> Option<&'static [&'static str]> {
    let s = match s {
        "bits" => "bits-client",
        "defender" | "windows-defender" => "windefend",
        "task-scheduler" => "taskscheduler",
        s => s,
    };
    Some(match s {
        "security" => SECURITY,
        "system" => &["System"],
        "application" => &["Application"],
        "sysmon" => SYSMON,
        "powershell" => PS,
        "powershell-classic" => PS_CLASSIC,
        "windefend" => DEFENDER,
        "taskscheduler" => &["Microsoft-Windows-TaskScheduler/Operational"],
        "wmi" => &["Microsoft-Windows-WMI-Activity/Operational"],
        "dns-server" => &["DNS Server"],
        "dns-server-audit" => &["Microsoft-Windows-DNS-Server/Audit"],
        "dns-server-analytic" => &["Microsoft-Windows-DNS-Server/Analytical"],
        "dns-client" => &["Microsoft-Windows-DNS-Client/Operational"],
        "dhcp" => &["Microsoft-Windows-DHCP-Server/Operational"],
        "bits-client" => &["Microsoft-Windows-Bits-Client/Operational"],
        "codeintegrity-operational" => &["Microsoft-Windows-CodeIntegrity/Operational"],
        "firewall-as" => &["Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"],
        "msexchange-management" => &["MSExchange Management"],
        "appxdeployment-server" => &["Microsoft-Windows-AppXDeploymentServer/Operational"],
        "appxpackaging-om" => &["Microsoft-Windows-AppxPackaging/Operational"],
        "appmodel-runtime" => &["Microsoft-Windows-AppModel-Runtime/Admin"],
        "ntlm" => &["Microsoft-Windows-NTLM/Operational"],
        "applocker" => &[
            "Microsoft-Windows-AppLocker/MSI and Script",
            "Microsoft-Windows-AppLocker/EXE and DLL",
            "Microsoft-Windows-AppLocker/Packaged app-Deployment",
            "Microsoft-Windows-AppLocker/Packaged app-Execution",
        ],
        "security-mitigations" => &[
            "Microsoft-Windows-Security-Mitigations/Kernel Mode",
            "Microsoft-Windows-Security-Mitigations/User Mode",
        ],
        "iis-configuration" => &["Microsoft-IIS-Configuration/Operational"],
        "printservice-admin" => &["Microsoft-Windows-PrintService/Admin"],
        "printservice-operational" => &["Microsoft-Windows-PrintService/Operational"],
        "smbclient-security" => &["Microsoft-Windows-SmbClient/Security"],
        "smbclient-connectivity" => &["Microsoft-Windows-SmbClient/Connectivity"],
        "smbserver-security" => &["Microsoft-Windows-SMBServer/Security"],
        "terminalservices-localsessionmanager" => {
            &["Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"]
        }
        "terminalservices-remoteconnectionmanager" => {
            &["Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"]
        }
        "rdp-corets" => &["Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"],
        "winrm" => &["Microsoft-Windows-WinRM/Operational"],
        "shell-core" => &["Microsoft-Windows-Shell-Core/Operational"],
        "ldap" => &["Microsoft-Windows-LDAP-Client/Debug"],
        "driver-framework" => &["Microsoft-Windows-DriverFrameworks-UserMode/Operational"],
        "certificateservicesclient-lifecycle-system" => {
            &["Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational"]
        }
        "capi2" => &["Microsoft-Windows-CAPI2/Operational"],
        "openssh" => &["OpenSSH/Operational"],
        "diagnosis-scripted" => &["Microsoft-Windows-Diagnosis-Scripted/Operational"],
        "lsa-server" => &["Microsoft-Windows-LSA/Operational"],
        "microsoft-servicebus-client" => &["Microsoft-ServiceBus-Client"],
        "bitlocker" => &["Microsoft-Windows-BitLocker/BitLocker Management"],
        "vhdmp" => &["Microsoft-Windows-VHDMP-Operational"],
        "hyper-v-worker" => &["Microsoft-Windows-Hyper-V-Worker-Admin"],
        "kernel-shimengine" => &["Microsoft-Windows-Kernel-ShimEngine/Operational"],
        "ntfs" => &["Microsoft-Windows-Ntfs/Operational"],
        "kernel-event-tracing" => &["Microsoft-Windows-Kernel-EventTracing/Admin"],
        "sense" => &["Microsoft-Windows-SENSE/Operational"],
        "ntlm-operational" => &["Microsoft-Windows-NTLM/Operational"],
        _ => return None,
    })
}

/// forhunt's own artifacts (`product: forhunt`).
fn forhunt_service(s: &str) -> Option<&'static [&'static str]> {
    Some(match s {
        "prefetch" => &["Prefetch"],
        "registry" => &["Registry"],
        "mft" => &["MFT"],
        "usnjrnl" | "usn" => &["UsnJrnl"],
        "mail" => &["Mail"],
        _ => return None,
    })
}

/// What a `logsource` maps to.
pub(crate) enum Mapped {
    /// No constraint to add (no logsource, or a windows rule naming none).
    Any,
    Variants(Vec<Variant>),
    /// Not in Windows event logs or forhunt artifacts: the reason.
    Unsupported(String),
}

/// Maps a logsource; `category` / `service` may be lists (any of them).
pub(crate) fn map(product: Option<&str>, categories: &[String], services: &[String]) -> Mapped {
    // `service: security, system`: a list written as one string.
    let split = |v: &[String]| -> Vec<String> {
        v.iter()
            .flat_map(|x| x.split(',').map(|y| y.trim().to_string()))
            .filter(|y| !y.is_empty())
            .collect()
    };
    let (categories, services) = (&split(categories)[..], &split(services)[..]);
    let product = product.map(str::to_ascii_lowercase);
    match product.as_deref() {
        None | Some("windows") => {}
        Some("forhunt") => {
            let mut out = Vec::new();
            for s in services {
                match forhunt_service(&s.to_ascii_lowercase()) {
                    Some(ch) => out.push(v(ch, &[])),
                    None => {
                        return Mapped::Unsupported(format!(
                            "logsource forhunt/{s} is not a forhunt artifact"
                        ));
                    }
                }
            }
            return if out.is_empty() {
                Mapped::Any
            } else {
                Mapped::Variants(out)
            };
        }
        Some(p) => {
            return Mapped::Unsupported(format!("logsource product {p} (not Windows event logs)"));
        }
    }
    let mut out = Vec::new();
    for c in categories {
        match category(&c.to_ascii_lowercase()) {
            Some(vs) => out.extend(vs),
            None => {
                return Mapped::Unsupported(format!(
                    "logsource category {c} (not in Windows event logs, or unknown)"
                ));
            }
        }
    }
    if categories.is_empty() {
        for s in services {
            match service(&s.to_ascii_lowercase()) {
                Some(ch) => out.push(v(ch, &[])),
                None => {
                    return Mapped::Unsupported(format!(
                        "logsource service {s} (unknown Windows log)"
                    ));
                }
            }
        }
    }
    if out.is_empty() {
        // No product and no category / service: rules written for any log.
        Mapped::Any
    } else {
        Mapped::Variants(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn mappings() {
        let Mapped::Variants(v) = map(Some("windows"), &s(&["process_creation"]), &[]) else {
            panic!()
        };
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].eids, &[4688]);
        let Mapped::Variants(v) = map(Some("windows"), &[], &s(&["security"])) else {
            panic!()
        };
        assert_eq!(v[0].channels, &["Security"]);
        assert!(v[0].eids.is_empty());
        assert!(matches!(
            map(Some("linux"), &s(&["process_creation"]), &[]),
            Mapped::Unsupported(_)
        ));
        assert!(matches!(
            map(Some("windows"), &s(&["file_access"]), &[]),
            Mapped::Unsupported(_)
        ));
        assert!(matches!(map(None, &[], &[]), Mapped::Any));
        let Mapped::Variants(v) = map(Some("forhunt"), &[], &s(&["prefetch"])) else {
            panic!()
        };
        assert_eq!(v[0].channels, &["Prefetch"]);
        // Lists: any of them.
        let Mapped::Variants(v) = map(Some("windows"), &s(&["ps_module", "ps_script"]), &[]) else {
            panic!()
        };
        assert_eq!(v.len(), 2);
    }
}
