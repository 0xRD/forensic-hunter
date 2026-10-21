//! Event templates (one per event type, shaped like Windows' manifests) and
//! a deterministic generator of realistic values. Every name, address and
//! SID is synthetic: hosts are `WS-xx`/`DC01` in `CONTOSO`, external
//! addresses come from the documentation ranges (RFC 5737).

use crate::writer::{Content, Node, Template, Ty, V, el, sub};

pub const EVENT_NS: &str = "http://schemas.microsoft.com/win/2004/08/events/event";

/// Number of System substitutions; EventData substitutions start here.
pub const SYS_SUBS: u16 = 14;

/// The System element shared by all templates (substitutions 0..14).
fn system() -> Node {
    use Content::Sub;
    el(
        "System",
        vec![],
        vec![
            el(
                "Provider",
                vec![("Name", Sub(0, Ty::Str)), ("Guid", Sub(1, Ty::Guid))],
                vec![],
            ),
            el("EventID", vec![], vec![sub(2, Ty::U16)]),
            el("Version", vec![], vec![sub(3, Ty::U8)]),
            el("Level", vec![], vec![sub(4, Ty::U8)]),
            el("Task", vec![], vec![sub(5, Ty::U16)]),
            el("Opcode", vec![], vec![sub(6, Ty::U8)]),
            el("Keywords", vec![], vec![sub(7, Ty::Hex64)]),
            el(
                "TimeCreated",
                vec![("SystemTime", Sub(8, Ty::FileTime))],
                vec![],
            ),
            el("EventRecordID", vec![], vec![sub(9, Ty::U64)]),
            el("Correlation", vec![], vec![]),
            el(
                "Execution",
                vec![
                    ("ProcessID", Sub(10, Ty::U32)),
                    ("ThreadID", Sub(11, Ty::U32)),
                ],
                vec![],
            ),
            el("Channel", vec![], vec![sub(12, Ty::Str)]),
            el("Computer", vec![], vec![sub(13, Ty::Str)]),
            el("Security", vec![("UserID", Sub(14, Ty::Sid))], vec![]),
        ],
    )
}

/// Builds `<Event><System/><EventData><Data Name=..>%n</Data>...</EventData></Event>`.
fn template(seed: u32, fields: &[(&'static str, Ty)]) -> Template {
    let data = fields
        .iter()
        .enumerate()
        .map(|(i, (n, ty))| {
            el(
                "Data",
                vec![("Name", Content::Text(n))],
                vec![sub(SYS_SUBS + 1 + i as u16, *ty)],
            )
        })
        .collect();
    let root = el(
        "Event",
        vec![("xmlns", Content::Text(EVENT_NS))],
        vec![system(), el("EventData", vec![], data)],
    );
    let mut guid = [0u8; 16];
    guid[0..4].copy_from_slice(&seed.to_le_bytes());
    guid[4..8].copy_from_slice(&0x4648_4754u32.to_le_bytes()); // "FHGT"
    for (i, b) in guid[8..].iter_mut().enumerate() {
        *b = (seed as u8).wrapping_mul(31).wrapping_add(i as u8 * 17);
    }
    Template { guid, root }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Logon4624,
    LogonFail4625,
    Logoff4634,
    SpecialPriv4672,
    Process4688,
    UserCreated4720,
    GroupAdd4732,
    Kerberos4769,
    Share5140,
    Task4698,
    LogCleared1102,
    Service7045,
    ServiceState7036,
    SysmonProcess1,
    SysmonNet3,
    SysmonAccess10,
    SysmonFile11,
    PsScript4104,
}

pub struct Spec {
    pub kind: Kind,
    pub channel: &'static str,
    pub provider: &'static str,
    pub provider_guid: [u8; 16],
    pub event_id: u16,
    pub task: u16,
    pub keywords: u64,
    pub level: u8,
    pub version: u8,
    pub fields: &'static [(&'static str, Ty)],
}

const SEC_GUID: [u8; 16] = [
    0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49, 0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d,
];
const SCM_GUID: [u8; 16] = [
    0x7e, 0x9e, 0x5b, 0x55, 0x2d, 0xe6, 0x2e, 0x4b, 0x9d, 0x9a, 0x92, 0x7a, 0x86, 0x1e, 0x0e, 0x7a,
];
const SYSMON_GUID: [u8; 16] = [
    0x5f, 0x38, 0x70, 0x57, 0x2a, 0xc2, 0xe0, 0x43, 0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f, 0xfb, 0xd9,
];
const PS_GUID: [u8; 16] = [
    0xc4, 0x42, 0x41, 0xa0, 0x9c, 0xdb, 0x3d, 0x4b, 0xa1, 0x71, 0xa3, 0xcc, 0x6c, 0x7a, 0x5f, 0x9d,
];

pub const SECURITY: &str = "Security";
pub const SYSTEM: &str = "System";
pub const SYSMON: &str = "Microsoft-Windows-Sysmon/Operational";
pub const POWERSHELL: &str = "Microsoft-Windows-PowerShell/Operational";

use Ty::{Hex32, Hex64, Sid, Str, U16, U32};

pub static SPECS: &[Spec] = &[
    Spec {
        kind: Kind::Logon4624,
        channel: SECURITY,
        provider: "Microsoft-Windows-Security-Auditing",
        provider_guid: SEC_GUID,
        event_id: 4624,
        task: 12544,
        keywords: 0x8020000000000000,
        level: 0,
        version: 2,
        fields: &[
            ("SubjectUserSid", Sid),
            ("SubjectUserName", Str),
            ("SubjectDomainName", Str),
            ("SubjectLogonId", Hex64),
            ("TargetUserSid", Sid),
            ("TargetUserName", Str),
            ("TargetDomainName", Str),
            ("TargetLogonId", Hex64),
            ("LogonType", U32),
            ("LogonProcessName", Str),
            ("AuthenticationPackageName", Str),
            ("WorkstationName", Str),
            ("LogonGuid", Ty::Guid),
            ("TransmittedServices", Str),
            ("LmPackageName", Str),
            ("KeyLength", U32),
            ("ProcessId", Hex64),
            ("ProcessName", Str),
            ("IpAddress", Str),
            ("IpPort", Str),
            ("ImpersonationLevel", Str),
            ("RestrictedAdminMode", Str),
            ("TargetOutboundUserName", Str),
            ("TargetOutboundDomainName", Str),
            ("VirtualAccount", Str),
            ("TargetLinkedLogonId", Hex64),
            ("ElevatedToken", Str),
        ],
    },
    Spec {
        kind: Kind::LogonFail4625,
        channel: SECURITY,
        provider: "Microsoft-Windows-Security-Auditing",
        provider_guid: SEC_GUID,
        event_id: 4625,
        task: 12544,
        keywords: 0x8010000000000000,
        level: 0,
        version: 0,
        fields: &[
            ("SubjectUserSid", Sid),
            ("SubjectUserName", Str),
            ("SubjectDomainName", Str),
            ("SubjectLogonId", Hex64),
            ("TargetUserSid", Sid),
            ("TargetUserName", Str),
            ("TargetDomainName", Str),
            ("Status", Hex32),
            ("FailureReason", Str),
            ("SubStatus", Hex32),
            ("LogonType", U32),
            ("LogonProcessName", Str),
            ("AuthenticationPackageName", Str),
            ("WorkstationName", Str),
            ("TransmittedServices", Str),
            ("LmPackageName", Str),
            ("KeyLength", U32),
            ("ProcessId", Hex64),
            ("ProcessName", Str),
            ("IpAddress", Str),
            ("IpPort", Str),
        ],
    },
    Spec {
        kind: Kind::Logoff4634,
        channel: SECURITY,
        provider: "Microsoft-Windows-Security-Auditing",
        provider_guid: SEC_GUID,
        event_id: 4634,
        task: 12545,
        keywords: 0x8020000000000000,
        level: 0,
        version: 0,
        fields: &[
            ("TargetUserSid", Sid),
            ("TargetUserName", Str),
            ("TargetDomainName", Str),
            ("TargetLogonId", Hex64),
            ("LogonType", U32),
        ],
    },
    Spec {
        kind: Kind::SpecialPriv4672,
        channel: SECURITY,
        provider: "Microsoft-Windows-Security-Auditing",
        provider_guid: SEC_GUID,
        event_id: 4672,
        task: 12548,
        keywords: 0x8020000000000000,
        level: 0,
        version: 0,
        fields: &[
            ("SubjectUserSid", Sid),
            ("SubjectUserName", Str),
            ("SubjectDomainName", Str),
            ("SubjectLogonId", Hex64),
            ("PrivilegeList", Str),
        ],
    },
    Spec {
        kind: Kind::Process4688,
        channel: SECURITY,
        provider: "Microsoft-Windows-Security-Auditing",
        provider_guid: SEC_GUID,
        event_id: 4688,
        task: 13312,
        keywords: 0x8020000000000000,
        level: 0,
        version: 2,
        fields: &[
            ("SubjectUserSid", Sid),
            ("SubjectUserName", Str),
            ("SubjectDomainName", Str),
            ("SubjectLogonId", Hex64),
            ("NewProcessId", Hex64),
            ("NewProcessName", Str),
            ("TokenElevationType", Str),
            ("ProcessId", Hex64),
            ("CommandLine", Str),
            ("TargetUserSid", Sid),
            ("TargetUserName", Str),
            ("TargetDomainName", Str),
            ("TargetLogonId", Hex64),
            ("ParentProcessName", Str),
            ("MandatoryLabel", Sid),
        ],
    },
    Spec {
        kind: Kind::UserCreated4720,
        channel: SECURITY,
        provider: "Microsoft-Windows-Security-Auditing",
        provider_guid: SEC_GUID,
        event_id: 4720,
        task: 13824,
        keywords: 0x8020000000000000,
        level: 0,
        version: 0,
        fields: &[
            ("TargetUserName", Str),
            ("TargetDomainName", Str),
            ("TargetSid", Sid),
            ("SubjectUserSid", Sid),
            ("SubjectUserName", Str),
            ("SubjectDomainName", Str),
            ("SubjectLogonId", Hex64),
            ("SamAccountName", Str),
            ("DisplayName", Str),
            ("UserPrincipalName", Str),
            ("UserAccountControl", Str),
        ],
    },
    Spec {
        kind: Kind::GroupAdd4732,
        channel: SECURITY,
        provider: "Microsoft-Windows-Security-Auditing",
        provider_guid: SEC_GUID,
        event_id: 4732,
        task: 13826,
        keywords: 0x8020000000000000,
        level: 0,
        version: 0,
        fields: &[
            ("MemberName", Str),
            ("MemberSid", Sid),
            ("TargetUserName", Str),
            ("TargetDomainName", Str),
            ("TargetSid", Sid),
            ("SubjectUserSid", Sid),
            ("SubjectUserName", Str),
            ("SubjectDomainName", Str),
            ("SubjectLogonId", Hex64),
            ("PrivilegeList", Str),
        ],
    },
    Spec {
        kind: Kind::Kerberos4769,
        channel: SECURITY,
        provider: "Microsoft-Windows-Security-Auditing",
        provider_guid: SEC_GUID,
        event_id: 4769,
        task: 14337,
        keywords: 0x8020000000000000,
        level: 0,
        version: 0,
        fields: &[
            ("TargetUserName", Str),
            ("TargetDomainName", Str),
            ("ServiceName", Str),
            ("ServiceSid", Sid),
            ("TicketOptions", Hex32),
            ("TicketEncryptionType", Hex32),
            ("IpAddress", Str),
            ("IpPort", Str),
            ("Status", Hex32),
            ("LogonGuid", Ty::Guid),
            ("TransmittedServices", Str),
        ],
    },
    Spec {
        kind: Kind::Share5140,
        channel: SECURITY,
        provider: "Microsoft-Windows-Security-Auditing",
        provider_guid: SEC_GUID,
        event_id: 5140,
        task: 12808,
        keywords: 0x8020000000000000,
        level: 0,
        version: 1,
        fields: &[
            ("SubjectUserSid", Sid),
            ("SubjectUserName", Str),
            ("SubjectDomainName", Str),
            ("SubjectLogonId", Hex64),
            ("ObjectType", Str),
            ("IpAddress", Str),
            ("IpPort", U32),
            ("ShareName", Str),
            ("ShareLocalPath", Str),
            ("AccessMask", Hex32),
            ("AccessList", Str),
        ],
    },
    Spec {
        kind: Kind::Task4698,
        channel: SECURITY,
        provider: "Microsoft-Windows-Security-Auditing",
        provider_guid: SEC_GUID,
        event_id: 4698,
        task: 12804,
        keywords: 0x8020000000000000,
        level: 0,
        version: 1,
        fields: &[
            ("SubjectUserSid", Sid),
            ("SubjectUserName", Str),
            ("SubjectDomainName", Str),
            ("SubjectLogonId", Hex64),
            ("TaskName", Str),
            ("TaskContent", Str),
        ],
    },
    Spec {
        kind: Kind::LogCleared1102,
        channel: SECURITY,
        provider: "Microsoft-Windows-Eventlog",
        provider_guid: SEC_GUID,
        event_id: 1102,
        task: 104,
        keywords: 0x4020000000000000,
        level: 4,
        version: 0,
        fields: &[
            ("SubjectUserSid", Sid),
            ("SubjectUserName", Str),
            ("SubjectDomainName", Str),
            ("SubjectLogonId", Hex64),
        ],
    },
    Spec {
        kind: Kind::Service7045,
        channel: SYSTEM,
        provider: "Service Control Manager",
        provider_guid: SCM_GUID,
        event_id: 7045,
        task: 0,
        keywords: 0x8080000000000000,
        level: 4,
        version: 0,
        fields: &[
            ("ServiceName", Str),
            ("ImagePath", Str),
            ("ServiceType", Str),
            ("StartType", Str),
            ("AccountName", Str),
        ],
    },
    Spec {
        kind: Kind::ServiceState7036,
        channel: SYSTEM,
        provider: "Service Control Manager",
        provider_guid: SCM_GUID,
        event_id: 7036,
        task: 0,
        keywords: 0x8080000000000000,
        level: 4,
        version: 0,
        fields: &[("param1", Str), ("param2", Str)],
    },
    Spec {
        kind: Kind::SysmonProcess1,
        channel: SYSMON,
        provider: "Microsoft-Windows-Sysmon",
        provider_guid: SYSMON_GUID,
        event_id: 1,
        task: 1,
        keywords: 0x8000000000000000,
        level: 4,
        version: 5,
        fields: &[
            ("RuleName", Str),
            ("UtcTime", Str),
            ("ProcessGuid", Ty::Guid),
            ("ProcessId", U32),
            ("Image", Str),
            ("FileVersion", Str),
            ("Description", Str),
            ("Product", Str),
            ("Company", Str),
            ("OriginalFileName", Str),
            ("CommandLine", Str),
            ("CurrentDirectory", Str),
            ("User", Str),
            ("LogonGuid", Ty::Guid),
            ("LogonId", Hex64),
            ("TerminalSessionId", U32),
            ("IntegrityLevel", Str),
            ("Hashes", Str),
            ("ParentProcessGuid", Ty::Guid),
            ("ParentProcessId", U32),
            ("ParentImage", Str),
            ("ParentCommandLine", Str),
            ("ParentUser", Str),
        ],
    },
    Spec {
        kind: Kind::SysmonNet3,
        channel: SYSMON,
        provider: "Microsoft-Windows-Sysmon",
        provider_guid: SYSMON_GUID,
        event_id: 3,
        task: 3,
        keywords: 0x8000000000000000,
        level: 4,
        version: 5,
        fields: &[
            ("RuleName", Str),
            ("UtcTime", Str),
            ("ProcessGuid", Ty::Guid),
            ("ProcessId", U32),
            ("Image", Str),
            ("User", Str),
            ("Protocol", Str),
            ("Initiated", Ty::Str),
            ("SourceIsIpv6", Str),
            ("SourceIp", Str),
            ("SourceHostname", Str),
            ("SourcePort", U16),
            ("SourcePortName", Str),
            ("DestinationIsIpv6", Str),
            ("DestinationIp", Str),
            ("DestinationHostname", Str),
            ("DestinationPort", U16),
            ("DestinationPortName", Str),
        ],
    },
    Spec {
        kind: Kind::SysmonAccess10,
        channel: SYSMON,
        provider: "Microsoft-Windows-Sysmon",
        provider_guid: SYSMON_GUID,
        event_id: 10,
        task: 10,
        keywords: 0x8000000000000000,
        level: 4,
        version: 3,
        fields: &[
            ("RuleName", Str),
            ("UtcTime", Str),
            ("SourceProcessGUID", Ty::Guid),
            ("SourceProcessId", U32),
            ("SourceThreadId", U32),
            ("SourceImage", Str),
            ("TargetProcessGUID", Ty::Guid),
            ("TargetProcessId", U32),
            ("TargetImage", Str),
            ("GrantedAccess", Hex32),
            ("CallTrace", Str),
            ("SourceUser", Str),
            ("TargetUser", Str),
        ],
    },
    Spec {
        kind: Kind::SysmonFile11,
        channel: SYSMON,
        provider: "Microsoft-Windows-Sysmon",
        provider_guid: SYSMON_GUID,
        event_id: 11,
        task: 11,
        keywords: 0x8000000000000000,
        level: 4,
        version: 2,
        fields: &[
            ("RuleName", Str),
            ("UtcTime", Str),
            ("ProcessGuid", Ty::Guid),
            ("ProcessId", U32),
            ("Image", Str),
            ("TargetFilename", Str),
            ("CreationUtcTime", Str),
            ("User", Str),
        ],
    },
    Spec {
        kind: Kind::PsScript4104,
        channel: POWERSHELL,
        provider: "Microsoft-Windows-PowerShell",
        provider_guid: PS_GUID,
        event_id: 4104,
        task: 2,
        keywords: 0x0,
        level: 5,
        version: 1,
        fields: &[
            ("MessageNumber", U32),
            ("MessageTotal", U32),
            ("ScriptBlockText", Str),
            ("ScriptBlockId", Ty::Guid),
            ("Path", Str),
        ],
    },
];

pub fn templates() -> Vec<Template> {
    SPECS
        .iter()
        .enumerate()
        .map(|(i, s)| template(0x1000 + i as u32 + s.event_id as u32 * 64, s.fields))
        .collect()
}

pub fn spec(kind: Kind) -> (usize, &'static Spec) {
    SPECS
        .iter()
        .enumerate()
        .find(|(_, s)| s.kind == kind)
        .expect("kind has a spec")
}

/// xorshift64*: small, fast, deterministic.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
    pub fn guid(&mut self) -> [u8; 16] {
        let a = self.next().to_le_bytes();
        let b = self.next().to_le_bytes();
        let mut g = [0u8; 16];
        g[..8].copy_from_slice(&a);
        g[8..].copy_from_slice(&b);
        g
    }
}

/// System substitution values (indices 0..=14) for a record.
pub fn system_values(
    s: &Spec,
    filetime: u64,
    rid: u64,
    computer: &str,
    user_sid: Option<&str>,
    rng: &mut Rng,
) -> Vec<V> {
    vec![
        V::Str(s.provider.to_string()),
        V::Guid(s.provider_guid),
        V::U16(s.event_id),
        V::U8(s.version),
        V::U8(s.level),
        V::U16(s.task),
        V::U8(0),
        V::Hex64(s.keywords),
        V::FileTime(filetime),
        V::U64(rid),
        V::U32(if s.channel == SECURITY {
            4
        } else {
            600 + rng.below(4000) as u32
        }),
        V::U32(rng.below(9000) as u32 + 100),
        V::Str(s.channel.to_string()),
        V::Str(computer.to_string()),
        match user_sid {
            Some(sid) => V::Sid(sid.to_string()),
            None => V::Null,
        },
    ]
}

pub const DOMAIN: &str = "CONTOSO";
pub const DOMAIN_SID: &str = "S-1-5-21-3623811015-3361044348-30300820";
pub const USERS: &[&str] = &[
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy",
];
pub const SERVICES: &[&str] = &[
    "Spooler",
    "BITS",
    "wuauserv",
    "WinDefend",
    "Dnscache",
    "W32Time",
    "LanmanServer",
    "Schedule",
];
pub const PROCS: &[(&str, &str)] = &[
    (
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
    ),
    (
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"",
    ),
    (
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --type=renderer",
    ),
    (
        "C:\\Windows\\System32\\conhost.exe",
        "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1",
    ),
    (
        "C:\\Windows\\System32\\SearchProtocolHost.exe",
        "\"C:\\Windows\\system32\\SearchProtocolHost.exe\" Global\\UsGthrFltPipeMssGthrPipe1",
    ),
    ("C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE"),
    (
        "C:\\Windows\\System32\\taskhostw.exe",
        "taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}",
    ),
];

pub fn user_sid(i: u64) -> String {
    format!("{DOMAIN_SID}-{}", 1100 + i)
}
