//! What the registry says about a case. Every plugin looks for its keys from
//! the hive's root, so a hive is recognised by what it holds, not by its
//! file name. Times come from the record itself when it has one; otherwise
//! the key's last write, which says when *something* under it changed.

use std::borrow::Cow;

use super::hive::{Key, MAX_DEPTH, REG_DWORD, REG_QWORD};
use super::*;
use crate::ntfs::record::{filetime, u16_at, u32_at, u64_at};

pub(super) struct Rec {
    pub eid: u32,
    pub ts: Ts,
    pub fields: Vec<Field<'static>>,
}

type Emit<'e> = &'e mut dyn FnMut(Rec);

impl Rec {
    fn new(eid: u32, ts: Ts, key_path: &str) -> Rec {
        let mut r = Rec {
            eid,
            ts,
            fields: Vec::new(),
        };
        r.s("KeyPath", key_path);
        r
    }
    fn s(&mut self, name: &'static str, v: impl Into<String>) -> &mut Rec {
        let v = v.into();
        if !v.is_empty() {
            self.fields.push(field(name, Val::Str(Cow::Owned(v))));
        }
        self
    }
    fn n(&mut self, name: &'static str, v: u64) -> &mut Rec {
        self.fields
            .push(field(name, Val::Num(Cow::Owned(v.to_string()))));
        self
    }
    fn opt(&mut self, name: &'static str, v: Option<String>) -> &mut Rec {
        if let Some(v) = v {
            self.s(name, v);
        }
        self
    }
    fn time(&mut self, name: &'static str, v: Option<Ts>) -> &mut Rec {
        if let Some(t) = v {
            self.s(name, iso(t));
        }
        self
    }
    fn flag(&mut self, name: &'static str, v: bool) -> &mut Rec {
        if v {
            self.fields.push(field(name, Val::Bool(true)));
        }
        self
    }
}

const RUN_KEYS: &[&str] = &[
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
];
/// Values read one by one in keys that hold other settings.
const NAMED: &[(&str, &[&str])] = &[
    (
        "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        &["Shell", "Userinit", "Taskman", "AppSetup"],
    ),
    (
        "Microsoft\\Windows NT\\CurrentVersion\\Windows",
        &["AppInit_DLLs", "Load", "Run"],
    ),
];

/// The live control set (`ControlSet001` if `Select` is unreadable).
fn control_set<'r, 'h>(root: &Key<'r, 'h>) -> Option<Key<'r, 'h>> {
    let n = root
        .open("Select")
        .and_then(|s| s.value("Current"))
        .and_then(|v| v.u32())
        .unwrap_or(1);
    root.subkey(&format!("ControlSet{n:03}"))
        .or_else(|| root.subkey("ControlSet001"))
}

pub(super) fn computer_name(root: &Key<'_, '_>) -> Option<String> {
    control_set(root)?
        .open("Control\\ComputerName\\ComputerName")?
        .text("ComputerName")
}

pub(super) fn run(root: &Key<'_, '_>, all_keys: bool, emit: Emit<'_>) {
    if let Some(cs) = control_set(root) {
        let name = format!("{}\\", cs.name());
        system_info(&cs, &name, emit);
        services(&cs, &name, emit);
        shimcache(&cs, &name, emit);
        bam(&cs, &name, emit);
        usb(&cs, &name, emit);
        if let Some(sm) = cs.open("Control\\Session Manager")
            && let Some(v) = sm
                .text("BootExecute")
                .filter(|v| v != "autocheck autochk *")
        {
            let path = format!("{name}Control\\Session Manager");
            let mut r = Rec::new(EID_AUTORUN, sm.last_write(), &path);
            r.s("Name", "BootExecute").s("Command", v);
            emit(r);
        }
    }
    // SOFTWARE keeps these at the root, user hives under `Software`.
    let (soft, prefix) = match root.subkey("Software") {
        Some(s) => (s, "Software\\"),
        None => (*root, ""),
    };
    software_info(&soft, prefix, emit);
    autoruns(&soft, prefix, emit);
    tasks(&soft, prefix, emit);
    networks(&soft, prefix, emit);
    userassist(&soft, prefix, emit);
    mru(&soft, prefix, emit);
    amcache(root, emit);
    accounts(root, emit);
    if all_keys {
        let mut seen = std::collections::HashSet::new();
        walk(root, "", 0, &mut seen, emit);
    }
}

fn walk(
    k: &Key<'_, '_>,
    parent: &str,
    depth: usize,
    seen: &mut std::collections::HashSet<u32>,
    emit: Emit<'_>,
) {
    if depth > MAX_DEPTH || !seen.insert(k.offset()) {
        return;
    }
    let path = if parent.is_empty() {
        k.name()
    } else {
        format!("{parent}\\{}", k.name())
    };
    let mut r = Rec::new(EID_KEY, k.last_write(), &path);
    let values = k.values();
    r.n("ValueCount", values.len() as u64);
    if !values.is_empty() {
        let text: Vec<String> = values
            .iter()
            .map(|v| format!("{}={}", v.name(), v.text()))
            .collect();
        r.s("Values", text.join(", "));
    }
    emit(r);
    for s in k.subkeys() {
        walk(&s, &path, depth + 1, seen, emit);
    }
}

fn system_info(cs: &Key<'_, '_>, cs_name: &str, emit: Emit<'_>) {
    let Some(host) = cs.open("Control\\ComputerName\\ComputerName") else {
        return;
    };
    let path = format!("{cs_name}Control\\ComputerName\\ComputerName");
    let mut r = Rec::new(EID_SYSTEM, host.last_write(), &path);
    r.opt("ComputerName", host.text("ComputerName"));
    if let Some(tz) = cs.open("Control\\TimeZoneInformation") {
        r.opt("TimeZone", tz.text("TimeZoneKeyName"));
    }
    if let Some(w) = cs.open("Control\\Windows")
        && let Some(v) = w.value("ShutdownTime")
    {
        r.time("LastShutdown", u64_at(&v.data(), 0).and_then(filetime));
    }
    emit(r);
}

fn software_info(soft: &Key<'_, '_>, prefix: &str, emit: Emit<'_>) {
    let Some(k) = soft.open("Microsoft\\Windows NT\\CurrentVersion") else {
        return;
    };
    if k.value("ProductName").is_none() {
        return;
    }
    let install = k
        .value("InstallDate")
        .and_then(|v| v.u32())
        .map(|s| Ts(s as i64 * 10_000_000));
    let path = format!("{prefix}Microsoft\\Windows NT\\CurrentVersion");
    let mut r = Rec::new(EID_SYSTEM, install.unwrap_or(k.last_write()), &path);
    r.opt("ProductName", k.text("ProductName"))
        .opt("DisplayVersion", k.text("DisplayVersion"))
        .opt("CurrentBuild", k.text("CurrentBuild"))
        .opt("RegisteredOwner", k.text("RegisteredOwner"))
        .time("InstallDate", install);
    emit(r);
}

fn services(cs: &Key<'_, '_>, cs_name: &str, emit: Emit<'_>) {
    let Some(all) = cs.subkey("Services") else {
        return;
    };
    for s in all.subkeys() {
        let image = s.text("ImagePath");
        let dll = s.open("Parameters").and_then(|p| p.text("ServiceDll"));
        // Keys without either are drivers' settings or leftovers.
        if image.is_none() && dll.is_none() {
            continue;
        }
        let path = format!("{cs_name}Services\\{}", s.name());
        let mut r = Rec::new(EID_SERVICE, s.last_write(), &path);
        r.s("ServiceName", s.name())
            .opt("ImagePath", image)
            .opt("ServiceDll", dll)
            .opt("DisplayName", s.text("DisplayName"))
            .opt("ServiceAccount", s.text("ObjectName"))
            .opt("StartType", s.value("Start").map(|v| v.text()))
            .opt("ServiceType", s.value("Type").map(|v| v.text()));
        emit(r);
    }
}

/// Windows 10 and 11 format (`10ts` entries). The time is the file's own
/// last modification, not an execution.
fn shimcache(cs: &Key<'_, '_>, cs_name: &str, emit: Emit<'_>) {
    let Some(k) = cs.open("Control\\Session Manager\\AppCompatCache") else {
        return;
    };
    let path = format!("{cs_name}Control\\Session Manager\\AppCompatCache");
    let Some(v) = k.value("AppCompatCache") else {
        return;
    };
    let d = v.data();
    let mut off = u32_at(&d, 0).unwrap_or(0) as usize;
    if !matches!(off, 0x30 | 0x34) || d.get(off..off + 4) != Some(b"10ts") {
        let mut r = Rec::new(EID_SHIMCACHE, k.last_write(), &path);
        r.flag("UnsupportedFormat", true);
        emit(r);
        return;
    }
    let mut pos = 0u64;
    while d.get(off..off + 4) == Some(b"10ts") {
        let Some(size) = u32_at(&d, off + 8).map(|s| s as usize) else {
            break;
        };
        let Some(chars) = u16_at(&d, off + 12).map(|c| c as usize) else {
            break;
        };
        let Some(raw) = d.get(off + 14..off + 14 + chars) else {
            break;
        };
        let modified = u64_at(&d, off + 14 + chars).and_then(filetime);
        pos += 1;
        let mut text = Vec::with_capacity(chars);
        crate::ntfs::record::push_utf16(&mut text, raw);
        let mut r = Rec::new(EID_SHIMCACHE, modified.unwrap_or(k.last_write()), &path);
        let text = String::from_utf8_lossy(&text);
        // Packaged apps: tab-separated ids around the package name.
        match text.split('\t').nth(4) {
            Some(package) => r.s("Package", package),
            None => r.s("ExePath", text.as_ref()),
        };
        r.n("Position", pos)
            .time("FileModified", modified)
            .flag("NoFileTime", modified.is_none());
        emit(r);
        off += 12 + size;
    }
}

fn bam(cs: &Key<'_, '_>, cs_name: &str, emit: Emit<'_>) {
    for (svc, base) in [
        ("bam", "State\\UserSettings"),
        ("bam", "UserSettings"),
        ("dam", "State\\UserSettings"),
        ("dam", "UserSettings"),
    ] {
        let Some(k) = cs.open(&format!("Services\\{svc}\\{base}")) else {
            continue;
        };
        for sid in k.subkeys() {
            for v in sid.values() {
                let d = v.data();
                // Bookkeeping values (`Version`, `SequenceNumber`) are numbers.
                if d.len() < 8 || matches!(v.kind(), REG_DWORD | REG_QWORD) {
                    continue;
                }
                let Some(t) = u64_at(&d, 0).and_then(filetime) else {
                    continue;
                };
                let path = format!("{cs_name}Services\\{svc}\\{base}\\{}", sid.name());
                let mut r = Rec::new(EID_BAM, t, &path);
                r.s("ExePath", v.name())
                    .s("UserSid", sid.name())
                    .s("Source", svc);
                emit(r);
            }
        }
    }
}

fn usb(cs: &Key<'_, '_>, cs_name: &str, emit: Emit<'_>) {
    let Some(stor) = cs.open("Enum\\USBSTOR") else {
        return;
    };
    for class in stor.subkeys() {
        for dev in class.subkeys() {
            let path = format!("{cs_name}Enum\\USBSTOR\\{}\\{}", class.name(), dev.name());
            let mut r = Rec::new(EID_USB, dev.last_write(), &path);
            r.s("Device", class.name())
                .s("Serial", dev.name())
                .opt("FriendlyName", dev.text("FriendlyName"));
            emit(r);
        }
    }
}

fn autoruns(soft: &Key<'_, '_>, prefix: &str, emit: Emit<'_>) {
    for sub in RUN_KEYS {
        let Some(k) = soft.open(sub) else {
            continue;
        };
        let path = format!("{prefix}{sub}");
        for v in k.values() {
            let mut r = Rec::new(EID_AUTORUN, k.last_write(), &path);
            r.s("Name", v.name()).s("Command", v.text());
            emit(r);
        }
    }
    for (sub, names) in NAMED {
        let Some(k) = soft.open(sub) else {
            continue;
        };
        let path = format!("{prefix}{sub}");
        for n in *names {
            if let Some(v) = k.text(n) {
                let mut r = Rec::new(EID_AUTORUN, k.last_write(), &path);
                r.s("Name", *n).s("Command", v);
                emit(r);
            }
        }
    }
    let ifeo = "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    if let Some(k) = soft.open(ifeo) {
        for app in k.subkeys() {
            if let Some(v) = app.text("Debugger") {
                let path = format!("{prefix}{ifeo}\\{}", app.name());
                let mut r = Rec::new(EID_AUTORUN, app.last_write(), &path);
                r.s("Name", app.name()).s("Command", v);
                emit(r);
            }
        }
    }
}

fn tasks(soft: &Key<'_, '_>, prefix: &str, emit: Emit<'_>) {
    let base = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks";
    let Some(k) = soft.open(base) else {
        return;
    };
    for t in k.subkeys() {
        let path = format!("{prefix}{base}\\{}", t.name());
        let mut r = Rec::new(EID_TASK, t.last_write(), &path);
        r.opt("TaskPath", t.text("Path"))
            .opt("Author", t.text("Author"))
            .opt("Description", t.text("Description"))
            .opt("Date", t.text("Date"));
        emit(r);
    }
}

fn networks(soft: &Key<'_, '_>, prefix: &str, emit: Emit<'_>) {
    let base = "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles";
    let Some(k) = soft.open(base) else {
        return;
    };
    // SYSTEMTIME in the machine's local time: kept as written.
    let local = |d: &[u8]| {
        let w = |i: usize| u16_at(d, i * 2).unwrap_or(0);
        (d.len() >= 16).then(|| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                w(0),
                w(1),
                w(3),
                w(4),
                w(5),
                w(6)
            )
        })
    };
    for p in k.subkeys() {
        let path = format!("{prefix}{base}\\{}", p.name());
        let mut r = Rec::new(EID_NETWORK, p.last_write(), &path);
        r.opt("ProfileName", p.text("ProfileName"))
            .opt("Description", p.text("Description"))
            .opt(
                "CreatedLocal",
                p.value("DateCreated").and_then(|v| local(&v.data())),
            )
            .opt(
                "LastConnectedLocal",
                p.value("DateLastConnected").and_then(|v| local(&v.data())),
            );
        emit(r);
    }
}

/// Known folders UserAssist writes as GUIDs.
const FOLDERS: &[(&str, &str)] = &[
    ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "%SYSTEM32%"),
    ("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", "%SYSWOW64%"),
    ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "%WINDIR%"),
    ("{6D809377-6AF0-444B-8957-A3773F02200E}", "%PROGRAMFILES%"),
    (
        "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}",
        "%PROGRAMFILES(X86)%",
    ),
    (
        "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}",
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
    ),
    (
        "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}",
        "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
    ),
];

fn known_folder(name: String) -> String {
    for (guid, path) in FOLDERS {
        if name
            .get(..guid.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(guid))
        {
            return format!("{path}{}", &name[guid.len()..]);
        }
    }
    name
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            c => c,
        })
        .collect()
}

fn userassist(soft: &Key<'_, '_>, prefix: &str, emit: Emit<'_>) {
    let base = "Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
    let Some(k) = soft.open(base) else {
        return;
    };
    for guid in k.subkeys() {
        let Some(c) = guid.subkey("Count") else {
            continue;
        };
        let path = format!("{prefix}{base}\\{}\\Count", guid.name());
        for v in c.values() {
            let name = rot13(&v.name());
            let d = v.data();
            // Windows 7 and later: 72 bytes.
            if name.starts_with("UEME_") || d.len() < 68 {
                continue;
            }
            let last = u64_at(&d, 60).and_then(filetime);
            let mut r = Rec::new(EID_USERASSIST, last.unwrap_or(c.last_write()), &path);
            r.s("ExePath", known_folder(name))
                .n("RunCount", u32_at(&d, 4).unwrap_or(0) as u64)
                .n("FocusCount", u32_at(&d, 8).unwrap_or(0) as u64)
                .n("FocusMs", u32_at(&d, 12).unwrap_or(0) as u64)
                .flag("NoRunTime", last.is_none());
            emit(r);
        }
    }
}

fn mru(soft: &Key<'_, '_>, prefix: &str, emit: Emit<'_>) {
    let explorer = "Microsoft\\Windows\\CurrentVersion\\Explorer";
    for (sub, kind) in [
        ("RunMRU", "Run dialog"),
        ("TypedPaths", "Explorer address bar"),
    ] {
        let Some(k) = soft.open(&format!("{explorer}\\{sub}")) else {
            continue;
        };
        let path = format!("{prefix}{explorer}\\{sub}");
        for v in k.values() {
            if v.name().eq_ignore_ascii_case("MRUList") {
                continue;
            }
            let mut r = Rec::new(EID_MRU, k.last_write(), &path);
            r.s("Source", kind)
                .s("Name", v.name())
                .s("Command", v.text().trim_end_matches("\\1").to_string());
            emit(r);
        }
    }
}

fn amcache(root: &Key<'_, '_>, emit: Emit<'_>) {
    let Some(k) = root.open("Root\\InventoryApplicationFile") else {
        return;
    };
    for f in k.subkeys() {
        let path = format!("Root\\InventoryApplicationFile\\{}", f.name());
        let sha1 = f.text("FileId").map(|s| match s.strip_prefix("0000") {
            Some(h) if h.len() == 40 => h.to_string(),
            _ => s,
        });
        let mut r = Rec::new(EID_AMCACHE, f.last_write(), &path);
        r.opt("ExePath", f.text("LowerCaseLongPath"))
            .opt("Sha1", sha1)
            .opt("FileName", f.text("Name"))
            .opt("Publisher", f.text("Publisher"))
            .opt("ProductName", f.text("ProductName"))
            .opt("Version", f.text("Version"))
            .opt("LinkDate", f.text("LinkDate"))
            .opt("Size", f.value("Size").map(|v| v.text()))
            .opt("IsOsComponent", f.value("IsOsComponent").map(|v| v.text()));
        emit(r);
    }
}

fn accounts(root: &Key<'_, '_>, emit: Emit<'_>) {
    let Some(users) = root.open("SAM\\Domains\\Account\\Users") else {
        return;
    };
    let Some(names) = users.subkey("Names") else {
        return;
    };
    for n in names.subkeys() {
        // The RID is the type of the key's default value.
        let Some(rid) = n.value("").map(|v| v.kind()) else {
            continue;
        };
        let Some(u) = users.subkey(&format!("{rid:08X}")) else {
            continue;
        };
        let Some(f) = u.value("F").map(|v| v.data()) else {
            continue;
        };
        let t = |o| u64_at(&f, o).and_then(filetime);
        let flags = u16_at(&f, 56).unwrap_or(0);
        let path = format!("SAM\\Domains\\Account\\Users\\{rid:08X}");
        let mut r = Rec::new(EID_ACCOUNT, t(8).unwrap_or(u.last_write()), &path);
        r.s("User", n.name())
            .n("Rid", rid as u64)
            .time("LastLogon", t(8))
            .time("PasswordSet", t(24))
            .time("LastFailedLogon", t(40))
            .n("LogonCount", u16_at(&f, 66).unwrap_or(0) as u64)
            .n("FailedCount", u16_at(&f, 64).unwrap_or(0) as u64)
            .flag("Disabled", flags & 1 != 0)
            .time("AccountCreated", Some(n.last_write()));
        emit(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_names() {
        assert_eq!(rot13("pzq.rkr"), "cmd.exe");
        assert_eq!(
            known_folder("{6d809377-6af0-444b-8957-a3773f02200e}\\app.exe".into()),
            "%PROGRAMFILES%\\app.exe"
        );
        assert_eq!(known_folder("x".into()), "x");
    }
}
