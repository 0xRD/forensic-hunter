//! Windows registry hives (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`,
//! `NTUSER.DAT`, `UsrClass.dat`, `Amcache.hve`): the keys that answer
//! forensic questions become events (see [`plugins`]), dated by what they
//! record, or else by the key's last write time. `ParseOptions::registry_keys`
//! adds one event per key of the hive (D-050).
//!
//! A hive is one unit. `.LOG1`/`.LOG2` beside a dirty hive are replayed in
//! memory; evidence is never written. Event ids are `<file key>:<n>`, the
//! position of the event in the hive's output.

pub mod hive;
mod plugins;

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Context;

use crate::artifact::{Artifact, ParseOptions, Sink, Source, UnitReport};
use crate::event::{EventView, Field, Val};
use crate::id::{EventRef, FileKey};
use crate::time::Ts;
use hive::Hive;

pub const CHANNEL: &str = "Registry";
pub const PROVIDER: &str = "Registry";

pub const EID_KEY: u32 = 1;
pub const EID_SYSTEM: u32 = 2;
pub const EID_AUTORUN: u32 = 10;
pub const EID_SERVICE: u32 = 11;
pub const EID_TASK: u32 = 12;
pub const EID_SHIMCACHE: u32 = 20;
pub const EID_AMCACHE: u32 = 21;
pub const EID_USERASSIST: u32 = 22;
pub const EID_BAM: u32 = 23;
pub const EID_MRU: u32 = 30;
pub const EID_USB: u32 = 40;
pub const EID_NETWORK: u32 = 41;
pub const EID_ACCOUNT: u32 = 42;

const NAMES: &[&str] = &[
    "system",
    "software",
    "sam",
    "security",
    "default",
    "ntuser.dat",
    "usrclass.dat",
    "amcache.hve",
];
/// Windows refuses hives near 2 GiB.
const MAX_SIZE: u64 = 1 << 31;

pub struct RegistryArtifact;

impl Artifact for RegistryArtifact {
    fn name(&self) -> &'static str {
        "registry"
    }
    fn sniff(&self, head: &[u8]) -> bool {
        // The type field: 0 for a hive, other values for its logs.
        head.starts_with(b"regf") && head.get(0x1C..0x20) == Some(&[0; 4])
    }
    fn matches_name(&self, path: &Path) -> bool {
        path.file_name().is_some_and(|n| {
            let n = n.to_string_lossy().to_ascii_lowercase();
            NAMES.contains(&n.as_str())
        })
    }
    fn open(&self, path: &Path, opts: &ParseOptions) -> anyhow::Result<Arc<dyn Source>> {
        Ok(Arc::new(RegistrySource::open(path, opts)?))
    }
}

pub struct RegistrySource {
    path: PathBuf,
    key: FileKey,
    len: u64,
    hive: Hive,
    host: String,
    user: String,
    all_keys: bool,
    warnings: Vec<String>,
}

/// `.LOG1`/`.LOG2` beside `path`, whatever their case.
fn logs_of(path: &Path) -> Vec<Vec<u8>> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Vec::new();
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let stem = name.to_string_lossy().to_ascii_lowercase();
    let wanted = [format!("{stem}.log1"), format!("{stem}.log2")];
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| wanted.contains(&e.file_name().to_string_lossy().to_ascii_lowercase()))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
        .iter()
        .filter(|p| std::fs::metadata(p).is_ok_and(|m| m.len() <= MAX_SIZE))
        .filter_map(|p| std::fs::read(p).ok())
        .collect()
}

/// The profile a user hive sits in, from where a collection keeps it. Other
/// hives have no owner, and the folders above the collection say nothing
/// about it (`/Users/analyst/case/.../SOFTWARE`).
fn user_of(path: &Path) -> String {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let depth = if name.eq_ignore_ascii_case("NTUSER.DAT") {
        1
    } else if name.eq_ignore_ascii_case("UsrClass.dat") {
        5 // AppData\Local\Microsoft\Windows
    } else {
        return String::new();
    };
    let profile = path.ancestors().nth(depth);
    let parent = profile.and_then(Path::parent).and_then(Path::file_name);
    match (profile.and_then(Path::file_name), parent) {
        (Some(user), Some(parent))
            if ["Users", "Documents and Settings", "ServiceProfiles"]
                .iter()
                .any(|p| parent.eq_ignore_ascii_case(p)) =>
        {
            user.to_string_lossy().into_owned()
        }
        _ => String::new(),
    }
}

impl RegistrySource {
    pub fn open(path: &Path, opts: &ParseOptions) -> anyhow::Result<RegistrySource> {
        let len = std::fs::metadata(path)
            .with_context(|| format!("cannot open {}", path.display()))?
            .len();
        if len > MAX_SIZE {
            anyhow::bail!("{}: too large for a registry hive", path.display());
        }
        // Opened read-only: evidence is never written.
        let bytes =
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let key = opts
            .key
            .unwrap_or_else(|| FileKey::fingerprint(&bytes, 64 * 1024 + 4096));
        let (hive, warnings) =
            Hive::open(bytes, &logs_of(path)).with_context(|| path.display().to_string())?;
        let host = computer_for(path).unwrap_or_default();
        Ok(RegistrySource {
            path: path.to_path_buf(),
            key,
            len,
            hive,
            host,
            user: user_of(path),
            all_keys: opts.registry_keys,
            warnings,
        })
    }
}

impl Source for RegistrySource {
    fn key(&self) -> FileKey {
        self.key
    }
    fn path(&self) -> &Path {
        &self.path
    }
    fn units(&self) -> usize {
        1
    }
    fn byte_len(&self) -> u64 {
        self.len
    }
    fn is_log(&self) -> bool {
        false
    }
    fn open_warnings(&self) -> &[String] {
        &self.warnings
    }
    fn parse_unit(&self, _unit: usize, sink: &mut dyn Sink) -> UnitReport {
        let mut rep = UnitReport::default();
        let r = self.hive.reader();
        let Some(root) = r.root() else {
            rep.bad_unit = true;
            return rep;
        };
        let mut n = 0u64;
        let mut emit = |rec: plugins::Rec| {
            n += 1;
            if !sink.want_event_id(rec.eid) || !sink.want_time(rec.ts) {
                return;
            }
            let mut fields = rec.fields;
            if !self.user.is_empty() && !fields.iter().any(|f| f.name == "User") {
                fields.insert(0, field("User", Val::Str(Cow::Borrowed(&self.user))));
            }
            sink.event(&EventView {
                id: EventRef {
                    file: self.key,
                    record: n,
                },
                ts: rec.ts,
                event_id: rec.eid,
                provider: Cow::Borrowed(PROVIDER),
                channel: Cow::Borrowed(CHANNEL),
                computer: Cow::Borrowed(&self.host),
                event_record_id: n,
                fields,
                ..EventView::default()
            });
        };
        plugins::run(&root, self.all_keys, &mut emit);
        rep.records = n;
        let (bad, cut) = r.damage();
        if bad > 0 {
            rep.bad_records = bad;
            rep.note(|| format!("{bad} unreadable cells"));
        }
        if cut {
            rep.bad_records += 1;
            rep.note(|| "values repeat beyond the size of the hive: output cut".into());
        }
        rep
    }
}

fn field<'a>(name: &'static str, value: Val<'a>) -> Field<'a> {
    Field {
        name: Cow::Borrowed(name),
        value,
    }
}

/// By hive, its size and modification time.
type HostKey = (PathBuf, u64, Option<std::time::SystemTime>);
type HostCache = Mutex<std::collections::HashMap<HostKey, Option<String>>>;

/// The computer name from the `SYSTEM` hive of the collection `path` is in:
/// in the same folder, or at `Windows/System32/config` under any parent
/// (KAPE and Velociraptor keep the volume's layout). Read once per version of
/// the hive: a long-lived process may see it replaced.
pub fn computer_for(path: &Path) -> Option<String> {
    static CACHE: OnceLock<HostCache> = OnceLock::new();
    let hive = system_hive(path)?;
    let cache = CACHE.get_or_init(Default::default);
    let meta = std::fs::metadata(&hive).ok()?;
    let key = (hive, meta.len(), meta.modified().ok());
    if let Some(known) = cache.lock().ok()?.get(&key) {
        return known.clone();
    }
    let name = read_computer_name(&key.0);
    cache.lock().ok()?.insert(key, name.clone());
    name
}

fn child(dir: &Path, name: &str) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(name))
        .map(|e| e.path())
}

fn system_hive(path: &Path) -> Option<PathBuf> {
    let beside = path.parent().and_then(|d| {
        let d = if d.as_os_str().is_empty() {
            Path::new(".")
        } else {
            d
        };
        child(d, "SYSTEM")
    });
    beside.filter(|p| p.is_file()).or_else(|| {
        path.ancestors().skip(1).find_map(|a| {
            let a = if a.as_os_str().is_empty() {
                Path::new(".")
            } else {
                a
            };
            child(
                &child(&child(&child(a, "Windows")?, "System32")?, "config")?,
                "SYSTEM",
            )
            .filter(|p| p.is_file())
        })
    })
}

fn read_computer_name(path: &Path) -> Option<String> {
    let mut head = [0u8; 4];
    std::io::Read::read_exact(&mut std::fs::File::open(path).ok()?, &mut head).ok()?;
    if &head != b"regf" || std::fs::metadata(path).ok()?.len() > MAX_SIZE {
        return None;
    }
    let (hive, _) = Hive::open(std::fs::read(path).ok()?, &logs_of(path)).ok()?;
    let r = hive.reader();
    plugins::computer_name(&r.root()?)
}

/// Writes a time like every other date field of forhunt.
fn iso(ts: Ts) -> String {
    let mut v = Vec::with_capacity(27);
    ts.write_iso(&mut v);
    String::from_utf8_lossy(&v).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_user_hives_in_a_profile_have_an_owner() {
        let user = |p: &str| user_of(Path::new(p));
        let case = "/Users/analyst/case/host/C";
        assert_eq!(user(&format!("{case}/Users/bob/NTUSER.DAT")), "bob");
        assert_eq!(user(&format!("{case}/Users/bob/ntuser.dat")), "bob");
        assert_eq!(
            user(&format!(
                "{case}/Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat"
            )),
            "bob"
        );
        assert_eq!(
            user(&format!(
                "{case}/Windows/ServiceProfiles/LocalService/NTUSER.DAT"
            )),
            "LocalService"
        );
        assert_eq!(user(&format!("{case}/Windows/System32/config/SYSTEM")), "");
        assert_eq!(
            user(&format!("{case}/Windows/AppCompat/Programs/Amcache.hve")),
            ""
        );
        assert_eq!(user("/Users/analyst/case/NTUSER.DAT"), "");
    }
}
