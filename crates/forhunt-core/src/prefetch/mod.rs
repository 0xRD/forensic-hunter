//! Windows prefetch (`.pf`) artifact: proof of execution.
//!
//! One event per stored run time (one on XP to Windows 7, up to eight on
//! Windows 8 and later), each carrying the whole file's content: run count,
//! all run times, volumes, directories and the files loaded in the first ten
//! seconds of the run (D-049). Files are small and fully parsed at open
//! time, so a source is one unit. Formats 17 (XP), 23 (Vista/7), 26 (8.1),
//! 30 (10) and 31 (11) are read, plain or `MAM`-compressed (see [`xpress`]).
//! Event ids are `<file key>:<run index>`, the index being the slot in the
//! file: 1 is the latest run, the others normally follow newest first.

mod xpress;

use std::borrow::Cow;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;

use crate::artifact::{Artifact, ParseOptions, Sink, Source, UnitReport};
use crate::event::{EventView, Field, Val};
use crate::id::{EventRef, FileKey};
use crate::ntfs::record::{filetime, hexdump, push_utf16, u16_at, u32_at, u64_at};
use crate::time::Ts;

pub const CHANNEL: &str = "Prefetch";
pub const PROVIDER: &str = "Prefetch";
pub const EID_RUN: u32 = 1;

/// Windows stops at a few MiB: anything larger is not a prefetch file, and a
/// damaged size field must not allocate gigabytes.
const MAX_SIZE: usize = 64 * 1024 * 1024;
const COMPRESSED: &[u8; 3] = b"MAM";
/// `COMPRESSION_FORMAT_XPRESS_HUFF` in the low bits of the fourth byte.
const XPRESS_HUFF: u8 = 4;
const SIGNATURE: &[u8; 4] = b"SCCA";
const HEADER: usize = 84;
const NAME_BYTES: usize = 60;
/// Offset of the first section in the second Windows 10 layout, which is 8
/// bytes shorter before the run count.
const SHORT_LAYOUT: u32 = 296;

pub struct PrefetchArtifact;

impl Artifact for PrefetchArtifact {
    fn name(&self) -> &'static str {
        "prefetch"
    }
    fn sniff(&self, head: &[u8]) -> bool {
        head.len() >= 8
            && ((head.starts_with(COMPRESSED) && head[3] & 0x0F == XPRESS_HUFF)
                || &head[4..8] == SIGNATURE)
    }
    fn matches_name(&self, path: &Path) -> bool {
        path.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("pf"))
    }
    fn open(&self, path: &Path, opts: &ParseOptions) -> anyhow::Result<Arc<dyn Source>> {
        Ok(Arc::new(PrefetchSource::open(path, opts)?))
    }
}

#[derive(Debug, Default, Clone)]
struct Parsed {
    version: u32,
    name: String,
    hash: String,
    run_count: u32,
    /// In file order, unset slots left out.
    runs: Vec<Ts>,
    run_times: String,
    exe_path: String,
    volume_names: String,
    volume_serials: String,
    volume_created: String,
    directory_count: usize,
    directories: String,
    file_count: usize,
    files: String,
}

pub struct PrefetchSource {
    path: PathBuf,
    key: FileKey,
    len: u64,
    parsed: Option<Parsed>,
    /// What could not be read (the file is damaged or of an unknown format).
    problems: Vec<String>,
}

impl PrefetchSource {
    pub fn open(path: &Path, opts: &ParseOptions) -> anyhow::Result<PrefetchSource> {
        let meta =
            std::fs::metadata(path).with_context(|| format!("cannot open {}", path.display()))?;
        if meta.len() > MAX_SIZE as u64 {
            anyhow::bail!("{}: too large for a prefetch file", path.display());
        }
        // Opened read-only: evidence is never written.
        let bytes =
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        Self::from_bytes(path.to_path_buf(), &bytes, opts)
    }

    pub fn from_bytes(path: PathBuf, bytes: &[u8], opts: &ParseOptions) -> anyhow::Result<Self> {
        if bytes.is_empty() {
            anyhow::bail!("{}: empty file", path.display());
        }
        let key = opts
            .key
            .unwrap_or_else(|| FileKey::fingerprint(bytes, 64 * 1024 + 4096));
        let mut problems = Vec::new();
        let body = body(bytes, &mut problems);
        let parsed = parse(&body, &mut problems);
        Ok(PrefetchSource {
            path,
            key,
            len: bytes.len() as u64,
            parsed,
            problems,
        })
    }

    fn emit(&self, p: &Parsed, index: usize, ts: Ts, sink: &mut dyn Sink) {
        if !sink.want_event_id(EID_RUN) || !sink.want_time(ts) {
            return;
        }
        let f = |name: &'static str, value| Field {
            name: Cow::Borrowed(name),
            value,
        };
        let s = |v: &'_ str| Val::Str(Cow::Owned(v.to_string()));
        let n = |v: u64| Val::Num(Cow::Owned(v.to_string()));
        let mut fields = Vec::with_capacity(14);
        fields.push(f("ExecutableName", Val::Str(Cow::Borrowed(&p.name))));
        if !p.exe_path.is_empty() {
            fields.push(f("ExePath", Val::Str(Cow::Borrowed(&p.exe_path))));
        }
        fields.push(f("Hash", Val::Str(Cow::Borrowed(&p.hash))));
        fields.push(f("RunCount", n(p.run_count as u64)));
        fields.push(f("RunIndex", n(index as u64)));
        fields.push(f("RunTimes", s(&p.run_times)));
        if p.runs.is_empty() {
            fields.push(f("NoRunTime", Val::Bool(true)));
        }
        fields.push(f("PrefetchVersion", n(p.version as u64)));
        fields.push(f("VolumeNames", Val::Str(Cow::Borrowed(&p.volume_names))));
        fields.push(f(
            "VolumeSerials",
            Val::Str(Cow::Borrowed(&p.volume_serials)),
        ));
        fields.push(f(
            "VolumeCreated",
            Val::Str(Cow::Borrowed(&p.volume_created)),
        ));
        fields.push(f("DirectoryCount", n(p.directory_count as u64)));
        fields.push(f("FileCount", n(p.file_count as u64)));
        fields.push(f("Directories", Val::Str(Cow::Borrowed(&p.directories))));
        fields.push(f("FilesLoaded", Val::Str(Cow::Borrowed(&p.files))));
        sink.event(&EventView {
            id: EventRef {
                file: self.key,
                record: index as u64,
            },
            ts,
            event_id: EID_RUN,
            provider: Cow::Borrowed(PROVIDER),
            channel: Cow::Borrowed(CHANNEL),
            event_record_id: index as u64,
            fields,
            ..EventView::default()
        });
    }
}

impl Source for PrefetchSource {
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
    fn unit_record_range(&self, _unit: usize) -> Option<(u64, u64)> {
        let p = self.parsed.as_ref()?;
        Some((1, p.runs.len().max(1) as u64))
    }
    fn parse_unit(&self, _unit: usize, sink: &mut dyn Sink) -> UnitReport {
        let mut rep = UnitReport::default();
        for e in &self.problems {
            rep.note(|| e.clone());
        }
        let Some(p) = &self.parsed else {
            rep.bad_unit = true;
            return rep;
        };
        rep.bad_records = !self.problems.is_empty() as u64;
        rep.records = p.runs.len().max(1) as u64 + rep.bad_records;
        // A file without a run time is still evidence the program ran.
        if p.runs.is_empty() {
            self.emit(p, 1, Ts::default(), sink);
        }
        for (i, ts) in p.runs.iter().enumerate() {
            self.emit(p, i + 1, *ts, sink);
        }
        rep
    }
    /// The hex dump of the decompressed file: each run shares it.
    fn raw_record(&self, unit: usize, record: u64) -> Option<anyhow::Result<String>> {
        let (a, b) = self.unit_record_range(unit)?;
        if record < a || record > b {
            return None;
        }
        Some(
            std::fs::read(&self.path)
                .map(|bytes| hexdump(&body(&bytes, &mut Vec::new())))
                .map_err(Into::into),
        )
    }
    fn is_log(&self) -> bool {
        false
    }
    fn open_warnings(&self) -> &[String] {
        &self.problems
    }
}

/// The uncompressed file (the bytes as they are unless `MAM`).
fn body<'a>(bytes: &'a [u8], problems: &mut Vec<String>) -> Cow<'a, [u8]> {
    if !bytes.starts_with(COMPRESSED) {
        return Cow::Borrowed(bytes);
    }
    let flags = bytes.get(3).copied().unwrap_or(0);
    if flags & 0x0F != XPRESS_HUFF {
        problems.push(format!("unsupported compression {flags:#x}"));
        return Cow::Borrowed(&[]);
    }
    // The high bit announces a CRC32 between the size and the stream.
    let start = if flags & 0x80 != 0 { 12 } else { 8 };
    let Some(size) = u32_at(bytes, 4).map(|s| s as usize) else {
        problems.push("truncated compression header".into());
        return Cow::Borrowed(&[]);
    };
    if size > MAX_SIZE {
        problems.push(format!("implausible uncompressed size {size}"));
        return Cow::Borrowed(&[]);
    }
    let (out, err) = xpress::decompress(bytes.get(start..).unwrap_or(&[]), size);
    if let Some(e) = err {
        problems.push(format!("decompressed {} of {size} bytes: {e}", out.len()));
    }
    Cow::Owned(out)
}

fn utf16(b: &[u8]) -> String {
    let mut v = Vec::with_capacity(b.len() / 2);
    push_utf16(&mut v, b);
    String::from_utf8_lossy(&v).into_owned()
}

/// Bytes of a NUL-terminated UTF-16 string at the start of `b`.
fn until_nul(b: &[u8]) -> &[u8] {
    let n = b
        .chunks_exact(2)
        .position(|c| c == [0, 0])
        .unwrap_or(b.len() / 2);
    &b[..n * 2]
}

fn iso(ts: Ts) -> String {
    let mut v = Vec::with_capacity(27);
    ts.write_iso(&mut v);
    String::from_utf8_lossy(&v).into_owned()
}

/// Offsets of the file information block, which follows the header.
struct Layout {
    run_times: usize,
    run_slots: usize,
    run_count: usize,
    metric_size: usize,
    volume_size: usize,
}

fn layout(version: u32, first_section: u32) -> Option<Layout> {
    let (run_times, run_slots, run_count, metric_size, volume_size) = match version {
        17 => (36, 1, 60, 20, 40),
        23 => (44, 1, 68, 32, 104),
        26 => (44, 8, 124, 32, 104),
        30 | 31 if first_section == SHORT_LAYOUT => (44, 8, 116, 32, 96),
        30 | 31 => (44, 8, 124, 32, 96),
        _ => return None,
    };
    Some(Layout {
        run_times: HEADER + run_times,
        run_slots,
        run_count: HEADER + run_count,
        metric_size,
        volume_size,
    })
}

fn parse(b: &[u8], problems: &mut Vec<String>) -> Option<Parsed> {
    if b.is_empty() {
        return None;
    }
    if b.len() < HEADER + 36 || b.get(4..8) != Some(SIGNATURE) {
        problems.push("no prefetch header (SCCA signature)".into());
        return None;
    }
    let version = u32_at(b, 0)?;
    let at = |o: usize| u32_at(b, HEADER + o).map_or(0, |v| v as usize);
    let (metrics, n_metrics) = (at(0), at(4));
    let (strings, strings_size) = (at(16), at(20));
    let (volumes, n_volumes) = (at(24), at(28));
    let volumes_size = at(32);
    let Some(l) = layout(version, metrics as u32) else {
        problems.push(format!("unsupported prefetch version {version}"));
        return None;
    };
    let mut p = Parsed {
        version,
        name: utf16(until_nul(&b[16..16 + NAME_BYTES])),
        hash: format!("{:08X}", u32_at(b, 76)?),
        run_count: u32_at(b, l.run_count).unwrap_or(0),
        ..Parsed::default()
    };
    let mut times = Vec::with_capacity(l.run_slots);
    for i in 0..l.run_slots {
        let v = u64_at(b, l.run_times + i * 8);
        if v.is_none() {
            problems.push("run times cut off".into());
        }
        if let Some(ts) = v.and_then(filetime) {
            p.runs.push(ts);
            times.push(iso(ts));
        }
    }
    p.run_times = times.join(", ");

    let names = strings
        .checked_add(strings_size)
        .and_then(|end| b.get(strings..end));
    let mut files = Vec::new();
    // Counts come from the file: never loop further than it can hold.
    let fits = b.len().saturating_sub(metrics) / l.metric_size;
    let mut missing = n_metrics.saturating_sub(fits);
    for i in 0..n_metrics.min(fits) {
        let m = metrics + i * l.metric_size;
        let (off, chars) = match l.metric_size {
            20 => (u32_at(b, m + 8), u32_at(b, m + 12)),
            _ => (u32_at(b, m + 12), u32_at(b, m + 16)),
        };
        let name = off
            .zip(chars)
            .zip(names)
            .and_then(|((o, c), s)| s.get(o as usize..(o as usize).checked_add(c as usize * 2)?));
        match name {
            Some(n) => files.push(utf16(n)),
            None => missing += 1,
        }
    }
    if missing > 0 {
        problems.push(format!("{missing} of {n_metrics} file names unreadable"));
    }
    p.file_count = files.len();
    p.exe_path = exe_paths(&p.name, &files).join(", ");
    p.files = files.join(", ");

    let area = volumes
        .checked_add(volumes_size)
        .and_then(|end| b.get(volumes..end));
    let (mut vnames, mut serials, mut created, mut dirs) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let fits = area.map_or(0, |a| a.len() / l.volume_size);
    let mut bad_volumes = n_volumes.saturating_sub(fits);
    for i in 0..n_volumes.min(fits) {
        let v = area.and_then(|a| volume(a, i * l.volume_size));
        match v {
            Some(v) => {
                vnames.push(v.name);
                serials.push(v.serial);
                created.push(v.created);
                dirs.extend(v.dirs);
            }
            None => bad_volumes += 1,
        }
    }
    if bad_volumes > 0 {
        problems.push(format!("{bad_volumes} of {n_volumes} volumes unreadable"));
    }
    p.volume_names = vnames.join(", ");
    p.volume_serials = serials.join(", ");
    p.volume_created = created.join(", ");
    p.directory_count = dirs.len();
    p.directories = dirs.join(", ");
    Some(p)
}

/// Files named like the program. The header keeps 29 characters of the name;
/// when a name appears in several folders all candidates are given: the
/// file does not say which one ran.
fn exe_paths(name: &str, files: &[String]) -> Vec<String> {
    if name.is_empty() {
        return Vec::new();
    }
    let full = name.chars().count() < NAME_BYTES / 2 - 1;
    let upper = name.to_uppercase();
    let mut out: Vec<String> = Vec::new();
    for f in files {
        let base = f.rsplit('\\').next().unwrap_or(f).to_uppercase();
        let hit = if full {
            base == upper
        } else {
            base.starts_with(&upper)
        };
        if hit && !out.contains(f) {
            out.push(f.clone());
        }
    }
    out
}

struct Volume {
    name: String,
    serial: String,
    created: String,
    dirs: Vec<String>,
}

/// One volume entry at `e` of the volumes area, whose offsets it is relative to.
fn volume(a: &[u8], e: usize) -> Option<Volume> {
    let (name, chars) = (u32_at(a, e)? as usize, u32_at(a, e + 4)? as usize);
    let name = a.get(name..name.checked_add(chars.checked_mul(2)?)?)?;
    // Unset on removable media: a dash keeps the lists aligned.
    let created = filetime(u64_at(a, e + 8)?).map_or_else(|| "-".to_string(), iso);
    let mut serial = String::new();
    write!(serial, "{:08X}", u32_at(a, e + 16)?).ok()?;
    let mut pos = u32_at(a, e + 28)? as usize;
    let count = u32_at(a, e + 32)? as usize;
    let mut dirs = Vec::new();
    for _ in 0..count {
        let Some(chars) = u16_at(a, pos) else { break };
        let end = pos + 2 + chars as usize * 2;
        let Some(d) = a.get(pos + 2..end) else { break };
        dirs.push(utf16(d));
        pos = end + 2;
    }
    Some(Volume {
        name: utf16(name),
        serial,
        created,
        dirs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_path_handles_cut_names_and_ambiguity() {
        let f = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let files = f(&["\\V\\A\\CMD.EXE", "\\V\\B\\CMD.EXE", "\\V\\A\\XCMD.EXE"]);
        assert_eq!(exe_paths("CMD.EXE", &files).len(), 2);
        let cut = "A234567890123456789012345678.";
        assert_eq!(cut.len(), 29);
        let files = f(&["\\V\\A234567890123456789012345678.ORIGINAL.EXE"]);
        assert_eq!(exe_paths(cut, &files).len(), 1);
        assert!(exe_paths("", &files).is_empty());
    }

    #[test]
    fn sniffs_and_refuses_unknown_content() {
        let a = PrefetchArtifact;
        assert!(a.sniff(b"MAM\x04\0\0\0\0"));
        assert!(a.sniff(b"MAM\x84\0\0\0\0"));
        assert!(a.sniff(b"\x1e\0\0\0SCCA"));
        assert!(!a.sniff(b"MAM\x02\0\0\0\0"));
        assert!(!a.sniff(b"ElfFile\0"));
        assert!(a.matches_name(Path::new("C/Windows/Prefetch/CMD.EXE-1234ABCD.PF")));
        let o = ParseOptions::default();
        // A `.pf` that is something else: a bad unit, not an error or a panic.
        let s = PrefetchSource::from_bytes("x.pf".into(), b"not prefetch at all", &o).unwrap();
        assert!(s.parse_unit(0, &mut |_: &EventView<'_>| {}).bad_unit);
        assert!(!s.open_warnings().is_empty());
        let mut v = vec![0u8; 400];
        v[0] = 99;
        v[4..8].copy_from_slice(SIGNATURE);
        let s = PrefetchSource::from_bytes("x.pf".into(), &v, &o).unwrap();
        assert!(s.open_warnings()[0].contains("version 99"));
        assert!(PrefetchSource::from_bytes("x.pf".into(), b"", &o).is_err());
    }

    #[test]
    fn hostile_offsets_never_panic() {
        // Every header and file information value set to extremes.
        for fill in [0x00u8, 0x7F, 0xFF] {
            for version in [17u32, 23, 26, 30, 31] {
                let mut v = vec![fill; 600];
                v[0..4].copy_from_slice(&version.to_le_bytes());
                v[4..8].copy_from_slice(SIGNATURE);
                let s = PrefetchSource::from_bytes("x.pf".into(), &v, &ParseOptions::default());
                s.unwrap().parse_unit(0, &mut |_: &EventView<'_>| {});
            }
        }
    }
}
