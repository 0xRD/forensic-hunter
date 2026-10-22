//! `$UsnJrnl:$J` artifact: the NTFS change journal, one event per USN record.
//!
//! The file is split into 64 KiB units; zero-filled regions (the sparse head
//! of an extracted journal) are skipped. Records are validated strictly
//! (version, length, name bounds, plausible timestamp); after a damaged one
//! the scan resynchronises on the next 8-byte boundary.
//!
//! Event ids group the accumulated reason flags into an action:
//! 1 created, 2 deleted, 3 renamed, 4 data changed, 5 metadata changed,
//! 6 other (close only). When an `$MFT` sits next to the journal (same
//! directory or its parent, as in KAPE/Velociraptor collections), parent
//! directories are resolved to full paths with it. Event ids are
//! `<file key>:<byte offset of the record>`.

use std::borrow::Cow;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;

use super::mft::{PROVIDER, record_size};
use super::paths::{self, DirTable};
use super::record::{self, filetime, split_ref, u16_at, u32_at, u64_at};
use crate::artifact::{Artifact, ParseOptions, Sink, Source, UnitReport};
use crate::event::{EventView, Field, Val};
use crate::id::{EventRef, FileKey, fmt_u64};
use crate::io::Data;

const UNIT_BYTES: usize = 64 * 1024;
/// Longest record (v3, 255-character name) rounded up: read past the unit end
/// so a record starting near it is complete.
const MAX_RECORD: usize = 1024;
pub const CHANNEL: &str = "UsnJrnl";

pub const EID_CREATE: u32 = 1;
pub const EID_DELETE: u32 = 2;
pub const EID_RENAME: u32 = 3;
pub const EID_DATA: u32 = 4;
pub const EID_META: u32 = 5;
pub const EID_OTHER: u32 = 6;

/// USN_REASON_* names, lowest bit first.
const REASONS: &[(u32, &str)] = &[
    (0x1, "DataOverwrite"),
    (0x2, "DataExtend"),
    (0x4, "DataTruncation"),
    (0x10, "NamedDataOverwrite"),
    (0x20, "NamedDataExtend"),
    (0x40, "NamedDataTruncation"),
    (0x100, "FileCreate"),
    (0x200, "FileDelete"),
    (0x400, "EaChange"),
    (0x800, "SecurityChange"),
    (0x1000, "RenameOldName"),
    (0x2000, "RenameNewName"),
    (0x4000, "IndexableChange"),
    (0x8000, "BasicInfoChange"),
    (0x10000, "HardLinkChange"),
    (0x20000, "CompressionChange"),
    (0x40000, "EncryptionChange"),
    (0x80000, "ObjectIdChange"),
    (0x100000, "ReparsePointChange"),
    (0x200000, "StreamChange"),
    (0x400000, "TransactedChange"),
    (0x800000, "IntegrityChange"),
    (0x80000000, "Close"),
];

/// The action a record's accumulated reasons describe, most telling first.
pub fn action(reason: u32) -> u32 {
    if reason & 0x200 != 0 {
        EID_DELETE
    } else if reason & 0x3000 != 0 {
        EID_RENAME
    } else if reason & 0x100 != 0 {
        EID_CREATE
    } else if reason & 0x77 != 0 {
        EID_DATA
    } else if reason & 0x00FF_CC00 != 0 {
        EID_META
    } else {
        EID_OTHER
    }
}

thread_local! {
    static BUF: std::cell::RefCell<(Vec<u8>, Vec<u8>)> = Default::default();
}

pub struct UsnArtifact;

impl Artifact for UsnArtifact {
    fn name(&self) -> &'static str {
        "usnjrnl"
    }
    fn sniff(&self, head: &[u8]) -> bool {
        // Non-sparse extracts start with a record; sparse ones are found by name.
        parse_record(head, 0).is_some()
    }
    fn matches_name(&self, path: &Path) -> bool {
        path.file_name().is_some_and(|n| {
            let n = n.to_string_lossy().to_ascii_lowercase();
            n == "$j" || n == "%24j" || n.contains("usnjrnl")
        })
    }
    fn open(&self, path: &Path, opts: &ParseOptions) -> anyhow::Result<Arc<dyn Source>> {
        Ok(Arc::new(UsnSource::open(path, opts)?))
    }
}

pub struct UsnSource {
    path: PathBuf,
    key: FileKey,
    data: Data,
    units: usize,
    dirs: Option<Arc<DirTable>>,
    warnings: Vec<String>,
}

/// `$MFT` in the journal's directory or its parent (`C/$Extend/$J` next to
/// `C/$MFT`), matched case-insensitively.
fn sibling_mft(path: &Path) -> Option<PathBuf> {
    let dir = path.parent()?;
    for d in [Some(dir), dir.parent()].into_iter().flatten() {
        let d = if d.as_os_str().is_empty() {
            Path::new(".")
        } else {
            d
        };
        let Ok(rd) = std::fs::read_dir(d) else {
            continue;
        };
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_ascii_lowercase();
            if (n == "$mft" || n == "%24mft") && e.path().is_file() {
                return Some(e.path());
            }
        }
    }
    None
}

impl UsnSource {
    pub fn open(path: &Path, opts: &ParseOptions) -> anyhow::Result<UsnSource> {
        let file =
            std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        // Opened read-only: evidence is never written.
        let len = file.metadata()?.len();
        let mut warnings = Vec::new();
        let dirs = match sibling_mft(path) {
            Some(m) => match std::fs::File::open(&m).and_then(|f| {
                let len = f.metadata()?.len();
                Ok(Data::File { file: f, len })
            }) {
                Ok(mdata) => {
                    let head = mdata.read(0, 4096)?;
                    head.starts_with(b"FILE")
                        .then(|| paths::cached(&m, &mdata, record_size(&head)))
                }
                Err(_) => None,
            },
            None => None,
        };
        if dirs.is_none() {
            warnings.push(
                "no $MFT next to the journal: parent directories are not resolved to paths"
                    .to_string(),
            );
        }
        Self::from_data(
            path.to_path_buf(),
            Data::File { file, len },
            dirs,
            warnings,
            opts,
        )
    }

    pub fn from_bytes(path: PathBuf, bytes: Vec<u8>, opts: &ParseOptions) -> anyhow::Result<Self> {
        Self::from_data(path, Data::Owned(bytes), None, Vec::new(), opts)
    }

    fn from_data(
        path: PathBuf,
        data: Data,
        dirs: Option<Arc<DirTable>>,
        warnings: Vec<String>,
        opts: &ParseOptions,
    ) -> anyhow::Result<Self> {
        let len = data.len();
        if len == 0 {
            anyhow::bail!("{}: empty file", path.display());
        }
        let sample = 64 * 1024 + 4096;
        let (h, t) = FileKey::sample_ranges(len, sample);
        let hb = data.read(h.0, (h.1 - h.0) as usize)?;
        let tb = match t {
            Some((a, b)) => Some(data.read(a, (b - a) as usize)?),
            None => None,
        };
        let key = opts
            .key
            .unwrap_or_else(|| FileKey::from_samples(len, &hb, tb.as_deref()));
        Ok(UsnSource {
            units: (len as usize).div_ceil(UNIT_BYTES),
            path,
            key,
            data,
            dirs,
            warnings,
        })
    }

    fn parse_block(&self, unit: usize, sink: &mut dyn Sink, rep: &mut UnitReport) {
        BUF.with(|b| {
            let (buf, txt) = &mut *b.borrow_mut();
            let start = (unit * UNIT_BYTES) as u64;
            let raw = match self.data.read_into(start, UNIT_BYTES + MAX_RECORD, buf) {
                Ok(r) => r,
                Err(e) => {
                    rep.bad_unit = true;
                    rep.note(|| format!("unit {unit}: read error: {e}"));
                    return;
                }
            };
            let end = raw.len().min(UNIT_BYTES);
            let mut off = 0usize;
            // Bytes before the first valid record may be the tail of a record
            // from the previous unit: not counted as damage.
            let mut synced = unit == 0;
            let mut damaged = false;
            while off < end {
                if raw[off..].len() >= 8 && raw[off..off + 8] == [0; 8] {
                    // Padding or sparse region: jump to the next non-zero byte.
                    let next = raw[off..end].iter().position(|&b| b != 0);
                    match next {
                        Some(p) => off += p & !7,
                        None => break,
                    }
                    if raw[off..off + 8] == [0; 8] {
                        off += 8;
                    }
                    continue;
                }
                match parse_record(raw, off) {
                    Some(r) => {
                        synced = true;
                        damaged = false;
                        rep.records += 1;
                        self.emit(&r, start + off as u64, txt, sink);
                        off += r.len;
                    }
                    None => {
                        if synced && !damaged {
                            rep.records += 1;
                            rep.bad_records += 1;
                            rep.note(|| {
                                format!("offset {}: invalid USN record", start + off as u64)
                            });
                            damaged = true;
                        }
                        off += 8;
                    }
                }
            }
        });
    }

    fn emit(&self, r: &Rec<'_>, offset: u64, txt: &mut Vec<u8>, sink: &mut dyn Sink) {
        let eid = action(r.reason);
        let Some(ts) = filetime(r.timestamp) else {
            return;
        };
        if !sink.want_event_id(eid) || !sink.want_time(ts) {
            return;
        }
        let (entry, seq) = split_ref(r.file_ref);
        let (pentry, pseq) = split_ref(r.parent_ref);
        txt.clear();
        let name = put(txt, |t| record::push_utf16(t, r.name));
        let path = self.dirs.as_ref().map(|d| {
            put(txt, |t| {
                d.push_parent(t, pentry, pseq);
                t.push(b'\\');
                record::push_utf16(t, r.name);
            })
        });
        let reason = put(txt, |t| record::flag_names(t, r.reason, REASONS));
        let attrs = put(txt, |t| record::push_attrs(t, r.attributes));
        let nums = [entry, seq as u64, pentry, pseq as u64, r.usn];
        let nums = nums.map(|v| num(txt, v));
        let source = (r.source_info != 0).then(|| num(txt, r.source_info as u64));
        let Ok(t) = std::str::from_utf8(txt) else {
            return;
        };
        let s = |r: (usize, usize)| Val::Str(Cow::Borrowed(&t[r.0..r.1]));
        let n = |r: (usize, usize)| Val::Num(Cow::Borrowed(&t[r.0..r.1]));
        let f = |name: &'static str, value| Field {
            name: Cow::Borrowed(name),
            value,
        };
        let mut fields = Vec::with_capacity(11);
        fields.push(f("Reason", s(reason)));
        fields.push(f("FileName", s(name)));
        if let Some(p) = path {
            fields.push(f("Path", s(p)));
        }
        fields.push(f("EntryNumber", n(nums[0])));
        fields.push(f("SequenceNumber", n(nums[1])));
        fields.push(f("ParentEntryNumber", n(nums[2])));
        fields.push(f("ParentSequenceNumber", n(nums[3])));
        fields.push(f("Usn", n(nums[4])));
        fields.push(f("FileAttributes", s(attrs)));
        if let Some(v) = source {
            fields.push(f("SourceInfo", n(v)));
        }
        let ev = EventView {
            id: EventRef {
                file: self.key,
                record: offset,
            },
            ts,
            event_id: eid,
            provider: Cow::Borrowed(PROVIDER),
            channel: Cow::Borrowed(CHANNEL),
            event_record_id: offset,
            fields,
            ..EventView::default()
        };
        sink.event(&ev);
    }
}

fn put(txt: &mut Vec<u8>, f: impl FnOnce(&mut Vec<u8>)) -> (usize, usize) {
    let s = txt.len();
    f(txt);
    (s, txt.len())
}

fn num(txt: &mut Vec<u8>, v: u64) -> (usize, usize) {
    put(txt, |t| {
        let mut b = [0u8; 20];
        t.extend_from_slice(fmt_u64(&mut b, v));
    })
}

struct Rec<'a> {
    len: usize,
    file_ref: u64,
    parent_ref: u64,
    usn: u64,
    timestamp: u64,
    reason: u32,
    source_info: u32,
    attributes: u32,
    name: &'a [u8],
}

/// FILETIME bounds for a plausible journal entry: 1995 to 2100.
const MIN_TS: u64 = 0x01BA_0000_0000_0000;
const MAX_TS: u64 = 0x0240_0000_0000_0000;

/// A USN_RECORD_V2 or V3 at `off`, if it passes validation. V4 (range
/// tracking, no file name) records are not timeline events.
fn parse_record(b: &[u8], off: usize) -> Option<Rec<'_>> {
    let r = b.get(off..)?;
    let len = u32_at(r, 0)? as usize;
    let major = u16_at(r, 4)?;
    if u16_at(r, 6)? != 0 || len % 8 != 0 || len > MAX_RECORD || len > r.len() {
        return None;
    }
    let (file_ref, parent_ref, base) = match major {
        2 => (u64_at(r, 8)?, u64_at(r, 16)?, 24),
        // 128-bit ids: NTFS uses the low 64 bits.
        3 => (u64_at(r, 8)?, u64_at(r, 24)?, 40),
        _ => return None,
    };
    let usn = u64_at(r, base)?;
    let timestamp = u64_at(r, base + 8)?;
    let reason = u32_at(r, base + 16)?;
    let name_len = u16_at(r, base + 32)? as usize;
    let name_off = u16_at(r, base + 34)? as usize;
    if name_off != base + 36
        || name_len == 0
        || name_len % 2 != 0
        || name_off + name_len > len
        || !(MIN_TS..MAX_TS).contains(&timestamp)
        || reason == 0
    {
        return None;
    }
    Some(Rec {
        len,
        file_ref,
        parent_ref,
        usn,
        timestamp,
        reason,
        source_info: u32_at(r, base + 20)?,
        attributes: u32_at(r, base + 28)?,
        name: &r[name_off..name_off + name_len],
    })
}

impl Source for UsnSource {
    fn key(&self) -> FileKey {
        self.key
    }
    fn path(&self) -> &Path {
        &self.path
    }
    fn units(&self) -> usize {
        self.units
    }
    fn byte_len(&self) -> u64 {
        self.data.len()
    }
    fn open_warnings(&self) -> &[String] {
        &self.warnings
    }
    fn is_log(&self) -> bool {
        false
    }
    fn unit_record_range(&self, unit: usize) -> Option<(u64, u64)> {
        let s = (unit * UNIT_BYTES) as u64;
        Some((s, s + UNIT_BYTES as u64 - 1))
    }
    /// The USN record at that offset as a hex dump.
    fn raw_record(&self, unit: usize, record: u64) -> Option<anyhow::Result<String>> {
        let (a, b) = self.unit_record_range(unit)?;
        if record < a || record > b {
            return None;
        }
        let bytes = match self.data.read(record, MAX_RECORD) {
            Ok(r) => r,
            Err(e) => return Some(Err(e.into())),
        };
        let r = parse_record(&bytes, 0)?;
        Some(Ok(record::hexdump(&bytes[..r.len])))
    }
    fn parse_unit(&self, unit: usize, sink: &mut dyn Sink) -> UnitReport {
        let mut rep = UnitReport::default();
        if catch_unwind(AssertUnwindSafe(|| self.parse_block(unit, sink, &mut rep))).is_err() {
            rep.bad_unit = true;
            rep.note(|| format!("unit {unit}: parser panicked"));
        }
        rep
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions() {
        assert_eq!(action(0x8000_0102), EID_CREATE);
        assert_eq!(action(0x8000_0200), EID_DELETE);
        assert_eq!(action(0x2000), EID_RENAME);
        assert_eq!(action(0x2), EID_DATA);
        assert_eq!(action(0x8000), EID_META);
        assert_eq!(action(0x8000_0000), EID_OTHER);
    }
}
