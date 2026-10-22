//! `$MFT` artifact: each 64 KiB run of FILE records is a parse unit.
//!
//! A record becomes timeline events, one per distinct timestamp of its
//! $STANDARD_INFORMATION (event id 16, `0x10`) and of its $FILE_NAME (event
//! id 48, `0x30`), with a `MACB` field telling which of Modified, Accessed,
//! record Changed and Born (created) share that time. Every event carries the
//! record's path, size, flags and all eight timestamps, so one event is enough
//! to judge timestomping (`SiLtFn`, `uSecZeros`). Event ids are
//! `<file key>:<entry * 8 + n>`, n numbering the record's events.

use std::borrow::Cow;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;

use super::paths::{self, DirTable};
use super::record::{self, FLAG_DIRECTORY, FLAG_IN_USE, Parsed, Times};
use crate::artifact::{Artifact, ParseOptions, Sink, Source, UnitReport};
use crate::event::{EventView, Field, Val};
use crate::id::{EventRef, FileKey, fmt_u64};
use crate::io::Data;
use crate::time::Ts;

const UNIT_BYTES: usize = 64 * 1024;
/// Event ids: the attribute type the timestamps come from.
pub const EID_SI: u32 = 0x10;
pub const EID_FN: u32 = 0x30;
pub const CHANNEL: &str = "MFT";
pub const PROVIDER: &str = "NTFS";

thread_local! {
    static BUF: std::cell::RefCell<(Vec<u8>, Vec<u8>, Vec<u8>)> = Default::default();
}

pub struct MftArtifact;

impl Artifact for MftArtifact {
    fn name(&self) -> &'static str {
        "mft"
    }
    fn sniff(&self, head: &[u8]) -> bool {
        // Record 0 ($MFT itself), update sequence array right after the header.
        head.starts_with(b"FILE") && matches!(record::u16_at(head, 4), Some(0x2A | 0x30))
    }
    fn matches_name(&self, path: &Path) -> bool {
        path.file_name().is_some_and(|n| {
            let n = n.to_string_lossy().to_ascii_lowercase();
            n == "$mft" || n == "%24mft" || n.ends_with(".mft")
        })
    }
    fn open(&self, path: &Path, opts: &ParseOptions) -> anyhow::Result<Arc<dyn Source>> {
        Ok(Arc::new(MftSource::open(path, opts)?))
    }
}

pub struct MftSource {
    path: PathBuf,
    key: FileKey,
    data: Data,
    rec_size: usize,
    units: usize,
    dirs: Arc<DirTable>,
    warnings: Vec<String>,
}

/// Record size from record 0 (allocated size at 0x1C), 1 KiB by default.
pub(crate) fn record_size(head: &[u8]) -> usize {
    match record::u32_at(head, 0x1C) {
        Some(n @ (1024 | 4096)) => n as usize,
        _ => 1024,
    }
}

impl MftSource {
    pub fn open(path: &Path, opts: &ParseOptions) -> anyhow::Result<MftSource> {
        let file =
            std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        // Opened read-only: evidence is never written.
        let len = file.metadata()?.len();
        Self::from_data(path.to_path_buf(), Data::File { file, len }, opts)
    }

    pub fn from_bytes(path: PathBuf, bytes: Vec<u8>, opts: &ParseOptions) -> anyhow::Result<Self> {
        Self::from_data(path, Data::Owned(bytes), opts)
    }

    fn from_data(path: PathBuf, data: Data, opts: &ParseOptions) -> anyhow::Result<Self> {
        let len = data.len();
        let head = data.read(0, 4096)?;
        if !head.starts_with(b"FILE") {
            anyhow::bail!(
                "{}: not an $MFT (no FILE record at offset 0)",
                path.display()
            );
        }
        let rec_size = record_size(&head);
        let mut warnings = Vec::new();
        if len % rec_size as u64 != 0 {
            warnings.push(format!(
                "file size is not a multiple of the {rec_size}-byte record size; last record ignored"
            ));
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
        let dirs = paths::cached(&path, &data, rec_size);
        Ok(MftSource {
            units: (len as usize / rec_size).div_ceil(UNIT_BYTES / rec_size),
            path,
            key,
            data,
            rec_size,
            dirs,
            warnings,
        })
    }

    fn per_unit(&self) -> usize {
        UNIT_BYTES / self.rec_size
    }

    fn parse_records(&self, unit: usize, sink: &mut dyn Sink, rep: &mut UnitReport) {
        BUF.with(|b| {
            let (buf, rec, txt) = &mut *b.borrow_mut();
            let off = (unit * UNIT_BYTES) as u64;
            let raw = match self.data.read_into(off, UNIT_BYTES, buf) {
                Ok(r) => r,
                Err(e) => {
                    rep.bad_unit = true;
                    rep.note(|| format!("unit {unit}: read error: {e}"));
                    return;
                }
            };
            for (i, chunk) in raw.chunks_exact(self.rec_size).enumerate() {
                let entry = (unit * self.per_unit() + i) as u64;
                rec.clear();
                rec.extend_from_slice(chunk);
                if rec[..4] == [0, 0, 0, 0] {
                    continue;
                }
                rep.records += 1;
                if let Err(e) = record::fixup(rec) {
                    rep.bad_records += 1;
                    rep.note(|| format!("entry {entry}: {e}"));
                    continue;
                }
                match record::parse(rec) {
                    Parsed::Empty => rep.records -= 1,
                    Parsed::Bad(e) => {
                        rep.bad_records += 1;
                        rep.note(|| format!("entry {entry}: {e}"));
                    }
                    Parsed::Ok(r) if r.base == 0 => {
                        emit(self.key, &self.dirs, entry, &r, txt, sink);
                    }
                    Parsed::Ok(_) => {} // extension record: attributes of its base entry
                }
            }
        });
    }
}

/// Text appended to `txt`, as a byte range.
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

const MACB: [&str; 16] = [
    "....", "M...", ".A..", "MA..", "..C.", "M.C.", ".AC.", "MAC.", "...B", "M..B", ".A.B", "MA.B",
    "..CB", "M.CB", ".ACB", "MACB",
];

/// Distinct non-zero timestamps of a $SI/$FN set, ascending, with their MACB mask.
fn groups(t: &Times) -> Vec<(Ts, usize)> {
    // Stored order: created (B), modified (M), changed (C), accessed (A).
    const BIT: [usize; 4] = [8, 1, 4, 2];
    let mut out: Vec<(Ts, usize)> = Vec::with_capacity(4);
    for (k, &v) in t.iter().enumerate() {
        let Some(ts) = record::filetime(v) else {
            continue;
        };
        match out.iter_mut().find(|(x, _)| *x == ts) {
            Some(g) => g.1 |= BIT[k],
            None => out.push((ts, BIT[k])),
        }
    }
    out.sort_by_key(|g| g.0);
    out
}

fn emit(
    key: FileKey,
    dirs: &DirTable,
    entry: u64,
    r: &record::FileRecord<'_>,
    txt: &mut Vec<u8>,
    sink: &mut dyn Sink,
) {
    let si = r.si.as_ref().map(|s| groups(&s.times)).unwrap_or_default();
    let fname = r
        .name
        .as_ref()
        .map(|n| groups(&n.times))
        .unwrap_or_default();
    let want_si = !si.is_empty() && sink.want_event_id(EID_SI);
    let want_fn = !fname.is_empty() && sink.want_event_id(EID_FN);
    let wanted = |g: &[(Ts, usize)], s: &mut dyn Sink| g.iter().any(|(ts, _)| s.want_time(*ts));
    let want_si = want_si && wanted(&si, sink);
    let want_fn = want_fn && wanted(&fname, sink);
    if !want_si && !want_fn {
        return;
    }

    // All text of the record, built once and borrowed by every event.
    txt.clear();
    let in_use = r.flags & FLAG_IN_USE != 0;
    let is_dir = r.flags & FLAG_DIRECTORY != 0;
    let (path, name, parent) = match &r.name {
        Some(n) => {
            let (pe, ps) = record::split_ref(n.parent);
            let start = txt.len();
            if entry == 5 {
                txt.push(b'.');
            } else {
                dirs.push_parent(txt, pe, ps);
                txt.push(b'\\');
            }
            let name_start = txt.len();
            if entry != 5 {
                record::push_utf16(txt, n.name);
            }
            (
                Some((start, txt.len())),
                Some((name_start, txt.len())),
                Some((pe, ps)),
            )
        }
        None => (None, None, None),
    };
    let ts_text = |txt: &mut Vec<u8>, t: Option<&Times>| -> [Option<(usize, usize)>; 4] {
        let mut o = [None; 4];
        if let Some(t) = t {
            for k in 0..4 {
                if let Some(ts) = record::filetime(t[k]) {
                    o[k] = Some(put(txt, |b| ts.write_iso(b)));
                }
            }
        }
        o
    };
    let si_t = ts_text(txt, r.si.as_ref().map(|s| &s.times));
    let fn_t = ts_text(txt, r.name.as_ref().map(|n| &n.times));
    let size = r.size.filter(|_| !is_dir).map(|v| num(txt, v));
    let entry_r = num(txt, entry);
    let seq_r = num(txt, r.seq as u64);
    let parent_r = parent.map(|(pe, ps)| (num(txt, pe), num(txt, ps as u64)));
    let attrs =
        r.si.as_ref()
            .filter(|s| s.flags != 0)
            .map(|s| put(txt, |b| record::push_attrs(b, s.flags)));
    let ads = (!r.ads.is_empty()).then(|| {
        put(txt, |b| {
            for (i, a) in r.ads.iter().enumerate() {
                if i > 0 {
                    b.push(b'|');
                }
                record::push_utf16(b, a);
            }
        })
    });
    let zone = r.zone.map(|z| {
        put(txt, |b| {
            let s = String::from_utf8_lossy(z);
            b.extend_from_slice(s.trim_end_matches(['\0', '\r', '\n', ' ']).as_bytes());
        })
    });
    let usn = r.si.as_ref().and_then(|s| s.usn).map(|v| num(txt, v));
    let lsn = num(txt, r.lsn);
    // Text is ASCII, `push_utf16` output or lossy UTF-8: always valid.
    let Ok(t) = std::str::from_utf8(txt) else {
        return;
    };
    let s = |r: (usize, usize)| Val::Str(Cow::Borrowed(&t[r.0..r.1]));
    let n = |r: (usize, usize)| Val::Num(Cow::Borrowed(&t[r.0..r.1]));

    let (si_created, si_modified) =
        r.si.as_ref()
            .map(|s| (s.times[0], s.times[1]))
            .unwrap_or((0, 0));
    let fn_created = r.name.as_ref().map(|f| f.times[0]).unwrap_or(0);
    let mut common: Vec<Field<'_>> = Vec::with_capacity(28);
    let mut push = |name: &'static str, value| {
        common.push(Field {
            name: Cow::Borrowed(name),
            value,
        })
    };
    if let Some(p) = path {
        push("Path", s(p));
    }
    if let Some(p) = name {
        push("FileName", s(p));
    }
    if let Some(v) = size {
        push("FileSize", n(v));
    }
    push("EntryNumber", n(entry_r));
    push("SequenceNumber", n(seq_r));
    if let Some((pe, ps)) = parent_r {
        push("ParentEntryNumber", n(pe));
        push("ParentSequenceNumber", n(ps));
    }
    if !in_use {
        push("Deleted", Val::Bool(true));
    }
    if is_dir {
        push("IsDirectory", Val::Bool(true));
    }
    if let Some(v) = attrs {
        push("SiFlags", s(v));
    }
    if let Some(v) = ads {
        push("AdsNames", s(v));
    }
    if let Some(v) = zone {
        push("ZoneIdContents", s(v));
    }
    if si_created != 0 && fn_created != 0 && si_created < fn_created {
        push("SiLtFn", Val::Bool(true));
    }
    if si_created != 0 && si_created % 10_000_000 == 0 {
        push("uSecZeros", Val::Bool(true));
    }
    if si_created != 0 && si_modified != 0 && si_created > si_modified {
        push("Copied", Val::Bool(true));
    }
    const SI_NAMES: [&str; 4] = [
        "Created0x10",
        "LastModified0x10",
        "LastRecordChange0x10",
        "LastAccess0x10",
    ];
    const FN_NAMES: [&str; 4] = [
        "Created0x30",
        "LastModified0x30",
        "LastRecordChange0x30",
        "LastAccess0x30",
    ];
    for (names, vals) in [(SI_NAMES, si_t), (FN_NAMES, fn_t)] {
        for k in 0..4 {
            if let Some(v) = vals[k] {
                push(names[k], s(v));
            }
        }
    }
    if let Some(v) = usn {
        push("Usn", n(v));
    }
    push("LogfileSequenceNumber", n(lsn));

    let mut ev = EventView {
        provider: Cow::Borrowed(PROVIDER),
        channel: Cow::Borrowed(CHANNEL),
        fields: Vec::with_capacity(common.len() + 1),
        ..EventView::default()
    };
    let sets = [
        (EID_SI, &si, want_si, 0u64),
        (EID_FN, &fname, want_fn, 4u64),
    ];
    for (eid, groups, want, base) in sets {
        if !want {
            continue;
        }
        for (k, &(ts, mask)) in groups.iter().enumerate() {
            if !sink.want_time(ts) {
                continue;
            }
            ev.id = EventRef {
                file: key,
                record: entry * 8 + base + k as u64,
            };
            ev.event_record_id = ev.id.record;
            ev.ts = ts;
            ev.event_id = eid;
            ev.fields.clear();
            ev.fields.push(Field {
                name: Cow::Borrowed("MACB"),
                value: Val::Str(Cow::Borrowed(MACB[mask])),
            });
            ev.fields.extend(common.iter().cloned());
            sink.event(&ev);
        }
    }
}

impl Source for MftSource {
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
        let first = (unit * self.per_unit()) as u64;
        Some((first * 8, (first + self.per_unit() as u64) * 8 - 1))
    }
    /// The FILE record (fixups applied) as a hex dump.
    fn raw_record(&self, unit: usize, record: u64) -> Option<anyhow::Result<String>> {
        let entry = record / 8;
        let (a, b) = self.unit_record_range(unit)?;
        if record < a || record > b {
            return None;
        }
        let mut rec = match self.data.read(entry * self.rec_size as u64, self.rec_size) {
            Ok(r) => r.into_owned(),
            Err(e) => return Some(Err(e.into())),
        };
        if rec.len() < self.rec_size {
            return None;
        }
        if let Err(e) = record::fixup(&mut rec) {
            return Some(Err(anyhow::anyhow!("entry {entry}: {e}")));
        }
        Some(Ok(record::hexdump(&rec)))
    }
    fn parse_unit(&self, unit: usize, sink: &mut dyn Sink) -> UnitReport {
        let mut rep = UnitReport::default();
        if catch_unwind(AssertUnwindSafe(|| {
            self.parse_records(unit, sink, &mut rep)
        }))
        .is_err()
        {
            rep.bad_unit = true;
            rep.note(|| format!("unit {unit}: parser panicked"));
        }
        rep
    }
}

impl MftSource {
    /// Number of directories resolved in the path table (diagnostics).
    pub fn directories(&self) -> usize {
        self.dirs.len()
    }
}
