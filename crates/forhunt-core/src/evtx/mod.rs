//! EVTX artifact: memory-maps the file and exposes each 64 KiB chunk as an
//! independent parse unit.

pub mod decode;
mod fast;

thread_local! {
    static PLANS: std::cell::RefCell<fast::PlanCache> = Default::default();
    /// Reused read buffer: allocated and zeroed once per thread.
    static CHUNK_BUF: std::cell::Cell<Vec<u8>> = const { std::cell::Cell::new(Vec::new()) };
}

use std::borrow::Cow;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use evtx::{EvtxChunkData, EvtxChunkHeader, ParserSettings};

use crate::artifact::{Artifact, ParseOptions, Sink, Source, UnitReport};
use crate::event::EventView;
use crate::id::{EventRef, FileKey};
use crate::time::Ts;

pub const FILE_HEADER_SIZE: usize = 4096;
pub const CHUNK_SIZE: usize = 65536;
const MAGIC: &[u8; 8] = b"ElfFile\0";
const CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\0";

pub struct EvtxArtifact;

impl Artifact for EvtxArtifact {
    fn name(&self) -> &'static str {
        "evtx"
    }
    fn sniff(&self, head: &[u8]) -> bool {
        head.starts_with(MAGIC)
            || head
                .get(FILE_HEADER_SIZE..)
                .is_some_and(|c| c.starts_with(CHUNK_MAGIC))
    }
    fn matches_name(&self, path: &Path) -> bool {
        path.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
    }
    fn open(&self, path: &Path, opts: &ParseOptions) -> anyhow::Result<Arc<dyn Source>> {
        Ok(Arc::new(EvtxSource::open(path, opts)?))
    }
}

/// Where the bytes come from. Files are read with positional reads, one
/// chunk at a time, straight into the buffer the parser owns: resident
/// memory stays bounded whatever the file size (an mmap would count every
/// touched page; see DECISIONS.md D-021).
enum Data {
    File { file: std::fs::File, len: u64 },
    Owned(Vec<u8>),
}

impl Data {
    fn len(&self) -> u64 {
        match self {
            Data::File { len, .. } => *len,
            Data::Owned(v) => v.len() as u64,
        }
    }

    /// Reads `[off, off + n)`, clamped to the end of the input.
    fn read(&self, off: u64, n: usize) -> std::io::Result<Cow<'_, [u8]>> {
        let end = (off + n as u64).min(self.len());
        if off >= end {
            return Ok(Cow::Borrowed(&[]));
        }
        match self {
            Data::Owned(v) => Ok(Cow::Borrowed(&v[off as usize..end as usize])),
            Data::File { file, .. } => {
                let mut buf = vec![0u8; (end - off) as usize];
                read_exact_at(file, &mut buf, off)?;
                Ok(Cow::Owned(buf))
            }
        }
    }
}

impl Data {
    /// Like [`Data::read`], into a caller-owned buffer that is reused across
    /// calls (no allocation or zeroing once it has grown).
    fn read_into<'s>(
        &'s self,
        off: u64,
        n: usize,
        buf: &'s mut Vec<u8>,
    ) -> std::io::Result<&'s [u8]> {
        let end = (off + n as u64).min(self.len());
        if off >= end {
            return Ok(&[]);
        }
        let len = (end - off) as usize;
        match self {
            Data::Owned(v) => Ok(&v[off as usize..end as usize]),
            Data::File { file, .. } => {
                if buf.len() < len {
                    buf.resize(len, 0);
                }
                read_exact_at(file, &mut buf[..len], off)?;
                Ok(&buf[..len])
            }
        }
    }
}

fn read_exact_at(file: &std::fs::File, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    while !buf.is_empty() {
        #[cfg(unix)]
        let n = std::os::unix::fs::FileExt::read_at(file, buf, off)?;
        #[cfg(windows)]
        let n = std::os::windows::fs::FileExt::seek_read(file, buf, off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
        off += n as u64;
    }
    Ok(())
}

pub struct EvtxSource {
    path: PathBuf,
    key: FileKey,
    data: Data,
    units: usize,
    settings: Arc<ParserSettings>,
    validate: bool,
    slow: bool,
    warnings: Vec<String>,
}

impl EvtxSource {
    pub fn open(path: &Path, opts: &ParseOptions) -> anyhow::Result<EvtxSource> {
        let file =
            std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        // Opened read-only: evidence is never written.
        let len = file.metadata()?.len();
        Self::from_data(path.to_path_buf(), Data::File { file, len }, opts)
    }

    pub fn from_bytes(
        path: PathBuf,
        bytes: Vec<u8>,
        opts: &ParseOptions,
    ) -> anyhow::Result<EvtxSource> {
        Self::from_data(path, Data::Owned(bytes), opts)
    }

    fn from_data(path: PathBuf, data: Data, opts: &ParseOptions) -> anyhow::Result<EvtxSource> {
        let len = data.len();
        let mut warnings = Vec::new();
        if len < FILE_HEADER_SIZE as u64 {
            anyhow::bail!(
                "{}: too small to be an EVTX file ({len} bytes)",
                path.display()
            );
        }
        let sample = FILE_HEADER_SIZE + CHUNK_SIZE;
        let (head_r, tail_r) = FileKey::sample_ranges(len, sample);
        let head = data.read(head_r.0, (head_r.1 - head_r.0) as usize)?;
        let bytes: &[u8] = &head;
        // A "dirty" header flag is normal for a log copied from a live system,
        // so it is not reported.
        match evtx::EvtxFileHeader::from_bytes(bytes) {
            Ok(_) => {}
            Err(e) => {
                if !bytes.starts_with(MAGIC) && !bytes[FILE_HEADER_SIZE..].starts_with(CHUNK_MAGIC)
                {
                    anyhow::bail!("{}: not an EVTX file ({e})", path.display());
                }
                warnings.push(format!("invalid file header, scanning chunks anyway: {e}"));
            }
        }
        let body = (len - FILE_HEADER_SIZE as u64) as usize;
        let mut units = body / CHUNK_SIZE;
        let tail = body % CHUNK_SIZE;
        if tail > 0 {
            warnings.push(format!("file truncated: last chunk has {tail} of {CHUNK_SIZE} bytes, recovering what parses"));
            units += 1;
        }
        let tail = match tail_r {
            Some((a, b)) => Some(data.read(a, (b - a) as usize)?),
            None => None,
        };
        let key = FileKey::from_samples(len, bytes, tail.as_deref());
        drop(tail);
        drop(head);
        let settings = ParserSettings::new()
            .validate_checksums(opts.validate_checksums)
            .num_threads(1);
        Ok(EvtxSource {
            path,
            key,
            data,
            units,
            settings: Arc::new(settings),
            validate: opts.validate_checksums,
            slow: opts.slow_decoder,
            warnings,
        })
    }

    fn chunk_bytes(&self, unit: usize) -> std::io::Result<Cow<'_, [u8]>> {
        self.data
            .read((FILE_HEADER_SIZE + unit * CHUNK_SIZE) as u64, CHUNK_SIZE)
    }

    fn parse_chunk(&self, unit: usize, sink: &mut dyn Sink, rep: &mut UnitReport) {
        let mut buf = CHUNK_BUF.take();
        let off = (FILE_HEADER_SIZE + unit * CHUNK_SIZE) as u64;
        match self.data.read_into(off, CHUNK_SIZE, &mut buf) {
            Ok(raw) => self.parse_raw(unit, raw, sink, rep),
            Err(e) => {
                rep.bad_unit = true;
                rep.note(|| format!("chunk {unit}: read error: {e}"));
            }
        }
        CHUNK_BUF.set(buf);
    }

    fn parse_raw(&self, unit: usize, raw: &[u8], sink: &mut dyn Sink, rep: &mut UnitReport) {
        if raw.iter().all(|&b| b == 0) {
            return; // preallocated, never written
        }
        let partial = raw.len() < CHUNK_SIZE;
        if !self.slow && !partial {
            let checked = !self.validate
                || EvtxChunkData::new(raw.to_vec(), true).is_ok_and(|c| c.validate_checksum());
            if checked {
                let done = PLANS.with(|c| {
                    let mut cache = c.borrow_mut();
                    fast::decode_chunk(raw, self.key, &mut cache, sink, &mut rep.records)
                });
                if done {
                    rep.fast = true;
                    return;
                }
            }
        }
        let mut buf = Vec::with_capacity(CHUNK_SIZE);
        buf.extend_from_slice(raw);
        buf.resize(CHUNK_SIZE, 0);
        // A truncated chunk can never pass its checksum, but the records
        // before the cut are intact.
        let validate = self.validate && !partial;
        let mut chunk = match EvtxChunkData::new(buf, validate) {
            Ok(c) => c,
            Err(e) => {
                rep.bad_unit = true;
                rep.note(|| format!("chunk {unit}: {e}"));
                return;
            }
        };
        // A damaged string table makes the whole chunk unparseable, but names
        // can still be resolved by offset: retry with the table index cleared.
        if chunk.parse(Arc::clone(&self.settings)).is_err() {
            let mut retry = Vec::with_capacity(CHUNK_SIZE);
            retry.extend_from_slice(raw);
            retry.resize(CHUNK_SIZE, 0);
            retry[128..384].fill(0);
            if let Ok(mut c) = EvtxChunkData::new(retry, false)
                && c.parse(Arc::clone(&self.settings)).is_ok()
            {
                rep.bad_unit = true;
                rep.note(|| {
                    format!("chunk {unit}: damaged string table, recovered records by offset")
                });
                chunk = c;
            }
        }
        let mut parsed = match chunk.parse(Arc::clone(&self.settings)) {
            Ok(p) => p,
            Err(e) => {
                rep.bad_unit = true;
                rep.note(|| format!("chunk {unit}: {e}"));
                return;
            }
        };
        let mut spare: Vec<crate::event::Field<'static>> = Vec::new();
        for rec in parsed.iter() {
            let rec = match rec {
                Ok(r) => r,
                Err(e) => {
                    rep.bad_records += 1;
                    rep.note(|| format!("chunk {unit}: {e}"));
                    if partial {
                        break;
                    }
                    continue;
                }
            };
            let record_id = rec.event_record_id;
            // In a truncated chunk, anything reaching past the real data was
            // decoded from the zero padding.
            if partial && rec.binxml_offset as usize + rec.binxml_size as usize + 4 > raw.len() {
                rep.bad_records += 1;
                rep.note(|| format!("chunk {unit}: record {record_id} cut by truncation"));
                break;
            }
            if !sink.want_time(Ts::from_jiff(rec.timestamp)) {
                rep.records += 1;
                continue;
            }
            let header_ts = Ts::from_jiff(rec.timestamp);
            let json = match rec.into_json_bytes() {
                Ok(j) => j.data,
                Err(e) => {
                    rep.bad_records += 1;
                    rep.note(|| format!("chunk {unit} record {record_id}: {e}"));
                    continue;
                }
            };
            // Reuse the field vector's allocation across records. The
            // borrow of `json` ends with this iteration, so the vector is
            // emptied and re-lifetimed before the next one.
            let mut view = EventView {
                fields: recycle(std::mem::take(&mut spare)),
                ..EventView::default()
            };
            view.id = EventRef {
                file: self.key,
                record: record_id,
            };
            view.ts = header_ts;
            match decode::decode(&json, &mut view) {
                Ok(()) => {
                    rep.records += 1;
                    sink.event(&view);
                }
                Err(e) => {
                    rep.bad_records += 1;
                    rep.note(|| format!("chunk {unit} record {record_id}: undecodable JSON: {e}"));
                }
            }
            spare = recycle(view.fields);
        }
    }
}

/// Empties a vector and gives it a new element lifetime. The in-place
/// `collect` specialisation keeps the allocation (same layout), so the field
/// buffer is allocated once per chunk instead of once per record.
fn recycle<'b>(mut v: Vec<crate::event::Field<'_>>) -> Vec<crate::event::Field<'b>> {
    v.clear();
    v.into_iter().map(|_| unreachable!()).collect()
}

impl Source for EvtxSource {
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
    fn unit_record_range(&self, unit: usize) -> Option<(u64, u64)> {
        let raw = self
            .data
            .read((FILE_HEADER_SIZE + unit * CHUNK_SIZE) as u64, 512)
            .ok()?;
        if raw.len() < 512 || !raw.starts_with(CHUNK_MAGIC) {
            return None;
        }
        EvtxChunkHeader::from_bytes(&raw)
            .ok()
            .map(|h| (h.first_event_record_id, h.last_event_record_id))
    }
    fn raw_record(&self, unit: usize, record: u64) -> Option<anyhow::Result<String>> {
        let raw = match self.chunk_bytes(unit) {
            Ok(r) => r,
            Err(e) => return Some(Err(e.into())),
        };
        let mut buf = raw.to_vec();
        buf.resize(CHUNK_SIZE, 0);
        let res = catch_unwind(AssertUnwindSafe(|| -> Option<anyhow::Result<String>> {
            let mut chunk = EvtxChunkData::new(buf, false).ok()?;
            let mut parsed = chunk.parse(Arc::clone(&self.settings)).ok()?;
            for rec in parsed.iter().flatten() {
                if rec.event_record_id == record {
                    return Some(rec.into_xml().map(|r| r.data).map_err(anyhow::Error::from));
                }
            }
            None
        }));
        res.unwrap_or_else(|_| Some(Err(anyhow::anyhow!("decoder panicked on chunk {unit}"))))
    }

    fn parse_unit(&self, unit: usize, sink: &mut dyn Sink) -> UnitReport {
        let mut rep = UnitReport::default();
        let res = catch_unwind(AssertUnwindSafe(|| self.parse_chunk(unit, sink, &mut rep)));
        if let Err(p) = res {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".into());
            rep.bad_unit = true;
            rep.note(|| format!("chunk {unit}: decoder panicked: {msg}"));
        }
        rep
    }
}
