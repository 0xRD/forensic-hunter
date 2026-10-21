//! EVTX artifact: memory-maps the file and exposes each 64 KiB chunk as an
//! independent parse unit.

pub mod decode;

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

enum Data {
    Mmap(memmap2::Mmap),
    Owned(Vec<u8>),
}

impl Data {
    fn bytes(&self) -> &[u8] {
        match self {
            Data::Mmap(m) => m,
            Data::Owned(v) => v,
        }
    }
}

pub struct EvtxSource {
    path: PathBuf,
    key: FileKey,
    data: Data,
    units: usize,
    settings: Arc<ParserSettings>,
    validate: bool,
    warnings: Vec<String>,
}

impl EvtxSource {
    pub fn open(path: &Path, opts: &ParseOptions) -> anyhow::Result<EvtxSource> {
        let file =
            std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let len = file.metadata()?.len();
        // Read-only private mapping: evidence is never written. Empty files
        // cannot be mapped on every platform, so they get an empty buffer.
        let data = if len == 0 {
            Data::Owned(Vec::new())
        } else {
            // SAFETY: the map is read-only. If another process truncates the
            // file while we read it, the OS may raise SIGBUS; evidence files
            // are expected to be stable copies (see SKILL.md step a).
            match unsafe { memmap2::Mmap::map(&file) } {
                Ok(m) => Data::Mmap(m),
                Err(_) => Data::Owned(std::fs::read(path)?),
            }
        };
        Self::from_data(path.to_path_buf(), data, opts)
    }

    pub fn from_bytes(
        path: PathBuf,
        bytes: Vec<u8>,
        opts: &ParseOptions,
    ) -> anyhow::Result<EvtxSource> {
        Self::from_data(path, Data::Owned(bytes), opts)
    }

    fn from_data(path: PathBuf, data: Data, opts: &ParseOptions) -> anyhow::Result<EvtxSource> {
        let bytes = data.bytes();
        let mut warnings = Vec::new();
        if bytes.len() < FILE_HEADER_SIZE {
            anyhow::bail!(
                "{}: too small to be an EVTX file ({} bytes)",
                path.display(),
                bytes.len()
            );
        }
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
        let body = bytes.len() - FILE_HEADER_SIZE;
        let mut units = body / CHUNK_SIZE;
        let tail = body % CHUNK_SIZE;
        if tail > 0 {
            warnings.push(format!("file truncated: last chunk has {tail} of {CHUNK_SIZE} bytes, recovering what parses"));
            units += 1;
        }
        let key = FileKey::fingerprint(bytes, FILE_HEADER_SIZE + CHUNK_SIZE);
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
            warnings,
        })
    }

    fn chunk_bytes(&self, unit: usize) -> &[u8] {
        let b = self.data.bytes();
        let start = FILE_HEADER_SIZE + unit * CHUNK_SIZE;
        &b[start..(start + CHUNK_SIZE).min(b.len())]
    }

    fn parse_chunk(&self, unit: usize, sink: &mut dyn Sink, rep: &mut UnitReport) {
        let raw = self.chunk_bytes(unit);
        if raw.iter().all(|&b| b == 0) {
            return; // preallocated, never written
        }
        let partial = raw.len() < CHUNK_SIZE;
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
        self.data.bytes().len() as u64
    }
    fn open_warnings(&self) -> &[String] {
        &self.warnings
    }
    fn unit_record_range(&self, unit: usize) -> Option<(u64, u64)> {
        let raw = self.chunk_bytes(unit);
        if raw.len() < 512 || !raw.starts_with(CHUNK_MAGIC) {
            return None;
        }
        EvtxChunkHeader::from_bytes(raw)
            .ok()
            .map(|h| (h.first_event_record_id, h.last_event_record_id))
    }
    fn raw_record(&self, unit: usize, record: u64) -> Option<anyhow::Result<String>> {
        let raw = self.chunk_bytes(unit);
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
