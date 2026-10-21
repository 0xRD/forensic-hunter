//! The extension point for artifact types (EVTX today; MFT, registry,
//! prefetch, LNK, jump lists, shellbags, amcache later).
//!
//! An [`Artifact`] recognises a file and opens it as a [`Source`]. A source is
//! split into independent *units* that the engine parses in parallel and
//! whose output it reassembles in unit order, so every artifact gets
//! parallelism and deterministic output for free.

use std::path::Path;
use std::sync::Arc;

use crate::event::EventView;
use crate::id::FileKey;

/// Outcome of parsing one unit.
#[derive(Debug, Default, Clone)]
pub struct UnitReport {
    pub records: u64,
    pub bad_records: u64,
    pub bad_unit: bool,
    /// Decoded on the fast path (diagnostics).
    pub fast: bool,
    /// First error messages, capped, for diagnostics.
    pub errors: Vec<String>,
}

impl UnitReport {
    pub const MAX_ERRORS: usize = 4;

    pub fn note(&mut self, msg: impl FnOnce() -> String) {
        if self.errors.len() < Self::MAX_ERRORS {
            self.errors.push(msg());
        }
    }

    pub fn merge(&mut self, o: &UnitReport) {
        self.records += o.records;
        self.bad_records += o.bad_records;
        for e in &o.errors {
            if self.errors.len() < Self::MAX_ERRORS {
                self.errors.push(e.clone());
            }
        }
    }
}

/// What a unit consumer wants to hear about. Returning `false` from
/// [`Sink::want_time`] lets the parser skip rendering a record entirely.
pub trait Sink {
    /// Called with the record header time before the record is decoded.
    fn want_time(&mut self, _header_ts: crate::Ts) -> bool {
        true
    }
    fn event(&mut self, ev: &EventView<'_>);
}

impl<F: FnMut(&EventView<'_>)> Sink for F {
    fn event(&mut self, ev: &EventView<'_>) {
        self(ev)
    }
}

/// Options shared by all parsers.
#[derive(Debug, Clone, Default)]
pub struct ParseOptions {
    /// Verify chunk and record checksums; a mismatch makes the unit bad.
    pub validate_checksums: bool,
    /// Force the JSON decoding path (differential testing, debugging).
    pub slow_decoder: bool,
}

pub trait Source: Send + Sync {
    fn key(&self) -> FileKey;
    fn path(&self) -> &Path;
    /// Number of independently parseable units.
    fn units(&self) -> usize;
    /// Byte size of the input, for throughput reporting.
    fn byte_len(&self) -> u64;
    /// Optional range of record ids in a unit, used by `show` to jump to the
    /// right unit without parsing the others.
    fn unit_record_range(&self, _unit: usize) -> Option<(u64, u64)> {
        None
    }
    fn parse_unit(&self, unit: usize, sink: &mut dyn Sink) -> UnitReport;
    /// The record in its native textual form (XML for EVTX), if supported.
    fn raw_record(&self, _unit: usize, _record: u64) -> Option<anyhow::Result<String>> {
        None
    }
    /// Problems found while opening (truncated tail, bad file header, ...).
    fn open_warnings(&self) -> &[String] {
        &[]
    }
}

pub trait Artifact: Send + Sync {
    fn name(&self) -> &'static str;
    /// True if `head` (the first bytes of a file) looks like this artifact.
    fn sniff(&self, head: &[u8]) -> bool;
    /// True if the file name alone suggests this artifact (used when walking
    /// directories, before opening anything).
    fn matches_name(&self, path: &Path) -> bool;
    fn open(&self, path: &Path, opts: &ParseOptions) -> anyhow::Result<Arc<dyn Source>>;
}

/// All artifacts known to this build.
pub fn registry() -> Vec<Box<dyn Artifact>> {
    vec![Box::new(crate::evtx::EvtxArtifact)]
}
