//! Plumbing shared by the commands: input discovery, the worker pool,
//! output sinks, progress and run totals.

use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use forhunt_core::artifact::{self, ParseOptions, Source, UnitReport};
use forhunt_core::filter::{FieldCond, Filter, RegexCond, parse_event_ids};
use forhunt_core::id::FileKey;
use forhunt_core::normalize::FieldMap;
use forhunt_core::{Ts, input};

use crate::cli::{Common, FilterArgs};

/// Exit codes (see `forhunt --help`).
pub mod exit {
    pub const ERROR: i32 = 1;
    pub const NO_INPUT: i32 = 3;
    pub const CORRUPT: i32 = 4;
}

#[derive(Debug)]
pub struct Fail {
    pub code: i32,
    pub msg: String,
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Fail {}

pub fn fail(code: i32, msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Fail {
        code,
        msg: msg.into(),
    })
}

pub struct Ctx {
    pub common: Common,
    pub pool: rayon::ThreadPool,
    pub map: FieldMap,
    pub tz: Option<jiff::tz::TimeZone>,
    pub progress: bool,
}

impl Ctx {
    pub fn new(common: &Common) -> anyhow::Result<Ctx> {
        let pool = forhunt_core::engine::build_pool(common.threads, num_cpus::get_physical())?;
        let mut map = FieldMap::default_map().clone();
        if let Some(p) = &common.map {
            let src = std::fs::read_to_string(p)
                .with_context(|| format!("cannot read map {}", p.display()))?;
            map.extend(&src)
                .with_context(|| format!("invalid map {}", p.display()))?;
        }
        let tz = match &common.tz {
            None => None,
            Some(name) if name.eq_ignore_ascii_case("utc") => None,
            Some(name) => Some(
                jiff::tz::TimeZone::get(name)
                    .with_context(|| format!("unknown time zone `{name}`"))?,
            ),
        };
        let progress = !common.no_progress && !common.quiet && io::stderr().is_terminal();
        Ok(Ctx {
            common: common.clone(),
            pool,
            map,
            tz,
            progress,
        })
    }

    /// Expands paths and opens every input in parallel. Unreadable or
    /// non-artifact files are reported and skipped; byte-identical inputs
    /// (same file key) are opened once.
    fn parse_options(&self) -> ParseOptions {
        ParseOptions {
            validate_checksums: self.common.checksums,
            slow_decoder: self.common.slow_decoder,
            key: None,
        }
    }

    /// Opens one file under an explicit key (full-content key fallback).
    pub fn open_keyed(&self, path: &Path, key: FileKey) -> anyhow::Result<Arc<dyn Source>> {
        let o = ParseOptions {
            key: Some(key),
            ..self.parse_options()
        };
        input::open_one(&artifact::registry(), path, &o)
    }

    pub fn open(&self, paths: &[String]) -> anyhow::Result<Inputs> {
        let o = input::open_all(paths, &self.parse_options(), &self.pool)?;
        for w in &o.warnings {
            self.warn(w);
        }
        if o.found == 0 {
            return Err(fail(exit::NO_INPUT, "no input files found"));
        }
        if o.sources.is_empty() {
            return Err(fail(exit::NO_INPUT, "no readable input files"));
        }
        Ok(Inputs {
            sources: o.sources,
            failed: o.failed,
            bytes: o.bytes,
        })
    }

    pub fn warn(&self, msg: &str) {
        if !self.common.quiet {
            let mut e = io::stderr().lock();
            let _ = writeln!(e, "forhunt: warning: {msg}");
        }
    }

    pub fn filter(&self, f: &FilterArgs) -> anyhow::Result<Filter> {
        let ts = |s: &Option<String>, what: &str| -> anyhow::Result<Option<Ts>> {
            match s {
                None => Ok(None),
                Some(s) => Ts::parse(s).map(Some).ok_or_else(|| {
                    anyhow::anyhow!(
                        "--{what} `{s}`: not a valid time (use ISO 8601, e.g. 2024-05-01T10:00:00Z)"
                    )
                }),
            }
        };
        Ok(Filter::new()
            .event_ids(parse_event_ids(&f.event_id)?)
            .channels(f.channel.clone())
            .computers(f.computer.clone())
            .time(ts(&f.since, "since")?, ts(&f.until, "until")?)
            .fields(
                f.field
                    .iter()
                    .map(|s| FieldCond::parse(s))
                    .collect::<anyhow::Result<_>>()?,
            )
            .regexes(
                f.regex
                    .iter()
                    .map(|s| RegexCond::parse(s))
                    .collect::<anyhow::Result<_>>()?,
            ))
    }

    pub fn writer(
        &self,
        format: crate::cli::OutFormat,
        out: &crate::cli::OutputArgs,
    ) -> forhunt_output::Writer<'_> {
        forhunt_output::Writer::new(
            format.into(),
            forhunt_output::WriteOptions {
                tz: self.tz.clone(),
                max_value_len: out.max_value_len,
                all_fields: out.all_fields,
                only: out.fields.clone(),
            },
            &self.map,
        )
    }
}

pub struct Inputs {
    pub sources: Vec<Arc<dyn Source>>,
    pub failed: usize,
    pub bytes: u64,
}

/// Totals over a run, updated from the consumer thread.
#[derive(Debug, Default)]
pub struct Totals {
    pub records: u64,
    pub bad_records: u64,
    pub bad_units: u64,
    pub matched: u64,
    pub fast_units: u64,
    pub units: u64,
    pub errors: Vec<String>,
}

impl Totals {
    pub fn add(&mut self, path: &Path, rep: &UnitReport) {
        self.records += rep.records;
        self.bad_records += rep.bad_records;
        if rep.bad_unit {
            self.bad_units += 1;
        }
        self.units += 1;
        if rep.fast {
            self.fast_units += 1;
        }
        for e in &rep.errors {
            if self.errors.len() < 20 {
                self.errors.push(format!("{}: {e}", path.display()));
            }
        }
    }

    pub fn corrupt(&self) -> bool {
        self.bad_records > 0 || self.bad_units > 0
    }

    /// Reports errors and the run summary on stderr; enforces `--strict`.
    pub fn finish(
        &self,
        ctx: &Ctx,
        inputs: &Inputs,
        started: Instant,
        what: &str,
    ) -> anyhow::Result<()> {
        if !ctx.common.quiet {
            let mut e = io::stderr().lock();
            for msg in &self.errors {
                let _ = writeln!(e, "forhunt: corrupt: {msg}");
            }
            let secs = started.elapsed().as_secs_f64().max(1e-9);
            let mb = inputs.bytes as f64 / (1024.0 * 1024.0);
            let _ = writeln!(
                e,
                "forhunt: {} files, {:.1} MiB, {} events, {} {what}, {} bad chunks, {} bad records, {:.2}s ({:.0} MiB/s, {:.0} events/s)",
                inputs.sources.len(),
                mb,
                self.records,
                self.matched,
                self.bad_units,
                self.bad_records,
                secs,
                mb / secs,
                self.records as f64 / secs
            );
            if std::env::var_os("FORHUNT_DEBUG").is_some() {
                let _ = writeln!(
                    e,
                    "forhunt: debug: {} of {} chunks on the fast path",
                    self.fast_units, self.units
                );
            }
        }
        if ctx.common.strict && self.corrupt() {
            return Err(fail(
                exit::CORRUPT,
                format!(
                    "--strict: {} bad chunks, {} bad records",
                    self.bad_units, self.bad_records
                ),
            ));
        }
        if inputs.failed > 0 && ctx.common.strict {
            return Err(fail(
                exit::CORRUPT,
                format!("--strict: {} unreadable input files", inputs.failed),
            ));
        }
        Ok(())
    }
}

/// Opens the output: a file or stdout, with a large buffer.
pub fn output(path: &str) -> anyhow::Result<Box<dyn Write>> {
    const BUF: usize = 1 << 20;
    if path == "-" {
        Ok(Box::new(io::BufWriter::with_capacity(
            BUF,
            io::stdout().lock(),
        )))
    } else {
        let f = std::fs::File::create(path).with_context(|| format!("cannot create {path}"))?;
        Ok(Box::new(io::BufWriter::with_capacity(BUF, f)))
    }
}

/// Writes all of `buf`, treating a closed pipe (`| head`) as a normal stop.
pub fn write_out(w: &mut dyn Write, buf: &[u8]) -> anyhow::Result<bool> {
    match w.write_all(buf) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub fn flush(w: &mut dyn Write) -> anyhow::Result<()> {
    match w.flush() {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(e.into()),
        _ => Ok(()),
    }
}

/// A throttled progress line on stderr, driven by bytes of input processed.
pub struct Progress {
    enabled: bool,
    total: u64,
    done: AtomicU64,
    started: Instant,
    last: std::sync::Mutex<Instant>,
}

impl Progress {
    pub fn new(enabled: bool, total: u64) -> Self {
        let now = Instant::now();
        Progress {
            enabled,
            total,
            done: AtomicU64::new(0),
            started: now,
            last: std::sync::Mutex::new(now),
        }
    }

    pub fn add(&self, bytes: u64, events: u64) {
        if !self.enabled {
            return;
        }
        let done = self.done.fetch_add(bytes, Ordering::Relaxed) + bytes;
        let mut last = self.last.lock().unwrap();
        if last.elapsed() < Duration::from_millis(250) {
            return;
        }
        *last = Instant::now();
        let secs = self.started.elapsed().as_secs_f64().max(1e-9);
        let pct = if self.total > 0 {
            done as f64 * 100.0 / self.total as f64
        } else {
            100.0
        };
        let _ = write!(
            io::stderr(),
            "\r\x1b[2Kforhunt: {:5.1}% {:>8.1} MiB  {:>6.0} MiB/s  {} events in last unit",
            pct,
            done as f64 / 1048576.0,
            done as f64 / 1048576.0 / secs,
            events
        );
    }

    pub fn clear(&self) {
        if self.enabled {
            let _ = write!(io::stderr(), "\r\x1b[2K");
        }
    }
}

/// Size of one unit, for progress accounting.
pub fn unit_bytes(src: &dyn Source) -> u64 {
    let u = src.units().max(1) as u64;
    src.byte_len() / u
}

/// Folds host-name variants into one entry: a short name (`AD01`) goes into
/// the single FQDN that extends it (`AD01.corp.local`), and names differing
/// only in case are merged. Windows writes both forms (Application events
/// often carry the NetBIOS name), and they are one machine.
pub fn merge_host_aliases(hosts: &mut std::collections::HashMap<String, u64>) {
    use std::collections::HashMap;
    // Linear: one lowercase key per name, then one lookup per short name.
    let mut by_lower: HashMap<String, Vec<String>> = HashMap::new();
    for n in hosts.keys() {
        by_lower
            .entry(n.to_lowercase())
            .or_default()
            .push(n.clone());
    }
    // Case variants: keep the greatest spelling.
    for names in by_lower.values_mut() {
        names.sort();
        let keep = names.pop().expect("non-empty");
        for n in names.drain(..) {
            if let Some(c) = hosts.remove(&n) {
                *hosts.entry(keep.clone()).or_default() += c;
            }
        }
        names.push(keep);
    }
    // Short names: into the FQDN that extends them, when unambiguous.
    let lower: Vec<&str> = by_lower.keys().map(String::as_str).collect();
    for (short, fqdn) in short_name_targets(&lower) {
        let (short, fqdn) = (by_lower[short][0].clone(), by_lower[fqdn][0].clone());
        if let Some(c) = hosts.remove(&short) {
            *hosts.entry(fqdn).or_default() += c;
        }
    }
}

/// For lowercase host names: each short name (no dot) paired with the
/// single FQDN whose first label it is (`ad01` -> `ad01.corp.local`); a
/// short name matching several FQDNs is left alone. Linear.
pub fn short_name_targets<'a>(lower: &[&'a str]) -> Vec<(&'a str, &'a str)> {
    use std::collections::HashMap;
    let mut fqdn_by_label: HashMap<&str, Vec<&str>> = HashMap::new();
    for n in lower {
        if let Some((label, _)) = n.split_once('.') {
            fqdn_by_label.entry(label).or_default().push(n);
        }
    }
    lower
        .iter()
        .filter(|n| !n.is_empty() && !n.contains('.'))
        .filter_map(|n| match fqdn_by_label.get(n).map(Vec::as_slice) {
            Some([fqdn]) => Some((*n, *fqdn)),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod host_tests {
    use super::merge_host_aliases;

    #[test]
    fn folds_short_names_into_fqdn() {
        let mut h: std::collections::HashMap<String, u64> = [
            ("AD01.corp.local".to_string(), 10),
            ("AD01".to_string(), 1),
            ("PC01.corp.local".to_string(), 5),
            ("WS9".to_string(), 2),
        ]
        .into();
        merge_host_aliases(&mut h);
        assert_eq!(h.len(), 3);
        assert_eq!(h["AD01.corp.local"], 11);
        assert_eq!(h["WS9"], 2);
        // Ambiguous short name (two domains): left alone.
        let mut h: std::collections::HashMap<String, u64> = [
            ("DC.a.local".to_string(), 1),
            ("DC.b.local".to_string(), 1),
            ("DC".to_string(), 1),
        ]
        .into();
        merge_host_aliases(&mut h);
        assert_eq!(h.len(), 3);
        // Case variants become one entry.
        let mut h: std::collections::HashMap<String, u64> =
            [("ws1.corp".to_string(), 1), ("WS1.corp".to_string(), 2)].into();
        merge_host_aliases(&mut h);
        assert_eq!(h.values().copied().collect::<Vec<_>>(), vec![3]);
        // Many hosts stay fast (linear).
        let mut h: std::collections::HashMap<String, u64> = (0..50_000)
            .map(|i| (format!("H{i}.corp.local"), 1))
            .collect();
        h.extend((0..50_000).map(|i| (format!("H{i}"), 1)));
        let t = std::time::Instant::now();
        merge_host_aliases(&mut h);
        assert_eq!(h.len(), 50_000);
        assert!(t.elapsed().as_secs() < 5);
    }
}
