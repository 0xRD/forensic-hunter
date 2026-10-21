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
use forhunt_core::normalize::FieldMap;
use forhunt_core::{Ts, input};
use rayon::prelude::*;

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
    pub fn open(&self, paths: &[String]) -> anyhow::Result<Inputs> {
        let arts = artifact::registry();
        let exp = input::expand(paths, &arts)?;
        for m in &exp.missing {
            self.warn(&format!("no input matched `{m}`"));
        }
        if exp.files.is_empty() {
            return Err(fail(exit::NO_INPUT, "no input files found"));
        }
        let opts = ParseOptions {
            validate_checksums: self.common.checksums,
        };
        let opened: Vec<_> = self.pool.install(|| {
            exp.files
                .par_iter()
                .map(|p| open_one(&arts, p, &opts))
                .collect()
        });
        let mut sources: Vec<Arc<dyn Source>> = Vec::new();
        let mut failed = 0usize;
        let mut seen = std::collections::HashMap::new();
        for (path, r) in exp.files.iter().zip(opened) {
            match r {
                Ok(s) => {
                    for w in s.open_warnings() {
                        self.warn(&format!("{}: {w}", path.display()));
                    }
                    if let Some(prev) = seen.insert(s.key(), path.clone()) {
                        self.warn(&format!(
                            "{}: same content as {} (key {}), skipped",
                            path.display(),
                            prev.display(),
                            s.key()
                        ));
                        seen.insert(s.key(), prev);
                        continue;
                    }
                    sources.push(s);
                }
                Err(e) => {
                    failed += 1;
                    self.warn(&format!("{e:#}"));
                }
            }
        }
        if sources.is_empty() {
            return Err(fail(exit::NO_INPUT, "no readable input files"));
        }
        let bytes = sources.iter().map(|s| s.byte_len()).sum();
        Ok(Inputs {
            sources,
            failed,
            bytes,
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
            },
            &self.map,
        )
    }
}

fn open_one(
    arts: &[Box<dyn artifact::Artifact>],
    p: &Path,
    opts: &ParseOptions,
) -> anyhow::Result<Arc<dyn Source>> {
    let mut head = [0u8; 8192];
    let n = {
        use std::io::Read;
        let mut f =
            std::fs::File::open(p).with_context(|| format!("{}: cannot open", p.display()))?;
        let mut n = 0;
        while n < head.len() {
            let r = f.read(&mut head[n..])?;
            if r == 0 {
                break;
            }
            n += r;
        }
        n
    };
    let art = arts
        .iter()
        .find(|a| a.sniff(&head[..n]))
        .or_else(|| arts.iter().find(|a| a.matches_name(p)))
        .ok_or_else(|| anyhow::anyhow!("{}: unrecognised artifact type", p.display()))?;
    art.open(p, opts)
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
    pub errors: Vec<String>,
}

impl Totals {
    pub fn add(&mut self, path: &Path, rep: &UnitReport) {
        self.records += rep.records;
        self.bad_records += rep.bad_records;
        if rep.bad_unit {
            self.bad_units += 1;
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
