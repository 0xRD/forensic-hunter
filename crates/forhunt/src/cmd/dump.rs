//! `parse` and `search`: stream matching events in input order, into one
//! output (default: every input concatenated) or one file per input file or
//! per host (`--output-dir`, `--split`).

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::Context;
use forhunt_core::artifact::{Sink, Source, UnitReport};
use forhunt_core::engine::Engine;
use forhunt_core::{EventView, Filter, Ts};
use forhunt_output::Writer;

use crate::cli::{OutFormat, OutputArgs, ParseArgs, SearchArgs, Split};
use crate::common::{self, Ctx, Totals};
use crate::facets::{Facets, SummaryInput, write_summary};

pub fn parse(a: ParseArgs) -> anyhow::Result<()> {
    let ctx = Ctx::new(&a.common)?;
    let filter = Filter::new().computers(a.computer);
    run(
        &ctx, &a.paths, filter, a.format, &a.out, None, false, "parse",
    )
}

pub fn search(a: SearchArgs) -> anyhow::Result<()> {
    let ctx = Ctx::new(&a.common)?;
    let filter = ctx.filter(&a.filter)?;
    let llm = a.format == OutFormat::Llm;
    if a.out.output_dir.is_some() && a.limit.is_some_and(|l| l > 0) {
        anyhow::bail!(
            "--limit applies to a single output; it cannot be combined with --output-dir"
        );
    }
    let limit = match a.limit {
        Some(0) => None,
        Some(n) => Some(n),
        // Split outputs are files on disk, not LLM context: no default cap.
        None if llm && a.out.output_dir.is_none() => Some(200),
        None => None,
    };
    run(
        &ctx, &a.paths, filter, a.format, &a.out, limit, llm, "search",
    )
}

/// Per-unit output: formatted events plus the end offset of each; in
/// per-host mode, one buffer per computer name.
struct UnitOut {
    buf: Vec<u8>,
    ends: Vec<u32>,
    hosts: Vec<(String, Vec<u8>)>,
    rep: UnitReport,
    facets: Option<Facets>,
    matched: u64,
}

struct UnitSink<'a> {
    filter: &'a Filter,
    writer: &'a Writer<'a>,
    source: &'a str,
    out: &'a mut UnitOut,
    format: bool,
    by_host: bool,
}

impl Sink for UnitSink<'_> {
    #[inline]
    fn want_time(&mut self, t: Ts) -> bool {
        self.filter.want_time(t)
    }
    fn want_event_id(&mut self, id: u32) -> bool {
        self.filter.want_event_id(id)
    }
    #[inline]
    fn event(&mut self, ev: &EventView<'_>) {
        if !self.filter.matches(ev) {
            return;
        }
        self.out.matched += 1;
        if let Some(f) = &mut self.out.facets {
            f.add(ev);
        }
        if !self.format {
            return;
        }
        if self.by_host {
            let hosts = &mut self.out.hosts;
            let i = match hosts
                .iter()
                .position(|(h, _)| h.eq_ignore_ascii_case(&ev.computer))
            {
                Some(i) => i,
                None => {
                    hosts.push((ev.computer.to_string(), Vec::with_capacity(64 * 1024)));
                    hosts.len() - 1
                }
            };
            self.writer.write(ev, self.source, &mut hosts[i].1);
        } else {
            self.writer.write(ev, self.source, &mut self.out.buf);
            self.out.ends.push(self.out.buf.len() as u32);
        }
    }
}

/// Keeps characters that are safe in file names on every platform.
fn sanitize(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let out = out.trim_matches('.').to_string();
    if out.is_empty() {
        "_unknown".into()
    } else {
        out
    }
}

/// Longest common directory of the inputs, to name per-file outputs by
/// their relative path (`host1/Security.evtx` -> `host1__Security.csv`).
fn common_dir(sources: &[std::sync::Arc<dyn Source>]) -> PathBuf {
    let mut it = sources
        .iter()
        .map(|s| s.path().parent().map(Path::to_path_buf).unwrap_or_default());
    let Some(mut base) = it.next() else {
        return PathBuf::new();
    };
    for p in it {
        while !p.starts_with(&base) {
            if !base.pop() {
                return PathBuf::new();
            }
        }
    }
    base
}

/// Output files of a split run. At most `MAX_OPEN` stay open; others are
/// reopened in append mode when needed (thousands of hosts are fine).
struct SplitOut {
    dir: PathBuf,
    ext: &'static str,
    header: &'static [u8],
    names: HashMap<String, PathBuf>,
    used: HashSet<String>,
    open: Vec<(String, BufWriter<File>)>,
    /// Files already in `dir` before this run (lowercase name -> name).
    before: HashMap<String, String>,
}

/// What a split run left in its directory.
#[derive(Debug, Default)]
struct SplitReport {
    files: usize,
    /// (short host name, FQDN file it was appended to).
    folded: Vec<(String, String)>,
    /// Files in the directory that this run did not write.
    stale: Vec<String>,
}

const MAX_OPEN: usize = 128;

impl SplitOut {
    fn new(dir: &Path, ext: &'static str, header: &'static [u8]) -> anyhow::Result<SplitOut> {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        let mut before = HashMap::new();
        for e in std::fs::read_dir(dir)
            .with_context(|| format!("cannot list {}", dir.display()))?
            .flatten()
        {
            if e.file_type().is_ok_and(|t| t.is_file()) {
                let n = e.file_name().to_string_lossy().into_owned();
                before.insert(n.to_lowercase(), n);
            }
        }
        Ok(SplitOut {
            dir: dir.to_path_buf(),
            ext,
            header,
            names: HashMap::new(),
            used: HashSet::new(),
            open: Vec::new(),
            before,
        })
    }

    fn write(&mut self, key: &str, name_hint: &str, data: &[u8]) -> anyhow::Result<()> {
        let pos = match self.open.iter().position(|(k, _)| k == key) {
            Some(p) => p,
            None => {
                let (path, fresh) = match self.names.get(key) {
                    Some(p) => (p.clone(), false),
                    None => {
                        let base = sanitize(name_hint);
                        let mut name = format!("{base}.{}", self.ext);
                        let mut n = 2;
                        while !self.used.insert(name.to_lowercase()) {
                            name = format!("{base}-{n}.{}", self.ext);
                            n += 1;
                        }
                        let p = self.dir.join(name);
                        self.names.insert(key.to_string(), p.clone());
                        (p, true)
                    }
                };
                if self.open.len() >= MAX_OPEN {
                    let (_, mut w) = self.open.remove(0);
                    w.flush()?;
                }
                let f = if fresh {
                    File::create(&path)
                } else {
                    std::fs::OpenOptions::new().append(true).open(&path)
                }
                .with_context(|| format!("cannot write {}", path.display()))?;
                let mut w = BufWriter::with_capacity(256 * 1024, f);
                if fresh {
                    w.write_all(self.header)?;
                }
                self.open.push((key.to_string(), w));
                self.open.len() - 1
            }
        };
        // Most recently used at the end.
        let entry = self.open.remove(pos);
        self.open.push(entry);
        let w = &mut self.open.last_mut().expect("just pushed").1;
        w.write_all(data)?;
        Ok(())
    }

    /// Flushes everything. With `fold_hosts` (keys are lowercase host
    /// names), a short name's file is appended to the file of the single
    /// FQDN extending it (as `stats` folds them) and removed.
    fn finish(mut self, fold_hosts: bool) -> anyhow::Result<SplitReport> {
        for (_, w) in &mut self.open {
            w.flush()?;
        }
        self.open.clear();
        let mut rep = SplitReport::default();
        if fold_hosts {
            let keys: Vec<String> = self.names.keys().cloned().collect();
            let lower: Vec<&str> = keys.iter().map(String::as_str).collect();
            for (short, fqdn) in common::short_name_targets(&lower) {
                let (from, to) = (self.names[short].clone(), self.names[fqdn].clone());
                let data = std::fs::read(&from)
                    .with_context(|| format!("cannot read {}", from.display()))?;
                let body = data.strip_prefix(self.header).unwrap_or(&data);
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&to)
                    .with_context(|| format!("cannot write {}", to.display()))?;
                f.write_all(body)?;
                std::fs::remove_file(&from)
                    .with_context(|| format!("cannot remove {}", from.display()))?;
                let short_name = from
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let to_name = to
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                rep.folded.push((short_name, to_name));
                self.names.remove(short);
            }
            rep.folded.sort();
        }
        let written: HashSet<String> = self
            .names
            .values()
            .filter_map(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_lowercase())
            .collect();
        rep.stale = self
            .before
            .iter()
            .filter(|(l, _)| !written.contains(*l))
            .map(|(_, n)| n.clone())
            .collect();
        rep.stale.sort();
        rep.files = self.names.len();
        Ok(rep)
    }
}

#[allow(clippy::too_many_arguments)]
fn run(
    ctx: &Ctx,
    paths: &[String],
    filter: Filter,
    format: OutFormat,
    out_args: &OutputArgs,
    limit: Option<usize>,
    summary: bool,
    kind: &str,
) -> anyhow::Result<()> {
    let started = Instant::now();
    let inputs = ctx.open(paths)?;
    let writer = ctx.writer(format, out_args);
    let by_host = out_args.output_dir.is_some() && out_args.split == Split::Host;
    let mut split = match &out_args.output_dir {
        Some(dir) => Some(SplitOut::new(dir, writer.extension(), writer.header())?),
        None => None,
    };
    let base = common_dir(&inputs.sources);
    // Single output: the file given with -o, or stdout (which also carries
    // the summary line in split mode).
    let mut out = common::output(if split.is_some() {
        "-"
    } else {
        &out_args.output
    })?;
    let progress = common::Progress::new(ctx.progress, inputs.bytes);
    let stop = AtomicBool::new(false);
    // Once the cap is reached, workers stop formatting (facets still count).
    let formatting_done = AtomicBool::new(false);
    let mut totals = Totals::default();
    let mut facets = Facets::default();
    let mut shown = 0u64;
    let mut pipe_open = if split.is_none() {
        common::write_out(&mut *out, writer.header())?
    } else {
        true
    };
    let mut io_err: Option<anyhow::Error> = None;
    let strict = ctx.common.strict;

    Engine::new(&ctx.pool).run(
        &inputs.sources,
        &stop,
        |u, src| {
            let reserve = if formatting_done.load(Ordering::Relaxed) || by_host {
                0
            } else {
                256 * 1024
            };
            let mut uo = UnitOut {
                buf: Vec::with_capacity(reserve),
                ends: Vec::new(),
                hosts: Vec::new(),
                rep: UnitReport::default(),
                facets: summary.then(Facets::default),
                matched: 0,
            };
            let fmt = !formatting_done.load(Ordering::Relaxed);
            let path = src.path().display().to_string();
            let rep = {
                let mut sink = UnitSink {
                    filter: &filter,
                    writer: &writer,
                    source: &path,
                    out: &mut uo,
                    format: fmt,
                    by_host,
                };
                src.parse_unit(u.unit, &mut sink)
            };
            uo.rep = rep;
            progress.add(common::unit_bytes(src), uo.rep.records);
            uo
        },
        |u, uo| {
            let src = &inputs.sources[u.source];
            totals.add(src.path(), &uo.rep);
            totals.matched += uo.matched;
            if let Some(f) = uo.facets {
                facets.merge(f);
            }
            if strict && (uo.rep.bad_unit || uo.rep.bad_records > 0) {
                stop.store(true, Ordering::Relaxed);
            }
            if !pipe_open || io_err.is_some() {
                return;
            }
            if let Some(sp) = &mut split {
                let r = if by_host {
                    uo.hosts
                        .iter()
                        .try_for_each(|(host, data)| sp.write(&host.to_lowercase(), host, data))
                } else if uo.ends.is_empty() {
                    Ok(())
                } else {
                    let rel = src.path().strip_prefix(&base).unwrap_or(src.path());
                    let hint = rel
                        .with_extension("")
                        .to_string_lossy()
                        .replace(['/', '\\'], "__");
                    sp.write(&src.key().to_string(), &hint, &uo.buf)
                };
                if let Err(e) = r {
                    io_err = Some(e);
                }
                return;
            }
            // Write the whole unit, or the part under the cap.
            let remaining = limit.map(|l| (l as u64).saturating_sub(shown));
            let take = match remaining {
                Some(r) => (r as usize).min(uo.ends.len()),
                None => uo.ends.len(),
            };
            if take > 0 {
                let end = uo.ends[take - 1] as usize;
                match common::write_out(&mut *out, &uo.buf[..end]) {
                    Ok(open) => pipe_open = open,
                    Err(e) => io_err = Some(e),
                }
                shown += take as u64;
            }
            if let Some(l) = limit
                && shown >= l as u64
            {
                formatting_done.store(true, Ordering::Relaxed);
                if !summary {
                    stop.store(true, Ordering::Relaxed);
                }
            }
            if !pipe_open {
                stop.store(true, Ordering::Relaxed);
            }
        },
    );
    progress.clear();
    if let Some(e) = io_err {
        return Err(e);
    }
    if let Some(sp) = split {
        let dir = sp.dir.clone();
        let rep = sp.finish(by_host)?;
        shown = totals.matched;
        if !ctx.common.quiet {
            eprintln!("forhunt: wrote {} files to {}", rep.files, dir.display());
        }
        for (short, file) in &rep.folded {
            ctx.warn(&format!(
                "events logged under the short host name {short} were appended at the end of \
                 {file} (same machine as its FQDN; out of time order there)"
            ));
        }
        if !rep.stale.is_empty() {
            let first: Vec<&str> = rep.stale.iter().take(5).map(String::as_str).collect();
            ctx.warn(&format!(
                "{} file(s) in {} were not written by this run (older output?): {}{}",
                rep.stale.len(),
                dir.display(),
                first.join(", "),
                if rep.stale.len() > 5 { ", ..." } else { "" }
            ));
        }
    }
    if summary && pipe_open {
        common::merge_host_aliases(&mut facets.host);
        let mut line = Vec::new();
        write_summary(
            &SummaryInput {
                kind,
                facets: &facets,
                shown,
                scanned: totals.records,
                files: inputs.sources.len(),
                bad_chunks: totals.bad_units,
                bad_records: totals.bad_records,
                filter: &filter,
                map: &ctx.map,
                limit,
            },
            &mut line,
        );
        common::write_out(&mut *out, &line)?;
    }
    common::flush(&mut *out)?;
    totals.finish(
        ctx,
        &inputs,
        started,
        if kind == "parse" {
            "written"
        } else {
            "matched"
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{SplitOut, sanitize};

    #[test]
    fn split_host_folds_a_short_name_into_its_fqdn() {
        let d = tempfile::tempdir().unwrap();
        let mut sp = SplitOut::new(d.path(), "csv", b"H\n").unwrap();
        sp.write("ad01.corp.local", "AD01.corp.local", b"a\n")
            .unwrap();
        sp.write("ad01", "AD01", b"b\n").unwrap();
        sp.write("pc01", "PC01", b"c\n").unwrap();
        let rep = sp.finish(true).unwrap();
        let read = |n: &str| std::fs::read_to_string(d.path().join(n)).unwrap();
        assert_eq!(read("AD01.corp.local.csv"), "H\na\nb\n");
        assert!(!d.path().join("AD01.csv").exists());
        assert_eq!(read("PC01.csv"), "H\nc\n");
        assert_eq!(
            rep.folded,
            [("AD01".to_string(), "AD01.corp.local.csv".to_string())]
        );
        assert_eq!(rep.files, 2);
    }

    #[test]
    fn split_reports_files_it_did_not_write() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("old-host.csv"), b"stale").unwrap();
        std::fs::write(d.path().join("PC01.csv"), b"replaced").unwrap();
        let mut sp = SplitOut::new(d.path(), "csv", b"H\n").unwrap();
        sp.write("pc01", "PC01", b"c\n").unwrap();
        let rep = sp.finish(false).unwrap();
        assert_eq!(rep.stale, ["old-host.csv"]);
    }

    #[test]
    fn file_names() {
        assert_eq!(sanitize("WS-07.contoso.local"), "WS-07.contoso.local");
        assert_eq!(
            sanitize("host1__Microsoft-Windows-Sysmon%4Operational"),
            "host1__Microsoft-Windows-Sysmon_4Operational"
        );
        assert_eq!(sanitize(""), "_unknown");
        assert_eq!(sanitize("../x"), "_x");
    }
}
