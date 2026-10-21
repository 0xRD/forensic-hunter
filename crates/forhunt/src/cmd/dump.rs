//! `parse` and `search`: stream matching events in input order.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use forhunt_core::artifact::{Sink, UnitReport};
use forhunt_core::engine::Engine;
use forhunt_core::{EventView, Filter, Ts};
use forhunt_output::Writer;

use crate::cli::{OutFormat, OutputArgs, ParseArgs, SearchArgs};
use crate::common::{self, Ctx, Totals};
use crate::facets::{Facets, SummaryInput, write_summary};

pub fn parse(a: ParseArgs) -> anyhow::Result<()> {
    let ctx = Ctx::new(&a.common)?;
    run(
        &ctx,
        &a.paths,
        Filter::new(),
        a.format,
        &a.out,
        None,
        false,
        "parse",
    )
}

pub fn search(a: SearchArgs) -> anyhow::Result<()> {
    let ctx = Ctx::new(&a.common)?;
    let filter = ctx.filter(&a.filter)?;
    let llm = a.format == OutFormat::Llm;
    let limit = match a.limit {
        Some(0) => None,
        Some(n) => Some(n),
        None if llm => Some(200),
        None => None,
    };
    run(
        &ctx, &a.paths, filter, a.format, &a.out, limit, llm, "search",
    )
}

/// Per-unit output: formatted events plus the end offset of each.
struct UnitOut {
    buf: Vec<u8>,
    ends: Vec<u32>,
    rep: UnitReport,
    facets: Option<Facets>,
    matched: u64,
}

struct UnitSink<'a> {
    filter: &'a Filter,
    writer: &'a Writer<'a>,
    out: &'a mut UnitOut,
    format: bool,
}

impl Sink for UnitSink<'_> {
    #[inline]
    fn want_time(&mut self, t: Ts) -> bool {
        self.filter.want_header_time(t)
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
        if self.format {
            self.writer.write(ev, &mut self.out.buf);
            self.out.ends.push(self.out.buf.len() as u32);
        }
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
    let mut out = common::output(&out_args.output)?;
    let progress = common::Progress::new(ctx.progress, inputs.bytes);
    let stop = AtomicBool::new(false);
    // Once the cap is reached, workers stop formatting (facets still count).
    let formatting_done = AtomicBool::new(false);
    let mut totals = Totals::default();
    let mut facets = Facets::default();
    let mut shown = 0u64;
    let mut pipe_open = common::write_out(&mut *out, writer.header())?;
    let mut io_err = None;
    let strict = ctx.common.strict;

    Engine::new(&ctx.pool).run(
        &inputs.sources,
        &stop,
        |u, src| {
            let mut uo = UnitOut {
                buf: Vec::with_capacity(if formatting_done.load(Ordering::Relaxed) {
                    0
                } else {
                    256 * 1024
                }),
                ends: Vec::new(),
                rep: UnitReport::default(),
                facets: summary.then(Facets::default),
                matched: 0,
            };
            let fmt = !formatting_done.load(Ordering::Relaxed);
            let rep = {
                let mut sink = UnitSink {
                    filter: &filter,
                    writer: &writer,
                    out: &mut uo,
                    format: fmt,
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
    if summary && pipe_open {
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
