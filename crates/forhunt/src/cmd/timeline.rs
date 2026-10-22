//! `timeline`: events from all inputs merged in time order.
//!
//! With a cap (the `llm` default) only the earliest N events are kept, in a
//! bounded heap. Without a cap, events are sorted in memory up to
//! `--mem-budget` and spilled to sorted runs in temporary files beyond it,
//! then k-way merged: memory stays bounded whatever the input size.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io::{BufReader, BufWriter, Read, Write};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use forhunt_core::artifact::{Sink, UnitReport};
use forhunt_core::engine::Engine;
use forhunt_core::{EventView, Filter, Ts};
use forhunt_output::Writer;

use crate::cli::{OutFormat, TimelineArgs};
use crate::common::{self, Ctx, Totals};
use crate::facets::{Facets, SummaryInput, write_summary};

/// Sort key: time, then file key, record id and input index (all unique
/// together), so the order is total and reproducible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    ts: i64,
    file: u32,
    rid: u64,
    src: u32,
}

const KEY_BYTES: usize = 8 + 4 + 8 + 4;

impl Key {
    fn write(&self, w: &mut impl Write, len: u32) -> std::io::Result<()> {
        w.write_all(&self.ts.to_le_bytes())?;
        w.write_all(&self.file.to_le_bytes())?;
        w.write_all(&self.rid.to_le_bytes())?;
        w.write_all(&self.src.to_le_bytes())?;
        w.write_all(&len.to_le_bytes())
    }

    fn read(r: &mut impl Read) -> std::io::Result<Option<(Key, u32)>> {
        let mut b = [0u8; KEY_BYTES + 4];
        match r.read_exact(&mut b) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let k = Key {
            ts: i64::from_le_bytes(b[0..8].try_into().unwrap()),
            file: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            rid: u64::from_le_bytes(b[12..20].try_into().unwrap()),
            src: u32::from_le_bytes(b[20..24].try_into().unwrap()),
        };
        Ok(Some((k, u32::from_le_bytes(b[24..28].try_into().unwrap()))))
    }
}

struct UnitOut {
    buf: Vec<u8>,
    items: Vec<(Key, u32, u32)>,
    facets: Option<Facets>,
    rep: UnitReport,
}

struct UnitSink<'a> {
    filter: &'a Filter,
    writer: &'a Writer<'a>,
    src: u32,
    out: &'a mut UnitOut,
}

impl Sink for UnitSink<'_> {
    fn want_time(&mut self, t: Ts) -> bool {
        self.filter.want_header_time(t)
    }
    fn event(&mut self, ev: &EventView<'_>) {
        if !self.filter.matches(ev) {
            return;
        }
        if let Some(f) = &mut self.out.facets {
            f.add(ev);
        }
        let start = self.out.buf.len();
        self.writer.write(ev, &mut self.out.buf);
        let key = Key {
            ts: ev.ts.0,
            file: ev.id.file.0,
            rid: ev.id.record,
            src: self.src,
        };
        self.out
            .items
            .push((key, start as u32, (self.out.buf.len() - start) as u32));
    }
}

/// Collects lines and produces them in key order.
enum Collector {
    TopN {
        limit: usize,
        heap: BinaryHeap<(Key, Vec<u8>)>,
    },
    Sort {
        budget: usize,
        buf: Vec<u8>,
        idx: Vec<(Key, u32, u32)>,
        runs: Vec<tempfile::NamedTempFile>,
    },
}

impl Collector {
    fn push(&mut self, key: Key, line: &[u8]) -> anyhow::Result<()> {
        match self {
            Collector::TopN { limit, heap } => {
                if heap.len() < *limit {
                    heap.push((key, line.to_vec()));
                } else if let Some(top) = heap.peek()
                    && key < top.0
                {
                    heap.pop();
                    heap.push((key, line.to_vec()));
                }
            }
            Collector::Sort {
                budget,
                buf,
                idx,
                runs,
            } => {
                // Spill before a Vec would double past the budget (capacity,
                // not length, is what the process holds).
                let item = std::mem::size_of::<(Key, u32, u32)>();
                let grow_buf = buf.len() + line.len() > buf.capacity();
                let grow_idx = idx.len() == idx.capacity();
                let buf_cap = if grow_buf {
                    (buf.capacity() * 2).max(buf.len() + line.len())
                } else {
                    buf.capacity()
                };
                let idx_cap = if grow_idx { idx.capacity().max(4) * 2 } else { idx.capacity() };
                let too_big = buf_cap + idx_cap * item > *budget || buf_cap > (u32::MAX as usize) / 2;
                if (grow_buf || grow_idx) && too_big && !idx.is_empty() {
                    runs.push(spill(buf, idx)?);
                }
                idx.push((key, buf.len() as u32, line.len() as u32));
                buf.extend_from_slice(line);
            }
        }
        Ok(())
    }

    /// Writes everything in order; returns the number of lines written.
    fn finish(self, out: &mut dyn Write) -> anyhow::Result<u64> {
        match self {
            Collector::TopN { heap, .. } => {
                let v = heap.into_sorted_vec();
                for (_, line) in &v {
                    if !common::write_out(out, line)? {
                        break;
                    }
                }
                Ok(v.len() as u64)
            }
            Collector::Sort {
                mut buf,
                mut idx,
                mut runs,
                ..
            } => {
                if runs.is_empty() {
                    idx.sort_unstable_by_key(|x| x.0);
                    for (_, off, len) in &idx {
                        if !common::write_out(out, &buf[*off as usize..(*off + *len) as usize])? {
                            break;
                        }
                    }
                    return Ok(idx.len() as u64);
                }
                if !idx.is_empty() {
                    runs.push(spill(&mut buf, &mut idx)?);
                }
                merge(runs, out)
            }
        }
    }
}

fn spill(
    buf: &mut Vec<u8>,
    idx: &mut Vec<(Key, u32, u32)>,
) -> anyhow::Result<tempfile::NamedTempFile> {
    idx.sort_unstable_by_key(|x| x.0);
    let f = tempfile::NamedTempFile::new()?;
    {
        let mut w = BufWriter::with_capacity(1 << 20, f.as_file());
        for (k, off, len) in idx.iter() {
            k.write(&mut w, *len)?;
            w.write_all(&buf[*off as usize..(*off + *len) as usize])?;
        }
        w.flush()?;
    }
    buf.clear();
    idx.clear();
    Ok(f)
}

fn merge(runs: Vec<tempfile::NamedTempFile>, out: &mut dyn Write) -> anyhow::Result<u64> {
    let mut readers = Vec::with_capacity(runs.len());
    for r in &runs {
        let mut f = r.reopen()?;
        use std::io::Seek;
        f.seek(std::io::SeekFrom::Start(0))?;
        readers.push(BufReader::with_capacity(256 * 1024, f));
    }
    let mut heap = BinaryHeap::new();
    let mut lines: Vec<Vec<u8>> = vec![Vec::new(); readers.len()];
    for (i, r) in readers.iter_mut().enumerate() {
        if let Some((k, len)) = Key::read(r)? {
            lines[i].resize(len as usize, 0);
            r.read_exact(&mut lines[i])?;
            heap.push(Reverse((k, i)));
        }
    }
    let mut n = 0u64;
    while let Some(Reverse((_, i))) = heap.pop() {
        if !common::write_out(out, &lines[i])? {
            break;
        }
        n += 1;
        if let Some((k, len)) = Key::read(&mut readers[i])? {
            lines[i].resize(len as usize, 0);
            readers[i].read_exact(&mut lines[i])?;
            heap.push(Reverse((k, i)));
        }
    }
    Ok(n)
}

pub fn run(a: TimelineArgs) -> anyhow::Result<()> {
    let ctx = Ctx::new(&a.common)?;
    let filter = ctx.filter(&a.filter)?;
    let started = Instant::now();
    let inputs = ctx.open(&a.paths)?;
    let writer = ctx.writer(a.format, &a.out);
    let llm = a.format == OutFormat::Llm;
    let limit = match a.limit {
        Some(0) => None,
        Some(n) => Some(n),
        None if llm => Some(200),
        None => None,
    };
    let progress = common::Progress::new(ctx.progress, inputs.bytes);
    let mut collector = match limit {
        Some(l) => Collector::TopN {
            limit: l,
            heap: BinaryHeap::with_capacity(l.min(1 << 20) + 1),
        },
        None => Collector::Sort {
            budget: a.mem_budget.max(16) << 20,
            buf: Vec::new(),
            idx: Vec::new(),
            runs: Vec::new(),
        },
    };
    let mut totals = Totals::default();
    let mut facets = Facets::default();
    let mut err = None;
    let stop = AtomicBool::new(false);
    let strict = ctx.common.strict;
    Engine::new(&ctx.pool).run(
        &inputs.sources,
        &stop,
        |u, src| {
            let mut uo = UnitOut {
                buf: Vec::new(),
                items: Vec::new(),
                facets: llm.then(Facets::default),
                rep: UnitReport::default(),
            };
            let rep = {
                let mut sink = UnitSink {
                    filter: &filter,
                    writer: &writer,
                    src: u.source as u32,
                    out: &mut uo,
                };
                src.parse_unit(u.unit, &mut sink)
            };
            uo.rep = rep;
            progress.add(common::unit_bytes(src), uo.rep.records);
            uo
        },
        |u, uo| {
            totals.add(inputs.sources[u.source].path(), &uo.rep);
            totals.matched += uo.items.len() as u64;
            if strict && (uo.rep.bad_unit || uo.rep.bad_records > 0) {
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            if let Some(f) = uo.facets {
                facets.merge(f);
            }
            if err.is_some() {
                return;
            }
            for (k, off, len) in &uo.items {
                if let Err(e) = collector.push(*k, &uo.buf[*off as usize..(*off + *len) as usize]) {
                    err = Some(e);
                    return;
                }
            }
        },
    );
    progress.clear();
    if let Some(e) = err {
        return Err(e);
    }
    let mut out = common::output(&a.out.output)?;
    let _ = common::write_out(&mut *out, writer.header())?;
    let shown = collector.finish(&mut *out)?;
    if llm {
        let mut line = Vec::new();
        write_summary(
            &SummaryInput {
                kind: "timeline",
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
    totals.finish(&ctx, &inputs, started, "in timeline")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(ts: i64, rid: u64) -> Key {
        Key {
            ts,
            file: 1,
            rid,
            src: 0,
        }
    }

    #[test]
    fn spill_and_merge_match_in_memory_sort() {
        // Tiny budget forces many runs.
        let mut c = Collector::Sort {
            budget: 64,
            buf: Vec::new(),
            idx: Vec::new(),
            runs: Vec::new(),
        };
        let mut want = Vec::new();
        for i in 0..500u64 {
            let ts = ((i * 7919) % 101) as i64;
            let line = format!("{ts}:{i}\n");
            c.push(k(ts, i), line.as_bytes()).unwrap();
            want.push((k(ts, i), line));
        }
        if let Collector::Sort { runs, .. } = &c {
            assert!(runs.len() > 10);
        }
        want.sort_by_key(|x| x.0);
        let mut out = Vec::new();
        assert_eq!(c.finish(&mut out).unwrap(), 500);
        let want: String = want.into_iter().map(|x| x.1).collect();
        assert_eq!(String::from_utf8(out).unwrap(), want);
    }

    #[test]
    fn top_n_keeps_earliest() {
        let mut c = Collector::TopN {
            limit: 3,
            heap: BinaryHeap::new(),
        };
        for (ts, rid) in [(5, 1), (1, 2), (9, 3), (2, 4), (1, 5)] {
            c.push(k(ts, rid), format!("{ts}.{rid}\n").as_bytes())
                .unwrap();
        }
        let mut out = Vec::new();
        c.finish(&mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "1.2\n1.5\n2.4\n");
    }
}
