//! `sigma`: Sigma / Hayabusa rules over the evidence, in one parallel pass,
//! with forhunt's own engine (no Hayabusa binary).
//!
//! Output is the `llm` form of `forhunt hayabusa` (same keys), so the skill
//! reads both the same way. Every detection names the rule's author: the
//! Detection Rule License 1.1 asks for it on messages based on matches.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use forhunt_core::artifact::{Sink, UnitReport};
use forhunt_core::engine::Engine;
use forhunt_core::sigma::{self, LoadOptions, RuleSet, level_name, level_rank};
use forhunt_core::{EventRef, EventView, Filter, Ts};
use forhunt_output::json;

use crate::cli::{FilterArgs, SigmaArgs, SigmaFormat};
use crate::common::{self, Ctx, Totals, exit, fail};
use crate::facets::top;

/// Rule folders when `--rules` is not given: `$FORHUNT_RULES` (a path
/// list), else `rules/` of the install prefix (next to `bin/forhunt`, or the
/// installer's default prefix).
pub fn default_rules() -> Vec<PathBuf> {
    if let Some(v) = std::env::var_os("FORHUNT_RULES") {
        return std::env::split_paths(&v)
            .filter(|p| !p.as_os_str().is_empty())
            .collect();
    }
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(prefix) = exe.parent().and_then(Path::parent)
    {
        cands.push(prefix.join("rules"));
    }
    if let Some(p) = std::env::var_os("FORHUNT_PREFIX") {
        cands.push(PathBuf::from(p).join("rules"));
    }
    if cfg!(windows) {
        if let Some(p) = std::env::var_os("LOCALAPPDATA") {
            cands.push(PathBuf::from(p).join("forensic-hunter").join("rules"));
        }
    } else if let Some(h) = std::env::var_os("HOME") {
        cands.push(PathBuf::from(h).join(".local/share/forensic-hunter/rules"));
    }
    cands.into_iter().filter(|p| p.is_dir()).take(1).collect()
}

struct Det {
    ts: Ts,
    level: u8,
    rule: u32,
    id: EventRef,
    rec: u64,
    computer: String,
    channel: String,
    eid: u32,
    /// Rendered `d` object (JSON) or, with `-F jsonl`, the full event line.
    body: Vec<u8>,
}

struct DetSink<'a> {
    set: &'a RuleSet,
    m: sigma::Matcher<'a>,
    window: &'a Filter,
    w: &'a forhunt_output::Writer<'a>,
    full: bool,
    max: usize,
    src: &'a str,
    hits: Vec<u32>,
    out: Vec<Det>,
}

impl Sink for DetSink<'_> {
    fn want_time(&mut self, t: Ts) -> bool {
        self.window.want_time(t)
    }

    fn want_event_id(&mut self, eid: u32) -> bool {
        self.set.wants_event_id(eid)
    }

    fn event(&mut self, ev: &EventView<'_>) {
        if !self.window.matches(ev) {
            return;
        }
        self.hits.clear();
        self.m.matches(ev, &mut self.hits);
        if self.hits.is_empty() {
            return;
        }
        let mut shared: Option<Vec<u8>> = None;
        for &r in &self.hits {
            let rule = &self.set.rules()[r as usize];
            let body = if self.full {
                shared
                    .get_or_insert_with(|| {
                        let mut b = Vec::new();
                        self.w.write(ev, self.src, &mut b);
                        while b.last() == Some(&b'\n') {
                            b.pop();
                        }
                        b
                    })
                    .clone()
            } else {
                let det = self.set.details(r, ev);
                if det.is_empty() {
                    shared
                        .get_or_insert_with(|| {
                            let mut b = Vec::new();
                            forhunt_output::llm::write_fields(self.w, ev, &mut b);
                            b
                        })
                        .clone()
                } else {
                    let mut b = vec![b'{'];
                    for (j, (k, v)) in det.iter().enumerate() {
                        if j > 0 {
                            b.push(b',');
                        }
                        json::str(&mut b, k);
                        b.push(b':');
                        forhunt_output::llm::trunc_str(&mut b, v, self.max);
                    }
                    b.push(b'}');
                    b
                }
            };
            self.out.push(Det {
                ts: ev.ts,
                level: rule.level,
                rule: r,
                id: ev.id,
                rec: match ev.event_record_id {
                    0 => ev.id.record,
                    n => n,
                },
                computer: ev.computer.to_string(),
                channel: ev.channel.to_string(),
                eid: ev.event_id,
                body,
            });
        }
    }
}

pub fn run(a: SigmaArgs) -> anyhow::Result<()> {
    let ctx = Ctx::new(&a.common)?;
    let started = Instant::now();
    let min = level_rank(&a.min_level);
    if min == 0 {
        return Err(fail(
            exit::USAGE,
            format!(
                "--min-level `{}`: use informational, low, medium, high or critical",
                a.min_level
            ),
        ));
    }
    let rules = if a.rules.is_empty() {
        default_rules()
    } else {
        a.rules.clone()
    };
    if rules.is_empty() {
        return Err(fail(
            exit::USAGE,
            "no rules: pass --rules DIR (a hayabusa-rules checkout or your own Sigma rules), set FORHUNT_RULES, \
             or install them with the skill installer (skill/scripts/install.sh)",
        ));
    }
    let opts = LoadOptions {
        min_level: min,
        noisy: a.noisy,
        deprecated: a.deprecated,
        ids: a.rule_id.clone(),
    };
    let t = Instant::now();
    let (set, rep) = sigma::load(&rules, &opts);
    if !a.common.quiet {
        let skipped: Vec<String> = rep
            .skipped
            .iter()
            .map(|(k, v)| format!("{v} {k}"))
            .collect();
        eprintln!(
            "forhunt: {} rules loaded from {} files in {:.2}s{}{}",
            set.len(),
            rep.files,
            t.elapsed().as_secs_f64(),
            if skipped.is_empty() {
                String::new()
            } else {
                format!("; skipped: {}", skipped.join(", "))
            },
            if rep.errors.is_empty() {
                String::new()
            } else {
                format!("; {} not loaded (errors below)", rep.errors.len())
            }
        );
        for (p, e) in rep.errors.iter().take(10) {
            ctx.warn(&format!("rule not loaded: {}: {e}", p.display()));
        }
        if rep.errors.len() > 10 {
            ctx.warn(&format!(
                "... and {} more rules not loaded",
                rep.errors.len() - 10
            ));
        }
    }
    if set.is_empty() {
        return Err(fail(
            exit::USAGE,
            "no rule to run (see the load summary above)",
        ));
    }
    if a.list_rules {
        let mut out = common::output(&a.output)?;
        let mut buf = Vec::new();
        for r in set.rules() {
            buf.extend_from_slice(b"{\"rid\":");
            json::str(&mut buf, &r.id);
            buf.extend_from_slice(b",\"rule\":");
            json::str(&mut buf, &r.title);
            buf.extend_from_slice(b",\"lvl\":");
            json::str(&mut buf, level_name(r.level));
            buf.extend_from_slice(b",\"auth\":");
            json::str(&mut buf, &r.author);
            buf.extend_from_slice(b",\"path\":");
            json::str(&mut buf, &r.path.to_string_lossy());
            buf.extend_from_slice(b"}\n");
        }
        common::write_out(&mut *out, &buf)?;
        return common::flush(&mut *out);
    }

    let window = ctx.filter(&FilterArgs {
        since: a.since.clone(),
        until: a.until.clone(),
        computer: a.computer.clone(),
        ..Default::default()
    })?;
    let inputs = ctx.open(&a.paths)?;
    {
        let files: Vec<&Path> = inputs.sources.iter().map(|s| s.path()).collect();
        common::guard_output(Path::new(&a.output), &a.paths, &files)?;
    }
    let full = a.format == SigmaFormat::Jsonl;
    let w = forhunt_output::Writer::new(
        if full {
            forhunt_output::Format::Jsonl
        } else {
            forhunt_output::Format::Llm
        },
        forhunt_output::WriteOptions {
            tz: ctx.tz.clone(),
            max_value_len: a.max_value_len,
            all_fields: false,
            only: Vec::new(),
        },
        &ctx.map,
    );
    let progress = common::Progress::new(ctx.progress, inputs.bytes);
    let mut dets: Vec<Det> = Vec::new();
    let mut totals = Totals::default();
    let stop = AtomicBool::new(false);
    Engine::new(&ctx.pool).run(
        &inputs.sources,
        &stop,
        |u, src| {
            let path = src.path().to_string_lossy();
            let mut sink = DetSink {
                set: &set,
                m: set.matcher(),
                window: &window,
                w: &w,
                full,
                max: a.max_value_len,
                src: &path,
                hits: Vec::new(),
                out: Vec::new(),
            };
            let rep: UnitReport = src.parse_unit(u.unit, &mut sink);
            progress.add(common::unit_bytes(src), rep.records);
            (sink.out, rep)
        },
        |u, (part, rep)| {
            totals.add(inputs.sources[u.source].path(), &rep);
            dets.extend(part);
        },
    );
    progress.clear();
    let rules = set.rules();
    // Deterministic: time, level (most severe first), rule title, event.
    dets.sort_by(|x, y| {
        x.ts.cmp(&y.ts)
            .then(y.level.cmp(&x.level))
            .then_with(|| {
                rules[x.rule as usize]
                    .title
                    .cmp(&rules[y.rule as usize].title)
            })
            .then(x.id.cmp(&y.id))
    });
    totals.matched = dets.len() as u64;

    let mut out = common::output(&a.output)?;
    let mut buf = Vec::new();
    let shown: Vec<usize> = if a.limit > 0 && dets.len() > a.limit && !a.group {
        // Keep the most severe detections, printed in time order.
        let mut idx: Vec<usize> = (0..dets.len()).collect();
        idx.sort_by(|&i, &j| dets[j].level.cmp(&dets[i].level).then(i.cmp(&j)));
        idx.truncate(a.limit);
        idx.sort_unstable();
        idx
    } else {
        (0..dets.len()).collect()
    };
    let write_ts = |buf: &mut Vec<u8>, t: Ts| match &ctx.tz {
        Some(tz) => t.write_in_tz(tz, buf),
        None => t.write_iso(buf),
    };
    if a.group {
        write_groups(&set, &dets, a.limit, &mut buf, &write_ts);
    } else {
        for &i in &shown {
            let d = &dets[i];
            let r = &rules[d.rule as usize];
            if full {
                buf.extend_from_slice(b"{\"rule\":");
                json::str(&mut buf, &r.title);
                buf.extend_from_slice(b",\"rid\":");
                json::str(&mut buf, &r.id);
                buf.extend_from_slice(b",\"lvl\":");
                json::str(&mut buf, level_name(d.level));
                buf.extend_from_slice(b",\"auth\":");
                json::str(&mut buf, &r.author);
                write_mitre(&mut buf, &r.mitre());
                buf.extend_from_slice(b",\"rule_path\":");
                json::str(&mut buf, &r.path.to_string_lossy());
                buf.extend_from_slice(b",\"event\":");
                buf.extend_from_slice(&d.body);
                buf.extend_from_slice(b"}\n");
                continue;
            }
            buf.extend_from_slice(b"{\"id\":\"");
            d.id.write(&mut buf);
            buf.extend_from_slice(b"\",\"t\":\"");
            write_ts(&mut buf, d.ts);
            buf.extend_from_slice(b"\",\"h\":");
            json::str(&mut buf, &d.computer);
            buf.extend_from_slice(b",\"ch\":");
            json::str(&mut buf, ctx.map.channel_alias(&d.channel));
            buf.extend_from_slice(b",\"eid\":");
            json::u64(&mut buf, d.eid as u64);
            buf.extend_from_slice(b",\"rec\":");
            json::u64(&mut buf, d.rec);
            buf.extend_from_slice(b",\"lvl\":");
            json::str(&mut buf, level_name(d.level));
            buf.extend_from_slice(b",\"rule\":");
            json::str(&mut buf, &r.title);
            buf.extend_from_slice(b",\"rid\":");
            json::str(&mut buf, &r.id);
            write_mitre(&mut buf, &r.mitre());
            buf.extend_from_slice(b",\"auth\":");
            json::str(&mut buf, &r.author);
            buf.extend_from_slice(b",\"d\":");
            buf.extend_from_slice(&d.body);
            buf.extend_from_slice(b"}\n");
        }
    }

    if !full {
        let mut levels: BTreeMap<u8, u64> = BTreeMap::new();
        let mut by_rule: HashMap<u32, u64> = HashMap::new();
        let mut hosts: HashMap<String, u64> = HashMap::new();
        for d in &dets {
            *levels.entry(d.level).or_default() += 1;
            *by_rule.entry(d.rule).or_default() += 1;
            *hosts.entry(d.computer.clone()).or_default() += 1;
        }
        buf.extend_from_slice(b"{\"summary\":{\"cmd\":\"sigma\",\"detections\":");
        json::u64(&mut buf, dets.len() as u64);
        buf.extend_from_slice(b",\"shown\":");
        json::u64(
            &mut buf,
            if a.group { dets.len() } else { shown.len() } as u64,
        );
        buf.extend_from_slice(b",\"rules\":");
        json::u64(&mut buf, set.len() as u64);
        buf.extend_from_slice(b",\"rules_hit\":");
        json::u64(&mut buf, by_rule.len() as u64);
        buf.extend_from_slice(b",\"rules_not_loaded\":");
        json::u64(&mut buf, rep.errors.len() as u64);
        buf.extend_from_slice(b",\"scanned\":");
        json::u64(&mut buf, totals.records);
        buf.extend_from_slice(b",\"levels\":{");
        for (j, (l, n)) in levels.iter().rev().enumerate() {
            if j > 0 {
                buf.push(b',');
            }
            json::str(&mut buf, level_name(*l));
            buf.push(b':');
            json::u64(&mut buf, *n);
        }
        buf.extend_from_slice(b"},\"top_rules\":[");
        let mut tr: Vec<(u32, u64)> = by_rule.into_iter().collect();
        tr.sort_by(|x, y| {
            let (rx, ry) = (&rules[x.0 as usize], &rules[y.0 as usize]);
            ry.level
                .cmp(&rx.level)
                .then(y.1.cmp(&x.1))
                .then_with(|| rx.title.cmp(&ry.title))
        });
        for (j, (r, n)) in tr.iter().take(15).enumerate() {
            if j > 0 {
                buf.push(b',');
            }
            let r = &rules[*r as usize];
            buf.push(b'[');
            json::str(&mut buf, &r.title);
            buf.push(b',');
            json::str(&mut buf, level_name(r.level));
            buf.push(b',');
            json::u64(&mut buf, *n);
            buf.push(b']');
        }
        buf.extend_from_slice(b"],\"top_hosts\":[");
        for (j, (h, n)) in top(hosts, 5).into_iter().enumerate() {
            if j > 0 {
                buf.push(b',');
            }
            buf.push(b'[');
            json::str(&mut buf, &h);
            buf.push(b',');
            json::u64(&mut buf, n);
            buf.push(b']');
        }
        buf.push(b']');
        if !a.group && dets.len() > shown.len() {
            buf.extend_from_slice(
                b",\"note\":\"capped: the most severe detections are shown; use -g, raise --min-level or --limit\"",
            );
        }
        buf.extend_from_slice(b",\"credit\":\"rule authors are in `auth` (Detection Rule License 1.1 for hayabusa-rules / SigmaHQ)\"}}\n");
    }
    common::write_out(&mut *out, &buf)?;
    common::flush(&mut *out)?;
    totals.finish(&ctx, &inputs, started, "detections")
}

fn write_mitre(buf: &mut Vec<u8>, m: &[String]) {
    if m.is_empty() {
        return;
    }
    buf.extend_from_slice(b",\"mitre\":[");
    for (j, x) in m.iter().enumerate() {
        if j > 0 {
            buf.push(b',');
        }
        json::str(buf, x);
    }
    buf.push(b']');
}

/// One line per (rule, host): count, first / last time, event ids and up
/// to 5 sample forhunt ids; most severe first, then by first occurrence.
fn write_groups(
    set: &RuleSet,
    dets: &[Det],
    limit: usize,
    buf: &mut Vec<u8>,
    write_ts: &dyn Fn(&mut Vec<u8>, Ts),
) {
    struct G<'d> {
        rule: u32,
        host: &'d str,
        n: u64,
        first: Ts,
        last: Ts,
        eids: Vec<u32>,
        ids: Vec<EventRef>,
    }
    let mut groups: Vec<G<'_>> = Vec::new();
    let mut index: HashMap<(u32, &str), usize> = HashMap::new();
    for d in dets {
        let gi = *index
            .entry((d.rule, d.computer.as_str()))
            .or_insert_with(|| {
                groups.push(G {
                    rule: d.rule,
                    host: &d.computer,
                    n: 0,
                    first: d.ts,
                    last: d.ts,
                    eids: Vec::new(),
                    ids: Vec::new(),
                });
                groups.len() - 1
            });
        let g = &mut groups[gi];
        g.n += 1;
        g.first = g.first.min(d.ts);
        g.last = g.last.max(d.ts);
        if !g.eids.contains(&d.eid) {
            g.eids.push(d.eid);
        }
        if g.ids.len() < 5 {
            g.ids.push(d.id);
        }
    }
    let rules = set.rules();
    groups.sort_by(|x, y| {
        let (rx, ry) = (&rules[x.rule as usize], &rules[y.rule as usize]);
        ry.level
            .cmp(&rx.level)
            .then(x.first.cmp(&y.first))
            .then_with(|| rx.title.cmp(&ry.title))
            .then_with(|| x.host.cmp(y.host))
    });
    let n = if limit == 0 {
        groups.len()
    } else {
        groups.len().min(limit)
    };
    for g in &groups[..n] {
        let r = &rules[g.rule as usize];
        buf.extend_from_slice(b"{\"rule\":");
        json::str(buf, &r.title);
        buf.extend_from_slice(b",\"rid\":");
        json::str(buf, &r.id);
        buf.extend_from_slice(b",\"lvl\":");
        json::str(buf, level_name(r.level));
        buf.extend_from_slice(b",\"h\":");
        json::str(buf, g.host);
        buf.extend_from_slice(b",\"n\":");
        json::u64(buf, g.n);
        buf.extend_from_slice(b",\"first\":\"");
        write_ts(buf, g.first);
        buf.extend_from_slice(b"\",\"last\":\"");
        write_ts(buf, g.last);
        buf.extend_from_slice(b"\",\"eid\":[");
        for (j, e) in g.eids.iter().enumerate() {
            if j > 0 {
                buf.push(b',');
            }
            json::u64(buf, *e as u64);
        }
        buf.push(b']');
        write_mitre(buf, &r.mitre());
        buf.extend_from_slice(b",\"auth\":");
        json::str(buf, &r.author);
        buf.extend_from_slice(b",\"ids\":[");
        for (j, id) in g.ids.iter().enumerate() {
            if j > 0 {
                buf.push(b',');
            }
            buf.push(b'"');
            id.write(buf);
            buf.push(b'"');
        }
        buf.extend_from_slice(b"]}\n");
    }
}
