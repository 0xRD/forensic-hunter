//! `stats`: a dense triage summary of what the logs contain.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use forhunt_core::artifact::{Sink, UnitReport};
use forhunt_core::engine::Engine;
use forhunt_core::{EventView, Filter, Ts};
use forhunt_output::json;
use serde::Serialize;

use crate::cli::{StatsArgs, StatsFormat};
use crate::common::{self, Ctx, Totals};
use crate::facets::top;

const ACCOUNT_FIELDS: &[&str] = &["TargetUserName", "User", "SubjectUserName", "AccountName"];
const IP_FIELDS: &[&str] = &[
    "IpAddress",
    "SourceIp",
    "SourceAddress",
    "ClientAddress",
    "Address",
];
/// Events that indicate log tampering or loss.
const LOG_EVENTS: &[(&str, u32)] = &[
    ("Security", 1102),
    ("System", 104),
    ("Security", 1100),
    ("Security", 4719),
];

#[derive(Default)]
struct Part {
    events: u64,
    chan_eid: HashMap<(String, u32), u64>,
    day: HashMap<i64, u64>,
    hour: [u64; 24],
    hosts: HashMap<String, u64>,
    accounts: HashMap<String, u64>,
    ips: HashMap<String, u64>,
    logons: HashMap<(u32, String), u64>,
    log_events: Vec<LogEvent>,
    minutes: Vec<i64>,
    first: Option<Ts>,
    last: Option<Ts>,
    rid_min: u64,
    rid_max: u64,
    rid_n: u64,
}

#[derive(Clone, Serialize)]
struct LogEvent {
    id: String,
    t: String,
    ch: String,
    eid: u32,
    user: String,
    #[serde(skip)]
    ts: Ts,
}

fn first_of(ev: &EventView<'_>, names: &[&str]) -> Option<String> {
    names.iter().find_map(|n| {
        ev.field(n)
            .filter(|v| !v.is_blank())
            .map(|v| v.as_str().to_string())
    })
}

struct PartSink<'a> {
    filter: &'a Filter,
    part: &'a mut Part,
}

impl Sink for PartSink<'_> {
    fn want_time(&mut self, t: Ts) -> bool {
        self.filter.want_header_time(t)
    }
    fn want_event_id(&mut self, id: u32) -> bool {
        self.filter.want_event_id(id)
    }
    fn event(&mut self, ev: &EventView<'_>) {
        if !self.filter.matches(ev) {
            return;
        }
        let p = &mut *self.part;
        p.events += 1;
        *p.chan_eid
            .entry((ev.channel.to_string(), ev.event_id))
            .or_default() += 1;
        let secs = ev.ts.secs();
        *p.day.entry(secs.div_euclid(86_400)).or_default() += 1;
        p.hour[secs.rem_euclid(86_400) as usize / 3600] += 1;
        if !ev.computer.is_empty() {
            *p.hosts.entry(ev.computer.to_string()).or_default() += 1;
        }
        if let Some(a) = first_of(ev, ACCOUNT_FIELDS) {
            *p.accounts.entry(a).or_default() += 1;
        }
        if let Some(ip) = first_of(ev, IP_FIELDS)
            && !matches!(ip.as_str(), "127.0.0.1" | "::1" | "-" | "localhost")
        {
            *p.ips.entry(ip).or_default() += 1;
        }
        if matches!(ev.event_id, 4624 | 4625)
            && ev.channel == "Security"
            && let Some(lt) = ev.field("LogonType")
        {
            *p.logons
                .entry((ev.event_id, lt.as_str().to_string()))
                .or_default() += 1;
        }
        if LOG_EVENTS
            .iter()
            .any(|(c, id)| *id == ev.event_id && ev.channel.eq_ignore_ascii_case(c))
        {
            p.log_events.push(LogEvent {
                id: ev.id.to_string(),
                t: ev.ts.iso(),
                ch: ev.channel.to_string(),
                eid: ev.event_id,
                user: first_of(ev, &["SubjectUserName", "TargetUserName"]).unwrap_or_default(),
                ts: ev.ts,
            });
        }
        let minute = secs.div_euclid(60);
        if p.minutes.last() != Some(&minute) {
            p.minutes.push(minute);
        }
        p.first = Some(p.first.map_or(ev.ts, |f| f.min(ev.ts)));
        p.last = Some(p.last.map_or(ev.ts, |l| l.max(ev.ts)));
        let rid = ev.id.record;
        if p.rid_n == 0 {
            p.rid_min = rid;
            p.rid_max = rid;
        } else {
            p.rid_min = p.rid_min.min(rid);
            p.rid_max = p.rid_max.max(rid);
        }
        p.rid_n += 1;
    }
}

#[derive(Default, Serialize)]
struct FileStats {
    key: String,
    path: String,
    events: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    first: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last: Option<String>,
    channels: Vec<String>,
    bad_chunks: u64,
    bad_records: u64,
    /// Ranges of record ids missing between chunks: [after, before).
    record_id_gaps: Vec<(u64, u64)>,
    #[serde(skip)]
    is_log: bool,
    #[serde(skip)]
    ranges: Vec<(u64, u64, u64)>,
    #[serde(skip)]
    minutes: Vec<i64>,
    #[serde(skip)]
    first_ts: Option<Ts>,
    #[serde(skip)]
    last_ts: Option<Ts>,
}

#[derive(Default)]
struct Agg {
    events: u64,
    chan_eid: HashMap<(String, u32), u64>,
    day: BTreeMap<i64, u64>,
    hour: [u64; 24],
    hosts: HashMap<String, u64>,
    accounts: HashMap<String, u64>,
    ips: HashMap<String, u64>,
    logons: BTreeMap<(u32, String), u64>,
    log_events: Vec<LogEvent>,
    files: Vec<FileStats>,
}

fn add_map(dst: &mut HashMap<String, u64>, src: HashMap<String, u64>) {
    for (k, v) in src {
        *dst.entry(k).or_default() += v;
    }
}

pub fn run(a: StatsArgs) -> anyhow::Result<()> {
    let ctx = Ctx::new(&a.common)?;
    let filter = ctx.filter(&a.filter)?;
    let started = Instant::now();
    let inputs = ctx.open(&a.paths)?;
    let progress = common::Progress::new(ctx.progress, inputs.bytes);
    let mut totals = Totals::default();
    let mut agg = Agg {
        files: inputs
            .sources
            .iter()
            .map(|s| FileStats {
                key: s.key().to_string(),
                path: s.path().display().to_string(),
                is_log: s.is_log(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let stop = AtomicBool::new(false);
    Engine::new(&ctx.pool).run(
        &inputs.sources,
        &stop,
        |u, src| {
            let mut part = Part::default();
            let rep: UnitReport = src.parse_unit(
                u.unit,
                &mut PartSink {
                    filter: &filter,
                    part: &mut part,
                },
            );
            progress.add(common::unit_bytes(src), rep.records);
            (part, rep)
        },
        |u, (part, rep)| {
            let src = &inputs.sources[u.source];
            totals.add(src.path(), &rep);
            totals.matched += part.events;
            let f = &mut agg.files[u.source];
            f.events += part.events;
            f.bad_records += rep.bad_records;
            if rep.bad_unit {
                f.bad_chunks += 1;
            }
            if part.rid_n > 0 {
                f.ranges.push((part.rid_min, part.rid_max, part.rid_n));
            }
            f.minutes.extend_from_slice(&part.minutes);
            f.first_ts = match (f.first_ts, part.first) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            f.last_ts = match (f.last_ts, part.last) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            for k in part.chan_eid.keys() {
                if !f.channels.contains(&k.0) {
                    f.channels.push(k.0.clone());
                }
            }
            agg.events += part.events;
            for (k, v) in part.chan_eid {
                *agg.chan_eid.entry(k).or_default() += v;
            }
            for (k, v) in part.day {
                *agg.day.entry(k).or_default() += v;
            }
            for (i, v) in part.hour.iter().enumerate() {
                agg.hour[i] += v;
            }
            add_map(&mut agg.hosts, part.hosts);
            add_map(&mut agg.accounts, part.accounts);
            add_map(&mut agg.ips, part.ips);
            for (k, v) in part.logons {
                *agg.logons.entry(k).or_default() += v;
            }
            agg.log_events.extend(part.log_events);
        },
    );
    progress.clear();

    // Per-file derived values.
    let gap_min = a.gap_minutes.max(1);
    let mut quiet: Vec<(i64, String, i64, i64)> = Vec::new();
    for f in &mut agg.files {
        f.first = f.first_ts.map(|t| t.iso());
        f.last = f.last_ts.map(|t| t.iso());
        f.channels.sort();
        if !f.is_log {
            continue;
        }
        f.ranges.sort();
        for w in f.ranges.windows(2) {
            let (prev_max, next_min) = (w[0].1, w[1].0);
            if next_min > prev_max + 1 {
                f.record_id_gaps.push((prev_max, next_min));
            }
        }
        f.minutes.sort_unstable();
        f.minutes.dedup();
        for w in f.minutes.windows(2) {
            let d = w[1] - w[0];
            if d > gap_min {
                quiet.push((d, f.key.clone(), w[0], w[1]));
            }
        }
    }
    quiet.sort_by(|x, y| {
        y.0.cmp(&x.0)
            .then_with(|| x.1.cmp(&y.1))
            .then(x.2.cmp(&y.2))
    });
    agg.log_events
        .sort_by(|x, y| x.ts.cmp(&y.ts).then_with(|| x.id.cmp(&y.id)));

    let mut out = common::output(&a.output)?;
    let mut buf = Vec::new();
    match a.format {
        StatsFormat::Llm => write_llm(&ctx, &agg, &quiet, a.top, &totals, &mut buf),
        StatsFormat::Json => write_json(&ctx, &agg, &quiet, &totals, &mut buf)?,
        StatsFormat::Csv => write_csv(&ctx, &agg, &quiet, &mut buf),
    }
    common::write_out(&mut *out, &buf)?;
    common::flush(&mut *out)?;
    totals.finish(&ctx, &inputs, started, "counted")
}

fn minute_iso(m: i64) -> String {
    Ts(m * 60 * 10_000_000).iso()[..16].to_string() + "Z"
}

fn day_iso(d: i64) -> String {
    Ts(d * 86_400 * 10_000_000).iso()[..10].to_string()
}

fn pairs<K: AsRef<str>>(out: &mut Vec<u8>, items: impl IntoIterator<Item = (K, u64)>) {
    out.push(b'[');
    for (i, (k, n)) in items.into_iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.push(b'[');
        forhunt_output::llm::trunc_str(out, k.as_ref(), 120);
        out.push(b',');
        json::u64(out, n);
        out.push(b']');
    }
    out.push(b']');
}

fn write_llm(
    ctx: &Ctx,
    agg: &Agg,
    quiet: &[(i64, String, i64, i64)],
    n: usize,
    totals: &Totals,
    out: &mut Vec<u8>,
) {
    let first = agg.files.iter().filter_map(|f| f.first_ts).min();
    let last = agg.files.iter().filter_map(|f| f.last_ts).max();
    out.extend_from_slice(b"{\"stats\":{\"files\":");
    json::u64(out, agg.files.len() as u64);
    out.extend_from_slice(b",\"events\":");
    json::u64(out, agg.events);
    if let (Some(a), Some(b)) = (first, last) {
        out.extend_from_slice(b",\"first\":\"");
        a.write_iso(out);
        out.extend_from_slice(b"\",\"last\":\"");
        b.write_iso(out);
        out.push(b'"');
    }
    out.extend_from_slice(b",\"hosts\":");
    json::u64(out, agg.hosts.len() as u64);
    out.extend_from_slice(b",\"bad_chunks\":");
    json::u64(out, totals.bad_units);
    out.extend_from_slice(b",\"bad_records\":");
    json::u64(out, totals.bad_records);
    out.extend_from_slice(b"}}\n");

    // Per file. Large collections: files with anomalies plus the biggest ones.
    const MAX_FILES: usize = 30;
    let mut shown: Vec<&FileStats> = agg.files.iter().collect();
    if shown.len() > MAX_FILES {
        shown.sort_by(|x, y| {
            let ax = x.bad_chunks + x.bad_records + x.record_id_gaps.len() as u64;
            let ay = y.bad_chunks + y.bad_records + y.record_id_gaps.len() as u64;
            (ay > 0)
                .cmp(&(ax > 0))
                .then(y.events.cmp(&x.events))
                .then_with(|| x.path.cmp(&y.path))
        });
        shown.truncate(MAX_FILES);
        shown.sort_by(|x, y| x.path.cmp(&y.path));
    }
    for f in &shown {
        out.extend_from_slice(b"{\"file\":");
        json::str(out, &f.key);
        out.extend_from_slice(b",\"path\":");
        json::str(out, &f.path);
        out.extend_from_slice(b",\"events\":");
        json::u64(out, f.events);
        if let (Some(a), Some(b)) = (&f.first, &f.last) {
            out.extend_from_slice(b",\"first\":");
            json::str(out, a);
            out.extend_from_slice(b",\"last\":");
            json::str(out, b);
        }
        out.extend_from_slice(b",\"ch\":[");
        for (i, c) in f.channels.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            json::str(out, ctx.map.channel_alias(c));
        }
        out.push(b']');
        if f.bad_chunks + f.bad_records > 0 {
            out.extend_from_slice(b",\"bad_chunks\":");
            json::u64(out, f.bad_chunks);
            out.extend_from_slice(b",\"bad_records\":");
            json::u64(out, f.bad_records);
        }
        if !f.record_id_gaps.is_empty() {
            out.extend_from_slice(b",\"rid_gaps\":[");
            for (i, (a, b)) in f.record_id_gaps.iter().take(10).enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.push(b'[');
                json::u64(out, *a);
                out.push(b',');
                json::u64(out, *b);
                out.push(b']');
            }
            out.push(b']');
        }
        out.extend_from_slice(b"}\n");
    }

    if agg.files.len() > shown.len() {
        out.extend_from_slice(b"{\"files_omitted\":");
        json::u64(out, (agg.files.len() - shown.len()) as u64);
        out.extend_from_slice(b",\"note\":\"files without anomalies and with fewer events are omitted; use --format json for all\"}\n");
    }

    // Coverage: every channel and event id present, with counts.
    let mut by_chan: BTreeMap<&str, Vec<(u32, u64)>> = BTreeMap::new();
    for ((c, id), v) in &agg.chan_eid {
        by_chan.entry(c.as_str()).or_default().push((*id, *v));
    }
    out.extend_from_slice(b"{\"present\":{");
    for (i, (c, ids)) in by_chan.iter_mut().enumerate() {
        ids.sort();
        if i > 0 {
            out.push(b',');
        }
        json::str(out, ctx.map.channel_alias(c));
        out.extend_from_slice(b":{");
        for (j, (id, v)) in ids.iter().enumerate() {
            if j > 0 {
                out.push(b',');
            }
            out.push(b'"');
            json::u64(out, *id as u64);
            out.extend_from_slice(b"\":");
            json::u64(out, *v);
        }
        out.push(b'}');
    }
    out.extend_from_slice(b"}}\n");

    // Volumes over time.
    out.extend_from_slice(b"{\"days\":");
    if agg.day.len() <= 31 {
        pairs(out, agg.day.iter().map(|(d, v)| (day_iso(*d), *v)));
    } else {
        out.extend_from_slice(b"{\"active\":");
        json::u64(out, agg.day.len() as u64);
        out.extend_from_slice(b",\"busiest\":");
        pairs(out, top(agg.day.iter().map(|(d, v)| (day_iso(*d), *v)), n));
        out.push(b'}');
    }
    out.extend_from_slice(b",\"hours_utc\":[");
    for (i, v) in agg.hour.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        json::u64(out, *v);
    }
    out.extend_from_slice(b"]}\n");

    out.extend_from_slice(b"{\"top_hosts\":");
    pairs(out, top(agg.hosts.iter().map(|(k, v)| (k.clone(), *v)), n));
    out.extend_from_slice(b",\"top_accounts\":");
    pairs(
        out,
        top(agg.accounts.iter().map(|(k, v)| (k.clone(), *v)), n),
    );
    out.extend_from_slice(b",\"top_src_ip\":");
    pairs(out, top(agg.ips.iter().map(|(k, v)| (k.clone(), *v)), n));
    out.extend_from_slice(b"}\n");

    if !agg.logons.is_empty() {
        out.extend_from_slice(b"{\"logon_types\":{");
        let eids: Vec<u32> = [4624u32, 4625]
            .into_iter()
            .filter(|e| agg.logons.keys().any(|(x, _)| x == e))
            .collect();
        for (i, eid) in eids.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.push(b'"');
            json::u64(out, *eid as u64);
            out.extend_from_slice(b"\":{");
            let mut first = true;
            for ((e, lt), v) in &agg.logons {
                if e != eid {
                    continue;
                }
                if !first {
                    out.push(b',');
                }
                first = false;
                json::str(out, lt);
                out.push(b':');
                json::u64(out, *v);
            }
            out.push(b'}');
        }
        out.extend_from_slice(b"}}\n");
    }

    out.extend_from_slice(b"{\"log_tampering\":[");
    for (i, e) in agg.log_events.iter().take(50).enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"id\":");
        json::str(out, &e.id);
        out.extend_from_slice(b",\"t\":");
        json::str(out, &e.t);
        out.extend_from_slice(b",\"ch\":");
        json::str(out, ctx.map.channel_alias(&e.ch));
        out.extend_from_slice(b",\"eid\":");
        json::u64(out, e.eid as u64);
        if !e.user.is_empty() {
            out.extend_from_slice(b",\"user\":");
            json::str(out, &e.user);
        }
        out.push(b'}');
    }
    out.extend_from_slice(b"]");
    if agg.log_events.len() > 50 {
        out.extend_from_slice(b",\"more\":");
        json::u64(out, agg.log_events.len() as u64 - 50);
    }
    out.extend_from_slice(b"}\n");

    out.extend_from_slice(b"{\"quiet_periods\":[");
    for (i, (d, key, a, b)) in quiet.iter().take(n).enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"file\":");
        json::str(out, key);
        out.extend_from_slice(b",\"from\":");
        json::str(out, &minute_iso(*a));
        out.extend_from_slice(b",\"to\":");
        json::str(out, &minute_iso(*b));
        out.extend_from_slice(b",\"min\":");
        json::u64(out, *d as u64);
        out.push(b'}');
    }
    out.extend_from_slice(b"]}\n");
}

#[derive(Serialize)]
struct JsonStats<'a> {
    files: &'a [FileStats],
    events: u64,
    bad_chunks: u64,
    bad_records: u64,
    channels_event_ids: BTreeMap<String, BTreeMap<u32, u64>>,
    days: BTreeMap<String, u64>,
    hours_utc: [u64; 24],
    hosts: BTreeMap<&'a str, u64>,
    accounts: BTreeMap<&'a str, u64>,
    src_ips: BTreeMap<&'a str, u64>,
    logon_types: BTreeMap<String, BTreeMap<String, u64>>,
    log_tampering: &'a [LogEvent],
    quiet_periods: Vec<QuietPeriod>,
}

#[derive(Serialize)]
struct QuietPeriod {
    file: String,
    from: String,
    to: String,
    minutes: i64,
}

fn write_json(
    _ctx: &Ctx,
    agg: &Agg,
    quiet: &[(i64, String, i64, i64)],
    totals: &Totals,
    out: &mut Vec<u8>,
) -> anyhow::Result<()> {
    let mut ce: BTreeMap<String, BTreeMap<u32, u64>> = BTreeMap::new();
    for ((c, id), v) in &agg.chan_eid {
        ce.entry(c.clone()).or_default().insert(*id, *v);
    }
    let mut lt: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    for ((e, t), v) in &agg.logons {
        lt.entry(e.to_string()).or_default().insert(t.clone(), *v);
    }
    let s = JsonStats {
        files: &agg.files,
        events: agg.events,
        bad_chunks: totals.bad_units,
        bad_records: totals.bad_records,
        channels_event_ids: ce,
        days: agg.day.iter().map(|(d, v)| (day_iso(*d), *v)).collect(),
        hours_utc: agg.hour,
        hosts: agg.hosts.iter().map(|(k, v)| (k.as_str(), *v)).collect(),
        accounts: agg.accounts.iter().map(|(k, v)| (k.as_str(), *v)).collect(),
        src_ips: agg.ips.iter().map(|(k, v)| (k.as_str(), *v)).collect(),
        logon_types: lt,
        log_tampering: &agg.log_events,
        quiet_periods: quiet
            .iter()
            .map(|(d, k, a, b)| QuietPeriod {
                file: k.clone(),
                from: minute_iso(*a),
                to: minute_iso(*b),
                minutes: *d,
            })
            .collect(),
    };
    serde_json::to_writer_pretty(&mut *out, &s)?;
    out.push(b'\n');
    Ok(())
}

fn csv_cell(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn write_csv(ctx: &Ctx, agg: &Agg, quiet: &[(i64, String, i64, i64)], out: &mut Vec<u8>) {
    let mut rows: Vec<(String, String, String, String)> = Vec::new();
    for f in &agg.files {
        rows.push((
            "file".into(),
            f.key.clone(),
            f.path.clone(),
            f.events.to_string(),
        ));
        rows.push((
            "file_first".into(),
            f.key.clone(),
            f.first.clone().unwrap_or_default(),
            String::new(),
        ));
        rows.push((
            "file_last".into(),
            f.key.clone(),
            f.last.clone().unwrap_or_default(),
            String::new(),
        ));
    }
    let mut ce: Vec<_> = agg.chan_eid.iter().collect();
    ce.sort();
    for ((c, id), v) in ce {
        rows.push((
            "event_id".into(),
            ctx.map.channel_alias(c).to_string(),
            id.to_string(),
            v.to_string(),
        ));
    }
    for (d, v) in &agg.day {
        rows.push(("day".into(), day_iso(*d), String::new(), v.to_string()));
    }
    for (h, v) in agg.hour.iter().enumerate() {
        rows.push((
            "hour_utc".into(),
            h.to_string(),
            String::new(),
            v.to_string(),
        ));
    }
    for (name, m) in [
        ("host", &agg.hosts),
        ("account", &agg.accounts),
        ("src_ip", &agg.ips),
    ] {
        for (k, v) in top(m.iter().map(|(k, v)| (k.clone(), *v)), usize::MAX) {
            rows.push((name.into(), k, String::new(), v.to_string()));
        }
    }
    for e in &agg.log_events {
        rows.push((
            "log_tampering".into(),
            e.id.clone(),
            e.t.clone(),
            format!("{}:{} {}", e.ch, e.eid, e.user),
        ));
    }
    for (d, k, a, b) in quiet {
        rows.push((
            "quiet_period".into(),
            k.clone(),
            format!("{} - {}", minute_iso(*a), minute_iso(*b)),
            d.to_string(),
        ));
    }
    out.extend_from_slice(b"section,key,detail,count\n");
    for (a, b, c, d) in rows {
        out.extend_from_slice(
            format!(
                "{},{},{},{}\n",
                csv_cell(&a),
                csv_cell(&b),
                csv_cell(&c),
                csv_cell(&d)
            )
            .as_bytes(),
        );
    }
}
