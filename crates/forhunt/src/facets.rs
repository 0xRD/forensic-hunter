//! Match facets and the final `llm` summary line with narrowing suggestions.

use std::collections::{BTreeMap, HashMap};

use forhunt_core::normalize::FieldMap;
use forhunt_core::{EventView, Filter, Ts};
use forhunt_output::json;

/// Payload fields that identify "who" and "from where" in suggestions.
const USER_FIELDS: &[&str] = &["TargetUserName", "SubjectUserName", "User", "AccountName"];
const IP_FIELDS: &[&str] = &["IpAddress", "SourceIp", "SourceAddress", "ClientAddress"];
const PROC_FIELDS: &[&str] = &["NewProcessName", "Image", "ProcessName"];

#[derive(Debug, Default)]
pub struct Facets {
    pub n: u64,
    pub eid: HashMap<(String, u32), u64>,
    pub host: HashMap<String, u64>,
    pub day: BTreeMap<i64, u64>,
    pub hour: BTreeMap<i64, u64>,
    /// (field, value) -> count
    pub vals: HashMap<(&'static str, String), u64>,
    pub first: Option<Ts>,
    pub last: Option<Ts>,
}

fn pick(ev: &EventView<'_>, names: &[&'static str]) -> Option<(&'static str, String)> {
    for n in names {
        if let Some(v) = ev.field(n)
            && !v.is_blank()
        {
            return Some((*n, v.as_str().to_string()));
        }
    }
    None
}

impl Facets {
    pub fn add(&mut self, ev: &EventView<'_>) {
        self.n += 1;
        *self
            .eid
            .entry((ev.channel.to_string(), ev.event_id))
            .or_default() += 1;
        *self.host.entry(ev.computer.to_string()).or_default() += 1;
        let secs = ev.ts.secs();
        *self.day.entry(secs.div_euclid(86_400)).or_default() += 1;
        *self.hour.entry(secs.div_euclid(3600)).or_default() += 1;
        for names in [USER_FIELDS, IP_FIELDS, PROC_FIELDS] {
            if let Some(k) = pick(ev, names) {
                *self.vals.entry(k).or_default() += 1;
            }
        }
        self.first = Some(self.first.map_or(ev.ts, |f| f.min(ev.ts)));
        self.last = Some(self.last.map_or(ev.ts, |l| l.max(ev.ts)));
    }

    pub fn merge(&mut self, o: Facets) {
        self.n += o.n;
        for (k, v) in o.eid {
            *self.eid.entry(k).or_default() += v;
        }
        for (k, v) in o.host {
            *self.host.entry(k).or_default() += v;
        }
        for (k, v) in o.day {
            *self.day.entry(k).or_default() += v;
        }
        for (k, v) in o.hour {
            *self.hour.entry(k).or_default() += v;
        }
        for (k, v) in o.vals {
            *self.vals.entry(k).or_default() += v;
        }
        self.first = match (self.first, o.first) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.last = match (self.last, o.last) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }
}

/// Sorts by count desc, then key, for deterministic tops.
pub fn top<K: Ord + Clone>(m: impl IntoIterator<Item = (K, u64)>, n: usize) -> Vec<(K, u64)> {
    let mut v: Vec<(K, u64)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

pub struct SummaryInput<'a> {
    pub kind: &'a str,
    pub facets: &'a Facets,
    pub shown: u64,
    pub scanned: u64,
    pub files: usize,
    pub bad_chunks: u64,
    pub bad_records: u64,
    pub filter: &'a Filter,
    pub map: &'a FieldMap,
    pub limit: Option<usize>,
}

/// One JSON line: `{"summary":{...}}`.
pub fn write_summary(s: &SummaryInput<'_>, out: &mut Vec<u8>) {
    let f = s.facets;
    out.extend_from_slice(b"{\"summary\":{\"cmd\":");
    json::str(out, s.kind);
    out.extend_from_slice(b",\"matches\":");
    json::u64(out, f.n);
    out.extend_from_slice(b",\"shown\":");
    json::u64(out, s.shown);
    out.extend_from_slice(b",\"truncated\":");
    out.extend_from_slice(if f.n > s.shown { b"true" } else { b"false" });
    out.extend_from_slice(b",\"scanned\":");
    json::u64(out, s.scanned);
    out.extend_from_slice(b",\"files\":");
    json::u64(out, s.files as u64);
    if s.bad_chunks + s.bad_records > 0 {
        out.extend_from_slice(b",\"bad_chunks\":");
        json::u64(out, s.bad_chunks);
        out.extend_from_slice(b",\"bad_records\":");
        json::u64(out, s.bad_records);
    }
    if let (Some(a), Some(b)) = (f.first, f.last) {
        out.extend_from_slice(b",\"first\":\"");
        a.write_iso(out);
        out.extend_from_slice(b"\",\"last\":\"");
        b.write_iso(out);
        out.push(b'"');
    }
    let active = s.filter.describe();
    if !active.is_empty() {
        out.extend_from_slice(b",\"filter\":");
        json::str(out, &active.join(" "));
    }
    // Facets, compact: [["Sec:4624",120],...]
    out.extend_from_slice(b",\"top_eid\":[");
    for (i, ((ch, id), n)) in top(f.eid.iter().map(|(k, v)| (k.clone(), *v)), 8)
        .into_iter()
        .enumerate()
    {
        if i > 0 {
            out.push(b',');
        }
        out.push(b'[');
        json::str(out, &format!("{}:{id}", s.map.channel_alias(&ch)));
        out.push(b',');
        json::u64(out, n);
        out.push(b']');
    }
    out.extend_from_slice(b"],\"top_host\":[");
    for (i, (h, n)) in top(f.host.iter().map(|(k, v)| (k.clone(), *v)), 5)
        .into_iter()
        .enumerate()
    {
        if i > 0 {
            out.push(b',');
        }
        out.push(b'[');
        json::str(out, &h);
        out.push(b',');
        json::u64(out, n);
        out.push(b']');
    }
    out.extend_from_slice(b"],\"top_values\":[");
    for (i, ((field, v), n)) in top(f.vals.iter().map(|(k, v)| (k.clone(), *v)), 8)
        .into_iter()
        .enumerate()
    {
        if i > 0 {
            out.push(b',');
        }
        out.push(b'[');
        json::str(out, field);
        out.push(b',');
        forhunt_output::llm::trunc_str(out, &v, 120);
        out.push(b',');
        json::u64(out, n);
        out.push(b']');
    }
    out.push(b']');
    if f.n > s.shown {
        out.extend_from_slice(b",\"narrow\":[");
        for (i, (flag, n)) in suggestions(s).into_iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(b"{\"add\":");
            json::str(out, &flag);
            out.extend_from_slice(b",\"matches\":");
            json::u64(out, n);
            out.push(b'}');
        }
        out.push(b']');
        if let Some(l) = s.limit {
            out.extend_from_slice(b",\"note\":");
            json::str(
                out,
                &format!(
                    "output capped at {l} events; add a filter from `narrow` or raise --limit"
                ),
            );
        }
    }
    out.extend_from_slice(b"}}\n");
}

fn quote(v: &str) -> String {
    if v.chars()
        .any(|c| c.is_whitespace() || "\"'$&|;<>()`\\*?".contains(c))
    {
        format!("'{}'", v.replace('\'', "'\\''"))
    } else {
        v.to_string()
    }
}

fn suggestions(s: &SummaryInput<'_>) -> Vec<(String, u64)> {
    let f = s.facets;
    let mut out = Vec::new();
    let eids = top(f.eid.iter().map(|(k, v)| (k.clone(), *v)), 2);
    if f.eid.len() > 1
        && let Some(((ch, id), n)) = eids.first()
    {
        out.push((
            format!(
                "--channel {} --event-id {id}",
                quote(s.map.channel_alias(ch))
            ),
            *n,
        ));
    }
    if f.host.len() > 1
        && let Some((h, n)) = top(f.host.iter().map(|(k, v)| (k.clone(), *v)), 1).first()
    {
        out.push((format!("--computer {}", quote(h)), *n));
    }
    let span_days = f.day.len();
    if span_days > 1 {
        if let Some((d, n)) = top(f.day.iter().map(|(k, v)| (*k, *v)), 1).first() {
            let a = Ts(d * 86_400 * 10_000_000);
            let b = Ts((d + 1) * 86_400 * 10_000_000 - 1);
            out.push((format!("--since {} --until {}", a.iso(), b.iso()), *n));
        }
    } else if f.hour.len() > 1
        && let Some((h, n)) = top(f.hour.iter().map(|(k, v)| (*k, *v)), 1).first()
    {
        let a = Ts(h * 3600 * 10_000_000);
        let b = Ts((h + 1) * 3600 * 10_000_000 - 1);
        out.push((format!("--since {} --until {}", a.iso(), b.iso()), *n));
    }
    let vals = top(f.vals.iter().map(|(k, v)| (k.clone(), *v)), 3);
    for ((field, v), n) in vals {
        let noisy = v.ends_with('$')
            || v.eq_ignore_ascii_case("SYSTEM")
            || v.eq_ignore_ascii_case("LOCAL SERVICE")
            || v.eq_ignore_ascii_case("NETWORK SERVICE");
        if noisy {
            out.push((
                format!("--field {}", quote(&format!("{field}!={v}"))),
                f.n - n,
            ));
        } else if n < f.n {
            out.push((format!("--field {}", quote(&format!("{field}={v}"))), n));
        }
        if out.len() >= 6 {
            break;
        }
    }
    out
}
