//! `hayabusa`: normalise Hayabusa `json-timeline` output into the `llm` format.
//!
//! Hayabusa is an external GPLv3 tool; nothing of it is linked or vendored.
//! This command only reads its JSON output. When the scanned EVTX files are
//! reachable, detections get forhunt ids (`<file key>:<record id>`) so the
//! analyst can pivot with `forhunt show`.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use forhunt_core::artifact::ParseOptions;
use forhunt_core::id::FileKey;
use forhunt_core::{EventRef, Ts};
use forhunt_output::json;
use serde_json::Value;

use crate::cli::HayabusaArgs;
use crate::common::{self, Ctx};
use crate::facets::top;

/// Hayabusa level names (full and abbreviated) to a rank.
fn level_rank(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "emergency" | "emer" => 6,
        "critical" | "crit" => 5,
        "high" => 4,
        "medium" | "med" => 3,
        "low" => 2,
        "informational" | "info" => 1,
        _ => 0,
    }
}

fn level_name(r: u8) -> &'static str {
    match r {
        6 => "emergency",
        5 => "critical",
        4 => "high",
        3 => "medium",
        2 => "low",
        1 => "informational",
        _ => "unknown",
    }
}

/// `2016-08-19 16:07:09.766 +09:00` (Hayabusa default) or RFC 3339.
fn parse_time(s: &str) -> Option<Ts> {
    if let Some(t) = Ts::parse(s) {
        return Some(t);
    }
    let s = s.trim();
    let mut t = String::with_capacity(s.len());
    let mut seen_date = false;
    for (i, c) in s.char_indices() {
        if c == ' ' {
            if !seen_date && i == 10 {
                t.push('T');
                seen_date = true;
            }
            continue;
        }
        t.push(c);
    }
    Ts::parse(&t)
}

struct Det {
    ts: Option<Ts>,
    level: u8,
    rule: String,
    computer: String,
    channel: String,
    eid: u64,
    rid: Option<u64>,
    file: Option<String>,
    mitre: Vec<String>,
    details: Vec<(String, String)>,
    id: Option<EventRef>,
}

fn s(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(o) => o.to_string(),
    }
}

fn num(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn get<'a>(o: &'a serde_json::Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|n| o.get(*n))
}

fn flatten_details(v: Option<&Value>, out: &mut Vec<(String, String)>) {
    match v {
        Some(Value::Object(m)) => {
            for (k, v) in m {
                let val = s(Some(v));
                if !val.is_empty() && val != "-" {
                    out.push((k.clone(), val));
                }
            }
        }
        Some(Value::String(t)) if !t.is_empty() && t != "-" => {
            // Text profile: `Key: value ¦ Key: value`.
            for part in t.split('¦') {
                match part.split_once(':') {
                    Some((k, v)) => out.push((k.trim().to_string(), v.trim().to_string())),
                    None => out.push(("Details".into(), part.trim().to_string())),
                }
            }
        }
        _ => {}
    }
}

fn det(o: &serde_json::Map<String, Value>) -> Det {
    let mut details = Vec::new();
    flatten_details(get(o, &["Details"]), &mut details);
    flatten_details(get(o, &["ExtraFieldInfo"]), &mut details);
    flatten_details(get(o, &["AllFieldInfo"]), &mut details);
    let mut mitre = Vec::new();
    for k in ["MitreTactics", "MitreTags", "MitreTechniques"] {
        match o.get(k) {
            Some(Value::Array(a)) => mitre.extend(a.iter().map(|x| s(Some(x)))),
            Some(Value::String(t)) if !t.is_empty() && t != "-" => mitre.extend(
                t.split(['¦', ','])
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty()),
            ),
            _ => {}
        }
    }
    mitre.sort();
    mitre.dedup();
    Det {
        ts: parse_time(&s(get(o, &["Timestamp", "timestamp", "Datetime"]))),
        level: level_rank(&s(get(o, &["Level", "level"]))),
        rule: s(get(o, &["RuleTitle", "Rule", "rule_title"])),
        computer: s(get(o, &["Computer", "computer"])),
        channel: s(get(o, &["Channel", "channel"])),
        eid: num(get(o, &["EventID", "EventId", "event_id"])).unwrap_or(0),
        rid: num(get(o, &["RecordID", "RecordId", "record_id"])),
        file: get(o, &["EvtxFile", "evtx_file"])
            .map(|v| s(Some(v)))
            .filter(|f| !f.is_empty()),
        mitre,
        details,
        id: None,
    }
}

fn read_input(path: &str) -> anyhow::Result<Vec<Value>> {
    let mut text = String::new();
    if path == "-" {
        std::io::stdin().read_to_string(&mut text)?;
    } else {
        std::fs::File::open(path)
            .with_context(|| format!("cannot open {path}"))?
            .read_to_string(&mut text)?;
    }
    // JSONL, concatenated pretty-printed objects, or one array.
    let mut out = Vec::new();
    for v in
        serde_json::Deserializer::from_str(text.trim_start_matches('\u{feff}')).into_iter::<Value>()
    {
        match v.context("invalid Hayabusa JSON")? {
            Value::Array(a) => out.extend(a),
            v => out.push(v),
        }
    }
    Ok(out)
}

/// Resolves Hayabusa `EvtxFile` values to forhunt file keys, and Hayabusa
/// record ids (`System/EventRecordID`) to record header ids, which differ in
/// exported logs.
struct KeyResolver {
    by_path: HashMap<PathBuf, (FileKey, PathBuf)>,
    by_name: HashMap<String, Option<(FileKey, PathBuf)>>,
    cache: HashMap<String, Option<(FileKey, PathBuf)>>,
    remap: HashMap<FileKey, HashMap<u64, u64>>,
}

impl KeyResolver {
    fn new(ctx: &Ctx, paths: &[String]) -> anyhow::Result<KeyResolver> {
        let mut r = KeyResolver {
            by_path: HashMap::new(),
            by_name: HashMap::new(),
            cache: HashMap::new(),
            remap: HashMap::new(),
        };
        if !paths.is_empty() {
            let inputs = ctx.open(paths)?;
            for s in &inputs.sources {
                let p = s.path().to_path_buf();
                if let Some(n) = p.file_name() {
                    let n = n.to_string_lossy().to_lowercase();
                    r.by_name
                        .entry(n)
                        .and_modify(|v| *v = None)
                        .or_insert(Some((s.key(), p.clone())));
                }
                let canon = p.canonicalize().unwrap_or(p.clone());
                r.by_path.insert(canon, (s.key(), p));
            }
        }
        Ok(r)
    }

    fn resolve(&mut self, file: &str) -> Option<(FileKey, PathBuf)> {
        if let Some(k) = self.cache.get(file) {
            return k.clone();
        }
        let p = Path::new(file);
        let k = p
            .canonicalize()
            .ok()
            .and_then(|c| self.by_path.get(&c).cloned())
            .or_else(|| {
                let n = p
                    .file_name()
                    .or_else(|| file.rsplit(['\\', '/']).next().map(std::ffi::OsStr::new))?;
                self.by_name
                    .get(&n.to_string_lossy().to_lowercase())
                    .cloned()
                    .flatten()
            })
            .or_else(|| {
                // The scanned file itself may be reachable.
                let src = forhunt_core::evtx::EvtxSource::open(p, &ParseOptions::default()).ok()?;
                use forhunt_core::artifact::Source;
                Some((src.key(), p.to_path_buf()))
            });
        self.cache.insert(file.to_string(), k.clone());
        k
    }

    /// Maps an `EventRecordID` to the record header id (identity for native logs).
    fn record(&mut self, key: FileKey, path: &Path, erid: u64) -> u64 {
        let map = self.remap.entry(key).or_insert_with(|| {
            use forhunt_core::artifact::Source;
            let mut m = HashMap::new();
            if let Ok(src) = forhunt_core::evtx::EvtxSource::open(path, &ParseOptions::default()) {
                for u in 0..src.units() {
                    src.parse_unit(u, &mut |ev: &forhunt_core::EventView<'_>| {
                        if ev.event_record_id != ev.id.record {
                            m.insert(ev.event_record_id, ev.id.record);
                        }
                    });
                }
            }
            m
        });
        map.get(&erid).copied().unwrap_or(erid)
    }
}

pub fn run(a: HayabusaArgs) -> anyhow::Result<()> {
    let ctx = Ctx::new(&a.common)?;
    let min = level_rank(&a.min_level);
    if min == 0 {
        anyhow::bail!(
            "--min-level `{}`: use informational, low, medium, high or critical",
            a.min_level
        );
    }
    let values = read_input(&a.input)?;
    let mut resolver = KeyResolver::new(&ctx, &a.evtx)?;
    let mut dets: Vec<Det> = Vec::new();
    let mut skipped = 0u64;
    let mut below = 0u64;
    for v in &values {
        let Value::Object(o) = v else {
            skipped += 1;
            continue;
        };
        let mut d = det(o);
        if d.level < min {
            below += 1;
            continue;
        }
        if let (Some(f), Some(rid)) = (&d.file, d.rid)
            && let Some((file, path)) = resolver.resolve(f)
        {
            let record = resolver.record(file, &path, rid);
            d.id = Some(EventRef { file, record });
        }
        dets.push(d);
    }
    // Deterministic: time, then level desc, rule, record.
    dets.sort_by(|x, y| {
        x.ts.cmp(&y.ts)
            .then(y.level.cmp(&x.level))
            .then_with(|| x.rule.cmp(&y.rule))
            .then(x.rid.cmp(&y.rid))
            .then_with(|| x.computer.cmp(&y.computer))
    });
    // With a cap, keep the most severe detections, then print them in time order.
    let shown: Vec<usize> = if a.limit > 0 && dets.len() > a.limit {
        let mut idx: Vec<usize> = (0..dets.len()).collect();
        idx.sort_by(|&i, &j| dets[j].level.cmp(&dets[i].level).then(i.cmp(&j)));
        idx.truncate(a.limit);
        idx.sort_unstable();
        idx
    } else {
        (0..dets.len()).collect()
    };

    let mut out = common::output(&a.output)?;
    let mut buf = Vec::new();
    for &i in &shown {
        let d = &dets[i];
        buf.extend_from_slice(b"{\"id\":");
        match d.id {
            Some(id) => {
                buf.push(b'"');
                id.write(&mut buf);
                buf.push(b'"');
            }
            None => buf.extend_from_slice(b"null"),
        }
        buf.extend_from_slice(b",\"t\":");
        match d.ts {
            Some(t) => {
                buf.push(b'"');
                match &ctx.tz {
                    Some(tz) => t.write_in_tz(tz, &mut buf),
                    None => t.write_iso(&mut buf),
                }
                buf.push(b'"');
            }
            None => buf.extend_from_slice(b"null"),
        }
        buf.extend_from_slice(b",\"h\":");
        json::str(&mut buf, &d.computer);
        buf.extend_from_slice(b",\"ch\":");
        json::str(&mut buf, ctx.map.channel_alias(&d.channel));
        buf.extend_from_slice(b",\"eid\":");
        json::u64(&mut buf, d.eid);
        if let Some(r) = d.rid {
            buf.extend_from_slice(b",\"rec\":");
            json::u64(&mut buf, r);
        }
        buf.extend_from_slice(b",\"lvl\":");
        json::str(&mut buf, level_name(d.level));
        buf.extend_from_slice(b",\"rule\":");
        json::str(&mut buf, &d.rule);
        if !d.mitre.is_empty() {
            buf.extend_from_slice(b",\"mitre\":[");
            for (j, m) in d.mitre.iter().enumerate() {
                if j > 0 {
                    buf.push(b',');
                }
                json::str(&mut buf, m);
            }
            buf.push(b']');
        }
        buf.extend_from_slice(b",\"d\":{");
        for (j, (k, v)) in d.details.iter().enumerate() {
            if j > 0 {
                buf.push(b',');
            }
            json::str(&mut buf, k);
            buf.push(b':');
            forhunt_output::llm::trunc_str(&mut buf, v, a.max_value_len);
        }
        buf.extend_from_slice(b"}}\n");
    }

    // Summary.
    let mut levels: BTreeMap<u8, u64> = BTreeMap::new();
    let mut rules: HashMap<(String, u8), u64> = HashMap::new();
    let mut hosts: HashMap<String, u64> = HashMap::new();
    for d in &dets {
        *levels.entry(d.level).or_default() += 1;
        *rules.entry((d.rule.clone(), d.level)).or_default() += 1;
        *hosts.entry(d.computer.clone()).or_default() += 1;
    }
    buf.extend_from_slice(b"{\"summary\":{\"cmd\":\"hayabusa\",\"detections\":");
    json::u64(&mut buf, dets.len() as u64);
    buf.extend_from_slice(b",\"shown\":");
    json::u64(&mut buf, shown.len() as u64);
    buf.extend_from_slice(b",\"below_min_level\":");
    json::u64(&mut buf, below);
    if skipped > 0 {
        buf.extend_from_slice(b",\"skipped_non_objects\":");
        json::u64(&mut buf, skipped);
    }
    buf.extend_from_slice(b",\"with_forhunt_id\":");
    json::u64(
        &mut buf,
        dets.iter().filter(|d| d.id.is_some()).count() as u64,
    );
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
    let mut tr: Vec<((String, u8), u64)> = rules.into_iter().collect();
    tr.sort_by(|x, y| {
        y.0.1
            .cmp(&x.0.1)
            .then(y.1.cmp(&x.1))
            .then_with(|| x.0.0.cmp(&y.0.0))
    });
    for (j, ((r, l), n)) in tr.iter().take(15).enumerate() {
        if j > 0 {
            buf.push(b',');
        }
        buf.push(b'[');
        json::str(&mut buf, r);
        buf.push(b',');
        json::str(&mut buf, level_name(*l));
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
    if dets.len() > shown.len() {
        buf.extend_from_slice(b",\"note\":\"capped: the most severe detections are shown; raise --min-level or --limit\"");
    }
    buf.extend_from_slice(b"}}\n");
    common::write_out(&mut *out, &buf)?;
    common::flush(&mut *out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_and_levels() {
        assert_eq!(
            parse_time("2016-08-19 16:07:09.766 +09:00").unwrap().iso(),
            "2016-08-19T07:07:09.766000Z"
        );
        assert_eq!(
            parse_time("2016-08-19T07:07:09Z").unwrap().iso(),
            "2016-08-19T07:07:09.000000Z"
        );
        assert_eq!(level_rank("crit"), 5);
        assert_eq!(level_rank("Medium"), 3);
        assert_eq!(level_rank("info"), 1);
    }

    #[test]
    fn details_text_profile() {
        let mut v = Vec::new();
        flatten_details(
            Some(&Value::String("Cmdline: whoami /all ¦ User: bob".into())),
            &mut v,
        );
        assert_eq!(
            v,
            vec![
                ("Cmdline".into(), "whoami /all".into()),
                ("User".into(), "bob".into())
            ]
        );
    }
}
