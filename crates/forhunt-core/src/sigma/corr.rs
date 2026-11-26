//! Correlation rules (Sigma 2: `event_count`, `value_count`, `temporal`,
//! `temporal_ordered`, `value_sum`, `value_avg`) and the deprecated
//! `condition: selection | count(field) by group > N` aggregation, which is
//! read as a correlation over a hidden base rule (D-068).
//!
//! Matching stays per event; correlations run afterwards over the
//! observations of their base rules ([`super::RuleSet::observe`]): per
//! correlation and group-by key, a window of `timespan` slides over the
//! events in time order, and every event of a window meeting the condition
//! belongs to a detection. Consecutive members less than `timespan` apart
//! form one burst, reported once with its first and last time.

use std::collections::HashMap;

use super::yaml::Node;
use crate::time::Ts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrKind {
    EventCount,
    ValueCount,
    Temporal,
    TemporalOrdered,
    ValueSum,
    ValueAvg,
}

impl CorrKind {
    pub fn name(self) -> &'static str {
        match self {
            CorrKind::EventCount => "event_count",
            CorrKind::ValueCount => "value_count",
            CorrKind::Temporal => "temporal",
            CorrKind::TemporalOrdered => "temporal_ordered",
            CorrKind::ValueSum => "value_sum",
            CorrKind::ValueAvg => "value_avg",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CmpOp {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Ne,
}

impl CmpOp {
    fn holds(self, x: f64, n: f64) -> bool {
        match self {
            CmpOp::Gt => x > n,
            CmpOp::Ge => x >= n,
            CmpOp::Lt => x < n,
            CmpOp::Le => x <= n,
            CmpOp::Eq => x == n,
            CmpOp::Ne => x != n,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Corr {
    pub kind: CorrKind,
    /// Referenced rules, by `name` or `id`, as written.
    pub refs: Vec<String>,
    /// The same, resolved to rule indexes when the set is built.
    pub rules: Vec<u32>,
    pub group_by: Vec<String>,
    /// Group-by alias -> (rule name or id -> that rule's field).
    pub aliases: HashMap<String, HashMap<String, String>>,
    /// Window, in 100 ns ticks.
    pub timespan: i64,
    pub op: CmpOp,
    pub n: f64,
    /// Field counted (`value_count`) or summed (`value_sum`, `value_avg`).
    pub field: Option<String>,
    /// The referenced rules also report their own matches.
    pub generate: bool,
}

/// `5m`, `30s`, `1h`, `2d`, `1w` -> ticks.
pub fn timespan(s: &str) -> Option<i64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: i64 = num.parse().ok()?;
    let secs = match unit.trim() {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 7 * 86_400,
        _ => return None,
    };
    Some(n * secs * 10_000_000)
}

fn op_of(k: &str) -> Option<CmpOp> {
    Some(match k {
        "gt" => CmpOp::Gt,
        "gte" => CmpOp::Ge,
        "lt" => CmpOp::Lt,
        "lte" => CmpOp::Le,
        "eq" => CmpOp::Eq,
        "neq" => CmpOp::Ne,
        _ => return None,
    })
}

/// A `correlation:` section.
pub fn parse(c: &Node) -> Result<Corr, String> {
    let text = |k: &str| c.get(k).and_then(Node::as_str).map(str::trim);
    let kind = match text("type").unwrap_or("") {
        "event_count" => CorrKind::EventCount,
        "value_count" => CorrKind::ValueCount,
        "temporal" => CorrKind::Temporal,
        "temporal_ordered" => CorrKind::TemporalOrdered,
        "value_sum" => CorrKind::ValueSum,
        "value_avg" => CorrKind::ValueAvg,
        t => return Err(format!("correlation type `{t}` is not supported")),
    };
    let refs = c.get("rules").map(Node::strings).unwrap_or_default();
    if refs.is_empty() {
        return Err("correlation without rules".into());
    }
    let span = text("timespan")
        .or_else(|| text("timeframe"))
        .ok_or("correlation without timespan")?;
    let timespan = timespan(span).ok_or_else(|| format!("timespan `{span}`"))?;
    let mut aliases = HashMap::new();
    if let Some(Node::Map(m)) = c.get("aliases") {
        for (alias, per_rule) in m {
            if let Node::Map(r) = per_rule {
                let fields = r
                    .iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                    .collect();
                aliases.insert(alias.clone(), fields);
            }
        }
    }
    let (mut op, mut n, mut field) = (None, None, None);
    match c.get("condition") {
        Some(Node::Map(m)) => {
            for (k, v) in m {
                if k == "field" {
                    field = v.as_str().map(str::to_string);
                } else if let Some(o) = op_of(k) {
                    op = Some(o);
                    n = v.as_str().and_then(|x| x.trim().parse::<f64>().ok());
                }
            }
        }
        // temporal rules may omit it: every rule at least once.
        None if matches!(kind, CorrKind::Temporal | CorrKind::TemporalOrdered) => {
            op = Some(CmpOp::Ge);
            n = Some(refs.len() as f64);
        }
        _ => {}
    }
    let (Some(op), Some(n)) = (op, n) else {
        return Err(
            "correlation condition: expected gt, gte, lt, lte, eq or neq with a number".into(),
        );
    };
    if matches!(
        kind,
        CorrKind::ValueCount | CorrKind::ValueSum | CorrKind::ValueAvg
    ) && field.is_none()
    {
        return Err(format!("{} needs `condition: field:`", kind.name()));
    }
    Ok(Corr {
        kind,
        refs,
        rules: Vec::new(),
        group_by: c.get("group-by").map(Node::strings).unwrap_or_default(),
        aliases,
        timespan,
        op,
        n,
        field,
        generate: matches!(text("generate"), Some("true" | "True" | "yes")),
    })
}

/// The deprecated aggregation after `|`: `count([field]) [by a[, b]] OP N`.
pub fn parse_aggregation(agg: &str, timeframe: Option<&str>, base: &str) -> Result<Corr, String> {
    let s = agg.trim();
    let rest = s
        .strip_prefix("count")
        .ok_or_else(|| format!("aggregation `{s}`: only count() is supported"))?;
    let rest = rest.trim_start();
    let close = rest.find(')').ok_or("aggregation: missing `)`")?;
    let field = rest
        .get(1..close)
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(str::to_string);
    let mut rest = rest[close + 1..].trim();
    let mut group_by = Vec::new();
    if let Some(r) = rest.strip_prefix("by ") {
        let end = r
            .find(['>', '<', '=', '!'])
            .ok_or("aggregation: missing the comparison")?;
        group_by = r[..end]
            .split(',')
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty())
            .collect();
        rest = r[end..].trim();
    }
    let (op, num) = [
        (">=", CmpOp::Ge),
        ("<=", CmpOp::Le),
        ("==", CmpOp::Eq),
        ("!=", CmpOp::Ne),
        (">", CmpOp::Gt),
        ("<", CmpOp::Lt),
        ("=", CmpOp::Eq),
    ]
    .into_iter()
    .find_map(|(t, o)| rest.strip_prefix(t).map(|v| (o, v)))
    .ok_or_else(|| format!("aggregation `{s}`: missing the comparison"))?;
    let n: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("aggregation `{s}`: `{}` is not a number", num.trim()))?;
    // Without a timeframe the whole timeline is the window.
    let timespan = match timeframe {
        Some(t) => timespan(t).ok_or_else(|| format!("timeframe `{t}`"))?,
        None => i64::MAX / 4,
    };
    Ok(Corr {
        kind: if field.is_some() {
            CorrKind::ValueCount
        } else {
            CorrKind::EventCount
        },
        refs: vec![base.to_string()],
        rules: Vec::new(),
        group_by,
        aliases: HashMap::new(),
        timespan,
        op,
        n,
        field,
        generate: false,
    })
}

/// One base-rule match kept for a correlation.
#[derive(Debug, Clone)]
pub struct Obs {
    /// Correlation rule index.
    pub corr: u32,
    /// Position of the base rule in the correlation's `rules`.
    pub base: u16,
    pub ts: Ts,
    /// Group-by values, joined.
    pub group: Box<str>,
    pub value: Option<Box<str>>,
}

/// A detection of a correlation: the events of one burst.
#[derive(Debug, Clone)]
pub struct Burst<H> {
    pub rule: u32,
    pub group: Box<str>,
    pub first: Ts,
    pub last: Ts,
    pub members: Vec<H>,
}

/// Runs the correlations over their observations (`H`: how the caller
/// names an event: a forhunt id, a CSV row).
pub fn correlate<H: Clone>(corrs: &HashMap<u32, &Corr>, mut obs: Vec<(Obs, H)>) -> Vec<Burst<H>> {
    obs.sort_by(|(a, _), (b, _)| {
        a.corr
            .cmp(&b.corr)
            .then_with(|| a.group.cmp(&b.group))
            .then(a.ts.cmp(&b.ts))
    });
    let mut out = Vec::new();
    let mut i = 0;
    while i < obs.len() {
        let mut j = i;
        while j < obs.len() && obs[j].0.corr == obs[i].0.corr && obs[j].0.group == obs[i].0.group {
            j += 1;
        }
        if let Some(c) = corrs.get(&obs[i].0.corr) {
            run_group(c, &obs[i..j], &mut out);
        }
        i = j;
    }
    out
}

fn run_group<H: Clone>(c: &Corr, ev: &[(Obs, H)], out: &mut Vec<Burst<H>>) {
    let n = ev.len();
    // diff[k]: +1 where a satisfied window starts, -1 after it ends.
    let mut diff = vec![0i32; n + 1];
    let mut values: HashMap<&str, u32> = HashMap::new();
    let mut per_base = vec![0u32; c.refs.len().max(c.rules.len()).max(1)];
    let (mut sum, mut cnt_num) = (0f64, 0u32);
    let num = |o: &Obs| {
        o.value
            .as_deref()
            .and_then(|v| v.trim().parse::<f64>().ok())
    };
    let mut lo = 0;
    for hi in 0..n {
        let o = &ev[hi].0;
        if let Some(v) = o.value.as_deref() {
            *values.entry(v).or_default() += 1;
        }
        if let Some(x) = num(o) {
            sum += x;
            cnt_num += 1;
        }
        if let Some(b) = per_base.get_mut(o.base as usize) {
            *b += 1;
        }
        while ev[hi].0.ts.0.saturating_sub(ev[lo].0.ts.0) > c.timespan {
            let p = &ev[lo].0;
            if let Some(v) = p.value.as_deref()
                && let Some(k) = values.get_mut(v)
            {
                *k -= 1;
                if *k == 0 {
                    values.remove(v);
                }
            }
            if let Some(x) = num(p) {
                sum -= x;
                cnt_num -= 1;
            }
            if let Some(b) = per_base.get_mut(p.base as usize) {
                *b -= 1;
            }
            lo += 1;
        }
        // First member of the window (ordered: where the sequence starts).
        let mut start = lo;
        let ok = match c.kind {
            CorrKind::EventCount => c.op.holds((hi - lo + 1) as f64, c.n),
            CorrKind::ValueCount => c.op.holds(values.len() as f64, c.n),
            CorrKind::ValueSum => cnt_num > 0 && c.op.holds(sum, c.n),
            CorrKind::ValueAvg => cnt_num > 0 && c.op.holds(sum / cnt_num as f64, c.n),
            CorrKind::Temporal => per_base.iter().take(c.refs.len()).all(|&b| b > 0),
            CorrKind::TemporalOrdered => {
                // The rules appear in their order within the window.
                let mut k = 0;
                for (x, e) in ev[lo..=hi].iter().enumerate() {
                    if e.0.base as usize == k {
                        if k == 0 {
                            start = lo + x;
                        }
                        k += 1;
                        if k == c.refs.len() {
                            break;
                        }
                    }
                }
                k == c.refs.len()
            }
        };
        if ok {
            diff[start] += 1;
            diff[hi + 1] -= 1;
        }
    }
    // Members, cut into bursts where the gap exceeds the timespan.
    let mut acc = 0;
    let mut cur: Option<Burst<H>> = None;
    for k in 0..n {
        acc += diff[k];
        if acc <= 0 {
            continue;
        }
        let (o, h) = &ev[k];
        match &mut cur {
            Some(b) if o.ts.0.saturating_sub(b.last.0) <= c.timespan => {
                b.last = o.ts;
                b.members.push(h.clone());
            }
            _ => {
                if let Some(b) = cur.take() {
                    out.push(b);
                }
                cur = Some(Burst {
                    rule: o.corr,
                    group: o.group.clone(),
                    first: o.ts,
                    last: o.ts,
                    members: vec![h.clone()],
                });
            }
        }
    }
    out.extend(cur);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(kind: CorrKind, op: CmpOp, n: f64, refs: usize) -> Corr {
        Corr {
            kind,
            refs: (0..refs).map(|i| format!("r{i}")).collect(),
            rules: (0..refs as u32).collect(),
            group_by: vec![],
            aliases: HashMap::new(),
            timespan: timespan("5m").unwrap(),
            op,
            n,
            field: None,
            generate: false,
        }
    }

    fn obs(min: i64, base: u16, value: &str) -> (Obs, i64) {
        (
            Obs {
                corr: 9,
                base,
                ts: Ts(min * 60 * 10_000_000),
                group: "g".into(),
                value: Some(value.into()),
            },
            min,
        )
    }

    #[test]
    fn counts_in_windows() {
        let ec = c(CorrKind::EventCount, CmpOp::Ge, 3.0, 1);
        let m: HashMap<u32, &Corr> = [(9, &ec)].into();
        // 3 events within 5 minutes (minutes 0, 2, 4), then a lone one at 30.
        let b = correlate(
            &m,
            vec![
                obs(0, 0, "a"),
                obs(2, 0, "a"),
                obs(4, 0, "b"),
                obs(30, 0, "c"),
            ],
        );
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].members, vec![0, 2, 4]);
        // Spread out: no window holds 3.
        assert!(correlate(&m, vec![obs(0, 0, "a"), obs(6, 0, "a"), obs(12, 0, "a")]).is_empty());
        let mut vc = c(CorrKind::ValueCount, CmpOp::Ge, 3.0, 1);
        vc.field = Some("User".into());
        let m: HashMap<u32, &Corr> = [(9, &vc)].into();
        assert!(correlate(&m, vec![obs(0, 0, "a"), obs(1, 0, "a"), obs(2, 0, "b")]).is_empty());
        assert_eq!(
            correlate(&m, vec![obs(0, 0, "a"), obs(1, 0, "b"), obs(2, 0, "c")]).len(),
            1
        );
    }

    #[test]
    fn temporal_and_ordered() {
        let t = c(CorrKind::Temporal, CmpOp::Ge, 2.0, 2);
        let m: HashMap<u32, &Corr> = [(9, &t)].into();
        assert_eq!(correlate(&m, vec![obs(0, 1, ""), obs(1, 0, "")]).len(), 1);
        let o = c(CorrKind::TemporalOrdered, CmpOp::Ge, 2.0, 2);
        let m: HashMap<u32, &Corr> = [(9, &o)].into();
        assert!(correlate(&m, vec![obs(0, 1, ""), obs(1, 0, "")]).is_empty());
        assert_eq!(correlate(&m, vec![obs(0, 0, ""), obs(1, 1, "")]).len(), 1);
    }

    #[test]
    fn aggregation_syntax() {
        let a =
            parse_aggregation("count(TargetUserName) by IpAddress >= 5", Some("5m"), "b").unwrap();
        assert_eq!((a.kind, a.op, a.n), (CorrKind::ValueCount, CmpOp::Ge, 5.0));
        assert_eq!(a.group_by, ["IpAddress"]);
        let a = parse_aggregation("count() by Computer, User > 10", None, "b").unwrap();
        assert_eq!((a.kind, a.op), (CorrKind::EventCount, CmpOp::Gt));
        assert_eq!(a.group_by, ["Computer", "User"]);
        assert!(parse_aggregation("max(x) > 3", None, "b").is_err());
        assert_eq!(timespan("90s"), Some(900_000_000));
    }
}
