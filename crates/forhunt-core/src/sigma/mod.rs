//! Sigma rule engine: loads Sigma / Hayabusa rule files and matches them
//! against [`EventView`]s, from any artifact.
//!
//! Written from the public Sigma specification (clean-room; no code from
//! Hayabusa or other engines). Rule sets such as Yamato Security's
//! `hayabusa-rules` (Detection Rule License 1.1) are read from disk, never
//! bundled. DRL 1.1 asks that messages based on matches keep the rule's
//! author: [`Rule::author`] is there for that.
//!
//! Speed: rules are compiled once; each event is tried only against the
//! rules whose `Channel` / `EventID` constraints it meets (an index built from
//! the conditions), and [`RuleSet::wants_event_id`] lets parsers skip
//! decoding events no rule can match.

mod compile;
mod eval;
mod load;
pub mod yaml;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

pub use load::{LoadOptions, LoadReport, load, load_str};

use crate::event::EventView;
use compile::{Cond, Sel};

/// Rule levels, lowest first (`0` = unknown).
pub const LEVELS: [&str; 6] = [
    "unknown",
    "informational",
    "low",
    "medium",
    "high",
    "critical",
];

/// `informational`/`info`, `low`, `medium`/`med`, `high`, `critical`/`crit`
/// (case-insensitive) -> 1..=5; anything else 0.
pub fn level_rank(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" | "crit" | "emergency" => 5,
        "high" => 4,
        "medium" | "med" => 3,
        "low" => 2,
        "informational" | "info" => 1,
        _ => 0,
    }
}

pub fn level_name(r: u8) -> &'static str {
    LEVELS.get(r as usize).copied().unwrap_or("unknown")
}

/// A compiled rule and what to show about it.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub title: String,
    /// 1 informational .. 5 critical (after `level_tuning.txt`).
    pub level: u8,
    pub status: String,
    /// Credit owed under DRL 1.1 on every message based on a match.
    pub author: String,
    pub description: String,
    pub tags: Vec<String>,
    pub references: Vec<String>,
    pub falsepositives: Vec<String>,
    pub date: String,
    pub modified: String,
    /// `Sigma` or `Hayabusa` (from `ruletype`), else empty.
    pub ruletype: String,
    /// Hayabusa `details` template (`Key: %Field% ¦ ...`).
    pub details: Option<String>,
    /// Fields the rule tests, without `Channel` / `EventID`.
    pub fields: Vec<String>,
    pub path: PathBuf,
    sels: Vec<Sel>,
    cond: Cond,
    /// Lowercased channels / event ids the rule can match (`None` = any).
    chans: Option<Vec<String>>,
    eids: Option<Vec<u32>>,
    /// Necessary (field, literal) pairs, when the condition has them.
    req: Option<compile::Req>,
}

impl Rule {
    /// Channels (lowercased) the rule can match; `None` = any.
    pub fn channels(&self) -> Option<&[String]> {
        self.chans.as_deref()
    }

    /// Event ids the rule can match; `None` = any.
    pub fn event_ids(&self) -> Option<&[u32]> {
        self.eids.as_deref()
    }

    /// ATT&CK technique ids from the tags (`attack.t1059.001` -> `T1059.001`).
    pub fn mitre(&self) -> Vec<String> {
        self.tags
            .iter()
            .filter_map(|t| t.strip_prefix("attack."))
            .map(|t| {
                if t.len() > 1 && t.starts_with('t') && t.as_bytes()[1].is_ascii_digit() {
                    t.to_ascii_uppercase()
                } else {
                    t.to_string()
                }
            })
            .collect()
    }
}

/// A loaded rule set, ready to match. Cheap to share across threads.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    by_channel: HashMap<String, Vec<u32>>,
    any_channel: Vec<u32>,
    /// Event ids some rule can match; `None` when a rule matches any id.
    eids: Option<HashSet<u32>>,
    /// (provider lowercased, event id) -> Hayabusa default details template.
    default_details: HashMap<(String, u32), String>,
    aliases: HashMap<String, String>,
    /// Number of interned payload field names.
    names: usize,
    /// Matching plans per (channel, event id), shared by all threads.
    plans: std::sync::Mutex<PlanCache>,
}

type PlanCache = HashMap<(Box<str>, u32), Arc<Plan>>;
/// Field -> (literal -> gated rule indexes).
type FieldLits = Vec<(compile::FieldRef, HashMap<Box<str>, Vec<u32>>)>;
/// Event id -> (channel, plan).
type LocalPlans = HashMap<u32, Vec<(Box<str>, Arc<Plan>)>>;

/// How to match the events of one (channel, event id).
#[derive(Debug, Default)]
struct Plan {
    /// Candidate rules evaluated on every event.
    always: Vec<u32>,
    /// Candidate rules with a necessary literal, evaluated only when one of
    /// their literals is found.
    gated: Vec<u32>,
    /// Per field: one automaton over the literals of the gated rules, and
    /// for each literal the gated rules (indexes into `gated`) it opens.
    fields: Vec<(compile::FieldRef, aho_corasick::AhoCorasick, Vec<Vec<u32>>)>,
}

impl RuleSet {
    fn build(
        mut rules: Vec<Rule>,
        default_details: HashMap<(String, u32), String>,
        aliases: HashMap<String, String>,
    ) -> RuleSet {
        let mut names = HashMap::new();
        for r in &mut rules {
            for s in &mut r.sels {
                compile::intern(s, &mut names);
            }
            let reqs: Vec<_> = r.sels.iter().map(compile::sel_req).collect();
            r.req = compile::cond_req(&r.cond, &reqs);
        }
        let mut by_channel: HashMap<String, Vec<u32>> = HashMap::new();
        let mut any_channel = Vec::new();
        let mut eids = Some(HashSet::new());
        for (i, r) in rules.iter().enumerate() {
            match &r.chans {
                Some(cs) => {
                    for c in cs {
                        by_channel.entry(c.clone()).or_default().push(i as u32);
                    }
                }
                None => any_channel.push(i as u32),
            }
            match (&r.eids, &mut eids) {
                (Some(e), Some(all)) => all.extend(e.iter().copied()),
                (None, _) => eids = None,
                _ => {}
            }
        }
        RuleSet {
            rules,
            by_channel,
            any_channel,
            eids,
            default_details,
            aliases,
            names: names.len(),
            plans: Default::default(),
        }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// False when no rule can match events with this id: the parser may skip
    /// decoding them.
    pub fn wants_event_id(&self, eid: u32) -> bool {
        self.eids.as_ref().is_none_or(|s| s.contains(&eid))
    }

    /// Rules that can match an event of this channel and id, ascending.
    pub fn candidates(&self, channel: &str, eid: u32) -> Vec<u32> {
        let ch = compile::lower(channel);
        let mut out: Vec<u32> = self
            .by_channel
            .get(ch.as_ref())
            .into_iter()
            .flatten()
            .chain(self.any_channel.iter())
            .copied()
            .filter(|&r| {
                self.rules[r as usize]
                    .eids
                    .as_ref()
                    .is_none_or(|e| e.contains(&eid))
            })
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    fn plan(&self, channel: &str, eid: u32) -> Arc<Plan> {
        let mut plans = self.plans.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = plans.get(&(Box::<str>::from(channel), eid)) {
            return p.clone();
        }
        let mut p = Plan::default();
        // field -> (literal -> gated rule indexes)
        let mut by_field: FieldLits = Vec::new();
        for r in self.candidates(channel, eid) {
            match &self.rules[r as usize].req {
                None => p.always.push(r),
                Some(req) => {
                    let g = p.gated.len() as u32;
                    p.gated.push(r);
                    for (f, lit) in req {
                        let k = match by_field.iter().position(|(x, _)| x == f) {
                            Some(k) => k,
                            None => {
                                by_field.push((f.clone(), HashMap::new()));
                                by_field.len() - 1
                            }
                        };
                        let v = by_field[k].1.entry(lit.clone()).or_default();
                        if v.last() != Some(&g) {
                            v.push(g);
                        }
                    }
                }
            }
        }
        for (f, lits) in by_field {
            let mut lits: Vec<(Box<str>, Vec<u32>)> = lits.into_iter().collect();
            lits.sort();
            match aho_corasick::AhoCorasick::builder().build(lits.iter().map(|(l, _)| l.as_bytes()))
            {
                Ok(ac) => p
                    .fields
                    .push((f, ac, lits.into_iter().map(|(_, v)| v).collect())),
                // Cannot happen with these sizes; never lose a rule: run them all.
                Err(_) => {
                    for (_, v) in lits {
                        for g in v {
                            p.always.push(p.gated[g as usize]);
                        }
                    }
                }
            }
        }
        p.always.sort_unstable();
        p.always.dedup();
        let p = Arc::new(p);
        plans.insert((channel.into(), eid), p.clone());
        p
    }

    /// A matcher for one thread.
    pub fn matcher(&self) -> Matcher<'_> {
        Matcher {
            set: self,
            cache: HashMap::new(),
            memo: Vec::new(),
            open: Vec::new(),
        }
    }

    /// The rule's details (`Key: value` pairs): its own `details` template,
    /// else Hayabusa's default for the event's provider and id, else none.
    pub fn details(&self, rule: u32, ev: &EventView<'_>) -> Vec<(String, String)> {
        let r = &self.rules[rule as usize];
        let tpl = match &r.details {
            Some(t) => t.as_str(),
            None => match self
                .default_details
                .get(&(compile::lower(&ev.provider).into_owned(), ev.event_id))
            {
                Some(t) => t.as_str(),
                None => return Vec::new(),
            },
        };
        let e = eval::Ev::new(ev, 0);
        let mut out = Vec::new();
        for part in tpl.split('¦') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (k, v) = part.split_once(':').unwrap_or(("Details", part));
            let mut val = String::new();
            let mut rest = v.trim();
            while let Some(s) = rest.find('%') {
                val.push_str(&rest[..s]);
                let after = &rest[s + 1..];
                match after.find('%') {
                    Some(e2) => {
                        let name = &after[..e2];
                        let f = compile::resolve_field(name, &self.aliases);
                        let mut got = None;
                        e.each(&f, |i| {
                            got = Some(e.orig(i).to_string());
                            true
                        });
                        val.push_str(got.as_deref().unwrap_or("n/a"));
                        rest = &after[e2 + 1..];
                    }
                    None => {
                        val.push('%');
                        rest = after;
                    }
                }
            }
            val.push_str(rest);
            out.push((k.trim().to_string(), val));
        }
        out
    }
}

/// Per-thread matching state: caches the plan of each (channel, event id)
/// seen.
pub struct Matcher<'s> {
    set: &'s RuleSet,
    /// Event id -> (channel, plan); few channels per id.
    cache: LocalPlans,
    memo: Vec<u8>,
    /// Gated rules opened by a literal of the current event.
    open: Vec<bool>,
}

impl Matcher<'_> {
    /// Reference path: every candidate rule evaluated, no literal gate.
    /// Must give the same rules as [`Matcher::matches`] (checked in tests).
    #[doc(hidden)]
    pub fn matches_ungated(&mut self, ev: &EventView<'_>, out: &mut Vec<u32>) {
        let e = eval::Ev::new(ev, self.set.names);
        for r in self.set.candidates(&ev.channel, ev.event_id) {
            let rule = &self.set.rules[r as usize];
            self.memo.clear();
            self.memo.resize(rule.sels.len(), 0);
            if e.cond(&rule.cond, &rule.sels, &mut self.memo) {
                out.push(r);
            }
        }
    }

    /// Appends the rules matching `ev` to `out` (ascending rule index).
    pub fn matches(&mut self, ev: &EventView<'_>, out: &mut Vec<u32>) {
        let slot = self.cache.entry(ev.event_id).or_default();
        let plan = match slot.iter().find(|(c, _)| c.as_ref() == ev.channel.as_ref()) {
            Some((_, p)) => p.clone(),
            None => {
                let p = self.set.plan(&ev.channel, ev.event_id);
                slot.push((ev.channel.as_ref().into(), p.clone()));
                p
            }
        };
        if plan.always.is_empty() && plan.gated.is_empty() {
            return;
        }
        let e = eval::Ev::new(ev, self.set.names);
        let first = out.len();
        let run = |r: u32, memo: &mut Vec<u8>, out: &mut Vec<u32>| {
            let rule = &self.set.rules[r as usize];
            memo.clear();
            memo.resize(rule.sels.len(), 0);
            if e.cond(&rule.cond, &rule.sels, memo) {
                out.push(r);
            }
        };
        for &r in &plan.always {
            run(r, &mut self.memo, out);
        }
        if !plan.gated.is_empty() {
            self.open.clear();
            self.open.resize(plan.gated.len(), false);
            for (f, ac, rules) in &plan.fields {
                e.each(f, |i| {
                    for m in ac.find_overlapping_iter(e.low(i)) {
                        for &g in &rules[m.pattern().as_usize()] {
                            self.open[g as usize] = true;
                        }
                    }
                    false
                });
            }
            for (g, &r) in plan.gated.iter().enumerate() {
                if self.open[g] {
                    run(r, &mut self.memo, out);
                }
            }
            out[first..].sort_unstable();
        }
    }
}

#[cfg(test)]
mod tests;
