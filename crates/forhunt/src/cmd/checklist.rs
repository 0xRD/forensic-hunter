//! `checklist`: evaluates every check of the skill's detection checklists in
//! a single pass over the evidence and pre-fills the checklist status.
//!
//! For each check: does its log source exist in the evidence (events of its
//! channel and event ids)? If not: `LOG_SOURCE_MISSING`. Otherwise each of
//! its `forhunt search` queries is evaluated: any match gives `HIT?` (to be
//! confirmed by the analyst, with match counts and sample event ids), no
//! match gives `NO_HIT`. Queries using `stats`/`timeline`, and judgement
//! calls (thresholds, correlations, `NOT_APPLICABLE`), stay with the analyst.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use anyhow::Context;
use clap::Parser;
use forhunt_core::artifact::{Sink, UnitReport};
use forhunt_core::engine::Engine;
use forhunt_core::normalize::channel_matches;
use forhunt_core::{EventRef, EventView, Filter, Ts};
use serde::{Deserialize, Serialize};

use crate::cli::{ChecklistArgs, ChecklistFormat, Cli, Cmd};
use crate::common::{self, Ctx, Totals};

#[derive(Deserialize)]
struct File {
    checks: Vec<Check>,
}

#[derive(Deserialize, Clone)]
struct Check {
    id: String,
    title: String,
    tactic: String,
    channels: Vec<String>,
    event_ids: Vec<u32>,
    #[serde(default)]
    forhunt: Vec<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    verified: bool,
}

struct Query {
    text: String,
    filter: Option<Filter>,
}

/// Splits a command line like a POSIX shell (quotes and backslashes).
fn shell_split(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for d in chars.by_ref() {
                    if d == '\'' {
                        break;
                    }
                    cur.push(d);
                }
            }
            '"' => {
                in_word = true;
                while let Some(d) = chars.next() {
                    match d {
                        '"' => break,
                        '\\' if matches!(chars.peek(), Some('"' | '\\' | '$' | '`')) => {
                            cur.push(chars.next().unwrap_or('\\'))
                        }
                        _ => cur.push(d),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(d) = chars.next() {
                    cur.push(d);
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            _ => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

/// Compiles a `forhunt search ...` line into a filter; other commands
/// (stats, timeline) are left to the analyst.
fn compile(ctx: &Ctx, text: &str) -> Option<Filter> {
    let mut argv = shell_split(text);
    // Drop pipes and redirections.
    if let Some(i) = argv.iter().position(|a| a == "|" || a == ">") {
        argv.truncate(i);
    }
    if argv.first().map(String::as_str) != Some("forhunt")
        || argv.get(1).map(String::as_str) != Some("search")
    {
        return None;
    }
    for a in argv.iter_mut().skip(2) {
        if a.starts_with('<') && a.ends_with('>') {
            *a = ".".into();
        }
    }
    match Cli::try_parse_from(&argv).ok()?.cmd {
        Cmd::Search(s) => ctx.filter(&s.filter).ok(),
        _ => None,
    }
}

#[derive(Default, Clone)]
struct Counts {
    source: u64,
    hits: Vec<u64>,
    samples: Vec<Vec<(Ts, EventRef)>>,
}

struct Part {
    counts: Vec<Counts>,
}

struct PartSink<'a> {
    checks: &'a [Check],
    queries: &'a [Vec<Query>],
    by_eid: &'a HashMap<u32, Vec<usize>>,
    part: &'a mut Part,
}

impl Sink for PartSink<'_> {
    fn event(&mut self, ev: &EventView<'_>) {
        let Some(idx) = self.by_eid.get(&ev.event_id) else {
            return;
        };
        for &ci in idx {
            let c = &self.checks[ci];
            if !c.channels.iter().any(|ch| channel_matches(ch, &ev.channel)) {
                continue;
            }
            let k = &mut self.part.counts[ci];
            k.source += 1;
            for (qi, q) in self.queries[ci].iter().enumerate() {
                if let Some(f) = &q.filter
                    && f.matches(ev)
                {
                    k.hits[qi] += 1;
                    let s = &mut k.samples[qi];
                    s.push((ev.ts, ev.id));
                    if s.len() > 6 {
                        s.sort();
                        s.truncate(3);
                    }
                }
            }
        }
    }
}

#[derive(Serialize)]
struct QueryResult {
    query: String,
    evaluated: bool,
    matches: u64,
    samples: Vec<String>,
}

#[derive(Serialize)]
struct CheckResult {
    id: String,
    title: String,
    tactic: String,
    channels: Vec<String>,
    event_ids: Vec<u32>,
    severity: Option<String>,
    verified: bool,
    status: String,
    source_events: u64,
    queries: Vec<QueryResult>,
}

pub fn run(a: ChecklistArgs) -> anyhow::Result<()> {
    let ctx = Ctx::new(&a.common)?;
    let started = Instant::now();
    let text = std::fs::read_to_string(&a.checks)
        .with_context(|| format!("cannot read {}", a.checks.display()))?;
    let file: File = serde_json::from_str(&text)
        .with_context(|| format!("invalid checklists file {}", a.checks.display()))?;
    let checks: Vec<Check> = file
        .checks
        .into_iter()
        .filter(|c| {
            a.tactic.is_empty() || a.tactic.iter().any(|t| t.eq_ignore_ascii_case(&c.tactic))
        })
        .collect();
    let queries: Vec<Vec<Query>> = checks
        .iter()
        .map(|c| {
            c.forhunt
                .iter()
                .map(|t| Query {
                    text: t.clone(),
                    filter: compile(&ctx, t),
                })
                .collect()
        })
        .collect();
    let mut by_eid: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, c) in checks.iter().enumerate() {
        for e in &c.event_ids {
            by_eid.entry(*e).or_default().push(i);
        }
    }
    for v in by_eid.values_mut() {
        v.dedup();
    }
    let inputs = ctx.open(&a.paths)?;
    let progress = common::Progress::new(ctx.progress, inputs.bytes);
    let empty = || Part {
        counts: queries
            .iter()
            .map(|q| Counts {
                source: 0,
                hits: vec![0; q.len()],
                samples: vec![Vec::new(); q.len()],
            })
            .collect(),
    };
    let mut total = empty();
    let mut totals = Totals::default();
    let stop = AtomicBool::new(false);
    Engine::new(&ctx.pool).run(
        &inputs.sources,
        &stop,
        |u, src| {
            let mut part = empty();
            let rep: UnitReport = {
                let mut sink = PartSink {
                    checks: &checks,
                    queries: &queries,
                    by_eid: &by_eid,
                    part: &mut part,
                };
                src.parse_unit(u.unit, &mut sink)
            };
            progress.add(common::unit_bytes(src), rep.records);
            (part, rep)
        },
        |u, (part, rep)| {
            totals.add(inputs.sources[u.source].path(), &rep);
            for (t, p) in total.counts.iter_mut().zip(part.counts) {
                t.source += p.source;
                for (qi, h) in p.hits.iter().enumerate() {
                    t.hits[qi] += h;
                }
                for (qi, s) in p.samples.into_iter().enumerate() {
                    t.samples[qi].extend(s);
                    t.samples[qi].sort();
                    t.samples[qi].truncate(3);
                }
            }
        },
    );
    progress.clear();

    let results: Vec<CheckResult> = checks
        .iter()
        .zip(&queries)
        .zip(&total.counts)
        .map(|((c, qs), k)| {
            let any_eval = qs.iter().any(|q| q.filter.is_some());
            let hit = k.hits.iter().any(|h| *h > 0);
            let status = if k.source == 0 {
                "LOG_SOURCE_MISSING"
            } else if hit {
                "HIT?"
            } else if any_eval {
                "NO_HIT"
            } else {
                "REVIEW"
            };
            CheckResult {
                id: c.id.clone(),
                title: c.title.clone(),
                tactic: c.tactic.clone(),
                channels: c.channels.clone(),
                event_ids: c.event_ids.clone(),
                severity: c.severity.clone(),
                verified: c.verified,
                status: status.into(),
                source_events: k.source,
                queries: qs
                    .iter()
                    .enumerate()
                    .map(|(qi, q)| QueryResult {
                        query: q.text.clone(),
                        evaluated: q.filter.is_some(),
                        matches: k.hits[qi],
                        samples: k.samples[qi].iter().map(|(_, id)| id.to_string()).collect(),
                    })
                    .collect(),
            }
        })
        .collect();

    let mut out = common::output(&a.output)?;
    let body = match a.format {
        ChecklistFormat::Json => serde_json::to_string_pretty(&results)? + "\n",
        ChecklistFormat::Md => markdown(&results, &a.paths),
    };
    common::write_out(&mut *out, body.as_bytes())?;
    common::flush(&mut *out)?;
    totals.finish(&ctx, &inputs, started, "scanned")
}

fn markdown(results: &[CheckResult], paths: &[String]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "# Checklist status\n");
    let _ = writeln!(
        s,
        "Pre-filled by `forhunt checklist` over `{}`. Review every `HIT?` (confirm as HIT or downgrade to \
         NO_HIT with the reason), resolve `REVIEW` rows by hand, and change `LOG_SOURCE_MISSING` to \
         `NOT_APPLICABLE` where the check cannot apply (for example DC-only checks on a workstation).\n",
        paths.join(" ")
    );
    let mut tactic = "";
    let mut summary: Vec<(String, [u32; 5])> = Vec::new();
    for r in results {
        if r.tactic != tactic {
            tactic = &r.tactic;
            let _ = writeln!(s, "\n## {}\n", r.tactic);
            let _ = writeln!(s, "| Id | Check | Source | Status | Evidence / reason |");
            let _ = writeln!(s, "|---|---|---|---|---|");
            summary.push((r.tactic.clone(), [0; 5]));
        }
        let ids = r
            .event_ids
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let evidence = match r.status.as_str() {
            "LOG_SOURCE_MISSING" => {
                format!("no {} {} events in the evidence", r.channels.join("/"), ids)
            }
            "REVIEW" => format!(
                "{} source events; queries need manual evaluation",
                r.source_events
            ),
            _ => r
                .queries
                .iter()
                .filter(|q| q.evaluated)
                .map(|q| {
                    if q.matches > 0 {
                        format!("{} match(es), e.g. {}", q.matches, q.samples.join(" "))
                    } else {
                        format!("0 matches: `{}`", q.query.replace('|', "\\|"))
                    }
                })
                .collect::<Vec<_>>()
                .join("; "),
        };
        let _ = writeln!(
            s,
            "| {} | {} | {} {} | {} | {} |",
            r.id,
            r.title.replace('|', "/"),
            r.channels.join(", "),
            ids,
            r.status,
            evidence
        );
        let slot = match r.status.as_str() {
            "HIT?" => 0,
            "NO_HIT" => 1,
            "LOG_SOURCE_MISSING" => 3,
            _ => 4,
        };
        if let Some(last) = summary.last_mut() {
            last.1[slot] += 1;
        }
    }
    let _ = writeln!(s, "\n## Summary\n");
    let _ = writeln!(
        s,
        "| Tactic | HIT? | NO_HIT | NOT_APPLICABLE | LOG_SOURCE_MISSING | REVIEW |"
    );
    let _ = writeln!(s, "|---|---|---|---|---|---|");
    for (t, c) in summary {
        let _ = writeln!(
            s,
            "| {t} | {} | {} | {} | {} | {} |",
            c[0], c[1], c[2], c[3], c[4]
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::shell_split;

    #[test]
    fn splits_like_a_shell() {
        assert_eq!(
            shell_split(r#"forhunt search <paths> --field 'CommandLine~-enc ' -r "a\"b" x\ y"#),
            vec![
                "forhunt",
                "search",
                "<paths>",
                "--field",
                "CommandLine~-enc ",
                "-r",
                "a\"b",
                "x y"
            ]
        );
    }
}
