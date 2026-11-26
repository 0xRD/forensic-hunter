//! Loading rule folders: Sigma / Hayabusa YAML files, and Hayabusa's
//! `config/` files when the folder is a `hayabusa-rules` checkout.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use super::compile::{self, Cond, Ctx, FieldRef, FieldTest, Kind, M, Sel, Sys};
use super::logsource::{self, Mapped, Variant};
use super::yaml::{self, Node};
use super::{Rule, RuleSet, level_rank};

#[derive(Debug, Clone)]
pub struct LoadOptions {
    /// Lowest level kept (1 informational .. 5 critical).
    pub min_level: u8,
    /// Keep the rules of `noisy_rules.txt` (off in Hayabusa by default).
    pub noisy: bool,
    /// Keep `deprecated` and `unsupported` rules.
    pub deprecated: bool,
    /// Only these rule ids (all when empty).
    pub ids: Vec<String>,
    /// How rules use their `logsource` (default for every path).
    pub profile: Profile,
    /// Per rule folder or file: its own profile (longest path prefix wins).
    pub profiles: Vec<(PathBuf, Profile)>,
}

impl Default for LoadOptions {
    fn default() -> Self {
        LoadOptions {
            min_level: 1,
            noisy: false,
            deprecated: false,
            ids: Vec::new(),
            profile: Profile::Auto,
            profiles: Vec::new(),
        }
    }
}

/// How a rule's `logsource` becomes the events it is tried on (D-067).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Profile {
    /// Rules that name a `Channel` run as written (Hayabusa rules, forhunt
    /// rules); the others are mapped from their logsource (SigmaHQ and most
    /// public repositories).
    #[default]
    Auto,
    /// Always mapped from the logsource (added to any Channel they name).
    Sigma,
    /// Never mapped: the detection alone decides.
    AsWritten,
}

impl Profile {
    pub fn name(self) -> &'static str {
        match self {
            Profile::Auto => "auto",
            Profile::Sigma => "sigma",
            Profile::AsWritten => "as-written",
        }
    }

    pub fn parse(s: &str) -> Option<Profile> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Profile::Auto),
            "sigma" | "logsource" => Some(Profile::Sigma),
            "as-written" | "aswritten" | "hayabusa" | "raw" => Some(Profile::AsWritten),
            _ => None,
        }
    }
}

impl LoadOptions {
    fn profile_of(&self, file: &Path) -> Profile {
        self.profiles
            .iter()
            .filter(|(p, _)| file.starts_with(p))
            .max_by_key(|(p, _)| p.components().count())
            .map_or(self.profile, |(_, x)| *x)
    }
}

/// What happened to every file: nothing is dropped silently.
#[derive(Debug, Default, Clone)]
pub struct LoadReport {
    pub files: usize,
    pub loaded: usize,
    /// Reason -> number of rules skipped by design (status, exclusions,
    /// level, unsupported kinds).
    pub skipped: BTreeMap<String, usize>,
    /// Files or rules that could not be read or compiled.
    pub errors: Vec<(PathBuf, String)>,
    /// Hayabusa `config/` folders used.
    pub config: Vec<PathBuf>,
}

impl LoadReport {
    pub fn skipped_total(&self) -> usize {
        self.skipped.values().sum()
    }
}

const CONFIG_FILES: [&str; 3] = ["eventkey_alias.txt", "exclude_rules.txt", "noisy_rules.txt"];

/// A Hayabusa-style `config/` folder (exclusions, aliases, or `expand/`
/// placeholder values): read, and never walked for rules.
fn is_config_dir(p: &Path) -> bool {
    p.file_name().is_some_and(|n| n == "config")
        && (CONFIG_FILES.iter().any(|f| p.join(f).is_file()) || p.join("expand").is_dir())
}

/// A SigmaHQ/sigma checkout: `rules/` next to `rules-*` or `regression_data/`.
fn is_sigmahq_checkout(p: &Path) -> bool {
    p.join("rules").is_dir()
        && (p.join("rules-emerging-threats").is_dir() || p.join("regression_data").is_dir())
}

/// A hayabusa-rules checkout: its rules are only under `hayabusa/` and
/// `sigma/` (not the test fixtures under `scripts/`).
fn is_checkout(p: &Path) -> bool {
    is_config_dir(&p.join("config")) && (p.join("sigma").is_dir() || p.join("hayabusa").is_dir())
}

/// The Hayabusa config folder of a rules path: `config/` in it, or in one
/// of its two parents (`hayabusa-rules/sigma/builtin` -> `hayabusa-rules/config`).
fn config_of(p: &Path) -> Option<PathBuf> {
    let mut cur = Some(if p.is_dir() { p } else { p.parent()? });
    for _ in 0..3 {
        let d = cur?;
        let c = d.join("config");
        if is_config_dir(&c) {
            return Some(c);
        }
        cur = d.parent();
    }
    None
}

#[derive(Default)]
struct Config {
    exclude: HashSet<String>,
    noisy: HashSet<String>,
    tuning: HashMap<String, u8>,
    aliases: HashMap<String, String>,
    details: HashMap<(String, u32), String>,
    expand: HashMap<String, Vec<String>>,
}

/// Lines without comments (`# ...`) and blanks.
fn lines(p: &Path) -> Vec<String> {
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

impl Config {
    fn read(&mut self, dir: &Path) {
        for l in lines(&dir.join("exclude_rules.txt")) {
            self.exclude
                .insert(l.split_whitespace().next().unwrap_or("").to_string());
        }
        for l in lines(&dir.join("noisy_rules.txt")) {
            self.noisy
                .insert(l.split_whitespace().next().unwrap_or("").to_string());
        }
        for l in lines(&dir.join("level_tuning.txt")).into_iter().skip(1) {
            if let Some((id, lvl)) = l.split_once(',') {
                let r = level_rank(lvl);
                if r > 0 {
                    self.tuning.insert(id.trim().to_string(), r);
                }
            }
        }
        for l in lines(&dir.join("eventkey_alias.txt")).into_iter().skip(1) {
            if let Some((a, k)) = l.split_once(',') {
                self.aliases
                    .entry(a.trim().to_string())
                    .or_insert_with(|| k.trim().to_string());
            }
        }
        // `Provider, EID, Details` (the details may contain commas).
        for l in std::fs::read_to_string(dir.join("default_details.txt"))
            .unwrap_or_default()
            .lines()
            .skip(1)
        {
            let mut it = l.splitn(3, ',');
            if let (Some(p), Some(e), Some(d)) = (it.next(), it.next(), it.next())
                && let Ok(e) = e.trim().parse::<u32>()
            {
                self.details
                    .entry((p.trim().to_lowercase(), e))
                    .or_insert_with(|| d.trim().to_string());
            }
        }
        if let Ok(rd) = std::fs::read_dir(dir.join("expand")) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "txt")
                    && let Some(stem) = p.file_stem()
                {
                    self.expand
                        .entry(stem.to_string_lossy().into_owned())
                        .or_default()
                        .extend(lines(&p));
                }
            }
        }
    }
}

fn rule_files(paths: &[PathBuf], report: &mut LoadReport) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_file() {
            out.push(p.clone());
            continue;
        }
        if !p.is_dir() {
            report
                .errors
                .push((p.clone(), "no such file or folder".into()));
            continue;
        }
        // A hayabusa-rules checkout: only its rule folders (not the test
        // fixtures under scripts/).
        let roots: Vec<PathBuf> = if is_sigmahq_checkout(p) {
            // SigmaHQ: the rule folders, not deprecated/, unsupported/,
            // tests or regression data.
            let mut v: Vec<PathBuf> = std::fs::read_dir(p)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|d| {
                    d.is_dir()
                        && d.file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with("rules"))
                })
                .collect();
            v.sort();
            v
        } else if is_checkout(p) {
            ["hayabusa", "sigma"]
                .iter()
                .map(|d| p.join(d))
                .filter(|d| d.is_dir())
                .collect()
        } else {
            vec![p.clone()]
        };
        let mut files: Vec<PathBuf> = Vec::new();
        for root in &roots {
            let walk = walkdir::WalkDir::new(root)
                .follow_links(true)
                .into_iter()
                .filter_entry(|e| {
                    let n = e.file_name().to_string_lossy();
                    // Nested hayabusa-rules checkouts are roots of their own
                    // (see `expand_roots`).
                    !(e.file_type().is_dir()
                        && (n.starts_with('.') && e.depth() > 0
                            || is_config_dir(e.path())
                            || (e.depth() > 0
                                && (is_checkout(e.path()) || is_sigmahq_checkout(e.path())))))
                });
            for e in walk {
                match e {
                    Ok(e) if e.file_type().is_file() => {
                        let ok = e.path().extension().is_some_and(|x| {
                            x.eq_ignore_ascii_case("yml") || x.eq_ignore_ascii_case("yaml")
                        });
                        if ok {
                            files.push(e.into_path());
                        }
                    }
                    Ok(_) => {}
                    Err(err) => report.errors.push((p.clone(), err.to_string())),
                }
            }
        }
        files.sort();
        out.extend(files);
    }
    let mut seen = HashSet::new();
    out.retain(|p| seen.insert(p.canonicalize().unwrap_or(p.clone())));
    out
}

enum Outcome {
    Rule(Box<Rule>),
    /// A hidden base rule and the correlation over it (`| count()`).
    Pair(Box<Rule>, Box<Rule>),
    Skip(String),
    Error(String),
}

fn text(n: Option<&Node>) -> String {
    match n {
        Some(Node::Str(s)) => s.clone(),
        Some(Node::Seq(v)) => v
            .iter()
            .filter_map(Node::as_str)
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
}

fn list(n: Option<&Node>) -> Vec<String> {
    n.map(Node::strings).unwrap_or_default()
}

/// A selection value (or list of maps) names `Channel`.
fn mentions_channel(n: &Node) -> bool {
    match n {
        Node::Map(m) => m
            .iter()
            .any(|(k, _)| k.split('|').next() == Some("Channel")),
        Node::Seq(v) => v.iter().any(mentions_channel),
        _ => false,
    }
}

/// Shifts selection indexes by `k` (selections of a later variant).
fn offset(c: Cond, k: usize) -> Cond {
    match c {
        Cond::Sel(i) => Cond::Sel(i + k),
        Cond::Not(x) => Cond::Not(Box::new(offset(*x, k))),
        Cond::And(xs) => Cond::And(xs.into_iter().map(|x| offset(x, k)).collect()),
        Cond::Or(xs) => Cond::Or(xs.into_iter().map(|x| offset(x, k)).collect()),
    }
}

/// The variant's channel, event ids and extra condition, as a selection.
fn scope_sel(v: &Variant) -> Sel {
    let eq = |field: FieldRef, vals: Vec<String>| FieldTest {
        field,
        ms: vals
            .into_iter()
            .map(|x| M::Str {
                kind: Kind::Eq,
                needle: x.to_lowercase().into(),
                cased: false,
                finder: None,
            })
            .collect(),
        all: false,
    };
    let mut tests = vec![eq(
        FieldRef::Sys(Sys::Channel),
        v.channels.iter().map(|c| c.to_string()).collect(),
    )];
    if !v.eids.is_empty() {
        tests.push(eq(
            FieldRef::Sys(Sys::EventId),
            v.eids.iter().map(|e| e.to_string()).collect(),
        ));
    }
    if let Some((f, vals)) = v.extra {
        tests.push(eq(
            FieldRef::Payload(f.into(), u32::MAX),
            vals.iter().map(|x| x.to_string()).collect(),
        ));
    }
    Sel::And(tests)
}

/// The descriptive part of a rule (no detection yet).
fn meta(doc: &Node, path: &Path, id: String, level: u8, status: String) -> Rule {
    Rule {
        title: text(doc.get("title")),
        name: text(doc.get("name")),
        level,
        status,
        author: text(doc.get("author")),
        description: text(doc.get("description")).trim().to_string(),
        tags: list(doc.get("tags")),
        references: list(doc.get("references")),
        falsepositives: list(doc.get("falsepositives")),
        date: text(doc.get("date")),
        modified: text(doc.get("modified")),
        ruletype: text(doc.get("ruletype")),
        details: doc
            .get("details")
            .and_then(Node::as_str)
            .map(str::to_string),
        fields: Vec::new(),
        path: path.to_path_buf(),
        sels: Vec::new(),
        // Correlations are never matched per event.
        cond: Cond::Or(Vec::new()),
        chans: Some(Vec::new()),
        eids: Some(Vec::new()),
        req: None,
        hidden: false,
        corr: None,
        derived_from: doc
            .get("related")
            .map(|r| match r {
                Node::Seq(v) => v
                    .iter()
                    .filter(|x| x.get("type").and_then(Node::as_str) == Some("derived"))
                    .filter_map(|x| {
                        x.get("id")
                            .and_then(Node::as_str)
                            .map(str::to_ascii_lowercase)
                    })
                    .collect(),
                _ => Vec::new(),
            })
            .unwrap_or_default(),
        id,
    }
}

fn compile_doc(doc: &Node, path: &Path, cfg: &Config, opts: &LoadOptions) -> Vec<Outcome> {
    let id = text(doc.get("id"));
    let status = text(doc.get("status")).to_ascii_lowercase();
    // A `correlation:` map; some repositories use the key for a note.
    if let Some(c @ Node::Map(_)) = doc.get("correlation") {
        if !opts.deprecated && (status == "deprecated" || status == "unsupported") {
            return vec![Outcome::Skip(format!("status {status}"))];
        }
        let level = level_rank(&text(doc.get("level")));
        return vec![match super::corr::parse(c) {
            Ok(c) => {
                let mut r = meta(doc, path, id, level, status);
                r.corr = Some(Box::new(c));
                Outcome::Rule(Box::new(r))
            }
            Err(e) => Outcome::Error(format!("correlation: {e}")),
        }];
    }
    vec![compile_detection(doc, path, cfg, opts, id, status)]
}

fn compile_detection(
    doc: &Node,
    path: &Path,
    cfg: &Config,
    opts: &LoadOptions,
    id: String,
    status: String,
) -> Outcome {
    let Some(det) = doc.get("detection") else {
        return Outcome::Skip("not a rule (no detection)".into());
    };
    if !opts.deprecated && (status == "deprecated" || status == "unsupported") {
        return Outcome::Skip(format!("status {status}"));
    }
    if cfg.exclude.contains(&id) {
        return Outcome::Skip("excluded (exclude_rules.txt)".into());
    }
    if !opts.noisy && cfg.noisy.contains(&id) {
        return Outcome::Skip("noisy (noisy_rules.txt)".into());
    }
    let level = cfg
        .tuning
        .get(&id)
        .copied()
        .unwrap_or_else(|| level_rank(&text(doc.get("level"))))
        // No level: informational (shown, never above the analyst's floor).
        .max(1);
    let Node::Map(det) = det else {
        return Outcome::Error("`detection` is not a map".into());
    };
    // Where the rule's events are: as written, or one variant per log the
    // logsource maps to.
    let profile = opts.profile_of(path);
    let names_channel = det
        .iter()
        .any(|(k, v)| k != "condition" && mentions_channel(v));
    let variants: Vec<Option<Variant>> =
        if profile == Profile::AsWritten || (profile == Profile::Auto && names_channel) {
            vec![None]
        } else {
            let ls = doc.get("logsource");
            let get = |k: &str| ls.and_then(|l| l.get(k));
            match logsource::map(
                get("product").and_then(Node::as_str),
                &list(get("category")),
                &list(get("service")),
            ) {
                Mapped::Any => vec![None],
                Mapped::Variants(v) => v.into_iter().map(Some).collect(),
                Mapped::Unsupported(why) => return Outcome::Skip(why),
            }
        };
    // `selection | count(f) by g > N`: the part before `|` is a hidden base
    // rule, the aggregation a correlation over it (D-068).
    let mut aggregation: Option<String> = None;
    let mut names = Vec::new();
    let mut sels = Vec::new();
    let mut alts = Vec::new();
    for var in &variants {
        let cx = Ctx {
            aliases: &cfg.aliases,
            expand: &cfg.expand,
            variant: var.as_ref(),
        };
        let first = sels.len();
        names.clear();
        let mut cond_text: Vec<String> = Vec::new();
        for (k, v) in det {
            match k.as_str() {
                "condition" => {
                    cond_text = v
                        .strings()
                        .into_iter()
                        .map(|c| match c.split_once('|') {
                            Some((left, agg)) => {
                                aggregation = Some(agg.trim().to_string());
                                left.trim().to_string()
                            }
                            None => c,
                        })
                        .collect()
                }
                "timeframe" => {}
                _ => match compile::selection(v, &cx) {
                    Ok(s) => {
                        names.push(k.clone());
                        sels.push(s);
                    }
                    Err(e) if e.starts_with("expand placeholder") => {
                        return Outcome::Skip(
                            "expand placeholder without values (config/expand/)".into(),
                        );
                    }
                    Err(e) => return Outcome::Error(format!("selection `{k}`: {e}")),
                },
            }
        }
        if cond_text.is_empty() {
            return Outcome::Error("no condition".into());
        }
        let mut conds = Vec::new();
        for c in &cond_text {
            match compile::condition(c, &names) {
                Ok(c) => conds.push(offset(c, first)),
                Err(e) if e.starts_with("aggregation") => {
                    return Outcome::Skip("count() aggregation (not supported)".into());
                }
                Err(e) => return Outcome::Error(format!("condition: {e}")),
            }
        }
        let cond = if conds.len() == 1 {
            conds.pop().unwrap()
        } else {
            Cond::Or(conds)
        };
        alts.push(match var {
            None => cond,
            Some(v) => {
                sels.push(scope_sel(v));
                Cond::And(vec![Cond::Sel(sels.len() - 1), cond])
            }
        });
    }
    let cond = if alts.len() == 1 {
        alts.pop().unwrap()
    } else {
        Cond::Or(alts)
    };
    let scopes: Vec<_> = sels.iter().map(compile::sel_scope).collect();
    let scope = compile::cond_scope(&cond, &scopes);
    let mut fields = Vec::new();
    for s in &sels {
        compile::tested_fields(s, &mut fields);
    }
    let mut r = meta(doc, path, id.clone(), level, status);
    r.fields = fields;
    r.sels = sels;
    r.cond = cond;
    r.chans = scope.chans.map(|s| s.into_iter().collect());
    r.eids = scope.eids.map(|s| s.into_iter().collect());
    if let Some(agg) = aggregation {
        let timeframe = doc
            .get("detection")
            .and_then(|d| d.get("timeframe"))
            .or_else(|| doc.get("timeframe"))
            .and_then(Node::as_str);
        // The hidden base rule is linked by this id: unique even when the
        // rule has none.
        let base = if id.is_empty() {
            format!("{}#{}:base", path.display(), r.title)
        } else {
            format!("{id}:base")
        };
        return match super::corr::parse_aggregation(&agg, timeframe, &base) {
            Ok(c) => {
                let mut corr = meta(doc, path, id, level, r.status.clone());
                corr.corr = Some(Box::new(c));
                r.id = base.clone();
                r.name = base;
                Outcome::Pair(Box::new(r), Box::new(corr))
            }
            Err(e) => Outcome::Error(e),
        };
    }
    Outcome::Rule(Box::new(r))
}

/// YAML, read again with `*values` quoted when they were taken as aliases
/// (a common slip: a wildcard meant).
fn parse_lenient(text: &str) -> Result<Vec<Node>, String> {
    yaml::parse(text).or_else(|e| {
        if e.contains("unknown anchor") {
            yaml::parse(&quote_star_values(text)).map_err(|_| e)
        } else {
            Err(e)
        }
    })
}

/// Quotes plain scalars that start with `*` (`- *\\evil.exe`,
/// `Image: *\\x.exe`): wildcards, not aliases.
fn quote_star_values(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 64);
    for line in text.lines() {
        let t = line.trim_start();
        let lead = &line[..line.len() - t.len()];
        let (head, val) = if let Some(rest) = t.strip_prefix("- ") {
            (format!("{lead}- "), rest)
        } else if let Some(i) = t.find(": ") {
            (format!("{lead}{}: ", &t[..i]), &t[i + 2..])
        } else {
            (String::new(), "")
        };
        let v = val.trim_end();
        if v.starts_with('*') && !v.contains(" #") {
            out.push_str(&head);
            out.push('\'');
            out.push_str(&v.replace('\'', "''"));
            out.push('\'');
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

fn compile_file(path: &Path, cfg: &Config, opts: &LoadOptions) -> Vec<Outcome> {
    let text = match std::fs::read(path) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => return vec![Outcome::Error(e.to_string())],
    };
    let parsed = parse_lenient(&text);
    match parsed {
        Ok(docs) if docs.is_empty() => vec![Outcome::Skip("not a rule (empty)".into())],
        Ok(docs) => docs
            .iter()
            .flat_map(|d| compile_doc(d, path, cfg, opts))
            .collect(),
        Err(e) => vec![Outcome::Error(format!("YAML: {e}"))],
    }
}

/// The paths, plus every hayabusa-rules checkout directly inside a folder
/// (`rules/hayabusa-rules` next to `rules/custom`): each checkout brings its
/// own `config/`.
fn expand_roots(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in paths {
        out.push(p.clone());
        if p.is_dir()
            && !is_checkout(p)
            && let Ok(rd) = std::fs::read_dir(p)
        {
            let mut kids: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|c| {
                    c.is_dir() && (is_config_dir(&c.join("config")) || is_sigmahq_checkout(c))
                })
                .collect();
            kids.sort();
            out.extend(kids);
        }
    }
    out
}

/// Loads every `.yml` / `.yaml` rule under `paths` (files or folders).
/// Rules with the same `id` are loaded once (the first path wins).
pub fn load(paths: &[PathBuf], opts: &LoadOptions) -> (RuleSet, LoadReport) {
    let mut report = LoadReport::default();
    let mut cfg = Config::default();
    let paths = &expand_roots(paths);
    for p in paths {
        if let Some(c) = config_of(p)
            && !report.config.contains(&c)
        {
            cfg.read(&c);
            report.config.push(c);
        }
    }
    let files = rule_files(paths, &mut report);
    report.files = files.len();
    let outcomes: Vec<(usize, Vec<Outcome>)> = files
        .par_iter()
        .enumerate()
        .map(|(i, p)| (i, compile_file(p, &cfg, opts)))
        .collect();
    let mut rules = Vec::new();
    let mut ids = HashSet::new();
    for (i, os) in outcomes {
        for o in os {
            match o {
                Outcome::Rule(r) => {
                    if !r.id.is_empty() && !ids.insert(r.id.to_ascii_lowercase()) {
                        *report.skipped.entry("duplicate id".into()).or_default() += 1;
                        continue;
                    }
                    rules.push(*r);
                }
                Outcome::Pair(base, corr) => {
                    if !corr.id.is_empty() && !ids.insert(corr.id.to_ascii_lowercase()) {
                        *report.skipped.entry("duplicate id".into()).or_default() += 1;
                        continue;
                    }
                    rules.push(*base);
                    rules.push(*corr);
                }
                Outcome::Skip(why) => *report.skipped.entry(why).or_default() += 1,
                Outcome::Error(e) => report.errors.push((files[i].clone(), e)),
            }
        }
    }
    let rules = finalize(rules, opts, &mut report);
    report.loaded = rules.iter().filter(|r| !r.hidden).count();
    (RuleSet::build(rules, cfg.details, cfg.aliases), report)
}

/// Compiles the rules of one YAML text (no Hayabusa config): for tests and
/// for checking a rule being written.
pub fn load_str(text: &str, opts: &LoadOptions) -> (RuleSet, LoadReport) {
    let cfg = Config::default();
    let mut report = LoadReport {
        files: 1,
        ..Default::default()
    };
    let path = PathBuf::from("<text>");
    let outs = match parse_lenient(text) {
        Ok(docs) => docs
            .iter()
            .flat_map(|d| compile_doc(d, &path, &cfg, opts))
            .collect(),
        Err(e) => vec![Outcome::Error(format!("YAML: {e}"))],
    };
    let mut rules = Vec::new();
    for o in outs {
        match o {
            Outcome::Rule(r) => rules.push(*r),
            Outcome::Pair(a, b) => {
                rules.push(*a);
                rules.push(*b);
            }
            Outcome::Skip(why) => *report.skipped.entry(why).or_default() += 1,
            Outcome::Error(e) => report.errors.push((path.clone(), e)),
        }
    }
    let rules = finalize(rules, opts, &mut report);
    report.loaded = rules.iter().filter(|r| !r.hidden).count();
    (RuleSet::build(rules, cfg.details, cfg.aliases), report)
}

/// Links correlations to their rules, then applies the level and id
/// filters: a correlation kept keeps its rules (hidden unless `generate`).
fn finalize(rules: Vec<Rule>, opts: &LoadOptions, report: &mut LoadReport) -> Vec<Rule> {
    let mut by_ref: HashMap<String, usize> = HashMap::new();
    for (i, r) in rules.iter().enumerate() {
        for k in [&r.id, &r.name] {
            if !k.is_empty() {
                by_ref.entry(k.to_ascii_lowercase()).or_insert(i);
            }
        }
    }
    // A correlation without a level takes its rules' highest.
    let mut rules = rules;
    for i in 0..rules.len() {
        if rules[i].level == 0
            && let Some(c) = &rules[i].corr
        {
            let lvl = c
                .refs
                .iter()
                .filter_map(|x| by_ref.get(&x.to_ascii_lowercase()))
                .map(|&k| rules[k].level)
                .max()
                .unwrap_or(1);
            rules[i].level = lvl.max(1);
        }
    }
    let selected =
        |r: &Rule| opts.ids.is_empty() || opts.ids.iter().any(|x| x.eq_ignore_ascii_case(&r.id));
    let mut keep = vec![false; rules.len()];
    let mut hidden = vec![false; rules.len()];
    let mut links: Vec<Option<Vec<usize>>> = vec![None; rules.len()];
    for (i, r) in rules.iter().enumerate() {
        if let Some(c) = &r.corr {
            let found: Option<Vec<usize>> = c
                .refs
                .iter()
                .map(|x| by_ref.get(&x.to_ascii_lowercase()).copied())
                .collect();
            match found {
                Some(v) if v.iter().all(|&k| rules[k].corr.is_none()) => links[i] = Some(v),
                Some(_) => report.errors.push((
                    r.path.clone(),
                    "correlation of correlations is not supported".into(),
                )),
                None => report.errors.push((
                    r.path.clone(),
                    format!(
                        "correlation `{}` names a rule that is not loaded: {}",
                        r.title,
                        c.refs.join(", ")
                    ),
                )),
            }
        }
    }
    for (i, r) in rules.iter().enumerate() {
        let ok = r.corr.is_none() || links[i].is_some();
        keep[i] = ok && r.level >= opts.min_level && selected(r);
    }
    // A rule whose converted copy runs too (hayabusa-rules keeps the
    // SigmaHQ id in `related: derived`): the copy runs, not both. Only a
    // copy that is kept counts (`--rule-id <sigma id>`, a copy whose level
    // was tuned down), and a `| count()` rule's base goes with it.
    let derived: HashSet<String> = rules
        .iter()
        .enumerate()
        .filter(|&(i, _)| keep[i])
        .flat_map(|(_, r)| r.derived_from.iter().cloned())
        .collect();
    let superseded: Vec<bool> = rules
        .iter()
        .map(|r| {
            let id = r.id.to_ascii_lowercase();
            derived.contains(&id)
                || id
                    .strip_suffix(":base")
                    .is_some_and(|b| derived.contains(b))
        })
        .collect();
    for i in 0..rules.len() {
        keep[i] &= !superseded[i];
    }
    // Rules a kept correlation uses: kept, and hidden unless it has
    // `generate: true` (Sigma: its rules alert only through it) or they
    // were not kept on their own.
    let own = keep.clone();
    for (i, r) in rules.iter().enumerate() {
        if let (true, Some(v), Some(c)) = (keep[i], &links[i], &r.corr) {
            for &b in v {
                if !own[b] || !c.generate {
                    hidden[b] = true;
                }
                keep[b] = true;
            }
        }
    }
    // Counted once the correlations took the rules they need.
    for (i, r) in rules.iter().enumerate() {
        if keep[i] || (r.corr.is_some() && links[i].is_none()) {
            continue;
        }
        let why = if superseded[i] {
            "converted copy loaded too (related: derived)"
        } else if r.level < opts.min_level {
            "below the minimum level"
        } else {
            "not selected"
        };
        *report.skipped.entry(why.into()).or_default() += 1;
    }
    // New indexes, and the correlations' rule indexes in them.
    let mut new_ix = vec![u32::MAX; rules.len()];
    let mut n = 0;
    for i in 0..rules.len() {
        if keep[i] {
            new_ix[i] = n;
            n += 1;
        }
    }
    let authors: Vec<String> = rules.iter().map(|r| r.author.clone()).collect();
    let mut out = Vec::with_capacity(n as usize);
    for (i, mut r) in rules.into_iter().enumerate() {
        if !keep[i] {
            continue;
        }
        r.hidden = hidden[i];
        if let (Some(c), Some(v)) = (r.corr.as_mut(), &links[i]) {
            c.rules = v.iter().map(|&k| new_ix[k]).collect();
            // Credit: a correlation without an author names its rules'.
            if r.author.is_empty() {
                let mut a: Vec<&str> = v
                    .iter()
                    .map(|&k| authors[k].as_str())
                    .filter(|x| !x.is_empty())
                    .collect();
                a.dedup();
                r.author = a.join(", ");
            }
            // Something stable to select it by (`--rule-id`).
            if r.id.is_empty() {
                let stem = r
                    .path
                    .file_stem()
                    .map(|x| x.to_string_lossy().into_owned())
                    .unwrap_or_default();
                r.id = format!("{stem}#correlation");
            }
        }
        out.push(r);
    }
    out
}
