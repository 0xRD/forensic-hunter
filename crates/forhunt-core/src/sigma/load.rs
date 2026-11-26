//! Loading rule folders: Sigma / Hayabusa YAML files, and Hayabusa's
//! `config/` files when the folder is a `hayabusa-rules` checkout.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use super::compile::{self, Cond, Ctx};
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
}

impl Default for LoadOptions {
    fn default() -> Self {
        LoadOptions {
            min_level: 1,
            noisy: false,
            deprecated: false,
            ids: Vec::new(),
        }
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
        let roots: Vec<PathBuf> = if is_checkout(p) {
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
                            || (e.depth() > 0 && is_checkout(e.path()))))
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

fn compile_doc(doc: &Node, path: &Path, cfg: &Config, opts: &LoadOptions) -> Outcome {
    if doc.get("correlation").is_some() {
        return Outcome::Skip("correlation rule (not supported yet)".into());
    }
    let Some(det) = doc.get("detection") else {
        return Outcome::Skip("not a rule (no detection)".into());
    };
    let id = text(doc.get("id"));
    if !opts.ids.is_empty() && !opts.ids.iter().any(|x| x.eq_ignore_ascii_case(&id)) {
        return Outcome::Skip("not selected".into());
    }
    let status = text(doc.get("status")).to_ascii_lowercase();
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
        .unwrap_or_else(|| level_rank(&text(doc.get("level"))));
    if level < opts.min_level {
        return Outcome::Skip("below the minimum level".into());
    }
    let Node::Map(det) = det else {
        return Outcome::Error("`detection` is not a map".into());
    };
    let cx = Ctx {
        aliases: &cfg.aliases,
        expand: &cfg.expand,
    };
    let mut names = Vec::new();
    let mut sels = Vec::new();
    let mut cond_text: Vec<String> = Vec::new();
    for (k, v) in det {
        match k.as_str() {
            "condition" => cond_text = v.strings(),
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
            Ok(c) => conds.push(c),
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
    let scopes: Vec<_> = sels.iter().map(compile::sel_scope).collect();
    let scope = compile::cond_scope(&cond, &scopes);
    let mut fields = Vec::new();
    for s in &sels {
        compile::tested_fields(s, &mut fields);
    }
    Outcome::Rule(Box::new(Rule {
        title: text(doc.get("title")),
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
        fields,
        path: path.to_path_buf(),
        sels,
        cond,
        chans: scope.chans.map(|s| s.into_iter().collect()),
        eids: scope.eids.map(|s| s.into_iter().collect()),
        req: None,
        id,
    }))
}

fn compile_file(path: &Path, cfg: &Config, opts: &LoadOptions) -> Vec<Outcome> {
    let text = match std::fs::read(path) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => return vec![Outcome::Error(e.to_string())],
    };
    match yaml::parse(&text) {
        Ok(docs) if docs.is_empty() => vec![Outcome::Skip("not a rule (empty)".into())],
        Ok(docs) => docs
            .iter()
            .map(|d| compile_doc(d, path, cfg, opts))
            .collect(),
        Err(e) => vec![Outcome::Error(format!("YAML: {e}"))],
    }
}

/// Loads every `.yml` / `.yaml` rule under `paths` (files or folders).
/// Rules with the same `id` are loaded once (the first path wins).
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
                .filter(|c| c.is_dir() && is_config_dir(&c.join("config")))
                .collect();
            kids.sort();
            out.extend(kids);
        }
    }
    out
}

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
                Outcome::Skip(why) => *report.skipped.entry(why).or_default() += 1,
                Outcome::Error(e) => report.errors.push((files[i].clone(), e)),
            }
        }
    }
    report.loaded = rules.len();
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
    let outs = match yaml::parse(text) {
        Ok(docs) => docs
            .iter()
            .map(|d| compile_doc(d, &path, &cfg, opts))
            .collect(),
        Err(e) => vec![Outcome::Error(format!("YAML: {e}"))],
    };
    let mut rules = Vec::new();
    for o in outs {
        match o {
            Outcome::Rule(r) => rules.push(*r),
            Outcome::Skip(why) => *report.skipped.entry(why).or_default() += 1,
            Outcome::Error(e) => report.errors.push((path.clone(), e)),
        }
    }
    report.loaded = rules.len();
    (RuleSet::build(rules, cfg.details, cfg.aliases), report)
}
