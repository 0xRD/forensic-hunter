//! Sigma detection -> matcher tree, and the condition parser.
//!
//! Everything that can be done once is done here: needles are lowercased and
//! given a prebuilt substring finder, wildcards become anchored regexes,
//! `windash` / `base64offset` / `wide` values are expanded into their
//! variants, CIDR ranges are parsed. Matching an event is then only
//! comparisons.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use memchr::memmem;
use regex::{Regex, RegexBuilder};

pub(crate) use super::corr::CmpOp;
use super::yaml::Node;

/// `System` values a rule can test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sys {
    Channel,
    EventId,
    Provider,
    Computer,
    Level,
    Keywords,
    UserId,
    ProcessId,
    ThreadId,
    Version,
    RecordId,
    Task,
    Opcode,
}

pub(crate) const SYS_COUNT: usize = 13;

impl Sys {
    pub(crate) fn slot(self) -> usize {
        self as usize
    }
}

/// What a field name in a rule designates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FieldRef {
    Sys(Sys),
    /// A payload field by its (leaf) name; also matches `Name[1]`, `Name[2]`...
    /// `id`: index in the rule set's interned names (`u32::MAX` until
    /// interned), so an event resolves each name once for all rules.
    Payload(Box<str>, u32),
}

/// Field name -> what it designates, through Hayabusa's `eventkey_alias.txt`
/// when present (`Alias,Event.System.X` / `Event.EventData.X` /
/// `Event.UserData.A.X`), else the usual Sigma names of `System` values.
pub(crate) fn resolve_field(name: &str, aliases: &HashMap<String, String>) -> FieldRef {
    if let Some(path) = aliases.get(name) {
        if let Some(rest) = path.strip_prefix("Event.System.") {
            if let Some(s) = sys_path(rest) {
                return FieldRef::Sys(s);
            }
        }
        if let Some(leaf) = path.rsplit('.').next()
            && (path.starts_with("Event.EventData.") || path.starts_with("Event.UserData."))
        {
            return FieldRef::Payload(leaf.into(), u32::MAX);
        }
    }
    match name {
        "Channel" => FieldRef::Sys(Sys::Channel),
        "EventID" => FieldRef::Sys(Sys::EventId),
        "Provider_Name" | "ProviderName" => FieldRef::Sys(Sys::Provider),
        "Computer" | "ComputerName" => FieldRef::Sys(Sys::Computer),
        "Level" => FieldRef::Sys(Sys::Level),
        "Keywords" => FieldRef::Sys(Sys::Keywords),
        "SecurityUserID" => FieldRef::Sys(Sys::UserId),
        "ExecutionProcessID" => FieldRef::Sys(Sys::ProcessId),
        "EventRecordID" => FieldRef::Sys(Sys::RecordId),
        _ => FieldRef::Payload(name.into(), u32::MAX),
    }
}

fn sys_path(p: &str) -> Option<Sys> {
    Some(match p {
        "Channel" => Sys::Channel,
        "EventID" => Sys::EventId,
        "Provider_attributes.Name" => Sys::Provider,
        "Computer" => Sys::Computer,
        "Level" => Sys::Level,
        "Keywords" => Sys::Keywords,
        "Security_attributes.UserID" => Sys::UserId,
        "Execution_attributes.ProcessID" => Sys::ProcessId,
        "Execution_attributes.ThreadID" => Sys::ThreadId,
        "Version" => Sys::Version,
        "EventRecordID" => Sys::RecordId,
        "Task" => Sys::Task,
        "Opcode" => Sys::Opcode,
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Eq,
    Starts,
    Ends,
    Contains,
}

#[derive(Debug, Clone)]
pub(crate) struct Net {
    v6: bool,
    addr: u128,
    mask: u128,
}

impl Net {
    fn parse(s: &str) -> Option<Net> {
        let (a, len) = match s.trim().split_once('/') {
            Some((a, l)) => (a, Some(l.trim().parse::<u32>().ok()?)),
            None => (s.trim(), None),
        };
        match a.parse::<IpAddr>().ok()? {
            IpAddr::V4(v) => {
                let len = len.unwrap_or(32);
                if len > 32 {
                    return None;
                }
                let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) } as u128;
                Some(Net {
                    v6: false,
                    addr: u32::from(v) as u128 & mask,
                    mask,
                })
            }
            IpAddr::V6(v) => {
                let len = len.unwrap_or(128);
                if len > 128 {
                    return None;
                }
                let mask = if len == 0 {
                    0
                } else {
                    u128::MAX << (128 - len)
                };
                Some(Net {
                    v6: true,
                    addr: u128::from(v) & mask,
                    mask,
                })
            }
        }
    }

    pub(crate) fn contains(&self, s: &str) -> bool {
        let s = s.trim().trim_start_matches('[').trim_end_matches(']');
        let ip = match s.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return false,
        };
        // `::ffff:10.0.0.5` (how Windows logs IPv4 peers on dual-stack
        // sockets) is the IPv4 address.
        let ip = match ip {
            IpAddr::V6(v) => match v.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v),
            },
            v4 => v4,
        };
        match ip {
            IpAddr::V4(v) if !self.v6 => (u32::from(v) as u128 & self.mask) == self.addr,
            IpAddr::V6(v) if self.v6 => (u128::from(v) & self.mask) == self.addr,
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum M {
    /// `Field: null`: absent or empty.
    Null,
    /// `Field|exists: true/false`.
    Exists(bool),
    /// Literal comparison. Case-insensitive needles are stored lowercased
    /// and tested against the lowercased value.
    Str {
        kind: Kind,
        needle: Box<str>,
        cased: bool,
        finder: Option<Box<memmem::Finder<'static>>>,
    },
    /// Wildcard value or `|re`. `lowered`: tested against the lowercased
    /// value (wildcards without `|cased`), else against the value as written.
    Re {
        re: Regex,
        lowered: bool,
        /// Longest literal of a wildcard value (lowercased): the value
        /// must contain it. `None` for `|re`.
        hint: Option<Box<str>>,
    },
    Cidr(Net),
    Cmp(CmpOp, f64),
    /// `|fieldref` (and Hayabusa's `equalsfield` / `endswithfield`).
    FieldRef {
        other: FieldRef,
        kind: Kind,
    },
    /// Several `contains` literals of one field test, found in one pass.
    AnyContains {
        ac: aho_corasick::AhoCorasick,
        needles: Vec<Box<str>>,
        cased: bool,
    },
    /// Several equality literals of one field test.
    AnyEq {
        set: std::collections::HashSet<Box<str>>,
        cased: bool,
    },
}

/// A literal matcher (lowercased needle unless `cased`).
fn lit(kind: Kind, needle: Box<str>, cased: bool) -> M {
    let finder = (kind == Kind::Contains && !needle.is_empty())
        .then(|| Box::new(memmem::Finder::new(needle.as_bytes()).into_owned()));
    M::Str {
        kind,
        needle,
        cased,
        finder,
    }
}

/// Folds the ORed literals of one field test: `contains` lists into one
/// Aho-Corasick automaton, equality lists into a hash set (rules with
/// hundreds of values cost one pass instead of hundreds).
fn fold(ms: Vec<M>) -> Result<Vec<M>, String> {
    let mut cont: [Vec<Box<str>>; 2] = Default::default();
    let mut eq: [Vec<Box<str>>; 2] = Default::default();
    let mut out = Vec::new();
    for m in ms {
        match m {
            M::Str {
                kind: Kind::Contains,
                needle,
                cased,
                ..
            } if !needle.is_empty() => cont[cased as usize].push(needle),
            // An empty equality also holds on an absent field: kept apart.
            M::Str {
                kind: Kind::Eq,
                needle,
                cased,
                ..
            } if !needle.is_empty() => eq[cased as usize].push(needle),
            m => out.push(m),
        }
    }
    for c in 0..2 {
        let cased = c == 1;
        let ns = std::mem::take(&mut cont[c]);
        if ns.len() >= 3 {
            let ac = aho_corasick::AhoCorasick::builder()
                .build(ns.iter().map(|n| n.as_bytes()))
                .map_err(|e| format!("contains list: {e}"))?;
            out.push(M::AnyContains {
                ac,
                needles: ns,
                cased,
            });
        } else {
            out.extend(ns.into_iter().map(|n| lit(Kind::Contains, n, cased)));
        }
        let ns = std::mem::take(&mut eq[c]);
        if ns.len() >= 4 {
            out.push(M::AnyEq {
                set: ns.into_iter().collect(),
                cased,
            });
        } else {
            out.extend(ns.into_iter().map(|n| lit(Kind::Eq, n, cased)));
        }
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub(crate) struct FieldTest {
    pub field: FieldRef,
    pub ms: Vec<M>,
    /// `|all`: every value must match.
    pub all: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum Sel {
    /// A map: every field test holds.
    And(Vec<FieldTest>),
    /// A list of maps / keywords: one of them holds.
    Or(Vec<Sel>),
    /// Keywords: one of the matchers matches a value of any payload field.
    Keywords(Vec<M>),
}

#[derive(Debug, Clone)]
pub(crate) enum Cond {
    Sel(usize),
    Not(Box<Cond>),
    And(Vec<Cond>),
    Or(Vec<Cond>),
}

/// Values a part of a rule can match on `Channel` (lowercased) and
/// `EventID`; `None` = any. Over-approximates: used to pick candidate rules.
#[derive(Debug, Clone, Default)]
pub(crate) struct Scope {
    pub chans: Option<BTreeSet<String>>,
    pub eids: Option<BTreeSet<u32>>,
}

fn inter<T: Ord + Clone>(a: &Option<BTreeSet<T>>, b: &Option<BTreeSet<T>>) -> Option<BTreeSet<T>> {
    match (a, b) {
        (None, x) | (x, None) => x.clone(),
        (Some(a), Some(b)) => Some(a.intersection(b).cloned().collect()),
    }
}

fn union<T: Ord + Clone>(a: &Option<BTreeSet<T>>, b: &Option<BTreeSet<T>>) -> Option<BTreeSet<T>> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.union(b).cloned().collect()),
        _ => None,
    }
}

impl Scope {
    fn and(&self, o: &Scope) -> Scope {
        Scope {
            chans: inter(&self.chans, &o.chans),
            eids: inter(&self.eids, &o.eids),
        }
    }

    fn or(&self, o: &Scope) -> Scope {
        Scope {
            chans: union(&self.chans, &o.chans),
            eids: union(&self.eids, &o.eids),
        }
    }

    fn empty() -> Scope {
        Scope {
            chans: Some(BTreeSet::new()),
            eids: Some(BTreeSet::new()),
        }
    }
}

/// Exact, case-insensitive literal values of a test (what the index can use).
fn literal_values(t: &FieldTest) -> Option<Vec<&str>> {
    if t.all && t.ms.len() > 1 {
        return None;
    }
    let mut out = Vec::new();
    for m in &t.ms {
        match m {
            M::Str {
                kind: Kind::Eq,
                needle,
                ..
            } => out.push(needle.as_ref()),
            M::AnyEq { set, .. } => out.extend(set.iter().map(|s| s.as_ref())),
            _ => return None,
        }
    }
    Some(out)
}

pub(crate) fn sel_scope(s: &Sel) -> Scope {
    match s {
        Sel::And(tests) => {
            let mut sc = Scope::default();
            for t in tests {
                let Some(vals) = literal_values(t) else {
                    continue;
                };
                match t.field {
                    FieldRef::Sys(Sys::Channel) => {
                        let set = vals.iter().map(|v| v.to_lowercase()).collect();
                        sc.chans = inter(&sc.chans, &Some(set));
                    }
                    FieldRef::Sys(Sys::EventId) => {
                        // A value that is not a number matches no event id.
                        let set = vals
                            .iter()
                            .filter_map(|v| v.trim().parse::<u32>().ok())
                            .collect();
                        sc.eids = inter(&sc.eids, &Some(set));
                    }
                    _ => {}
                }
            }
            sc
        }
        Sel::Or(xs) => xs
            .iter()
            .map(sel_scope)
            .reduce(|a, b| a.or(&b))
            .unwrap_or_else(Scope::empty),
        Sel::Keywords(_) => Scope::default(),
    }
}

pub(crate) fn cond_scope(c: &Cond, sels: &[Scope]) -> Scope {
    match c {
        Cond::Sel(i) => sels[*i].clone(),
        Cond::Not(_) => Scope::default(),
        Cond::And(xs) => xs
            .iter()
            .map(|x| cond_scope(x, sels))
            .reduce(|a, b| a.and(&b))
            .unwrap_or_default(),
        Cond::Or(xs) => xs
            .iter()
            .map(|x| cond_scope(x, sels))
            .reduce(|a, b| a.or(&b))
            .unwrap_or_else(Scope::empty),
    }
}

// ---------------------------------------------------------------- values

pub(crate) fn lower(s: &str) -> std::borrow::Cow<'_, str> {
    if s.is_ascii() {
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            std::borrow::Cow::Owned(s.to_ascii_lowercase())
        } else {
            std::borrow::Cow::Borrowed(s)
        }
    } else {
        // Per character: `str::to_lowercase` turns a word-final Σ into ς,
        // and a needle would then miss the same letters inside a word.
        let l: String = s.chars().flat_map(char::to_lowercase).collect();
        if l == s {
            std::borrow::Cow::Borrowed(s)
        } else {
            std::borrow::Cow::Owned(l)
        }
    }
}

#[derive(Debug, PartialEq)]
enum Piece {
    Lit(String),
    Star,
    One,
}

/// Splits a Sigma string into literals and wildcards. `\*`, `\?` and `\\`
/// are escapes; any other backslash is a plain character (`C:\Windows`).
fn pieces(s: &str) -> Vec<Piece> {
    let mut out = Vec::new();
    let mut lit = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' => match it.peek() {
                Some(&n @ ('*' | '?' | '\\')) => {
                    lit.push(n);
                    it.next();
                }
                _ => lit.push('\\'),
            },
            '*' | '?' => {
                if !lit.is_empty() {
                    out.push(Piece::Lit(std::mem::take(&mut lit)));
                }
                out.push(if c == '*' { Piece::Star } else { Piece::One });
            }
            c => lit.push(c),
        }
    }
    if !lit.is_empty() {
        out.push(Piece::Lit(lit));
    }
    out
}

/// A string matcher for `value` with `kind`, honouring wildcards unless
/// `literal` (base64 and UTF-16 variants are literal).
fn str_matcher(value: &str, kind: Kind, cased: bool, literal: bool) -> Result<M, String> {
    let ps = if literal {
        vec![Piece::Lit(value.to_string())]
    } else {
        pieces(value)
    };
    let wild = ps.iter().any(|p| !matches!(p, Piece::Lit(_)));
    if !wild {
        let text: String = ps
            .into_iter()
            .map(|p| match p {
                Piece::Lit(s) => s,
                _ => String::new(),
            })
            .collect();
        let needle = if cased {
            text
        } else {
            lower(&text).into_owned()
        };
        return Ok(lit(kind, needle.into(), cased));
    }
    let mut re = String::from("(?s)");
    if matches!(kind, Kind::Eq | Kind::Starts) {
        re.push('^');
    }
    for p in &ps {
        match p {
            Piece::Lit(s) => re.push_str(&regex::escape(&if cased {
                s.clone()
            } else {
                lower(s).into_owned()
            })),
            Piece::Star => re.push_str(".*"),
            Piece::One => re.push('.'),
        }
    }
    if matches!(kind, Kind::Eq | Kind::Ends) {
        re.push('$');
    }
    let re = RegexBuilder::new(&re)
        .size_limit(1 << 22)
        .build()
        .map_err(|e| format!("wildcard value `{value}`: {e}"))?;
    let hint = ps
        .iter()
        .filter_map(|p| match p {
            Piece::Lit(s) => Some(lower(s).into_owned()),
            _ => None,
        })
        .max_by_key(|s| s.len())
        .map(Into::into);
    Ok(M::Re {
        re,
        lowered: !cased,
        hint,
    })
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// The three encodings of `v` at byte offsets 0, 1, 2 of a longer base64
/// text, with the characters that depend on the neighbours cut off.
pub(crate) fn base64_offsets(v: &[u8]) -> Vec<String> {
    const START: [usize; 3] = [0, 2, 3];
    const END: [usize; 3] = [0, 3, 2];
    (0..3)
        .map(|i| {
            let mut b = vec![b' '; i];
            b.extend_from_slice(v);
            let enc = base64(&b);
            let cut = END[(v.len() + i) % 3];
            enc[START[i]..enc.len() - cut].to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

const WINDASH: [char; 5] = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];

/// Every spelling of the command-line options of `v`: a `-` or `/` that
/// starts an option word (after the start or a non-word character, before a
/// word character) is replaced by each Windows option dash.
pub(crate) fn windash(v: &str) -> Vec<String> {
    let cs: Vec<char> = v.chars().collect();
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let pos: Vec<usize> = (0..cs.len())
        .filter(|&i| {
            matches!(cs[i], '-' | '/')
                && (i == 0 || !word(cs[i - 1]))
                && cs.get(i + 1).is_some_and(|&c| word(c))
        })
        .collect();
    // 5^4 = 625 variants at most; further dashes keep their spelling.
    let pos = &pos[..pos.len().min(4)];
    let mut out = vec![cs.clone()];
    for &p in pos {
        out = out
            .into_iter()
            .flat_map(|s| {
                WINDASH.iter().map(move |&d| {
                    let mut s = s.clone();
                    s[p] = d;
                    s
                })
            })
            .collect();
    }
    let mut v: Vec<String> = out.into_iter().map(|s| s.into_iter().collect()).collect();
    v.dedup();
    v
}

/// Values of a field entry: a scalar or a list of scalars (`null` allowed).
fn scalars(n: &Node) -> Result<Vec<Option<String>>, String> {
    match n {
        Node::Null => Ok(vec![None]),
        Node::Str(s) => Ok(vec![Some(s.clone())]),
        Node::Seq(v) => v
            .iter()
            .map(|x| match x {
                Node::Null => Ok(None),
                Node::Str(s) => Ok(Some(s.clone())),
                _ => Err("a field value list holds a list or map".to_string()),
            })
            .collect(),
        Node::Map(_) => Err("a field value is a map".to_string()),
    }
}

pub(crate) struct Ctx<'a> {
    pub aliases: &'a HashMap<String, String>,
    /// Placeholder name (without `%`) -> values, for `|expand`.
    pub expand: &'a HashMap<String, Vec<String>>,
    /// Logsource variant being compiled (field renames, value maps).
    pub variant: Option<&'a super::logsource::Variant>,
}

impl Ctx<'_> {
    /// A rule's field name, renamed for the variant, then resolved.
    pub(crate) fn field(&self, name: &str) -> FieldRef {
        let name = self
            .variant
            .and_then(|v| v.renames.iter().find(|(a, _)| *a == name))
            .map_or(name, |(_, b)| *b);
        resolve_field(name, self.aliases)
    }

    /// A value as the variant's events write it (`High` -> `S-1-16-12288`).
    fn value(&self, field: &str, v: String) -> String {
        self.variant
            .and_then(|x| x.values.iter().find(|(f, _)| *f == field))
            .and_then(|(_, m)| m.iter().find(|(a, _)| a.eq_ignore_ascii_case(v.trim())))
            .map_or(v, |(_, b)| b.to_string())
    }
}

/// Compiles one `Field|mod|mod: values` entry. Usually one test; `|all`
/// over values that expand into variants (windash, base64offset) gives one
/// test per value, each matching any of its variants.
pub(crate) fn field_test(key: &str, val: &Node, cx: &Ctx<'_>) -> Result<Vec<FieldTest>, String> {
    let mut parts = key.split('|');
    let name = parts.next().unwrap_or_default().trim();
    let mut kind = Kind::Eq;
    let (mut all, mut cased, mut re, mut cidr, mut b64, mut b64off) =
        (false, false, false, false, false, false);
    let (mut wdash, mut expand, mut fieldref, mut exists) = (false, false, false, false);
    let mut enc: Option<&str> = None;
    let mut cmp = None;
    let mut re_flags = String::new();
    for m in parts {
        match m.trim() {
            "contains" => kind = Kind::Contains,
            "startswith" => kind = Kind::Starts,
            "endswith" => kind = Kind::Ends,
            "all" => all = true,
            "cased" => cased = true,
            "re" => re = true,
            "i" | "m" | "s" if re => re_flags.push_str(m.trim()),
            "cidr" => cidr = true,
            "base64" => b64 = true,
            "base64offset" => b64off = true,
            "wide" | "utf16le" => enc = Some("utf16le"),
            "utf16be" => enc = Some("utf16be"),
            "utf16" => enc = Some("utf16"),
            "windash" => wdash = true,
            "expand" => expand = true,
            "fieldref" => fieldref = true,
            "equalsfield" => fieldref = true,
            "endswithfield" => {
                fieldref = true;
                kind = Kind::Ends;
            }
            "exists" => exists = true,
            "gt" => cmp = Some(CmpOp::Gt),
            "gte" => cmp = Some(CmpOp::Ge),
            "lt" => cmp = Some(CmpOp::Lt),
            "lte" => cmp = Some(CmpOp::Le),
            other => return Err(format!("unsupported modifier `{other}` in `{key}`")),
        }
    }
    let field = cx.field(name);
    let mut ms = Vec::new();
    let vals = scalars(val)?;
    // Where each value's matchers start in `ms`.
    let mut bounds = Vec::new();
    for v in vals {
        bounds.push(ms.len());
        let v = v.map(|v| cx.value(name, v));
        let Some(v) = v else {
            ms.push(M::Null);
            continue;
        };
        if exists {
            ms.push(M::Exists(matches!(v.trim(), "true" | "True" | "yes")));
            continue;
        }
        if let Some(op) = cmp {
            let n = parse_num(&v).ok_or_else(|| format!("`{key}`: `{v}` is not a number"))?;
            ms.push(M::Cmp(op, n));
            continue;
        }
        if fieldref {
            ms.push(M::FieldRef {
                other: cx.field(v.trim()),
                kind,
            });
            continue;
        }
        if cidr {
            ms.push(M::Cidr(
                Net::parse(&v).ok_or_else(|| format!("`{key}`: bad CIDR `{v}`"))?,
            ));
            continue;
        }
        if re {
            let mut b = RegexBuilder::new(&pcre_to_rust(&v));
            b.case_insensitive(re_flags.contains('i'))
                .multi_line(re_flags.contains('m'))
                .dot_matches_new_line(re_flags.contains('s'))
                .size_limit(1 << 23);
            let r = b.build().map_err(|e| format!("`{key}`: bad regex: {e}"))?;
            ms.push(M::Re {
                re: r,
                lowered: false,
                hint: None,
            });
            continue;
        }
        // String values: expand placeholders, then windash, then encodings.
        let mut texts = vec![v.clone()];
        if expand {
            let mut out = Vec::new();
            for t in &texts {
                out.extend(expand_value(t, cx.expand)?);
            }
            texts = out;
        }
        if wdash {
            texts = texts.iter().flat_map(|t| windash(t)).collect();
        }
        if b64 || b64off || enc.is_some() {
            for t in &texts {
                let bytes: Vec<u8> = match enc {
                    Some("utf16le") => t.encode_utf16().flat_map(|u| u.to_le_bytes()).collect(),
                    Some("utf16be") => t.encode_utf16().flat_map(|u| u.to_be_bytes()).collect(),
                    Some(_) => [0xFF, 0xFE]
                        .into_iter()
                        .chain(t.encode_utf16().flat_map(|u| u.to_le_bytes()))
                        .collect(),
                    None => t.as_bytes().to_vec(),
                };
                if b64off {
                    for s in base64_offsets(&bytes) {
                        ms.push(str_matcher(&s, kind, true, true)?);
                    }
                } else if b64 {
                    ms.push(str_matcher(&base64(&bytes), kind, true, true)?);
                } else {
                    // UTF-16 without base64 cannot appear in rendered text.
                    return Err(format!("`{key}`: utf16 without base64 is not supported"));
                }
            }
            continue;
        }
        let device = cx.variant.is_some_and(|x| x.device_paths.contains(&name));
        for t in &texts {
            let b = t.as_bytes();
            let drive = b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
            match (device && drive, kind) {
                (true, Kind::Eq) => ms.push(str_matcher(&t[2..], Kind::Ends, cased, false)?),
                (true, Kind::Starts) => {
                    ms.push(str_matcher(&t[2..], Kind::Contains, cased, false)?)
                }
                _ => ms.push(str_matcher(t, kind, cased, false)?),
            }
        }
    }
    // `base64offset` gives 3 variants per value: `all` means "every value",
    // so variants of one value must be ORed. Rules never combine them; keep
    // `all` only where it is unambiguous.
    if all && ms.len() > bounds.len() {
        bounds.push(ms.len());
        let mut out = Vec::new();
        for w in bounds.windows(2).rev() {
            let group: Vec<M> = ms.drain(w[0]..w[1]).collect();
            out.push(FieldTest {
                field: field.clone(),
                ms: fold(group)?,
                all: false,
            });
        }
        out.reverse();
        return Ok(out);
    }
    let ms = if all { ms } else { fold(ms)? };
    Ok(vec![FieldTest { field, ms, all }])
}

/// Rewrites PCRE / Python regex syntax the Rust engine reads differently:
/// inside a character class, `[` is a nested class and `&&`, `--`, `~~` are
/// set operations in Rust, literal characters in the rules' dialect.
pub(crate) fn pcre_to_rust(re: &str) -> String {
    let cs: Vec<char> = re.chars().collect();
    let mut out = String::with_capacity(re.len() + 8);
    let (mut i, mut class) = (0, false);
    while i < cs.len() {
        let c = cs[i];
        if c == '\\' {
            out.push(c);
            if let Some(&n) = cs.get(i + 1) {
                out.push(n);
            }
            i += 2;
            continue;
        }
        if !class {
            if c == '[' {
                class = true;
                out.push('[');
                // `[^]...]` / `[]...]`: a leading `]` is a literal.
                if cs.get(i + 1) == Some(&'^') {
                    out.push('^');
                    i += 1;
                }
                if cs.get(i + 1) == Some(&']') {
                    out.push_str("\\]");
                    i += 1;
                }
            } else {
                out.push(c);
            }
            i += 1;
            continue;
        }
        match c {
            ']' => {
                class = false;
                out.push(']');
            }
            '[' if cs.get(i + 1) == Some(&':') => {
                // POSIX class `[:alpha:]`: copy as is.
                let end =
                    (i + 2..cs.len().saturating_sub(1)).find(|&k| cs[k] == ':' && cs[k + 1] == ']');
                match end {
                    Some(e) => {
                        out.extend(&cs[i..=e + 1]);
                        i = e + 2;
                        continue;
                    }
                    None => out.push_str("\\["),
                }
            }
            '[' => out.push_str("\\["),
            '&' | '-' | '~' if cs.get(i + 1) == Some(&c) => {
                out.push(c);
                out.push('\\');
            }
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

fn expand_value(v: &str, table: &HashMap<String, Vec<String>>) -> Result<Vec<String>, String> {
    // One placeholder per value is what rules use; more would multiply.
    let Some(s) = v.find('%') else {
        return Ok(vec![v.to_string()]);
    };
    let Some(len) = v[s + 1..].find('%') else {
        return Ok(vec![v.to_string()]);
    };
    let name = &v[s + 1..s + 1 + len];
    let vals = table.get(name).filter(|x| !x.is_empty()).ok_or_else(|| {
        format!("expand placeholder `%{name}%` is not configured (config/expand/{name}.txt)")
    })?;
    let mut out = Vec::new();
    for x in vals {
        let t = format!("{}{}{}", &v[..s], x, &v[s + 2 + len..]);
        out.extend(expand_value(&t, table)?);
    }
    Ok(out)
}

pub(crate) fn parse_num(s: &str) -> Option<f64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok().map(|n| n as f64),
        None => s.parse::<f64>().ok().filter(|f| f.is_finite()),
    }
}

/// Compiles a selection (`selection_x: ...` under `detection`).
pub(crate) fn selection(n: &Node, cx: &Ctx<'_>) -> Result<Sel, String> {
    match n {
        Node::Map(m) => {
            let mut tests = Vec::with_capacity(m.len());
            for (k, v) in m {
                tests.extend(field_test(k, v, cx)?);
            }
            Ok(Sel::And(tests))
        }
        Node::Seq(items) => {
            let mut alts = Vec::new();
            let mut kws = Vec::new();
            for it in items {
                match it {
                    Node::Map(_) => alts.push(selection(it, cx)?),
                    Node::Str(s) => kws.push(str_matcher(s, Kind::Contains, false, false)?),
                    Node::Null => {}
                    Node::Seq(_) => return Err("a selection list holds a list".into()),
                }
            }
            if !kws.is_empty() {
                alts.push(Sel::Keywords(kws));
            }
            Ok(Sel::Or(alts))
        }
        Node::Str(s) => Ok(Sel::Keywords(vec![str_matcher(
            s,
            Kind::Contains,
            false,
            false,
        )?])),
        Node::Null => Err("empty selection".into()),
    }
}

// ------------------------------------------------------------- condition

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    LParen,
    RParen,
    And,
    Or,
    Not,
    OneOf,
    AllOf,
    Them,
    Ident(String),
    Pipe,
}

fn tokens(s: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => out.push(Tok::LParen),
            ')' => out.push(Tok::RParen),
            '|' => out.push(Tok::Pipe),
            _ => {
                let st = i;
                while i < b.len() && !b[i].is_whitespace() && !matches!(b[i], '(' | ')' | '|') {
                    i += 1;
                }
                let w: String = b[st..i].iter().collect();
                match w.to_ascii_lowercase().as_str() {
                    "and" => out.push(Tok::And),
                    "or" => out.push(Tok::Or),
                    "not" => out.push(Tok::Not),
                    "them" => out.push(Tok::Them),
                    "of" => match out.pop() {
                        Some(Tok::Ident(q)) if q == "1" || q.eq_ignore_ascii_case("any") => {
                            out.push(Tok::OneOf)
                        }
                        Some(Tok::Ident(q)) if q.eq_ignore_ascii_case("all") => {
                            out.push(Tok::AllOf)
                        }
                        _ => return Err(format!("`of` without `1` / `all` in `{s}`")),
                    },
                    _ => out.push(Tok::Ident(w)),
                }
                continue;
            }
        }
        i += 1;
    }
    Ok(out)
}

struct CondParser<'a> {
    t: Vec<Tok>,
    i: usize,
    names: &'a [String],
}

fn glob_match(pat: &str, name: &str) -> bool {
    match pat.split_once('*') {
        None => pat == name,
        Some((pre, rest)) => {
            if !name.starts_with(pre) {
                return false;
            }
            let tail = &name[pre.len()..];
            if rest.is_empty() {
                return true;
            }
            (0..=tail.len())
                .filter(|&k| tail.is_char_boundary(k))
                .any(|k| glob_match(rest, &tail[k..]))
        }
    }
}

impl CondParser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }

    fn or(&mut self) -> Result<Cond, String> {
        let mut xs = vec![self.and()?];
        while self.peek() == Some(&Tok::Or) {
            self.i += 1;
            xs.push(self.and()?);
        }
        Ok(if xs.len() == 1 {
            xs.pop().unwrap()
        } else {
            Cond::Or(xs)
        })
    }

    fn and(&mut self) -> Result<Cond, String> {
        let mut xs = vec![self.unary()?];
        while self.peek() == Some(&Tok::And) {
            self.i += 1;
            xs.push(self.unary()?);
        }
        Ok(if xs.len() == 1 {
            xs.pop().unwrap()
        } else {
            Cond::And(xs)
        })
    }

    fn unary(&mut self) -> Result<Cond, String> {
        match self.t.get(self.i).cloned() {
            Some(Tok::Not) => {
                self.i += 1;
                Ok(Cond::Not(Box::new(self.unary()?)))
            }
            Some(Tok::LParen) => {
                self.i += 1;
                let c = self.or()?;
                if self.peek() != Some(&Tok::RParen) {
                    return Err("missing `)`".into());
                }
                self.i += 1;
                Ok(c)
            }
            Some(q @ (Tok::OneOf | Tok::AllOf)) => {
                self.i += 1;
                let idx: Vec<usize> = match self.t.get(self.i).cloned() {
                    // `them`: every selection, but not the `_`-prefixed ones.
                    Some(Tok::Them) => (0..self.names.len())
                        .filter(|&k| !self.names[k].starts_with('_'))
                        .collect(),
                    Some(Tok::Ident(p)) => (0..self.names.len())
                        .filter(|&k| glob_match(&p, &self.names[k]))
                        .collect(),
                    _ => return Err("`of` needs `them` or a selection name".into()),
                };
                self.i += 1;
                if idx.is_empty() {
                    return Err("`of` names no selection".into());
                }
                let xs: Vec<Cond> = idx.into_iter().map(Cond::Sel).collect();
                Ok(if q == Tok::OneOf {
                    Cond::Or(xs)
                } else {
                    Cond::And(xs)
                })
            }
            Some(Tok::Ident(n)) => {
                self.i += 1;
                match self.names.iter().position(|x| *x == n) {
                    Some(k) => Ok(Cond::Sel(k)),
                    // `sel_*` without `1 of`: read as `1 of sel_*`.
                    None if n.contains('*') => {
                        let xs: Vec<Cond> = (0..self.names.len())
                            .filter(|&k| glob_match(&n, &self.names[k]))
                            .map(Cond::Sel)
                            .collect();
                        if xs.is_empty() {
                            Err(format!("`{n}` names no selection"))
                        } else {
                            Ok(Cond::Or(xs))
                        }
                    }
                    None => Err(format!("unknown selection `{n}`")),
                }
            }
            Some(Tok::Pipe) => {
                Err("aggregation (`| count()`) is not supported; use a correlation rule".into())
            }
            Some(t) => Err(format!("unexpected `{t:?}`")),
            None => Err("condition ends early".into()),
        }
    }
}

/// Parses a condition over the selection `names`.
pub(crate) fn condition(text: &str, names: &[String]) -> Result<Cond, String> {
    let t = tokens(text)?;
    if t.contains(&Tok::Pipe) {
        return Err("aggregation (`| count()`) is not supported; use a correlation rule".into());
    }
    let mut p = CondParser { t, i: 0, names };
    let c = p.or()?;
    if p.i != p.t.len() {
        return Err(format!("unexpected text after the condition `{text}`"));
    }
    Ok(c)
}

/// Field names a rule tests (what to highlight), without Channel / EventID.
pub(crate) fn tested_fields(s: &Sel, out: &mut Vec<String>) {
    match s {
        Sel::And(ts) => {
            for t in ts {
                let n = match &t.field {
                    FieldRef::Payload(n, _) => n.to_string(),
                    FieldRef::Sys(Sys::Channel | Sys::EventId) => continue,
                    FieldRef::Sys(x) => format!("{x:?}"),
                };
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
        Sel::Or(xs) => xs.iter().for_each(|x| tested_fields(x, out)),
        Sel::Keywords(_) => {}
    }
}

/// Gives every payload field name of `s` its interned id.
pub(crate) fn intern(s: &mut Sel, names: &mut HashMap<Box<str>, u32>) {
    fn one(f: &mut FieldRef, names: &mut HashMap<Box<str>, u32>) {
        if let FieldRef::Payload(n, id) = f {
            let next = names.len() as u32;
            *id = *names.entry(n.clone()).or_insert(next);
        }
    }
    match s {
        Sel::And(ts) => {
            for t in ts {
                one(&mut t.field, names);
                for m in &mut t.ms {
                    if let M::FieldRef { other, .. } = m {
                        one(other, names);
                    }
                }
            }
        }
        Sel::Or(xs) => xs.iter_mut().for_each(|x| intern(x, names)),
        Sel::Keywords(_) => {}
    }
}

/// A necessary condition of a rule: it can only match when one of these
/// (field, literal) pairs holds, i.e. the lowercased field value contains
/// the literal. Used to skip rules without evaluating them.
pub(crate) type Req = Vec<(FieldRef, Box<str>)>;

/// Shortest literal a prefilter accepts: shorter ones match too often.
const REQ_MIN: usize = 3;

fn score(r: &Req) -> usize {
    r.iter().map(|(_, n)| n.len()).min().unwrap_or(0)
}

fn best(a: Option<Req>, b: Option<Req>) -> Option<Req> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if score(&b) > score(&a) { b } else { a }),
        (a, b) => a.or(b),
    }
}

/// Literals one matcher implies (the value contains one of them).
fn needles(m: &M) -> Option<Vec<Box<str>>> {
    let v: Vec<Box<str>> = match m {
        M::Str { needle, .. } => vec![lower(needle).into()],
        M::AnyContains { needles, .. } => needles.iter().map(|n| lower(n).into()).collect(),
        M::AnyEq { set, .. } => set.iter().map(|n| lower(n).into()).collect(),
        M::Re { hint: Some(h), .. } => vec![h.clone()],
        _ => return None,
    };
    v.iter().all(|n| n.len() >= REQ_MIN).then_some(v)
}

fn test_req(t: &FieldTest) -> Option<Req> {
    if matches!(t.field, FieldRef::Sys(Sys::Channel | Sys::EventId)) || t.ms.is_empty() {
        return None;
    }
    let req = |ns: Vec<Box<str>>| -> Req { ns.into_iter().map(|n| (t.field.clone(), n)).collect() };
    if t.all {
        // Every matcher holds: any one of them is necessary.
        t.ms.iter()
            .filter_map(needles)
            .map(req)
            .reduce(|a, b| best(Some(a), Some(b)).unwrap())
    } else {
        let mut all = Vec::new();
        for m in &t.ms {
            all.extend(needles(m)?);
        }
        Some(req(all))
    }
}

pub(crate) fn sel_req(s: &Sel) -> Option<Req> {
    match s {
        Sel::And(ts) => ts.iter().map(test_req).fold(None, best),
        Sel::Or(xs) => {
            let mut out = Vec::new();
            for x in xs {
                out.extend(sel_req(x)?);
            }
            (!out.is_empty()).then_some(out)
        }
        Sel::Keywords(_) => None,
    }
}

pub(crate) fn cond_req(c: &Cond, sels: &[Option<Req>]) -> Option<Req> {
    match c {
        Cond::Sel(k) => sels[*k].clone(),
        Cond::Not(_) => None,
        Cond::And(xs) => xs.iter().map(|x| cond_req(x, sels)).fold(None, best),
        Cond::Or(xs) => {
            let mut out = Vec::new();
            for x in xs {
                out.extend(cond_req(x, sels)?);
            }
            Some(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_and_escapes() {
        // Sigma: `\*` is an escaped star, `\\*` a backslash then a wildcard.
        assert_eq!(
            pieces(r"C:\Windows\*.exe"),
            vec![Piece::Lit(r"C:\Windows*.exe".into())]
        );
        assert_eq!(
            pieces(r"C:\Windows\\*.exe"),
            vec![
                Piece::Lit(r"C:\Windows\".into()),
                Piece::Star,
                Piece::Lit(".exe".into())
            ]
        );
        assert_eq!(pieces(r"a\*b"), vec![Piece::Lit("a*b".into())]);
        assert_eq!(pieces(r"a\\*"), vec![Piece::Lit(r"a\".into()), Piece::Star]);
    }

    #[test]
    fn base64_variants() {
        assert_eq!(base64(b"hello"), "aGVsbG8=");
        // pySigma's reference values for `|base64offset|contains: /bin/bash`.
        assert_eq!(
            base64_offsets(b"/bin/bash"),
            ["L2Jpbi9iYXNo", "9iaW4vYmFza", "vYmluL2Jhc2"]
        );
    }

    #[test]
    fn windash_variants() {
        let v = windash(" -enc ");
        assert_eq!(v.len(), 5);
        assert!(v.contains(&" /enc ".to_string()));
        assert!(v.contains(&" \u{2015}enc ".to_string()));
        // A dash inside a word is not an option.
        assert_eq!(windash("a-b"), ["a-b"]);
    }

    #[test]
    fn cidr() {
        let n = Net::parse("10.0.0.0/8").unwrap();
        assert!(n.contains("10.1.2.3"));
        assert!(n.contains("::ffff:10.1.2.3"));
        assert!(!n.contains("11.0.0.1"));
        assert!(!n.contains("-"));
        let n = Net::parse("fe80::/10").unwrap();
        assert!(n.contains("fe80::1"));
        assert!(!n.contains("10.0.0.1"));
    }

    #[test]
    fn pcre_classes() {
        assert_eq!(pcre_to_rust(r"[^^=%![(; ]*"), r"[^^=%!\[(; ]*");
        assert_eq!(pcre_to_rust(r"[a&&b]"), r"[a&\&b]");
        assert_eq!(pcre_to_rust(r"[[:alpha:]]x\["), r"[[:alpha:]]x\[");
        assert_eq!(pcre_to_rust(r"[]a]"), r"[\]a]");
        assert!(
            regex::Regex::new(&pcre_to_rust(
                r"^([^^=%![(; ]*[\^=%![(; ]){8,}[^^=%![(; ]*$"
            ))
            .is_ok()
        );
    }

    #[test]
    fn conditions() {
        let names: Vec<String> = ["sel", "sel_a", "filter", "_x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let c = condition("sel and not 1 of filter*", &names).unwrap();
        assert!(matches!(c, Cond::And(ref v) if v.len() == 2));
        let c = condition("all of them", &names).unwrap();
        assert!(matches!(c, Cond::And(ref v) if v.len() == 3));
        assert!(condition("sel | count() > 5", &names).is_err());
        assert!(condition("nope", &names).is_err());
        let c = condition("(sel or sel_a) and filter", &names).unwrap();
        assert!(matches!(c, Cond::And(_)));
    }
}
