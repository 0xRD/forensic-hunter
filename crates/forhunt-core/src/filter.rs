//! Event filters. Cheap checks (event id, channel, time) run first; field
//! comparisons and regexes only run on events that survive them.

use regex::{Regex, RegexBuilder};

use crate::event::EventView;
use crate::normalize::channel_matches;
use crate::time::Ts;

#[derive(Debug, Clone)]
pub enum FieldOp {
    /// Case-insensitive equality.
    Eq(String),
    /// Case-insensitive inequality (also true when the field is absent).
    Ne(String),
    /// Case-insensitive substring (needle stored lowercased).
    Contains(String),
    /// `Name!~text`: no case-insensitive substring (also true when the
    /// field is absent).
    NotContains(String),
}

#[derive(Debug, Clone)]
pub struct FieldCond {
    pub name: String,
    pub op: FieldOp,
}

impl FieldCond {
    /// Parses `Name=value`, `Name!=value` or `Name~substring`.
    pub fn parse(s: &str) -> anyhow::Result<FieldCond> {
        let idx = s.find(['=', '~', '!']).ok_or_else(|| {
            anyhow::anyhow!(
                "--field `{s}`: expected Name=value, Name!=value, Name~substring or Name!~substring"
            )
        })?;
        let (name, rest) = s.split_at(idx);
        let name = name.trim();
        if name.is_empty() {
            anyhow::bail!("--field `{s}`: empty field name");
        }
        let op = if let Some(v) = rest.strip_prefix("!~") {
            FieldOp::NotContains(v.to_lowercase())
        } else if let Some(v) = rest.strip_prefix("!=") {
            FieldOp::Ne(v.to_string())
        } else if let Some(v) = rest.strip_prefix('=') {
            FieldOp::Eq(v.to_string())
        } else if let Some(v) = rest.strip_prefix('~') {
            FieldOp::Contains(v.to_lowercase())
        } else {
            anyhow::bail!(
                "--field `{s}`: expected Name=value, Name!=value, Name~substring or Name!~substring"
            );
        };
        Ok(FieldCond {
            name: name.to_string(),
            op,
        })
    }

    fn matches(&self, ev: &EventView<'_>) -> bool {
        let v = ev.get_ci(&self.name);
        match (&self.op, v) {
            (FieldOp::Eq(want), Some(v)) => value_eq(&v, want),
            (FieldOp::Eq(want), None) => want.is_empty(),
            (FieldOp::Ne(want), Some(v)) => !value_eq(&v, want),
            (FieldOp::Ne(_), None) => true,
            (FieldOp::Contains(n), Some(v)) => value_contains(&v, n),
            (FieldOp::Contains(_), None) => false,
            (FieldOp::NotContains(n), Some(v)) => !value_contains(&v, n),
            (FieldOp::NotContains(_), None) => true,
        }
    }
}

/// Parses decimal or `0x` hexadecimal integers.
pub fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) if !h.is_empty() => u64::from_str_radix(h, 16).ok(),
        _ if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s.parse().ok(),
        _ => None,
    }
}

/// Numeric equality, so `0x17` matches `0x00000017` and `23`. Only applies when
/// the wanted value is written in hex: plain decimal strings are compared as text.
fn num_eq(have: &str, want: &str) -> bool {
    let w = want.trim();
    if !(w.starts_with("0x") || w.starts_with("0X"))
        && !(have.starts_with("0x") || have.starts_with("0X"))
    {
        return false;
    }
    matches!((parse_num(have), parse_num(want)), (Some(a), Some(b)) if a == b)
}

/// Equality as an analyst means it: text ignoring case, numbers across hex
/// and decimal, GUIDs with or without braces (`{42e0bcd9-...}`, as Windows
/// shows them), timestamps at microsecond precision (Windows shows 7 digits).
fn value_eq(have: &str, want: &str) -> bool {
    eq_ci(have, want) || num_eq(have, want) || guid_eq(have, want) || time_eq(have, want)
}

/// Case-insensitive substring; a GUID value also contains its braces.
fn value_contains(have: &str, needle: &str) -> bool {
    contains_ci(have, needle)
        || (needle.contains(['{', '}'])
            && braced_guid(have).is_some_and(|b| contains_ci(&b, needle)))
}

/// `8-4-4-4-12` hexadecimal digits, as evtx renders GUID values.
fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// `{GUID}` for a bare GUID value (the Windows form), else `None`.
fn braced_guid(s: &str) -> Option<String> {
    is_guid(s).then(|| format!("{{{s}}}"))
}

fn strip_braces(s: &str) -> &str {
    let s = s.trim();
    s.strip_prefix('{')
        .and_then(|x| x.strip_suffix('}'))
        .unwrap_or(s)
}

fn guid_eq(have: &str, want: &str) -> bool {
    let (a, b) = (strip_braces(have), strip_braces(want));
    is_guid(a) && is_guid(b) && a.eq_ignore_ascii_case(b)
}

fn time_eq(have: &str, want: &str) -> bool {
    let looks = |s: &str| {
        let b = s.as_bytes();
        b.len() >= 19
            && b[4] == b'-'
            && b[7] == b'-'
            && matches!(b[10], b'T' | b' ')
            && b[13] == b':'
    };
    let want = want.trim();
    if !looks(have) || !looks(want) {
        return false;
    }
    match (Ts::parse(have), Ts::parse(want)) {
        (Some(a), Some(b)) => a.0.div_euclid(10) == b.0.div_euclid(10),
        _ => false,
    }
}

pub fn eq_ci(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        a.eq_ignore_ascii_case(b)
    } else {
        a.to_lowercase() == b.to_lowercase()
    }
}

/// `needle` must already be lowercase.
pub fn contains_ci(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if hay.is_ascii() && needle.is_ascii() {
        let (h, n) = (hay.as_bytes(), needle.as_bytes());
        if n.len() > h.len() {
            return false;
        }
        // Candidate positions of the first byte (either case), then compare.
        let (lo, up) = (n[0], n[0].to_ascii_uppercase());
        let last = h.len() - n.len();
        let mut i = 0;
        while i <= last {
            match memchr::memchr2(lo, up, &h[i..=last]) {
                Some(p) if h[i + p..i + p + n.len()].eq_ignore_ascii_case(n) => return true,
                Some(p) => i += p + 1,
                None => return false,
            }
        }
        return false;
    }
    hay.to_lowercase().contains(needle)
}

#[derive(Debug, Clone)]
pub struct RegexCond {
    /// `None`: match against any payload value and the System strings.
    pub field: Option<String>,
    pub re: Regex,
    /// With `field`: the whole argument as a pattern, used on events that
    /// have no such field (`pAA==$` is a pattern, not field `pAA`).
    whole: Option<Regex>,
}

impl RegexCond {
    /// `Name=PATTERN` targets field `Name` on events that have it; on other
    /// events the whole argument is matched against every value, so patterns
    /// containing `=` (base64 padding...) still work. Case-insensitive.
    pub fn parse(s: &str) -> anyhow::Result<RegexCond> {
        let build = |pat: &str| {
            RegexBuilder::new(pat)
                .case_insensitive(true)
                .size_limit(32 << 20)
                .build()
        };
        let err = |e: regex::Error| anyhow::anyhow!("--regex `{s}`: {e}");
        match s.split_once('=') {
            Some((n, p)) if is_field_name(n) && (build(p).is_ok() || build(s).is_err()) => {
                Ok(RegexCond {
                    field: Some(n.to_string()),
                    re: build(p).map_err(err)?,
                    whole: build(s).ok(),
                })
            }
            _ => Ok(RegexCond {
                field: None,
                re: build(s).map_err(err)?,
                whole: None,
            }),
        }
    }

    fn matches(&self, ev: &EventView<'_>) -> bool {
        match &self.field {
            Some(f) => match ev.get_ci(f) {
                Some(v) => re_match(&self.re, &v),
                None => self.whole.as_ref().is_some_and(|w| any_value(w, ev)),
            },
            None => any_value(&self.re, ev),
        }
    }
}

/// A GUID value also matches in its Windows form, `{guid}`.
fn re_match(re: &Regex, v: &str) -> bool {
    re.is_match(v) || braced_guid(v).is_some_and(|b| re.is_match(&b))
}

fn any_value(re: &Regex, ev: &EventView<'_>) -> bool {
    ev.fields.iter().any(|f| re_match(re, f.value.as_str()))
        || re.is_match(&ev.computer)
        || re.is_match(&ev.provider)
}

fn is_field_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
        && c.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '[' | ']' | '-'))
}

/// `--computer` semantics (both sides lowercase): exact, short name of an
/// FQDN, or (event logged under its short name) the first label of the
/// wanted FQDN.
pub fn computer_matches(want: &str, host: &str) -> bool {
    host == want
        || host.strip_prefix(want).is_some_and(|r| r.starts_with('.'))
        || (!host.is_empty()
            && !host.contains('.')
            && want.split_once('.').is_some_and(|(short, _)| short == host))
}

/// A compiled filter. The default filter matches everything.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    event_ids: Option<Vec<u32>>,
    channels: Vec<String>,
    computers: Vec<String>,
    pub since: Option<Ts>,
    pub until: Option<Ts>,
    fields: Vec<FieldCond>,
    regexes: Vec<RegexCond>,
    /// Slack (in [`Ts`] ticks) applied to the record-header pre-check (see [`Filter::want_header_time`]).
    pub header_slack: i64,
}

impl Filter {
    pub fn new() -> Self {
        Filter {
            header_slack: 24 * 3600 * 10_000_000,
            ..Default::default()
        }
    }

    pub fn event_ids(mut self, ids: Vec<u32>) -> Self {
        if !ids.is_empty() {
            let mut ids = ids;
            ids.sort_unstable();
            ids.dedup();
            self.event_ids = Some(ids);
        }
        self
    }

    pub fn channels(mut self, c: Vec<String>) -> Self {
        self.channels = c;
        self
    }

    pub fn computers(mut self, c: Vec<String>) -> Self {
        self.computers = c.into_iter().map(|s| s.to_lowercase()).collect();
        self
    }

    pub fn time(mut self, since: Option<Ts>, until: Option<Ts>) -> Self {
        self.since = since;
        self.until = until;
        self
    }

    pub fn fields(mut self, f: Vec<FieldCond>) -> Self {
        self.fields = f;
        self
    }

    pub fn regexes(mut self, r: Vec<RegexCond>) -> Self {
        self.regexes = r;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.event_ids.is_none()
            && self.channels.is_empty()
            && self.computers.is_empty()
            && self.since.is_none()
            && self.until.is_none()
            && self.fields.is_empty()
            && self.regexes.is_empty()
    }

    /// Cheap pre-check on the event id, before the record is decoded.
    #[inline]
    pub fn want_event_id(&self, id: u32) -> bool {
        self.event_ids
            .as_ref()
            .is_none_or(|ids| ids.binary_search(&id).is_ok())
    }

    /// Pre-check on the record header timestamp, before the record is
    /// rendered. The header holds the time the record was *written*, which
    /// can lag `TimeCreated` (forwarded events), hence the slack.
    #[inline]
    pub fn want_header_time(&self, t: Ts) -> bool {
        if let Some(s) = self.since
            && t.0 < s.0.saturating_sub(self.header_slack)
        {
            return false;
        }
        if let Some(u) = self.until
            && t.0 > u.0.saturating_add(self.header_slack)
        {
            return false;
        }
        true
    }

    #[inline]
    pub fn matches(&self, ev: &EventView<'_>) -> bool {
        self.matches_source(ev)
            && self.fields.iter().all(|f| f.matches(ev))
            && self.regexes.iter().all(|r| r.matches(ev))
    }

    /// The channels this filter keeps (empty: any).
    pub fn channel_list(&self) -> &[String] {
        &self.channels
    }

    /// The computers this filter keeps, lowercased (empty: any).
    pub fn computer_list(&self) -> &[String] {
        &self.computers
    }

    /// The event ids this filter keeps (`None`: any).
    pub fn event_id_list(&self) -> Option<&[u32]> {
        self.event_ids.as_deref()
    }

    /// True if every field a positive condition reads (`Name=value`,
    /// `Name~text`, `Name=regex`) exists in `ev`. Otherwise the event cannot
    /// tell a match from a miss (e.g. 4688 without command-line auditing).
    pub fn fields_present(&self, ev: &EventView<'_>) -> bool {
        self.fields.iter().all(|f| match &f.op {
            FieldOp::Eq(v) if v.is_empty() => true,
            FieldOp::Eq(_) | FieldOp::Contains(_) => ev.get_ci(&f.name).is_some(),
            FieldOp::Ne(_) | FieldOp::NotContains(_) => true,
        }) && self
            .regexes
            .iter()
            .all(|r| r.field.as_ref().is_none_or(|n| ev.get_ci(n).is_some()))
    }

    /// True if `ev` is in this filter's log source: its event ids, channels,
    /// computers and time window; field and regex conditions are ignored.
    pub fn matches_source(&self, ev: &EventView<'_>) -> bool {
        if let Some(ids) = &self.event_ids
            && ids.binary_search(&ev.event_id).is_err()
        {
            return false;
        }
        if let Some(s) = self.since
            && ev.ts < s
        {
            return false;
        }
        if let Some(u) = self.until
            && ev.ts > u
        {
            return false;
        }
        if !self.channels.is_empty()
            && !self
                .channels
                .iter()
                .any(|c| channel_matches(c, &ev.channel))
        {
            return false;
        }
        if !self.computers.is_empty() {
            let host = ev.computer.to_lowercase();
            if !self.computers.iter().any(|c| computer_matches(c, &host)) {
                return false;
            }
        }
        true
    }

    /// Renders the active filter as CLI flags (for summaries and suggestions).
    pub fn describe(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(ids) = &self.event_ids {
            out.push(format!(
                "--event-id {}",
                ids.iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        for c in &self.channels {
            out.push(format!("--channel {c}"));
        }
        for c in &self.computers {
            out.push(format!("--computer {c}"));
        }
        if let Some(s) = self.since {
            out.push(format!("--since {s}"));
        }
        if let Some(u) = self.until {
            out.push(format!("--until {u}"));
        }
        for f in &self.fields {
            let s = match &f.op {
                FieldOp::Eq(v) => format!("{}={v}", f.name),
                FieldOp::Ne(v) => format!("{}!={v}", f.name),
                FieldOp::Contains(v) => format!("{}~{v}", f.name),
                FieldOp::NotContains(v) => format!("{}!~{v}", f.name),
            };
            out.push(format!("--field {s}"));
        }
        for r in &self.regexes {
            match &r.field {
                Some(f) => out.push(format!("--regex {f}={}", r.re.as_str())),
                None => out.push(format!("--regex {}", r.re.as_str())),
            }
        }
        out
    }
}

/// Parses `4624,4625,4600-4700`.
pub fn parse_event_ids(specs: &[String]) -> anyhow::Result<Vec<u32>> {
    let mut out = Vec::new();
    for spec in specs {
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if let Some((a, b)) = part.split_once('-') {
                let (a, b): (u32, u32) = (a.trim().parse()?, b.trim().parse()?);
                if b < a || b - a > 70_000 {
                    anyhow::bail!("bad event id range `{part}`");
                }
                out.extend(a..=b);
            } else {
                out.push(
                    part.parse()
                        .map_err(|_| anyhow::anyhow!("bad event id `{part}`"))?,
                );
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Field, Val};
    use std::borrow::Cow;

    fn ev() -> EventView<'static> {
        EventView {
            event_id: 4624,
            channel: "Security".into(),
            computer: "DC01.corp.local".into(),
            ts: Ts::parse("2024-01-01T10:00:00Z").unwrap(),
            fields: vec![
                Field {
                    name: "TargetUserName".into(),
                    value: Val::Str(Cow::Borrowed("Alice")),
                },
                Field {
                    name: "LogonType".into(),
                    value: Val::Num(Cow::Borrowed("3")),
                },
                Field {
                    name: "CommandLine".into(),
                    value: Val::Str(Cow::Borrowed("powershell -enc SQBFAFgA")),
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn basic() {
        let e = ev();
        assert!(Filter::new().matches(&e));
        assert!(Filter::new().event_ids(vec![4625, 4624]).matches(&e));
        assert!(!Filter::new().event_ids(vec![4625]).matches(&e));
        assert!(Filter::new().channels(vec!["security".into()]).matches(&e));
        assert!(Filter::new().computers(vec!["dc01".into()]).matches(&e));
        assert!(!Filter::new().computers(vec!["dc0".into()]).matches(&e));
        let since = Ts::parse("2024-01-01T11:00:00Z");
        assert!(!Filter::new().time(since, None).matches(&e));
    }

    #[test]
    fn fields_and_regex() {
        let e = ev();
        let f = |s: &str| Filter::new().fields(vec![FieldCond::parse(s).unwrap()]);
        assert!(f("TargetUserName=alice").matches(&e));
        assert!(f("logontype=3").matches(&e));
        assert!(!f("LogonType!=3").matches(&e));
        assert!(f("CommandLine~-ENC").matches(&e));
        assert!(!f("CommandLine!~-ENC").matches(&e));
        assert!(f("CommandLine!~mimikatz").matches(&e));
        assert!(f("Missing!~x").matches(&e));
        // Coverage: the source matches, but a tested field may be absent.
        assert!(f("Missing~x").matches_source(&e));
        assert!(!f("Missing~x").fields_present(&e));
        assert!(f("CommandLine~x").fields_present(&e));
        assert!(f("Missing!~x").fields_present(&e));
        assert!(f("Computer~corp").matches(&e));
        assert!(f("LogonType=0x3").matches(&e));
        assert!(!f("LogonType=03").matches(&e));
        let r = |s: &str| Filter::new().regexes(vec![RegexCond::parse(s).unwrap()]);
        assert!(r("CommandLine=-enc\\s+[A-Za-z0-9+/=]{8}").matches(&e));
        assert!(r("POWERSHELL").matches(&e));
        assert!(!r("TargetUserName=bob").matches(&e));
        assert!(r("a=b|alice").matches(&e) || r("alice").matches(&e));
        // Not a field of this event: the whole argument is the pattern.
        assert!(r("alic=?e$").matches(&e));
        assert!(r("TargetUserName=^alice$").matches(&e));
        assert!(!r("TargetUserName=x=y").matches(&e));
        let mut b = e.clone();
        b.fields.push(Field {
            name: "ScriptBlockText".into(),
            value: Val::Str(Cow::Borrowed("-e JABpAA==")),
        });
        assert!(r("pAA==$").matches(&b));
        assert!(r("ScriptBlockText=pAA==$").matches(&b));
    }

    #[test]
    fn event_record_id_is_the_system_value() {
        // Exported logs renumber record headers: the analyst sees (and
        // Hayabusa reports) System/EventRecordID, not the header id.
        let mut e = ev();
        e.id.record = 1;
        e.event_record_id = 3166;
        let f = |s: &str| Filter::new().fields(vec![FieldCond::parse(s).unwrap()]);
        assert!(f("EventRecordID=3166").matches(&e));
        assert!(!f("EventRecordID=1").matches(&e));
    }

    #[test]
    fn single_unnamed_data_is_data_1() {
        // One unnamed <Data> decodes as `Data`; several as `Data[1]`...
        // The documented name `Data[1]` must find both.
        let mut e = ev();
        e.fields = vec![Field {
            name: "Data".into(),
            value: Val::Str(Cow::Borrowed("TriggerStarted:6")),
        }];
        let f = |s: &str| Filter::new().fields(vec![FieldCond::parse(s).unwrap()]);
        assert!(f("Data[1]=TriggerStarted:6").matches(&e));
        assert!(f("data[1]~started").matches(&e));
        assert!(!f("Data[1]!=TriggerStarted:6").matches(&e));
        assert!(f("Data=TriggerStarted:6").matches(&e));
        assert!(!f("Data[2]=TriggerStarted:6").matches(&e));
        let r = |s: &str| Filter::new().regexes(vec![RegexCond::parse(s).unwrap()]);
        assert!(r("Data[1]=^Trigger").matches(&e));
    }

    #[test]
    fn guids_match_in_windows_form() {
        // forhunt renders GUIDs as evtx does (`42E0BCD9-...`); Windows,
        // Sysmon XML, EvtxECmd and SIEMs show `{42e0bcd9-...}`.
        let mut e = ev();
        e.fields.push(Field {
            name: "ProcessGuid".into(),
            value: Val::Str(Cow::Borrowed("42E0BCD9-851F-68F7-F800-000000002E00")),
        });
        let f = |s: &str| Filter::new().fields(vec![FieldCond::parse(s).unwrap()]);
        assert!(f("ProcessGuid={42e0bcd9-851f-68f7-f800-000000002e00}").matches(&e));
        assert!(f("ProcessGuid=42e0bcd9-851f-68f7-f800-000000002e00").matches(&e));
        assert!(!f("ProcessGuid!={42e0bcd9-851f-68f7-f800-000000002e00}").matches(&e));
        assert!(f("ProcessGuid~{42e0bcd9-851f").matches(&e));
        assert!(f("ProcessGuid~2e00}").matches(&e));
        assert!(!f("ProcessGuid!~{42e0bcd9").matches(&e));
        assert!(!f("ProcessGuid={42e0bcd9-851f-68f7-f800-000000002e01}").matches(&e));
        let r = |s: &str| Filter::new().regexes(vec![RegexCond::parse(s).unwrap()]);
        assert!(r("ProcessGuid=^\\{42e0bcd9-").matches(&e));
        assert!(r("\\{42e0bcd9-851f").matches(&e));
        assert!(!r("ProcessGuid=^\\{0000").matches(&e));
    }

    #[test]
    fn timestamps_match_in_windows_form() {
        // forhunt renders FILETIME values with microseconds; Windows shows
        // 7 digits (`2025-10-21T14:19:55.9050049Z`).
        let mut e = ev();
        e.fields.push(Field {
            name: "ProcessCreationTime".into(),
            value: Val::Str(Cow::Borrowed("2025-10-21T14:19:55.905004Z")),
        });
        let f = |s: &str| Filter::new().fields(vec![FieldCond::parse(s).unwrap()]);
        assert!(f("ProcessCreationTime=2025-10-21T14:19:55.9050049Z").matches(&e));
        assert!(f("ProcessCreationTime=2025-10-21 14:19:55.905004").matches(&e));
        assert!(!f("ProcessCreationTime!=2025-10-21T14:19:55.9050049Z").matches(&e));
        assert!(!f("ProcessCreationTime=2025-10-21T14:19:55.9050059Z").matches(&e));
        assert!(!f("ProcessCreationTime=2025-10-21").matches(&e));
    }

    #[test]
    fn computer_fqdn_also_matches_its_short_name() {
        // Some events (early boot, some providers) carry the short name;
        // `stats` folds it into the FQDN, so the FQDN filter must keep them.
        let mut e = ev();
        e.computer = "DC01".into();
        let c = |s: &str| Filter::new().computers(vec![s.into()]);
        assert!(c("DC01.corp.local").matches(&e));
        assert!(c("dc01").matches(&e));
        assert!(!c("DC02.corp.local").matches(&e));
        assert!(!c("DC0.corp.local").matches(&e));
        e.computer = "DC01.other.local".into();
        assert!(!c("DC01.corp.local").matches(&e));
    }

    #[test]
    fn ids() {
        assert_eq!(
            parse_event_ids(&["4624, 4625".into(), "1-3".into()]).unwrap(),
            vec![4624, 4625, 1, 2, 3]
        );
        assert!(parse_event_ids(&["x".into()]).is_err());
    }
}
