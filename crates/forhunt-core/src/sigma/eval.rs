//! Matching compiled rules against one event.

use std::borrow::Cow;
use std::cell::OnceCell;

use super::compile::{Cond, FieldRef, FieldTest, Kind, M, SYS_COUNT, Sel, Sys, lower, parse_num};
use crate::event::EventView;

/// One event under evaluation. Values are lowercased at most once, on first
/// use, and shared by every rule tried on the event.
pub(crate) struct Ev<'e, 'v> {
    pub ev: &'e EventView<'v>,
    low: Vec<OnceCell<Cow<'e, str>>>,
    sys: [OnceCell<Cow<'e, str>>; SYS_COUNT],
    /// Slots of each interned field name, resolved on first use.
    names: Vec<OnceCell<Box<[u16]>>>,
}

/// `name` or `name[N]` (how forhunt names the items of a list value).
fn name_is(field: &str, name: &str, ci: bool) -> bool {
    if field.len() < name.len() {
        return false;
    }
    let (head, tail) = field.split_at(name.len());
    let head_ok = if ci {
        head.eq_ignore_ascii_case(name)
    } else {
        head == name
    };
    head_ok
        && (tail.is_empty()
            || (tail.len() > 2
                && tail.starts_with('[')
                && tail.ends_with(']')
                && tail[1..tail.len() - 1].bytes().all(|b| b.is_ascii_digit())))
}

impl<'e, 'v> Ev<'e, 'v> {
    /// `names`: number of interned field names of the rule set.
    pub fn new(ev: &'e EventView<'v>, names: usize) -> Self {
        Ev {
            ev,
            low: (0..ev.fields.len() + SYS_COUNT)
                .map(|_| OnceCell::new())
                .collect(),
            sys: std::array::from_fn(|_| OnceCell::new()),
            names: (0..names).map(|_| OnceCell::new()).collect(),
        }
    }

    /// Slots of payload field `name`: exact name (or `name[N]`), else the
    /// same ignoring case.
    fn resolve(&self, name: &str) -> Box<[u16]> {
        for ci in [false, true] {
            let v: Vec<u16> = (0..self.ev.fields.len().min(u16::MAX as usize))
                .filter(|&i| name_is(&self.ev.fields[i].name, name, ci))
                .map(|i| i as u16)
                .collect();
            if !v.is_empty() {
                return v.into();
            }
        }
        Box::new([])
    }

    fn sys_text(&self, s: Sys) -> &str {
        let ev = self.ev;
        self.sys[s.slot()].get_or_init(|| match s {
            Sys::Channel => Cow::Borrowed(ev.channel.as_ref()),
            Sys::Provider => Cow::Borrowed(ev.provider.as_ref()),
            Sys::Computer => Cow::Borrowed(ev.computer.as_ref()),
            Sys::Keywords => Cow::Borrowed(ev.keywords.as_ref()),
            Sys::UserId => Cow::Borrowed(ev.user_sid.as_ref()),
            Sys::EventId => Cow::Owned(ev.event_id.to_string()),
            Sys::Level => Cow::Owned(ev.level.to_string()),
            Sys::ProcessId => Cow::Owned(ev.process_id.to_string()),
            Sys::ThreadId => Cow::Owned(ev.thread_id.to_string()),
            Sys::Version => Cow::Owned(ev.version.to_string()),
            Sys::Task => Cow::Owned(ev.task.to_string()),
            Sys::Opcode => Cow::Owned(ev.opcode.to_string()),
            Sys::RecordId => Cow::Owned(
                match ev.event_record_id {
                    0 => ev.id.record,
                    n => n,
                }
                .to_string(),
            ),
        })
    }

    /// The value in slot `i`: payload fields first, then `System` values.
    pub fn orig(&self, i: usize) -> &str {
        let n = self.ev.fields.len();
        if i < n {
            self.ev.fields[i].value.as_str()
        } else {
            self.sys_text(SYS_ORDER[i - n])
        }
    }

    pub fn low(&self, i: usize) -> &str {
        self.low[i].get_or_init(|| {
            let n = self.ev.fields.len();
            if i < n {
                lower(self.ev.fields[i].value.as_str())
            } else {
                Cow::Owned(lower(self.sys_text(SYS_ORDER[i - n])).into_owned())
            }
        })
    }

    /// Calls `f` on each slot holding `field` until it returns true.
    /// `None` when the event has no such field.
    pub fn each(&self, field: &FieldRef, mut f: impl FnMut(usize) -> bool) -> Option<bool> {
        match field {
            FieldRef::Sys(s) => Some(f(self.ev.fields.len() + s.slot())),
            FieldRef::Payload(name, id) => {
                let fresh;
                let slots: &[u16] = match self.names.get(*id as usize) {
                    Some(c) => c.get_or_init(|| self.resolve(name)),
                    None => {
                        fresh = self.resolve(name);
                        &fresh
                    }
                };
                if slots.is_empty() {
                    return None;
                }
                Some(slots.iter().any(|&i| f(i as usize)))
            }
        }
    }

    fn value_matches(&self, i: usize, m: &M) -> bool {
        match m {
            M::Str {
                kind,
                needle,
                cased,
                finder,
            } => {
                let h = if *cased { self.orig(i) } else { self.low(i) };
                match kind {
                    Kind::Eq => h == needle.as_ref(),
                    Kind::Starts => h.starts_with(needle.as_ref()),
                    Kind::Ends => h.ends_with(needle.as_ref()),
                    Kind::Contains => match finder {
                        Some(f) => f.find(h.as_bytes()).is_some(),
                        None => true,
                    },
                }
            }
            M::AnyContains { ac, cased, .. } => {
                ac.is_match(if *cased { self.orig(i) } else { self.low(i) })
            }
            M::AnyEq { set, cased } => {
                set.contains(if *cased { self.orig(i) } else { self.low(i) })
            }
            M::Re { re, lowered, .. } => {
                re.is_match(if *lowered { self.low(i) } else { self.orig(i) })
            }
            M::Cidr(n) => n.contains(self.orig(i)),
            M::Cmp(op, n) => parse_num(self.orig(i)).is_some_and(|x| {
                use super::compile::CmpOp::*;
                match op {
                    Gt => x > *n,
                    Ge => x >= *n,
                    Lt => x < *n,
                    Le => x <= *n,
                }
            }),
            M::FieldRef { other, kind } => self
                .each(other, |o| {
                    let (a, b) = (self.low(i), self.low(o));
                    match kind {
                        Kind::Eq => a == b,
                        Kind::Starts => a.starts_with(b),
                        Kind::Ends => a.ends_with(b),
                        Kind::Contains => a.contains(b),
                    }
                })
                .unwrap_or(false),
            M::Null | M::Exists(_) => false,
        }
    }

    fn matcher(&self, f: &FieldRef, m: &M) -> bool {
        match m {
            M::Null => match self.each(f, |i| !self.orig(i).is_empty()) {
                None => true,
                Some(non_empty) => !non_empty,
            },
            M::Exists(want) => self.each(f, |_| true).is_some() == *want,
            // `Field: ''` also holds when the field is absent (Hayabusa's
            // reading, which its own rules rely on: Sysmon `RuleName: ''`).
            M::Str {
                kind: Kind::Eq,
                needle,
                ..
            } if needle.is_empty() => self.each(f, |i| self.orig(i).is_empty()).unwrap_or(true),
            _ => self.each(f, |i| self.value_matches(i, m)).unwrap_or(false),
        }
    }

    fn test(&self, t: &FieldTest) -> bool {
        if t.all {
            !t.ms.is_empty() && t.ms.iter().all(|m| self.matcher(&t.field, m))
        } else {
            t.ms.iter().any(|m| self.matcher(&t.field, m))
        }
    }

    pub fn sel(&self, s: &Sel) -> bool {
        match s {
            Sel::And(ts) => ts.iter().all(|t| self.test(t)),
            Sel::Or(xs) => xs.iter().any(|x| self.sel(x)),
            Sel::Keywords(ms) => {
                (0..self.ev.fields.len()).any(|i| ms.iter().any(|m| self.value_matches(i, m)))
            }
        }
    }

    /// `memo[k]`: 0 unknown, 1 false, 2 true.
    pub fn cond(&self, c: &Cond, sels: &[Sel], memo: &mut [u8]) -> bool {
        match c {
            Cond::Sel(k) => match memo[*k] {
                0 => {
                    let r = self.sel(&sels[*k]);
                    memo[*k] = 1 + r as u8;
                    r
                }
                v => v == 2,
            },
            Cond::Not(x) => !self.cond(x, sels, memo),
            Cond::And(xs) => xs.iter().all(|x| self.cond(x, sels, memo)),
            Cond::Or(xs) => xs.iter().any(|x| self.cond(x, sels, memo)),
        }
    }
}

/// Slot order of the `System` values (same as `Sys as usize`).
const SYS_ORDER: [Sys; SYS_COUNT] = [
    Sys::Channel,
    Sys::EventId,
    Sys::Provider,
    Sys::Computer,
    Sys::Level,
    Sys::Keywords,
    Sys::UserId,
    Sys::ProcessId,
    Sys::ThreadId,
    Sys::Version,
    Sys::RecordId,
    Sys::Task,
    Sys::Opcode,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(name_is("Data", "Data", false));
        assert!(name_is("Data[12]", "Data", false));
        assert!(!name_is("DataX", "Data", false));
        assert!(!name_is("Data[]", "Data", false));
        assert!(name_is("commandline", "CommandLine", true));
        assert!(!name_is("commandline", "CommandLine", false));
        for (k, s) in SYS_ORDER.iter().enumerate() {
            assert_eq!(s.slot(), k);
        }
    }
}
