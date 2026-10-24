//! The borrowed event model shared by every artifact.

use std::borrow::Cow;

use crate::id::EventRef;
use crate::time::Ts;

/// A field value as decoded, borrowing from the decoder buffer when possible.
#[derive(Debug, Clone, PartialEq)]
pub enum Val<'a> {
    Str(Cow<'a, str>),
    /// A number kept as its decimal text (no float round trip).
    Num(Cow<'a, str>),
    Bool(bool),
    Null,
}

impl Val<'_> {
    /// Text view of the value (`""` for null).
    pub fn as_str(&self) -> &str {
        match self {
            Val::Str(s) | Val::Num(s) => s,
            Val::Bool(true) => "true",
            Val::Bool(false) => "false",
            Val::Null => "",
        }
    }

    /// True for values that carry no information in Windows logs (`-`, empty, null).
    pub fn is_blank(&self) -> bool {
        match self {
            Val::Null => true,
            Val::Str(s) => s.is_empty() || s == "-",
            _ => false,
        }
    }

    pub fn into_owned(self) -> Val<'static> {
        match self {
            Val::Str(s) => Val::Str(Cow::Owned(s.into_owned())),
            Val::Num(s) => Val::Num(Cow::Owned(s.into_owned())),
            Val::Bool(b) => Val::Bool(b),
            Val::Null => Val::Null,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field<'a> {
    pub name: Cow<'a, str>,
    pub value: Val<'a>,
}

/// One decoded event. `System` header values are typed, payload values
/// (`EventData`, `UserData`, ...) are flattened into `fields` in document order.
#[derive(Debug, Clone, Default)]
pub struct EventView<'a> {
    pub id: EventRef,
    /// Event creation time (`TimeCreated/@SystemTime`), UTC.
    pub ts: Ts,
    pub event_id: u32,
    pub provider: Cow<'a, str>,
    pub channel: Cow<'a, str>,
    pub computer: Cow<'a, str>,
    pub level: u8,
    pub task: u32,
    pub opcode: u32,
    pub version: u32,
    pub keywords: Cow<'a, str>,
    pub process_id: u32,
    pub thread_id: u32,
    /// `Security/@UserID`: the SID the event was logged under.
    pub user_sid: Cow<'a, str>,
    pub activity_id: Cow<'a, str>,
    /// `System/EventRecordID`. Equal to `id.record` (the record header id) in
    /// native logs; differs in exported or filtered logs, where headers are
    /// renumbered but this keeps the original value (what Hayabusa reports).
    pub event_record_id: u64,
    pub fields: Vec<Field<'a>>,
}

impl<'a> EventView<'a> {
    /// First payload field with this name (case-sensitive, as Windows writes it).
    pub fn field(&self, name: &str) -> Option<&Val<'a>> {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| &f.value)
    }

    /// Case-insensitive lookup, also covering the `System` values so filters can
    /// address `Computer`, `Channel`, `Provider`, `EventID` like any field.
    pub fn get_ci(&self, name: &str) -> Option<Cow<'_, str>> {
        if let Some(f) = self
            .fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
        {
            return Some(Cow::Borrowed(f.value.as_str()));
        }
        let sys = match name.to_ascii_lowercase().as_str() {
            "computer" => &self.computer,
            "channel" => &self.channel,
            "provider" => &self.provider,
            "keywords" => &self.keywords,
            "userid" | "user_sid" => &self.user_sid,
            "eventid" => return Some(Cow::Owned(self.event_id.to_string())),
            "level" => return Some(Cow::Owned(self.level.to_string())),
            // The System value (what Windows and Hayabusa show), not the
            // record header id: they differ in exported logs.
            "eventrecordid" => {
                let n = match self.event_record_id {
                    0 => self.id.record,
                    n => n,
                };
                return Some(Cow::Owned(n.to_string()));
            }
            _ => return None,
        };
        Some(Cow::Borrowed(sys.as_ref()))
    }

    pub fn into_owned(self) -> EventView<'static> {
        fn o(c: Cow<'_, str>) -> Cow<'static, str> {
            Cow::Owned(c.into_owned())
        }
        EventView {
            id: self.id,
            ts: self.ts,
            event_id: self.event_id,
            provider: o(self.provider),
            channel: o(self.channel),
            computer: o(self.computer),
            level: self.level,
            task: self.task,
            opcode: self.opcode,
            version: self.version,
            keywords: o(self.keywords),
            process_id: self.process_id,
            thread_id: self.thread_id,
            user_sid: o(self.user_sid),
            activity_id: o(self.activity_id),
            event_record_id: self.event_record_id,
            fields: self
                .fields
                .into_iter()
                .map(|f| Field {
                    name: o(f.name),
                    value: f.value.into_owned(),
                })
                .collect(),
        }
    }
}
