//! Output writers. Every writer appends one event to a byte buffer; the
//! caller owns buffering and ordering, so writers can run on worker threads.

pub mod csv;
pub mod export;
pub mod json;
pub mod jsonl;
pub mod llm;

use forhunt_core::normalize::FieldMap;
use forhunt_core::{EventView, Ts};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Csv,
    Jsonl,
    Llm,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "csv" => Ok(Format::Csv),
            "jsonl" | "json" => Ok(Format::Jsonl),
            "llm" => Ok(Format::Llm),
            _ => Err(format!("unknown format `{s}` (csv, jsonl, llm)")),
        }
    }
}

/// Options shared by all writers.
#[derive(Debug, Clone)]
pub struct WriteOptions {
    /// Display time zone; `None` writes UTC (`...Z`).
    pub tz: Option<jiff::tz::TimeZone>,
    /// `llm`: maximum characters per value before truncation.
    pub max_value_len: usize,
    /// `llm`: keep every non-blank field instead of the mapped selection.
    pub all_fields: bool,
    /// `llm`: only these fields in `d` (short or full names; empty: all).
    pub only: Vec<String>,
}

impl Default for WriteOptions {
    fn default() -> Self {
        WriteOptions {
            tz: None,
            max_value_len: 256,
            all_fields: false,
            only: Vec::new(),
        }
    }
}

pub struct Writer<'m> {
    pub format: Format,
    pub opts: WriteOptions,
    pub map: &'m FieldMap,
}

impl<'m> Writer<'m> {
    pub fn new(format: Format, opts: WriteOptions, map: &'m FieldMap) -> Self {
        Writer { format, opts, map }
    }

    /// Bytes to emit once before the first event (CSV header).
    pub fn header(&self) -> &'static [u8] {
        match self.format {
            Format::Csv => csv::HEADER,
            _ => b"",
        }
    }

    /// Appends one event. `source` is the input file path (CSV `SourceFile`,
    /// JSONL `source_file`; not in the compact `llm` format).
    pub fn write(&self, ev: &EventView<'_>, source: &str, out: &mut Vec<u8>) {
        match self.format {
            Format::Csv => csv::write(self, ev, source, out),
            Format::Jsonl => jsonl::write(self, ev, source, out),
            Format::Llm => llm::write(self, ev, out),
        }
    }

    /// File extension for this format.
    pub fn extension(&self) -> &'static str {
        match self.format {
            Format::Csv => "csv",
            Format::Jsonl => "jsonl",
            Format::Llm => "llm.jsonl",
        }
    }

    pub fn write_ts(&self, ts: Ts, out: &mut Vec<u8>) {
        match &self.opts.tz {
            None => ts.write_iso(out),
            Some(tz) => ts.write_in_tz(tz, out),
        }
    }
}

/// Field names tried in order for the common CSV columns.
pub(crate) const USER_FIELDS: &[&str] = &[
    "TargetUserName",
    "User",
    "SubjectUserName",
    "AccountName",
    "Param1",
    "UserName",
];
pub(crate) const IP_FIELDS: &[&str] = &[
    "IpAddress",
    "SourceIp",
    "SourceAddress",
    "ClientAddress",
    "Address",
    "Param3",
    "ClientIP",
];
pub(crate) const PROC_FIELDS: &[&str] = &[
    "NewProcessName",
    "Image",
    "ProcessName",
    "ServiceFileName",
    "ImagePath",
    "Application",
    "SourceImage",
];
pub(crate) const CMD_FIELDS: &[&str] =
    &["CommandLine", "ScriptBlockText", "Payload", "TaskContent"];

pub(crate) fn first_of<'e>(ev: &'e EventView<'_>, names: &[&str]) -> &'e str {
    for n in names {
        if let Some(v) = ev.field(n)
            && !v.is_blank()
        {
            return v.as_str();
        }
    }
    ""
}
