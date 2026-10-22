use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "forhunt",
    version,
    about = "Forensic Hunter: very fast Windows event log (EVTX) parsing, search, stats and timelines for DFIR",
    long_about = None,
    after_help = "Exit codes: 0 ok, 1 error, 2 usage error, 3 no input files, 4 corrupt input with --strict.\n\
                  Docs: https://github.com/0xRD/forensic-hunter"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Parse every event and write it out (default: full-fidelity JSONL).
    Parse(ParseArgs),
    /// Triage summary: volumes per channel/EventID/day/hour, top accounts and
    /// hosts, time gaps, log clearing, per-file time ranges and coverage.
    Stats(StatsArgs),
    /// Find events matching filters (default: `llm` format, capped).
    Search(SearchArgs),
    /// Merged, time-sorted timeline across files.
    Timeline(TimelineArgs),
    /// Show one event in full by its stable id (`<file key>:<record id>`).
    Show(ShowArgs),
    /// Normalise Hayabusa JSON/JSONL detections into the `llm` format.
    Hayabusa(HayabusaArgs),
    /// Sweep every detection checklist in one pass: log source coverage,
    /// query hits, and a pre-filled checklist-status file for review.
    Checklist(ChecklistArgs),
}

#[derive(Args, Debug, Clone)]
pub struct Common {
    /// Worker threads (0 = one per physical core; at most 1024).
    #[arg(long, short = 't', default_value_t = 0, global = true,
          value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(0..=1024))]
    pub threads: usize,
    /// Disable the progress line on stderr.
    #[arg(long, global = true)]
    pub no_progress: bool,
    /// Suppress the run summary on stderr.
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,
    /// Treat corrupt chunks or records as fatal (exit code 4).
    #[arg(long, global = true)]
    pub strict: bool,
    /// Verify chunk checksums (a mismatch marks the chunk as bad).
    #[arg(long, global = true)]
    pub checksums: bool,
    /// Display timestamps in this IANA time zone (e.g. Europe/Paris) instead of UTC.
    #[arg(long, global = true, value_name = "TZ")]
    pub tz: Option<String>,
    /// Decode every record through the JSON path (testing only).
    #[arg(long, global = true, hide = true)]
    pub slow_decoder: bool,
    /// Extra field map (TOML, same format as the built-in map).
    #[arg(long, global = true, value_name = "FILE")]
    pub map: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutFormat {
    Csv,
    Jsonl,
    Llm,
}

impl From<OutFormat> for forhunt_output::Format {
    fn from(f: OutFormat) -> Self {
        match f {
            OutFormat::Csv => forhunt_output::Format::Csv,
            OutFormat::Jsonl => forhunt_output::Format::Jsonl,
            OutFormat::Llm => forhunt_output::Format::Llm,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Split {
    /// One output file per input EVTX file.
    File,
    /// One output file per computer (endpoint) name.
    Host,
}

#[derive(Args, Debug, Clone)]
pub struct OutputArgs {
    /// Output file (`-` for stdout). All inputs are concatenated into it.
    #[arg(long, short = 'o', default_value = "-")]
    pub output: String,
    /// Write one file per input file or per host into this directory
    /// instead of a single output (see --split).
    #[arg(long, short = 'O', value_name = "DIR")]
    pub output_dir: Option<std::path::PathBuf>,
    /// With --output-dir: split by input file (default) or by computer name.
    #[arg(long, value_enum, default_value_t = Split::File, requires = "output_dir")]
    pub split: Split,
    /// `llm` format: maximum characters per value before truncation (0 = no limit).
    #[arg(long, default_value_t = 256, value_name = "N")]
    pub max_value_len: usize,
    /// `llm` format: keep every field, not only the mapped key fields.
    #[arg(long)]
    pub all_fields: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct FilterArgs {
    /// Event ids: `4624`, `4624,4625`, `4720-4738`. Repeatable.
    #[arg(long = "event-id", short = 'e', value_name = "IDS")]
    pub event_id: Vec<String>,
    /// Channel name or alias (Security, Sysmon, PS, ...), `*` globs allowed. Repeatable.
    #[arg(long, short = 'c', value_name = "NAME")]
    pub channel: Vec<String>,
    /// Only events at or after this time (ISO 8601; no offset = UTC).
    #[arg(long, value_name = "TIME")]
    pub since: Option<String>,
    /// Only events at or before this time.
    #[arg(long, value_name = "TIME")]
    pub until: Option<String>,
    /// Field condition: `Name=value` (case-insensitive, hex-aware), `Name!=value`,
    /// `Name~substring`. System fields (Computer, Channel, Provider) work too. Repeatable, ANDed.
    #[arg(long, short = 'f', value_name = "COND")]
    pub field: Vec<String>,
    /// Case-insensitive regex on any value, or on one field with `Name=REGEX`. Repeatable, ANDed.
    #[arg(long, short = 'r', value_name = "[NAME=]REGEX")]
    pub regex: Vec<String>,
    /// Computer name (exact, or the short name of an FQDN). Repeatable.
    #[arg(long, value_name = "HOST")]
    pub computer: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ParseArgs {
    /// Files, directories (recursive) or globs.
    #[arg(required = true, value_name = "PATHS")]
    pub paths: Vec<String>,
    #[arg(long, short = 'F', value_enum, default_value_t = OutFormat::Jsonl)]
    pub format: OutFormat,
    /// Only events from this computer (exact, or the short name of an FQDN). Repeatable.
    /// Other filters live in `search`.
    #[arg(long, value_name = "HOST")]
    pub computer: Vec<String>,
    #[command(flatten)]
    pub out: OutputArgs,
    #[command(flatten)]
    pub common: Common,
}

#[derive(Args, Debug)]
pub struct SearchArgs {
    #[arg(required = true, value_name = "PATHS")]
    pub paths: Vec<String>,
    #[command(flatten)]
    pub filter: FilterArgs,
    /// Maximum events written (default: 200 for `llm`, unlimited otherwise; 0 = unlimited).
    #[arg(long, short = 'n')]
    pub limit: Option<usize>,
    #[arg(long, short = 'F', value_enum, default_value_t = OutFormat::Llm)]
    pub format: OutFormat,
    #[command(flatten)]
    pub out: OutputArgs,
    #[command(flatten)]
    pub common: Common,
}

#[derive(Args, Debug)]
pub struct TimelineArgs {
    #[arg(required = true, value_name = "PATHS")]
    pub paths: Vec<String>,
    #[command(flatten)]
    pub filter: FilterArgs,
    /// Maximum events written, earliest first (default: 200 for `llm`, unlimited otherwise; 0 = unlimited).
    #[arg(long, short = 'n')]
    pub limit: Option<usize>,
    #[arg(long, short = 'F', value_enum, default_value_t = OutFormat::Llm)]
    pub format: OutFormat,
    /// Memory budget for sorting before spilling to temporary files, in MiB
    /// (smaller sorted runs are also more cache-friendly).
    #[arg(long, default_value_t = 256, value_name = "MIB")]
    pub mem_budget: usize,
    #[command(flatten)]
    pub out: OutputArgs,
    #[command(flatten)]
    pub common: Common,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum StatsFormat {
    Llm,
    Json,
    Csv,
}

#[derive(Args, Debug)]
pub struct StatsArgs {
    #[arg(required = true, value_name = "PATHS")]
    pub paths: Vec<String>,
    #[command(flatten)]
    pub filter: FilterArgs,
    #[arg(long, short = 'F', value_enum, default_value_t = StatsFormat::Llm)]
    pub format: StatsFormat,
    /// Rows per "top" table.
    #[arg(long, default_value_t = 10, value_name = "N")]
    pub top: usize,
    /// Report quiet periods longer than this many minutes.
    #[arg(long, default_value_t = 60, value_name = "MIN")]
    pub gap_minutes: i64,
    #[arg(long, short = 'o', default_value = "-")]
    pub output: String,
    #[command(flatten)]
    pub common: Common,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ShowFormat {
    Json,
    #[value(alias = "raw")]
    Xml,
    Llm,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Event id(s) as printed by other commands, e.g. `a1b2c3d4:4821`.
    #[arg(required = true, value_name = "ID")]
    pub ids: Vec<String>,
    /// Where to look for the file (files, directories, globs).
    #[arg(long, short = 'p', value_name = "PATHS", default_value = ".")]
    pub path: Vec<String>,
    /// `xml`: the record in its native form (EVTX XML; hex dump for $MFT and $J).
    #[arg(long, short = 'F', value_enum, default_value_t = ShowFormat::Json)]
    pub format: ShowFormat,
    #[arg(long, short = 'o', default_value = "-")]
    pub output: String,
    #[command(flatten)]
    pub common: Common,
}

#[derive(Args, Debug)]
pub struct HayabusaArgs {
    /// Hayabusa output: `dfir-timeline -t jsonl` (4.x) or `json-timeline` (2.x), JSONL or a JSON array. `-` for stdin.
    #[arg(value_name = "FILE")]
    pub input: String,
    /// Only keep detections at or above this level (informational, low, medium, high, critical).
    #[arg(long, default_value = "low")]
    pub min_level: String,
    /// Maximum detections written (0 = unlimited).
    #[arg(long, short = 'n', default_value_t = 200)]
    pub limit: usize,
    /// One line per (rule, level, host) with count, first/last time and up to 5
    /// sample event ids, instead of one line per detection.
    #[arg(long, short = 'g')]
    pub group: bool,
    /// Directories or files holding the scanned EVTX, to attach forhunt ids to detections.
    #[arg(long, short = 'p', value_name = "PATHS")]
    pub evtx: Vec<String>,
    #[arg(long, default_value_t = 256, value_name = "N")]
    pub max_value_len: usize,
    #[arg(long, short = 'o', default_value = "-")]
    pub output: String,
    #[command(flatten)]
    pub common: Common,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ChecklistFormat {
    Md,
    Json,
}

#[derive(Args, Debug)]
pub struct ChecklistArgs {
    /// Evidence: files, directories or globs.
    #[arg(required = true, value_name = "PATHS")]
    pub paths: Vec<String>,
    /// Machine-readable checklists (skill/references/checklists/checklists.json).
    #[arg(long, short = 'k', value_name = "FILE")]
    pub checks: std::path::PathBuf,
    /// Only checks of these tactics (e.g. credential-access). Repeatable.
    #[arg(long)]
    pub tactic: Vec<String>,
    #[arg(long, short = 'F', value_enum, default_value_t = ChecklistFormat::Md)]
    pub format: ChecklistFormat,
    #[arg(long, short = 'o', default_value = "-")]
    pub output: String,
    #[command(flatten)]
    pub common: Common,
}
