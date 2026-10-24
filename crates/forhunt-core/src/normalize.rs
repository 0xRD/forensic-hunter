//! Field normalisation maps: channel aliases, short field names and the
//! per-event field selection used by the `llm` format.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::filter::eq_ci;

pub const DEFAULT_MAP: &str = include_str!("../maps/default.toml");

#[derive(Debug, Deserialize)]
struct MapFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    channels: HashMap<String, String>,
    #[serde(default)]
    fields: HashMap<String, String>,
    #[serde(default)]
    event: Vec<EventEntry>,
}

#[derive(Debug, Deserialize)]
struct EventEntry {
    channel: String,
    id: u32,
    title: String,
    #[serde(default)]
    keep: Vec<String>,
    #[serde(default)]
    rename: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct EventSpec {
    pub title: String,
    /// Ordered field names to keep (empty: header only).
    pub keep: Vec<String>,
    /// Short names for this event only, over `[fields]` (4688: the
    /// creator's `ProcessId` is the parent, `ppid`).
    pub rename: HashMap<String, String>,
}

#[derive(Debug, Default, Clone)]
pub struct FieldMap {
    /// Lowercased full channel name -> alias.
    channel_alias: HashMap<String, String>,
    /// Lowercased alias -> full channel name.
    alias_channel: HashMap<String, String>,
    fields: HashMap<String, String>,
    events: HashMap<(String, u32), EventSpec>,
}

impl FieldMap {
    pub fn parse(src: &str) -> anyhow::Result<FieldMap> {
        let mut m = FieldMap::default();
        m.extend(src)?;
        Ok(m)
    }

    /// Adds (and overrides) entries from another map file.
    pub fn extend(&mut self, src: &str) -> anyhow::Result<()> {
        let f: MapFile = toml::from_str(src)?;
        if f.version > 1 {
            anyhow::bail!(
                "field map version {} is newer than this build supports (1)",
                f.version
            );
        }
        for (full, alias) in f.channels {
            self.alias_channel
                .insert(alias.to_lowercase(), full.clone());
            self.channel_alias.insert(full.to_lowercase(), alias);
        }
        self.fields.extend(f.fields);
        for e in f.event {
            self.events.insert(
                (e.channel.to_lowercase(), e.id),
                EventSpec {
                    title: e.title,
                    keep: e.keep,
                    rename: e.rename,
                },
            );
        }
        Ok(())
    }

    pub fn default_map() -> &'static FieldMap {
        static M: OnceLock<FieldMap> = OnceLock::new();
        M.get_or_init(|| FieldMap::parse(DEFAULT_MAP).expect("built-in map is valid"))
    }

    pub fn channel_alias<'a>(&'a self, channel: &'a str) -> &'a str {
        self.channel_alias
            .get(&channel.to_ascii_lowercase())
            .map(|s| s.as_str())
            .unwrap_or(channel)
    }

    /// Resolves an alias (`Sysmon`) to a full channel name.
    pub fn channel_from_alias(&self, alias: &str) -> Option<&str> {
        self.alias_channel
            .get(&alias.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    pub fn short_field<'a>(&'a self, name: &'a str) -> &'a str {
        self.fields.get(name).map(|s| s.as_str()).unwrap_or(name)
    }

    pub fn event(&self, channel: &str, id: u32) -> Option<&EventSpec> {
        // Forwarded events keep their original channel name, so one lookup
        // covers both.
        self.events.get(&(channel.to_ascii_lowercase(), id))
    }
}

/// `want` (as typed by the user) matches `actual` when equal ignoring case,
/// when `want` is the alias of `actual`, or when `want` is a `*` glob.
pub fn channel_matches(want: &str, actual: &str) -> bool {
    if eq_ci(want, actual) {
        return true;
    }
    if want.contains('*') {
        return glob_ci(want, actual);
    }
    let m = FieldMap::default_map();
    m.channel_from_alias(want)
        .is_some_and(|full| eq_ci(full, actual))
}

fn glob_ci(pat: &str, s: &str) -> bool {
    let p = pat.to_lowercase();
    let s = s.to_lowercase();
    let parts: Vec<&str> = p.split('*').collect();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !s.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if let Some(idx) = s[pos..].find(part) {
            pos += idx + part.len();
        } else {
            return false;
        }
    }
    parts.last().is_none_or(|l| l.is_empty() || s.ends_with(l))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_map_loads() {
        let m = FieldMap::default_map();
        assert_eq!(
            m.channel_alias("Microsoft-Windows-Sysmon/Operational"),
            "Sysmon"
        );
        assert_eq!(m.short_field("TargetUserName"), "user");
        assert_eq!(m.event("security", 4624).unwrap().title, "Logon success");
    }

    #[test]
    fn channels() {
        assert!(channel_matches(
            "sysmon",
            "Microsoft-Windows-Sysmon/Operational"
        ));
        assert!(channel_matches("SECURITY", "Security"));
        assert!(channel_matches(
            "*terminalservices*",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
        ));
        assert!(!channel_matches(
            "System",
            "Microsoft-Windows-Kernel-System"
        ));
        assert!(channel_matches(
            "Microsoft-*/Operational",
            "Microsoft-Windows-WinRM/Operational"
        ));
    }
}
