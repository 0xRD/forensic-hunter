//! The `regf` hive format, read-only and bounds-checked: base block, hive
//! bins, key nodes, values, big data, and the replay of transaction logs.
//! Written from the published format specification; no code from other
//! parsers.
//!
//! Offsets in cells are relative to the first hive bin, at 4096. Everything
//! read comes from the file, so nothing here trusts a count or an offset, and
//! a [`Reader`] limits what one pass may decode: cells can alias each other.

use std::borrow::Cow;
use std::cell::Cell;

use crate::ntfs::record::{filetime, push_utf16, u16_at, u32_at, u64_at};
use crate::time::Ts;

const BINS: usize = 4096;
const LOG_ENTRIES: usize = 512;
const LOG_HEADER: usize = 40;
const MARVIN_SEED: u64 = 0x82EF_4D88_7A4E_55C5;
const BIG_SEGMENT: usize = 16344;
const NK_NAME: usize = 76;
const VK_NAME: usize = 20;
/// Limit of nested keys: Windows allows 512 levels.
pub const MAX_DEPTH: usize = 512;

pub struct Hive {
    data: Vec<u8>,
    root: u32,
    /// File name stored in the base block (a tail of the path).
    pub stored_name: String,
}

fn marvin_block(a: &mut u32, b: &mut u32) {
    *b ^= *a;
    *a = a.rotate_left(20).wrapping_add(*b);
    *b = b.rotate_left(9) ^ *a;
    *a = a.rotate_left(27).wrapping_add(*b);
    *b = b.rotate_left(19);
}

/// Marvin32 state as the log stores it (both 32-bit halves).
fn marvin(d: &[u8]) -> u64 {
    let (mut a, mut b) = (MARVIN_SEED as u32, (MARVIN_SEED >> 32) as u32);
    let words = d.chunks_exact(4);
    let tail = words.remainder();
    for w in words {
        a = a.wrapping_add(u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
        marvin_block(&mut a, &mut b);
    }
    let mut last = 0x80u32 << (8 * tail.len());
    for (i, c) in tail.iter().enumerate() {
        last |= (*c as u32) << (8 * i);
    }
    a = a.wrapping_add(last);
    marvin_block(&mut a, &mut b);
    marvin_block(&mut a, &mut b);
    ((b as u64) << 32) | a as u64
}

struct LogEntry<'a> {
    seq: u32,
    bins: usize,
    pages: Vec<(usize, &'a [u8])>,
}

/// The valid entries of a new-format (`HvLE`) log: stops at the first bad one
/// and at the first out of sequence. Logs are reused from their start, so
/// what follows the last commit can be whole entries of an older cycle.
fn log_entries(log: &[u8]) -> Vec<LogEntry<'_>> {
    let mut out = Vec::new();
    let mut p = LOG_ENTRIES;
    while let Some(head) = log.get(p..p + LOG_HEADER) {
        if &head[..4] != b"HvLE" {
            break;
        }
        let (Some(size), Some(seq), Some(bins), Some(count), Some(h1), Some(h2)) = (
            u32_at(head, 4).map(|v| v as usize),
            u32_at(head, 12),
            u32_at(head, 16),
            u32_at(head, 20).map(|v| v as usize),
            u64_at(head, 24),
            u64_at(head, 32),
        ) else {
            break;
        };
        let Some(e) = p.checked_add(size).and_then(|end| log.get(p..end)) else {
            break;
        };
        if size < LOG_HEADER
            || size % LOG_ENTRIES != 0
            || count > (size - LOG_HEADER) / 8
            || marvin(&e[LOG_HEADER..]) != h1
            || marvin(&e[..32]) != h2
        {
            break;
        }
        if out
            .last()
            .is_some_and(|l: &LogEntry<'_>| l.seq.wrapping_add(1) != seq)
        {
            break;
        }
        let mut pages = Vec::with_capacity(count);
        let mut at = LOG_HEADER + count * 8;
        for i in 0..count {
            let r = LOG_HEADER + i * 8;
            let (Some(off), Some(n)) = (u32_at(e, r), u32_at(e, r + 4)) else {
                break;
            };
            let Some(page) = at.checked_add(n as usize).and_then(|end| e.get(at..end)) else {
                break;
            };
            pages.push((off as usize, page));
            at += n as usize;
        }
        out.push(LogEntry {
            seq,
            bins: bins as usize,
            pages,
        });
        p += size;
    }
    out
}

impl Hive {
    /// Opens a hive. A dirty one (its two sequence numbers differ) is brought
    /// up to date from `logs`. Returns what the analyst must know.
    pub fn open(mut data: Vec<u8>, logs: &[Vec<u8>]) -> anyhow::Result<(Hive, Vec<String>)> {
        if data.len() < BINS || &data[..4] != b"regf" {
            anyhow::bail!("not a registry hive");
        }
        let mut warnings = Vec::new();
        let (primary, secondary) = (u32_at(&data, 4).unwrap_or(0), u32_at(&data, 8).unwrap_or(0));
        let mut root = u32_at(&data, 0x24).unwrap_or(0);
        if primary != secondary {
            let mut entries: Vec<(LogEntry<'_>, u32)> = Vec::new();
            for log in logs.iter().filter(|l| l.starts_with(b"regf")) {
                let log_root = u32_at(log, 0x24).unwrap_or(0);
                entries.extend(log_entries(log).into_iter().map(|e| (e, log_root)));
            }
            entries.retain(|(e, _)| e.seq >= secondary);
            // Written in turns, so together they make one sequence.
            entries.sort_by_key(|(e, _)| e.seq);
            entries.dedup_by_key(|(e, _)| e.seq);
            let before = entries.len();
            let cut = entries
                .windows(2)
                .position(|w| w[1].0.seq != w[0].0.seq + 1)
                .map_or(before, |i| i + 1);
            entries.truncate(cut);
            if entries.is_empty() {
                let old = logs
                    .iter()
                    .any(|l| l.get(LOG_ENTRIES..LOG_ENTRIES + 4) == Some(b"DIRT"));
                warnings.push(if old {
                    "dirty hive with an old-format (Windows 8 and earlier) log, not replayed: \
                     recent changes may be missing"
                        .to_string()
                } else {
                    "dirty hive and no usable .LOG1/.LOG2 beside it: recent changes may be missing"
                        .to_string()
                });
            } else {
                let mut applied = data.clone();
                let mut fits = true;
                for (e, log_root) in &entries {
                    if BINS + e.bins > 1 << 31 {
                        fits = false;
                        break;
                    }
                    if applied.len() < BINS + e.bins {
                        applied.resize(BINS + e.bins, 0);
                    }
                    for (off, page) in &e.pages {
                        match applied.get_mut(BINS + off..BINS + off + page.len()) {
                            Some(dst) => dst.copy_from_slice(page),
                            None => fits = false,
                        }
                    }
                    root = *log_root;
                }
                if fits && is_key(&applied, root) {
                    data = applied;
                    if cut != before {
                        warnings.push(format!(
                            "transaction logs have a gap: replayed {cut} of {before} entries"
                        ));
                    }
                } else {
                    root = u32_at(&data, 0x24).unwrap_or(0);
                    warnings.push(
                        "transaction logs do not fit the hive, not replayed: recent changes may \
                         be missing"
                            .to_string(),
                    );
                }
            }
        }
        if !is_key(&data, root) {
            anyhow::bail!("hive has no root key");
        }
        let mut name = Vec::new();
        push_utf16(&mut name, data.get(0x30..0x70).unwrap_or(&[]));
        let stored_name = String::from_utf8_lossy(&name)
            .split('\0')
            .next()
            .unwrap_or("")
            .to_string();
        Ok((
            Hive {
                data,
                root,
                stored_name,
            },
            warnings,
        ))
    }

    pub fn reader(&self) -> Reader<'_> {
        Reader {
            hive: self,
            budget: Cell::new(self.data.len().saturating_mul(4)),
            bad: Cell::new(0),
        }
    }
}

fn cell_at(d: &[u8], off: u32) -> Option<&[u8]> {
    let at = BINS.checked_add(off as usize)?;
    let size = (u32_at(d, at)? as i32).unsigned_abs() as usize;
    if size < 8 {
        return None;
    }
    d.get(at + 4..at.checked_add(size)?)
}

fn is_key(d: &[u8], off: u32) -> bool {
    cell_at(d, off).is_some_and(|c| c.starts_with(b"nk"))
}

/// One pass over a hive: counts damage and limits decoding.
pub struct Reader<'h> {
    hive: &'h Hive,
    budget: Cell<usize>,
    bad: Cell<u64>,
}

impl<'h> Reader<'h> {
    fn cell(&self, off: u32) -> Option<&'h [u8]> {
        cell_at(&self.hive.data, off)
    }

    fn damaged<T>(&self) -> Option<T> {
        self.bad.set(self.bad.get() + 1);
        None
    }

    fn spend(&self, n: usize) -> bool {
        match self.budget.get().checked_sub(n) {
            Some(left) => {
                self.budget.set(left);
                true
            }
            None => {
                self.budget.set(0);
                false
            }
        }
    }

    /// Cells that could not be read so far, and whether decoding was cut.
    pub fn damage(&self) -> (u64, bool) {
        (self.bad.get(), self.budget.get() == 0)
    }

    pub fn root(&self) -> Option<Key<'_, 'h>> {
        self.key(self.hive.root)
    }

    fn key(&self, off: u32) -> Option<Key<'_, 'h>> {
        match self.cell(off) {
            Some(c) if c.starts_with(b"nk") && c.len() >= NK_NAME => Some(Key { r: self, off, c }),
            _ => self.damaged(),
        }
    }

    /// Follows `lf`, `lh`, `li` and one level of `ri`.
    fn list(&self, off: u32, depth: u8, out: &mut Vec<u32>) {
        let Some(c) = self.cell(off) else {
            self.bad.set(self.bad.get() + 1);
            return;
        };
        let count = u16_at(c, 2).unwrap_or(0) as usize;
        let (step, nested) = match c.get(..2) {
            Some(b"lf" | b"lh") => (8, false),
            Some(b"li") => (4, false),
            Some(b"ri") if depth == 0 => (4, true),
            _ => {
                self.bad.set(self.bad.get() + 1);
                return;
            }
        };
        for i in 0..count {
            let Some(v) = u32_at(c, 4 + i * step) else {
                self.bad.set(self.bad.get() + 1);
                return;
            };
            if nested {
                self.list(v, 1, out);
            } else {
                out.push(v);
            }
        }
    }
}

fn name_of(raw: &[u8], ascii: bool) -> String {
    if ascii {
        // Latin-1, not ASCII, whatever the flag is called.
        raw.iter().map(|&b| b as char).collect()
    } else {
        let mut v = Vec::with_capacity(raw.len());
        push_utf16(&mut v, raw);
        String::from_utf8_lossy(&v).into_owned()
    }
}

#[derive(Clone, Copy)]
pub struct Key<'r, 'h> {
    r: &'r Reader<'h>,
    off: u32,
    c: &'h [u8],
}

impl<'r, 'h> Key<'r, 'h> {
    pub fn offset(&self) -> u32 {
        self.off
    }

    pub fn name(&self) -> String {
        let n = u16_at(self.c, 72).unwrap_or(0) as usize;
        let ascii = u16_at(self.c, 2).unwrap_or(0) & 0x20 != 0;
        match self.c.get(NK_NAME..NK_NAME + n) {
            Some(raw) => name_of(raw, ascii),
            None => String::new(),
        }
    }

    pub fn last_write(&self) -> Ts {
        u64_at(self.c, 4).and_then(filetime).unwrap_or_default()
    }

    pub fn subkeys(&self) -> Vec<Key<'r, 'h>> {
        let n = u32_at(self.c, 20).unwrap_or(0);
        let list = u32_at(self.c, 28).unwrap_or(u32::MAX);
        let mut offs = Vec::new();
        if n > 0 && list != u32::MAX {
            self.r.list(list, 0, &mut offs);
        }
        offs.into_iter().filter_map(|o| self.r.key(o)).collect()
    }

    pub fn subkey(&self, name: &str) -> Option<Key<'r, 'h>> {
        self.subkeys()
            .into_iter()
            .find(|k| k.name().eq_ignore_ascii_case(name))
    }

    /// The key at a `\`-separated path below this one.
    pub fn open(&self, path: &str) -> Option<Key<'r, 'h>> {
        path.split('\\').try_fold(*self, |k, part| k.subkey(part))
    }

    pub fn values(&self) -> Vec<Value<'r, 'h>> {
        let n = u32_at(self.c, 36).unwrap_or(0) as usize;
        let list = u32_at(self.c, 40).unwrap_or(u32::MAX);
        if n == 0 || list == u32::MAX {
            return Vec::new();
        }
        let Some(l) = self.r.cell(list) else {
            self.r.bad.set(self.r.bad.get() + 1);
            return Vec::new();
        };
        let mut out = Vec::with_capacity(n.min(l.len() / 4));
        for i in 0..n {
            let Some(v) = u32_at(l, i * 4) else {
                self.r.bad.set(self.r.bad.get() + 1);
                break;
            };
            match self.r.cell(v) {
                Some(c) if c.starts_with(b"vk") && c.len() >= VK_NAME => {
                    out.push(Value { r: self.r, c })
                }
                _ => self.r.bad.set(self.r.bad.get() + 1),
            }
        }
        out
    }

    pub fn value(&self, name: &str) -> Option<Value<'r, 'h>> {
        self.values()
            .into_iter()
            .find(|v| v.name().eq_ignore_ascii_case(name))
    }

    /// Text of a value, `None` when absent or blank.
    pub fn text(&self, name: &str) -> Option<String> {
        self.value(name).map(|v| v.text()).filter(|s| !s.is_empty())
    }
}

#[derive(Clone, Copy)]
pub struct Value<'r, 'h> {
    r: &'r Reader<'h>,
    c: &'h [u8],
}

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

impl<'h> Value<'_, 'h> {
    /// `""` is the key's default value.
    pub fn name(&self) -> String {
        let n = u16_at(self.c, 2).unwrap_or(0) as usize;
        let ascii = u16_at(self.c, 16).unwrap_or(0) & 1 != 0;
        match self.c.get(VK_NAME..VK_NAME + n) {
            Some(raw) => name_of(raw, ascii),
            None => String::new(),
        }
    }

    pub fn kind(&self) -> u32 {
        u32_at(self.c, 12).unwrap_or(0)
    }

    pub fn data(&self) -> Cow<'h, [u8]> {
        let raw = u32_at(self.c, 4).unwrap_or(0);
        let off = u32_at(self.c, 8).unwrap_or(u32::MAX);
        let len = (raw & 0x7FFF_FFFF) as usize;
        if raw & 0x8000_0000 != 0 {
            return Cow::Borrowed(self.c.get(8..8 + len.min(4)).unwrap_or(&[]));
        }
        if len == 0 {
            return Cow::Borrowed(&[]);
        }
        if !self.r.spend(len) {
            return Cow::Borrowed(&[]);
        }
        let Some(cell) = self.r.cell(off) else {
            self.r.bad.set(self.r.bad.get() + 1);
            return Cow::Borrowed(&[]);
        };
        if cell.starts_with(b"db") && len > BIG_SEGMENT {
            return Cow::Owned(self.big(cell, len));
        }
        match cell.get(..len) {
            Some(d) => Cow::Borrowed(d),
            None => {
                self.r.bad.set(self.r.bad.get() + 1);
                Cow::Borrowed(&[])
            }
        }
    }

    fn big(&self, db: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let n = u16_at(db, 2).unwrap_or(0) as usize;
        let list = u32_at(db, 4).and_then(|o| self.r.cell(o));
        for i in 0..n {
            let seg = list
                .and_then(|l| u32_at(l, i * 4))
                .and_then(|o| self.r.cell(o));
            match seg {
                Some(s) => {
                    let want = (len - out.len()).min(BIG_SEGMENT).min(s.len());
                    out.extend_from_slice(&s[..want]);
                }
                None => {
                    self.r.bad.set(self.r.bad.get() + 1);
                    break;
                }
            }
        }
        out
    }

    pub fn u32(&self) -> Option<u32> {
        u32_at(&self.data(), 0)
    }

    pub fn u64(&self) -> Option<u64> {
        let d = self.data();
        u64_at(&d, 0).or_else(|| u32_at(&d, 0).map(u64::from))
    }

    /// Text form: strings as they are, numbers in decimal, the rest in hex.
    pub fn text(&self) -> String {
        let d = self.data();
        let wide = |d: &[u8]| {
            let mut v = Vec::with_capacity(d.len());
            push_utf16(&mut v, d);
            String::from_utf8_lossy(&v).into_owned()
        };
        // Device properties keep flags in the high bits.
        match self.kind() & 0xFFFF {
            REG_SZ | REG_EXPAND_SZ => wide(&d).split('\0').next().unwrap_or("").to_string(),
            REG_MULTI_SZ => wide(&d)
                .split('\0')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", "),
            REG_DWORD if d.len() >= 4 => u32_at(&d, 0).unwrap_or(0).to_string(),
            REG_QWORD if d.len() >= 8 => u64_at(&d, 0).unwrap_or(0).to_string(),
            _ => d.iter().map(|b| format!("{b:02x}")).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: u32) -> Vec<u8> {
        let mut e = vec![0u8; 512];
        e[..4].copy_from_slice(b"HvLE");
        e[4..8].copy_from_slice(&512u32.to_le_bytes());
        e[12..16].copy_from_slice(&seq.to_le_bytes());
        let h1 = marvin(&e[40..]);
        e[24..32].copy_from_slice(&h1.to_le_bytes());
        let h2 = marvin(&e[..32]);
        e[32..40].copy_from_slice(&h2.to_le_bytes());
        e
    }

    #[test]
    fn log_stops_at_stale_entries_and_bad_hashes() {
        let mut log = vec![0u8; 512];
        for s in [521, 522, 523, 506, 507] {
            log.extend(entry(s));
        }
        let seqs: Vec<_> = log_entries(&log).iter().map(|e| e.seq).collect();
        assert_eq!(seqs, [521, 522, 523]);
        log[512 + 100] ^= 1;
        assert!(log_entries(&log).is_empty());
    }

    #[test]
    fn refuses_what_is_not_a_hive() {
        assert!(Hive::open(vec![0; 8192], &[]).is_err());
        let mut d = vec![0; 8192];
        d[..4].copy_from_slice(b"regf");
        assert!(Hive::open(d, &[]).is_err());
    }
}
