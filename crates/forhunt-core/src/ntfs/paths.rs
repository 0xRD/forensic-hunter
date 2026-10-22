//! Full paths of directories, resolved once per `$MFT` so that every record
//! (and every `$J` entry) gets its path with a table lookup.
//!
//! Built by a parallel pre-pass that keeps only directory records (a small
//! fraction of the table), then resolved parent by parent with memoisation.
//! A parent whose sequence number does not match the reference (the entry
//! was reused) gives an orphan marker instead of a wrong path.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rayon::prelude::*;

use super::record::{self, FLAG_DIRECTORY, FLAG_IN_USE, Parsed};
use crate::io::Data;

const ROOT: u64 = 5;
/// Records read per pre-pass task.
const BLOCK: usize = 1 << 20;

struct RawDir {
    entry: u64,
    seq: u16,
    in_use: bool,
    parent: u64,
    parent_seq: u16,
    name: Vec<u8>,
}

struct Dir {
    seq: u16,
    in_use: bool,
    path: (u32, u32),
}

pub(crate) struct DirTable {
    /// Entry number -> index + 1 into `dirs` (0: not a directory).
    slot: Vec<u32>,
    dirs: Vec<Dir>,
    arena: Vec<u8>,
}

impl DirTable {
    pub(crate) fn build(data: &Data, rec_size: usize) -> DirTable {
        let len = data.len() as usize;
        let per_block = (BLOCK / rec_size).max(1);
        let blocks = len.div_ceil(per_block * rec_size);
        let raw: Vec<RawDir> = (0..blocks)
            .into_par_iter()
            .flat_map_iter(|b| {
                let mut out = Vec::new();
                let off = (b * per_block * rec_size) as u64;
                let Ok(bytes) = data.read(off, per_block * rec_size) else {
                    return out.into_iter();
                };
                let mut rec = vec![0u8; rec_size];
                for (i, chunk) in bytes.chunks_exact(rec_size).enumerate() {
                    // Cheap filter before any work: directory flag set.
                    if record::u16_at(chunk, 0x16).is_none_or(|f| f & FLAG_DIRECTORY == 0) {
                        continue;
                    }
                    rec.copy_from_slice(chunk);
                    if record::fixup(&mut rec).is_err() {
                        continue;
                    }
                    let Parsed::Ok(r) = record::parse(&rec) else {
                        continue;
                    };
                    let Some(n) = r.name.as_ref().filter(|_| r.base == 0) else {
                        continue;
                    };
                    let (parent, parent_seq) = record::split_ref(n.parent);
                    let mut name = Vec::with_capacity(n.name.len() / 2);
                    record::push_utf16(&mut name, n.name);
                    out.push(RawDir {
                        entry: (b * per_block + i) as u64,
                        seq: r.seq,
                        in_use: r.flags & FLAG_IN_USE != 0,
                        parent,
                        parent_seq,
                        name,
                    });
                }
                out.into_iter()
            })
            .collect();
        Self::resolve(raw)
    }

    fn resolve(raw: Vec<RawDir>) -> DirTable {
        let max = raw.iter().map(|d| d.entry).max().unwrap_or(0) as usize;
        let mut slot = vec![0u32; max + 1];
        for (i, d) in raw.iter().enumerate() {
            slot[d.entry as usize] = i as u32 + 1;
        }
        let mut t = DirTable {
            slot,
            dirs: raw
                .iter()
                .map(|d| Dir {
                    seq: d.seq,
                    in_use: d.in_use,
                    path: (0, 0),
                })
                .collect(),
            arena: Vec::new(),
        };
        let mut done = vec![false; raw.len()];
        let mut chain = Vec::new();
        for start in 0..raw.len() {
            // Walk up to the root or to a resolved ancestor, then fill in
            // paths top-down.
            chain.clear();
            let mut i = start;
            let prefix = loop {
                if done[i] {
                    break None;
                }
                chain.push(i);
                let d = &raw[i];
                if d.entry == ROOT {
                    break Some(Vec::from(&b"."[..]));
                }
                match t.lookup(d.parent, d.parent_seq) {
                    Some(p) if !chain.contains(&p) && chain.len() < 256 => i = p,
                    _ => break Some(orphan(d.parent, d.parent_seq)),
                }
            };
            let mut base = match prefix {
                Some(p) => p,
                None => t.path_of(i).to_vec(),
            };
            for &c in chain.iter().rev() {
                let d = &raw[c];
                if d.entry != ROOT || base != b"." {
                    base.push(b'\\');
                    base.extend_from_slice(&d.name);
                }
                let s = t.arena.len() as u32;
                t.arena.extend_from_slice(&base);
                t.dirs[c].path = (s, base.len() as u32);
                done[c] = true;
            }
        }
        t
    }

    /// Index of the directory a reference points to. A deleted directory
    /// had its sequence number bumped, so `seq - 1` also matches it.
    fn lookup(&self, entry: u64, seq: u16) -> Option<usize> {
        let i = *self.slot.get(entry as usize)? as usize;
        let d = self.dirs.get(i.checked_sub(1)?)?;
        (d.seq == seq || (!d.in_use && d.seq == seq.wrapping_add(1))).then_some(i - 1)
    }

    fn path_of(&self, i: usize) -> &[u8] {
        let (s, l) = self.dirs[i].path;
        &self.arena[s as usize..(s + l) as usize]
    }

    /// Appends the full path of a parent directory, or an orphan marker.
    pub(crate) fn push_parent(&self, out: &mut Vec<u8>, entry: u64, seq: u16) {
        match self.lookup(entry, seq) {
            Some(i) => out.extend_from_slice(self.path_of(i)),
            None => out.extend_from_slice(&orphan(entry, seq)),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.dirs.len()
    }
}

fn orphan(entry: u64, seq: u16) -> Vec<u8> {
    format!(".\\[orphan 0x{entry:x}-{seq}]").into_bytes()
}

type Cache = Vec<(PathBuf, u64, Arc<DirTable>)>;
static CACHE: Mutex<Cache> = Mutex::new(Vec::new());

/// The table for an `$MFT` file, built once per run even when both the
/// `$MFT` and its `$J` are inputs.
pub(crate) fn cached(path: &Path, data: &Data, rec_size: usize) -> Arc<DirTable> {
    let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let len = data.len();
    let hit = |c: &Cache| {
        c.iter()
            .find(|(p, l, _)| *p == canon && *l == len)
            .map(|(_, _, t)| t.clone())
    };
    if let Some(t) = hit(&CACHE.lock().unwrap_or_else(|e| e.into_inner())) {
        return t;
    }
    let t = Arc::new(DirTable::build(data, rec_size));
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(t) = hit(&c) {
        return t;
    }
    c.push((canon, len, t.clone()));
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(entry: u64, seq: u16, parent: u64, parent_seq: u16, name: &str) -> RawDir {
        RawDir {
            entry,
            seq,
            in_use: true,
            parent,
            parent_seq,
            name: name.as_bytes().to_vec(),
        }
    }

    #[test]
    fn resolves_paths_orphans_and_cycles() {
        let t = DirTable::resolve(vec![
            d(5, 5, 5, 5, "."),
            d(40, 1, 41, 1, "System32"),
            d(41, 1, 5, 5, "Windows"),
            d(50, 2, 41, 9, "Stale"),
            d(60, 1, 61, 1, "A"),
            d(61, 1, 60, 1, "B"),
        ]);
        let p = |e, s| {
            let mut o = Vec::new();
            t.push_parent(&mut o, e, s);
            String::from_utf8(o).unwrap()
        };
        assert_eq!(p(5, 5), ".");
        assert_eq!(p(40, 1), ".\\Windows\\System32");
        assert_eq!(p(50, 2), ".\\[orphan 0x29-9]\\Stale");
        assert_eq!(p(41, 2), ".\\[orphan 0x29-2]");
        assert!(p(60, 1).contains("[orphan"));
    }
}
