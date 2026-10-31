//! The node database of `.pst` and `.ost` files ([MS-PST] 2.2): two B-trees
//! map nodes to blocks, and blocks to file offsets. Blocks are read on demand,
//! so a mailbox of many gigabytes costs little memory.
//!
//! Version 23 is the Unicode format (512-byte pages). Version 36 is the OST
//! of Outlook 2013 and later (4 KiB pages, zlib-compressed blocks).

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::Context;
use flate2::read::ZlibDecoder;

use super::crypt;
use crate::ntfs::record::{u16_at, u32_at, u64_at};

const ROOT_NBT: usize = 224;
const ROOT_BBT: usize = 240;
const CRYPT: usize = 513;
const PAGE_NBT: u8 = 0x81;
const PAGE_BBT: u8 = 0x80;
/// Block ids with this bit hold structure, never encrypted.
const INTERNAL: u64 = 2;
const MAX_DEPTH: u8 = 16;

#[derive(Clone, Copy, Debug)]
pub struct Node {
    pub data: u64,
    pub sub: u64,
    pub parent: u32,
}

#[derive(Clone, Copy)]
struct Block {
    ib: u64,
    cb: u16,
    inflated: u16,
}

pub struct Store {
    file: File,
    len: u64,
    wide_page: bool,
    crypt: u8,
    pub nodes: BTreeMap<u32, Node>,
    blocks: HashMap<u64, Block>,
    /// Pages of the two trees that could not be read.
    pub bad_pages: u64,
}

#[cfg(unix)]
fn read_at(f: &File, buf: &mut [u8], ib: u64) -> bool {
    std::os::unix::fs::FileExt::read_exact_at(f, buf, ib).is_ok()
}

#[cfg(windows)]
fn read_at(f: &File, buf: &mut [u8], ib: u64) -> bool {
    let mut done = 0;
    while done < buf.len() {
        match std::os::windows::fs::FileExt::seek_read(f, &mut buf[done..], ib + done as u64) {
            Ok(0) | Err(_) => return false,
            Ok(n) => done += n,
        }
    }
    true
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Store> {
        let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let len = file.metadata()?.len();
        let mut head = vec![0u8; 4096.min(len as usize)];
        if !read_at(&file, &mut head, 0) || !head.starts_with(b"!BDN") {
            anyhow::bail!("{}: not a PST or OST file", path.display());
        }
        let version = u16_at(&head, 10).unwrap_or(0);
        let wide_page = match version {
            23 => false,
            36 => true,
            14 | 15 => anyhow::bail!(
                "{}: ANSI PST (Outlook 2002 and earlier) is not supported",
                path.display()
            ),
            v => anyhow::bail!("{}: unknown PST version {v}", path.display()),
        };
        let mut store = Store {
            file,
            len,
            wide_page,
            crypt: *head.get(CRYPT).context("short header")?,
            nodes: BTreeMap::new(),
            blocks: HashMap::new(),
            bad_pages: 0,
        };
        let mut seen = HashSet::new();
        let nbt = u64_at(&head, ROOT_NBT).context("short header")?;
        let bbt = u64_at(&head, ROOT_BBT).context("short header")?;
        store.tree(nbt, PAGE_NBT, 0, &mut seen);
        store.tree(bbt, PAGE_BBT, 0, &mut seen);
        Ok(store)
    }

    fn tree(&mut self, ib: u64, kind: u8, depth: u8, seen: &mut HashSet<u64>) {
        let (size, trailer) = if self.wide_page {
            (4096, 24)
        } else {
            (512, 16)
        };
        let misplaced = ib % size as u64 != 0 || ib.saturating_add(size as u64) > self.len;
        if depth > MAX_DEPTH || misplaced || !seen.insert(ib) {
            self.bad_pages += 1;
            return;
        }
        let mut p = vec![0u8; size];
        if !read_at(&self.file, &mut p, ib) || p[size - trailer] != kind {
            self.bad_pages += 1;
            return;
        }
        let (count, width, level) = if self.wide_page {
            (u16_at(&p, 4056).unwrap_or(0) as usize, p[4060], p[4061])
        } else {
            (p[488] as usize, p[490], p[491])
        };
        let width = width as usize;
        let room = size - trailer - if self.wide_page { 16 } else { 8 };
        if width == 0 || count * width > room {
            self.bad_pages += 1;
            return;
        }
        let entries: Vec<Vec<u8>> = p[..count * width]
            .chunks_exact(width)
            .map(<[u8]>::to_vec)
            .collect();
        for e in entries {
            if level > 0 {
                if let Some(child) = u64_at(&e, 16) {
                    self.tree(child, kind, depth + 1, seen);
                }
            } else if kind == PAGE_NBT {
                if let (Some(nid), Some(data), Some(sub), Some(parent)) =
                    (u32_at(&e, 0), u64_at(&e, 8), u64_at(&e, 16), u32_at(&e, 24))
                {
                    self.nodes.insert(nid, Node { data, sub, parent });
                }
            } else if let (Some(bid), Some(ib), Some(cb), Some(second)) =
                (u64_at(&e, 0), u64_at(&e, 8), u16_at(&e, 16), u16_at(&e, 18))
            {
                // In version 23 the second field is a reference count.
                let inflated = if self.wide_page { second } else { cb };
                self.blocks.insert(bid & !1, Block { ib, cb, inflated });
            }
        }
    }

    pub fn reader(&self) -> Reader<'_> {
        Reader {
            store: self,
            // Items are read more than once, and compressed blocks inflate.
            budget: Cell::new((self.len as usize).saturating_mul(32).max(1 << 26)),
            bad: Cell::new(0),
        }
    }
}

/// One pass over a store: counts damage and limits decoding, because blocks
/// and heap items can be shared to multiply their size.
pub struct Reader<'s> {
    store: &'s Store,
    budget: Cell<usize>,
    bad: Cell<u64>,
}

impl Reader<'_> {
    pub fn damaged<T>(&self) -> Option<T> {
        self.bad.set(self.bad.get() + 1);
        None
    }

    pub fn spend(&self, n: usize) -> bool {
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

    /// (damaged items, output cut because the budget ran out).
    pub fn damage(&self) -> (u64, bool) {
        (self.bad.get(), self.budget.get() == 0)
    }

    fn block(&self, bid: u64) -> Option<Vec<u8>> {
        let Some(b) = self.store.blocks.get(&(bid & !1)).copied() else {
            return self.damaged();
        };
        if !self.spend((b.cb as usize).max(b.inflated as usize)) {
            return None;
        }
        let mut d = vec![0u8; b.cb as usize];
        if !read_at(&self.store.file, &mut d, b.ib) {
            return self.damaged();
        }
        if b.cb != b.inflated && b.inflated != 0 {
            let mut out = Vec::with_capacity(b.inflated as usize);
            let z = ZlibDecoder::new(&d[..]).take(b.inflated as u64);
            if { z }.read_to_end(&mut out).is_err() {
                return self.damaged();
            }
            d = out;
        }
        if bid & INTERNAL == 0 {
            match self.store.crypt {
                1 => crypt::permute(&mut d),
                2 => crypt::cyclic(&mut d, bid as u32),
                _ => {}
            }
        }
        Some(d)
    }

    /// The data blocks of a node, through its `XBLOCK`s.
    pub fn data(&self, bid: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        self.collect(bid, 2, &mut out);
        out
    }

    fn collect(&self, bid: u64, levels: u8, out: &mut Vec<Vec<u8>>) {
        let Some(b) = self.block(bid) else {
            return;
        };
        if bid & INTERNAL == 0 {
            out.push(b);
            return;
        }
        if b.first() != Some(&1) || levels == 0 {
            self.damaged::<()>();
            return;
        }
        let count = u16_at(&b, 2).unwrap_or(0) as usize;
        for i in 0..count {
            match u64_at(&b, 8 + i * 8) {
                Some(child) => self.collect(child, levels - 1, out),
                None => {
                    self.damaged::<()>();
                    return;
                }
            }
        }
    }

    /// The subnodes of a node.
    pub fn subnodes(&self, bid: u64) -> HashMap<u32, Node> {
        let mut out = HashMap::new();
        if bid != 0 {
            self.sub(bid, 0, &mut out);
        }
        out
    }

    fn sub(&self, bid: u64, depth: u8, out: &mut HashMap<u32, Node>) {
        let Some(b) = self.block(bid) else {
            return;
        };
        if b.first() != Some(&2) || depth > 1 {
            self.damaged::<()>();
            return;
        }
        let level = b.get(1).copied().unwrap_or(0);
        let count = u16_at(&b, 2).unwrap_or(0) as usize;
        for i in 0..count {
            if level > 0 {
                match u64_at(&b, 8 + i * 16 + 8) {
                    Some(child) => self.sub(child, depth + 1, out),
                    None => {
                        self.damaged::<()>();
                        return;
                    }
                }
            } else {
                let at = 8 + i * 24;
                let (Some(nid), Some(data), Some(sub)) =
                    (u32_at(&b, at), u64_at(&b, at + 8), u64_at(&b, at + 16))
                else {
                    self.damaged::<()>();
                    return;
                };
                let parent = 0;
                out.insert(nid, Node { data, sub, parent });
            }
        }
    }
}
