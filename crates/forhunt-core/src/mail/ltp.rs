//! Lists, tables and properties ([MS-PST] 2.3): a heap inside a node's
//! blocks, a B-tree inside the heap, and on top of it property contexts
//! (one item) and table contexts (rows of items).

use std::collections::HashMap;

use super::ndb::{Node, Reader};
use crate::Ts;
use crate::ntfs::record::{filetime, u16_at, u32_at, u64_at};

const SIG_HEAP: u8 = 0xEC;
const SIG_BTREE: u8 = 0xB5;
const SIG_PC: u8 = 0xBC;
const SIG_TC: u8 = 0x7C;
const PT_INT16: u16 = 2;
const PT_INT32: u16 = 3;
const PT_FLOAT: u16 = 4;
const PT_ERROR: u16 = 0xA;
const PT_BOOL: u16 = 0xB;
const PT_INT64: u16 = 0x14;
const PT_STRING8: u16 = 0x1E;
pub const PT_UNICODE: u16 = 0x1F;
const PT_TIME: u16 = 0x40;
const MAX_LEVELS: u8 = 8;

struct Heap<'r, 's> {
    r: &'r Reader<'s>,
    blocks: Vec<Vec<u8>>,
    subs: HashMap<u32, Node>,
}

impl Heap<'_, '_> {
    fn client(&self) -> Option<u8> {
        let b = self.blocks.first()?;
        (b.get(2) == Some(&SIG_HEAP)).then(|| b.get(3).copied())?
    }

    fn root(&self) -> Option<u32> {
        u32_at(self.blocks.first()?, 4)
    }

    fn alloc(&self, hid: u32) -> Option<&[u8]> {
        let index = ((hid >> 5) & 0x7FF) as usize;
        let block = self.blocks.get((hid >> 16) as usize)?;
        if hid & 0x1F != 0 || index == 0 {
            return None;
        }
        let map = u16_at(block, 0)? as usize;
        if index > u16_at(block, map)? as usize {
            return None;
        }
        let at = |i: usize| u16_at(block, map + 4 + i * 2).map(usize::from);
        block.get(at(index - 1)?..at(index)?)
    }

    /// A value: a heap item or a subnode.
    fn value(&self, hnid: u32) -> Option<Vec<u8>> {
        if hnid == 0 {
            return Some(Vec::new());
        }
        if hnid & 0x1F == 0 {
            let item = self.alloc(hnid)?;
            return self.r.spend(item.len()).then(|| item.to_vec());
        }
        let node = self.subs.get(&hnid)?;
        Some(self.r.data(node.data).concat())
    }

    fn btree(&self, hid: u32) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let Some(h) = self.alloc(hid) else {
            self.r.damaged::<()>();
            return out;
        };
        if h.len() < 8 || h[0] != SIG_BTREE || h[3] > MAX_LEVELS {
            self.r.damaged::<()>();
            return out;
        }
        let (key, entry, levels) = (h[1] as usize, h[2] as usize, h[3]);
        if let Some(root) = u32_at(h, 4).filter(|r| *r != 0) {
            self.walk(root, key, entry, levels, &mut out);
        }
        out
    }

    fn walk(&self, hid: u32, key: usize, entry: usize, level: u8, out: &mut Vec<Vec<u8>>) {
        let Some(d) = self.alloc(hid) else {
            self.r.damaged::<()>();
            return;
        };
        if !self.r.spend(d.len()) {
            return;
        }
        if level == 0 {
            out.extend(d.chunks_exact((key + entry).max(1)).map(<[u8]>::to_vec));
            return;
        }
        for c in d.chunks_exact(key + 4) {
            if let Some(child) = u32_at(c, key) {
                self.walk(child, key, entry, level - 1, out);
            }
        }
    }
}

fn utf16(d: &[u8]) -> String {
    let v: Vec<u16> = d
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&v)
}

/// Bytes of unknown code page: UTF-8 if it holds, else Latin-1.
pub fn text_of(d: &[u8]) -> String {
    match std::str::from_utf8(d) {
        Ok(s) => s.to_string(),
        Err(_) => d.iter().map(|&b| b as char).collect(),
    }
}

fn decode(kind: u16, d: &[u8]) -> Option<String> {
    match kind {
        PT_UNICODE => Some(utf16(d)),
        PT_STRING8 => Some(text_of(d)),
        _ => None,
    }
}

fn is_inline(kind: u16) -> bool {
    matches!(kind, PT_INT16 | PT_INT32 | PT_FLOAT | PT_ERROR | PT_BOOL)
}

pub struct Props<'r, 's> {
    heap: Heap<'r, 's>,
    map: HashMap<u16, (u16, u32)>,
}

impl<'r, 's> Props<'r, 's> {
    pub fn open(r: &'r Reader<'s>, node: &Node) -> Option<Props<'r, 's>> {
        let heap = Heap {
            r,
            blocks: r.data(node.data),
            subs: r.subnodes(node.sub),
        };
        if heap.client() != Some(SIG_PC) {
            return r.damaged();
        }
        let root = heap.root()?;
        let map = heap
            .btree(root)
            .iter()
            .filter_map(|e| Some((u16_at(e, 0)?, (u16_at(e, 2)?, u32_at(e, 4)?))))
            .collect();
        Some(Props { heap, map })
    }

    pub fn subnodes(&self) -> &HashMap<u32, Node> {
        &self.heap.subs
    }

    pub fn ids(&self, kind: u16) -> Vec<u16> {
        let mut v: Vec<u16> = self
            .map
            .iter()
            .filter(|(_, t)| t.0 == kind)
            .map(|(id, _)| *id)
            .collect();
        v.sort_unstable();
        v
    }

    pub fn kind(&self, id: u16) -> Option<u16> {
        self.map.get(&id).map(|t| t.0)
    }

    pub fn bytes(&self, id: u16) -> Option<Vec<u8>> {
        let (kind, v) = *self.map.get(&id)?;
        if is_inline(kind) {
            return Some(v.to_le_bytes().to_vec());
        }
        self.heap.value(v)
    }

    pub fn text(&self, id: u16) -> Option<String> {
        let kind = self.map.get(&id)?.0;
        decode(kind, &self.bytes(id)?).filter(|s| !s.is_empty())
    }

    pub fn int(&self, id: u16) -> Option<u64> {
        let (kind, v) = *self.map.get(&id)?;
        match kind {
            PT_INT16 | PT_INT32 | PT_BOOL => Some(u64::from(v)),
            PT_INT64 => u64_at(&self.bytes(id)?, 0),
            _ => None,
        }
    }

    pub fn time(&self, id: u16) -> Option<Ts> {
        (self.map.get(&id)?.0 == PT_TIME)
            .then(|| filetime(u64_at(&self.bytes(id)?, 0)?))
            .flatten()
    }
}

struct Column {
    id: u16,
    kind: u16,
    offset: usize,
    size: usize,
    bit: usize,
}

pub struct Table<'r, 's> {
    heap: Heap<'r, 's>,
    columns: Vec<Column>,
    present: usize,
    rows: Vec<Vec<u8>>,
}

impl<'r, 's> Table<'r, 's> {
    pub fn open(r: &'r Reader<'s>, node: &Node, subs: HashMap<u32, Node>) -> Option<Table<'r, 's>> {
        let heap = Heap {
            r,
            blocks: r.data(node.data),
            subs: subs.into_iter().chain(r.subnodes(node.sub)).collect(),
        };
        if heap.client() != Some(SIG_TC) {
            return r.damaged();
        }
        let info = heap.alloc(heap.root()?)?;
        if info.len() < 22 {
            return r.damaged();
        }
        let present = u16_at(info, 6)? as usize;
        let width = u16_at(info, 8)? as usize;
        let index = u32_at(info, 10)?;
        let rows_at = u32_at(info, 14)?;
        let columns = (0..info[1] as usize)
            .filter_map(|i| {
                let c = info.get(22 + i * 8..30 + i * 8)?;
                Some(Column {
                    kind: u16_at(c, 0)?,
                    id: u16_at(c, 2)?,
                    offset: u16_at(c, 4)? as usize,
                    size: c[6] as usize,
                    bit: c[7] as usize,
                })
            })
            .collect();
        let count = heap.btree(index).len();
        let rows = if width == 0 || rows_at == 0 {
            Vec::new()
        } else if rows_at & 0x1F == 0 {
            let d = heap.alloc(rows_at).unwrap_or(&[]);
            d.chunks_exact(width).map(<[u8]>::to_vec).collect()
        } else {
            let node = heap.subs.get(&rows_at)?;
            let blocks = r.data(node.data);
            let rows = blocks.iter().flat_map(|b| b.chunks_exact(width));
            rows.map(<[u8]>::to_vec).collect()
        };
        let rows: Vec<Vec<u8>> = rows.into_iter().take(count).collect();
        Some(Table {
            heap,
            columns,
            present,
            rows,
        })
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    fn cell(&self, row: usize, id: u16) -> Option<(u16, u32, &[u8])> {
        let row = self.rows.get(row)?;
        let c = self.columns.iter().find(|c| c.id == id)?;
        let flags = row.get(self.present + c.bit / 8)?;
        if flags & (0x80 >> (c.bit % 8)) == 0 {
            return None;
        }
        let raw = row.get(c.offset..c.offset + c.size)?;
        let small = u32_at(raw, 0)
            .unwrap_or_else(|| raw.iter().rev().fold(0, |v, b| v << 8 | u32::from(*b)));
        Some((c.kind, small, raw))
    }

    pub fn text(&self, row: usize, id: u16) -> Option<String> {
        let (kind, hnid, _) = self.cell(row, id)?;
        decode(kind, &self.heap.value(hnid)?).filter(|s| !s.is_empty())
    }

    pub fn int(&self, row: usize, id: u16) -> Option<u64> {
        self.cell(row, id).map(|c| u64::from(c.1))
    }
}
