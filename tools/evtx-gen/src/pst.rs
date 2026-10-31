//! Writes small `.pst` and `.ost` files: the node database and the heap,
//! B-tree, property and table layers on top of it ([MS-PST]). Everything sits
//! in one heap block per node, except an attachment that must span blocks.

use std::io::Write;

use flate2::Compression;
use flate2::write::ZlibEncoder;

const PT_INT32: u16 = 3;
const PT_UNICODE: u16 = 0x1F;
const PT_TIME: u16 = 0x40;
const PT_BINARY: u16 = 0x102;

pub enum V<'a> {
    Int(u32),
    Text(&'a str),
    Time(u64),
    Binary(&'a [u8]),
}

fn wide(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn hid(item: usize) -> u32 {
    ((item + 1) as u32) << 5
}

/// A heap of one block.
fn heap(client: u8, root: u32, items: &[Vec<u8>]) -> Vec<u8> {
    let mut d = vec![0u8; 12];
    d[2] = 0xEC;
    d[3] = client;
    d[4..8].copy_from_slice(&root.to_le_bytes());
    let mut offsets = vec![12u16];
    for i in items {
        d.extend(i);
        d.resize(d.len().next_multiple_of(2), 0);
        offsets.push(d.len() as u16);
    }
    let map = d.len() as u16;
    d[..2].copy_from_slice(&map.to_le_bytes());
    d.extend((items.len() as u16).to_le_bytes());
    d.extend(0u16.to_le_bytes());
    for o in offsets {
        d.extend(o.to_le_bytes());
    }
    d
}

fn btree_header(key: u8, entry: u8, root: u32) -> Vec<u8> {
    let mut h = vec![0xB5, key, entry, 0];
    h.extend(root.to_le_bytes());
    h
}

/// Property context. `sub`: subnode ids for values stored outside the heap,
/// by property id.
pub fn props(values: &[(u16, V<'_>)], sub: &[(u16, u32)]) -> Vec<u8> {
    let mut items: Vec<Vec<u8>> = vec![Vec::new(), Vec::new()];
    let mut rows: Vec<(u16, Vec<u8>)> = Vec::new();
    let put = |items: &mut Vec<Vec<u8>>, d: Vec<u8>| {
        items.push(d);
        hid(items.len() - 1)
    };
    for (id, v) in values {
        let linked = sub.iter().find(|s| s.0 == *id).map(|s| s.1);
        let (kind, raw) = match v {
            V::Int(n) => (PT_INT32, *n),
            V::Text(t) => (PT_UNICODE, put(&mut items, wide(t))),
            V::Time(t) => (PT_TIME, put(&mut items, t.to_le_bytes().to_vec())),
            V::Binary(_) if linked.is_some() => (PT_BINARY, linked.unwrap_or(0)),
            V::Binary(b) => (PT_BINARY, put(&mut items, b.to_vec())),
        };
        let mut r = kind.to_le_bytes().to_vec();
        r.extend(raw.to_le_bytes());
        rows.push((*id, r));
    }
    rows.sort_by_key(|r| r.0);
    let leaf: Vec<u8> = rows
        .iter()
        .flat_map(|(id, r)| id.to_le_bytes().into_iter().chain(r.iter().copied()))
        .collect();
    items[0] = btree_header(2, 6, hid(1));
    items[1] = leaf;
    heap(0xBC, hid(0), &items)
}

/// Table context. A row is its id, then values of the columns as text or
/// integers; a missing value is `None`.
pub fn table(columns: &[(u16, u16)], rows: &[(u32, Vec<Option<V<'_>>>)]) -> Vec<u8> {
    let count = columns.len() + 1;
    let fixed = 4 + 4 * columns.len();
    let present = fixed + 4; // Fixed part, then the 4-byte row version slot.
    let flags = count.div_ceil(8);
    let width = present + flags;
    let mut items: Vec<Vec<u8>> = vec![Vec::new(); 4];
    let mut data = Vec::new();
    let mut index = Vec::new();
    for (i, (id, values)) in rows.iter().enumerate() {
        let mut row = vec![0u8; width];
        row[..4].copy_from_slice(&id.to_le_bytes());
        row[present] = 0x80;
        for (c, v) in values.iter().enumerate() {
            let Some(v) = v else {
                continue;
            };
            let raw = match v {
                V::Int(n) => *n,
                V::Text(t) => {
                    items.push(wide(t));
                    hid(items.len() - 1)
                }
                _ => 0,
            };
            row[4 + c * 4..8 + c * 4].copy_from_slice(&raw.to_le_bytes());
            row[present + (c + 1) / 8] |= 0x80 >> ((c + 1) % 8);
        }
        data.extend(row);
        index.extend(id.to_le_bytes());
        index.extend((i as u32).to_le_bytes());
    }
    let mut info = vec![0x7C, count as u8];
    for off in [present - 4, present, present, width] {
        info.extend((off as u16).to_le_bytes());
    }
    info.extend(hid(1).to_le_bytes());
    info.extend(if rows.is_empty() { 0 } else { hid(3) }.to_le_bytes());
    info.extend(0u32.to_le_bytes());
    let mut column = |tag: u32, at: usize, bit: usize| {
        info.extend(tag.to_le_bytes());
        info.extend((at as u16).to_le_bytes());
        info.push(4);
        info.push(bit as u8);
    };
    column(0x67F2_0003, 0, 0);
    for (c, (id, kind)) in columns.iter().enumerate() {
        column((u32::from(*id) << 16) | u32::from(*kind), 4 + c * 4, c + 1);
    }
    items[0] = info;
    items[1] = btree_header(4, 4, if rows.is_empty() { 0 } else { hid(2) });
    items[2] = index;
    items[3] = data;
    heap(0x7C, hid(0), &items)
}

fn crc(d: &[u8]) -> u32 {
    let mut c = 0u32;
    for b in d {
        c ^= u32::from(*b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    c
}

fn sig(ib: u64, bid: u64) -> u16 {
    let v = (ib ^ bid) as u32;
    (v >> 16) as u16 ^ v as u16
}

/// The compressible-encryption table, inverted: encrypting is the way back.
fn encrypt(d: &mut [u8]) {
    const DECODE: [u8; 256] = include!("pst_table.in");
    let mut encode = [0u8; 256];
    for (i, v) in DECODE.iter().enumerate() {
        encode[*v as usize] = i as u8;
    }
    for b in d {
        *b = encode[*b as usize];
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum Format {
    /// Version 23, compressible encryption.
    Pst,
    /// Version 36, zlib blocks.
    Ost,
}

pub struct File {
    format: Format,
    next: u64,
    blocks: Vec<(u64, Vec<u8>)>,
    nodes: Vec<[u64; 4]>,
}

pub type SubEntry = (u32, u64, u64);

impl File {
    pub fn new(format: Format) -> File {
        File {
            format,
            next: 1,
            blocks: Vec::new(),
            nodes: Vec::new(),
        }
    }

    fn bid(&mut self, internal: bool) -> u64 {
        self.next += 1;
        (self.next * 4) | if internal { 2 } else { 0 }
    }

    pub fn block(&mut self, d: Vec<u8>) -> u64 {
        let bid = self.bid(false);
        self.blocks.push((bid, d));
        bid
    }

    /// Data over several blocks, through an `XBLOCK`.
    pub fn spanned(&mut self, d: &[u8]) -> u64 {
        let parts: Vec<u64> = d.chunks(8000).map(|c| self.block(c.to_vec())).collect();
        let mut x = vec![1, 1];
        x.extend((parts.len() as u16).to_le_bytes());
        x.extend((d.len() as u32).to_le_bytes());
        for p in parts {
            x.extend(p.to_le_bytes());
        }
        let bid = self.bid(true);
        self.blocks.push((bid, x));
        bid
    }

    pub fn subnodes(&mut self, entries: &[SubEntry]) -> u64 {
        let mut b = vec![2, 0];
        b.extend((entries.len() as u16).to_le_bytes());
        b.extend([0; 4]);
        let mut sorted = entries.to_vec();
        sorted.sort_unstable();
        for (nid, data, sub) in sorted {
            b.extend(u64::from(nid).to_le_bytes());
            b.extend(data.to_le_bytes());
            b.extend(sub.to_le_bytes());
        }
        let bid = self.bid(true);
        self.blocks.push((bid, b));
        bid
    }

    pub fn node(&mut self, nid: u32, data: u64, sub: u64, parent: u32) {
        self.nodes
            .push([u64::from(nid), data, sub, u64::from(parent)]);
    }

    fn page(&self, entries: &[Vec<u8>], width: u8, level: u8, kind: u8, ib: u64) -> Vec<u8> {
        let wide = self.format == Format::Ost;
        let (size, tail) = if wide { (4096, 24) } else { (512, 16) };
        let mut p = vec![0u8; size];
        for (i, e) in entries.iter().enumerate() {
            p[i * width as usize..][..e.len()].copy_from_slice(e);
        }
        let max = ((if wide { 4056 } else { 488 }) / width as usize) as u16;
        if wide {
            p[4056..4058].copy_from_slice(&(entries.len() as u16).to_le_bytes());
            p[4058..4060].copy_from_slice(&max.to_le_bytes());
            p[4060] = width;
            p[4061] = level;
        } else {
            p[488] = entries.len() as u8;
            p[489] = max as u8;
            p[490] = width;
            p[491] = level;
        }
        let at = size - tail;
        let bid = ib | 0x100_0000;
        p[at] = kind;
        p[at + 1] = kind;
        p[at + 2..at + 4].copy_from_slice(&sig(ib, bid).to_le_bytes());
        let check = crc(&p[..at]);
        p[at + 4..at + 8].copy_from_slice(&check.to_le_bytes());
        p[at + 8..at + 16].copy_from_slice(&bid.to_le_bytes());
        p
    }

    /// Writes the tree's pages at the end of `out`, returns the root's offset.
    fn tree(&self, out: &mut Vec<u8>, mut leaves: Vec<Vec<u8>>, width: u8, kind: u8) -> (u64, u64) {
        let wide = self.format == Format::Ost;
        let size: usize = if wide { 4096 } else { 512 };
        let per = (if wide { 4056 } else { 488 }) / width as usize;
        leaves.sort();
        leaves.sort_by_key(|l| u64::from_le_bytes(l[..8].try_into().unwrap_or([0; 8])));
        let mut parents = Vec::new();
        for chunk in leaves.chunks(per) {
            out.resize(out.len().next_multiple_of(size), 0);
            let ib = out.len() as u64;
            let page = self.page(chunk, width, 0, kind, ib);
            out.extend(page);
            let mut e = chunk[0][..8].to_vec();
            e.extend((ib | 0x100_0000).to_le_bytes());
            e.extend(ib.to_le_bytes());
            parents.push(e);
        }
        out.resize(out.len().next_multiple_of(size), 0);
        let ib = out.len() as u64;
        let page = self.page(&parents, 24, 1, kind, ib);
        out.extend(page);
        (ib | 0x100_0000, ib)
    }

    pub fn finish(self) -> Vec<u8> {
        let wide = self.format == Format::Ost;
        let (align, tail) = if wide { (512, 24) } else { (64, 16) };
        let mut out = vec![0u8; 0x4600];
        let mut entries = Vec::new();
        for (bid, d) in &self.blocks {
            let mut d = d.clone();
            let inflated = d.len() as u16;
            if wide {
                let mut z = ZlibEncoder::new(Vec::new(), Compression::best());
                z.write_all(&d).expect("in memory");
                let packed = z.finish().expect("in memory");
                if packed.len() < d.len() {
                    d = packed;
                }
            } else if bid & 2 == 0 {
                encrypt(&mut d);
            }
            out.resize(out.len().next_multiple_of(align), 0);
            let ib = out.len() as u64;
            let cb = d.len() as u16;
            let check = crc(&d);
            let total = (d.len() + tail).next_multiple_of(align);
            out.extend(&d);
            out.resize(ib as usize + total - tail, 0);
            out.extend(cb.to_le_bytes());
            out.extend(sig(ib, *bid).to_le_bytes());
            out.extend(check.to_le_bytes());
            out.extend(bid.to_le_bytes());
            if wide {
                out.extend(2u16.to_le_bytes());
                out.extend(inflated.to_le_bytes());
                out.extend([0; 4]);
            }
            let mut e = bid.to_le_bytes().to_vec();
            e.extend(ib.to_le_bytes());
            e.extend(cb.to_le_bytes());
            e.extend((if wide { inflated } else { 1 }).to_le_bytes());
            e.extend(1u32.to_le_bytes());
            entries.push(e);
        }
        let nodes: Vec<Vec<u8>> = self
            .nodes
            .iter()
            .map(|n| {
                let mut e: Vec<u8> = n[..3].iter().flat_map(|v| v.to_le_bytes()).collect();
                e.extend(n[3].to_le_bytes());
                e
            })
            .collect();
        let nbt = self.tree(&mut out, nodes, 32, 0x81);
        let bbt = self.tree(&mut out, entries, 24, 0x80);
        let size: usize = if wide { 4096 } else { 512 };
        out.resize(out.len().next_multiple_of(size), 0);
        let eof = out.len() as u64;
        let h = &mut out[..564];
        h[..4].copy_from_slice(b"!BDN");
        h[8..10].copy_from_slice(if wide { b"SO" } else { b"SM" });
        h[10..12].copy_from_slice(&(if wide { 36u16 } else { 23 }).to_le_bytes());
        h[12..14].copy_from_slice(&19u16.to_le_bytes());
        h[14] = 1;
        h[15] = 1;
        h[32..40].copy_from_slice(&0x10_0000u64.to_le_bytes());
        h[184..192].copy_from_slice(&eof.to_le_bytes());
        h[216..224].copy_from_slice(&nbt.0.to_le_bytes());
        h[224..232].copy_from_slice(&nbt.1.to_le_bytes());
        h[232..240].copy_from_slice(&bbt.0.to_le_bytes());
        h[240..248].copy_from_slice(&bbt.1.to_le_bytes());
        h[248] = 2;
        h[512] = 0x80;
        h[513] = u8::from(!wide);
        let partial = crc(&h[8..479]);
        h[4..8].copy_from_slice(&partial.to_le_bytes());
        let full = crc(&h[8..524]);
        h[524..528].copy_from_slice(&full.to_le_bytes());
        out
    }
}
