//! A minimal EVTX writer: file header, 64 KiB chunks with string and template
//! tables, template-based records and CRC32 checksums, following the on-disk
//! layout documented by libyal (libevtx) and parsed by the `evtx` crate.
//! Records are always `TemplateInstance`s, as Windows writes them.

use std::collections::HashMap;
use std::io::Write;

pub const FILE_HEADER_SIZE: usize = 4096;
pub const CHUNK_SIZE: usize = 65536;
const CHUNK_HEADER_SIZE: usize = 512;

/// Substitution value types (BinXML value type tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ty {
    Null = 0x00,
    Str = 0x01,
    U8 = 0x04,
    U16 = 0x06,
    U32 = 0x08,
    U64 = 0x0A,
    Guid = 0x0F,
    FileTime = 0x11,
    Sid = 0x13,
    Hex32 = 0x14,
    Hex64 = 0x15,
    BinXml = 0x21,
}

/// A substitution value.
#[derive(Debug, Clone)]
pub enum V {
    Null,
    Str(String),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Guid([u8; 16]),
    FileTime(u64),
    Sid(String),
    Hex32(u32),
    Hex64(u64),
    /// The record payload, written as a nested template instance (BinXML
    /// value type 0x21), as Windows does for `EventData`.
    Payload,
}

impl V {
    fn ty(&self) -> Ty {
        match self {
            V::Null => Ty::Null,
            V::Str(_) => Ty::Str,
            V::U8(_) => Ty::U8,
            V::U16(_) => Ty::U16,
            V::U32(_) => Ty::U32,
            V::U64(_) => Ty::U64,
            V::Guid(_) => Ty::Guid,
            V::FileTime(_) => Ty::FileTime,
            V::Sid(_) => Ty::Sid,
            V::Hex32(_) => Ty::Hex32,
            V::Hex64(_) => Ty::Hex64,
            V::Payload => Ty::BinXml,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            V::Null => {}
            V::Str(s) => {
                for u in s.encode_utf16() {
                    out.extend_from_slice(&u.to_le_bytes());
                }
            }
            V::U8(v) => out.push(*v),
            V::U16(v) => out.extend_from_slice(&v.to_le_bytes()),
            V::U32(v) | V::Hex32(v) => out.extend_from_slice(&v.to_le_bytes()),
            V::U64(v) | V::Hex64(v) | V::FileTime(v) => out.extend_from_slice(&v.to_le_bytes()),
            V::Guid(g) => out.extend_from_slice(g),
            V::Sid(s) => encode_sid(s, out),
            V::Payload => {}
        }
    }
}

/// `S-1-5-21-1-2-3-500` to its binary form.
fn encode_sid(s: &str, out: &mut Vec<u8>) {
    let parts: Vec<u64> = s
        .trim_start_matches("S-")
        .split('-')
        .filter_map(|p| p.parse().ok())
        .collect();
    let (rev, auth, subs) = match parts.as_slice() {
        [rev, auth, subs @ ..] => (*rev as u8, *auth, subs),
        _ => (1, 0, &[][..]),
    };
    out.push(rev);
    out.push(subs.len() as u8);
    out.extend_from_slice(&auth.to_be_bytes()[2..8]);
    for s in subs {
        out.extend_from_slice(&(*s as u32).to_le_bytes());
    }
}

/// Template tree nodes.
#[derive(Debug, Clone)]
pub enum Node {
    Elem {
        name: &'static str,
        attrs: Vec<(&'static str, Content)>,
        children: Vec<Node>,
    },
    Content(Content),
}

#[derive(Debug, Clone)]
pub enum Content {
    Text(&'static str),
    /// Optional substitution `index` of type `ty` (0x0E token).
    Sub(u16, Ty),
}

pub fn el(name: &'static str, attrs: Vec<(&'static str, Content)>, children: Vec<Node>) -> Node {
    Node::Elem {
        name,
        attrs,
        children,
    }
}

pub fn sub(i: u16, ty: Ty) -> Node {
    Node::Content(Content::Sub(i, ty))
}

#[derive(Debug, Clone)]
pub struct Template {
    pub guid: [u8; 16],
    pub root: Node,
}

impl Template {
    pub fn id(&self) -> u32 {
        u32::from_le_bytes(self.guid[0..4].try_into().unwrap())
    }
}

/// Name hash used by the chunk string table (lower 16 bits of a 65599 hash).
fn name_hash(name: &str) -> u16 {
    let mut h: u32 = 0;
    for u in name.encode_utf16() {
        h = h.wrapping_mul(65599).wrapping_add(u as u32);
    }
    h as u16
}

struct Undo {
    pos: usize,
    names: Vec<String>,
    templates: Vec<usize>,
    name_buckets: [u32; 64],
    tmpl_buckets: [u32; 32],
}

pub struct ChunkBuilder {
    buf: Vec<u8>,
    pos: usize,
    names: HashMap<String, u32>,
    name_buckets: [u32; 64],
    templates: HashMap<usize, u32>,
    tmpl_buckets: [u32; 32],
    first_rid: u64,
    last_rid: u64,
    last_record_offset: u32,
    count: u64,
    added_names: Vec<String>,
    added_templates: Vec<usize>,
}

impl Default for ChunkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkBuilder {
    pub fn new() -> Self {
        ChunkBuilder {
            // Slack past 64 KiB so an overflowing record can be written, then undone.
            buf: vec![0u8; CHUNK_SIZE * 2],
            pos: CHUNK_HEADER_SIZE,
            names: HashMap::new(),
            name_buckets: [0; 64],
            templates: HashMap::new(),
            tmpl_buckets: [0; 32],
            first_rid: 0,
            last_rid: 0,
            last_record_offset: 0,
            count: 0,
            added_names: Vec::new(),
            added_templates: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn u8(&mut self, v: u8) {
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
    }
    fn patch_u32(&mut self, at: usize, v: u32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn name(&mut self, name: &str) {
        if let Some(&off) = self.names.get(name) {
            self.u32(off);
            return;
        }
        let off = (self.pos + 4) as u32;
        self.u32(off);
        let h = name_hash(name);
        let b = (h % 64) as usize;
        self.u32(self.name_buckets[b]);
        self.u16(h);
        let units: Vec<u16> = name.encode_utf16().collect();
        self.u16(units.len() as u16);
        for u in units {
            self.u16(u);
        }
        self.u16(0);
        self.name_buckets[b] = off;
        self.names.insert(name.to_string(), off);
        self.added_names.push(name.to_string());
    }

    fn content(&mut self, c: &Content) {
        match c {
            Content::Text(t) => {
                self.u8(0x05);
                self.u8(0x01);
                let units: Vec<u16> = t.encode_utf16().collect();
                self.u16(units.len() as u16);
                for u in units {
                    self.u16(u);
                }
            }
            Content::Sub(i, ty) => {
                self.u8(0x0E);
                self.u16(*i);
                self.u8(*ty as u8);
            }
        }
    }

    fn node(&mut self, n: &Node) {
        match n {
            Node::Content(c) => self.content(c),
            Node::Elem {
                name,
                attrs,
                children,
            } => {
                self.u8(if attrs.is_empty() { 0x01 } else { 0x41 });
                self.u16(0xFFFF); // dependency identifier
                let size_at = self.pos;
                self.u32(0);
                let start = self.pos;
                self.name(name);
                if !attrs.is_empty() {
                    let list_at = self.pos;
                    self.u32(0);
                    let list_start = self.pos;
                    for (i, (an, av)) in attrs.iter().enumerate() {
                        self.u8(if i + 1 < attrs.len() { 0x46 } else { 0x06 });
                        self.name(an);
                        self.content(av);
                    }
                    let list_len = (self.pos - list_start) as u32;
                    self.patch_u32(list_at, list_len);
                }
                if children.is_empty() {
                    self.u8(0x03);
                } else {
                    self.u8(0x02);
                    for c in children {
                        self.node(c);
                    }
                    self.u8(0x04);
                }
                let size = (self.pos - start) as u32;
                self.patch_u32(size_at, size);
            }
        }
    }

    fn template_def(&mut self, idx: usize, t: &Template) -> u32 {
        if let Some(&off) = self.templates.get(&idx) {
            return off;
        }
        let off = self.pos as u32;
        let bucket = (t.id() % 32) as usize;
        self.u32(self.tmpl_buckets[bucket]);
        self.bytes(&t.guid);
        let size_at = self.pos;
        self.u32(0);
        let start = self.pos;
        self.bytes(&[0x0F, 0x01, 0x01, 0x00]);
        self.node(&t.root);
        self.u8(0x00);
        let size = (self.pos - start) as u32;
        self.patch_u32(size_at, size);
        self.tmpl_buckets[bucket] = off;
        self.templates.insert(idx, off);
        self.added_templates.push(idx);
        off
    }

    /// Writes a fragment header and a `TemplateInstance` (definition inline on
    /// first use in the chunk) at the current position. Returns false when it
    /// overflows the chunk.
    fn instance(
        &mut self,
        tidx: usize,
        t: &Template,
        values: &[V],
        payload: Option<(usize, &Template, &[V])>,
    ) -> bool {
        self.bytes(&[0x0F, 0x01, 0x01, 0x00]);
        self.u8(0x0C);
        self.u8(0x01);
        self.u32(t.id());
        let def_at = self.pos;
        self.u32(0);
        let def = self.template_def(tidx, t);
        self.patch_u32(def_at, def);
        self.u32(values.len() as u32);
        let desc = self.pos;
        for _ in values {
            self.u32(0);
        }
        for (i, v) in values.iter().enumerate() {
            if self.pos + 4096 > self.buf.len() {
                return false;
            }
            let before = self.pos;
            match (v, payload) {
                (V::Payload, Some((pt, ptmpl, pvals))) => {
                    if !self.instance(pt, ptmpl, pvals, None) {
                        return false;
                    }
                    self.u8(0x00);
                }
                (V::Payload, None) => {}
                _ => {
                    let mut data = Vec::new();
                    v.encode(&mut data);
                    if self.pos + data.len() + 8 > self.buf.len() {
                        return false;
                    }
                    self.bytes(&data);
                }
            }
            let size = (self.pos - before) as u16;
            let at = desc + i * 4;
            self.buf[at..at + 2].copy_from_slice(&size.to_le_bytes());
            self.buf[at + 2] = if matches!(v, V::Payload) && payload.is_none() {
                Ty::Null as u8
            } else {
                v.ty() as u8
            };
        }
        self.pos <= CHUNK_SIZE
    }

    /// Appends a record. Returns false (and leaves the chunk unchanged) if
    /// it does not fit.
    pub fn push(
        &mut self,
        rid: u64,
        filetime: u64,
        tidx: usize,
        t: &Template,
        values: &[V],
        payload: Option<(usize, &Template, &[V])>,
    ) -> bool {
        let undo = Undo {
            pos: self.pos,
            names: std::mem::take(&mut self.added_names),
            templates: std::mem::take(&mut self.added_templates),
            name_buckets: self.name_buckets,
            tmpl_buckets: self.tmpl_buckets,
        };
        let start = self.pos;
        self.bytes(&[0x2a, 0x2a, 0x00, 0x00]);
        self.u32(0);
        self.u64(rid);
        self.u64(filetime);
        if !self.instance(tidx, t, values, payload) {
            self.rollback(undo);
            return false;
        }
        self.u8(0x00); // end of fragment
        let size = (self.pos - start + 4) as u32;
        self.u32(size);
        if self.pos > CHUNK_SIZE {
            self.rollback(undo);
            return false;
        }
        self.patch_u32(start + 4, size);
        if self.count == 0 {
            self.first_rid = rid;
        }
        self.last_rid = rid;
        self.last_record_offset = start as u32;
        self.count += 1;
        let mut names = undo.names;
        names.append(&mut self.added_names);
        self.added_names = names;
        let mut tm = undo.templates;
        tm.append(&mut self.added_templates);
        self.added_templates = tm;
        true
    }

    fn rollback(&mut self, u: Undo) {
        for n in self.added_names.drain(..) {
            self.names.remove(&n);
        }
        for t in self.added_templates.drain(..) {
            self.templates.remove(&t);
        }
        self.added_names = u.names;
        self.added_templates = u.templates;
        self.name_buckets = u.name_buckets;
        self.tmpl_buckets = u.tmpl_buckets;
        let end = self.pos.min(self.buf.len());
        self.buf[u.pos..end].fill(0);
        self.pos = u.pos;
    }

    /// Finalises the chunk (header, tables, checksums) and returns its 64 KiB.
    pub fn finish(&mut self, first_number: u64) -> Vec<u8> {
        let mut c = self.buf[..CHUNK_SIZE].to_vec();
        c[0..8].copy_from_slice(b"ElfChnk\0");
        c[8..16].copy_from_slice(&first_number.to_le_bytes());
        c[16..24].copy_from_slice(&(first_number + self.count.saturating_sub(1)).to_le_bytes());
        c[24..32].copy_from_slice(&self.first_rid.to_le_bytes());
        c[32..40].copy_from_slice(&self.last_rid.to_le_bytes());
        c[40..44].copy_from_slice(&128u32.to_le_bytes());
        c[44..48].copy_from_slice(&self.last_record_offset.to_le_bytes());
        c[48..52].copy_from_slice(&(self.pos as u32).to_le_bytes());
        for (i, o) in self.name_buckets.iter().enumerate() {
            c[128 + i * 4..132 + i * 4].copy_from_slice(&o.to_le_bytes());
        }
        for (i, o) in self.tmpl_buckets.iter().enumerate() {
            c[384 + i * 4..388 + i * 4].copy_from_slice(&o.to_le_bytes());
        }
        let data_crc = crc32fast::hash(&c[CHUNK_HEADER_SIZE..self.pos]);
        c[52..56].copy_from_slice(&data_crc.to_le_bytes());
        let mut h = crc32fast::Hasher::new();
        h.update(&c[..120]);
        h.update(&c[128..512]);
        c[124..128].copy_from_slice(&h.finalize().to_le_bytes());
        c
    }
}

/// Streams records into an EVTX file, chunk by chunk.
pub struct EvtxWriter<W: Write + std::io::Seek> {
    out: W,
    chunk: ChunkBuilder,
    chunks: u64,
    next_number: u64,
    next_rid: u64,
    max_chunks: u64,
}

impl<W: Write + std::io::Seek> EvtxWriter<W> {
    pub fn new(mut out: W, first_rid: u64, max_chunks: u64) -> std::io::Result<Self> {
        out.write_all(&[0u8; FILE_HEADER_SIZE])?;
        Ok(EvtxWriter {
            out,
            chunk: ChunkBuilder::new(),
            chunks: 0,
            next_number: 1,
            next_rid: first_rid,
            max_chunks: max_chunks.clamp(1, 65535),
        })
    }

    pub fn chunks(&self) -> u64 {
        self.chunks
    }

    pub fn full(&self) -> bool {
        self.chunks >= self.max_chunks
    }

    /// Appends one record; returns its record id, or `None` when the file is full.
    pub fn push(
        &mut self,
        filetime: u64,
        tidx: usize,
        t: &Template,
        values: &[V],
        payload: Option<(usize, &Template, &[V])>,
    ) -> std::io::Result<Option<u64>> {
        let rid = self.next_rid;
        if self.chunk.push(rid, filetime, tidx, t, values, payload) {
            self.next_rid += 1;
            return Ok(Some(rid));
        }
        if self.chunk.is_empty() {
            return Err(std::io::Error::other("record larger than a chunk"));
        }
        self.flush_chunk()?;
        if self.full() {
            return Ok(None);
        }
        if !self.chunk.push(rid, filetime, tidx, t, values, payload) {
            return Err(std::io::Error::other("record larger than a chunk"));
        }
        self.next_rid += 1;
        Ok(Some(rid))
    }

    fn flush_chunk(&mut self) -> std::io::Result<()> {
        let count = self.chunk.count;
        let bytes = self.chunk.finish(self.next_number);
        self.out.write_all(&bytes)?;
        self.next_number += count;
        self.chunks += 1;
        self.chunk = ChunkBuilder::new();
        Ok(())
    }

    pub fn finish(mut self) -> std::io::Result<W> {
        if !self.chunk.is_empty() {
            self.flush_chunk()?;
        }
        let mut h = [0u8; 128];
        h[0..8].copy_from_slice(b"ElfFile\0");
        h[8..16].copy_from_slice(&0u64.to_le_bytes());
        h[16..24].copy_from_slice(&self.chunks.saturating_sub(1).to_le_bytes());
        h[24..32].copy_from_slice(&self.next_rid.to_le_bytes());
        h[32..36].copy_from_slice(&128u32.to_le_bytes());
        h[36..38].copy_from_slice(&1u16.to_le_bytes());
        h[38..40].copy_from_slice(&3u16.to_le_bytes());
        h[40..42].copy_from_slice(&4096u16.to_le_bytes());
        h[42..44].copy_from_slice(&(self.chunks as u16).to_le_bytes());
        // flags (120) = 0: clean
        let crc = crc32fast::hash(&h[..120]);
        h[124..128].copy_from_slice(&crc.to_le_bytes());
        self.out.seek(std::io::SeekFrom::Start(0))?;
        self.out.write_all(&h)?;
        self.out.flush()?;
        Ok(self.out)
    }
}
