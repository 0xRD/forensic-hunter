//! Fast decoding path: reads template substitution values straight from the
//! chunk bytes, skipping the `evtx` crate's IR build, its JSON rendering and
//! our JSON scan (about 70% of the work, see docs/PERF.md P-005).
//!
//! Windows writes nearly every record as a `TemplateInstance`: a template
//! definition (the XML skeleton, stored once per chunk) plus an array of typed
//! substitution values. For each template we build a [`Plan`] once: which
//! substitution feeds which `System` value or `EventData` field. Decoding a
//! record is then a walk over its value array.
//!
//! The fast path only accepts shapes whose output it can reproduce exactly
//! like the JSON path (`System` + `EventData` with named `<Data>` elements,
//! scalar value types). A chunk containing anything else is decoded by the
//! JSON path as a whole, so record order and output never depend on the path.
//! `tests/fast_path.rs` checks both paths agree, field by field.

use std::borrow::Cow;
use std::collections::HashMap;
use std::rc::Rc;

use crate::event::{EventView, Field, Val};
use crate::id::{EventRef, FileKey};
use crate::time::Ts;

const CHUNK_HEADER: usize = 512;
/// FILETIME (100 ns since 1601) of the Unix epoch.
const EPOCH_TICKS: i64 = 116_444_736_000_000_000;

/// Where a value comes from.
#[derive(Debug, Clone)]
enum Src {
    Sub(u16),
    Text(String),
}

#[derive(Debug, Default)]
struct SysPlan {
    provider: Option<Src>,
    source_name: Option<Src>,
    event_id: Option<Src>,
    version: Option<Src>,
    level: Option<Src>,
    task: Option<Src>,
    opcode: Option<Src>,
    keywords: Option<Src>,
    time: Option<Src>,
    erid: Option<Src>,
    activity: Option<Src>,
    pid: Option<Src>,
    tid: Option<Src>,
    channel: Option<Src>,
    computer: Option<Src>,
    user_sid: Option<Src>,
}

/// How to turn a record of one template into an [`EventView`].
#[derive(Debug, Default)]
pub(crate) struct Plan {
    sys: SysPlan,
    /// `EventData` fields in document order; `None` source = empty element.
    fields: Vec<(String, Option<Src>)>,
    /// Substitution holding the payload as a nested template (BinXML value):
    /// Windows' usual layout, the outer template carrying only `System`.
    payload: Option<u16>,
}

/// Fields of a nested `EventData` template.
#[derive(Debug, Default)]
pub(crate) struct PayloadPlan {
    fields: Vec<(String, Option<Src>)>,
}

/// A parsed template definition node.
#[derive(Debug)]
enum Node {
    Elem {
        name: String,
        attrs: Vec<(String, Vec<Node>)>,
        children: Vec<Node>,
    },
    Text(String),
    Sub(u16),
}

struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

type R<T> = Option<T>;

impl<'a> Cur<'a> {
    fn u8(&mut self) -> R<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }
    fn u16(&mut self) -> R<u16> {
        let v = u16::from_le_bytes(self.b.get(self.i..self.i + 2)?.try_into().ok()?);
        self.i += 2;
        Some(v)
    }
    fn u32(&mut self) -> R<u32> {
        let v = u32::from_le_bytes(self.b.get(self.i..self.i + 4)?.try_into().ok()?);
        self.i += 4;
        Some(v)
    }
    fn u64(&mut self) -> R<u64> {
        let v = u64::from_le_bytes(self.b.get(self.i..self.i + 8)?.try_into().ok()?);
        self.i += 8;
        Some(v)
    }
    fn peek(&self) -> R<u8> {
        self.b.get(self.i).copied()
    }
    fn utf16(&mut self, units: usize) -> R<String> {
        let raw = self.b.get(self.i..self.i + units * 2)?;
        self.i += units * 2;
        Some(decode_utf16(raw))
    }
}

fn decode_utf16(raw: &[u8]) -> String {
    let it = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]));
    char::decode_utf16(it)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

/// Reads a name reference: offset into the chunk; the name is inline when
/// the offset points right after the reference.
fn name(c: &mut Cur<'_>, chunk: &[u8]) -> R<String> {
    let off = c.u32()? as usize;
    let at = |o: usize| -> R<(String, usize)> {
        // [next u32][hash u16][len u16][utf16 * len][nul u16]
        let len = u16::from_le_bytes(chunk.get(o + 6..o + 8)?.try_into().ok()?) as usize;
        let s = decode_utf16(chunk.get(o + 8..o + 8 + len * 2)?);
        Some((s, 8 + len * 2 + 2))
    };
    if off == c.i {
        let (s, n) = at(off)?;
        c.i += n;
        Some(s)
    } else {
        at(off).map(|(s, _)| s)
    }
}

/// Parses a token stream until `EndElement`/EOF; returns the nodes.
fn content(c: &mut Cur<'_>, chunk: &[u8], depth: usize) -> R<Vec<Node>> {
    if depth > 32 {
        return None;
    }
    let mut out = Vec::new();
    loop {
        match c.peek()? {
            0x00 => {
                c.i += 1;
                return Some(out);
            }
            0x04 => {
                c.i += 1;
                return Some(out);
            }
            0x01 | 0x41 => out.push(element(c, chunk, depth + 1)?),
            0x05 | 0x45 => out.push(Node::Text(value_text(c)?)),
            0x0D | 0x0E => {
                c.i += 1;
                let idx = c.u16()?;
                let _ty = c.u8()?;
                out.push(Node::Sub(idx));
            }
            0x0F => c.i += 4, // nested fragment header
            _ => return None, // CDATA, entity/char refs, PIs, nested templates
        }
    }
}

fn value_text(c: &mut Cur<'_>) -> R<String> {
    c.i += 1;
    if c.u8()? != 0x01 {
        return None;
    }
    let n = c.u16()? as usize;
    c.utf16(n)
}

fn element(c: &mut Cur<'_>, chunk: &[u8], depth: usize) -> R<Node> {
    let tok = c.u8()?;
    let _dep = c.u16()?;
    let _size = c.u32()?;
    let ename = name(c, chunk)?;
    let mut attrs = Vec::new();
    if tok & 0x40 != 0 {
        let _list = c.u32()?;
        loop {
            let t = c.u8()?;
            if t & 0x3F != 0x06 {
                return None;
            }
            let an = name(c, chunk)?;
            let mut vals = Vec::new();
            // One value (text or substitution) per attribute.
            match c.peek()? {
                0x05 | 0x45 => vals.push(Node::Text(value_text(c)?)),
                0x0D | 0x0E => {
                    c.i += 1;
                    let idx = c.u16()?;
                    let _ty = c.u8()?;
                    vals.push(Node::Sub(idx));
                }
                _ => return None,
            }
            attrs.push((an, vals));
            if t & 0x40 == 0 {
                break;
            }
        }
    }
    let children = match c.u8()? {
        0x02 => content(c, chunk, depth)?,
        0x03 => Vec::new(),
        _ => return None,
    };
    Some(Node::Elem {
        name: ename,
        attrs,
        children,
    })
}

fn single(nodes: &[Node]) -> R<Option<Src>> {
    match nodes {
        [] => Some(None),
        [Node::Sub(i)] => Some(Some(Src::Sub(*i))),
        [Node::Text(t)] => Some(Some(Src::Text(t.clone()))),
        _ => None,
    }
}

fn attr<'n>(attrs: &'n [(String, Vec<Node>)], n: &str) -> Option<&'n [Node]> {
    attrs
        .iter()
        .find(|(k, _)| k == n)
        .map(|(_, v)| v.as_slice())
}

/// Builds a plan from a template definition's element tree, or `None` when
/// the shape is outside what the fast path reproduces exactly.
fn plan(root: &Node) -> R<Plan> {
    let Node::Elem { name, children, .. } = root else {
        return None;
    };
    if name != "Event" {
        return None;
    }
    let mut p = Plan::default();
    let mut seen_system = false;
    for ch in children {
        let (name, attrs, children) = match ch {
            Node::Elem {
                name,
                attrs,
                children,
            } => (name, attrs, children),
            Node::Sub(i) if p.payload.is_none() && p.fields.is_empty() => {
                p.payload = Some(*i);
                continue;
            }
            _ => return None,
        };
        match name.as_str() {
            "System" if attrs.is_empty() => {
                seen_system = true;
                for s in children {
                    let Node::Elem {
                        name,
                        attrs,
                        children,
                    } = s
                    else {
                        return None;
                    };
                    let sp = &mut p.sys;
                    let val = || single(children);
                    match name.as_str() {
                        "Provider" => {
                            if let Some(v) = attr(attrs, "Name") {
                                sp.provider = single(v)?;
                            }
                            if let Some(v) = attr(attrs, "EventSourceName") {
                                sp.source_name = single(v)?;
                            }
                        }
                        // Qualifiers attribute is not part of the model.
                        "EventID" => sp.event_id = val()?,
                        "Version" => sp.version = val()?,
                        "Level" => sp.level = val()?,
                        "Task" => sp.task = val()?,
                        "Opcode" => sp.opcode = val()?,
                        "Keywords" => sp.keywords = val()?,
                        "TimeCreated" => {
                            sp.time = attr(attrs, "SystemTime")
                                .map(single)
                                .unwrap_or(Some(None))?
                        }
                        "EventRecordID" => sp.erid = val()?,
                        "Correlation" => {
                            sp.activity = attr(attrs, "ActivityID")
                                .map(single)
                                .unwrap_or(Some(None))?
                        }
                        "Execution" => {
                            sp.pid = attr(attrs, "ProcessID").map(single).unwrap_or(Some(None))?;
                            sp.tid = attr(attrs, "ThreadID").map(single).unwrap_or(Some(None))?;
                        }
                        "Channel" => sp.channel = val()?,
                        "Computer" => sp.computer = val()?,
                        "Security" => {
                            sp.user_sid = attr(attrs, "UserID").map(single).unwrap_or(Some(None))?
                        }
                        _ => {}
                    }
                }
            }
            "EventData" if attrs.is_empty() && p.payload.is_none() => {
                p.fields = event_data(children)?
            }
            _ => return None,
        }
    }
    seen_system.then_some(p)
}

/// `<Data Name="literal">value</Data>` children only.
fn event_data(children: &[Node]) -> R<Vec<(String, Option<Src>)>> {
    let mut fields = Vec::with_capacity(children.len());
    for d in children {
        let Node::Elem {
            name,
            attrs,
            children,
        } = d
        else {
            return None;
        };
        if name != "Data" {
            return None;
        }
        let [(k, v)] = attrs.as_slice() else {
            return None;
        };
        let [Node::Text(field)] = v.as_slice() else {
            return None;
        };
        if k != "Name" {
            return None;
        }
        fields.push((field.clone(), single(children)?));
    }
    Some(fields)
}

/// Plan for a nested payload template: `<EventData>` with named `<Data>`.
fn payload_plan(root: &Node) -> R<PayloadPlan> {
    let Node::Elem {
        name,
        attrs,
        children,
    } = root
    else {
        return None;
    };
    if name != "EventData" || !attrs.is_empty() {
        return None;
    }
    Some(PayloadPlan {
        fields: event_data(children)?,
    })
}

/// Parses the template definition at `off` into its single root node.
fn template_root(chunk: &[u8], off: usize) -> R<Node> {
    let mut c = Cur { b: chunk, i: off };
    let _next = c.u32()?;
    c.i += 16; // GUID
    let size = c.u32()? as usize;
    let end = c.i.checked_add(size)?;
    if end > chunk.len() || c.u8()? != 0x0F {
        return None;
    }
    c.i += 3;
    let mut nodes = content(&mut c, chunk, 0)?;
    (nodes.len() == 1).then(|| nodes.pop()).flatten()
}

/// Parses the template definition at `off` (chunk-relative) into a plan.
fn parse_template(chunk: &[u8], off: usize) -> R<Plan> {
    let mut c = Cur { b: chunk, i: off };
    let _next = c.u32()?;
    c.i += 16; // GUID
    let size = c.u32()? as usize;
    let end = c.i.checked_add(size)?;
    if end > chunk.len() {
        return None;
    }
    if c.u8()? != 0x0F {
        return None;
    }
    c.i += 3;
    let nodes = content(&mut c, chunk, 0)?;
    let [root] = nodes.as_slice() else {
        return None;
    };
    plan(root)
}

/// Value types the fast path decodes. Others (ANSI strings, floats, SYSTEMTIME,
/// arrays, nested BinXML, handles) send the chunk to the JSON path.
fn supported(ty: u8) -> bool {
    matches!(
        ty,
        0x00 | 0x01 | 0x03..=0x0A | 0x0D | 0x0E | 0x0F | 0x10 | 0x11 | 0x13 | 0x14 | 0x15
    )
}

/// Value table of a template instance: (value type, start, end) in the chunk.
type Values = Vec<(u8, usize, usize)>;

/// One record located in the chunk.
struct Rec {
    rid: u64,
    filetime: u64,
    plan: Rc<Plan>,
    /// (type, value bytes range) per substitution.
    values: Values,
    /// Nested payload template and its values.
    payload: Option<(Rc<PayloadPlan>, Values)>,
}

/// Reads a `TemplateInstance` starting at `c` (token 0x0C included):
/// returns the template definition offset and the value table.
fn instance(
    c: &mut Cur<'_>,
    chunk: &[u8],
    limit: usize,
    allow_binxml: Option<u16>,
) -> R<(usize, Values)> {
    if c.u8()? != 0x0C {
        return None;
    }
    let _unknown = c.u8()?;
    let _template_id = c.u32()?;
    let def_off = c.u32()? as usize;
    if def_off == c.i {
        let size = u32::from_le_bytes(chunk.get(c.i + 20..c.i + 24)?.try_into().ok()?) as usize;
        c.i += 24 + size;
    }
    let n = c.u32()? as usize;
    if n > 4096 {
        return None;
    }
    let desc_start = c.i;
    c.i += n * 4;
    let mut values = Vec::with_capacity(n);
    let mut at = c.i;
    for k in 0..n {
        let d = desc_start + k * 4;
        let size = u16::from_le_bytes(chunk.get(d..d + 2)?.try_into().ok()?) as usize;
        let ty = *chunk.get(d + 2)?;
        let ok = supported(ty) || (ty == 0x21 && allow_binxml == Some(k as u16));
        if !ok || at + size > limit {
            return None;
        }
        values.push((ty, at, at + size));
        at += size;
    }
    c.i = at;
    Some((def_off, values))
}

/// Per-thread cache of plans keyed by a hash of the template definition
/// bytes (the same template is redefined in every chunk).
type Entry<T> = (usize, Vec<u8>, Option<Rc<T>>);

#[derive(Default)]
pub(crate) struct PlanCache {
    outer: HashMap<u64, Entry<Plan>>,
    payload: HashMap<u64, Entry<PayloadPlan>>,
}

/// The template definition bytes at `off` (header included).
fn def_bytes(chunk: &[u8], off: usize) -> Option<&[u8]> {
    let size = u32::from_le_bytes(chunk.get(off + 20..off + 24)?.try_into().ok()?) as usize;
    chunk.get(off..off.checked_add(24 + size)?)
}

/// Cache key for the template definition at `off`.
fn def_key(chunk: &[u8], off: usize) -> Option<u64> {
    let def = def_bytes(chunk, off)?;
    // Skip the chunk-local "next" link. Names are referenced by chunk
    // offset: equal bytes at a different offset could resolve to different
    // names, so the offset is keyed too.
    Some(hash_bytes(&def[4..], off as u64))
}

/// A fast 64-bit hash (multiply-xor over 8-byte words). Only selects the cache
/// bucket: entries also store the definition bytes, compared on every hit.
fn hash_bytes(b: &[u8], seed: u64) -> u64 {
    const K: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut h = seed ^ (b.len() as u64).wrapping_mul(K);
    let mut words = b.chunks_exact(8);
    for w in &mut words {
        let x = u64::from_le_bytes(w.try_into().unwrap());
        h = (h ^ x).wrapping_mul(K).rotate_left(29);
    }
    let mut tail = [0u8; 8];
    tail[..words.remainder().len()].copy_from_slice(words.remainder());
    h = (h ^ u64::from_le_bytes(tail)).wrapping_mul(K);
    h ^ (h >> 32)
}

fn cached<T>(
    map: &mut HashMap<u64, Entry<T>>,
    chunk: &[u8],
    off: usize,
    make: impl FnOnce() -> Option<T>,
) -> Option<Rc<T>> {
    let k = def_key(chunk, off)?;
    let def = def_bytes(chunk, off)?;
    if let Some((o, bytes, p)) = map.get(&k)
        && *o == off
        && bytes[4..] == def[4..]
    {
        return p.clone();
    }
    if map.len() > 4096 {
        map.clear();
    }
    let p = make().map(Rc::new);
    map.insert(k, (off, def.to_vec(), p.clone()));
    p
}

impl PlanCache {
    fn get(&mut self, chunk: &[u8], off: usize) -> Option<Rc<Plan>> {
        cached(&mut self.outer, chunk, off, || parse_template(chunk, off))
    }

    fn get_payload(&mut self, chunk: &[u8], off: usize) -> Option<Rc<PayloadPlan>> {
        cached(&mut self.payload, chunk, off, || {
            payload_plan(&template_root(chunk, off)?)
        })
    }
}

/// Scans all records of a chunk. Returns `None` if any record is outside
/// the fast path (the caller then uses the JSON path for the whole chunk).
fn scan(chunk: &[u8], cache: &mut PlanCache) -> R<Vec<Rec>> {
    let free = u32::from_le_bytes(chunk.get(48..52)?.try_into().ok()?) as usize;
    let end = free.min(chunk.len());
    let mut off = CHUNK_HEADER;
    let mut out = Vec::new();
    // Templates per chunk are few: a linear scan beats hashing per record.
    let mut local: Vec<(u32, Rc<Plan>)> = Vec::new();
    while off + 24 <= end {
        let mut c = Cur { b: chunk, i: off };
        if c.u32()? != 0x0000_2a2a {
            break;
        }
        let size = c.u32()? as usize;
        let rid = c.u64()?;
        let filetime = c.u64()?;
        if size < 28 || off + size > end {
            return None;
        }
        let rec_end = off + size - 4;
        // BinXML: fragment header, TemplateInstance, values, EOF.
        if c.u8()? != 0x0F {
            return None;
        }
        c.i += 3;
        let start = c.i;
        // First pass with any payload slot allowed; the plan decides.
        let def_off = {
            let mut probe = Cur {
                b: chunk,
                i: start + 6,
            };
            probe.u32()? as usize
        };
        let plan = match local.iter().find(|(o, _)| *o == def_off as u32) {
            Some((_, p)) => p.clone(),
            None => {
                let p = cache.get(chunk, def_off)?;
                local.push((def_off as u32, p.clone()));
                p
            }
        };
        let (_, values) = instance(&mut c, chunk, rec_end, plan.payload)?;
        let payload = match plan.payload {
            None => None,
            Some(slot) => match values.get(slot as usize) {
                None | Some(&(0x00, _, _)) => None,
                Some(&(0x21, a, b)) => {
                    // Nested fragment: header, TemplateInstance, EOF.
                    let mut n = Cur { b: chunk, i: a };
                    if n.u8()? != 0x0F {
                        return None;
                    }
                    n.i += 3;
                    let inner_def = {
                        let mut probe = Cur {
                            b: chunk,
                            i: n.i + 6,
                        };
                        probe.u32()? as usize
                    };
                    let pp = cache.get_payload(chunk, inner_def)?;
                    let (_, inner) = instance(&mut n, chunk, b, None)?;
                    Some((pp, inner))
                }
                Some(_) => return None,
            },
        };
        out.push(Rec {
            rid,
            filetime,
            plan,
            values,
            payload,
        });
        off += size;
    }
    Some(out)
}

/// Decoded values of one record, as text slices into `text`.
#[derive(Clone, Copy)]
enum V {
    Null,
    Str(usize, usize),
    Num(usize, usize),
    Bool(bool),
}

const HEX_UP: &[u8; 16] = b"0123456789ABCDEF";
const HEX_LO: &[u8; 16] = b"0123456789abcdef";

fn hex_lower(out: &mut String, v: u64) {
    let mut buf = [0u8; 18];
    let mut i = buf.len();
    let mut x = v;
    loop {
        i -= 1;
        buf[i] = HEX_LO[(x & 0xf) as usize];
        x >>= 4;
        if x == 0 {
            break;
        }
    }
    out.push_str("0x");
    // ASCII by construction.
    out.push_str(std::str::from_utf8(&buf[i..]).unwrap_or(""));
}

fn push_u64(out: &mut String, v: u64) {
    let mut b = [0u8; 20];
    out.push_str(std::str::from_utf8(crate::id::fmt_u64(&mut b, v)).unwrap_or(""));
}

fn push_i64(out: &mut String, v: i64) {
    if v < 0 {
        out.push('-');
    }
    push_u64(out, v.unsigned_abs());
}

fn push_hex_byte(out: &mut String, x: u8) {
    out.push(HEX_UP[(x >> 4) as usize] as char);
    out.push(HEX_UP[(x & 0xf) as usize] as char);
}

/// UTF-16LE to UTF-8, with an ASCII fast path; stops at a NUL like the JSON path.
fn push_utf16(out: &mut String, raw: &[u8]) {
    let units = raw.len() / 2;
    out.reserve(units);
    let mut i = 0;
    while i < units {
        let (lo, hi) = (raw[2 * i], raw[2 * i + 1]);
        if hi == 0 && lo < 0x80 {
            if lo == 0 {
                return;
            }
            out.push(lo as char);
            i += 1;
            continue;
        }
        // Non-ASCII: decode the rest generically.
        let it = raw[2 * i..units * 2]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]));
        for ch in char::decode_utf16(it) {
            let ch = ch.unwrap_or('\u{FFFD}');
            if ch == '\0' {
                return;
            }
            out.push(ch);
        }
        return;
    }
}

fn decode_value(chunk: &[u8], ty: u8, a: usize, b: usize, text: &mut String) -> V {
    let raw = &chunk[a..b];
    let start = text.len();
    let le = |n: usize| -> u64 {
        let mut x = [0u8; 8];
        x[..n.min(raw.len())].copy_from_slice(&raw[..n.min(raw.len())]);
        u64::from_le_bytes(x)
    };
    match ty {
        0x00 => return V::Null,
        0x01 => push_utf16(text, raw),
        0x03 => push_i64(text, le(1) as u8 as i8 as i64),
        0x04 => push_u64(text, le(1) as u8 as u64),
        0x05 => push_i64(text, le(2) as u16 as i16 as i64),
        0x06 => push_u64(text, le(2) as u16 as u64),
        0x07 => push_i64(text, le(4) as u32 as i32 as i64),
        0x08 => push_u64(text, le(4) as u32 as u64),
        0x09 => push_i64(text, le(8) as i64),
        0x0A => push_u64(text, le(8)),
        // SizeT renders as a hex string of its width, like the JSON path.
        0x10 => hex_lower(text, if raw.len() == 4 { le(4) } else { le(8) }),
        0x0D => return V::Bool(le(4) != 0),
        0x0E => {
            for &x in raw {
                push_hex_byte(text, x);
            }
        }
        0x0F => {
            if raw.len() != 16 {
                return V::Null;
            }
            const ORDER: [usize; 16] = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
            for (i, &idx) in ORDER.iter().enumerate() {
                if matches!(i, 4 | 6 | 8 | 10) {
                    text.push('-');
                }
                push_hex_byte(text, raw[idx]);
            }
        }
        0x11 => {
            let ft = le(8) as i64;
            let t = Ts((ft - EPOCH_TICKS) / 10 * 10);
            let mut buf = Vec::with_capacity(27);
            t.write_iso(&mut buf);
            text.push_str(std::str::from_utf8(&buf).unwrap_or(""));
        }
        0x13 => {
            if raw.len() < 8 {
                text.push_str("S-?");
            } else {
                let authority =
                    u64::from_be_bytes([0, 0, raw[2], raw[3], raw[4], raw[5], raw[6], raw[7]]);
                text.push_str("S-");
                push_u64(text, raw[0] as u64);
                text.push('-');
                push_u64(text, authority);
                for c in raw[8..].chunks_exact(4).take(raw[1] as usize) {
                    text.push('-');
                    push_u64(text, u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64);
                }
            }
        }
        0x14 => hex_lower(text, le(4)),
        0x15 => hex_lower(text, le(8)),
        _ => return V::Null,
    }
    if matches!(ty, 0x03..=0x0A) {
        return V::Num(start, text.len());
    }
    V::Str(start, text.len())
}

/// Decodes a chunk on the fast path and delivers events in record order.
/// Returns `false` (having delivered nothing) when the chunk needs the JSON
/// path. `want_time` gets the record header time before decoding.
pub(crate) fn decode_chunk(
    chunk: &[u8],
    key: FileKey,
    cache: &mut PlanCache,
    sink: &mut dyn crate::artifact::Sink,
    records: &mut u64,
) -> bool {
    if !chunk.starts_with(b"ElfChnk\0") {
        return false;
    }
    let Some(recs) = scan(chunk, cache) else {
        return false;
    };
    let mut text = String::with_capacity(4096);
    let mut vals: Vec<V> = Vec::with_capacity(64);
    let mut spare: Vec<Field<'static>> = Vec::new();
    for r in &recs {
        *records += 1;
        let header_ts = Ts(r.filetime as i64 - EPOCH_TICKS);
        if !sink.want_time(header_ts) {
            continue;
        }
        text.clear();
        vals.clear();
        for &(ty, a, b) in &r.values {
            vals.push(if ty == 0x21 {
                V::Null
            } else {
                decode_value(chunk, ty, a, b, &mut text)
            });
        }
        // Payload values follow the outer ones in `vals`.
        let payload_base = vals.len();
        if let Some((_, inner)) = &r.payload {
            for &(ty, a, b) in inner {
                vals.push(decode_value(chunk, ty, a, b, &mut text));
            }
        }
        let text: &str = &text;
        let vals: &[V] = &vals;
        let get = |src| get_val(src, vals, text);
        let s = |src| str_val(src, vals, text);
        let n = |src| num_val(src, vals, text);
        let p = &r.plan;
        let sp = &p.sys;
        let mut ev = EventView {
            fields: recycle(std::mem::take(&mut spare)),
            ..EventView::default()
        };
        ev.id = EventRef {
            file: key,
            record: r.rid,
        };
        // TimeCreated at microsecond precision, like the JSON path.
        ev.ts = match &sp.time {
            Some(Src::Sub(i)) => match r.values.get(*i as usize) {
                Some(&(0x11, a, b)) if b - a == 8 => {
                    let ft = u64::from_le_bytes(chunk[a..b].try_into().unwrap()) as i64;
                    Ts((ft - EPOCH_TICKS) / 10 * 10)
                }
                _ => Ts::parse(&s(&sp.time)).unwrap_or(Ts(header_ts.0 / 10 * 10)),
            },
            Some(Src::Text(t)) => Ts::parse(t).unwrap_or(Ts(header_ts.0 / 10 * 10)),
            None => Ts(header_ts.0 / 10 * 10),
        };
        let prov = s(&sp.provider);
        ev.provider = if prov.is_empty() {
            s(&sp.source_name)
        } else {
            prov
        };
        ev.event_id = n(&sp.event_id) as u32;
        ev.version = n(&sp.version) as u32;
        ev.level = n(&sp.level) as u8;
        ev.task = n(&sp.task) as u32;
        ev.opcode = n(&sp.opcode) as u32;
        ev.keywords = s(&sp.keywords);
        ev.event_record_id = n(&sp.erid);
        ev.activity_id = s(&sp.activity);
        ev.process_id = n(&sp.pid) as u32;
        ev.thread_id = n(&sp.tid) as u32;
        ev.channel = s(&sp.channel);
        ev.computer = s(&sp.computer);
        ev.user_sid = s(&sp.user_sid);
        for (name, src) in &p.fields {
            let value = match src {
                None => Val::Null,
                some => get(some).unwrap_or(Val::Null),
            };
            ev.fields.push(Field {
                name: Cow::Borrowed(name.as_str()),
                value,
            });
        }
        if let Some((pp, _)) = &r.payload {
            let base = payload_base;
            for (name, src) in &pp.fields {
                let value = match src {
                    None => Val::Null,
                    Some(Src::Sub(i)) => sub_val(*i as usize + base, vals, text),
                    some => get(some).unwrap_or(Val::Null),
                };
                ev.fields.push(Field {
                    name: Cow::Borrowed(name.as_str()),
                    value,
                });
            }
        }
        sink.event(&ev);
        spare = recycle(ev.fields);
    }
    true
}

fn sub_val<'x>(i: usize, vals: &[V], text: &'x str) -> Val<'x> {
    match vals.get(i).copied().unwrap_or(V::Null) {
        V::Null => Val::Null,
        V::Str(a, b) => Val::Str(Cow::Borrowed(&text[a..b])),
        V::Num(a, b) => Val::Num(Cow::Borrowed(&text[a..b])),
        V::Bool(b) => Val::Bool(b),
    }
}

fn get_val<'x>(src: &'x Option<Src>, vals: &[V], text: &'x str) -> Option<Val<'x>> {
    match src.as_ref()? {
        Src::Text(t) => Some(Val::Str(Cow::Borrowed(t.as_str()))),
        Src::Sub(i) => Some(sub_val(*i as usize, vals, text)),
    }
}

fn str_val<'x>(src: &'x Option<Src>, vals: &[V], text: &'x str) -> Cow<'x, str> {
    match get_val(src, vals, text) {
        Some(Val::Str(c)) | Some(Val::Num(c)) => c,
        Some(Val::Bool(b)) => Cow::Borrowed(if b { "true" } else { "false" }),
        _ => Cow::Borrowed(""),
    }
}

fn num_val(src: &Option<Src>, vals: &[V], text: &str) -> u64 {
    let v = str_val(src, vals, text);
    let v = v.trim();
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).unwrap_or(0),
        None => v.parse().unwrap_or(0),
    }
}

fn recycle<'b>(mut v: Vec<Field<'_>>) -> Vec<Field<'b>> {
    v.clear();
    v.into_iter().map(|_| unreachable!()).collect()
}
