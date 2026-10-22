//! Synthetic `$MFT` and `$UsnJrnl:$J` writer: FILE records with update
//! sequence fixups, $STANDARD_INFORMATION, $FILE_NAME and $DATA (resident or
//! not, named streams), and USN_RECORD_V2/V3 packed in 4 KiB pages after a
//! zero-filled head, like an extracted sparse journal.

use crate::events::Rng;

pub const RECORD: usize = 1024;
const ROOT: u64 = 5;

pub struct Node {
    pub entry: u64,
    pub seq: u16,
    pub parent: u64,
    pub name: String,
    pub dir: bool,
    pub in_use: bool,
    /// Created, modified, record changed, accessed.
    pub si: [u64; 4],
    pub fname: [u64; 4],
    pub size: u64,
    /// Resident content for small files (`None`: non-resident).
    pub content: Option<Vec<u8>>,
    pub attrs: u32,
    pub ads: Vec<(String, Vec<u8>)>,
}

pub struct Volume {
    pub nodes: Vec<Node>,
    pub records: u64,
}

impl Volume {
    // Entry numbers are indices into `nodes`.
    pub fn seq_of(&self, entry: u64) -> u16 {
        self.nodes.get(entry as usize).map(|n| n.seq).unwrap_or(1)
    }

    pub fn next_entry(&self) -> u64 {
        self.nodes.len() as u64
    }

    /// Adds a node under `parent` and returns its entry number.
    pub fn add(&mut self, parent: u64, name: &str, dir: bool, t: [u64; 4]) -> u64 {
        let entry = self.next_entry();
        self.nodes.push(Node {
            entry,
            seq: 1 + (entry % 3) as u16,
            parent,
            name: name.into(),
            dir,
            in_use: true,
            si: t,
            fname: [t[0], t[0], t[0], t[0]],
            size: 0,
            content: None,
            attrs: if dir { 0x10 } else { 0x20 },
            ads: Vec::new(),
        });
        entry
    }

    pub fn node(&mut self, entry: u64) -> &mut Node {
        &mut self.nodes[entry as usize]
    }

    /// The standard metadata files (entries 0-11) and the root directory.
    pub fn new(t: u64) -> Volume {
        let mut v = Volume {
            nodes: Vec::new(),
            records: 0,
        };
        for (i, name) in [
            "$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", ".", "$Bitmap", "$Boot",
            "$BadClus", "$Secure", "$UpCase", "$Extend",
        ]
        .iter()
        .enumerate()
        {
            let dir = i == 5 || i == 11;
            v.nodes.push(Node {
                entry: i as u64,
                seq: if i == 5 { 5 } else { i as u16 + 1 },
                parent: ROOT,
                name: (*name).into(),
                dir,
                in_use: true,
                si: [t; 4],
                fname: [t; 4],
                size: if dir { 0 } else { 65536 },
                content: None,
                attrs: 0x06,
                ads: Vec::new(),
            });
        }
        // Entries 12-15 are reserved; user files start at 16.
        for e in 12..16 {
            v.nodes.push(Node {
                entry: e,
                seq: 1,
                parent: ROOT,
                name: format!("$Reserved{e}"),
                dir: false,
                in_use: false,
                si: [0; 4],
                fname: [0; 4],
                size: 0,
                content: None,
                attrs: 0,
                ads: Vec::new(),
            });
        }
        v
    }

    pub fn mft_bytes(&self) -> Vec<u8> {
        let n = self.records.max(self.next_entry()) as usize;
        let mut out = vec![0u8; n * RECORD];
        for node in &self.nodes {
            if node.si == [0; 4] {
                continue; // never-used slot
            }
            let rec = record(node, self);
            let o = node.entry as usize * RECORD;
            out[o..o + RECORD].copy_from_slice(&rec);
        }
        // Record 0 describes the table itself.
        let size = out.len() as u64;
        let mut n0 = record(&self.nodes[0], self);
        set_data_size(&mut n0, size);
        out[..RECORD].copy_from_slice(&n0);
        out
    }
}

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn pad8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

/// A resident attribute: 24-byte header, optional name, then content.
fn resident(ty: u32, id: u16, name: &str, content: &[u8], indexed: bool) -> Vec<u8> {
    let nm = utf16(name);
    let coff = pad8(0x18 + nm.len());
    let mut a = vec![0u8; pad8(coff + content.len())];
    put32(&mut a, 0, ty);
    let len = a.len() as u32;
    put32(&mut a, 4, len);
    a[9] = (nm.len() / 2) as u8;
    put16(&mut a, 10, 0x18);
    put16(&mut a, 14, id);
    put32(&mut a, 0x10, content.len() as u32);
    put16(&mut a, 0x14, coff as u16);
    a[0x16] = indexed as u8;
    a[0x18..0x18 + nm.len()].copy_from_slice(&nm);
    a[coff..coff + content.len()].copy_from_slice(content);
    a
}

/// A non-resident unnamed $DATA with an empty run list.
fn nonresident_data(id: u16, size: u64) -> Vec<u8> {
    let mut a = vec![0u8; 0x48];
    put32(&mut a, 0, 0x80);
    put32(&mut a, 4, 0x48);
    a[8] = 1;
    put16(&mut a, 10, 0x40);
    put16(&mut a, 14, id);
    put64(&mut a, 0x18, size.div_ceil(4096).saturating_sub(1));
    put16(&mut a, 0x20, 0x40);
    put64(&mut a, 0x28, size.div_ceil(4096) * 4096);
    put64(&mut a, 0x30, size);
    put64(&mut a, 0x38, size);
    a
}

fn set_data_size(rec: &mut [u8], size: u64) {
    // Undo fixups, patch the $DATA real size, redo fixups.
    unfix(rec);
    let mut off = 0x38;
    while off + 8 < RECORD {
        let ty = u32::from_le_bytes(rec[off..off + 4].try_into().unwrap());
        let len = u32::from_le_bytes(rec[off + 4..off + 8].try_into().unwrap()) as usize;
        if ty == 0xFFFF_FFFF || len == 0 {
            break;
        }
        if ty == 0x80 && rec[off + 8] == 1 {
            put64(rec, off + 0x30, size);
            put64(rec, off + 0x38, size);
        }
        off += len;
    }
    fixup(rec);
}

fn record(n: &Node, v: &Volume) -> Vec<u8> {
    let mut r = vec![0u8; RECORD];
    r[..4].copy_from_slice(b"FILE");
    put16(&mut r, 4, 0x30); // update sequence array offset
    put16(&mut r, 6, 3); // usn + one entry per 512-byte sector
    put64(&mut r, 8, 0x1_0000 + n.entry * 37); // $LogFile sequence number
    put16(&mut r, 0x10, n.seq);
    put16(&mut r, 0x12, 1);
    put16(&mut r, 0x14, 0x38);
    put16(&mut r, 0x16, (n.in_use as u16) | ((n.dir as u16) << 1));
    put32(&mut r, 0x1C, RECORD as u32);
    put32(&mut r, 0x2C, n.entry as u32);
    let mut attrs = Vec::new();
    let mut si = vec![0u8; 72];
    for (k, t) in n.si.iter().enumerate() {
        put64(&mut si, k * 8, *t);
    }
    put32(&mut si, 32, n.attrs);
    put64(&mut si, 64, n.entry * 1000); // $UsnJrnl USN
    attrs.push(resident(0x10, 0, "", &si, false));
    let name = utf16(&n.name);
    let mut f = vec![0u8; 66 + name.len()];
    let pseq = v.seq_of(n.parent);
    put64(&mut f, 0, n.parent | ((pseq as u64) << 48));
    for (k, t) in n.fname.iter().enumerate() {
        put64(&mut f, 8 + k * 8, *t);
    }
    put64(&mut f, 40, n.size.div_ceil(4096) * 4096);
    put64(&mut f, 48, n.size);
    put32(&mut f, 56, if n.dir { 0x1000_0000 } else { n.attrs });
    f[64] = (name.len() / 2) as u8;
    f[65] = 3; // Win32 and DOS namespace
    f[66..].copy_from_slice(&name);
    attrs.push(resident(0x30, 1, "", &f, true));
    if !n.dir {
        match &n.content {
            Some(c) => attrs.push(resident(0x80, 2, "", c, false)),
            None => attrs.push(nonresident_data(2, n.size)),
        }
        for (i, (an, ac)) in n.ads.iter().enumerate() {
            attrs.push(resident(0x80, 3 + i as u16, an, ac, false));
        }
    }
    let mut off = 0x38;
    for a in &attrs {
        r[off..off + a.len()].copy_from_slice(a);
        off += a.len();
    }
    put32(&mut r, off, 0xFFFF_FFFF);
    put32(&mut r, 0x18, (off + 8) as u32);
    put16(&mut r, 0x28, attrs.len() as u16);
    fixup(&mut r);
    r
}

const USN: u16 = 0x0001;

fn fixup(r: &mut [u8]) {
    put16(r, 0x30, USN);
    for i in 0..2 {
        let end = (i + 1) * 512 - 2;
        let (a, b) = (r[end], r[end + 1]);
        r[0x32 + i * 2] = a;
        r[0x33 + i * 2] = b;
        put16(r, end, USN);
    }
}

fn unfix(r: &mut [u8]) {
    for i in 0..2 {
        let end = (i + 1) * 512 - 2;
        r[end] = r[0x32 + i * 2];
        r[end + 1] = r[0x33 + i * 2];
    }
}

/// USN reason flags used by the scenario.
pub mod reason {
    pub const DATA_EXTEND: u32 = 0x2;
    pub const NAMED_DATA_EXTEND: u32 = 0x20;
    pub const CREATE: u32 = 0x100;
    pub const DELETE: u32 = 0x200;
    pub const RENAME_OLD: u32 = 0x1000;
    pub const RENAME_NEW: u32 = 0x2000;
    pub const BASIC_INFO: u32 = 0x8000;
    pub const CLOSE: u32 = 0x8000_0000;
}

pub struct UsnRec {
    pub entry: u64,
    pub seq: u16,
    pub parent: u64,
    pub parent_seq: u16,
    pub ts: u64,
    pub reason: u32,
    pub attrs: u32,
    pub name: String,
    pub v3: bool,
}

/// Journal bytes: `head` zero bytes (the sparse, already-overwritten part),
/// then records in 4 KiB pages, zero-padded at page ends. USNs are file
/// offsets.
pub fn journal(head: usize, recs: &[UsnRec]) -> Vec<u8> {
    let mut out = vec![0u8; head];
    for r in recs {
        let name = utf16(&r.name);
        let base = if r.v3 { 76 } else { 60 };
        let len = pad8(base + name.len());
        let page_left = 4096 - out.len() % 4096;
        if len > page_left {
            out.resize(out.len() + page_left, 0);
        }
        let usn = out.len() as u64;
        let mut b = vec![0u8; len];
        put32(&mut b, 0, len as u32);
        let fref = r.entry | ((r.seq as u64) << 48);
        let pref = r.parent | ((r.parent_seq as u64) << 48);
        let o = if r.v3 {
            put16(&mut b, 4, 3);
            put64(&mut b, 8, fref);
            put64(&mut b, 24, pref);
            40
        } else {
            put16(&mut b, 4, 2);
            put64(&mut b, 8, fref);
            put64(&mut b, 16, pref);
            24
        };
        put64(&mut b, o, usn);
        put64(&mut b, o + 8, r.ts);
        put32(&mut b, o + 16, r.reason);
        put32(&mut b, o + 28, r.attrs);
        put16(&mut b, o + 32, name.len() as u16);
        put16(&mut b, o + 34, base as u16);
        b[base..base + name.len()].copy_from_slice(&name);
        out.extend_from_slice(&b);
    }
    let pad = (4096 - out.len() % 4096) % 4096;
    out.resize(out.len() + pad, 0);
    out
}

/// Background noise: `n` records of temporary-file churn (create, write,
/// close, delete) in the given directories, starting at `t0`.
pub fn churn(v: &Volume, dirs: &[u64], n: usize, t0: u64, rng: &mut Rng) -> Vec<UsnRec> {
    use reason::*;
    let mut out = Vec::with_capacity(n);
    let mut t = t0;
    let mut entry = v.next_entry() + 5000;
    while out.len() < n {
        let parent = *rng.pick(dirs);
        let parent_seq = v.seq_of(parent);
        let name = format!("tmp{:04X}.tmp", rng.below(0x10000));
        entry += 1;
        for r in [
            CREATE,
            CREATE | DATA_EXTEND,
            CREATE | DATA_EXTEND | CLOSE,
            DELETE | CLOSE,
        ] {
            t += 1 + rng.below(30_000_000);
            out.push(UsnRec {
                entry,
                seq: 2,
                parent,
                parent_seq,
                ts: t,
                reason: r,
                attrs: 0x120,
                name: name.clone(),
                v3: false,
            });
        }
    }
    out.truncate(n);
    out
}
