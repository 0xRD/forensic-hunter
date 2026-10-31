//! Synthetic registry hive writer: one hive bin of `nk`, `vk`, `lf` and data
//! cells behind a base block, and new-format (`HvLE`) transaction logs.

pub const REG_SZ: u32 = 1;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;

const BINS: usize = 4096;

pub struct Key {
    pub name: String,
    pub time: u64,
    pub values: Vec<(String, u32, Vec<u8>)>,
    pub subs: Vec<Key>,
}

fn wide(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

impl Key {
    pub fn new(name: &str, time: u64) -> Key {
        Key {
            name: name.to_string(),
            time,
            values: Vec::new(),
            subs: Vec::new(),
        }
    }
    pub fn sz(mut self, name: &str, v: &str) -> Key {
        self.values.push((name.to_string(), REG_SZ, wide(v)));
        self
    }
    pub fn dword(mut self, name: &str, v: u32) -> Key {
        self.values
            .push((name.to_string(), REG_DWORD, v.to_le_bytes().to_vec()));
        self
    }
    pub fn bin(mut self, name: &str, v: Vec<u8>) -> Key {
        self.values.push((name.to_string(), REG_BINARY, v));
        self
    }
    /// A value whose type field holds `kind` (SAM stores RIDs that way).
    pub fn typed(mut self, name: &str, kind: u32) -> Key {
        self.values.push((name.to_string(), kind, Vec::new()));
        self
    }
    pub fn sub(mut self, k: Key) -> Key {
        self.subs.push(k);
        self
    }
    /// A chain of nested keys ending in `leaf`.
    pub fn path(self, parts: &[&str], leaf: Key) -> Key {
        let time = leaf.time;
        let inner = parts
            .iter()
            .rev()
            .fold(leaf, |k, p| Key::new(p, time).sub(k));
        self.sub(inner)
    }
}

/// Cells after the 32-byte hive bin header; offsets count from the bin.
struct Bin(Vec<u8>);

impl Bin {
    fn cell(&mut self, body: &[u8]) -> u32 {
        let off = self.0.len() as u32 + 32;
        let size = (body.len() + 4).next_multiple_of(8);
        self.0.extend((-(size as i32)).to_le_bytes());
        self.0.extend(body);
        self.0.resize(self.0.len() + size - body.len() - 4, 0);
        off
    }

    fn key(&mut self, k: &Key, parent: u32) -> u32 {
        let subs: Vec<u32> = k.subs.iter().map(|s| self.key(s, 0)).collect();
        let list = if subs.is_empty() {
            u32::MAX
        } else {
            let mut l = b"lf".to_vec();
            l.extend((subs.len() as u16).to_le_bytes());
            for s in &subs {
                l.extend(s.to_le_bytes());
                l.extend([0; 4]);
            }
            self.cell(&l)
        };
        let vals: Vec<u32> = k.values.iter().map(|v| self.value(v)).collect();
        let vlist = if vals.is_empty() {
            u32::MAX
        } else {
            let b: Vec<u8> = vals.iter().flat_map(|v| v.to_le_bytes()).collect();
            self.cell(&b)
        };
        let mut nk = vec![0u8; 76];
        nk[..2].copy_from_slice(b"nk");
        nk[2..4].copy_from_slice(&0x20u16.to_le_bytes());
        nk[4..12].copy_from_slice(&k.time.to_le_bytes());
        nk[16..20].copy_from_slice(&parent.to_le_bytes());
        nk[20..24].copy_from_slice(&(subs.len() as u32).to_le_bytes());
        nk[28..32].copy_from_slice(&list.to_le_bytes());
        nk[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        nk[36..40].copy_from_slice(&(vals.len() as u32).to_le_bytes());
        nk[40..44].copy_from_slice(&vlist.to_le_bytes());
        nk[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
        nk[48..52].copy_from_slice(&u32::MAX.to_le_bytes());
        nk[72..74].copy_from_slice(&(k.name.len() as u16).to_le_bytes());
        nk.extend(k.name.as_bytes());
        self.cell(&nk)
    }

    fn value(&mut self, (name, kind, data): &(String, u32, Vec<u8>)) -> u32 {
        let mut vk = vec![0u8; 20];
        vk[..2].copy_from_slice(b"vk");
        vk[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
        vk[12..16].copy_from_slice(&kind.to_le_bytes());
        vk[16..18].copy_from_slice(&1u16.to_le_bytes());
        if data.len() <= 4 {
            let mut inline = [0u8; 4];
            inline[..data.len()].copy_from_slice(data);
            vk[4..8].copy_from_slice(&(data.len() as u32 | 0x8000_0000).to_le_bytes());
            vk[8..12].copy_from_slice(&inline);
        } else {
            let off = self.cell(data);
            vk[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
            vk[8..12].copy_from_slice(&off.to_le_bytes());
        }
        vk.extend(name.as_bytes());
        self.cell(&vk)
    }
}

/// A clean hive: both sequence numbers are `seq`.
pub fn hive(root: &Key, stored: &str, seq: u32) -> Vec<u8> {
    let mut b = Bin(Vec::new());
    let root_off = b.key(root, 0);
    let bin_size = (b.0.len() + 32 + 8).next_multiple_of(BINS);
    let mut out = vec![0u8; BINS + bin_size];
    out[..4].copy_from_slice(b"regf");
    out[4..8].copy_from_slice(&seq.to_le_bytes());
    out[8..12].copy_from_slice(&seq.to_le_bytes());
    out[12..20].copy_from_slice(&root.time.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[24..28].copy_from_slice(&5u32.to_le_bytes());
    out[32..36].copy_from_slice(&1u32.to_le_bytes());
    out[36..40].copy_from_slice(&root_off.to_le_bytes());
    out[40..44].copy_from_slice(&(bin_size as u32).to_le_bytes());
    out[44..48].copy_from_slice(&1u32.to_le_bytes());
    let name: Vec<u8> = stored.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out[48..48 + name.len()].copy_from_slice(&name);
    let sum = (0..508).step_by(4).fold(0u32, |x, i| {
        x ^ u32::from_le_bytes([out[i], out[i + 1], out[i + 2], out[i + 3]])
    });
    out[508..512].copy_from_slice(&sum.to_le_bytes());
    let b0 = BINS;
    out[b0..b0 + 4].copy_from_slice(b"hbin");
    out[b0 + 8..b0 + 12].copy_from_slice(&(bin_size as u32).to_le_bytes());
    out[b0 + 32..b0 + 32 + b.0.len()].copy_from_slice(&b.0);
    let tail = (bin_size - 32 - b.0.len()) as i32;
    let at = b0 + 32 + b.0.len();
    out[at..at + 4].copy_from_slice(&tail.to_le_bytes());
    out
}

fn marvin_block(a: &mut u32, b: &mut u32) {
    *b ^= *a;
    *a = a.rotate_left(20).wrapping_add(*b);
    *b = b.rotate_left(9) ^ *a;
    *a = a.rotate_left(27).wrapping_add(*b);
    *b = b.rotate_left(19);
}

fn marvin(d: &[u8]) -> u64 {
    const SEED: u64 = 0x82EF_4D88_7A4E_55C5;
    let (mut a, mut b) = (SEED as u32, (SEED >> 32) as u32);
    let whole = d.len() & !3;
    let tail = &d[whole..];
    for i in (0..whole).step_by(4) {
        a = a.wrapping_add(u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]));
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

/// One log entry holding the pages of `new` that differ from `old`.
fn entry(old: &[u8], new: &[u8], seq: u32) -> Vec<u8> {
    let pages: Vec<usize> = (0..(new.len() - BINS) / BINS)
        .filter(|i| {
            let r = BINS + i * BINS..BINS + (i + 1) * BINS;
            old.get(r.clone()) != Some(&new[r])
        })
        .collect();
    let mut e = vec![0u8; 40];
    e[..4].copy_from_slice(b"HvLE");
    e[12..16].copy_from_slice(&seq.to_le_bytes());
    e[16..20].copy_from_slice(&((new.len() - BINS) as u32).to_le_bytes());
    e[20..24].copy_from_slice(&(pages.len() as u32).to_le_bytes());
    for p in &pages {
        e.extend(((p * BINS) as u32).to_le_bytes());
        e.extend((BINS as u32).to_le_bytes());
    }
    for p in &pages {
        e.extend(&new[BINS + p * BINS..BINS + (p + 1) * BINS]);
    }
    e.resize(e.len().next_multiple_of(512), 0);
    let size = e.len() as u32;
    e[4..8].copy_from_slice(&size.to_le_bytes());
    let h1 = marvin(&e[40..]);
    e[24..32].copy_from_slice(&h1.to_le_bytes());
    let h2 = marvin(&e[..32]);
    e[32..40].copy_from_slice(&h2.to_le_bytes());
    e
}

/// Dirties `old` and returns the log that brings it to `new`, with a stale
/// entry of an earlier cycle behind the last commit, as real logs have.
pub fn dirty(old: &mut [u8], new: &[u8], seq: u32) -> Vec<u8> {
    old[4..8].copy_from_slice(&(seq - 1).to_le_bytes());
    old[8..12].copy_from_slice(&(seq - 2).to_le_bytes());
    let mut log = new[..512].to_vec();
    log[4..8].copy_from_slice(&seq.to_le_bytes());
    log[8..12].copy_from_slice(&seq.to_le_bytes());
    log[0x1C..0x20].copy_from_slice(&6u32.to_le_bytes());
    log.extend(entry(old, new, seq));
    log.extend(entry(new, old, seq - 40));
    log
}
