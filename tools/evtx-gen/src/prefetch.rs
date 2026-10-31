//! Synthetic prefetch writer: the SCCA layouts of formats 17 to 31, plain or
//! `MAM`-compressed. The compressor only writes literals with a flat 9-bit
//! code, which is valid LZXPRESS Huffman; matches are covered by the
//! decoder's unit tests.

pub struct Pf<'a> {
    pub version: u32,
    /// Offset of the metrics array: fixes the layout of the block before it.
    pub first: usize,
    pub exe: &'a str,
    pub hash: u32,
    pub run_count: u32,
    pub runs: &'a [u64],
    pub files: Vec<String>,
    pub dirs: Vec<String>,
    pub volume: &'a str,
    pub serial: u32,
    pub created: u64,
}

fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

fn wide(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

impl Pf<'_> {
    pub fn body(&self) -> Vec<u8> {
        // Run times and run count in the file information block at 84.
        let (times, count, metric, entry) = match (self.version, self.first) {
            (17, _) => (36, 60, 20, 40),
            (23, _) => (44, 68, 32, 104),
            (26, _) => (44, 124, 32, 104),
            (_, 296) => (44, 116, 32, 96),
            _ => (44, 124, 32, 96),
        };
        let mut names = Vec::new();
        let mut spans = Vec::new();
        for f in &self.files {
            spans.push((names.len(), f.encode_utf16().count()));
            names.extend(wide(f));
            names.extend([0, 0]);
        }
        let strings = self.first + self.files.len() * metric;
        let volumes = strings + names.len().next_multiple_of(4);
        let path = wide(self.volume);
        let path_off = entry;
        let dirs_off = path_off + path.len() + 2;
        let mut dir_blob = Vec::new();
        for d in &self.dirs {
            dir_blob.extend((d.encode_utf16().count() as u16).to_le_bytes());
            dir_blob.extend(wide(d));
            dir_blob.extend([0, 0]);
        }
        let vsize = dirs_off + dir_blob.len();
        let mut b = vec![0u8; volumes + vsize];
        put32(&mut b, 0, self.version);
        b[4..8].copy_from_slice(b"SCCA");
        put32(&mut b, 8, 0x11);
        let len = b.len() as u32;
        put32(&mut b, 12, len);
        let name = wide(self.exe);
        b[16..16 + name.len()].copy_from_slice(&name);
        put32(&mut b, 76, self.hash);
        put32(&mut b, 84, self.first as u32);
        put32(&mut b, 88, self.files.len() as u32);
        put32(&mut b, 100, strings as u32);
        put32(&mut b, 104, names.len() as u32);
        put32(&mut b, 108, volumes as u32);
        put32(&mut b, 112, 1);
        put32(&mut b, 116, vsize as u32);
        for (i, t) in self.runs.iter().enumerate() {
            put64(&mut b, 84 + times + i * 8, *t);
        }
        put32(&mut b, 84 + count, self.run_count);
        for (i, (off, chars)) in spans.iter().enumerate() {
            let m = self.first + i * metric;
            let at = if metric == 20 { m + 8 } else { m + 12 };
            put32(&mut b, at, *off as u32);
            put32(&mut b, at + 4, *chars as u32);
        }
        b[strings..strings + names.len()].copy_from_slice(&names);
        let v = volumes;
        put32(&mut b, v, path_off as u32);
        put32(&mut b, v + 4, path.len() as u32 / 2);
        put64(&mut b, v + 8, self.created);
        put32(&mut b, v + 16, self.serial);
        put32(&mut b, v + 28, dirs_off as u32);
        put32(&mut b, v + 32, self.dirs.len() as u32);
        b[v + path_off..v + path_off + path.len()].copy_from_slice(&path);
        b[v + dirs_off..v + dirs_off + dir_blob.len()].copy_from_slice(&dir_blob);
        b
    }
}

/// One block: the code table, then 9-bit literals in 16-bit words.
fn block(data: &[u8], out: &mut Vec<u8>) {
    out.extend([0x99; 256]);
    let mut words: Vec<u16> = Vec::new();
    let (mut cur, mut n) = (0u32, 0u32);
    for &byte in data {
        cur = (cur << 9) | byte as u32;
        n += 9;
        if n >= 16 {
            n -= 16;
            words.push((cur >> n) as u16);
            cur &= (1 << n) - 1;
        }
    }
    if n > 0 {
        words.push((cur << (16 - n)) as u16);
    }
    // The decoder holds one word more than it has consumed.
    words.push(0);
    out.extend(words.iter().flat_map(|w| w.to_le_bytes()));
}

/// `MAM` container; with `crc` the header carries the 4-byte checksum slot.
pub fn compress(body: &[u8], crc: bool) -> Vec<u8> {
    let mut out = b"MAM".to_vec();
    out.push(if crc { 0x84 } else { 0x04 });
    out.extend((body.len() as u32).to_le_bytes());
    if crc {
        out.extend([0; 4]);
    }
    for c in body.chunks(64 * 1024) {
        block(c, &mut out);
    }
    out
}
