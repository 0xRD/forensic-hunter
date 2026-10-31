//! LZXPRESS Huffman decompression (MS-XCA 2.2.4), the compression of Windows
//! 8.1+ prefetch files. Written from the specification.
//!
//! The stream is a run of blocks, each producing 64 KiB of output (the last
//! one less): 256 bytes of packed code lengths, then bits read as 16-bit
//! little-endian words, with the long-match length bytes in between. Matches
//! may reach back into earlier blocks.

const BLOCK: usize = 64 * 1024;
const TABLE_BYTES: usize = 256;
const SYMBOLS: usize = 512;
const MAX_BITS: usize = 15;

/// Symbol and code length per 15-bit prefix (`len` 0: no such code).
#[derive(Clone, Copy, Default)]
struct Entry {
    sym: u16,
    len: u8,
}

/// Canonical code: shorter codes first, then lower symbols.
fn build(lengths: &[u8], table: &mut [Entry]) -> Result<(), &'static str> {
    let mut lens = [0u8; SYMBOLS];
    for (i, l) in lens.iter_mut().enumerate() {
        *l = (lengths[i / 2] >> (4 * (i & 1))) & 15;
    }
    table.fill(Entry::default());
    let mut next = 0usize;
    for bits in 1..=MAX_BITS {
        let span = 1usize << (MAX_BITS - bits);
        for (sym, _) in lens
            .iter()
            .enumerate()
            .filter(|(_, l)| **l as usize == bits)
        {
            let end = next + span;
            if end > table.len() {
                return Err("Huffman table is over-subscribed");
            }
            table[next..end].fill(Entry {
                sym: sym as u16,
                len: bits as u8,
            });
            next = end;
        }
    }
    if next == 0 {
        return Err("empty Huffman table");
    }
    Ok(())
}

struct Bits<'a> {
    src: &'a [u8],
    pos: usize,
    next: u32,
    extra: i32,
    /// Words read past the end: the buffer looks ahead, so the last symbols
    /// legitimately do this.
    past: i32,
}

impl Bits<'_> {
    fn word(&mut self) -> u32 {
        match self.src.get(self.pos..self.pos + 2) {
            Some(b) => {
                self.pos += 2;
                u16::from_le_bytes([b[0], b[1]]) as u32
            }
            None => {
                self.past += 1;
                0
            }
        }
    }

    fn start(&mut self) {
        let hi = self.word();
        self.next = (hi << 16) | self.word();
        self.extra = 16;
    }

    fn skip(&mut self, n: u32) {
        if n == 0 {
            return;
        }
        self.next <<= n;
        self.extra -= n as i32;
        if self.extra < 0 {
            self.next |= self.word() << -self.extra;
            self.extra += 16;
        }
    }

    /// True once consumed bits include invented ones.
    fn overrun(&self) -> bool {
        16 + self.extra < 16 * self.past
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.src.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn bytes<const N: usize>(&mut self) -> Option<[u8; N]> {
        let b = self.src.get(self.pos..self.pos + N)?;
        self.pos += N;
        b.try_into().ok()
    }

    /// Match length as stored: 4 bits, then 1, 2 or 2 + 4 bytes.
    fn length(&mut self, low: usize) -> Option<usize> {
        if low < 15 {
            return Some(low);
        }
        let b = self.byte()?;
        if b < 255 {
            return Some(b as usize + 15);
        }
        match u16::from_le_bytes(self.bytes()?) {
            0 => Some(u32::from_le_bytes(self.bytes()?) as usize),
            n => Some(n as usize),
        }
    }
}

/// Decompresses to at most `size` bytes. Returns what was decoded and, when
/// the stream stops early, why: the head of a damaged file is still evidence.
pub(crate) fn decompress(src: &[u8], size: usize) -> (Vec<u8>, Option<&'static str>) {
    let mut out = Vec::with_capacity(size);
    let mut table = vec![Entry::default(); 1 << MAX_BITS];
    let mut b = Bits {
        src,
        pos: 0,
        next: 0,
        extra: 0,
        past: 0,
    };
    while out.len() < size {
        let Some(lengths) = src.get(b.pos..b.pos + TABLE_BYTES) else {
            return (out, Some("compressed stream ends inside a block header"));
        };
        if let Err(e) = build(lengths, &mut table) {
            return (out, Some(e));
        }
        b.pos += TABLE_BYTES;
        b.start();
        let end = (out.len() + BLOCK).min(size);
        while out.len() < end {
            let e = table[(b.next >> (32 - MAX_BITS)) as usize];
            if e.len == 0 {
                return (out, Some("bit pattern outside the Huffman table"));
            }
            b.skip(e.len as u32);
            if b.overrun() {
                return (out, Some("compressed stream is truncated"));
            }
            if e.sym < 256 {
                out.push(e.sym as u8);
                continue;
            }
            let sym = e.sym as usize - 256;
            let log2 = (sym >> 4) as u32;
            let bits = if log2 == 0 { 0 } else { b.next >> (32 - log2) };
            let offset = bits as usize + (1usize << log2);
            // Length bytes sit before the word that refills these bits.
            let Some(len) = b.length(sym & 15) else {
                return (out, Some("compressed stream ends inside a match"));
            };
            b.skip(log2);
            if b.overrun() {
                return (out, Some("compressed stream is truncated"));
            }
            if offset > out.len() {
                return (out, Some("match before the start of the output"));
            }
            let len = (len + 3).min(size - out.len());
            // Byte by byte: a match may overlap its own output.
            let from = out.len() - offset;
            for i in from..from + len {
                out.push(out[i]);
            }
        }
    }
    (out, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every symbol 9 bits long (a complete code): the code is the symbol.
    fn table() -> Vec<u8> {
        vec![0x99; TABLE_BYTES]
    }

    /// Packs (value, width) pairs the way the format stores them; `raw`
    /// entries are bytes placed in the stream at the current word.
    #[derive(Default)]
    struct Enc {
        out: Vec<u8>,
        slot: usize,
        slot2: usize,
        cur: u32,
        n: u32,
    }

    impl Enc {
        fn new() -> Enc {
            let mut e = Enc::default();
            e.out.extend(table());
            e.slot = e.out.len();
            e.out.extend([0, 0]);
            e.slot2 = e.out.len();
            e.out.extend([0, 0]);
            e
        }
        fn put(&mut self, v: u32, w: u32) {
            for i in (0..w).rev() {
                self.cur = (self.cur << 1) | ((v >> i) & 1);
                self.n += 1;
                if self.n == 16 {
                    self.out[self.slot..self.slot + 2]
                        .copy_from_slice(&(self.cur as u16).to_le_bytes());
                    self.slot = self.slot2;
                    self.slot2 = self.out.len();
                    self.out.extend([0, 0]);
                    self.cur = 0;
                    self.n = 0;
                }
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.put(0, 16 - self.n);
            }
            self.out
        }
    }

    #[test]
    fn literals_and_overlapping_match() {
        let mut e = Enc::new();
        for b in b"abc" {
            e.put(*b as u32, 9);
        }
        // Match: length 5 + 3, offset 3 (log2 1, one extra bit set).
        e.put(256 + (1 << 4) + 5, 9);
        e.put(1, 1);
        let z = e.finish();
        let (out, err) = decompress(&z, 11);
        assert_eq!(err, None);
        assert_eq!(out, b"abcabcabcab");
    }

    #[test]
    fn long_match_length_bytes() {
        let mut e = Enc::new();
        e.put(b'x' as u32, 9);
        e.put(256 + 15, 9); // log2 0: offset 1; length in the next byte
        // Length byte: follows the words the decoder has read so far.
        e.out.push(5);
        let z = e.finish();
        let (out, err) = decompress(&z, 1 + 5 + 15 + 3);
        assert_eq!(err, None);
        assert_eq!(out, vec![b'x'; 24]);
    }

    #[test]
    fn damage_keeps_the_head_and_never_panics() {
        let mut e = Enc::new();
        for b in b"hello world" {
            e.put(*b as u32, 9);
        }
        let z = e.finish();
        let (out, err) = decompress(&z[..TABLE_BYTES + 8], 11);
        assert!(err.is_some());
        assert!(b"hello world".starts_with(&out[..]) && !out.is_empty());
        assert!(decompress(&z[..100], 11).1.is_some());
        assert!(decompress(&[0; 300], 11).1.is_some());
        assert!(decompress(&vec![0xFF; 400], 11).1.is_some());
        // A match before the start of the output.
        let mut e = Enc::new();
        e.put(256 + (5 << 4), 9);
        e.put(0, 5);
        assert!(decompress(&e.finish(), 8).1.is_some());
        // Random bit flips: an error or a result, not a panic.
        let mut x = 0x1234_5678u32;
        for _ in 0..2000 {
            let mut m = z.clone();
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let i = x as usize % m.len();
            m[i] ^= (x >> 24) as u8 | 1;
            let (o, _) = decompress(&m, 4096);
            assert!(o.len() <= 4096);
        }
    }
}
