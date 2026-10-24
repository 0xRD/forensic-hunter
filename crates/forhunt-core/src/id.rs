//! Stable event identifiers: `<file key>:<record id>`.
//!
//! The file key is the first 32 bits of a BLAKE3 fingerprint of the file's
//! size, header, first and last chunk. It survives copies and renames, it is
//! different for two hosts' `Security.evtx`, and it is computed without
//! reading the whole file (see docs/DECISIONS.md, D-005).

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FileKey(pub u32);

impl FileKey {
    /// Fingerprints `data` by sampling a few fixed regions.
    pub fn fingerprint(data: &[u8], sample: usize) -> FileKey {
        let n = data.len();
        let (head, tail) = Self::sample_ranges(n as u64, sample);
        let tail = tail.map(|(a, b)| &data[a as usize..b as usize]);
        Self::from_samples(n as u64, &data[head.0 as usize..head.1 as usize], tail)
    }

    /// Byte ranges sampled by [`FileKey::fingerprint`] for a file of `len` bytes.
    pub fn sample_ranges(len: u64, sample: usize) -> ((u64, u64), Option<(u64, u64)>) {
        let s = sample as u64;
        let head = (0, len.min(s));
        let tail = (len > s).then(|| (len.saturating_sub(s).max(s), len));
        (head, tail)
    }

    /// The key from pre-read samples (see [`FileKey::sample_ranges`]).
    pub fn from_samples(len: u64, head: &[u8], tail: Option<&[u8]>) -> FileKey {
        let mut h = blake3::Hasher::new();
        h.update(&len.to_le_bytes());
        h.update(head);
        if let Some(t) = tail {
            h.update(t);
        }
        let out = h.finalize();
        let b = out.as_bytes();
        FileKey(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Key from the whole content, for the rare file whose sampled key is
    /// already taken by a different file in the same run.
    pub fn of_file(path: &std::path::Path) -> std::io::Result<FileKey> {
        let mut h = blake3::Hasher::new();
        h.update(b"forhunt full-content key");
        h.update_reader(std::fs::File::open(path)?)?;
        let out = h.finalize();
        let b = out.as_bytes();
        Ok(FileKey(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
    }

    /// True when both files have identical content.
    pub fn same_content(a: &std::path::Path, b: &std::path::Path) -> std::io::Result<bool> {
        use std::io::Read;
        let (mut fa, mut fb) = (std::fs::File::open(a)?, std::fs::File::open(b)?);
        if fa.metadata()?.len() != fb.metadata()?.len() {
            return Ok(false);
        }
        let (mut ba, mut bb) = (vec![0u8; 1 << 16], vec![0u8; 1 << 16]);
        loop {
            let n = fa.read(&mut ba)?;
            if n == 0 {
                return Ok(true);
            }
            fb.read_exact(&mut bb[..n])?;
            if ba[..n] != bb[..n] {
                return Ok(false);
            }
        }
    }
}

impl fmt::Display for FileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EventRef {
    pub file: FileKey,
    pub record: u64,
}

impl fmt::Display for EventRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.record)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid event id `{0}` (expected <8 hex>:<record id>, e.g. a1b2c3d4:4821)")]
pub struct ParseEventRefError(String);

impl FromStr for EventRef {
    type Err = ParseEventRefError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseEventRefError(s.to_string());
        let (f, r) = s.trim().split_once(':').ok_or_else(err)?;
        if f.len() != 8 {
            return Err(err());
        }
        let file = u32::from_str_radix(f, 16).map_err(|_| err())?;
        let record = r.parse().map_err(|_| err())?;
        Ok(EventRef {
            file: FileKey(file),
            record,
        })
    }
}

impl EventRef {
    /// Writes the id without going through `fmt` (hot path).
    pub fn write(&self, out: &mut Vec<u8>) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let k = self.file.0;
        for i in (0..8).rev() {
            out.push(HEX[((k >> (i * 4)) & 0xf) as usize]);
        }
        out.push(b':');
        let mut b = itoa_buf();
        out.extend_from_slice(fmt_u64(&mut b, self.record));
    }
}

pub(crate) fn itoa_buf() -> [u8; 20] {
    [0u8; 20]
}

const DIGITS2: &[u8; 200] = b"0001020304050607080910111213141516171819\
2021222324252627282930313233343536373839\
4041424344454647484950515253545556575859\
6061626364656667686970717273747576777879\
8081828384858687888990919293949596979899";

/// Formats `v` in decimal into `buf`, returning the used tail.
pub fn fmt_u64(buf: &mut [u8; 20], mut v: u64) -> &[u8] {
    let mut i = buf.len();
    while v >= 100 {
        let d = (v % 100) as usize * 2;
        v /= 100;
        i -= 2;
        buf[i..i + 2].copy_from_slice(&DIGITS2[d..d + 2]);
    }
    if v >= 10 {
        let d = v as usize * 2;
        i -= 2;
        buf[i..i + 2].copy_from_slice(&DIGITS2[d..d + 2]);
    } else {
        i -= 1;
        buf[i] = b'0' + v as u8;
    }
    &buf[i..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_display() {
        let r: EventRef = "a1b2c3d4:4821".parse().unwrap();
        assert_eq!(r.to_string(), "a1b2c3d4:4821");
        let mut v = Vec::new();
        r.write(&mut v);
        assert_eq!(v, b"a1b2c3d4:4821");
        assert!("xyz:1".parse::<EventRef>().is_err());
        assert!("a1b2c3d4".parse::<EventRef>().is_err());
    }

    #[test]
    fn decimal() {
        let mut b = [0u8; 20];
        for v in [0u64, 7, 10, 99, 100, 101, 999, 1000, 4294967295, u64::MAX] {
            assert_eq!(fmt_u64(&mut b, v), v.to_string().as_bytes());
        }
    }

    #[test]
    fn fingerprint_differs() {
        let a = vec![1u8; 200_000];
        let mut b = a.clone();
        b[199_999] = 2;
        assert_ne!(
            FileKey::fingerprint(&a, 4096),
            FileKey::fingerprint(&b, 4096)
        );
        assert_eq!(
            FileKey::fingerprint(&a, 4096),
            FileKey::fingerprint(&a.clone(), 4096)
        );
    }
}
