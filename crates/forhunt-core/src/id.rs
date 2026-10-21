//! Stable event identifiers: `<file key>:<record id>`.
//!
//! The file key is the first 32 bits of a BLAKE3 fingerprint of the file's
//! size, header, first and last chunk. It survives copies and renames, it is
//! different for two hosts' `Security.evtx`, and it is computed without
//! reading the whole file (see DECISIONS.md, D-005).

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FileKey(pub u32);

impl FileKey {
    /// Fingerprints `data` by sampling a few fixed regions.
    pub fn fingerprint(data: &[u8], sample: usize) -> FileKey {
        let mut h = blake3::Hasher::new();
        h.update(&(data.len() as u64).to_le_bytes());
        let n = data.len();
        h.update(&data[..n.min(sample)]);
        if n > sample {
            let tail = n.saturating_sub(sample).max(sample);
            h.update(&data[tail..]);
        }
        let out = h.finalize();
        let b = out.as_bytes();
        FileKey(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
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

/// Formats `v` in decimal into `buf`, returning the used tail.
pub fn fmt_u64(buf: &mut [u8; 20], mut v: u64) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
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
