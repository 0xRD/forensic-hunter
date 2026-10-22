//! FILE record parsing shared by the `$MFT` source and the directory path
//! table: update sequence fixups, then a single walk over the attributes
//! that keeps what the timeline needs ($STANDARD_INFORMATION, the best
//! $FILE_NAME, the unnamed $DATA size, alternate data streams and a resident
//! Zone.Identifier). Every read is bounds-checked; damaged records are
//! reported, never trusted.

use crate::time::Ts;

/// FILETIME ticks between 1601-01-01 and 1970-01-01.
const EPOCH_TICKS: i64 = 116_444_736_000_000_000;
/// FILETIME values above this (year 2500) are garbage.
const MAX_FILETIME: u64 = 0x0350_0000_0000_0000;

pub(crate) const FLAG_IN_USE: u16 = 0x0001;
pub(crate) const FLAG_DIRECTORY: u16 = 0x0002;

pub(crate) fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
pub(crate) fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
pub(crate) fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

/// A FILETIME as a timestamp; `None` for 0 and out-of-range values.
pub(crate) fn filetime(v: u64) -> Option<Ts> {
    (v != 0 && v < MAX_FILETIME).then(|| Ts(v as i64 - EPOCH_TICKS))
}

/// File reference: 48-bit entry number and 16-bit sequence number.
pub(crate) fn split_ref(r: u64) -> (u64, u16) {
    (r & 0x0000_FFFF_FFFF_FFFF, (r >> 48) as u16)
}

/// Appends UTF-16LE text, replacing unpaired surrogates.
pub(crate) fn push_utf16(out: &mut Vec<u8>, b: &[u8]) {
    if b.chunks_exact(2).all(|c| c[1] == 0 && c[0] < 0x80) {
        out.extend(b.chunks_exact(2).map(|c| c[0]));
        return;
    }
    let units = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]));
    let mut tmp = [0u8; 4];
    for ch in char::decode_utf16(units) {
        let ch = ch.unwrap_or(char::REPLACEMENT_CHARACTER);
        out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
    }
}

/// Created, modified, record changed, accessed (the order NTFS stores them).
pub(crate) type Times = [u64; 4];

pub(crate) struct StdInfo {
    pub times: Times,
    pub flags: u32,
    /// Present in NTFS 3.0+ records (72-byte attribute).
    pub usn: Option<u64>,
}

pub(crate) struct FileName<'a> {
    pub parent: u64,
    pub times: Times,
    /// UTF-16LE.
    pub name: &'a [u8],
}

pub(crate) struct FileRecord<'a> {
    pub seq: u16,
    pub flags: u16,
    pub lsn: u64,
    /// Non-zero for extension records (attributes of another entry).
    pub base: u64,
    pub si: Option<StdInfo>,
    pub name: Option<FileName<'a>>,
    /// Size of the unnamed $DATA stream.
    pub size: Option<u64>,
    /// Names (UTF-16LE) of named $DATA streams.
    pub ads: Vec<&'a [u8]>,
    /// Resident content of the `Zone.Identifier` stream.
    pub zone: Option<&'a [u8]>,
}

pub(crate) enum Parsed<'a> {
    /// Never-used slot (zeros).
    Empty,
    Bad(&'static str),
    Ok(FileRecord<'a>),
}

/// Applies the update sequence array in place: the last two bytes of each
/// sector were replaced on disk by the update sequence number.
pub(crate) fn fixup(rec: &mut [u8]) -> Result<(), &'static str> {
    let off = u16_at(rec, 4).ok_or("short record")? as usize;
    let count = u16_at(rec, 6).ok_or("short record")? as usize;
    if count < 2 || off + count * 2 > rec.len() {
        return Err("bad update sequence array");
    }
    let sectors = count - 1;
    if rec.len() % sectors != 0 || rec.len() / sectors < 512 {
        return Err("bad update sequence array");
    }
    let stride = rec.len() / sectors;
    let usn = [rec[off], rec[off + 1]];
    for i in 0..sectors {
        let end = (i + 1) * stride - 2;
        if rec[end..end + 2] != usn {
            return Err("fixup mismatch (torn write)");
        }
        let src = off + 2 + i * 2;
        rec[end] = rec[src];
        rec[end + 1] = rec[src + 1];
    }
    Ok(())
}

/// Namespace preference for the displayed name: Win32 (or Win32 and DOS)
/// over POSIX over the 8.3 DOS alias.
fn namespace_rank(ns: u8) -> u8 {
    match ns {
        1 | 3 => 3,
        0 => 2,
        _ => 1,
    }
}

/// Parses a record whose fixups were applied (see [`fixup`]).
pub(crate) fn parse(rec: &[u8]) -> Parsed<'_> {
    match rec.get(..4) {
        Some(b"FILE") => {}
        Some(b"BAAD") => return Parsed::Bad("record marked BAAD"),
        Some([0, 0, 0, 0]) => return Parsed::Empty,
        _ => return Parsed::Bad("bad record signature"),
    }
    let (Some(first), Some(flags), Some(used), Some(seq), Some(lsn), Some(base)) = (
        u16_at(rec, 0x14),
        u16_at(rec, 0x16),
        u32_at(rec, 0x18),
        u16_at(rec, 0x10),
        u64_at(rec, 0x08),
        u64_at(rec, 0x20),
    ) else {
        return Parsed::Bad("short record");
    };
    let end = (used as usize).min(rec.len());
    let mut r = FileRecord {
        seq,
        flags,
        lsn,
        base,
        si: None,
        name: None,
        size: None,
        ads: Vec::new(),
        zone: None,
    };
    let mut best_rank = 0u8;
    let mut off = first as usize;
    while off + 16 <= end {
        let Some(ty) = u32_at(rec, off) else { break };
        if ty == 0xFFFF_FFFF {
            break;
        }
        let Some(len) = u32_at(rec, off + 4).map(|l| l as usize) else {
            break;
        };
        if len < 16 || off + len > end {
            return Parsed::Bad("bad attribute length");
        }
        let a = &rec[off..off + len];
        off += len;
        let nonresident = a[8] != 0;
        let name_len = a[9] as usize * 2;
        let name = u16_at(a, 10)
            .and_then(|o| a.get(o as usize..o as usize + name_len))
            .unwrap_or(&[]);
        let content = if nonresident {
            None
        } else {
            let (Some(n), Some(o)) = (u32_at(a, 0x10), u16_at(a, 0x14)) else {
                continue;
            };
            a.get(o as usize..o as usize + n as usize)
        };
        match ty {
            0x10 => {
                if let Some(c) = content
                    && let (Some(c0), Some(c1), Some(c2), Some(c3), Some(fl)) = (
                        u64_at(c, 0),
                        u64_at(c, 8),
                        u64_at(c, 16),
                        u64_at(c, 24),
                        u32_at(c, 32),
                    )
                {
                    r.si = Some(StdInfo {
                        times: [c0, c1, c2, c3],
                        flags: fl,
                        usn: u64_at(c, 64),
                    });
                }
            }
            0x30 => {
                let Some(c) = content else { continue };
                let (Some(parent), Some(t0), Some(t1), Some(t2), Some(t3)) = (
                    u64_at(c, 0),
                    u64_at(c, 8),
                    u64_at(c, 16),
                    u64_at(c, 24),
                    u64_at(c, 32),
                ) else {
                    continue;
                };
                let (Some(&n), Some(&ns)) = (c.get(64), c.get(65)) else {
                    continue;
                };
                let Some(fname) = c.get(66..66 + n as usize * 2) else {
                    continue;
                };
                let rank = namespace_rank(ns);
                if rank > best_rank {
                    best_rank = rank;
                    r.name = Some(FileName {
                        parent,
                        times: [t0, t1, t2, t3],
                        name: fname,
                    });
                }
            }
            0x80 => {
                if name.is_empty() {
                    r.size = if nonresident {
                        u64_at(a, 0x30)
                    } else {
                        content.map(|c| c.len() as u64)
                    };
                } else {
                    if name == ZONE_IDENTIFIER {
                        r.zone = content;
                    }
                    r.ads.push(name);
                }
            }
            _ => {}
        }
    }
    Parsed::Ok(r)
}

/// `Zone.Identifier` in UTF-16LE.
const ZONE_IDENTIFIER: &[u8] = b"Z\0o\0n\0e\0.\0I\0d\0e\0n\0t\0i\0f\0i\0e\0r\0";

/// Windows file attribute names (FILE_ATTRIBUTE_*), lowest bit first.
const ATTRS: &[(u32, &str)] = &[
    (0x1, "ReadOnly"),
    (0x2, "Hidden"),
    (0x4, "System"),
    (0x10, "Directory"),
    (0x20, "Archive"),
    (0x40, "Device"),
    (0x80, "Normal"),
    (0x100, "Temporary"),
    (0x200, "SparseFile"),
    (0x400, "ReparsePoint"),
    (0x800, "Compressed"),
    (0x1000, "Offline"),
    (0x2000, "NotContentIndexed"),
    (0x4000, "Encrypted"),
    (0x8000, "IntegrityStream"),
    (0x10000, "Virtual"),
    (0x20000, "NoScrubData"),
    (0x40000, "RecallOnOpen"),
    (0x80000, "Pinned"),
    (0x100000, "Unpinned"),
    (0x400000, "RecallOnDataAccess"),
    (0x10000000, "IndexDirectory"),
    (0x20000000, "IndexView"),
];

/// `Hidden|System|Archive`; unknown bits as `0x...`.
pub(crate) fn push_attrs(out: &mut Vec<u8>, v: u32) {
    flag_names(out, v, ATTRS);
}

pub(crate) fn flag_names(out: &mut Vec<u8>, v: u32, names: &[(u32, &str)]) {
    let mut rest = v;
    let start = out.len();
    for &(bit, name) in names {
        if v & bit != 0 {
            if out.len() > start {
                out.push(b'|');
            }
            out.extend_from_slice(name.as_bytes());
            rest &= !bit;
        }
    }
    if rest != 0 {
        if out.len() > start {
            out.push(b'|');
        }
        out.extend_from_slice(format!("0x{rest:x}").as_bytes());
    }
}

/// Classic hex dump (offset, 16 bytes, ASCII), the native view of a record.
pub(crate) fn hexdump(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 4 + 64);
    for (i, row) in b.chunks(16).enumerate() {
        s.push_str(&format!("{:08x}  ", i * 16));
        for k in 0..16 {
            match row.get(k) {
                Some(x) => s.push_str(&format!("{x:02x} ")),
                None => s.push_str("   "),
            }
        }
        s.push(' ');
        s.extend(row.iter().map(|&c| {
            if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                '.'
            }
        }));
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixup_detects_torn_writes() {
        let mut rec = vec![0u8; 1024];
        rec[..4].copy_from_slice(b"FILE");
        rec[4] = 0x30; // usa offset
        rec[6] = 3; // usn + 2 sectors
        rec[0x30..0x32].copy_from_slice(&[0xAB, 0xCD]);
        rec[0x32..0x34].copy_from_slice(&[1, 2]);
        rec[0x34..0x36].copy_from_slice(&[3, 4]);
        rec[510..512].copy_from_slice(&[0xAB, 0xCD]);
        rec[1022..1024].copy_from_slice(&[0xAB, 0xCD]);
        let mut ok = rec.clone();
        fixup(&mut ok).unwrap();
        assert_eq!(&ok[510..512], &[1, 2]);
        assert_eq!(&ok[1022..1024], &[3, 4]);
        rec[1023] = 0;
        assert!(fixup(&mut rec).is_err());
    }

    #[test]
    fn utf16_and_flags() {
        let mut o = Vec::new();
        push_utf16(&mut o, b"a\0\xe9\0");
        assert_eq!(o, "aé".as_bytes());
        let mut o = Vec::new();
        push_attrs(&mut o, 0x26 | 0x8000_0000);
        assert_eq!(o, b"Hidden|System|Archive|0x80000000");
        assert_eq!(split_ref(0x0005_0000_0000_0123), (0x123, 5));
        assert!(filetime(0).is_none());
    }
}
