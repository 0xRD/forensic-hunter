//! Minimal JSON string escaping for the hot path.

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Appends `s` as a quoted JSON string.
#[inline]
pub fn str(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    raw(out, s);
    out.push(b'"');
}

/// Bytes that need escaping in a JSON string.
static NEEDS_ESCAPE: [bool; 256] = {
    let mut t = [false; 256];
    let mut i = 0;
    while i < 0x20 {
        t[i] = true;
        i += 1;
    }
    t[b'"' as usize] = true;
    t[b'\\' as usize] = true;
    t
};

/// Appends `s` escaped, without quotes.
#[inline]
pub fn raw(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    // Fast path: nothing to escape (the vast majority of values).
    if !b.iter().any(|&c| NEEDS_ESCAPE[c as usize]) {
        out.extend_from_slice(b);
        return;
    }
    escape_slow(out, b);
}

#[cold]
fn escape_slow(out: &mut Vec<u8>, b: &[u8]) {
    let mut start = 0;
    for (i, &c) in b.iter().enumerate() {
        let esc: &[u8] = match c {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0..=0x1f => {
                out.extend_from_slice(&b[start..i]);
                out.extend_from_slice(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[(c >> 4) as usize],
                    HEX[(c & 0xf) as usize],
                ]);
                start = i + 1;
                continue;
            }
            _ => continue,
        };
        out.extend_from_slice(&b[start..i]);
        out.extend_from_slice(esc);
        start = i + 1;
    }
    out.extend_from_slice(&b[start..]);
}

#[inline]
pub fn u64(out: &mut Vec<u8>, v: u64) {
    let mut buf = [0u8; 20];
    out.extend_from_slice(forhunt_core::id::fmt_u64(&mut buf, v));
}

#[cfg(test)]
mod tests {
    #[test]
    fn escapes() {
        let mut o = Vec::new();
        super::str(&mut o, "a\"b\\c\nd\u{1}é");
        assert_eq!(String::from_utf8(o).unwrap(), r#""a\"b\\c\nd\u0001é""#);
    }
}
