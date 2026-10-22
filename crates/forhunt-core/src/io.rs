//! Positional reads shared by the artifact sources.

use std::borrow::Cow;

/// Where the bytes come from. Files are read with positional reads, one
/// chunk at a time, straight into the buffer the parser owns: resident
/// memory stays bounded whatever the file size (an mmap would count every
/// touched page; see DECISIONS.md D-021).
pub(crate) enum Data {
    File { file: std::fs::File, len: u64 },
    Owned(Vec<u8>),
}

impl Data {
    pub(crate) fn len(&self) -> u64 {
        match self {
            Data::File { len, .. } => *len,
            Data::Owned(v) => v.len() as u64,
        }
    }

    /// Reads `[off, off + n)`, clamped to the end of the input.
    pub(crate) fn read(&self, off: u64, n: usize) -> std::io::Result<Cow<'_, [u8]>> {
        let end = (off + n as u64).min(self.len());
        if off >= end {
            return Ok(Cow::Borrowed(&[]));
        }
        match self {
            Data::Owned(v) => Ok(Cow::Borrowed(&v[off as usize..end as usize])),
            Data::File { file, .. } => {
                let mut buf = vec![0u8; (end - off) as usize];
                read_exact_at(file, &mut buf, off)?;
                Ok(Cow::Owned(buf))
            }
        }
    }
}

impl Data {
    /// Like [`Data::read`], into a caller-owned buffer that is reused across
    /// calls (no allocation or zeroing once it has grown).
    pub(crate) fn read_into<'s>(
        &'s self,
        off: u64,
        n: usize,
        buf: &'s mut Vec<u8>,
    ) -> std::io::Result<&'s [u8]> {
        let end = (off + n as u64).min(self.len());
        if off >= end {
            return Ok(&[]);
        }
        let len = (end - off) as usize;
        match self {
            Data::Owned(v) => Ok(&v[off as usize..end as usize]),
            Data::File { file, .. } => {
                if buf.len() < len {
                    buf.resize(len, 0);
                }
                read_exact_at(file, &mut buf[..len], off)?;
                Ok(&buf[..len])
            }
        }
    }
}

fn read_exact_at(file: &std::fs::File, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    while !buf.is_empty() {
        #[cfg(unix)]
        let n = std::os::unix::fs::FileExt::read_at(file, buf, off)?;
        #[cfg(windows)]
        let n = std::os::windows::fs::FileExt::seek_read(file, buf, off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
        off += n as u64;
    }
    Ok(())
}
