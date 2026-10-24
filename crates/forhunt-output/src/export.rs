//! Whole-input export for library users (forhunt-viewer): every event of
//! every source, in input order, through one [`Writer`].

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use forhunt_core::artifact::{Source, UnitReport};
use forhunt_core::engine::Engine;

use crate::Writer;

/// Totals of an export.
#[derive(Debug, Default, Clone)]
pub struct ExportStats {
    pub events: u64,
    pub units: u64,
    pub bad_units: u64,
    pub bad_records: u64,
}

/// Writes the header, then every event of `sources` in input order, to
/// `out`. `progress` is called after each unit with the bytes done so far
/// (out of the sum of [`Source::byte_len`]). Setting `cancel` stops the
/// export early with an [`io::ErrorKind::Interrupted`] error.
pub fn write_all(
    sources: &[Arc<dyn Source>],
    pool: &rayon::ThreadPool,
    writer: &Writer<'_>,
    out: &mut dyn Write,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(u64),
) -> io::Result<ExportStats> {
    out.write_all(writer.header())?;
    let mut stats = ExportStats::default();
    let mut done = 0u64;
    let mut err: Option<io::Error> = None;
    Engine::new(pool).run(
        sources,
        cancel,
        |u, src| {
            let mut buf = Vec::with_capacity(256 * 1024);
            let path = src.path().display().to_string();
            let mut n = 0u64;
            let mut sink = |ev: &forhunt_core::EventView<'_>| {
                writer.write(ev, &path, &mut buf);
                n += 1;
            };
            let rep: UnitReport = src.parse_unit(u.unit, &mut sink);
            (buf, n, rep)
        },
        |u, (buf, n, rep)| {
            let src = &sources[u.source];
            stats.units += 1;
            stats.events += n;
            stats.bad_records += rep.bad_records;
            stats.bad_units += u64::from(rep.bad_unit);
            done += src.byte_len() / src.units().max(1) as u64;
            if err.is_none()
                && let Err(e) = out.write_all(&buf)
            {
                err = Some(e);
                cancel.store(true, Ordering::Relaxed);
            }
            progress(done);
        },
    );
    if let Some(e) = err {
        return Err(e);
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "export cancelled",
        ));
    }
    out.flush()?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forhunt_core::artifact::ParseOptions;
    use forhunt_core::normalize::FieldMap;

    #[test]
    fn exports_fixture_as_csv() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/synthetic/Security.evtx"
        );
        let pool = forhunt_core::engine::build_pool(2, 2).unwrap();
        let o =
            forhunt_core::input::open_all(&[dir.into()], &ParseOptions::default(), &pool).unwrap();
        assert_eq!(o.sources.len(), 1);
        let w = Writer::new(
            crate::Format::Csv,
            Default::default(),
            FieldMap::default_map(),
        );
        let mut out = Vec::new();
        let mut last = 0;
        let stats = write_all(
            &o.sources,
            &pool,
            &w,
            &mut out,
            &AtomicBool::new(false),
            &mut |d| last = d,
        )
        .unwrap();
        assert_eq!(stats.events, 2548);
        assert!(out.starts_with(crate::csv::HEADER));
        assert!(last > 0 && last <= o.bytes);

        let cancelled = write_all(
            &o.sources,
            &pool,
            &w,
            &mut Vec::new(),
            &AtomicBool::new(true),
            &mut |_| {},
        );
        assert_eq!(cancelled.unwrap_err().kind(), io::ErrorKind::Interrupted);
    }
}
