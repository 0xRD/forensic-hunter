//! Micro-benchmarks of the hot path stages on one EVTX file:
//! `render` (evtx crate, chunk -> JSON), `decode` (JSON -> EventView) and
//! `filter`. Input: $FORHUNT_BENCH_EVTX, or the synthetic fixture.

use std::hint::black_box;
use std::path::PathBuf;
use std::sync::Arc;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use forhunt_core::EventView;
use forhunt_core::evtx::decode::decode;
use forhunt_core::filter::{FieldCond, Filter};

fn input() -> PathBuf {
    std::env::var_os("FORHUNT_BENCH_EVTX")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/synthetic/mixed.evtx"
            ))
        })
}

fn rendered(data: &[u8]) -> Vec<Vec<u8>> {
    let settings = Arc::new(evtx::ParserSettings::new());
    let mut out = Vec::new();
    for i in 0..(data.len() - 4096) / 65536 {
        let s = 4096 + i * 65536;
        let Ok(mut cd) = evtx::EvtxChunkData::new(data[s..s + 65536].to_vec(), false) else {
            continue;
        };
        let Ok(mut ch) = cd.parse(settings.clone()) else {
            continue;
        };
        for r in ch.iter().flatten() {
            if let Ok(j) = r.into_json_bytes() {
                out.push(j.data);
            }
        }
    }
    out
}

fn bench(c: &mut Criterion) {
    let path = input();
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let json = rendered(&data);
    let json_bytes: usize = json.iter().map(|j| j.len()).sum();

    let mut g = c.benchmark_group("hot_path");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("render", |b| b.iter(|| black_box(rendered(&data)).len()));
    g.throughput(Throughput::Bytes(json_bytes as u64));
    g.bench_function("decode", |b| {
        b.iter(|| {
            let mut n = 0usize;
            for j in &json {
                let mut ev = EventView::default();
                decode(j, &mut ev).unwrap();
                n += ev.fields.len();
            }
            n
        })
    });
    let filter = Filter::new()
        .event_ids(vec![4624, 4688, 1])
        .fields(vec![FieldCond::parse("CommandLine~powershell").unwrap()]);
    let decoded: Vec<EventView<'_>> = json
        .iter()
        .map(|j| {
            let mut ev = EventView::default();
            decode(j, &mut ev).unwrap();
            ev
        })
        .collect();
    g.throughput(Throughput::Elements(decoded.len() as u64));
    g.bench_function("filter", |b| {
        b.iter(|| decoded.iter().filter(|e| filter.matches(e)).count())
    });
    g.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}
criterion_main!(benches);
