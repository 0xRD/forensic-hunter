//! `cargo run -p forhunt-output --example export_csv -- OUT.csv PATH...`:
//! the library export used by forhunt-viewer (same bytes as `forhunt parse -F csv`).
use std::sync::atomic::AtomicBool;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let out = args.next().expect("usage: export_csv OUT.csv PATH...");
    let paths: Vec<String> = args.collect();
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    let pool = forhunt_core::engine::build_pool(0, cores)?;
    let o = forhunt_core::input::open_all(&paths, &Default::default(), &pool)?;
    for w in &o.warnings {
        eprintln!("warning: {w}");
    }
    let map = forhunt_core::normalize::FieldMap::default_map();
    let w = forhunt_output::Writer::new(forhunt_output::Format::Csv, Default::default(), map);
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);
    let s = forhunt_output::export::write_all(
        &o.sources,
        &pool,
        &w,
        &mut f,
        &AtomicBool::new(false),
        &mut |_| {},
    )?;
    eprintln!("{s:?}");
    Ok(())
}
