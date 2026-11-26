//! Loads a rule folder and prints the load report: `cargo run --release -p forhunt-core --example sigma_load -- DIR`.
fn main() {
    let dirs: Vec<std::path::PathBuf> = std::env::args().skip(1).map(Into::into).collect();
    let t = std::time::Instant::now();
    let (set, rep) = forhunt_core::sigma::load(&dirs, &Default::default());
    println!(
        "{} files, {} rules loaded in {:?}",
        rep.files,
        set.len(),
        t.elapsed()
    );
    for (k, v) in &rep.skipped {
        println!("  skipped {v:5}  {k}");
    }
    for (p, e) in &rep.errors {
        println!("  ERROR {}: {e}", p.display());
    }
    for r in set
        .rules()
        .iter()
        .filter(|r| r.event_ids().is_none() || r.channels().is_none())
    {
        println!(
            "  any {}: {:?} {:?} {}",
            if r.event_ids().is_none() {
                "eid"
            } else {
                "channel"
            },
            r.channels(),
            r.event_ids(),
            r.path.display()
        );
    }
    println!(
        "event-id prefilter: {}",
        if set.wants_event_id(u32::MAX) {
            "off"
        } else {
            "on"
        }
    );
}
