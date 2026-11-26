//! Times each rule over the events of an evidence folder:
//! `sigma_profile RULES_DIR EVIDENCE_DIR` (slowest rules first).
use std::sync::atomic::AtomicBool;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (set, _) = forhunt_core::sigma::load(&[a[1].clone().into()], &Default::default());
    let pool = forhunt_core::engine::build_pool(1, 1).unwrap();
    let o = forhunt_core::input::open_all(&[a[2].clone()], &Default::default(), &pool).unwrap();
    let mut evs = Vec::new();
    let stop = AtomicBool::new(false);
    forhunt_core::engine::Engine::new(&pool).run(
        &o.sources,
        &stop,
        |u, src| {
            let mut v = Vec::new();
            src.parse_unit(u.unit, &mut |e: &forhunt_core::EventView<'_>| {
                v.push(e.clone().into_owned())
            });
            v
        },
        |_, v| evs.extend(v),
    );
    let t = std::time::Instant::now();
    let mut m = set.matcher();
    let mut out = Vec::new();
    for e in &evs {
        m.matches(e, &mut out);
    }
    println!(
        "{} events, {} hits, all rules {:?}",
        evs.len(),
        out.len(),
        t.elapsed()
    );
    let (mut a, mut b) = (Vec::new(), Vec::new());
    let mut diff = 0;
    for e in &evs {
        a.clear();
        b.clear();
        m.matches(e, &mut a);
        m.matches_ungated(e, &mut b);
        if a != b {
            diff += 1;
        }
    }
    println!("gated vs ungated: {diff} events differ");
    if std::env::var_os("ONLY_TOTAL").is_some() {
        return;
    }
    let mut times = Vec::new();
    for r in set.rules() {
        let text = std::fs::read_to_string(&r.path).unwrap();
        let (one, _) = forhunt_core::sigma::load_str(&text, &Default::default());
        let mut m = one.matcher();
        let t = std::time::Instant::now();
        let mut out = Vec::new();
        for e in &evs {
            m.matches(e, &mut out);
        }
        times.push((t.elapsed(), r.path.display().to_string(), out.len()));
    }
    times.sort();
    for (d, p, n) in times.iter().rev().take(15) {
        println!("{d:?} {n} {p}");
    }
}
