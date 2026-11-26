//! Checks every rule against the sample event embedded in it (`sample-evtx`),
//! extracted to JSONL by `scripts/sigma-samples.py`:
//! `sigma_samples RULES_DIR SAMPLES.jsonl`.
use std::borrow::Cow;

use forhunt_core::{EventView, Field, Val};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (set, _) = forhunt_core::sigma::load(&[a[1].clone().into()], &Default::default());
    let (mut ok, mut miss, mut absent) = (0, 0, 0);
    for line in std::fs::read_to_string(&a[2]).unwrap().lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let s = |k: &str| v["sys"][k].as_str().unwrap_or("").to_string();
        let ev = EventView {
            channel: Cow::Owned(s("channel")),
            provider: Cow::Owned(s("provider")),
            computer: Cow::Owned(s("computer")),
            user_sid: Cow::Owned(s("user")),
            event_id: v["sys"]["eid"].as_u64().unwrap_or(0) as u32,
            level: v["sys"]["level"].as_u64().unwrap_or(0) as u8,
            fields: v["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| Field {
                    name: Cow::Owned(f[0].as_str().unwrap().to_string()),
                    value: Val::Str(Cow::Owned(f[1].as_str().unwrap().to_string())),
                })
                .collect(),
            ..Default::default()
        };
        let id = v["id"].as_str().unwrap_or("");
        let Some(idx) = set.rules().iter().position(|r| r.id == id) else {
            absent += 1;
            continue;
        };
        let mut out = Vec::new();
        set.matcher().matches(&ev, &mut out);
        if out.contains(&(idx as u32)) {
            ok += 1;
        } else {
            miss += 1;
            println!(
                "MISS {} ({} {})",
                v["rule"].as_str().unwrap(),
                ev.channel,
                ev.event_id
            );
        }
    }
    println!(
        "{ok} matched their sample, {miss} missed, {absent} rules not loaded (skipped by default)"
    );
}
