//! `show`: one event in full, by stable id.

use std::sync::Arc;

use forhunt_core::artifact::Source;
use forhunt_core::id::FileKey;
use forhunt_core::{EventRef, EventView, Val};
use forhunt_output::{Format, WriteOptions, Writer};
use serde_json::{Map, Value, json};

use crate::cli::{ShowArgs, ShowFormat};
use crate::common::{self, Ctx, Totals, exit, fail};

fn to_json(ev: &EventView<'_>, path: &str, tz: Option<&jiff::tz::TimeZone>) -> Value {
    let mut data = Map::new();
    for f in &ev.fields {
        let v = match &f.value {
            Val::Str(s) => Value::String(s.to_string()),
            Val::Num(n) => serde_json::from_str(n).unwrap_or_else(|_| Value::String(n.to_string())),
            Val::Bool(b) => Value::Bool(*b),
            Val::Null => Value::Null,
        };
        // Keep repeated names (rare) instead of overwriting.
        let mut name = f.name.to_string();
        let mut i = 2;
        while data.contains_key(&name) {
            name = format!("{}#{i}", f.name);
            i += 1;
        }
        data.insert(name, v);
    }
    let mut ts = Vec::new();
    match tz {
        Some(tz) => ev.ts.write_in_tz(tz, &mut ts),
        None => ev.ts.write_iso(&mut ts),
    }
    json!({
        "id": ev.id.to_string(),
        "file": path,
        "timestamp": String::from_utf8_lossy(&ts),
        "computer": ev.computer,
        "channel": ev.channel,
        "provider": ev.provider,
        "event_id": ev.event_id,
        "record_id": ev.id.record,
        "event_record_id": ev.event_record_id,
        "level": ev.level,
        "task": ev.task,
        "opcode": ev.opcode,
        "version": ev.version,
        "keywords": ev.keywords,
        "process_id": ev.process_id,
        "thread_id": ev.thread_id,
        "user_sid": ev.user_sid,
        "activity_id": ev.activity_id,
        "data": data,
    })
}

/// Units whose record id range contains `rid`, or all units when the
/// artifact does not expose ranges (or the header is damaged).
fn candidate_units(src: &dyn Source, rid: u64) -> Vec<usize> {
    let mut hit = Vec::new();
    let mut unknown = Vec::new();
    for u in 0..src.units() {
        match src.unit_record_range(u) {
            Some((a, b)) if a <= rid && rid <= b => hit.push(u),
            Some(_) => {}
            None => unknown.push(u),
        }
    }
    hit.extend(unknown);
    hit
}

pub fn run(a: ShowArgs) -> anyhow::Result<()> {
    let ctx = Ctx::new(&a.common)?;
    let ids: Vec<EventRef> = a.ids.iter().map(|s| s.parse()).collect::<Result<_, _>>()?;
    let mut inputs = ctx.open(&a.path)?;
    // An id whose key matches no sampled key may use a full-content key
    // (given to a file whose sampled key collided with another file's).
    if ids
        .iter()
        .any(|id| !inputs.sources.iter().any(|s| s.key() == id.file))
    {
        let mut extra = Vec::new();
        for s in &inputs.sources {
            let k = FileKey::of_file(s.path())?;
            if k != s.key() && ids.iter().any(|id| id.file == k) {
                extra.push(ctx.open_keyed(s.path(), k)?);
            }
        }
        inputs.sources.extend(extra);
    }
    let mut out = common::output(&a.output)?;
    let mut totals = Totals::default();
    let mut missing = Vec::new();
    let llm = Writer::new(
        Format::Llm,
        WriteOptions {
            tz: ctx.tz.clone(),
            max_value_len: 0,
            all_fields: true,
        },
        &ctx.map,
    );
    for id in &ids {
        let src: Option<&Arc<dyn Source>> = inputs.sources.iter().find(|s| s.key() == id.file);
        let Some(src) = src else {
            missing.push(format!(
                "{id}: no input file has key {} (searched {} files)",
                id.file,
                inputs.sources.len()
            ));
            continue;
        };
        let mut found = false;
        for u in candidate_units(src.as_ref(), id.record) {
            if a.format == ShowFormat::Xml {
                if let Some(r) = src.raw_record(u, id.record) {
                    let xml = r?;
                    common::write_out(&mut *out, xml.as_bytes())?;
                    common::write_out(&mut *out, b"\n")?;
                    found = true;
                    break;
                }
                continue;
            }
            let mut buf = Vec::new();
            let path = src.path().display().to_string();
            let rep = src.parse_unit(u, &mut |ev: &EventView<'_>| {
                if ev.id.record == id.record && !found {
                    found = true;
                    match a.format {
                        ShowFormat::Json => {
                            let v = to_json(ev, &path, ctx.tz.as_ref());
                            buf.extend_from_slice(
                                serde_json::to_string_pretty(&v)
                                    .unwrap_or_default()
                                    .as_bytes(),
                            );
                            buf.push(b'\n');
                        }
                        ShowFormat::Llm => llm.write(ev, &path, &mut buf),
                        ShowFormat::Xml => {}
                    }
                }
            });
            totals.add(src.path(), &rep);
            if found {
                common::write_out(&mut *out, &buf)?;
                break;
            }
        }
        if !found && a.format != ShowFormat::Xml {
            // Exported logs: the id may be the System EventRecordID (as in
            // Hayabusa output) rather than the record header id.
            for u in 0..src.units() {
                let mut buf = Vec::new();
                let path = src.path().display().to_string();
                src.parse_unit(u, &mut |ev: &EventView<'_>| {
                    if ev.event_record_id == id.record && !found {
                        found = true;
                        match a.format {
                            ShowFormat::Json => {
                                let v = to_json(ev, &path, ctx.tz.as_ref());
                                buf.extend_from_slice(
                                    serde_json::to_string_pretty(&v)
                                        .unwrap_or_default()
                                        .as_bytes(),
                                );
                                buf.push(b'\n');
                            }
                            ShowFormat::Llm => llm.write(ev, &path, &mut buf),
                            ShowFormat::Xml => {}
                        }
                    }
                });
                if found {
                    common::write_out(&mut *out, &buf)?;
                    break;
                }
            }
        }
        if !found {
            missing.push(format!(
                "{id}: record {} not found in {}",
                id.record,
                src.path().display()
            ));
        }
    }
    common::flush(&mut *out)?;
    if !missing.is_empty() {
        return Err(fail(exit::ERROR, missing.join("\n")));
    }
    Ok(())
}
