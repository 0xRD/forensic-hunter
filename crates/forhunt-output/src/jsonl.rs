//! Full-fidelity JSON Lines: every System value and every payload field.

use forhunt_core::{EventView, Val};

use crate::{Writer, json};

pub fn write(w: &Writer<'_>, ev: &EventView<'_>, source: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(b"{\"id\":\"");
    ev.id.write(out);
    out.extend_from_slice(b"\",\"timestamp\":\"");
    w.write_ts(ev.ts, out);
    out.extend_from_slice(b"\",\"computer\":");
    json::str(out, &ev.computer);
    out.extend_from_slice(b",\"channel\":");
    json::str(out, &ev.channel);
    out.extend_from_slice(b",\"provider\":");
    json::str(out, &ev.provider);
    out.extend_from_slice(b",\"event_id\":");
    json::u64(out, ev.event_id as u64);
    out.extend_from_slice(b",\"record_id\":");
    json::u64(out, ev.id.record);
    if ev.event_record_id != ev.id.record && ev.event_record_id != 0 {
        out.extend_from_slice(b",\"event_record_id\":");
        json::u64(out, ev.event_record_id);
    }
    out.extend_from_slice(b",\"level\":");
    json::u64(out, ev.level as u64);
    out.extend_from_slice(b",\"task\":");
    json::u64(out, ev.task as u64);
    out.extend_from_slice(b",\"opcode\":");
    json::u64(out, ev.opcode as u64);
    out.extend_from_slice(b",\"keywords\":");
    json::str(out, &ev.keywords);
    out.extend_from_slice(b",\"process_id\":");
    json::u64(out, ev.process_id as u64);
    out.extend_from_slice(b",\"thread_id\":");
    json::u64(out, ev.thread_id as u64);
    if !ev.user_sid.is_empty() {
        out.extend_from_slice(b",\"user_sid\":");
        json::str(out, &ev.user_sid);
    }
    if !ev.activity_id.is_empty() {
        out.extend_from_slice(b",\"activity_id\":");
        json::str(out, &ev.activity_id);
    }
    if !source.is_empty() {
        out.extend_from_slice(b",\"source_file\":");
        json::str(out, source);
    }
    out.extend_from_slice(b",\"data\":{");
    for (i, f) in ev.fields.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        json::str(out, &f.name);
        out.push(b':');
        value(out, &f.value);
    }
    out.extend_from_slice(b"}}\n");
}

pub(crate) fn value(out: &mut Vec<u8>, v: &Val<'_>) {
    match v {
        Val::Str(s) => json::str(out, s),
        Val::Num(n) => out.extend_from_slice(n.as_bytes()),
        Val::Bool(true) => out.extend_from_slice(b"true"),
        Val::Bool(false) => out.extend_from_slice(b"false"),
        Val::Null => out.extend_from_slice(b"null"),
    }
}
