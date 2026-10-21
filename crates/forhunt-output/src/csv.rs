//! CSV (RFC 4180) with a fixed set of analyst columns plus the full payload.

use forhunt_core::EventView;

use crate::{CMD_FIELDS, IP_FIELDS, PROC_FIELDS, USER_FIELDS, Writer, first_of};

pub const HEADER: &[u8] =
    b"id,timestamp,computer,channel,event_id,provider,level,record_id,title,user,ip,process,command_line,payload\n";

fn cell(out: &mut Vec<u8>, s: &str) {
    if s.bytes().any(|b| matches!(b, b',' | b'"' | b'\n' | b'\r')) {
        out.push(b'"');
        for &b in s.as_bytes() {
            if b == b'"' {
                out.push(b'"');
            }
            out.push(b);
        }
        out.push(b'"');
    } else {
        out.extend_from_slice(s.as_bytes());
    }
}

pub fn write(w: &Writer<'_>, ev: &EventView<'_>, out: &mut Vec<u8>) {
    ev.id.write(out);
    out.push(b',');
    w.write_ts(ev.ts, out);
    out.push(b',');
    cell(out, &ev.computer);
    out.push(b',');
    cell(out, &ev.channel);
    out.push(b',');
    crate::json::u64(out, ev.event_id as u64);
    out.push(b',');
    cell(out, &ev.provider);
    out.push(b',');
    crate::json::u64(out, ev.level as u64);
    out.push(b',');
    crate::json::u64(out, ev.id.record);
    out.push(b',');
    cell(
        out,
        w.map
            .event(&ev.channel, ev.event_id)
            .map(|s| s.title.as_str())
            .unwrap_or(""),
    );
    out.push(b',');
    cell(out, first_of(ev, USER_FIELDS));
    out.push(b',');
    cell(out, first_of(ev, IP_FIELDS));
    out.push(b',');
    cell(out, first_of(ev, PROC_FIELDS));
    out.push(b',');
    cell(out, first_of(ev, CMD_FIELDS));
    out.push(b',');
    // Payload: `Name: value | Name: value`, blanks skipped.
    let mut payload = String::new();
    for f in ev.fields.iter().filter(|f| !f.value.is_blank()) {
        if !payload.is_empty() {
            payload.push_str(" | ");
        }
        payload.push_str(&f.name);
        payload.push_str(": ");
        payload.push_str(f.value.as_str());
    }
    cell(out, &payload);
    out.push(b'\n');
}
