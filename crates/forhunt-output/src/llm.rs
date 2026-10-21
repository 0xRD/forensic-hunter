//! The `llm` format: compact JSON Lines designed for a limited context window.
//!
//! One event per line with short, stable keys:
//!
//! ```text
//! {"id":"a1b2c3d4:4821","t":"2024-05-01T10:22:03.123456Z","h":"WS01","ch":"Sec","eid":4624,
//!  "ti":"Logon success","d":{"user":"bob","lt":3,"ip":"10.0.0.5"}}
//! ```
//!
//! - `id` is the stable event id, accepted by `forhunt show`;
//! - `d` holds the mapped fields for known events (see `maps/default.toml`),
//!   or every non-blank field otherwise, with short names;
//! - values longer than the limit end with `…[+N chars]`.

use forhunt_core::{EventView, Val};

use crate::{Writer, json};

/// Appends a truncated, escaped string value.
pub fn trunc_str(out: &mut Vec<u8>, s: &str, max: usize) {
    out.push(b'"');
    if max > 0 && s.len() > max {
        // Cut on a char boundary at or below `max` bytes.
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        let rest = s[cut..].chars().count();
        json::raw(out, &s[..cut]);
        out.extend_from_slice("…[+".as_bytes());
        json::u64(out, rest as u64);
        out.extend_from_slice(b" chars]");
    } else {
        json::raw(out, s);
    }
    out.push(b'"');
}

fn value(out: &mut Vec<u8>, v: &Val<'_>, max: usize) {
    match v {
        Val::Str(s) => trunc_str(out, s, max),
        other => crate::jsonl::value(out, other),
    }
}

pub fn write(w: &Writer<'_>, ev: &EventView<'_>, out: &mut Vec<u8>) {
    let max = w.opts.max_value_len;
    out.extend_from_slice(b"{\"id\":\"");
    ev.id.write(out);
    out.extend_from_slice(b"\",\"t\":\"");
    w.write_ts(ev.ts, out);
    out.extend_from_slice(b"\",\"h\":");
    json::str(out, &ev.computer);
    out.extend_from_slice(b",\"ch\":");
    json::str(out, w.map.channel_alias(&ev.channel));
    out.extend_from_slice(b",\"eid\":");
    json::u64(out, ev.event_id as u64);
    let spec = w.map.event(&ev.channel, ev.event_id);
    if let Some(spec) = spec {
        out.extend_from_slice(b",\"ti\":");
        json::str(out, &spec.title);
    }
    out.extend_from_slice(b",\"d\":{");
    let mut first = true;
    let mut emit = |out: &mut Vec<u8>, name: &str, v: &Val<'_>| {
        if !first {
            out.push(b',');
        }
        first = false;
        json::str(out, w.map.short_field(name));
        out.push(b':');
        value(out, v, max);
    };
    match spec {
        Some(spec) if !w.opts.all_fields => {
            for name in &spec.keep {
                if let Some(v) = ev.field(name)
                    && !v.is_blank()
                {
                    emit(out, name, v);
                }
            }
        }
        _ => {
            for f in ev.fields.iter().filter(|f| !f.value.is_blank()) {
                emit(out, &f.name, &f.value);
            }
        }
    }
    out.extend_from_slice(b"}}\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_marker() {
        let mut o = Vec::new();
        trunc_str(&mut o, &"é".repeat(10), 5);
        assert_eq!(String::from_utf8(o).unwrap(), "\"éé…[+8 chars]\"");
        let mut o = Vec::new();
        trunc_str(&mut o, "short", 5);
        assert_eq!(o, b"\"short\"");
    }
}
