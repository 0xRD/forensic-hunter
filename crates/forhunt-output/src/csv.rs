//! CSV (RFC 4180, UTF-8) for spreadsheet-style timeline tools such as Eric
//! Zimmerman's Timeline Explorer.
//!
//! The first 25 columns follow EvtxECmd's CSV layout (names and order), so
//! analysts' existing views, filters and habits carry over; times use the
//! same `yyyy-MM-dd HH:mm:ss.fffffff` form (UTC unless `--tz`). One forhunt
//! column follows: `ForhuntId` (the stable id `forhunt show` takes).
//!
//! Column content: `MapDescription` is the event title from the field map;
//! `UserName`, `RemoteHost` and `ExecutableInfo` are the first non-blank
//! user / source address / process-or-command field; `PayloadData1..6` are
//! the event's key fields (field map order) as `Name: value`; `Payload` holds
//! every field as a JSON object.

use forhunt_core::EventView;

use crate::{CMD_FIELDS, IP_FIELDS, PROC_FIELDS, USER_FIELDS, Writer, first_of, json};

pub const HEADER: &[u8] = b"RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,ProcessId,ThreadId,\
Computer,UserId,MapDescription,UserName,RemoteHost,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,\
PayloadData6,ExecutableInfo,HiddenRecord,SourceFile,Keywords,Payload,ForhuntId\n";

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

/// Level names as Windows Event Viewer shows them.
fn level_name(l: u8) -> &'static str {
    match l {
        0 => "LogAlways",
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 => "Info",
        5 => "Verbose",
        _ => "",
    }
}

pub fn write(w: &Writer<'_>, ev: &EventView<'_>, source: &str, out: &mut Vec<u8>) {
    let num = |out: &mut Vec<u8>, v: u64| {
        json::u64(out, v);
        out.push(b',');
    };
    num(out, ev.id.record);
    num(
        out,
        if ev.event_record_id != 0 {
            ev.event_record_id
        } else {
            ev.id.record
        },
    );
    // TimeCreated: `yyyy-MM-dd HH:mm:ss.fffffff`.
    let mut ts = Vec::with_capacity(32);
    w.write_ts(ev.ts, &mut ts);
    let ts = String::from_utf8(ts).unwrap_or_default();
    let ts = ts.trim_end_matches('Z');
    let (main, frac) = ts.split_at(ts.find('.').unwrap_or(ts.len()));
    // Drop any offset (`--tz` output) from the fraction, keep digits only.
    let digits: String = frac
        .chars()
        .skip(1)
        .take_while(|c| c.is_ascii_digit())
        .collect();
    out.extend_from_slice(main.replacen('T', " ", 1).as_bytes());
    out.push(b'.');
    out.extend_from_slice(format!("{digits:0<7}").as_bytes());
    out.push(b',');
    num(out, ev.event_id as u64);
    cell(out, level_name(ev.level));
    out.push(b',');
    cell(out, &ev.provider);
    out.push(b',');
    cell(out, &ev.channel);
    out.push(b',');
    num(out, ev.process_id as u64);
    num(out, ev.thread_id as u64);
    cell(out, &ev.computer);
    out.push(b',');
    cell(out, &ev.user_sid);
    out.push(b',');
    let spec = w.map.event(&ev.channel, ev.event_id);
    cell(out, spec.map(|s| s.title.as_str()).unwrap_or(""));
    out.push(b',');
    cell(out, first_of(ev, USER_FIELDS));
    out.push(b',');
    cell(out, first_of(ev, IP_FIELDS));
    out.push(b',');
    // PayloadData1..6: key fields of known events, else the first fields.
    let mut pd: Vec<String> = Vec::with_capacity(6);
    let mut add = |name: &str, v: &str| {
        if pd.len() < 6 {
            pd.push(format!("{name}: {v}"));
        }
    };
    match spec.filter(|s| !s.keep.is_empty()) {
        Some(s) => {
            for name in &s.keep {
                if let Some(v) = ev.field(name)
                    && !v.is_blank()
                {
                    add(name, v.as_str());
                }
            }
        }
        None => {
            for f in ev.fields.iter().filter(|f| !f.value.is_blank()) {
                add(&f.name, f.value.as_str());
            }
        }
    }
    for i in 0..6 {
        cell(out, pd.get(i).map(String::as_str).unwrap_or(""));
        out.push(b',');
    }
    let exe = match first_of(ev, CMD_FIELDS) {
        "" => first_of(ev, PROC_FIELDS),
        c => c,
    };
    cell(out, exe);
    out.extend_from_slice(b",False,");
    cell(out, source);
    out.push(b',');
    cell(out, &ev.keywords);
    out.push(b',');
    let mut payload = Vec::with_capacity(256);
    payload.push(b'{');
    for (i, f) in ev.fields.iter().enumerate() {
        if i > 0 {
            payload.push(b',');
        }
        json::str(&mut payload, &f.name);
        payload.push(b':');
        crate::jsonl::value(&mut payload, &f.value);
    }
    payload.push(b'}');
    cell(out, std::str::from_utf8(&payload).unwrap_or(""));
    out.push(b',');
    ev.id.write(out);
    out.push(b'\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use forhunt_core::normalize::FieldMap;
    use forhunt_core::{EventView, Field, Ts, Val};

    #[test]
    fn layout() {
        let map = FieldMap::default_map();
        let w = Writer::new(crate::Format::Csv, Default::default(), map);
        let ev = EventView {
            ts: Ts::parse("2024-03-11T10:10:02.5Z").unwrap(),
            event_id: 4624,
            channel: "Security".into(),
            computer: "WS-07".into(),
            level: 0,
            fields: vec![
                Field {
                    name: "TargetUserName".into(),
                    value: Val::Str("bob".into()),
                },
                Field {
                    name: "IpAddress".into(),
                    value: Val::Str("10.0.0.5".into()),
                },
                Field {
                    name: "LogonType".into(),
                    value: Val::Num("3".into()),
                },
            ],
            ..Default::default()
        };
        let mut out = Vec::new();
        write(&w, &ev, "C:\\cases\\ws07\\Security.evtx", &mut out);
        let line = String::from_utf8(out).unwrap();
        let header_cols = std::str::from_utf8(HEADER)
            .unwrap()
            .trim_end()
            .split(',')
            .count();
        assert!(
            line.contains(",2024-03-11 10:10:02.5000000,4624,LogAlways,"),
            "{line}"
        );
        assert!(
            line.contains(
                ",Logon success,bob,10.0.0.5,TargetUserName: bob,LogonType: 3,IpAddress: 10.0.0.5,"
            ),
            "{line}"
        );
        assert!(line.contains(",C:\\cases\\ws07\\Security.evtx,"));
        // JSON payload is quoted, so count columns with a CSV-aware split.
        let mut cols = 1;
        let mut quoted = false;
        for c in line.trim_end().chars() {
            match c {
                '"' => quoted = !quoted,
                ',' if !quoted => cols += 1,
                _ => {}
            }
        }
        assert_eq!(cols, header_cols);
    }
}
