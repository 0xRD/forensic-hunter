//! Decodes the compact JSON rendered by the `evtx` crate straight into an
//! [`EventView`] that borrows from the JSON buffer.
//!
//! This is a purpose-built scanner, not a general JSON library: it walks the
//! document once, keeps only what the event model needs and skips the rest.
//! Strings without escapes are borrowed (located with `memchr`), so a typical
//! record decodes with no allocation besides the reused field vector. It was
//! measured at ~3x the speed of a serde visitor over the same input
//! (docs/PERF.md).

use std::borrow::Cow;

use crate::event::{EventView, Field, Val};
use crate::time::Ts;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub pos: usize,
    pub msg: &'static str,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at byte {}", self.msg, self.pos)
    }
}

impl std::error::Error for DecodeError {}

type R<T> = Result<T, DecodeError>;

/// Decodes one rendered record into `ev` (whose `fields` should be empty).
pub fn decode<'a>(json: &'a [u8], ev: &mut EventView<'a>) -> R<()> {
    // Validate once; every slice taken later starts and ends next to an
    // ASCII delimiter, so it is valid UTF-8 too (and `&str` slicing checks
    // the boundaries again, cheaply).
    let text = std::str::from_utf8(json).map_err(|e| DecodeError {
        pos: e.valid_up_to(),
        msg: "invalid UTF-8",
    })?;
    let mut p = P {
        s: text,
        b: json,
        i: 0,
    };
    p.ws();
    p.object(|p, k| if k == "Event" { event(p, ev) } else { p.skip() })?;
    p.ws();
    if p.i != p.b.len() {
        return Err(p.err("trailing characters"));
    }
    Ok(())
}

fn event<'a>(p: &mut P<'a>, ev: &mut EventView<'a>) -> R<()> {
    p.object(|p, k| match k.as_ref() {
        "System" => system(p, ev),
        "EventData" => flatten(p, &mut ev.fields, None, false),
        // The UserData child element (EventXML, ...) only wraps the payload.
        "UserData" => flatten(p, &mut ev.fields, None, true),
        "#attributes" => p.skip(),
        // RenderingInfo, ProcessingErrorData, DebugData, BinaryEventData.
        _ => flatten(p, &mut ev.fields, Some(k), false),
    })
}

fn str_of(v: Val<'_>) -> Cow<'_, str> {
    match v {
        Val::Str(s) | Val::Num(s) => s,
        Val::Bool(b) => Cow::Borrowed(if b { "true" } else { "false" }),
        Val::Null => Cow::Borrowed(""),
    }
}

/// Parses a number value, also accepting `{"#attributes":..,"#text":N}`
/// (EventID with Qualifiers) and hex strings.
fn num<'a>(p: &mut P<'a>) -> R<u64> {
    p.ws();
    match p.peek() {
        Some(b'{') => {
            let mut out = 0;
            p.object(|p, k| {
                if k == "#text" {
                    out = num(p)?;
                    Ok(())
                } else {
                    p.skip()
                }
            })?;
            Ok(out)
        }
        _ => {
            let v = p.scalar()?;
            let s = v.as_str().trim();
            Ok(
                match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    Some(h) => u64::from_str_radix(h, 16).unwrap_or(0),
                    None => s
                        .parse::<u64>()
                        .or_else(|_| s.parse::<f64>().map(|f| f as u64))
                        .unwrap_or(0),
                },
            )
        }
    }
}

/// Calls `f` for each attribute of an element `{"#attributes":{...}, ...}`.
fn attrs<'a>(p: &mut P<'a>, mut f: impl FnMut(&str, Val<'a>)) -> R<()> {
    p.ws();
    if p.peek() != Some(b'{') {
        return p.skip();
    }
    p.object(|p, k| {
        if k == "#attributes" {
            p.ws();
            if p.peek() != Some(b'{') {
                return p.skip();
            }
            p.object(|p, name| {
                let v = p.scalar_or_skip()?;
                f(&name, v);
                Ok(())
            })
        } else {
            p.skip()
        }
    })
}

fn system<'a>(p: &mut P<'a>, ev: &mut EventView<'a>) -> R<()> {
    p.object(|p, k| {
        match k.as_ref() {
            "Provider" => {
                let mut name = None;
                let mut source = None;
                attrs(p, |n, v| match n {
                    "Name" => name = Some(str_of(v)),
                    "EventSourceName" => source = Some(str_of(v)),
                    _ => {}
                })?;
                if let Some(n) = name.or(source) {
                    ev.provider = n;
                }
            }
            "EventID" => ev.event_id = num(p)? as u32,
            "Version" => ev.version = num(p)? as u32,
            "Level" => ev.level = num(p)? as u8,
            "Task" => ev.task = num(p)? as u32,
            "Opcode" => ev.opcode = num(p)? as u32,
            "Keywords" => ev.keywords = str_of(p.scalar_or_skip()?),
            "TimeCreated" => attrs(p, |n, v| {
                if n == "SystemTime"
                    && let Some(t) = Ts::parse(v.as_str())
                {
                    ev.ts = t;
                }
            })?,
            "Execution" => attrs(p, |n, v| match n {
                "ProcessID" => ev.process_id = v.as_str().parse().unwrap_or(0),
                "ThreadID" => ev.thread_id = v.as_str().parse().unwrap_or(0),
                _ => {}
            })?,
            "Channel" => ev.channel = str_of(p.scalar_or_skip()?),
            "Computer" => ev.computer = str_of(p.scalar_or_skip()?),
            "Security" => attrs(p, |n, v| {
                if n == "UserID" {
                    ev.user_sid = str_of(v);
                }
            })?,
            "Correlation" => attrs(p, |n, v| {
                if n == "ActivityID" {
                    ev.activity_id = str_of(v);
                }
            })?,
            _ => p.skip()?,
        }
        Ok(())
    })
}

/// Flattens a payload subtree into `(leaf name, scalar)` fields:
/// scalars are named after their element, `#attributes` become fields named
/// after the attribute (`xmlns*` dropped), `#text` carries the element's own
/// value, arrays (repeated unnamed `<Data>`) become `Name[1]`, `Name[2]`...
/// With `skip_wrapper`, the first object level does not name its children.
fn flatten<'a>(
    p: &mut P<'a>,
    out: &mut Vec<Field<'a>>,
    name: Option<Cow<'a, str>>,
    skip_wrapper: bool,
) -> R<()> {
    p.ws();
    match p.peek() {
        Some(b'{') => p.object(|p, k| match k.as_ref() {
            "#attributes" => {
                p.ws();
                if p.peek() != Some(b'{') {
                    return p.skip();
                }
                p.object(|p, a| {
                    let v = p.scalar_or_skip()?;
                    if !a.starts_with("xmlns") {
                        out.push(Field { name: a, value: v });
                    }
                    Ok(())
                })
            }
            "#text" => flatten(p, out, name.clone(), false),
            _ if skip_wrapper => flatten(p, out, None, false),
            _ => flatten(p, out, Some(k), false),
        }),
        Some(b'[') => {
            let base = name.unwrap_or(Cow::Borrowed("Data"));
            let mut i = 0usize;
            p.array(|p| {
                i += 1;
                flatten(p, out, Some(Cow::Owned(format!("{base}[{i}]"))), false)
            })
        }
        _ => {
            let v = p.scalar()?;
            match name {
                Some(n) => out.push(Field { name: n, value: v }),
                // `EventData: null` carries nothing.
                None if v == Val::Null => {}
                None => out.push(Field {
                    name: Cow::Borrowed("#text"),
                    value: v,
                }),
            }
            Ok(())
        }
    }
}

/// Position of the first `"` or `\\`, eight bytes at a time (SWAR). JSON
/// strings in event logs are short, where this beats a SIMD search's setup.
#[inline]
fn find_quote_or_backslash(b: &[u8]) -> Option<usize> {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    const Q: u64 = LO * b'"' as u64;
    const BS: u64 = LO * b'\\' as u64;
    let mut i = 0;
    while i + 8 <= b.len() {
        let w = u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let q = w ^ Q;
        let s = w ^ BS;
        // Exact zero-byte detection (no false positives).
        let zq = !(((q & !HI) + !HI) | q | !HI);
        let zs = !(((s & !HI) + !HI) | s | !HI);
        let m = zq | zs;
        if m != 0 {
            return Some(i + (m.trailing_zeros() / 8) as usize);
        }
        i += 8;
    }
    b[i..]
        .iter()
        .position(|&c| c == b'"' || c == b'\\')
        .map(|p| p + i)
}

struct P<'a> {
    s: &'a str,
    b: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    #[cold]
    fn err(&self, msg: &'static str) -> DecodeError {
        DecodeError { pos: self.i, msg }
    }

    #[inline]
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    #[inline]
    fn ws(&mut self) {
        while let Some(&c) = self.b.get(self.i) {
            if matches!(c, b' ' | b'\n' | b'\r' | b'\t') {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    #[inline]
    fn eat(&mut self, c: u8) -> R<()> {
        self.ws();
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.err("unexpected character"))
        }
    }

    /// Iterates an object; `f` receives each key and must consume its value.
    #[inline]
    fn object(&mut self, mut f: impl FnMut(&mut Self, Cow<'a, str>) -> R<()>) -> R<()> {
        self.eat(b'{')?;
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.eat(b':')?;
            f(self, k)?;
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(self.err("expected `,` or `}`")),
            }
        }
    }

    fn array(&mut self, mut f: impl FnMut(&mut Self) -> R<()>) -> R<()> {
        self.eat(b'[')?;
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(());
        }
        loop {
            f(self)?;
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(self.err("expected `,` or `]`")),
            }
        }
    }

    #[inline]
    fn string(&mut self) -> R<Cow<'a, str>> {
        if self.peek() != Some(b'"') {
            return Err(self.err("expected string"));
        }
        let start = self.i + 1;
        let rest = &self.b[start..];
        match find_quote_or_backslash(rest) {
            Some(n) if rest[n] == b'"' => {
                self.i = start + n + 1;
                let s = self
                    .s
                    .get(start..start + n)
                    .ok_or_else(|| self.err("invalid UTF-8"))?;
                Ok(Cow::Borrowed(s))
            }
            Some(n) => self.string_escaped(start, n),
            None => Err(self.err("unterminated string")),
        }
    }

    #[cold]
    fn string_escaped(&mut self, start: usize, first_escape: usize) -> R<Cow<'a, str>> {
        let mut out: Vec<u8> = Vec::with_capacity(first_escape + 16);
        out.extend_from_slice(&self.b[start..start + first_escape]);
        let mut i = start + first_escape;
        loop {
            let rest = &self.b[i..];
            let Some(n) = find_quote_or_backslash(rest) else {
                self.i = self.b.len();
                return Err(self.err("unterminated string"));
            };
            out.extend_from_slice(&rest[..n]);
            i += n;
            if self.b[i] == b'"' {
                self.i = i + 1;
                break;
            }
            let Some(&e) = self.b.get(i + 1) else {
                self.i = i;
                return Err(self.err("bad escape"));
            };
            i += 2;
            match e {
                b'"' => out.push(b'"'),
                b'\\' => out.push(b'\\'),
                b'/' => out.push(b'/'),
                b'b' => out.push(8),
                b'f' => out.push(12),
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'u' => {
                    let hi = self.hex4(i)?;
                    i += 4;
                    let c = if (0xD800..0xDC00).contains(&hi)
                        && self.b.get(i) == Some(&b'\\')
                        && self.b.get(i + 1) == Some(&b'u')
                    {
                        let lo = self.hex4(i + 2)?;
                        if (0xDC00..0xE000).contains(&lo) {
                            i += 6;
                            char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
                        } else {
                            None
                        }
                    } else {
                        char::from_u32(hi)
                    };
                    let c = c.unwrap_or('\u{FFFD}');
                    let mut tmp = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
                }
                _ => {
                    self.i = i;
                    return Err(self.err("bad escape"));
                }
            }
        }
        String::from_utf8(out)
            .map(Cow::Owned)
            .map_err(|_| self.err("invalid UTF-8"))
    }

    fn hex4(&self, at: usize) -> R<u32> {
        let h = self
            .b
            .get(at..at + 4)
            .ok_or_else(|| self.err("short \\u escape"))?;
        let s = std::str::from_utf8(h).map_err(|_| self.err("bad \\u escape"))?;
        u32::from_str_radix(s, 16).map_err(|_| self.err("bad \\u escape"))
    }

    /// A string, number, boolean or null.
    #[inline]
    fn scalar(&mut self) -> R<Val<'a>> {
        self.ws();
        match self.peek() {
            Some(b'"') => self.string().map(Val::Str),
            Some(b't') => self.lit(b"true", Val::Bool(true)),
            Some(b'f') => self.lit(b"false", Val::Bool(false)),
            Some(b'n') => self.lit(b"null", Val::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => {
                let start = self.i;
                while let Some(&c) = self.b.get(self.i) {
                    if c.is_ascii_digit() || matches!(c, b'-' | b'+' | b'.' | b'e' | b'E') {
                        self.i += 1;
                    } else {
                        break;
                    }
                }
                // ASCII by construction.
                Ok(Val::Num(Cow::Borrowed(&self.s[start..self.i])))
            }
            _ => Err(self.err("expected a value")),
        }
    }

    /// A scalar, or `Null` after skipping an object/array in its place.
    fn scalar_or_skip(&mut self) -> R<Val<'a>> {
        self.ws();
        match self.peek() {
            Some(b'{') | Some(b'[') => {
                self.skip()?;
                Ok(Val::Null)
            }
            _ => self.scalar(),
        }
    }

    fn lit(&mut self, word: &[u8], v: Val<'a>) -> R<Val<'a>> {
        if self.b[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.err("bad literal"))
        }
    }

    /// Skips any value.
    fn skip(&mut self) -> R<()> {
        self.ws();
        match self.peek() {
            Some(b'{') => self.object(|p, _| p.skip()),
            Some(b'[') => self.array(|p| p.skip()),
            _ => self.scalar().map(|_| ()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(json: &str) -> EventView<'_> {
        let mut e = EventView::default();
        decode(json.as_bytes(), &mut e).unwrap();
        e
    }

    #[test]
    fn security_4624() {
        let j = r##"{"Event":{"#attributes":{"xmlns":"x"},"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Security-Auditing","Guid":"5"}},"EventID":4624,"Version":2,"Level":0,"Task":12544,"Opcode":0,"Keywords":"0x8020000000000000","TimeCreated":{"#attributes":{"SystemTime":"2016-07-08T18:12:51.681640Z"}},"EventRecordID":2,"Correlation":null,"Execution":{"#attributes":{"ProcessID":456,"ThreadID":460}},"Channel":"Security","Computer":"HOST1","Security":null},"EventData":{"TargetUserName":"SYSTEM","LogonType":5,"IpAddress":"-","Path":"C:\\Windows"}}}"##;
        let e = ev(j);
        assert_eq!(e.event_id, 4624);
        assert_eq!(e.provider, "Microsoft-Windows-Security-Auditing");
        assert_eq!(e.channel, "Security");
        assert_eq!(e.computer, "HOST1");
        assert_eq!(e.process_id, 456);
        assert_eq!(e.ts.iso(), "2016-07-08T18:12:51.681640Z");
        assert_eq!(e.field("TargetUserName").unwrap().as_str(), "SYSTEM");
        assert_eq!(e.field("LogonType").unwrap(), &Val::Num("5".into()));
        assert_eq!(e.field("Path").unwrap().as_str(), "C:\\Windows");
        assert!(matches!(
            e.field("TargetUserName").unwrap(),
            Val::Str(Cow::Borrowed(_))
        ));
    }

    #[test]
    fn qualifiers_data_array_and_userdata() {
        let j = r##"{"Event":{"System":{"Provider":{"#attributes":{"Name":"EventLog"}},"EventID":{"#attributes":{"Qualifiers":32768},"#text":6009},"Channel":"System","Computer":"H","Security":{"#attributes":{"UserID":"S-1-5-18"}}},"EventData":{"Data":{"#text":["10.00.","15063",""]},"Binary":null}}}"##;
        let e = ev(j);
        assert_eq!(e.event_id, 6009);
        assert_eq!(e.user_sid, "S-1-5-18");
        let names: Vec<_> = e.fields.iter().map(|f| f.name.as_ref()).collect();
        assert_eq!(names, ["Data[1]", "Data[2]", "Data[3]", "Binary"]);

        let j = r##"{"Event":{"System":{"EventID":1149,"Channel":"C"},"UserData":{"EventXML":{"#attributes":{"xmlns":"Event_NS"},"Param1":"bob","Param3":"10.0.0.5"}}}}"##;
        let e = ev(j);
        assert_eq!(e.field("Param1").unwrap().as_str(), "bob");
        assert_eq!(e.field("Param3").unwrap().as_str(), "10.0.0.5");
        assert_eq!(e.fields.len(), 2);
    }
}

#[cfg(test)]
mod scanner_tests {
    use super::*;

    #[test]
    fn swar_search() {
        for len in 0..40 {
            for pos in 0..=len {
                let mut v = vec![b'a'; len];
                if pos < len {
                    v[pos] = if pos % 2 == 0 { b'"' } else { b'\\' };
                }
                let want = if pos < len { Some(pos) } else { None };
                assert_eq!(find_quote_or_backslash(&v), want, "len {len} pos {pos}");
            }
        }
        // High bytes (UTF-8) next to the target must not confuse the mask.
        assert_eq!(find_quote_or_backslash("ééé\"x".as_bytes()), Some(6));
        assert_eq!(find_quote_or_backslash(&[0xA2, 0x22]), Some(1));
        assert_eq!(
            find_quote_or_backslash(&[0xDC, 0xDC, 0xDC, 0xDC, 0xDC, 0xDC, 0xDC, 0xDC, 0x5C]),
            Some(8)
        );
    }

    #[test]
    fn escapes_and_errors() {
        let j = r##"{"Event":{"System":{"EventID":1,"Computer":"a\"b\\cé😀"},"EventData":{"X":"line1\nline2","N":-1.5e3,"B":false}}}"##;
        let mut e = EventView::default();
        decode(j.as_bytes(), &mut e).unwrap();
        assert_eq!(e.computer, "a\"b\\cé😀");
        assert_eq!(e.field("X").unwrap().as_str(), "line1\nline2");
        assert_eq!(e.field("N").unwrap(), &Val::Num("-1.5e3".into()));
        assert_eq!(e.field("B").unwrap(), &Val::Bool(false));
        for bad in [
            r#"{"Event":"#,
            r#"{"Event":{"System":{"EventID":1}}"#,
            r#"{"Event":{}} x"#,
            r#"{"Event":{"S":"\q"}}"#,
        ] {
            let mut e = EventView::default();
            assert!(decode(bad.as_bytes(), &mut e).is_err(), "{bad}");
        }
    }
}
