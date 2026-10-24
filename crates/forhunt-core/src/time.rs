//! Compact UTC timestamps (100 ns ticks since the Unix epoch, the FILETIME
//! resolution; i64 covers years -27000 to 31000) with a fast
//! ISO 8601 parser and formatter for the hot path.

use std::fmt;

/// 100-nanosecond ticks since 1970-01-01T00:00:00Z.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ts(pub i64);

const TICKS_PER_SEC: i64 = 10_000_000;

impl Ts {
    pub const MIN: Ts = Ts(i64::MIN);
    pub const MAX: Ts = Ts(i64::MAX);

    pub fn from_jiff(t: jiff::Timestamp) -> Ts {
        Ts((t.as_nanosecond() / 100) as i64)
    }

    pub fn to_jiff(self) -> jiff::Timestamp {
        jiff::Timestamp::from_nanosecond(self.0 as i128 * 100)
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
    }

    pub fn secs(self) -> i64 {
        self.0.div_euclid(TICKS_PER_SEC)
    }

    /// Parses `YYYY-MM-DDTHH:MM:SS[.fffffffff][Z]` (the format EVTX renders for
    /// `SystemTime`). Falls back to jiff for anything else (offsets, dates only).
    pub fn parse(s: &str) -> Option<Ts> {
        fast_parse(s.as_bytes()).or_else(|| slow_parse(s))
    }

    /// Writes `YYYY-MM-DDTHH:MM:SS.ffffffZ` (microseconds, UTC) into `out`.
    pub fn write_iso(self, out: &mut Vec<u8>) {
        let secs = self.0.div_euclid(TICKS_PER_SEC);
        let ticks = self.0.rem_euclid(TICKS_PER_SEC);
        let days = secs.div_euclid(86_400);
        let sod = secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        let mut buf = [0u8; 27];
        if !(0..=9999).contains(&y) {
            // Out of range for the fixed layout: let jiff deal with it.
            out.extend_from_slice(self.to_jiff().to_string().as_bytes());
            return;
        }
        put4(&mut buf[0..4], y as u32);
        buf[4] = b'-';
        put2(&mut buf[5..7], m);
        buf[7] = b'-';
        put2(&mut buf[8..10], d);
        buf[10] = b'T';
        put2(&mut buf[11..13], (sod / 3600) as u32);
        buf[13] = b':';
        put2(&mut buf[14..16], ((sod / 60) % 60) as u32);
        buf[16] = b':';
        put2(&mut buf[17..19], (sod % 60) as u32);
        buf[19] = b'.';
        let micros = (ticks / 10) as u32;
        put2(&mut buf[20..22], micros / 10_000);
        put2(&mut buf[22..24], (micros / 100) % 100);
        put2(&mut buf[24..26], micros % 100);
        buf[26] = b'Z';
        out.extend_from_slice(&buf);
    }

    /// Formats in a display time zone (RFC 3339 with offset). Slow path, only
    /// used when `--tz` is set.
    pub fn write_in_tz(self, tz: &jiff::tz::TimeZone, out: &mut Vec<u8>) {
        let zoned = self.to_jiff().to_zoned(tz.clone());
        let s = zoned.strftime("%Y-%m-%dT%H:%M:%S%.6f%:z").to_string();
        out.extend_from_slice(s.as_bytes());
    }

    pub fn iso(self) -> String {
        let mut v = Vec::with_capacity(27);
        self.write_iso(&mut v);
        String::from_utf8(v).expect("ascii")
    }
}

impl fmt::Display for Ts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.iso())
    }
}

#[inline]
fn put2(dst: &mut [u8], v: u32) {
    dst[0] = b'0' + (v / 10 % 10) as u8;
    dst[1] = b'0' + (v % 10) as u8;
}

#[inline]
fn put4(dst: &mut [u8], v: u32) {
    put2(&mut dst[0..2], v / 100);
    put2(&mut dst[2..4], v % 100);
}

#[inline]
fn digits(b: &[u8]) -> Option<i64> {
    let mut v = 0i64;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as i64;
    }
    Some(v)
}

fn fast_parse(b: &[u8]) -> Option<Ts> {
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let y = digits(&b[0..4])?;
    let mo = digits(&b[5..7])?;
    let d = digits(&b[8..10])?;
    let h = digits(&b[11..13])?;
    let mi = digits(&b[14..16])?;
    let s = digits(&b[17..19])?;
    if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let mut rest = &b[19..];
    let mut ticks = 0i64;
    if let Some((&b'.', frac)) = rest.split_first() {
        let n = frac.iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return None;
        }
        let mut scale = 1_000_000i64;
        for &c in &frac[..n.min(7)] {
            ticks += (c - b'0') as i64 * scale;
            scale /= 10;
        }
        rest = &frac[n..];
    }
    match rest {
        b"" | b"Z" | b"z" => {}
        _ => return None,
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    let secs = days * 86_400 + h * 3600 + mi * 60 + s;
    Some(Ts(secs.checked_mul(TICKS_PER_SEC)?.checked_add(ticks)?))
}

fn slow_parse(s: &str) -> Option<Ts> {
    if let Ok(t) = s.parse::<jiff::Timestamp>() {
        return Some(Ts::from_jiff(t));
    }
    // A bare date or a civil datetime without offset is taken as UTC.
    if let Ok(dt) = s.parse::<jiff::civil::DateTime>() {
        return dt
            .to_zoned(jiff::tz::TimeZone::UTC)
            .ok()
            .map(|z| Ts::from_jiff(z.timestamp()));
    }
    if let Ok(d) = s.parse::<jiff::civil::Date>() {
        return d
            .to_zoned(jiff::tz::TimeZone::UTC)
            .ok()
            .map(|z| Ts::from_jiff(z.timestamp()));
    }
    None
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's civil date algorithms.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let t = Ts::parse("2016-07-08T18:12:51.681640Z").unwrap();
        assert_eq!(t.iso(), "2016-07-08T18:12:51.681640Z");
        let j: jiff::Timestamp = "2016-07-08T18:12:51.68164Z".parse().unwrap();
        assert_eq!(t, Ts::from_jiff(j));
    }

    #[test]
    fn leap_and_epoch() {
        assert_eq!(Ts::parse("1970-01-01T00:00:00Z").unwrap(), Ts(0));
        let t = Ts::parse("2024-02-29T23:59:59.999999Z").unwrap();
        assert_eq!(t.iso(), "2024-02-29T23:59:59.999999Z");
        assert_eq!(
            Ts::parse("1601-01-01T00:00:00Z").unwrap().iso(),
            "1601-01-01T00:00:00.000000Z"
        );
    }

    #[test]
    fn slow_formats() {
        assert_eq!(
            Ts::parse("2024-03-01").unwrap().iso(),
            "2024-03-01T00:00:00.000000Z"
        );
        assert_eq!(
            Ts::parse("2024-03-01T02:00:00+02:00").unwrap().iso(),
            "2024-03-01T00:00:00.000000Z"
        );
        assert!(Ts::parse("garbage").is_none());
    }

    #[test]
    fn impossible_dates_are_rejected() {
        // A typo must not silently move a --since/--until window.
        assert!(Ts::parse("2025-02-30T10:00:00Z").is_none());
        assert!(Ts::parse("2025-09-31T10:00:00Z").is_none());
        assert!(Ts::parse("2023-02-29T10:00:00Z").is_none());
        assert!(Ts::parse("2024-02-29T10:00:00Z").is_some());
        assert!(Ts::parse("2000-02-29 10:00:00").is_some());
        assert!(Ts::parse("1900-02-29T10:00:00Z").is_none());
    }
}
