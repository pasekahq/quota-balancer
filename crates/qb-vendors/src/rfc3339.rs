//! RFC 3339 timestamps to Unix seconds, without a date library.

use std::fmt;

/// The text is not an RFC 3339 date-time at or after the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTimestamp;

impl fmt::Display for InvalidTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not an RFC 3339 timestamp at or after 1970-01-01T00:00:00Z")
    }
}

impl std::error::Error for InvalidTimestamp {}

/// Parses `YYYY-MM-DDTHH:MM:SS[.frac](Z|±hh:mm)` into Unix seconds, rounding fractions down.
///
/// `T`/`Z` may be lowercase and `T` may be a space; a leap second `60` is accepted.
///
/// # Errors
/// [`InvalidTimestamp`] for any other shape, an impossible date or time, or a time before 1970.
pub fn parse(text: &str) -> Result<u64, InvalidTimestamp> {
    let b = text.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return Err(InvalidTimestamp);
    }
    if !matches!(b[10], b'T' | b't' | b' ') {
        return Err(InvalidTimestamp);
    }
    let year = digits(&b[0..4])?;
    let month = digits(&b[5..7])?;
    let day = digits(&b[8..10])?;
    let hour = digits(&b[11..13])?;
    let minute = digits(&b[14..16])?;
    let second = digits(&b[17..19])?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(InvalidTimestamp);
    }
    let mut rest = &b[19..];
    if let Some(frac) = rest.strip_prefix(b".") {
        let len = frac.iter().take_while(|c| c.is_ascii_digit()).count();
        if len == 0 {
            return Err(InvalidTimestamp);
        }
        rest = &frac[len..];
    }
    let offset = match rest {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let (h, m) = (digits(&[*h1, *h2])?, digits(&[*m1, *m2])?);
            if h > 23 || m > 59 {
                return Err(InvalidTimestamp);
            }
            let secs = i64::from(h * 3600 + m * 60);
            if *sign == b'+' { secs } else { -secs }
        }
        _ => return Err(InvalidTimestamp),
    };
    let local =
        days_from_civil(year, month, day) * 86_400 + i64::from(hour * 3600 + minute * 60 + second);
    u64::try_from(local - offset).map_err(|_| InvalidTimestamp)
}

fn digits(b: &[u8]) -> Result<u32, InvalidTimestamp> {
    b.iter().try_fold(0, |acc, c| {
        if c.is_ascii_digit() {
            Ok(acc * 10 + u32::from(c - b'0'))
        } else {
            Err(InvalidTimestamp)
        }
    })
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Hinnant's `days_from_civil`).
fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    let y = i64::from(year) - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
