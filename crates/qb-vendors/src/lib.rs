//! Parsers that turn the quota data vendor CLIs and usage endpoints emit into
//! [`qb_proto::WindowReport`]s.
//!
//! Every parser is pure and total: any byte string yields a value, never a panic. Unknown fields
//! are ignored; a window whose numbers are unusable is dropped. Normalisation rules are in
//! `docs/vendors.md`.

#![forbid(unsafe_code)]

pub mod claude;
pub mod codex;
pub mod rfc3339;

use std::fmt;

use qb_proto::WindowReport;
use serde_json::{Map, Value};

/// Why an input could not be read as quota data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input is not one JSON value.
    NotJson,
    /// A field this source requires is absent or `null`; the payload is its path.
    Missing(&'static str),
    /// A value has the wrong JSON type; the payload is its path (`$` is the top level).
    WrongType(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJson => f.write_str("input is not JSON"),
            Self::Missing(path) => write!(f, "`{path}` is missing"),
            Self::WrongType(path) => write!(f, "`{path}` has the wrong JSON type"),
        }
    }
}

impl std::error::Error for Error {}

/// Absolute Unix times at or above this are read as milliseconds; a reset that still lands at or
/// above it (10^11 s is in year 5138) is unreadable.
pub const MS_THRESHOLD: u64 = 100_000_000_000;

/// How a source states utilisation.
#[derive(Clone, Copy)]
enum Scale {
    Fraction,
    Percent,
}

fn parse_object(input: &[u8]) -> Result<Map<String, Value>, Error> {
    match serde_json::from_slice(input) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(Error::WrongType("$")),
        Err(_) => Err(Error::NotJson),
    }
}

/// The value at `key`, with `null` read as absent.
fn get<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    map.get(key).filter(|v| !v.is_null())
}

/// The object at `key`: `Ok(None)` when absent or `null`, an error for any other type.
fn object<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<Option<&'a Map<String, Value>>, Error> {
    match get(map, key) {
        None => Ok(None),
        Some(Value::Object(inner)) => Ok(Some(inner)),
        Some(_) => Err(Error::WrongType(path)),
    }
}

/// A utilisation in `0.0..=1.0`, or `None` for a non-number, non-finite or negative value.
fn utilization(value: &Value, scale: Scale) -> Option<f64> {
    let raw = value.as_f64().filter(|u| u.is_finite() && *u >= 0.0)?;
    let fraction = match scale {
        Scale::Fraction => raw,
        Scale::Percent => raw / 100.0,
    };
    Some(fraction.min(1.0))
}

/// A non-negative JSON number as whole seconds, rounded down; `None` if it does not fit `u64`.
fn whole(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    let f = value.as_f64()?;
    if !(0.0..18_446_744_073_709_551_616.0).contains(&f) {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "range checked above; truncation rounds down"
    )]
    Some(f as u64)
}

/// An absolute numeric Unix time in seconds, or in milliseconds when at or above [`MS_THRESHOLD`].
fn unix_time(value: &Value) -> Option<u64> {
    let n = whole(value)?;
    if n < MS_THRESHOLD {
        Some(n)
    } else {
        Some(n / 1000).filter(|s| *s < MS_THRESHOLD)
    }
}

/// `base` plus a relative number of seconds.
fn after(base: u64, value: &Value) -> Option<u64> {
    base.checked_add(whole(value)?)
        .filter(|s| *s < MS_THRESHOLD)
}

/// Window name and `length_s` of a Codex window that lasts `minutes`.
fn codex_window(minutes: u64) -> Option<(String, u32)> {
    if minutes == 0 {
        return None;
    }
    let length_s = u32::try_from(minutes.checked_mul(60)?).ok()?;
    let name = match minutes {
        300 => "five_hour".to_owned(),
        10_080 => "seven_day".to_owned(),
        m => format!("window_{m}m"),
    };
    Some((name, length_s))
}

/// `length_s` of a Claude window key: `five_hour`, `seven_day` or `seven_day_<model>`.
fn claude_length(name: &str) -> Option<u32> {
    const FIVE_HOURS: u32 = 5 * 3600;
    const SEVEN_DAYS: u32 = 7 * 86_400;
    if name == "five_hour" {
        Some(FIVE_HOURS)
    } else if name == "seven_day"
        || name
            .strip_prefix("seven_day_")
            .is_some_and(|m| !m.is_empty())
    {
        Some(SEVEN_DAYS)
    } else {
        None
    }
}

/// Claude windows from the object `windows`: one per recognised key whose entry parses, by name.
fn claude_windows(
    windows: &Map<String, Value>,
    entry: impl Fn(&Map<String, Value>) -> Option<(f64, Option<u64>)>,
) -> Vec<WindowReport> {
    let mut out: Vec<WindowReport> = windows
        .iter()
        .filter_map(|(name, value)| {
            let length_s = claude_length(name)?;
            let (utilization, resets_at) = entry(value.as_object()?)?;
            Some(WindowReport {
                name: name.clone(),
                utilization,
                resets_at,
                length_s: Some(length_s),
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// A reset field that is present but unreadable; its window is dropped.
struct Unreadable;

/// `Ok(None)` for an absent or `null` reset.
fn resets(
    entry: &Map<String, Value>,
    key: &str,
    read: impl Fn(&Value) -> Option<u64>,
) -> Result<Option<u64>, Unreadable> {
    match get(entry, key) {
        None => Ok(None),
        Some(v) => read(v).map(Some).ok_or(Unreadable),
    }
}
