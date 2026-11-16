//! Codex sources: session rollout JSONL lines and `wham/usage` responses.

use qb_proto::WindowReport;
use serde_json::{Map, Value};

use crate::{
    Error, Scale, after, codex_window, get, object, parse_object, resets, rfc3339, unix_time,
    utilization,
};

/// Parses one rollout line; `Ok(None)` means it has no `payload.rate_limits` or
/// `payload.info.rate_limits`. `resets_in_seconds` counts from the line's `timestamp`, else `now`.
///
/// # Errors
/// [`Error::NotJson`] for non-JSON, [`Error::WrongType`] for a non-object line, `payload`,
/// `payload.info` or `rate_limits`.
pub fn rollout_line(line: &[u8], now: u64) -> Result<Option<Vec<WindowReport>>, Error> {
    let map = parse_object(line)?;
    let Some(payload) = object(&map, "payload", "payload")? else {
        return Ok(None);
    };
    let limits = match object(payload, "rate_limits", "payload.rate_limits")? {
        Some(limits) => limits,
        None => match object(payload, "info", "payload.info")? {
            Some(info) => match object(info, "rate_limits", "payload.info.rate_limits")? {
                Some(limits) => limits,
                None => return Ok(None),
            },
            None => return Ok(None),
        },
    };
    let base = get(&map, "timestamp")
        .and_then(Value::as_str)
        .and_then(|t| rfc3339::parse(t).ok())
        .unwrap_or(now);
    let window = |entry: &Map<String, Value>| {
        let (name, length_s) = codex_window(get(entry, "window_minutes")?.as_u64()?)?;
        let at = match resets(entry, "resets_at", unix_time).ok()? {
            Some(at) => Some(at),
            None => resets(entry, "resets_in_seconds", |v| after(base, v)).ok()?,
        };
        report(entry, name, length_s, at)
    };
    Ok(Some(windows(limits, ["primary", "secondary"], window)))
}

/// Parses a `wham/usage` response body; `reset_after_seconds` counts from `now`.
///
/// # Errors
/// [`Error::NotJson`] for non-JSON, [`Error::WrongType`] for a non-object body or `rate_limit`.
pub fn usage(body: &[u8], now: u64) -> Result<Vec<WindowReport>, Error> {
    let map = parse_object(body)?;
    let Some(limits) = object(&map, "rate_limit", "rate_limit")? else {
        return Ok(Vec::new());
    };
    let window = |entry: &Map<String, Value>| {
        let seconds = get(entry, "limit_window_seconds")?.as_u64()?;
        if seconds % 60 != 0 {
            return None;
        }
        let (name, length_s) = codex_window(seconds / 60)?;
        let at = match resets(entry, "reset_at", unix_time).ok()? {
            Some(at) => Some(at),
            None => resets(entry, "reset_after_seconds", |v| after(now, v)).ok()?,
        };
        report(entry, name, length_s, at)
    };
    Ok(windows(
        limits,
        ["primary_window", "secondary_window"],
        window,
    ))
}

fn windows(
    limits: &Map<String, Value>,
    keys: [&str; 2],
    window: impl Fn(&Map<String, Value>) -> Option<WindowReport>,
) -> Vec<WindowReport> {
    keys.iter()
        .filter_map(|key| window(get(limits, key)?.as_object()?))
        .collect()
}

fn report(
    entry: &Map<String, Value>,
    name: String,
    length_s: u32,
    resets_at: Option<u64>,
) -> Option<WindowReport> {
    Some(WindowReport {
        name,
        utilization: utilization(get(entry, "used_percent")?, Scale::Percent)?,
        resets_at,
        length_s: Some(length_s),
    })
}
