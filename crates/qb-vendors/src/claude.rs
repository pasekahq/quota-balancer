//! Claude sources: stream-json `rate_limit_event` lines, statusline input and `oauth/usage`.

use qb_proto::WindowReport;
use serde_json::Value;

use crate::{
    Error, Scale, claude_windows, get, object, parse_object, resets, rfc3339, unix_time,
    utilization,
};

/// One `rate_limit_event` of a stream-json run.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// `rate_limit_info.status` as sent: `allowed`, `allowed_warning`, `rejected` or another value.
    pub status: String,
    /// The parsed windows of `rate_limit_info.unifiedWindows`.
    pub windows: Vec<WindowReport>,
}

/// Parses one stream-json line; `Ok(None)` means the line is not a `rate_limit_event`.
///
/// # Errors
/// [`Error::NotJson`] for non-JSON, [`Error::WrongType`] for a non-object line or a mistyped
/// `rate_limit_info`, `status` or `unifiedWindows`, [`Error::Missing`] without them.
pub fn stream_line(line: &[u8]) -> Result<Option<Event>, Error> {
    let map = parse_object(line)?;
    if get(&map, "type").and_then(Value::as_str) != Some("rate_limit_event") {
        return Ok(None);
    }
    let info = object(&map, "rate_limit_info", "rate_limit_info")?
        .ok_or(Error::Missing("rate_limit_info"))?;
    let status = match get(info, "status") {
        None => return Err(Error::Missing("rate_limit_info.status")),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err(Error::WrongType("rate_limit_info.status")),
    };
    let windows = object(info, "unifiedWindows", "rate_limit_info.unifiedWindows")?
        .map(|w| {
            claude_windows(w, |entry| {
                let used = utilization(get(entry, "utilization")?, Scale::Fraction)?;
                Some((used, resets(entry, "resetsAt", unix_time).ok()?))
            })
        })
        .unwrap_or_default();
    Ok(Some(Event { status, windows }))
}

/// Parses statusline input; `Ok(None)` means it carries no `rate_limits`.
///
/// # Errors
/// [`Error::NotJson`] for non-JSON, [`Error::WrongType`] for a non-object input or `rate_limits`.
pub fn statusline(input: &[u8]) -> Result<Option<Vec<WindowReport>>, Error> {
    let map = parse_object(input)?;
    Ok(object(&map, "rate_limits", "rate_limits")?.map(|w| {
        claude_windows(w, |entry| {
            let used = utilization(get(entry, "used_percentage")?, Scale::Percent)?;
            Some((used, resets(entry, "resets_at", unix_time).ok()?))
        })
    }))
}

/// Parses an `oauth/usage` response body; `null` and unrecognised keys give no window.
///
/// # Errors
/// [`Error::NotJson`] for non-JSON, [`Error::WrongType`] for a non-object body.
pub fn usage(body: &[u8]) -> Result<Vec<WindowReport>, Error> {
    let map = parse_object(body)?;
    Ok(claude_windows(&map, |entry| {
        let used = utilization(get(entry, "utilization")?, Scale::Percent)?;
        let at = |v: &Value| rfc3339::parse(v.as_str()?).ok();
        Some((used, resets(entry, "resets_at", at).ok()?))
    }))
}
