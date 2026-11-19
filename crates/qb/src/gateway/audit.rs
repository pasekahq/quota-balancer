//! The admin audit: each admin action of the gateway appended to its `audit_file` as one JSON
//! line, and those lines read back for `GET /v1/model/audit`.

use std::fs::File;
use std::io::{self, ErrorKind, Write};
use std::ops::ControlFlow;
use std::path::Path;

use qb_proto::{AuditAction, AuditAnswer, AuditEntry, AuditResult};
use serde::Serialize;

use crate::journal::open_append;
use crate::jsonl;
use crate::log;
use crate::server::unix_now;

/// Actor of a reload that SIGHUP asked for.
pub const SIGNAL: &str = "signal";

/// `limit` of a read that names none.
pub const DEFAULT_LIMIT: usize = 100;

/// Largest `limit` of a read.
pub const MAX_LIMIT: usize = 1000;

/// The actor name of the unix socket peer of uid `uid`.
pub(crate) fn uid_actor(uid: u32) -> String {
    format!("uid:{uid}")
}

/// An `ok` entry of `action` by `actor` on `object` at the current time.
pub(crate) fn entry(actor: &str, action: AuditAction, object: Option<String>) -> AuditEntry {
    AuditEntry {
        at: unix_now(),
        actor: actor.to_owned(),
        action,
        object,
        result: AuditResult::Ok,
        reason: None,
        config_sha256_before: None,
        config_sha256_after: None,
        backup: None,
        token_sha256_prefix: None,
        key_sha256_prefix: None,
    }
}

/// `entry` as refused for `reason`.
pub(crate) fn refused(mut entry: AuditEntry, reason: impl Into<String>) -> AuditEntry {
    entry.result = AuditResult::Refused;
    entry.reason = Some(reason.into());
    entry
}

/// Appends `entry` to `file` as one line in one `write`, creating the file with mode 0600. A
/// failure is logged at error priority with the path and never returned, so the action's answer
/// does not depend on it.
pub fn append(file: &Path, entry: &AuditEntry) {
    let written = json_line(entry).and_then(|line| write_line(&mut open_append(file)?, &line));
    if let Err(e) = written {
        log::error(&format!(
            "gateway: audit line not appended to {}: {e}",
            file.display()
        ));
    }
}

/// `value` as one JSON line, newline included.
pub(crate) fn json_line<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    Ok(line)
}

/// Writes `line` to `f` in one `write`, so lines appended at once never interleave.
///
/// # Errors
/// The write failed or was short.
pub(crate) fn write_line(f: &mut File, line: &[u8]) -> io::Result<()> {
    let n = f.write(line)?;
    if n == line.len() {
        Ok(())
    } else {
        let short = format!("wrote {n} of {} bytes", line.len());
        Err(io::Error::new(ErrorKind::WriteZero, short))
    }
}

/// What a read of the audit asks for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Query {
    /// Entries at or after this Unix time.
    pub(crate) since: u64,
    /// Most entries answered, 1 to [`MAX_LIMIT`].
    pub(crate) limit: usize,
}

impl Query {
    /// The query string `query`: `since` (Unix s, default 0) and `limit` (default
    /// [`DEFAULT_LIMIT`]), each at most once.
    ///
    /// # Errors
    /// Another parameter, one given twice, or a value out of range.
    pub(crate) fn parse(query: Option<&str>) -> Result<Self, String> {
        let (mut since, mut limit) = (None, None);
        for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let slot = match key {
                "since" => &mut since,
                "limit" => &mut limit,
                _ => return Err("the query takes only `since` and `limit`".into()),
            };
            if slot.is_some() {
                return Err(format!("`{key}` is given twice"));
            }
            let n = value
                .parse::<u64>()
                .map_err(|_| format!("`{key}` must be a whole number"))?;
            *slot = Some(n);
        }
        let limit = match limit {
            None => DEFAULT_LIMIT,
            Some(n) => usize::try_from(n)
                .ok()
                .filter(|n| (1..=MAX_LIMIT).contains(n))
                .ok_or(format!("`limit` must be 1 to {MAX_LIMIT}"))?,
        };
        Ok(Self {
            since: since.unwrap_or(0),
            limit,
        })
    }
}

/// The first `query.limit` entries of `file` at or after `query.since`, in file order, which is
/// oldest first; a missing file has none. Every line of the file that does not parse as an entry
/// or is longer than [`jsonl::MAX_LINE`] is counted in `skipped`.
///
/// # Errors
/// The file cannot be opened or read.
pub(crate) fn read(file: &Path, query: &Query) -> io::Result<AuditAnswer> {
    let mut entries = Vec::new();
    let skipped = jsonl::read(file, |e: AuditEntry| {
        if e.at >= query.since && entries.len() < query.limit {
            entries.push(e);
        }
        ControlFlow::Continue(())
    })?;
    Ok(AuditAnswer { entries, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_takes_since_and_a_bounded_limit() {
        let parsed = |q: Option<&str>| Query::parse(q).map(|q| (q.since, q.limit));
        assert_eq!(parsed(None), Ok((0, DEFAULT_LIMIT)));
        assert_eq!(parsed(Some("since=1800000000")), Ok((1_800_000_000, 100)));
        assert_eq!(parsed(Some("limit=1000&since=5&")), Ok((5, 1000)));
        for (bad, says) in [
            ("limit=0", "`limit` must be 1 to 1000"),
            ("limit=1001", "`limit` must be 1 to 1000"),
            ("since=-1", "`since` must be a whole number"),
            ("since", "`since` must be a whole number"),
            ("since=1&since=2", "`since` is given twice"),
            ("until=5", "the query takes only `since` and `limit`"),
        ] {
            assert_eq!(parsed(Some(bad)), Err(says.to_owned()), "{bad}");
        }
    }
}
