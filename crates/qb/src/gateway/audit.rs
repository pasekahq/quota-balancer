//! The admin audit: each admin action of the gateway appended to its `audit_file` as one JSON
//! line, and those lines read back for `GET /v1/model/audit`.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use qb_proto::{AuditAction, AuditAnswer, AuditEntry, AuditResult};

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
    let written = serde_json::to_vec(entry)
        .map_err(io::Error::from)
        .and_then(|mut line| {
            line.push(b'\n');
            let mut f = OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(file)?;
            let n = f.write(&line)?;
            if n == line.len() {
                Ok(())
            } else {
                let short = format!("wrote {n} of {} bytes", line.len());
                Err(io::Error::new(ErrorKind::WriteZero, short))
            }
        });
    if let Err(e) = written {
        log::error(&format!(
            "gateway: audit line not appended to {}: {e}",
            file.display()
        ));
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
/// is counted in `skipped`.
///
/// # Errors
/// The file cannot be opened or read.
pub(crate) fn read(file: &Path, query: &Query) -> io::Result<AuditAnswer> {
    let mut answer = AuditAnswer {
        entries: Vec::new(),
        skipped: 0,
    };
    let f = match File::open(file) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(answer),
        Err(e) => return Err(e),
    };
    let mut reader = BufReader::new(f);
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(answer);
        }
        let text = line.strip_suffix(b"\n").unwrap_or(&line);
        match serde_json::from_slice::<AuditEntry>(text) {
            Ok(e) if e.at >= query.since && answer.entries.len() < query.limit => {
                answer.entries.push(e);
            }
            Ok(_) => {}
            Err(_) => answer.skipped += 1,
        }
    }
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
