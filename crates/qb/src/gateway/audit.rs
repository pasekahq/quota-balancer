//! The admin audit: each admin action of the gateway appended to its `audit_file` as one JSON
//! line, and those lines read back for `GET /v1/model/audit`.

use std::fs::{File, Metadata, Permissions};
use std::io::{self, ErrorKind, Write};
use std::ops::ControlFlow;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use qb_proto::{AuditAction, AuditAnswer, AuditEntry, AuditResult};
use serde::Serialize;

use crate::journal::open_append;
use crate::log;
use crate::server::unix_now;
use crate::{http, jsonl};

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

/// Narrows an existing regular `file` whose mode lets its group or others in to 0600 and logs a
/// warning when it did; a missing file or one of another kind is left alone. Called at startup
/// and on each reload: `append` creates the file 0600, but an older file keeps its mode.
///
/// # Errors
/// The file's mode cannot be read or changed; the message names the file.
pub fn narrow(file: &Path) -> Result<(), String> {
    let meta = match std::fs::metadata(file) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        meta => meta,
    };
    meta.and_then(|m| narrowed(file, &m, |p| std::fs::set_permissions(file, p)))
        .map_err(|e| format!("audit_file {}: {e}", file.display()))
}

/// Applies 0600 through `set` when `meta`, the metadata of the regular file `file`, gives the
/// group or others any bit, and logs it.
fn narrowed(
    file: &Path,
    meta: &Metadata,
    set: impl FnOnce(Permissions) -> io::Result<()>,
) -> io::Result<()> {
    let mode = meta.mode() & 0o7777;
    let wide = mode & 0o077 != 0;
    if !(meta.is_file() && wide) {
        return Ok(());
    }
    set(Permissions::from_mode(0o600)).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("mode {mode:04o} is wider than 0600 and cannot be narrowed: {e}"),
        )
    })?;
    log::warn(&format!(
        "gateway: audit_file {} had mode {mode:04o}; narrowed to 0600",
        file.display()
    ));
    Ok(())
}

/// Appends `entry` to `file` as one line in one `write`, creating the file with mode 0600 and
/// narrowing an existing one to it first, as [`narrow`] does; a file that cannot be narrowed
/// still gets the line. A failure is logged at error priority with the path and never returned,
/// so the action's answer does not depend on it.
pub fn append(file: &Path, entry: &AuditEntry) {
    let written = json_line(entry).and_then(|line| {
        let mut f = open_append(file)?;
        // A file that stays wide still gets the line: losing the record is worse.
        let meta = f.metadata()?;
        if let Err(e) = narrowed(file, &meta, |p| f.set_permissions(p)) {
            log::error(&format!("gateway: audit_file {}: {e}", file.display()));
        }
        write_line(&mut f, &line)
    });
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
        let [since, limit] = http::query_params(query, ["since", "limit"])?;
        let limit = match limit {
            None => DEFAULT_LIMIT,
            Some(v) => usize::try_from(http::whole_number("limit", v)?)
                .ok()
                .filter(|n| (1..=MAX_LIMIT).contains(n))
                .ok_or(format!("`limit` must be 1 to {MAX_LIMIT}"))?,
        };
        Ok(Self {
            since: since.map_or(Ok(0), |v| http::whole_number("since", v))?,
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
    fn an_append_narrows_a_wide_file_and_narrow_leaves_other_kinds_alone() {
        let dir = crate::testdir::new("audit");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().mode() & 0o7777;
        let file = dir.join("audit.jsonl");
        std::fs::write(&file, "").unwrap();
        std::fs::set_permissions(&file, Permissions::from_mode(0o644)).unwrap();
        append(&file, &entry("uid:1000", AuditAction::Reload, None));
        assert_eq!(mode(&file), 0o600);
        assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 1);

        std::fs::set_permissions(&file, Permissions::from_mode(0o400)).unwrap();
        assert_eq!(narrow(&file), Ok(()));
        assert_eq!(mode(&file), 0o400, "a narrower mode stays");
        assert_eq!(narrow(&dir.join("missing.jsonl")), Ok(()));
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::set_permissions(&sub, Permissions::from_mode(0o755)).unwrap();
        assert_eq!(narrow(&sub), Ok(()));
        assert_eq!(
            mode(&sub),
            0o755,
            "a directory is not the audit's to narrow"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

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
            (
                "until=5",
                "unknown parameter `until`: the query takes `since` and `limit`",
            ),
        ] {
            assert_eq!(parsed(Some(bad)), Err(says.to_owned()), "{bad}");
        }
    }
}
