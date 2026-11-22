//! The usage ledger: one JSON line per adapter attempt appended to `usage.file`, which is renamed
//! to `<file>.<unix s>` before a line would take it past `rotate_bytes`; rotated files older
//! than `keep_days` are removed at each rotation. `GET /v1/model/usage` sums the lines back by
//! period and group.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io;
use std::ops::ControlFlow;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use qb_proto::gateway::{MAX_USAGE_ROWS, MAX_USAGE_WINDOW_S};
use qb_proto::{Outcome, UsageAnswer, UsageBucket, UsageGroupBy, UsageLine, UsageQuery, UsageRow};

use super::audit::{json_line, write_line};
use super::config::UsageLedger;
use super::spend;
use crate::journal::open_append;
use crate::{http, jsonl, log};

/// The ledger files of one gateway; appends and rotations take turns.
#[derive(Debug)]
pub struct Ledger {
    config: UsageLedger,
    one: Mutex<()>,
}

impl Ledger {
    /// The ledger kept as `config` says.
    pub fn new(config: UsageLedger) -> Self {
        Self {
            config,
            one: Mutex::new(()),
        }
    }

    /// Appends `line` as of `now` in one `write`, creating the file with mode 0600 and rotating
    /// first when the line would take a non-empty file past `rotate_bytes`. A failure is logged
    /// at error priority with the path and never returned, so the turn does not depend on it.
    pub fn append(&self, line: &UsageLine, now: u64) {
        let _one = self
            .one
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = self.write(line, now) {
            log::error(&format!(
                "gateway: usage line not appended to {}: {e}",
                self.config.file.display()
            ));
        }
    }

    fn write(&self, line: &UsageLine, now: u64) -> io::Result<()> {
        let file = &self.config.file;
        let line = json_line(line)?;
        let mut f = open_append(file)?;
        let len = f.metadata()?.len();
        if len > 0 && len + line.len() as u64 > self.config.rotate_bytes {
            drop(f);
            std::fs::rename(file, free_stamp(file, now)?)?;
            self.prune(now);
            f = open_append(file)?;
        }
        write_line(&mut f, &line)
    }

    /// Removes the rotated files whose stamp lies more than `keep_days` before `now`; failures
    /// are logged at error priority.
    fn prune(&self, now: u64) {
        let file = &self.config.file;
        let keep_s = u64::from(self.config.keep_days) * 86_400;
        let expired = rotated(file).map(|files| {
            files
                .into_iter()
                .filter(|(stamp, _)| now.saturating_sub(*stamp) > keep_s)
        });
        let removed = expired.and_then(|mut files| {
            files.try_for_each(|(_, path)| match std::fs::remove_file(&path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            })
        });
        if let Err(e) = removed {
            log::error(&format!(
                "gateway: expired usage files beside {} not removed: {e}",
                file.display()
            ));
        }
    }
}

/// The rotated files of the ledger `file`: `(stamp, path)` of each regular file (or link to one)
/// `<file>.<unix s>` beside it, oldest first; a directory or other kind of that name is no
/// rotated file and is left out.
///
/// # Errors
/// The directory cannot be read.
pub fn rotated(file: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let (Some(dir), Some(name)) = (file.parent(), file.file_name()) else {
        return Ok(Vec::new());
    };
    let mut prefix = name.to_owned();
    prefix.push(".");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Some(stamp) = stamp_of(&entry.file_name(), &prefix) else {
            continue;
        };
        let path = entry.path();
        if std::fs::metadata(&path).is_ok_and(|m| m.is_file()) {
            files.push((stamp, path));
        }
    }
    files.sort();
    Ok(files)
}

/// The stamp of `name` when it is `prefix` followed by decimal digits only.
fn stamp_of(name: &OsString, prefix: &OsString) -> Option<u64> {
    let digits = name.to_str()?.strip_prefix(prefix.to_str()?)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// `<file>.<stamp>` for the first stamp from `now` on that names no file yet, so a second
/// rotation within one second keeps the first.
fn free_stamp(file: &Path, now: u64) -> io::Result<PathBuf> {
    let mut stamp = now;
    loop {
        let mut name = file.as_os_str().to_owned();
        name.push(format!(".{stamp}"));
        let path = PathBuf::from(name);
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(path),
            Err(e) => return Err(e),
            Ok(_) => stamp += 1,
        }
    }
}

/// The query string `query` of `GET /v1/model/usage`: `from` (required), `to`, `group_by` and
/// `bucket`, each at most once.
///
/// # Errors
/// A message naming the parameter that is unknown, given twice, missing or invalid.
pub(crate) fn parse_query(query: Option<&str>) -> Result<UsageQuery, String> {
    let [from, to, group_by, bucket] =
        http::query_params(query, ["from", "to", "group_by", "bucket"])?;
    let from = http::whole_number("from", from.ok_or("`from` is required")?)?;
    Ok(UsageQuery {
        from,
        to: to.map(|v| http::whole_number("to", v)).transpose()?,
        group_by: group_by
            .map(|v| named("group_by", v, UsageGroupBy::ALL, UsageGroupBy::as_str))
            .transpose()?,
        bucket: bucket
            .map(|v| named("bucket", v, UsageBucket::ALL, UsageBucket::as_str))
            .transpose()?,
    })
}

/// The one of `all` whose `name` is `value` of parameter `key`.
fn named<T: Copy, const N: usize>(
    key: &str,
    value: &str,
    all: [T; N],
    name: fn(T) -> &'static str,
) -> Result<T, String> {
    all.into_iter().find(|v| name(*v) == value).ok_or_else(|| {
        let names: Vec<&str> = all.into_iter().map(name).collect();
        format!("`{key}` must be one of {}", names.join(", "))
    })
}

/// The exclusive end of the window of `query`, `now` when it names no `to`.
///
/// # Errors
/// The end is not after `from` or lies more than [`MAX_USAGE_WINDOW_S`] after it.
pub(crate) fn window_end(query: &UsageQuery, now: u64) -> Result<u64, String> {
    let to = query.to.unwrap_or(now);
    if to <= query.from {
        return Err(match query.to {
            Some(_) => "`to` must be after `from`".into(),
            None => "`from` must lie before now, the default `to`".into(),
        });
    }
    if to - query.from > MAX_USAGE_WINDOW_S {
        let days = MAX_USAGE_WINDOW_S / 86_400;
        return Err(format!(
            "`from` and `to` must lie at most {days} days apart"
        ));
    }
    Ok(to)
}

/// Why a usage aggregate has no answer.
#[derive(Debug)]
pub(crate) enum AggregateError {
    /// It would have more than [`MAX_USAGE_ROWS`] rows.
    TooManyRows,
    /// A ledger file cannot be listed, opened or read.
    Io(io::Error),
}

/// The sums of the lines of the ledger `file` with `at` from `query.from` up to `to`, read from
/// `file` and the rotated files whose stamp is at or after `query.from`; a missing file counts
/// as empty. The current file is opened before the rotated files are listed and a rotated file
/// that is the one opened is not read twice, so a rotation during the read neither hides nor
/// doubles a line, and appends never wait for a read.
///
/// # Errors
/// More than [`MAX_USAGE_ROWS`] rows, or a ledger file that cannot be listed or read.
pub(crate) fn aggregate(
    file: &Path,
    query: &UsageQuery,
    to: u64,
) -> Result<UsageAnswer, AggregateError> {
    aggregate_paced(file, query, to, || ())
}

/// [`aggregate`], calling `pause` once the current file is open and again once the rotated
/// files are listed, before any is read.
fn aggregate_paced(
    file: &Path,
    query: &UsageQuery,
    to: u64,
    mut pause: impl FnMut(),
) -> Result<UsageAnswer, AggregateError> {
    let from = query.from;
    let current = jsonl::open(file).map_err(AggregateError::Io)?;
    let current_id = current
        .as_ref()
        .map(|f| f.metadata().map(|m| (m.dev(), m.ino())))
        .transpose()
        .map_err(AggregateError::Io)?;
    pause();
    let rotated: Vec<PathBuf> = match rotated(file) {
        Ok(files) => files
            .into_iter()
            .filter(|(stamp, _)| *stamp >= from)
            .map(|(_, path)| path)
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(AggregateError::Io(e)),
    };
    pause();
    let mut files = Vec::new();
    for path in &rotated {
        // Removed since the listing (pruned) or not a regular file now: nothing to read.
        let Some(f) = jsonl::open(path).map_err(AggregateError::Io)? else {
            continue;
        };
        let meta = f.metadata().map_err(AggregateError::Io)?;
        if meta.is_file() && Some((meta.dev(), meta.ino())) != current_id {
            files.push(f);
        }
    }
    files.extend(current);
    let mut rows = BTreeMap::new();
    let mut skipped = 0;
    for f in files {
        let mut full = false;
        skipped += jsonl::read_from(f, |line: UsageLine| {
            if !(from..to).contains(&line.at) {
                return ControlFlow::Continue(());
            }
            let start = bucket_start(query.bucket, from, line.at);
            for group in groups(query.group_by, &line) {
                let key = (start, group);
                if !rows.contains_key(&key) && rows.len() >= MAX_USAGE_ROWS {
                    full = true;
                    return ControlFlow::Break(());
                }
                let group = key.1.clone();
                add(rows.entry(key).or_insert_with(|| row(start, group)), &line);
            }
            ControlFlow::Continue(())
        })
        .map_err(AggregateError::Io)?;
        if full {
            return Err(AggregateError::TooManyRows);
        }
    }
    Ok(UsageAnswer {
        from,
        to,
        group_by: query.group_by,
        bucket: query.bucket,
        rows: rows.into_values().collect(),
        skipped,
    })
}

/// Start of the UTC `bucket` holding `at`; `from` without a bucket.
fn bucket_start(bucket: Option<UsageBucket>, from: u64, at: u64) -> u64 {
    match bucket {
        None => from,
        Some(UsageBucket::Hour) => at - at % 3_600,
        Some(UsageBucket::Day) => at - at % 86_400,
        Some(UsageBucket::Month) => spend::month(at).0,
    }
}

/// The groups `line` counts under: none without `group_by`, each unique tool name for `tool`.
fn groups(group_by: Option<UsageGroupBy>, line: &UsageLine) -> Vec<Option<String>> {
    let one = |value: &String| vec![Some(value.clone())];
    match group_by {
        None => vec![None],
        Some(UsageGroupBy::Client) => one(&line.client),
        Some(UsageGroupBy::Login) => one(&line.login),
        Some(UsageGroupBy::Model) => one(&line.model),
        Some(UsageGroupBy::Route) => one(&line.route),
        Some(UsageGroupBy::Tool) => {
            let tools: BTreeSet<&String> = line.tools.iter().collect();
            tools.into_iter().map(|t| Some(t.clone())).collect()
        }
    }
}

/// An empty row of bucket `start` and `group`.
fn row(start: u64, group: Option<String>) -> UsageRow {
    UsageRow {
        start,
        group,
        attempts: 0,
        failed: 0,
        input: 0,
        output: 0,
        cache_read: 0,
        cache_write: 0,
        usd: 0.0,
        unpriced: 0,
        duration_ms: 0,
    }
}

/// Adds `line` to `row`; sums saturate, so no line makes a field overflow or the USD infinite.
fn add(row: &mut UsageRow, line: &UsageLine) {
    row.attempts = row.attempts.saturating_add(1);
    if line.outcome != Outcome::Ok {
        row.failed = row.failed.saturating_add(1);
    }
    row.input = row.input.saturating_add(line.usage.input);
    row.output = row.output.saturating_add(line.usage.output);
    row.cache_read = row.cache_read.saturating_add(line.usage.cache_read);
    row.cache_write = row.cache_write.saturating_add(line.usage.cache_write);
    match line.usd {
        Some(usd) => row.usd = (row.usd + usd).clamp(-f64::MAX, f64::MAX),
        None => row.unpriced = row.unpriced.saturating_add(1),
    }
    row.duration_ms = row.duration_ms.saturating_add(line.duration_ms);
}

#[cfg(test)]
mod tests {
    use qb_proto::{Outcome, StopReason, Usage};

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn line(request_id: &str) -> UsageLine {
        UsageLine {
            at: NOW,
            duration_ms: 5,
            request_id: request_id.into(),
            client: "client-a".into(),
            route: "chat".into(),
            step: 0,
            login: "login-1".into(),
            model: "model-a".into(),
            outcome: Outcome::Ok,
            stop: Some(StopReason::End),
            error: None,
            usage: Usage::default(),
            usd: None,
            usd_source: None,
            tools: Vec::new(),
        }
    }

    fn request_ids(file: &Path) -> Vec<String> {
        std::fs::read_to_string(file)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<UsageLine>(l).unwrap().request_id)
            .collect()
    }

    #[test]
    fn a_rotation_during_a_read_neither_hides_nor_doubles_a_line() {
        let dir = crate::testdir::new("usage-race");
        let file = dir.join("usage.jsonl");
        let size = json_line(&line("turn-0")).unwrap().len() as u64;
        let ledger = Ledger::new(UsageLedger {
            file: file.clone(),
            rotate_bytes: 2 * size,
            keep_days: 1,
        });
        for id in ["turn-0", "turn-1", "turn-2"] {
            ledger.append(&line(id), NOW);
        }
        assert_eq!(rotated(&file).unwrap().len(), 1);
        let query = UsageQuery {
            from: NOW - 60,
            to: None,
            group_by: None,
            bucket: None,
        };
        // The opened current file, holding turn-2, gets turn-3 and is rotated before the read
        // lists the rotated files; its successor is rotated after the listing.
        let mut next = 3;
        let answer = aggregate_paced(&file, &query, NOW + 60, || {
            for _ in 0..2 {
                ledger.append(&line(&format!("turn-{next}")), NOW + next / 2);
                next += 1;
            }
        })
        .unwrap();
        assert_eq!(next, 7);
        assert_eq!(rotated(&file).unwrap().len(), 3);
        assert_eq!(answer.rows.len(), 1);
        assert_eq!(
            answer.rows[0].attempts, 4,
            "turn-0 to turn-3, once each: the lines of the files as the read opened them"
        );
        let after = aggregate(&file, &query, NOW + 60).unwrap();
        assert_eq!(after.rows[0].attempts, 7);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rotations_within_one_second_keep_every_line_under_its_own_stamp() {
        let dir = crate::testdir::new("usage");
        let file = dir.join("usage.jsonl");
        let size = json_line(&line("turn-0")).unwrap().len() as u64;
        let ledger = Ledger::new(UsageLedger {
            file: file.clone(),
            rotate_bytes: size,
            keep_days: 1,
        });
        for id in ["turn-0", "turn-1", "turn-2"] {
            ledger.append(&line(id), NOW);
        }
        let stamps: Vec<u64> = rotated(&file).unwrap().into_iter().map(|f| f.0).collect();
        assert_eq!(stamps, [NOW, NOW + 1]);
        assert_eq!(
            request_ids(&dir.join(format!("usage.jsonl.{NOW}"))),
            ["turn-0"]
        );
        assert_eq!(
            request_ids(&dir.join(format!("usage.jsonl.{}", NOW + 1))),
            ["turn-1"]
        );
        assert_eq!(request_ids(&file), ["turn-2"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
