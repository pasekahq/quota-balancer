//! The usage ledger: one JSON line per adapter attempt appended to `usage.file`, which is renamed
//! to `<file>.<unix s>` before a line would take it past `rotate_bytes`; rotated files older
//! than `keep_days` are removed at each rotation. `GET /v1/model/usage` sums the lines back by
//! period and group.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use qb_proto::gateway::{MAX_USAGE_ROWS, MAX_USAGE_WINDOW_S};
use qb_proto::{Outcome, UsageAnswer, UsageBucket, UsageGroupBy, UsageLine, UsageQuery, UsageRow};

use super::audit::{json_line, write_line};
use super::config::UsageLedger;
use super::spend;
use crate::journal::open_append;
use crate::{jsonl, log};

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

/// The rotated files of the ledger `file`: `(stamp, path)` of each `<file>.<unix s>` beside it,
/// oldest first.
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
        if let Some(stamp) = stamp_of(&entry.file_name(), &prefix) {
            files.push((stamp, entry.path()));
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
    let (mut from, mut to, mut group_by, mut bucket) = (None, None, None, None);
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "from" => set(&mut from, key, number(key, value)?)?,
            "to" => set(&mut to, key, number(key, value)?)?,
            "group_by" => {
                let named = named(key, value, UsageGroupBy::ALL, UsageGroupBy::as_str)?;
                set(&mut group_by, key, named)?;
            }
            "bucket" => {
                let named = named(key, value, UsageBucket::ALL, UsageBucket::as_str)?;
                set(&mut bucket, key, named)?;
            }
            _ => {
                return Err(format!(
                    "unknown parameter `{key}`: the query takes `from`, `to`, `group_by` and \
                     `bucket`"
                ));
            }
        }
    }
    let from = from.ok_or("`from` is required")?;
    Ok(UsageQuery {
        from,
        to,
        group_by,
        bucket,
    })
}

/// Stores `value` of parameter `key` in `slot`.
fn set<T>(slot: &mut Option<T>, key: &str, value: T) -> Result<(), String> {
    match slot.replace(value) {
        Some(_) => Err(format!("`{key}` is given twice")),
        None => Ok(()),
    }
}

/// `value` of parameter `key` as Unix seconds.
fn number(key: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("`{key}` must be a whole number"))
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
/// as empty.
///
/// # Errors
/// More than [`MAX_USAGE_ROWS`] rows, or a ledger file that cannot be listed or read.
pub(crate) fn aggregate(
    file: &Path,
    query: &UsageQuery,
    to: u64,
) -> Result<UsageAnswer, AggregateError> {
    let from = query.from;
    let mut files: Vec<PathBuf> = match rotated(file) {
        Ok(files) => files
            .into_iter()
            .filter(|(stamp, _)| *stamp >= from)
            .map(|(_, path)| path)
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(AggregateError::Io(e)),
    };
    files.push(file.to_owned());
    let mut rows = BTreeMap::new();
    let mut skipped = 0;
    for f in &files {
        let mut full = false;
        skipped += jsonl::read(f, |line: UsageLine| {
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
    fn rotations_within_one_second_keep_every_line_under_its_own_stamp() {
        let dir = std::env::temp_dir().join(format!("qb-usage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
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
