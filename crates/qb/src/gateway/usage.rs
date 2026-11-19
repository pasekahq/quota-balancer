//! The usage ledger: one JSON line per adapter attempt appended to `usage.file`, which is renamed
//! to `<file>.<unix s>` before a line would take it past `rotate_bytes`; rotated files older
//! than `keep_days` are removed at each rotation.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use qb_proto::UsageLine;

use super::audit::{json_line, write_line};
use super::config::UsageLedger;
use crate::journal::open_append;
use crate::log;

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
