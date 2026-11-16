//! The daemon's journal: one JSON line per state change, appended with `O_APPEND` and no fsync,
//! rotated to `<path>.1` with a header that restores the live state, replayed on start.
//! The line format is described in `docs/journal.md`.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use qb_core::{Auth, Core, LeaseRecord, Marks, Reason, Record};
use serde::{Deserialize, Serialize};

use crate::log;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issued: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease: Option<LeaseLine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    release: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    marks: Option<MarksLine>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseLine {
    id: u64,
    login: String,
    model: String,
    client: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    cost: Vec<f64>,
    expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthLine {
    #[default]
    Ok,
    Stale,
    Dead,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarksLine {
    login: String,
    #[serde(default, skip_serializing_if = "is_ok")]
    auth: AuthLine,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exhausted_until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rate_limited_until: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    model_dead: BTreeMap<String, u64>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's `skip_serializing_if` passes a reference
fn is_ok(a: &AuthLine) -> bool {
    *a == AuthLine::Ok
}

/// Encodes `record` as of `at` as one journal line, newline included.
///
/// # Errors
/// A cost that is not a finite number.
pub fn encode(record: &Record, at: u64) -> Result<Vec<u8>, serde_json::Error> {
    let mut line = Line {
        at,
        issued: None,
        lease: None,
        release: None,
        marks: None,
    };
    match record {
        Record::Issued(n) => line.issued = Some(*n),
        Record::Lease(l) => {
            line.lease = Some(LeaseLine {
                id: l.id,
                login: l.login.clone(),
                model: l.model.clone(),
                client: l.client.clone(),
                run_id: l.run_id.clone(),
                cost: l.cost.clone(),
                expires_at: l.expires_at,
                reason: l.reason.map(|r| r.as_str().to_owned()),
            });
        }
        Record::Release(id) => line.release = Some(*id),
        Record::Marks { login, marks } => {
            line.marks = Some(MarksLine {
                login: login.clone(),
                auth: match marks.auth {
                    Auth::Ok => AuthLine::Ok,
                    Auth::Stale => AuthLine::Stale,
                    Auth::Dead => AuthLine::Dead,
                },
                exhausted_until: marks.exhausted_until,
                rate_limited_until: marks.rate_limited_until,
                model_dead: marks.model_dead.iter().cloned().collect(),
            });
        }
    }
    let mut out = serde_json::to_vec(&line)?;
    out.push(b'\n');
    Ok(out)
}

/// Decodes one journal line without its newline into the record and its time.
///
/// # Errors
/// The line is not a JSON object of the journal format holding exactly one record.
pub fn decode(line: &[u8]) -> Result<(Record, u64), String> {
    let line: Line = serde_json::from_slice(line).map_err(|e| e.to_string())?;
    let at = line.at;
    let record = match (line.issued, line.lease, line.release, line.marks) {
        (Some(n), None, None, None) => Record::Issued(n),
        (None, Some(l), None, None) => Record::Lease(LeaseRecord {
            reason: match l.reason {
                None => None,
                Some(name) => Some(
                    Reason::from_name(&name).ok_or_else(|| format!("unknown reason `{name}`"))?,
                ),
            },
            id: l.id,
            login: l.login,
            model: l.model,
            client: l.client,
            run_id: l.run_id,
            cost: l.cost,
            expires_at: l.expires_at,
        }),
        (None, None, Some(id), None) => Record::Release(id),
        (None, None, None, Some(m)) => Record::Marks {
            login: m.login,
            marks: Marks {
                auth: match m.auth {
                    AuthLine::Ok => Auth::Ok,
                    AuthLine::Stale => Auth::Stale,
                    AuthLine::Dead => Auth::Dead,
                },
                exhausted_until: m.exhausted_until,
                rate_limited_until: m.rate_limited_until,
                model_dead: m.model_dead.into_iter().collect(),
            },
        },
        _ => {
            return Err("expected exactly one of `issued`, `lease`, `release`, `marks`".to_owned());
        }
    };
    Ok((record, at))
}

/// The previous journal file of `path`: `<path>.1`.
pub fn rotated(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

/// A journal line that stops replay: the file, the 1-based line number when the content is at
/// fault, and the reason.
#[derive(Debug)]
pub struct ReplayError {
    /// Journal file.
    pub file: PathBuf,
    /// Line number; `None` when the file could not be read.
    pub line: Option<usize>,
    /// What is wrong.
    pub reason: String,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(n) => write!(f, "{}: line {n}: {}", self.file.display(), self.reason),
            None => write!(f, "{}: {}", self.file.display(), self.reason),
        }
    }
}

impl std::error::Error for ReplayError {}

/// What a replay read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replayed {
    /// Length of the complete lines of the file.
    pub valid_len: u64,
    /// Time of the last decoded record; `None` without one.
    pub last_at: Option<u64>,
}

/// Restores every record of `file` into `core` in order; `None` when the file does not exist.
/// A final line without its newline was torn by a crash and is skipped with a warning; a record
/// that does not fit the config is skipped with a warning. The file is only read.
///
/// # Errors
/// The file cannot be read, or a complete line does not decode.
pub fn replay_file(core: &mut Core, file: &Path) -> Result<Option<Replayed>, ReplayError> {
    let fail = |line, reason: String| ReplayError {
        file: file.to_owned(),
        line,
        reason,
    };
    let mut text = Vec::new();
    match File::open(file) {
        Ok(mut f) => f
            .read_to_end(&mut text)
            .map_err(|e| fail(None, format!("cannot read: {e}")))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(fail(None, format!("cannot open: {e}"))),
    };
    let complete = text.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    let mut n = 0;
    let mut last_at = None;
    for line in text[..complete].split_inclusive(|&b| b == b'\n') {
        n += 1;
        let line = &line[..line.len() - 1];
        let (record, at) = decode(line).map_err(|reason| fail(Some(n), reason))?;
        last_at = Some(at);
        if let Err(e) = core.restore(&record, at) {
            log::warn(&format!("{}: line {n}: skipped: {e}", file.display()));
        }
    }
    if complete < text.len() {
        log::warn(&format!(
            "{}: line {}: torn final line skipped",
            file.display(),
            n + 1
        ));
    }
    Ok(Some(Replayed {
        valid_len: complete as u64,
        last_at,
    }))
}

/// Replays `<path>.1`, then `path`: the length of the complete lines of `path` and the time of
/// the last record of either file.
///
/// # Errors
/// See [`replay_file`].
pub fn replay(core: &mut Core, path: &Path) -> Result<Replayed, ReplayError> {
    let old = replay_file(core, &rotated(path))?;
    let current = replay_file(core, path)?;
    Ok(Replayed {
        valid_len: current.map_or(0, |r| r.valid_len),
        last_at: current
            .and_then(|r| r.last_at)
            .or(old.and_then(|r| r.last_at)),
    })
}

/// Where the daemon's state changes go: nowhere, or an appended file.
#[derive(Debug)]
pub struct Journal {
    file: Option<Appender>,
}

#[derive(Debug)]
struct Appender {
    path: PathBuf,
    /// `None` after a failed append; the next record starts a fresh file.
    file: Option<File>,
    len: u64,
    rotate_bytes: u64,
    open: fn(&Path) -> io::Result<File>,
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

impl Journal {
    /// A journal that writes nothing and opens no file.
    pub fn off() -> Self {
        Self { file: None }
    }

    /// Opens `path` for appending, creating it, and cuts it to `valid_len` bytes, the complete
    /// lines [`replay`] found, so a torn tail does not merge with the next line.
    ///
    /// # Errors
    /// The file cannot be opened or cut.
    pub fn open(path: &Path, rotate_bytes: u64, valid_len: u64) -> io::Result<Self> {
        let file = open_append(path)?;
        let len = file.metadata()?.len();
        if len > valid_len {
            file.set_len(valid_len)?;
        }
        Ok(Self {
            file: Some(Appender {
                path: path.to_owned(),
                file: Some(file),
                len: len.min(valid_len),
                rotate_bytes,
                open: open_append,
            }),
        })
    }

    /// Appends `record` as of `at`. Once the file reaches the rotation size it becomes
    /// `<path>.1` and the new file starts with `core`'s live state, so either file pair
    /// replays to the same leases and marks. After a failed write nothing more goes into that
    /// file: the next record moves it to `<path>.1` and starts a new file with the live state,
    /// which includes that record.
    ///
    /// # Errors
    /// Encoding, writing, rotation or reopening failed.
    pub fn record(&mut self, core: &Core, record: &Record, at: u64) -> io::Result<()> {
        let Some(a) = &mut self.file else {
            return Ok(());
        };
        let Some(file) = &mut a.file else {
            return a.start(core, at);
        };
        let line = encode(record, at)?;
        if let Err(e) = file.write_all(&line) {
            a.file = None;
            return Err(e);
        }
        a.len += line.len() as u64;
        if a.len < a.rotate_bytes {
            return Ok(());
        }
        a.start(core, at)
    }
}

impl Appender {
    /// Moves `path` to `<path>.1` if it exists, then opens a fresh `path` and writes `core`'s
    /// live state as of `at` as its header. Leaves no handle unless the header was written.
    fn start(&mut self, core: &Core, at: u64) -> io::Result<()> {
        let mut header = Vec::new();
        for r in core.records() {
            header.extend(encode(&r, at)?);
        }
        self.file = None;
        match std::fs::rename(&self.path, rotated(&self.path)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut file = (self.open)(&self.path)?;
        file.write_all(&header)?;
        self.len = header.len() as u64;
        self.file = Some(file);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use qb_core::{LoginSpec, OutcomeClass, ReportInput, ReportSubject, Spec, VendorSpec};

    use super::*;

    const NOW: u64 = 1_800_000_000;

    thread_local! {
        static REOPEN_FAILS: Cell<bool> = const { Cell::new(false) };
    }

    fn flaky_open(path: &Path) -> io::Result<File> {
        if REOPEN_FAILS.get() {
            Err(io::Error::other("injected open failure"))
        } else {
            open_append(path)
        }
    }

    fn fresh_core() -> Core {
        Core::new(Spec {
            vendors: vec![VendorSpec {
                name: "vendor-a".into(),
                windows: Vec::new(),
            }],
            logins: vec![LoginSpec {
                name: "login-1".into(),
                vendor: "vendor-a".into(),
            }],
            rate_limit_backoff_s: 60,
            ..Spec::default()
        })
        .expect("valid spec")
    }

    fn rate_limited_core() -> Core {
        let mut core = fresh_core();
        let input = ReportInput {
            subject: ReportSubject::Login("login-1".into()),
            outcome: OutcomeClass::Http429,
            model: None,
            release: false,
            windows: Vec::new(),
        };
        core.report(&input, NOW).expect("known login");
        core
    }

    fn records(file: &Path) -> Vec<Record> {
        std::fs::read(file)
            .expect("readable")
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| decode(l).expect("valid line").0)
            .collect()
    }

    #[test]
    fn a_failed_reopen_writes_nothing_until_the_live_state_can_start_a_file() {
        let dir = std::env::temp_dir().join(format!("qb-journal-reopen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("journal");
        let core = rate_limited_core();
        let mut journal = Journal::open(&path, 1, 0).expect("open");
        if let Some(a) = &mut journal.file {
            a.open = flaky_open;
        }

        REOPEN_FAILS.set(true);
        assert!(journal.record(&core, &Record::Release(1), NOW).is_err());
        let rotated_len = std::fs::metadata(rotated(&path)).expect(".1").len();
        for id in 2..5 {
            assert!(journal.record(&core, &Record::Release(id), NOW).is_err());
        }
        assert_eq!(
            std::fs::metadata(rotated(&path)).expect(".1").len(),
            rotated_len
        );
        assert!(!path.exists());

        REOPEN_FAILS.set(false);
        journal
            .record(&core, &Record::Release(5), NOW + 1)
            .expect("reopened");
        assert_eq!(records(&rotated(&path)), [Record::Release(1)]);
        assert_eq!(records(&path), core.records());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_failed_write_restarts_the_file_with_the_live_state() {
        const TORN: &[u8] = b"{\"at\":";
        let dir = std::env::temp_dir().join(format!("qb-journal-write-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("journal");
        let core = rate_limited_core();
        let mut journal = Journal::open(&path, 1 << 20, 0).expect("open");
        journal
            .record(&core, &Record::Release(1), NOW)
            .expect("append");
        open_append(&path)
            .and_then(|mut f| f.write_all(TORN))
            .expect("torn line");
        if let Some(a) = &mut journal.file {
            a.file = Some(File::open(&path).expect("read-only handle"));
        }

        assert!(journal.record(&core, &Record::Release(2), NOW).is_err());
        journal
            .record(&core, &Record::Release(3), NOW + 1)
            .expect("restarted");
        assert!(std::fs::read(rotated(&path)).expect(".1").ends_with(TORN));
        assert_eq!(records(&path), core.records());
        let mut replayed = fresh_core();
        replay(&mut replayed, &path).expect("replays");
        assert_eq!(replayed.records(), core.records());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
