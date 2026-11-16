//! The daemon's journal: one JSON line per state change, appended with `O_APPEND` and no fsync,
//! rotated to `<path>.1` with a header that restores the live state, replayed on start.
//! The line format is described in `docs/journal.md`.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use qb_core::{Auth, Core, LeaseRecord, Marks, Record};
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

/// Restores every record of `file` into `core` in order and returns the length of its complete
/// lines, `None` when the file does not exist. A final line without its newline was torn by a
/// crash and is skipped with a warning; a record that does not fit the config is skipped with a
/// warning.
///
/// # Errors
/// The file cannot be read, or a complete line does not decode.
pub fn replay_file(core: &mut Core, file: &Path) -> Result<Option<u64>, ReplayError> {
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
    for line in text[..complete].split_inclusive(|&b| b == b'\n') {
        n += 1;
        let line = &line[..line.len() - 1];
        let (record, at) = decode(line).map_err(|reason| fail(Some(n), reason))?;
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
    Ok(Some(complete as u64))
}

/// Replays `<path>.1`, then `path`, and returns the length of the complete lines of `path`.
///
/// # Errors
/// See [`replay_file`].
pub fn replay(core: &mut Core, path: &Path) -> Result<u64, ReplayError> {
    replay_file(core, &rotated(path))?;
    Ok(replay_file(core, path)?.unwrap_or(0))
}

/// Where the daemon's state changes go: nowhere, or an appended file.
#[derive(Debug)]
pub struct Journal {
    file: Option<Appender>,
}

#[derive(Debug)]
struct Appender {
    path: PathBuf,
    file: File,
    len: u64,
    rotate_bytes: u64,
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
                file,
                len: len.min(valid_len),
                rotate_bytes,
            }),
        })
    }

    /// Appends `record` as of `at`. Once the file reaches the rotation size it becomes
    /// `<path>.1` and the new file starts with `core`'s live state, so either file pair
    /// replays to the same leases and marks.
    ///
    /// # Errors
    /// Encoding, writing or rotation failed.
    pub fn record(&mut self, core: &Core, record: &Record, at: u64) -> io::Result<()> {
        let Some(a) = &mut self.file else {
            return Ok(());
        };
        a.append(&encode(record, at)?)?;
        if a.len < a.rotate_bytes {
            return Ok(());
        }
        std::fs::rename(&a.path, rotated(&a.path))?;
        a.file = open_append(&a.path)?;
        a.len = 0;
        let mut header = Vec::new();
        for r in core.records() {
            header.extend(encode(&r, at)?);
        }
        a.append(&header)
    }
}

impl Appender {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes)?;
        self.len += bytes.len() as u64;
        Ok(())
    }
}
