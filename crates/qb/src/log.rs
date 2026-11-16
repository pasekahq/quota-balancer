//! Logging to stderr. Under journald (`JOURNAL_STREAM` set) lines get `<N>` priority prefixes,
//! otherwise a plain `level:` label. No logging framework, no files, no network.

use std::io::Write;
use std::sync::OnceLock;

/// Syslog priority of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// `<3>` error.
    Error = 3,
    /// `<4>` warning.
    Warn = 4,
    /// `<6>` info.
    Info = 6,
}

fn journald() -> bool {
    static JOURNALD: OnceLock<bool> = OnceLock::new();
    *JOURNALD.get_or_init(|| std::env::var_os("JOURNAL_STREAM").is_some())
}

/// Writes one log line.
pub fn line(level: Level, msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = if journald() {
        writeln!(err, "<{}>{msg}", level as u8)
    } else {
        let label = match level {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
        };
        writeln!(err, "{label}: {msg}")
    };
}

/// Info line.
pub fn info(msg: &str) {
    line(Level::Info, msg);
}

/// Warning line.
pub fn warn(msg: &str) {
    line(Level::Warn, msg);
}

/// Error line.
pub fn error(msg: &str) {
    line(Level::Error, msg);
}
