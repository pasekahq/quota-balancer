//! Files `qbd` and the gateway rewrite on request: the old bytes kept as a 0600 backup beside the
//! file, the new ones written atomically, and the TOML scalars of a rendered config file.

use std::fmt::{self, Write as _};
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Write as _};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use zeroize::Zeroizing;

/// `s` as a TOML basic string.
pub fn basic(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `v` as a TOML float that parses back to the same `f64`.
pub fn float(v: f64) -> String {
    format!("{v:?}")
}

/// Replaces `file` with `bytes` so that a reader sees the old or the new file, never a part:
/// a 0600 temporary file in the same directory, fsync, rename, fsync of the directory.
///
/// # Errors
/// Any step failed; the temporary file is removed and `file` is unchanged.
pub fn write_atomic(file: &Path, bytes: &[u8]) -> io::Result<()> {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = file
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = file
        .file_name()
        .map_or_else(|| "file".into(), |n| n.to_string_lossy().into_owned());
    let tmp: PathBuf = dir.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, file)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Why [`replace`] failed: the write's error and whether the file may no longer hold its old
/// bytes.
#[derive(Debug)]
pub struct Unwritten {
    /// The write's error.
    pub error: io::Error,
    /// The file does not read back as its old bytes.
    pub replaced: bool,
}

/// Writes `candidate` over `file`, whose bytes were `old`, through `write`. On a failure the
/// backup `backup` of `old` is removed only when `file` still reads back as `old`; that read is
/// zeroized, since `file` may be a credential file.
///
/// # Errors
/// `write` failed.
pub fn replace(
    file: &Path,
    old: &[u8],
    candidate: &[u8],
    backup: &Path,
    write: impl FnOnce(&Path, &[u8]) -> io::Result<()>,
) -> Result<(), Unwritten> {
    let Err(error) = write(file, candidate) else {
        return Ok(());
    };
    let replaced = std::fs::read(file).map_or(true, |now| *Zeroizing::new(now) != old);
    if !replaced {
        let _ = std::fs::remove_file(backup);
    }
    Err(Unwritten { error, replaced })
}

/// Most backups of one second; one more is refused.
const BACKUPS_PER_SECOND: u32 = 100;

/// Writes `bytes` to a new 0600 file `<file>.bak-<now>`, with `-<n>` appended when a backup of
/// that second exists; never replaces a file.
///
/// # Errors
/// The file cannot be created or written; a partly written one is removed.
pub fn backup(file: &Path, bytes: &[u8], now: u64) -> io::Result<PathBuf> {
    for n in 0..BACKUPS_PER_SECOND {
        let mut name = file.as_os_str().to_owned();
        name.push(format!(".bak-{now}"));
        if n > 0 {
            name.push(format!("-{n}"));
        }
        let path = PathBuf::from(name);
        let mut f = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        return Ok(path);
    }
    Err(io::Error::new(
        ErrorKind::AlreadyExists,
        format!("{BACKUPS_PER_SECOND} backups of second {now} exist"),
    ))
}

/// Why [`rewrite`] failed.
#[derive(Debug)]
pub enum Failed {
    /// No backup was made; nothing was written.
    Backup(io::Error),
    /// The file still holds its old bytes; the backup is removed.
    Unwritten(io::Error),
    /// The write failed after the rename replaced the file; the backup is kept.
    Replaced {
        /// The write's error.
        error: io::Error,
        /// The backup of the old bytes.
        backup: PathBuf,
    },
}

impl Failed {
    /// The message of the answer refusing the rewrite of `file`.
    pub fn message(&self, file: &Path) -> String {
        match self {
            Self::Backup(e) => format!("cannot write a backup of {}: {e}", file.display()),
            Self::Unwritten(e) => format!("cannot write {}: {e}", file.display()),
            Self::Replaced { error, backup } => not_installed(file, error, backup),
        }
    }
}

/// The message of a rewrite that replaced `file` but could not install it for `why`, its old
/// bytes kept as `backup`.
pub fn not_installed(file: &Path, why: impl fmt::Display, backup: &Path) -> String {
    format!(
        "{} was replaced but not installed: {why}; the old file is kept as {}",
        file.display(),
        backup.display()
    )
}

/// Keeps `old`, the bytes of `file`, as a [`backup`] of second `now` and writes `candidate` over
/// `file` with [`write_atomic`]: the backup's path.
///
/// # Errors
/// See [`Failed`].
pub fn rewrite(file: &Path, old: &[u8], candidate: &[u8], now: u64) -> Result<PathBuf, Failed> {
    let backup = backup(file, old, now).map_err(Failed::Backup)?;
    match replace(file, old, candidate, &backup, write_atomic) {
        Ok(()) => Ok(backup),
        Err(u) if u.replaced => Err(Failed::Replaced {
            error: u.error,
            backup,
        }),
        Err(u) => Err(Failed::Unwritten(u.error)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qb-rewrite-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn written_floats_parse_back_to_the_same_f64() {
        for v in [25.0, 0.1, 1.0 / 3.0, 1e21, 1e-7, 123_456.789, f64::MAX] {
            let text = format!("x = {}\n", float(v));
            let read: BTreeMap<String, f64> = toml::from_str(&text).unwrap();
            assert_eq!(read["x"].to_bits(), v.to_bits(), "{text}");
        }
    }

    #[test]
    fn a_failed_write_that_replaced_the_file_keeps_the_backup() {
        let file = dir("replaced").join("gw.toml");
        std::fs::write(&file, "old").unwrap();
        let backup = backup(&file, b"old", 7).unwrap();
        let after_rename = |f: &Path, bytes: &[u8]| {
            std::fs::write(f, bytes).unwrap();
            Err(io::Error::other("directory sync failed"))
        };
        let u = replace(&file, b"old", b"new", &backup, after_rename).unwrap_err();
        assert_eq!(
            (u.replaced, u.error.to_string().as_str()),
            (true, "directory sync failed")
        );
        assert_eq!(std::fs::read(&backup).unwrap(), b"old");
        assert_eq!(std::fs::read(&file).unwrap(), b"new");
        std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_failed_write_that_left_the_file_alone_removes_the_backup() {
        let file = dir("unchanged").join("gw.toml");
        std::fs::write(&file, "old").unwrap();
        let backup = backup(&file, b"old", 7).unwrap();
        let before_rename = |_: &Path, _: &[u8]| Err(io::Error::other("disk full"));
        let u = replace(&file, b"old", b"new", &backup, before_rename).unwrap_err();
        assert!(!u.replaced);
        assert!(!backup.exists());
        assert_eq!(std::fs::read(&file).unwrap(), b"old");
        let ok = |f: &Path, bytes: &[u8]| std::fs::write(f, bytes);
        let backup = super::backup(&file, b"old", 7).unwrap();
        replace(&file, b"old", b"new", &backup, ok).unwrap();
        assert!(backup.exists());
        std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_rewrite_keeps_the_old_bytes_in_a_0600_backup_suffixed_on_a_collision() {
        let file = dir("rewrite").join("roles.toml");
        std::fs::write(&file, "old").unwrap();
        let first = rewrite(&file, b"old", b"mid", 9).unwrap();
        let second = rewrite(&file, b"mid", b"new", 9).unwrap();
        let name = |p: &Path| p.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(
            (name(&first), name(&second)),
            ("roles.toml.bak-9".into(), "roles.toml.bak-9-1".into())
        );
        assert_eq!(std::fs::read(&first).unwrap(), b"old");
        assert_eq!(std::fs::read(&second).unwrap(), b"mid");
        assert_eq!(std::fs::read(&file).unwrap(), b"new");
        for f in [&file, &first, &second] {
            let mode = std::fs::metadata(f).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{}", f.display());
        }
        std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_rewrite_without_room_for_a_backup_writes_nothing() {
        let missing = dir("nodir").join("gone").join("roles.toml");
        let e = rewrite(&missing, b"old", b"new", 9).unwrap_err();
        assert!(matches!(e, Failed::Backup(_)), "{e:?}");
        assert!(
            e.message(&missing)
                .starts_with(&format!("cannot write a backup of {}: ", missing.display())),
            "{}",
            e.message(&missing)
        );
        assert!(!missing.exists());
    }
}
