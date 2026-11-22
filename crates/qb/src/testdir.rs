//! Test directories removed when their test ends, passed or failed: libtest runs each test on a
//! thread of its own, and the end of that thread drops its thread-local list, also after a
//! panic. A directory registered on another thread goes when that thread ends.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

struct Dirs(RefCell<Vec<PathBuf>>);

impl Drop for Dirs {
    fn drop(&mut self) {
        for dir in self.0.get_mut().drain(..) {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

thread_local! {
    static DIRS: Dirs = const { Dirs(RefCell::new(Vec::new())) };
}

/// A fresh directory `qb-<pid>-<tag>-<n>` under the system's temporary directory, removed when
/// the calling test ends.
pub(crate) fn new(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "qb-{}-{tag}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("a test directory");
    remove_at_test_end(&dir);
    dir
}

/// Removes `dir` and everything in it when the calling thread ends.
fn remove_at_test_end(dir: &Path) {
    // Only fails while the thread is already ending, when nothing registers.
    let _ = DIRS.try_with(|d| d.0.borrow_mut().push(dir.to_owned()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_goes_when_its_thread_ends_even_by_a_panic() {
        let made = std::thread::spawn(|| {
            let dir = new("testdir");
            std::fs::write(dir.join("file"), "x").unwrap();
            assert!(dir.is_dir());
            dir
        })
        .join()
        .unwrap();
        assert!(!made.exists(), "{}", made.display());

        let (tx, rx) = std::sync::mpsc::channel();
        let panicked = std::thread::spawn(move || {
            tx.send(new("testdir-panic")).unwrap();
            panic!("a failing test");
        })
        .join();
        assert!(panicked.is_err());
        let dir = rx.recv().unwrap();
        assert!(!dir.exists(), "{}", dir.display());
    }
}
