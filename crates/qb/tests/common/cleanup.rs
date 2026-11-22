//! Test directories removed when their test ends, passed or failed: libtest runs each test on a
//! thread of its own, and the end of that thread drops its thread-local list, also after a
//! panic. A directory registered on another thread goes when that thread ends.

#![allow(dead_code, unreachable_pub)]

use std::cell::RefCell;
use std::path::{Path, PathBuf};

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

/// Removes `dir` and everything in it when the calling thread ends.
pub fn remove_at_test_end(dir: &Path) {
    // Only fails while the thread is already ending, when nothing registers.
    let _ = DIRS.try_with(|d| d.0.borrow_mut().push(dir.to_owned()));
}
