//! SIGHUP as a file descriptor for the poll loops of `qbd` and `qb gateway`: the signal is
//! blocked in every thread and read from a signalfd, so waiting for it costs no thread, timer or
//! wake-up.

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};

/// Bytes of one `struct signalfd_siginfo`.
const SIGINFO_BYTES: usize = 128;

/// A non-blocking signalfd of SIGHUP.
pub struct Hangup(OwnedFd);

impl Hangup {
    /// Blocks SIGHUP in the calling thread, and so in every thread it starts later, and opens a
    /// signalfd that reads it. Call it before any thread starts: a thread that does not block
    /// SIGHUP takes its default action, which ends the process.
    ///
    /// # Errors
    /// The signal mask cannot be changed or the signalfd cannot be created.
    #[allow(unsafe_code)]
    pub fn new() -> io::Result<Self> {
        let mut set = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: sigemptyset initialises the whole set behind the pointer, which points to a
        // live local; sigaddset with a valid signal number only sets one bit of it.
        let set = unsafe {
            libc::sigemptyset(set.as_mut_ptr());
            libc::sigaddset(set.as_mut_ptr(), libc::SIGHUP);
            set.assume_init()
        };
        // SAFETY: `set` is initialised and only read; SIGHUP is none of the signals libc reserves
        // for itself, and nothing else in this process relies on its delivery.
        let blocked =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut()) };
        if blocked != 0 {
            return Err(io::Error::from_raw_os_error(blocked));
        }
        // SAFETY: `set` is initialised and only read; -1 asks for a new descriptor.
        let fd =
            unsafe { libc::signalfd(-1, &raw const set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: signalfd returned a new open descriptor that nothing else owns.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Whether SIGHUP arrived since the last call; consumes every pending one.
    pub fn take(&self) -> bool {
        let mut info = [0u8; SIGINFO_BYTES];
        let mut arrived = false;
        while matches!(rustix::io::read(&self.0, &mut info), Ok(n) if n > 0) {
            arrived = true;
        }
        arrived
    }
}

impl AsFd for Hangup {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn a_hangup_of_a_blocking_thread_is_read_from_the_descriptor() {
        // Its own thread: the mask stays there, and `raise` signals only that thread.
        std::thread::spawn(|| {
            let hangup = Hangup::new().unwrap();
            assert!(!hangup.take(), "nothing pending yet");
            // SAFETY: raise sends SIGHUP to the calling thread, which blocks it.
            assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
            assert!(hangup.take(), "the signal is read, not delivered");
            assert!(!hangup.take(), "a read consumes it");
        })
        .join()
        .unwrap();
    }
}
