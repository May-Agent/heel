//! The seccomp user-notification listener and the reading of the stopped
//! process's memory.
//!
//! Every fact about the notification interface used here was checked against
//! `kernel/seccomp.c` of Linux 6.12:
//!
//! - a receive sleeps until a notification is pending and returns `ENOENT` when
//!   the stopped task has died, or when the filter has no tasks left;
//! - a send or an added descriptor is refused with `ENOENT` once the task is
//!   gone, and with `EINPROGRESS` before the notification was received;
//! - an added descriptor sent atomically with the reply leaves the notification
//!   unanswered if it could not be installed, so an error reply must follow;
//! - `NOTIF_ID_VALID` is true only while the notification is waiting for a
//!   reply, which is what makes it the check that `/proc` data read about the
//!   task still describes it.

use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

/// `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP`, 6.6: wake the supervisor on the stopped
/// task's CPU, which keeps a round trip from migrating.
const SYNC_WAKE_UP: u64 = 1;

/// The largest path the kernel accepts, including the terminator.
pub(crate) const PATH_MAX: usize = 4096;

const PAGE: usize = 4096;

/// The listener of one filter, shared by the threads that serve it.
#[derive(Debug)]
pub(crate) struct Listener {
    fd: OwnedFd,
}

/// What a worker answers a notification with.
#[derive(Debug)]
pub(crate) enum Reply {
    /// The call succeeded with this return value.
    Value(i64),
    /// The call failed with this errno.
    Errno(i32),
    /// The call opened this file, to be installed in the caller.
    Fd { fd: OwnedFd, cloexec: bool },
    /// Let the kernel run the call as the caller made it.
    Continue,
}

/// Check that the kernel's notification structures are the ones this build was
/// written against. They have not changed since the interface appeared, so a
/// difference is a kernel this code has not been checked against.
pub(crate) fn check_sizes() -> crate::error::Result<()> {
    let mut sizes = MaybeUninit::<libc::seccomp_notif_sizes>::zeroed();
    // SAFETY: `SECCOMP_GET_NOTIF_SIZES` writes one `seccomp_notif_sizes`.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_NOTIF_SIZES,
            0,
            sizes.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(crate::error::Error::SeccompNotifyUnavailable(
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: the call succeeded, so the structure is initialized.
    let sizes = unsafe { sizes.assume_init() };
    let expected = (
        size_of::<libc::seccomp_notif>(),
        size_of::<libc::seccomp_notif_resp>(),
        size_of::<libc::seccomp_data>(),
    );
    let actual = (
        usize::from(sizes.seccomp_notif),
        usize::from(sizes.seccomp_notif_resp),
        usize::from(sizes.seccomp_data),
    );
    if actual == expected {
        Ok(())
    } else {
        Err(crate::error::Error::InitFailed(format!(
            "the kernel's seccomp notification structures are {actual:?} bytes, not the \
             {expected:?} this build knows"
        )))
    }
}

impl Listener {
    /// Adopt a listener received from a sandboxed process.
    pub(crate) fn new(fd: OwnedFd) -> Self {
        Self { fd }
    }

    /// Ask the kernel to wake this supervisor on the stopped task's CPU.
    pub(crate) fn set_sync_wake_up(&self) -> io::Result<()> {
        // SAFETY: `NOTIF_SET_FLAGS` takes the flags by value.
        let result = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_SET_FLAGS,
                SYNC_WAKE_UP,
            )
        };
        cvt(result).map(drop)
    }

    /// Wait for the next notification.
    pub(crate) fn recv(&self) -> io::Result<libc::seccomp_notif> {
        let mut notification = MaybeUninit::<libc::seccomp_notif>::zeroed();
        // SAFETY: the kernel requires a zeroed buffer of its structure's size,
        // which `zeroed` provides, and fills it in.
        let result = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_RECV,
                notification.as_mut_ptr(),
            )
        };
        cvt(result)?;
        // SAFETY: the receive succeeded, so the kernel wrote the structure.
        Ok(unsafe { notification.assume_init() })
    }

    /// Whether the notification `id` is still waiting for a reply, so the task
    /// it stands for is the one that made the call.
    pub(crate) fn is_valid(&self, id: u64) -> bool {
        let mut id = id;
        // SAFETY: `NOTIF_ID_VALID` reads one `u64`.
        let result = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
                &raw mut id,
            )
        };
        result == 0
    }

    /// Whether no task is left that the filter applies to.
    pub(crate) fn is_orphaned(&self) -> bool {
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: 0,
            revents: 0,
        };
        // SAFETY: one valid `pollfd`, and a zero timeout.
        let ready = unsafe { libc::poll(&raw mut poll, 1, 0) };
        ready > 0 && poll.revents & libc::POLLHUP != 0
    }

    /// Answer notification `id`.
    pub(crate) fn reply(&self, id: u64, reply: Reply) -> io::Result<()> {
        match reply {
            Reply::Value(value) => self.send(id, value, 0, 0),
            Reply::Errno(errno) => self.send(id, 0, -errno, 0),
            Reply::Continue => self.send(id, 0, 0, libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32),
            Reply::Fd { fd, cloexec } => {
                // The descriptor is installed without `SECCOMP_ADDFD_FLAG_SEND`,
                // so the caller stays stopped until the answer below: the
                // broker's own copy must be closed first, or a file the caller
                // just wrote is still open for writing here and its `execve`
                // fails with `ETXTBSY`. The filter's `WAIT_KILLABLE_RECV` keeps
                // the caller waiting across both steps.
                let mut request = libc::seccomp_notif_addfd {
                    id,
                    flags: 0,
                    srcfd: u32::try_from(fd.as_raw_fd()).map_err(io::Error::other)?,
                    newfd: 0,
                    newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
                };
                // SAFETY: `NOTIF_ADDFD` reads one `seccomp_notif_addfd`.
                let result = unsafe {
                    libc::ioctl(
                        self.fd.as_raw_fd(),
                        libc::SECCOMP_IOCTL_NOTIF_ADDFD,
                        &raw mut request,
                    )
                };
                drop(fd);
                match cvt(result) {
                    Ok(installed) => self.send(id, i64::from(installed), 0, 0),
                    // The task is gone, so there is nobody to answer.
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Err(error),
                    // The descriptor could not be installed, which leaves the
                    // notification waiting for a reply of its own.
                    Err(error) => {
                        let errno = error.raw_os_error().unwrap_or(libc::EIO);
                        self.send(id, 0, -errno, 0)
                    }
                }
            }
        }
    }

    fn send(&self, id: u64, value: i64, error: i32, flags: u32) -> io::Result<()> {
        let mut response = libc::seccomp_notif_resp {
            id,
            val: value,
            error,
            flags,
        };
        // SAFETY: `NOTIF_SEND` reads one `seccomp_notif_resp`.
        let result = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_SEND,
                &raw mut response,
            )
        };
        cvt(result).map(drop)
    }
}

fn cvt(result: libc::c_int) -> io::Result<libc::c_int> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

/// Copy `length` bytes from address `address` of the task `tid`.
pub(crate) fn read_memory(tid: u32, address: u64, length: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; length];
    let mut done = 0;
    while done < length {
        let local = libc::iovec {
            iov_base: buffer[done..].as_mut_ptr().cast(),
            iov_len: length - done,
        };
        let remote = libc::iovec {
            iov_base: (address as usize + done) as *mut libc::c_void,
            iov_len: length - done,
        };
        // SAFETY: both iovecs are valid for the call, the local one points into
        // `buffer`, and the remote one is only ever read by the kernel.
        let read = unsafe { libc::process_vm_readv(tid as libc::pid_t, &local, 1, &remote, 1, 0) };
        match usize::try_from(read) {
            Ok(0) => return Err(io::Error::from_raw_os_error(libc::EFAULT)),
            Ok(read) => done += read,
            Err(_) => return Err(io::Error::last_os_error()),
        }
    }
    Ok(buffer)
}

/// Copy the NUL-terminated string at `address` of the task `tid`, one page at a
/// time so that a string ending just before an unmapped page is still read.
pub(crate) fn read_c_string(tid: u32, address: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut at = address;
    loop {
        let to_page_end = PAGE - (at as usize % PAGE);
        let chunk = read_memory(tid, at, to_page_end)?;
        if let Some(end) = chunk.iter().position(|&byte| byte == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk);
        if bytes.len() >= PATH_MAX {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        at += to_page_end as u64;
    }
}

/// Take descriptor `fd` of the task `tgid` as a descriptor of this process.
pub(crate) fn steal_fd(tgid: u32, fd: RawFd) -> io::Result<OwnedFd> {
    let pid = rustix::process::Pid::from_raw(i32::try_from(tgid).map_err(io::Error::other)?)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ESRCH))?;
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
    let stolen =
        rustix::process::pidfd_getfd(&pidfd, fd, rustix::process::PidfdGetfdFlags::empty())?;
    Ok(stolen)
}
