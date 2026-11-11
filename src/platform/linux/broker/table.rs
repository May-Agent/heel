//! Descriptor tables of the broker's own, and the descriptors that move between
//! them.
//!
//! A POSIX record lock is owned by the descriptor table of the task that took it,
//! and every close that ends in `filp_close` removes all the locks of the closing
//! task's table on that inode: `close(2)`, `close_range`, `dup2` over a
//! descriptor, close-on-exec and the teardown of a table alike (`fs/open.c`
//! `filp_flush`, `fs/locks.c` `locks_remove_posix`). The broker opens files for the
//! sandbox inside the embedder's process, and closes its own copy once the
//! sandbox has its descriptor. Done in the embedder's table that close would
//! release locks the embedder holds on the file, so every thread of heel that
//! opens a descriptor of a user inode owns a table of its own. A table that is not
//! the embedder's can close any descriptor without touching the embedder's locks.
//! Locks owned by the open file description (`flock`, open file description
//! locks) are not affected either way.
//!
//! What follows from a thread having a table the embedder's code knows nothing
//! about:
//!
//! * `/proc/self/fd` names the thread-group leader's table, so a path to one of
//!   the thread's own descriptors is built by [`thread_fd_path`] and nowhere else;
//! * code of the embedder that runs on the thread, a `tracing` subscriber above
//!   all, would act on descriptor numbers that mean something else here, so such
//!   threads report through [`Diagnostic`](super::diag::Diagnostic) values that a
//!   thread of the embedder's own table emits;
//! * a panic would run the embedder's panic hook on the thread, which is why
//!   the code that runs there returns errno values and does not panic.

use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::{Builder, JoinHandle, Scope, ScopedJoinHandle};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

/// `CLOSE_RANGE_UNSHARE`: give the caller a table of its own first.
const CLOSE_RANGE_UNSHARE: libc::c_uint = 1 << 1;

/// The most descriptors one message carries, `SCM_MAX_FD`.
pub(crate) const MAX_FDS: usize = 253;

/// The path of descriptor `fd` of the calling thread's own table.
///
/// Never `/proc/self/fd`, which resolves through the thread-group leader.
pub(crate) fn thread_fd_path(fd: &impl AsRawFd) -> String {
    format!("/proc/thread-self/fd/{}", fd.as_raw_fd())
}

fn close_range(first: u32, last: u32, flags: libc::c_uint) -> io::Result<()> {
    // SAFETY: `close_range` takes three integers by value.
    let result = unsafe { libc::syscall(libc::SYS_close_range, first, last, flags) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// An error that says which call it came from.
fn named(call: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{call}: {error}"))
}

/// Whether the calling thread's descriptor table is the thread-group leader's,
/// which is the embedder's table.
///
/// A copy of `socket` made now is in this thread's table. The leader's table
/// holds the same socket under the same number only if the two are one table:
/// nothing else in the process has a descriptor of this socket but the starter,
/// under another number. Asked of procfs, which the broker needs anyway, and not
/// of `kcmp`, which a container's seccomp profile commonly refuses.
fn shares_the_leaders_table(socket: BorrowedFd<'_>) -> io::Result<bool> {
    let probe = rustix::io::fcntl_dupfd_cloexec(socket, 0)?;
    let mine = rustix::fs::fstat(&probe)?;
    match rustix::fs::stat(leader_fd_path(&probe)) {
        Ok(theirs) => Ok(theirs.st_dev == mine.st_dev && theirs.st_ino == mine.st_ino),
        // The leader has nothing under that number.
        Err(Errno::NOENT) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// The path of descriptor number `fd` in the thread-group leader's table: the
/// one place that means the embedder's table and not the thread's own.
fn leader_fd_path(fd: &impl AsRawFd) -> String {
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}

/// Give the calling thread a descriptor table of its own that holds `keep`,
/// `/dev/null` as descriptors 0, 1 and 2, and nothing else, and return `keep` as
/// a descriptor of that table.
///
/// The thread starts out sharing its creator's table. `close_range` with
/// `CLOSE_RANGE_UNSHARE` over a range that holds no descriptor copies the table
/// and closes nothing. The table is then checked to be the thread's own, because
/// everything after this closes descriptors and would close the embedder's if the
/// kernel had accepted the call without giving the thread a table: the check
/// fails, with nothing closed, before any descriptor is. The descriptors above
/// `keep` and then those below it go next. Each close runs with the new table as
/// the owner, which is what keeps the embedder's locks: the same work every
/// `fork` and `exec` does for the embedder's close-on-exec descriptors.
///
/// The check asks procfs whether a descriptor made after the unshare shows up
/// in the thread-group leader's table; a check that cannot be made stops the
/// thread.
///
/// # Safety
///
/// `keep` is open in the calling thread's table, and nothing closes it in the
/// table the thread is leaving before this returns.
unsafe fn private_table(keep: RawFd) -> io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;

    const UNSHARE: &str = "close_range(CLOSE_RANGE_UNSHARE)";
    let keep = u32::try_from(keep).map_err(io::Error::other)?;
    close_range(u32::MAX, u32::MAX, CLOSE_RANGE_UNSHARE).map_err(|error| named(UNSHARE, error))?;
    // SAFETY: the caller guarantees `keep` is open, in whichever table this is.
    let kept = unsafe { BorrowedFd::borrow_raw(keep as RawFd) };
    if shares_the_leaders_table(kept).map_err(|error| {
        named(
            "the check that the descriptor table is the thread's own",
            error,
        )
    })? {
        return Err(io::Error::other(format!(
            "{UNSHARE} succeeded but the thread still has the embedder's descriptor table"
        )));
    }
    close_range(keep + 1, u32::MAX, 0)
        .map_err(|error| named("close_range of the descriptors above the socket", error))?;
    if keep > 0 {
        close_range(0, keep - 1, 0)
            .map_err(|error| named("close_range of the descriptors below the socket", error))?;
    }
    // SAFETY: the caller guarantees the descriptor is open, and the new table
    // holds the only copy of it that this thread will use.
    let mut socket = unsafe { OwnedFd::from_raw_fd(keep as RawFd) };
    if keep < 3 {
        let moved = rustix::io::fcntl_dupfd_cloexec(&socket, 3)?;
        socket = moved;
    }
    // Stray writes by descriptor number to 0, 1 or 2 go nowhere, and never
    // land in a file this thread has open for the sandbox.
    for expected in 0..3 {
        let null = rustix::fs::open("/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())?;
        let number = null.into_raw_fd();
        if number != expected {
            return Err(io::Error::other(format!(
                "descriptor {expected} of a private table came out as {number}"
            )));
        }
    }
    Ok(socket)
}

/// What a thread tells the thread that started it once its table is its own.
type Ready = SyncSender<io::Result<()>>;

/// What the new thread runs: take the table, say so, then run `body`.
fn bootstrap<R>(keep: RawFd, ready: &Ready, body: impl FnOnce(OwnedFd) -> R) -> Option<R> {
    // SAFETY: the thread that started this one holds `keep` open until it has
    // heard from `ready`, which is sent below, after the table is private.
    match unsafe { private_table(keep) } {
        Ok(socket) => {
            let _ = ready.send(Ok(()));
            Some(body(socket))
        }
        Err(error) => {
            let _ = ready.send(Err(error));
            None
        }
    }
}

/// Wait for the thread to own its table, then close the starter's copy of `keep`.
fn handed_over(
    keep: OwnedFd,
    started: &std::sync::mpsc::Receiver<io::Result<()>>,
) -> io::Result<()> {
    let result = started
        .recv()
        .map_err(|_| io::Error::other("the thread ended before it had a table of its own"))?;
    drop(keep);
    result
}

/// Start a thread named `name` that owns a private descriptor table holding
/// only the descriptor `keep`, which `body` receives.
///
/// Returns once the table is in place. The starter's copy of `keep` is closed
/// by then. The handle's value is `None` if the table could not be made, in
/// which case `body` never ran.
pub(crate) fn spawn<F, R>(name: &str, keep: OwnedFd, body: F) -> io::Result<JoinHandle<Option<R>>>
where
    F: FnOnce(OwnedFd) -> R + Send + 'static,
    R: Send + 'static,
{
    let raw = keep.as_raw_fd();
    let (ready, started) = sync_channel(1);
    let handle = Builder::new()
        .name(name.to_owned())
        .spawn(move || bootstrap(raw, &ready, body))?;
    handed_over(keep, &started)?;
    Ok(handle)
}

/// [`spawn`] for a thread that borrows from its starter.
pub(crate) fn spawn_scoped<'scope, 'env, F, R>(
    scope: &'scope Scope<'scope, 'env>,
    name: &str,
    keep: OwnedFd,
    body: F,
) -> io::Result<ScopedJoinHandle<'scope, Option<R>>>
where
    F: FnOnce(OwnedFd) -> R + Send + 'scope,
    R: Send + 'scope,
{
    let raw = keep.as_raw_fd();
    let (ready, started) = sync_channel(1);
    let handle = Builder::new()
        .name(name.to_owned())
        .spawn_scoped(scope, move || bootstrap(raw, &ready, body))?;
    handed_over(keep, &started)?;
    Ok(handle)
}

/// A connected pair of `SOCK_SEQPACKET` sockets, which keep each message, with
/// its descriptors, whole.
pub(crate) fn socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    Ok(rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?)
}

/// Send `fds` over `socket` in one message.
///
/// Uses nothing but the stack, so it can run between `fork` and `exec`.
pub(crate) fn send_fds(socket: BorrowedFd<'_>, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    if fds.is_empty() || fds.len() > MAX_FDS {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // No `SIGPIPE` for a peer that is gone: the embedder's disposition of it is
    // not ours to rely on.
    rustix::net::sendmsg(
        socket,
        &[IoSlice::new(&[0])],
        &mut control,
        SendFlags::NOSIGNAL,
    )?;
    Ok(())
}

/// Receive the descriptors of the next message on `socket`, or `None` once the
/// other end is closed and everything it sent has been read.
pub(crate) fn recv_fds(socket: BorrowedFd<'_>) -> io::Result<Option<Vec<OwnedFd>>> {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut byte = [0u8];
    let received = loop {
        match rustix::net::recvmsg(
            socket,
            &mut [IoSliceMut::new(&mut byte)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        ) {
            Err(Errno::INTR) => {}
            result => break result?,
        }
    };
    let mut fds = Vec::new();
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(arrived) = message {
            fds.extend(arrived);
        }
    }
    if received.flags.contains(ReturnFlags::CTRUNC) {
        return Err(io::Error::other(
            "the descriptors of a message were cut short",
        ));
    }
    if fds.is_empty() {
        return if received.bytes == 0 {
            Ok(None)
        } else {
            Err(io::Error::other("a message arrived without a descriptor"))
        };
    }
    Ok(Some(fds))
}

/// What the tests of this module and of the setup thread look at.
#[cfg(test)]
pub(super) mod listing {
    use std::os::fd::RawFd;
    use std::path::PathBuf;

    /// The descriptors of the calling thread's table and what each one names, by
    /// number.
    pub(in super::super) fn thread_table() -> Vec<(RawFd, PathBuf)> {
        let mut numbers: Vec<RawFd> = std::fs::read_dir("/proc/thread-self/fd")
            .unwrap()
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
            .collect();
        numbers.sort_unstable();
        // The directory's own descriptor is closed by now, and no longer reads.
        numbers
            .into_iter()
            .filter_map(|number| {
                let target = std::fs::read_link(format!("/proc/thread-self/fd/{number}")).ok()?;
                Some((number, target))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::os::fd::AsFd;

    use super::*;

    /// Whether a thread of another table is refused a write lock on `path`.
    fn locked_for_others(path: &std::path::Path) -> bool {
        std::thread::scope(|scope| {
            let (mine, theirs) = socket_pair().unwrap();
            drop(mine);
            let probe = spawn_scoped(scope, "heel-table-probe", theirs, move |_socket| {
                let reopened = File::open(path).unwrap();
                // SAFETY: an all-zero `flock` is a valid request.
                let mut request: libc::flock = unsafe { std::mem::zeroed() };
                request.l_type = libc::F_WRLCK as libc::c_short;
                request.l_whence = libc::SEEK_SET as libc::c_short;
                // SAFETY: `request` outlives the call.
                let result =
                    unsafe { libc::fcntl(reopened.as_raw_fd(), libc::F_GETLK, &raw mut request) };
                assert_eq!(result, 0);
                request.l_type != libc::F_UNLCK as libc::c_short
            })
            .unwrap();
            probe.join().unwrap().unwrap()
        })
    }

    fn lock(file: &File) {
        // SAFETY: an all-zero `flock` is a valid request.
        let mut request: libc::flock = unsafe { std::mem::zeroed() };
        request.l_type = libc::F_WRLCK as libc::c_short;
        request.l_whence = libc::SEEK_SET as libc::c_short;
        // SAFETY: `request` outlives the call.
        let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &raw mut request) };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
    }

    /// The lock belongs to the table that took it: a thread that shares the
    /// table loses it by closing any descriptor of the file, and a thread with
    /// a table of its own does not.
    #[test]
    fn closing_a_file_in_a_private_table_keeps_the_locks_of_the_table_it_left() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("locked");
        std::fs::write(&path, "x").unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        lock(&file);
        assert!(locked_for_others(&path), "the lock was never taken");

        let (_mine, theirs) = socket_pair().unwrap();
        let private = spawn("heel-table-private", theirs, {
            let path = path.clone();
            move |_socket| drop(File::open(path).unwrap())
        })
        .unwrap();
        private.join().unwrap().unwrap();
        assert!(
            locked_for_others(&path),
            "a close in a private table released the embedder's lock"
        );

        // The same close from a thread that shares the table releases it, which
        // is what makes the check above mean something.
        std::thread::spawn({
            let path = path.clone();
            move || drop(File::open(path).unwrap())
        })
        .join()
        .unwrap();
        assert!(
            !locked_for_others(&path),
            "a close in the shared table kept the lock, so the check proves nothing"
        );
    }

    /// Descriptors 0, 1 and 2 are `/dev/null`, the socket is the only other
    /// descriptor, and none of the starter's descriptors came along.
    #[test]
    fn a_private_table_holds_the_socket_and_null_and_nothing_else() {
        let held: Vec<File> = (0..40)
            .map(|_| File::open("/proc/self/stat").unwrap())
            .collect();
        let (mine, theirs) = socket_pair().unwrap();
        let socket_number = theirs.as_raw_fd();
        let handle = spawn("heel-table-listing", theirs, |socket| {
            (socket.as_raw_fd(), listing::thread_table())
        })
        .unwrap();
        let (kept, table) = handle.join().unwrap().unwrap();
        drop(mine);
        assert_eq!(
            kept, socket_number,
            "the socket was renumbered although it was above 2"
        );
        let numbers: Vec<RawFd> = table.iter().map(|(number, _)| *number).collect();
        assert_eq!(numbers, [0, 1, 2, kept], "{table:?}");
        for (number, target) in &table[..3] {
            assert_eq!(
                target,
                std::path::Path::new("/dev/null"),
                "descriptor {number}"
            );
        }
        assert!(
            table[3].1.to_string_lossy().starts_with("socket:"),
            "{table:?}"
        );
        drop(held);
    }

    /// A socket that sits at 0, 1 or 2 is moved up so that those numbers can be
    /// `/dev/null`.
    #[test]
    fn a_socket_at_a_standard_number_is_moved_above_them() {
        let (mine, theirs) = socket_pair().unwrap();
        // The descriptors the test process was started with are open, so make
        // room: put the socket at 1 in this table, then leave it there.
        let raw = theirs.as_raw_fd();
        let result = std::thread::scope(|scope| {
            let handle = std::thread::Builder::new()
                .spawn_scoped(scope, || {
                    // A table of its own to rearrange without touching the test's.
                    close_range(raw as u32 + 1, u32::MAX, CLOSE_RANGE_UNSHARE).unwrap();
                    // SAFETY: duplicating over a descriptor of this thread's table.
                    unsafe { libc::dup2(raw, 1) };
                    // SAFETY: descriptor 1 is open in this table, and nothing
                    // closes the original before this returns. The descriptor
                    // belongs to a table of this thread, so only its number
                    // leaves it.
                    unsafe { private_table(1) }.map(|socket| socket.as_raw_fd())
                })
                .unwrap();
            handle.join().unwrap()
        });
        assert!(result.unwrap() >= 3);
        drop((mine, theirs));
    }

    #[test]
    fn descriptors_cross_in_one_message_and_the_end_of_the_stream_is_none() {
        let (mine, theirs) = socket_pair().unwrap();
        let directory = tempfile::tempdir().unwrap();
        // An `O_PATH` descriptor is one of the kinds that crosses.
        let path_fd = rustix::fs::open(
            directory.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let file = File::open("/proc/self/stat").unwrap();
        send_fds(mine.as_fd(), &[path_fd.as_fd(), file.as_fd()]).unwrap();
        send_fds(mine.as_fd(), &[file.as_fd()]).unwrap();
        drop(mine);

        let first = recv_fds(theirs.as_fd()).unwrap().unwrap();
        assert_eq!(first.len(), 2);
        let flags = rustix::fs::fcntl_getfl(&first[0]).unwrap();
        assert!(flags.contains(OFlags::PATH), "{flags:?}");
        assert_eq!(
            std::fs::read_link(thread_fd_path(&first[0])).unwrap(),
            directory.path().canonicalize().unwrap()
        );
        assert!(
            rustix::io::fcntl_getfd(&first[1])
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert_eq!(recv_fds(theirs.as_fd()).unwrap().unwrap().len(), 1);
        assert!(recv_fds(theirs.as_fd()).unwrap().is_none());
    }

    /// A thread of a table of its own opens a file. The path the helper builds
    /// names it, and `/proc/self/fd`, which follows the thread-group leader's
    /// table, does not: nothing the leader has open is that file.
    #[test]
    fn a_thread_fd_path_names_the_thread_and_not_the_leader() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("only-the-thread-opens-this");
        std::fs::write(&path, "x").unwrap();
        let wanted = path.canonicalize().unwrap();
        let (_mine, theirs) = socket_pair().unwrap();
        let seen = spawn("heel-table-path", theirs, {
            let path = path.clone();
            move |_socket| {
                let file = File::open(path).unwrap();
                let number = file.as_raw_fd();
                (
                    thread_fd_path(&file),
                    number,
                    std::fs::read_link(thread_fd_path(&file)).ok(),
                    std::fs::read_link(format!("/proc/self/fd/{number}")).ok(),
                )
            }
        })
        .unwrap()
        .join()
        .unwrap()
        .unwrap();
        let (helper, number, by_thread, by_leader) = seen;
        assert_eq!(helper, format!("/proc/thread-self/fd/{number}"));
        assert_eq!(by_thread, Some(wanted.clone()));
        assert_ne!(
            by_leader,
            Some(wanted),
            "/proc/self/fd/{number} named the thread's file, so the test shows nothing"
        );
    }

    /// A thread that shares the starter's table is the leader's, and the thread
    /// a private table was made for is not.
    #[test]
    fn the_check_tells_a_thread_of_its_own_table_from_one_that_shares() {
        let (ours, theirs) = socket_pair().unwrap();
        let shared = std::thread::scope(|scope| {
            scope
                .spawn(|| shares_the_leaders_table(ours.as_fd()).unwrap())
                .join()
                .unwrap()
        });
        let private = spawn("heel-table-check", theirs, |socket| {
            shares_the_leaders_table(socket.as_fd()).unwrap()
        })
        .unwrap()
        .join()
        .unwrap()
        .unwrap();
        assert!(shared, "a thread of the starter's table");
        assert!(!private, "a thread of a table of its own");
    }
}
