//! Standalone persistent sandbox runner compiled into `OUT_DIR/heel-unix-runner`.
//!
//! Built directly with `rustc` so every library build embeds it without
//! external binary version skew.
//!
//! - On **macOS**, one instance runs inside `/usr/bin/sandbox-exec` per
//!   confined `Sandbox` and forks every command of that sandbox so they share a
//!   single `(target same-sandbox)` credential and inherit live extension
//!   grants.
//! - On **Linux**, one instance runs as PID 1 (`init`) of an unprivileged
//!   `CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS` container per confined
//!   `Sandbox` with a private `/proc` mount, spawns nested child PID namespaces
//!   for child sandboxes, and also serves per-command tree supervision
//!   (`--supervise`) inside the namespace.

#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::ffi::{CString, c_char};
#[cfg(target_os = "linux")]
use std::ffi::{c_char, c_long, c_ulong};
use std::ffi::{c_int, c_uint, c_void};
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::ExitStatus;
use std::process::{Child, Command, ExitCode, Stdio};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use std::collections::{BTreeMap, BTreeSet};

const OP_SPAWN: u8 = 1;
const OP_KILL: u8 = 2;
#[cfg(target_os = "macos")]
const OP_GRANT: u8 = 3;
#[cfg(target_os = "linux")]
const OP_SPAWN_CHILD_RUNNER: u8 = 4;

const EV_SPAWN_OK: u8 = 1;
const EV_SPAWN_ERR: u8 = 2;
const EV_EXITED: u8 = 3;
const EV_ACK: u8 = 4;
const EV_ERR: u8 = 5;

const STDIO_INHERIT: u8 = 0;
const STDIO_NULL: u8 = 1;
const STDIO_PIPED: u8 = 2;

/// `<sys/resource.h>` `struct rlimit`.
#[repr(C)]
struct Rlimit {
    rlim_cur: u64,
    rlim_max: u64,
}

/// `<sys/uio.h>` `struct iovec`.
#[repr(C)]
struct IoVec {
    iov_base: *mut c_void,
    iov_len: usize,
}

#[cfg(target_os = "macos")]
type Socklen = u32;
#[cfg(target_os = "linux")]
type Socklen = usize;

/// `<sys/socket.h>` `struct msghdr`.
#[repr(C)]
struct MsgHdr {
    msg_name: *mut c_void,
    msg_namelen: u32,
    msg_iov: *mut IoVec,
    #[cfg(target_os = "macos")]
    msg_iovlen: c_int,
    #[cfg(target_os = "linux")]
    msg_iovlen: usize,
    msg_control: *mut c_void,
    msg_controllen: Socklen,
    msg_flags: c_int,
}

/// `<sys/socket.h>` `struct cmsghdr`.
#[repr(C)]
struct CmsgHdr {
    cmsg_len: Socklen,
    cmsg_level: c_int,
    cmsg_type: c_int,
}

/// `<errno.h>` `ESRCH`.
const ESRCH: c_int = 3;
/// `<errno.h>` `EINTR`.
const EINTR: c_int = 4;
/// `<errno.h>` `EAGAIN` on Linux.
#[cfg(target_os = "linux")]
const EAGAIN: c_int = 11;

/// `<fcntl.h>` `F_SETFD`, `F_GETFL`, `F_SETFL`, `FD_CLOEXEC`.
const F_SETFD: c_int = 2;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const FD_CLOEXEC: c_int = 1;

/// `<fcntl.h>` `O_NONBLOCK`.
#[cfg(target_os = "macos")]
const O_NONBLOCK: c_int = 0x0004;
#[cfg(target_os = "linux")]
const O_NONBLOCK: c_int = 0x0800;

/// `<signal.h>` signal numbers and `SIG_BLOCK` / `SIG_SETMASK`.
#[cfg(target_os = "macos")]
const SIGCHLD: c_int = 20;
#[cfg(target_os = "linux")]
const SIGCHLD: c_int = 17;

const SIGKILL: c_int = 9;
const SIGPIPE: c_int = 13;
#[cfg(target_os = "linux")]
const SIGSTOP: c_int = 19;
const SIG_DFL: usize = 0;

#[cfg(target_os = "macos")]
const SIG_BLOCK: c_int = 1;
#[cfg(target_os = "macos")]
const SIG_SETMASK: c_int = 3;

#[cfg(target_os = "linux")]
const SIG_BLOCK: c_int = 0;
#[cfg(target_os = "linux")]
const SIG_SETMASK: c_int = 2;

/// `<sys/socket.h>` `SOL_SOCKET` and `SCM_RIGHTS`.
#[cfg(target_os = "macos")]
const SOL_SOCKET: c_int = 0xffff;
#[cfg(target_os = "linux")]
const SOL_SOCKET: c_int = 1;

const SCM_RIGHTS: c_int = 1;

/// `<sys/socket.h>` `MSG_CMSG_CLOEXEC` and `MSG_NOSIGNAL`.
#[cfg(target_os = "linux")]
const MSG_CMSG_CLOEXEC: c_int = 0x4000_0000;
#[cfg(target_os = "macos")]
const MSG_CMSG_CLOEXEC: c_int = 0;

#[cfg(target_os = "linux")]
const MSG_NOSIGNAL: c_int = 0x4000;

/// `<sys/wait.h>` `WNOHANG`.
const WNOHANG: c_int = 1;
/// `<sys/resource.h>` `PRIO_PROCESS`.
const PRIO_PROCESS: c_int = 0;

/// `<signal.h>` `sigset_t`.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
#[repr(C)]
struct SigSet(u32);

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
#[repr(C)]
struct SigSet {
    words: [c_ulong; 16],
}

impl SigSet {
    fn empty() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self(0)
        }
        #[cfg(target_os = "linux")]
        {
            Self { words: [0; 16] }
        }
    }

    fn with_sigchld() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self(1u32 << (SIGCHLD - 1))
        }
        #[cfg(target_os = "linux")]
        {
            let mut s = Self::empty();
            s.words[0] = (1 as c_ulong) << (SIGCHLD - 1);
            s
        }
    }
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct SigAction {
    sa_handler: usize,
    sa_mask: u32,
    sa_flags: c_int,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct SigAction {
    sa_handler: usize,
    sa_flags: c_ulong,
    sa_restorer: usize,
    sa_mask: SigSet,
}

unsafe extern "C" {
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn setrlimit(resource: c_int, rlim: *const Rlimit) -> c_int;
    fn setpriority(which: c_int, who: c_uint, prio: c_int) -> c_int;
    fn recvmsg(sockfd: c_int, msg: *mut MsgHdr, flags: c_int) -> isize;
    fn signal(signum: c_int, handler: usize) -> usize;
    fn sigaction(signum: c_int, act: *const SigAction, oldact: *mut SigAction) -> c_int;
    fn pthread_sigmask(how: c_int, set: *const SigSet, oldset: *mut SigSet) -> c_int;

    #[cfg(target_os = "linux")]
    fn close(fd: c_int) -> c_int;
    #[cfg(target_os = "linux")]
    fn dup2(oldfd: c_int, newfd: c_int) -> c_int;
    #[cfg(target_os = "linux")]
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    #[cfg(target_os = "linux")]
    fn sendmsg(sockfd: c_int, msg: *const MsgHdr, flags: c_int) -> isize;
    #[cfg(target_os = "linux")]
    fn _exit(status: c_int) -> !;

    #[cfg(target_os = "macos")]
    fn kqueue() -> c_int;
    #[cfg(target_os = "macos")]
    fn kevent(
        kq: c_int,
        changelist: *const macos_ev::Kevent,
        nchanges: c_int,
        eventlist: *mut macos_ev::Kevent,
        nevents: c_int,
        timeout: *const c_void,
    ) -> c_int;
    #[cfg(target_os = "macos")]
    fn setiopolicy_np(iotype: c_int, scope: c_int, policy: c_int) -> c_int;
    #[cfg(target_os = "macos")]
    fn sandbox_extension_consume(token: *const c_char) -> i64;

    #[cfg(target_os = "linux")]
    fn poll(fds: *mut linux_ev::PollFd, nfds: c_uint, timeout: c_int) -> c_int;
    #[cfg(target_os = "linux")]
    fn signalfd(fd: c_int, mask: *const SigSet, flags: c_int) -> c_int;
    #[cfg(target_os = "linux")]
    fn fork() -> c_int;
    #[cfg(target_os = "linux")]
    fn getpid() -> c_int;
    #[cfg(target_os = "linux")]
    fn getuid() -> c_uint;
    #[cfg(target_os = "linux")]
    fn getgid() -> c_uint;
    #[cfg(target_os = "linux")]
    fn raise(sig: c_int) -> c_int;
    #[cfg(target_os = "linux")]
    fn unshare(flags: c_int) -> c_int;
    #[cfg(target_os = "linux")]
    fn mount(
        source: *const c_char,
        target: *const c_char,
        filesystemtype: *const c_char,
        mountflags: c_ulong,
        data: *const c_void,
    ) -> c_int;
    #[cfg(target_os = "linux")]
    fn prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> c_int;
    #[cfg(target_os = "linux")]
    fn syscall(num: c_long, ...) -> c_long;
}

fn reset_sigchld_default() -> io::Result<()> {
    #[cfg(target_os = "macos")]
    let act = SigAction {
        sa_handler: SIG_DFL,
        sa_mask: 0,
        sa_flags: 0,
    };
    #[cfg(target_os = "linux")]
    let act = SigAction {
        sa_handler: SIG_DFL,
        sa_flags: 0,
        sa_restorer: 0,
        sa_mask: SigSet::empty(),
    };
    // SAFETY: `act` is initialized with `SIG_DFL` and `sigaction` on `SIGCHLD` is valid.
    if unsafe { sigaction(SIGCHLD, &raw const act, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn block_sigchld() -> io::Result<SigSet> {
    reset_sigchld_default()?;
    let block = SigSet::with_sigchld();
    let mut original = SigSet::empty();
    // SAFETY: `block` and `original` are valid `sigset_t` values on this platform.
    let rc = unsafe { pthread_sigmask(SIG_BLOCK, &raw const block, &raw mut original) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok(original)
}

fn set_cloexec_nonblock(fd: RawFd, nonblock: bool) -> io::Result<()> {
    // SAFETY: `fd` is an open descriptor owned by this process.
    unsafe {
        if fcntl(fd, F_SETFD, FD_CLOEXEC) == -1 {
            return Err(io::Error::last_os_error());
        }
        let flags = fcntl(fd, F_GETFL);
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        let target = if nonblock {
            flags | O_NONBLOCK
        } else {
            flags & !O_NONBLOCK
        };
        if fcntl(fd, F_SETFL, target) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod macos_ev {
    use super::*;

    /// `<sys/event.h>` `EVFILT_READ` (`-1`) and `EVFILT_SIGNAL` (`-6`).
    pub const EVFILT_READ: i16 = -1;
    pub const EVFILT_SIGNAL: i16 = -6;
    /// `<sys/event.h>` `EV_ADD` (`0x0001`).
    pub const EV_ADD: u16 = 0x0001;

    /// `<sys/event.h>` `struct kevent` on Darwin (`#pragma pack(4)`).
    #[derive(Clone, Copy)]
    #[repr(C, packed(4))]
    pub struct Kevent {
        pub ident: usize,
        pub filter: i16,
        pub flags: u16,
        pub fflags: u32,
        pub data: isize,
        pub udata: *mut c_void,
    }

    pub struct Watcher {
        kq: OwnedFd,
    }

    #[derive(Default)]
    pub struct Ready {
        pub control_readable: bool,
        pub child_signal: bool,
    }

    impl Watcher {
        pub fn new(control_fd: RawFd) -> io::Result<Self> {
            // SAFETY: `kqueue` takes no arguments and returns a new descriptor or -1.
            let raw = unsafe { kqueue() };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `raw` was just created by `kqueue`; `F_SETFD` marks it close-on-exec.
            let kq = unsafe { OwnedFd::from_raw_fd(raw) };
            unsafe {
                if fcntl(kq.as_raw_fd(), F_SETFD, FD_CLOEXEC) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }

            let changes = [
                Kevent {
                    ident: control_fd as usize,
                    filter: EVFILT_READ,
                    flags: EV_ADD,
                    fflags: 0,
                    data: 0,
                    udata: std::ptr::null_mut(),
                },
                Kevent {
                    ident: SIGCHLD as usize,
                    filter: EVFILT_SIGNAL,
                    flags: EV_ADD,
                    fflags: 0,
                    data: 0,
                    udata: std::ptr::null_mut(),
                },
            ];
            // SAFETY: `changes` holds 2 initialized `kevent` entries; no events are read back.
            let rc = unsafe {
                kevent(
                    kq.as_raw_fd(),
                    changes.as_ptr(),
                    2,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { kq })
        }

        pub fn wait(&self) -> io::Result<Ready> {
            let mut events = [Kevent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            }; 2];
            loop {
                // SAFETY: `events` has room for 2 `kevent` records; null timeout blocks until ready.
                let n = unsafe {
                    kevent(
                        self.kq.as_raw_fd(),
                        std::ptr::null(),
                        0,
                        events.as_mut_ptr(),
                        2,
                        std::ptr::null(),
                    )
                };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(EINTR) {
                        continue;
                    }
                    return Err(err);
                }
                let mut out = Ready::default();
                for ev in &events[..n as usize] {
                    let filter = ev.filter;
                    if filter == EVFILT_READ {
                        out.control_readable = true;
                    } else if filter == EVFILT_SIGNAL {
                        out.child_signal = true;
                    }
                }
                return Ok(out);
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_ev {
    use super::*;

    /// `<poll.h>` `struct pollfd`, `POLLIN`, `POLLERR`, `POLLHUP`.
    #[repr(C)]
    pub struct PollFd {
        pub fd: c_int,
        pub events: i16,
        pub revents: i16,
    }

    pub const POLLIN: i16 = 0x0001;
    pub const POLLERR: i16 = 0x0008;
    pub const POLLHUP: i16 = 0x0010;

    /// `<sys/signalfd.h>` `SFD_NONBLOCK | SFD_CLOEXEC`.
    const SFD_NONBLOCK: c_int = 0x0800;
    const SFD_CLOEXEC: c_int = 0x0008_0000;

    pub struct Watcher {
        control_fd: RawFd,
        sig_fd: OwnedFd,
    }

    #[derive(Default)]
    pub struct Ready {
        pub control_readable: bool,
        pub child_signal: bool,
    }

    impl Watcher {
        pub fn new(control_fd: RawFd) -> io::Result<Self> {
            let mask = SigSet::with_sigchld();
            // SAFETY: `mask` is initialized and `-1` creates a new `signalfd`.
            let raw = unsafe { signalfd(-1, &raw const mask, SFD_NONBLOCK | SFD_CLOEXEC) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `raw` is a fresh descriptor returned by `signalfd`.
            let sig_fd = unsafe { OwnedFd::from_raw_fd(raw) };
            Ok(Self { control_fd, sig_fd })
        }

        pub fn wait(&self) -> io::Result<Ready> {
            self.wait_timeout(-1)
        }

        pub fn wait_timeout(&self, timeout_ms: c_int) -> io::Result<Ready> {
            let mut fds = [
                PollFd {
                    fd: self.control_fd,
                    events: POLLIN,
                    revents: 0,
                },
                PollFd {
                    fd: self.sig_fd.as_raw_fd(),
                    events: POLLIN,
                    revents: 0,
                },
            ];
            loop {
                // SAFETY: `fds` holds 2 initialized `PollFd` entries.
                let rc = unsafe { poll(fds.as_mut_ptr(), 2, timeout_ms) };
                if rc < 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(EINTR) {
                        continue;
                    }
                    return Err(err);
                }
                let mut out = Ready::default();
                if fds[0].revents & (POLLIN | POLLHUP | POLLERR) != 0 {
                    out.control_readable = true;
                }
                if fds[1].revents & POLLIN != 0 {
                    out.child_signal = true;
                    // Drain 128-byte `signalfd_siginfo` records.
                    let mut siginfo = [0u8; 128];
                    loop {
                        // SAFETY: `siginfo` is a 128-byte stack buffer matching `signalfd_siginfo`.
                        let n = unsafe {
                            read(
                                self.sig_fd.as_raw_fd(),
                                siginfo.as_mut_ptr().cast(),
                                siginfo.len(),
                            )
                        };
                        if n <= 0 {
                            break;
                        }
                    }
                }
                return Ok(out);
            }
        }
    }
}

#[cfg(target_os = "macos")]
use macos_ev::Watcher;
#[cfg(target_os = "linux")]
use linux_ev::Watcher;

#[cfg(target_os = "macos")]
const fn cmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

#[cfg(target_os = "linux")]
const fn cmsg_align(len: usize) -> usize {
    (len + 7) & !7
}

const fn cmsg_space(data_len: usize) -> usize {
    cmsg_align(std::mem::size_of::<CmsgHdr>()) + cmsg_align(data_len)
}

#[cfg(target_os = "linux")]
const fn cmsg_len(data_len: usize) -> Socklen {
    (cmsg_align(std::mem::size_of::<CmsgHdr>()) + data_len) as Socklen
}

fn recv_packet(sock: RawFd) -> io::Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
    let mut len_bytes = [0u8; 4];
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut cmsg_buf = [0u8; cmsg_space(std::mem::size_of::<RawFd>() * 8)];
    let mut read_so_far = 0usize;

    while read_so_far < 4 {
        let mut iov = IoVec {
            iov_base: len_bytes[read_so_far..].as_mut_ptr().cast(),
            iov_len: 4 - read_so_far,
        };
        let use_cmsg = read_so_far == 0;
        let mut hdr = MsgHdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &raw mut iov,
            msg_iovlen: 1,
            msg_control: if use_cmsg {
                cmsg_buf.as_mut_ptr().cast()
            } else {
                std::ptr::null_mut()
            },
            msg_controllen: if use_cmsg {
                cmsg_buf.len() as Socklen
            } else {
                0
            },
            msg_flags: 0,
        };
        let n = loop {
            // SAFETY: `hdr`, `iov`, and `cmsg_buf` outlive `recvmsg` on `sock`.
            let rc = unsafe { recvmsg(sock, &raw mut hdr, MSG_CMSG_CLOEXEC) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(EINTR) {
                    continue;
                }
                return Err(err);
            }
            break rc as usize;
        };
        if n == 0 {
            if read_so_far == 0 {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated frame header",
            ));
        }
        if use_cmsg && hdr.msg_controllen as usize >= std::mem::size_of::<CmsgHdr>() {
            let mut offset = 0usize;
            let total = hdr.msg_controllen as usize;
            let data_off = cmsg_align(std::mem::size_of::<CmsgHdr>());
            while offset + std::mem::size_of::<CmsgHdr>() <= total {
                // SAFETY: `offset + sizeof(CmsgHdr) <= total <= cmsg_buf.len()` and aligned.
                let cmsg = unsafe { &*cmsg_buf.as_ptr().add(offset).cast::<CmsgHdr>() };
                let clen = cmsg.cmsg_len as usize;
                if clen < data_off || offset + clen > total {
                    break;
                }
                if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_RIGHTS {
                    let count = (clen - data_off) / std::mem::size_of::<RawFd>();
                    // SAFETY: `offset + clen <= total <= cmsg_buf.len()`.
                    let ptr = unsafe { cmsg_buf.as_ptr().add(offset + data_off).cast::<RawFd>() };
                    for i in 0..count {
                        // SAFETY: `i < count` within the ancillary payload, read unaligned.
                        let raw = unsafe { ptr.add(i).read_unaligned() };
                        // SAFETY: kernel transferred ownership of `raw` via `SCM_RIGHTS`.
                        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                        let _ = set_cloexec_nonblock(owned.as_raw_fd(), false);
                        fds.push(owned);
                    }
                }
                offset += cmsg_align(clen);
            }
        }
        read_so_far += n;
    }

    let payload_len = u32::from_le_bytes(len_bytes) as usize;
    let mut payload = vec![0u8; payload_len];
    let mut pos = 0;
    while pos < payload_len {
        // SAFETY: `payload[pos..]` is valid writable memory of `payload_len - pos` bytes.
        let rc = unsafe {
            read(
                sock,
                payload[pos..].as_mut_ptr().cast(),
                payload_len - pos,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(EINTR) {
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated frame body",
            ));
        }
        pos += rc as usize;
    }
    Ok(Some((payload, fds)))
}

fn send_frame(stream: &mut UnixStream, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len()).map_err(io::Error::other)?;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(target_os = "linux")]
fn send_single_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
    let byte = [0u8; 1];
    let mut iov = IoVec {
        iov_base: byte.as_ptr().cast_mut().cast(),
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; cmsg_space(std::mem::size_of::<RawFd>())];
    let data_off = cmsg_align(std::mem::size_of::<CmsgHdr>());
    // SAFETY: `cmsg_buf` is sized by `cmsg_space(sizeof(RawFd))`.
    unsafe {
        let cmsg = &mut *cmsg_buf.as_mut_ptr().cast::<CmsgHdr>();
        cmsg.cmsg_len = cmsg_len(std::mem::size_of::<RawFd>());
        cmsg.cmsg_level = SOL_SOCKET;
        cmsg.cmsg_type = SCM_RIGHTS;
        cmsg_buf
            .as_mut_ptr()
            .add(data_off)
            .cast::<RawFd>()
            .write_unaligned(fd);
    }
    let hdr = MsgHdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &raw mut iov,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr().cast(),
        msg_controllen: cmsg_buf.len() as Socklen,
        msg_flags: 0,
    };
    loop {
        // SAFETY: `hdr` and its buffers are valid for the duration of `sendmsg`.
        let rc = unsafe { sendmsg(sock, &raw const hdr, MSG_NOSIGNAL) };
        if rc >= 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(EINTR) {
            return Err(err);
        }
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn u8(&mut self) -> io::Result<u8> {
        let b = *self.buf.get(self.pos).ok_or_else(eof)?;
        self.pos += 1;
        Ok(b)
    }

    fn u32(&mut self) -> io::Result<u32> {
        let s = self.buf.get(self.pos..self.pos + 4).ok_or_else(eof)?;
        self.pos += 4;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn i32(&mut self) -> io::Result<i32> {
        let s = self.buf.get(self.pos..self.pos + 4).ok_or_else(eof)?;
        self.pos += 4;
        Ok(i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn u64(&mut self) -> io::Result<u64> {
        let s = self.buf.get(self.pos..self.pos + 8).ok_or_else(eof)?;
        self.pos += 8;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn bytes(&mut self) -> io::Result<&'a [u8]> {
        let len = self.u32()? as usize;
        let s = self.buf.get(self.pos..self.pos + len).ok_or_else(eof)?;
        self.pos += len;
        Ok(s)
    }

    fn string(&mut self) -> io::Result<String> {
        let bytes = self.bytes()?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn opt_i32(&mut self) -> io::Result<Option<i32>> {
        if self.u8()? == 0 {
            Ok(None)
        } else {
            Ok(Some(self.i32()?))
        }
    }
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected end of message")
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

#[cfg(target_os = "macos")]
fn consume_tokens(tokens: &[CString]) -> io::Result<()> {
    for token in tokens {
        // SAFETY: `token` is a NUL-terminated C string issued by `sandbox_extension_issue_file`.
        let handle = unsafe { sandbox_extension_consume(token.as_ptr()) };
        if handle < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn stdio_from_mode(mode: u8, fds: &mut std::vec::IntoIter<OwnedFd>) -> io::Result<Stdio> {
    match mode {
        STDIO_INHERIT => Ok(Stdio::inherit()),
        STDIO_NULL => Ok(Stdio::null()),
        STDIO_PIPED => {
            let fd = fds.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing piped stdio descriptor")
            })?;
            Ok(Stdio::from(File::from(fd)))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown stdio mode {other}"),
        )),
    }
}

fn apply_limits_and_priority(
    limits: &[(i32, u64)],
    nice: Option<i32>,
    io_policy: Option<i32>,
) -> io::Result<()> {
    for &(resource, val) in limits {
        let rlim = Rlimit {
            rlim_cur: val,
            rlim_max: val,
        };
        // SAFETY: `rlim` is initialized and `resource` was prepared on the same OS.
        if unsafe { setrlimit(resource, &raw const rlim) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if let Some(nice) = nice {
        // SAFETY: `setpriority` takes plain integers and is async-signal-safe.
        if unsafe { setpriority(PRIO_PROCESS, 0, nice) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if let Some(policy) = io_policy {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `IOPOL_TYPE_DISK` (0) and `IOPOL_SCOPE_PROCESS` (0) are valid constants.
            if unsafe { setiopolicy_np(0, 0, policy) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(target_os = "linux")]
        {
            /// `<asm/unistd.h>` `SYS_ioprio_set`, `IOPRIO_WHO_PROCESS` (1).
            #[cfg(target_arch = "x86_64")]
            const SYS_IOPRIO_SET: c_long = 251;
            #[cfg(target_arch = "aarch64")]
            const SYS_IOPRIO_SET: c_long = 30;
            // SAFETY: bare `ioprio_set` syscall on the calling process.
            if unsafe { syscall(SYS_IOPRIO_SET, 1 as c_int, 0 as c_int, policy) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux_ns {
    use super::*;

    /// `<linux/sched.h>` namespace flags.
    pub const CLONE_NEWNS: c_int = 0x0002_0000;
    pub const CLONE_NEWUSER: c_int = 0x1000_0000;
    pub const CLONE_NEWPID: c_int = 0x2000_0000;

    /// `<sys/mount.h>` mount flags.
    pub const MS_NOSUID: c_ulong = 2;
    pub const MS_NODEV: c_ulong = 4;
    pub const MS_NOEXEC: c_ulong = 8;
    pub const MS_REC: c_ulong = 16384;
    pub const MS_PRIVATE: c_ulong = 1 << 18;

    /// `<linux/prctl.h>` operations.
    pub const PR_SET_PDEATHSIG: c_int = 1;
    pub const PR_SET_DUMPABLE: c_int = 4;
    pub const PR_SET_CHILD_SUBREAPER: c_int = 36;
    pub const PR_SET_NO_NEW_PRIVS: c_int = 38;

    /// `<asm-generic/unistd.h>` syscall numbers.
    pub const SYS_PIDFD_SEND_SIGNAL: c_long = 424;
    pub const SYS_PIDFD_OPEN: c_long = 434;
    pub const SYS_LANDLOCK_RESTRICT_SELF: c_long = 446;

    #[cfg(target_arch = "x86_64")]
    pub const SYS_SECCOMP: c_long = 317;
    #[cfg(target_arch = "aarch64")]
    pub const SYS_SECCOMP: c_long = 277;

    /// `<linux/seccomp.h>` flags.
    pub const SECCOMP_SET_MODE_FILTER: c_uint = 1;
    pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: c_ulong = 1 << 3;
    pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: c_ulong = 1 << 5;

    #[repr(C)]
    pub struct SockFilter {
        pub code: u16,
        pub jt: u8,
        pub jf: u8,
        pub k: u32,
    }

    #[repr(C)]
    pub struct SockFprog {
        pub len: u16,
        pub filter: *const SockFilter,
    }

    pub fn decode_filters(bytes: &[u8]) -> io::Result<Vec<SockFilter>> {
        if !bytes.len().is_multiple_of(8) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid BPF filter length",
            ));
        }
        let mut out = Vec::with_capacity(bytes.len() / 8);
        for chunk in bytes.chunks_exact(8) {
            out.push(SockFilter {
                code: u16::from_ne_bytes([chunk[0], chunk[1]]),
                jt: chunk[2],
                jf: chunk[3],
                k: u32::from_ne_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
            });
        }
        Ok(out)
    }

    pub fn mount_private_proc() -> io::Result<OwnedFd> {
        use std::os::unix::fs::OpenOptionsExt;

        let root = c"/";
        let proc_str = c"proc";
        let proc_dir = c"/proc";
        /// Linux `<fcntl.h>`: `O_PATH` (`0o10000000` on both x86_64 and aarch64).
        const O_PATH: i32 = 0o1000_0000;
        // SAFETY: all pointers are static NUL-terminated C strings.
        unsafe {
            if mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                MS_PRIVATE | MS_REC,
                std::ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if mount(
                proc_str.as_ptr(),
                proc_dir.as_ptr(),
                proc_str.as_ptr(),
                MS_NOSUID | MS_NOEXEC | MS_NODEV,
                std::ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_PATH)
            .open("/proc")?;
        Ok(OwnedFd::from(file))
    }

    pub fn send_handshake_with_proc(control: &UnixStream, proc_fd: RawFd) -> io::Result<()> {
        let mut payload = Vec::with_capacity(5);
        payload.push(EV_ACK);
        payload.extend_from_slice(&1u32.to_le_bytes());
        let len_bytes = (payload.len() as u32).to_le_bytes();
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(&payload);

        let mut iov = IoVec {
            iov_base: frame.as_ptr().cast_mut().cast(),
            iov_len: frame.len(),
        };
        let mut cmsg_buf = [0u8; super::cmsg_space(std::mem::size_of::<RawFd>())];
        let data_off = super::cmsg_align(std::mem::size_of::<super::CmsgHdr>());
        // SAFETY: `cmsg_buf` is sized by `cmsg_space(sizeof(RawFd))`.
        unsafe {
            let cmsg = &mut *cmsg_buf.as_mut_ptr().cast::<super::CmsgHdr>();
            cmsg.cmsg_len = super::cmsg_len(std::mem::size_of::<RawFd>());
            cmsg.cmsg_level = super::SOL_SOCKET;
            cmsg.cmsg_type = super::SCM_RIGHTS;
            cmsg_buf
                .as_mut_ptr()
                .add(data_off)
                .cast::<RawFd>()
                .write_unaligned(proc_fd);
        }
        let hdr = super::MsgHdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &raw mut iov,
            msg_iovlen: 1,
            msg_control: cmsg_buf.as_mut_ptr().cast(),
            msg_controllen: cmsg_buf.len() as super::Socklen,
            msg_flags: 0,
        };
        let sent = loop {
            // SAFETY: `hdr`, `iov` and `cmsg_buf` outlive `sendmsg`.
            let rc = unsafe { super::sendmsg(control.as_raw_fd(), &raw const hdr, super::MSG_NOSIGNAL) };
            if rc >= 0 {
                break rc as usize;
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(super::EINTR) {
                return Err(err);
            }
        };
        if sent < frame.len() {
            let mut clone = control.try_clone()?;
            clone.write_all(&frame[sent..])?;
        }
        Ok(())
    }

    pub fn bootstrap_root(mut control: UnixStream) -> ExitCode {
        // SAFETY: `getuid` and `getgid` are pure queries with no preconditions.
        let (uid, gid) = unsafe { (getuid(), getgid()) };

        let setup: io::Result<c_int> = (|| {
            // SAFETY: single-threaded process unsharing user, mount and PID namespaces.
            unsafe {
                if unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            std::fs::write("/proc/self/setgroups", "deny\n")?;
            std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"))?;
            std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"))?;

            // SAFETY: process is single-threaded here.
            let pid = unsafe { fork() };
            if pid < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(pid)
        })();

        match setup {
            Err(err) => {
                let mut msg = vec![EV_ERR];
                push_str(&mut msg, &err.to_string());
                let _ = send_frame(&mut control, &msg);
                ExitCode::FAILURE
            }
            Ok(0) => {
                // SAFETY: inside PID 1 of the new PID namespace; single-threaded.
                unsafe {
                    let _ = prctl(PR_SET_PDEATHSIG, SIGKILL as c_ulong, 0, 0, 0);
                    let _ = prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
                }
                let proc_fd = match mount_private_proc() {
                    Ok(fd) => fd,
                    Err(err) => {
                        let mut msg = vec![EV_ERR];
                        push_str(&mut msg, &format!("mounting /proc in pid_ns failed: {err}"));
                        let _ = send_frame(&mut control, &msg);
                        return ExitCode::FAILURE;
                    }
                };
                let (original_mask, watcher) = match init_serve_watcher(&control) {
                    Ok(pair) => pair,
                    Err(err) => {
                        let mut msg = vec![EV_ERR];
                        push_str(&mut msg, &format!("runner watcher init failed: {err}"));
                        let _ = send_frame(&mut control, &msg);
                        return ExitCode::FAILURE;
                    }
                };
                if send_handshake_with_proc(&control, proc_fd.as_raw_fd()).is_err() {
                    return ExitCode::FAILURE;
                }
                drop(proc_fd);
                serve(control, original_mask, watcher)
            }
            Ok(init_pid) => {
                drop(control);
                let mut status: c_int = 0;
                loop {
                    // SAFETY: waiting on child `init_pid` so `init` stays a descendant of embedder.
                    let rc = unsafe { waitpid(init_pid, &raw mut status, 0) };
                    if rc == init_pid {
                        break;
                    }
                    if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(EINTR) {
                        break;
                    }
                }
                ExitCode::SUCCESS
            }
        }
    }

    pub fn spawn_nested_child(child_control: OwnedFd, original_mask: SigSet) -> io::Result<()> {
        // SAFETY: runner is single-threaded.
        let outer = unsafe { fork() };
        if outer < 0 {
            return Err(io::Error::last_os_error());
        }
        if outer > 0 {
            return Ok(());
        }

        let mut control = UnixStream::from(child_control);
        // SAFETY: single-threaded child restoring signal mask before creating nested namespaces.
        unsafe {
            let _ = pthread_sigmask(SIG_SETMASK, &raw const original_mask, std::ptr::null_mut());
            let _ = signal(SIGCHLD, SIG_DFL);
        }
        // SAFETY: unsharing mount + PID namespaces inside existing user namespace.
        if unsafe { unshare(CLONE_NEWNS | CLONE_NEWPID) } != 0 {
            let err = io::Error::last_os_error();
            let mut msg = vec![EV_ERR];
            push_str(&mut msg, &err.to_string());
            let _ = send_frame(&mut control, &msg);
            // SAFETY: exiting child process immediately without running parent destructors.
            unsafe { _exit(1) };
        }
        // SAFETY: single-threaded fork into new nested PID namespace.
        let inner = unsafe { fork() };
        if inner < 0 {
            let err = io::Error::last_os_error();
            let mut msg = vec![EV_ERR];
            push_str(&mut msg, &err.to_string());
            let _ = send_frame(&mut control, &msg);
            // SAFETY: exiting child process immediately.
            unsafe { _exit(1) };
        }
        if inner == 0 {
            // SAFETY: inside nested PID 1.
            unsafe {
                let _ = prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
            }
            let proc_fd = match mount_private_proc() {
                Ok(fd) => fd,
                Err(err) => {
                    let mut msg = vec![EV_ERR];
                    push_str(&mut msg, &format!("mounting nested /proc failed: {err}"));
                    let _ = send_frame(&mut control, &msg);
                    // SAFETY: exiting nested PID 1 on mount failure.
                    unsafe { _exit(1) };
                }
            };
            let (nested_mask, watcher) = match init_serve_watcher(&control) {
                Ok(pair) => pair,
                Err(err) => {
                    let mut msg = vec![EV_ERR];
                    push_str(&mut msg, &format!("nested watcher init failed: {err}"));
                    let _ = send_frame(&mut control, &msg);
                    // SAFETY: exiting nested PID 1 on watcher failure.
                    unsafe { _exit(1) };
                }
            };
            if send_handshake_with_proc(&control, proc_fd.as_raw_fd()).is_err() {
                // SAFETY: exiting nested PID 1 on broken control socket.
                unsafe { _exit(1) };
            }
            drop(proc_fd);
            let code = serve(control, nested_mask, watcher);
            // SAFETY: exiting nested PID 1 cleanly.
            unsafe { _exit(i32::from(code == ExitCode::FAILURE)) };
        }

        drop(control);
        let mut status: c_int = 0;
        loop {
            // SAFETY: waiting on nested PID 1 (`inner`).
            let rc = unsafe { waitpid(inner, &raw mut status, 0) };
            if rc == inner {
                break;
            }
            if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(EINTR) {
                break;
            }
        }
        // SAFETY: exiting intermediate wrapper cleanly.
        unsafe { _exit(0) }
    }
}

#[cfg(target_os = "linux")]
mod supervise_mode {
    use super::*;

    fn json_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    fn format_report(killed: &[(u32, String)], survivors: &[(u32, String)]) -> String {
        let fmt_list = |items: &[(u32, String)]| -> String {
            items
                .iter()
                .map(|(pid, name)| format!("{{\"pid\":{pid},\"name\":{}}}", json_escape(name)))
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "{{\"killed\":[{}],\"survivors\":[{}]}}",
            fmt_list(killed),
            fmt_list(survivors)
        )
    }

    fn send_json_line(stream: &mut UnixStream, json: &str) -> io::Result<()> {
        stream.write_all(json.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()
    }

    fn proc_stat(pid: u32) -> Option<(char, u32, String)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let open = stat.find('(')?;
        let close = stat.rfind(')')?;
        let name = stat[open + 1..close].to_owned();
        let rest = stat.get(close + 2..)?;
        let mut fields = rest.split_whitespace();
        let state = fields.next()?.chars().next()?;
        let ppid: u32 = fields.next()?.parse().ok()?;
        Some((state, ppid, name))
    }

    fn descendants_of(own: u32) -> Vec<(u32, char, String)> {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        for entry in entries.flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            if pid == own {
                continue;
            }
            if let Some((state, ppid, name)) = proc_stat(pid) {
                rows.push((pid, state, ppid, name));
            }
        }
        let mut tree = BTreeSet::new();
        tree.insert(own);
        loop {
            let before = tree.len();
            for &(pid, _, ppid, _) in &rows {
                if tree.contains(&ppid) {
                    tree.insert(pid);
                }
            }
            if tree.len() == before {
                break;
            }
        }
        rows.into_iter()
            .filter(|(pid, _, _, _)| *pid != own && tree.contains(pid))
            .map(|(pid, state, _, name)| (pid, state, name))
            .collect()
    }

    fn pidfd_open_checked(pid: u32) -> Option<OwnedFd> {
        // SAFETY: `SYS_pidfd_open` takes `(pid, flags)` by value.
        let raw = unsafe { syscall(linux_ns::SYS_PIDFD_OPEN, pid as c_int, 0 as c_uint) };
        if raw < 0 {
            return None;
        }
        // SAFETY: `raw` is a fresh pidfd owned by this process.
        Some(unsafe { OwnedFd::from_raw_fd(raw as RawFd) })
    }

    fn pidfd_sig(fd: &OwnedFd, sig: c_int) -> io::Result<()> {
        // SAFETY: `SYS_pidfd_send_signal` with null `siginfo_t` and flags 0 is valid.
        let rc = unsafe {
            syscall(
                linux_ns::SYS_PIDFD_SEND_SIGNAL,
                fd.as_raw_fd(),
                sig,
                std::ptr::null::<c_void>(),
                0 as c_uint,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ESRCH) {
                Ok(())
            } else {
                Err(err)
            }
        }
    }

    fn kill_tree(
        own: u32,
        cmd_pid: u32,
        cmd_status: &mut Option<ExitStatus>,
        watcher: &Watcher,
        reap_timeout: Duration,
    ) -> (Vec<(u32, String)>, Vec<(u32, String)>) {
        let mut frozen: BTreeMap<u32, (OwnedFd, String)> = BTreeMap::new();
        loop {
            let mut added = false;
            for (pid, state, name) in descendants_of(own) {
                if state == 'Z' || frozen.contains_key(&pid) {
                    continue;
                }
                let Some(pfd) = pidfd_open_checked(pid) else {
                    continue;
                };
                // Re-verify still in our descendant tree after opening pidfd.
                if !descendants_of(own).iter().any(|(p, _, _)| *p == pid) {
                    continue;
                }
                let _ = pidfd_sig(&pfd, SIGSTOP);
                frozen.insert(pid, (pfd, name));
                added = true;
            }
            if !added {
                break;
            }
        }

        let mut killed = Vec::new();
        for (&pid, (pfd, name)) in &frozen {
            let _ = pidfd_sig(pfd, SIGKILL);
            killed.push((pid, name.clone()));
        }

        let deadline = Instant::now() + reap_timeout;
        loop {
            loop {
                let mut st: c_int = 0;
                // SAFETY: reaping any child of this subreaper.
                let w = unsafe { waitpid(-1, &raw mut st, WNOHANG) };
                if w <= 0 {
                    break;
                }
                if w as u32 == cmd_pid && cmd_status.is_none() {
                    *cmd_status = Some(ExitStatus::from_raw(st));
                }
            }
            if descendants_of(own).is_empty() {
                return (killed, Vec::new());
            }
            let now = Instant::now();
            if now >= deadline {
                let survivors = descendants_of(own)
                    .into_iter()
                    .map(|(pid, _, name)| (pid, name))
                    .collect();
                return (killed, survivors);
            }
            let rem_ms = deadline
                .saturating_duration_since(now)
                .as_millis()
                .min(50) as c_int;
            let _ = watcher.wait_timeout(rem_ms.max(1));
        }
    }

    pub fn run(mut args: std::env::Args) -> ExitCode {
        let Some(mode) = args.next() else {
            return ExitCode::FAILURE;
        };
        let foreground = match mode.as_str() {
            "foreground" => true,
            "background" => false,
            _ => return ExitCode::FAILURE,
        };
        let Some(control_fd) = args.next().and_then(|s| s.parse::<RawFd>().ok()) else {
            return ExitCode::FAILURE;
        };
        let Some(cred_fd) = args.next().and_then(|s| s.parse::<RawFd>().ok()) else {
            return ExitCode::FAILURE;
        };
        let Some(reap_ms) = args.next().and_then(|s| s.parse::<u64>().ok()) else {
            return ExitCode::FAILURE;
        };
        if args.next().as_deref() != Some("--") {
            return ExitCode::FAILURE;
        }
        let Some(program) = args.next() else {
            return ExitCode::FAILURE;
        };
        let cmd_args: Vec<String> = args.collect();

        let _ = set_cloexec_nonblock(control_fd, true);
        let _ = set_cloexec_nonblock(cred_fd, false);
        // SAFETY: `control_fd` was inherited specifically for the supervisor control channel.
        let mut control = unsafe { UnixStream::from_raw_fd(control_fd) };
        // SAFETY: `cred_fd` was inherited for announcing the spawned command's host PID.
        let cred_owned = unsafe { OwnedFd::from_raw_fd(cred_fd) };

        let Ok(original_mask) = block_sigchld() else {
            return ExitCode::FAILURE;
        };
        // SAFETY: setting child subreaper before spawning the supervised command.
        if unsafe { prctl(linux_ns::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return ExitCode::FAILURE;
        }
        let Ok(watcher) = Watcher::new(control.as_raw_fd()) else {
            let _ = send_json_line(&mut control, "{\"Failed\":\"cannot create signalfd\"}");
            let _ = send_json_line(&mut control, "\"Done\"");
            return ExitCode::FAILURE;
        };

        let cred_raw = cred_owned.as_raw_fd();
        let mut cmd = Command::new(&program);
        cmd.args(&cmd_args).process_group(0);
        // SAFETY: `pre_exec` only calls async-signal-safe `pthread_sigmask`, `write`, and `close`.
        unsafe {
            cmd.pre_exec(move || {
                let rc =
                    pthread_sigmask(SIG_SETMASK, &raw const original_mask, std::ptr::null_mut());
                if rc != 0 {
                    return Err(io::Error::from_raw_os_error(rc));
                }
                let b = 1u8;
                if write(cred_raw, (&raw const b).cast(), 1) != 1 {
                    return Err(io::Error::last_os_error());
                }
                let _ = close(cred_raw);
                Ok(())
            });
        }

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(err) => {
                drop(cred_owned);
                let os_err = match err.raw_os_error() {
                    Some(c) => c.to_string(),
                    None => "null".to_owned(),
                };
                let line = format!(
                    "{{\"SpawnFailed\":{{\"os_error\":{os_err},\"message\":{}}}}}",
                    json_escape(&err.to_string())
                );
                let _ = send_json_line(&mut control, &line);
                let _ = send_json_line(&mut control, "\"Done\"");
                return ExitCode::FAILURE;
            }
        };
        drop(cred_owned);
        let cmd_pid = child.id();
        std::mem::forget(child);

        let started_line = format!("{{\"Started\":{{\"pid\":{cmd_pid}}}}}");
        let _ = send_json_line(&mut control, &started_line);

        // SAFETY: `getpid` has no preconditions.
        let own = unsafe { getpid() as u32 };
        let reap_timeout = Duration::from_millis(reap_ms);
        let mut cmd_status: Option<ExitStatus> = None;
        let mut req_buf = Vec::new();
        let mut tmp = [0u8; 256];

        loop {
            loop {
                let mut st: c_int = 0;
                // SAFETY: reaping any exited child of this subreaper.
                let w = unsafe { waitpid(-1, &raw mut st, WNOHANG) };
                if w <= 0 {
                    break;
                }
                if w as u32 == cmd_pid && cmd_status.is_none() {
                    cmd_status = Some(ExitStatus::from_raw(st));
                }
            }

            if foreground && cmd_status.is_some() {
                let (killed, survivors) =
                    kill_tree(own, cmd_pid, &mut cmd_status, &watcher, reap_timeout);
                let _ = send_json_line(
                    &mut control,
                    &format!("{{\"Leftover\":{}}}", format_report(&killed, &survivors)),
                );
                break;
            }

            if !foreground && cmd_status.is_some() && descendants_of(own).is_empty() {
                break;
            }

            let Ok(ready) = watcher.wait() else {
                break;
            };
            if ready.control_readable {
                let mut host_gone = false;
                let mut kill_requested = false;
                loop {
                    match control.read(&mut tmp) {
                        Ok(0) => {
                            host_gone = true;
                            break;
                        }
                        Ok(n) => {
                            req_buf.extend_from_slice(&tmp[..n]);
                            while let Some(nl) = req_buf.iter().position(|&b| b == b'\n') {
                                let line: Vec<u8> = req_buf.drain(..=nl).collect();
                                if std::str::from_utf8(&line)
                                    .is_ok_and(|s| s.trim() == "\"Kill\"")
                                {
                                    kill_requested = true;
                                }
                            }
                        }
                        Err(e) if e.raw_os_error() == Some(EAGAIN) => break,
                        Err(e) if e.raw_os_error() == Some(EINTR) => {}
                        Err(_) => {
                            host_gone = true;
                            break;
                        }
                    }
                }
                if kill_requested || host_gone {
                    let (killed, survivors) =
                        kill_tree(own, cmd_pid, &mut cmd_status, &watcher, reap_timeout);
                    if kill_requested {
                        let _ = send_json_line(
                            &mut control,
                            &format!("{{\"Killed\":{}}}", format_report(&killed, &survivors)),
                        );
                    }
                    break;
                }
            }
        }

        let Some(status) = cmd_status else {
            let (killed, survivors) =
                kill_tree(own, cmd_pid, &mut cmd_status, &watcher, reap_timeout);
            let _ = send_json_line(
                &mut control,
                &format!(
                    "{{\"CommandUnreaped\":{}}}",
                    format_report(&killed, &survivors)
                ),
            );
            let _ = send_json_line(&mut control, "\"Done\"");
            return ExitCode::FAILURE;
        };

        let _ = send_json_line(&mut control, "\"Done\"");
        if let Some(sig) = status.signal() {
            let zero = Rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // Disable core dumps (`RLIMIT_CORE = 4` on Linux) before re-raising signal.
            // SAFETY: `zero` is initialized and `RLIMIT_CORE` is 4 on Linux.
            unsafe {
                let _ = setrlimit(4, &raw const zero);
                let _ = pthread_sigmask(
                    SIG_SETMASK,
                    &raw const original_mask,
                    std::ptr::null_mut(),
                );
                let _ = signal(sig, SIG_DFL);
                let _ = raise(sig);
                _exit(128 + sig);
            }
        }
        ExitCode::from((status.code().unwrap_or(1) & 0xff) as u8)
    }
}

fn handle_spawn(
    cur: &mut Cursor<'_>,
    fds: Vec<OwnedFd>,
    original_mask: SigSet,
    children: &mut HashMap<u32, Child>,
    control: &mut UnixStream,
) -> io::Result<()> {
    let req_id = cur.u64()?;
    let program = cur.string()?;
    let args_len = cur.u32()? as usize;
    let mut args = Vec::with_capacity(args_len);
    for _ in 0..args_len {
        args.push(cur.string()?);
    }
    let envs_len = cur.u32()? as usize;
    let mut envs = Vec::with_capacity(envs_len);
    for _ in 0..envs_len {
        envs.push((cur.string()?, cur.string()?));
    }
    let cwd = PathBuf::from(cur.string()?);
    let stdin_mode = cur.u8()?;
    let stdout_mode = cur.u8()?;
    let stderr_mode = cur.u8()?;
    let limits_len = cur.u32()? as usize;
    let mut limits = Vec::with_capacity(limits_len);
    for _ in 0..limits_len {
        limits.push((cur.i32()?, cur.u64()?));
    }
    let nice = cur.opt_i32()?;
    let io_policy = cur.opt_i32()?;

    #[cfg(target_os = "macos")]
    let extra_tokens = {
        let n = cur.u32()? as usize;
        let mut list = Vec::with_capacity(n);
        for _ in 0..n {
            let s = cur.string()?;
            list.push(
                CString::new(s)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            );
        }
        list
    };

    #[cfg(target_os = "linux")]
    let (has_ruleset, notif_prog, filter_progs, extra_targets) = {
        let has_ruleset = cur.u8()? != 0;
        let notif_bytes = cur.bytes()?;
        let filter_count = cur.u32()? as usize;
        let mut progs = Vec::with_capacity(filter_count);
        for _ in 0..filter_count {
            progs.push(linux_ns::decode_filters(cur.bytes()?)?);
        }
        let extra_count = cur.u8()? as usize;
        let mut targets = Vec::with_capacity(extra_count);
        for _ in 0..extra_count {
            targets.push(cur.i32()?);
        }
        (
            has_ruleset,
            linux_ns::decode_filters(notif_bytes)?,
            progs,
            targets,
        )
    };

    let mut fd_iter = fds.into_iter();
    let stdin_cfg = stdio_from_mode(stdin_mode, &mut fd_iter)?;
    let stdout_cfg = stdio_from_mode(stdout_mode, &mut fd_iter)?;
    let stderr_cfg = stdio_from_mode(stderr_mode, &mut fd_iter)?;

    #[cfg(target_os = "linux")]
    let (cred_fd, ruleset_fd, broker_fd, extra_fds) = {
        let cred = fd_iter.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing cred socket fd")
        })?;
        let ruleset = if has_ruleset {
            Some(fd_iter.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing ruleset fd")
            })?)
        } else {
            None
        };
        let broker = if !notif_prog.is_empty() {
            Some(fd_iter.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing broker socket fd")
            })?)
        } else {
            None
        };
        let mut inherited = Vec::with_capacity(extra_targets.len());
        for target in extra_targets {
            let fd = fd_iter.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing inherited fd")
            })?;
            inherited.push((fd, target));
        }
        (cred, ruleset, broker, inherited)
    };

    let mut cmd = Command::new(&program);
    cmd.args(&args)
        .current_dir(&cwd)
        .env_clear()
        .envs(envs)
        .stdin(stdin_cfg)
        .stdout(stdout_cfg)
        .stderr(stderr_cfg)
        .process_group(0);

    #[cfg(target_os = "macos")]
    // SAFETY: `pre_exec` runs in the forked child before `exec` using async-signal-safe calls.
    unsafe {
        cmd.pre_exec(move || {
            let rc = pthread_sigmask(SIG_SETMASK, &raw const original_mask, std::ptr::null_mut());
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc));
            }
            let _ = signal(SIGCHLD, SIG_DFL);
            let _ = signal(SIGPIPE, SIG_DFL);
            consume_tokens(&extra_tokens)?;
            apply_limits_and_priority(&limits, nice, io_policy)
        });
    }

    #[cfg(target_os = "linux")]
    let cred_raw = cred_fd.as_raw_fd();
    #[cfg(target_os = "linux")]
    let ruleset_raw = ruleset_fd.as_ref().map(AsRawFd::as_raw_fd);
    #[cfg(target_os = "linux")]
    let broker_raw = broker_fd.as_ref().map(AsRawFd::as_raw_fd);
    #[cfg(target_os = "linux")]
    let inherit_pairs: Vec<(RawFd, i32)> = extra_fds
        .iter()
        .map(|(fd, target)| (fd.as_raw_fd(), *target))
        .collect();

    #[cfg(target_os = "linux")]
    // SAFETY: `pre_exec` runs in the forked child before `exec` and only issues syscalls.
    unsafe {
        cmd.pre_exec(move || {
            let rc = pthread_sigmask(SIG_SETMASK, &raw const original_mask, std::ptr::null_mut());
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc));
            }
            let _ = signal(SIGCHLD, SIG_DFL);
            let _ = signal(SIGPIPE, SIG_DFL);
            let _ = prctl(linux_ns::PR_SET_DUMPABLE, 1, 0, 0, 0);

            let marker = 1u8;
            if write(cred_raw, (&raw const marker).cast(), 1) != 1 {
                return Err(io::Error::last_os_error());
            }
            let _ = close(cred_raw);

            for &(src_fd, dst_fd) in &inherit_pairs {
                if src_fd == dst_fd {
                    if fcntl(dst_fd, F_SETFD, 0) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                } else if dup2(src_fd, dst_fd) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }

            apply_limits_and_priority(&limits, nice, io_policy)?;

            if let Some(rfd) = ruleset_raw {
                if prctl(linux_ns::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if syscall(linux_ns::SYS_LANDLOCK_RESTRICT_SELF, rfd, 0 as c_uint) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let _ = close(rfd);
            }

            if let Some(bsock) = broker_raw {
                if prctl(linux_ns::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let _ = prctl(linux_ns::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
                let prog = linux_ns::SockFprog {
                    len: notif_prog.len() as u16,
                    filter: notif_prog.as_ptr(),
                };
                let flags = linux_ns::SECCOMP_FILTER_FLAG_NEW_LISTENER
                    | linux_ns::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
                let listener = syscall(
                    linux_ns::SYS_SECCOMP,
                    linux_ns::SECCOMP_SET_MODE_FILTER,
                    flags,
                    &raw const prog,
                );
                if listener < 0 {
                    return Err(io::Error::last_os_error());
                }
                let lfd = listener as RawFd;
                let sent = send_single_fd(bsock, lfd);
                let _ = close(lfd);
                let _ = close(bsock);
                sent?;
            }

            if !filter_progs.is_empty() {
                if prctl(linux_ns::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                for filter_prog in &filter_progs {
                    let prog = linux_ns::SockFprog {
                        len: filter_prog.len() as u16,
                        filter: filter_prog.as_ptr(),
                    };
                    if syscall(
                        linux_ns::SYS_SECCOMP,
                        linux_ns::SECCOMP_SET_MODE_FILTER,
                        0 as c_ulong,
                        &raw const prog,
                    ) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
            }

            Ok(())
        });
    }

    let spawned = cmd.spawn();
    #[cfg(target_os = "linux")]
    drop((cred_fd, ruleset_fd, broker_fd, extra_fds));

    match spawned {
        Ok(child) => {
            let pid = child.id();
            children.insert(pid, child);
            let mut reply = Vec::with_capacity(13);
            reply.push(EV_SPAWN_OK);
            reply.extend_from_slice(&req_id.to_le_bytes());
            reply.extend_from_slice(&pid.to_le_bytes());
            send_frame(control, &reply)
        }
        Err(err) => {
            let mut reply = Vec::new();
            reply.push(EV_SPAWN_ERR);
            reply.extend_from_slice(&req_id.to_le_bytes());
            match err.raw_os_error() {
                Some(code) => {
                    reply.push(1);
                    reply.extend_from_slice(&code.to_le_bytes());
                }
                None => reply.push(0),
            }
            push_str(&mut reply, &err.to_string());
            send_frame(control, &reply)
        }
    }
}

fn reap_ready(children: &mut HashMap<u32, Child>, control: &mut UnixStream) -> io::Result<()> {
    loop {
        let mut status: c_int = 0;
        // SAFETY: reaping any exited child of this runner without blocking.
        let waited = unsafe { waitpid(-1, &raw mut status, WNOHANG) };
        if waited <= 0 {
            break;
        }
        let pid = waited as u32;
        if children.remove(&pid).is_some() {
            let mut ev = Vec::with_capacity(9);
            ev.push(EV_EXITED);
            ev.extend_from_slice(&pid.to_le_bytes());
            ev.extend_from_slice(&status.to_le_bytes());
            send_frame(control, &ev)?;
        }
    }
    Ok(())
}

fn kill_all_remaining(children: &mut HashMap<u32, Child>) {
    for (pid, mut child) in children.drain() {
        // SAFETY: each child was started in its own process group (`pgrp == pid`).
        unsafe {
            let _ = kill(-(pid as c_int), SIGKILL);
        }
        let _ = child.wait();
    }
}

fn init_serve_watcher(control: &UnixStream) -> io::Result<(SigSet, Watcher)> {
    let original_mask = block_sigchld()?;
    let watcher = Watcher::new(control.as_raw_fd())?;
    Ok((original_mask, watcher))
}

fn serve(mut control: UnixStream, original_mask: SigSet, watcher: Watcher) -> ExitCode {
    let mut children: HashMap<u32, Child> = HashMap::new();

    loop {
        let Ok(ready) = watcher.wait() else {
            break;
        };

        if ready.child_signal && reap_ready(&mut children, &mut control).is_err() {
            break;
        }

        if ready.control_readable {
            let packet = match recv_packet(control.as_raw_fd()) {
                Ok(Some(pkt)) => pkt,
                Ok(None) | Err(_) => break,
            };
            let (payload, fds) = packet;
            let mut cur = Cursor::new(&payload);
            let Ok(op) = cur.u8() else { break };

            let res = match op {
                OP_SPAWN => handle_spawn(&mut cur, fds, original_mask, &mut children, &mut control),
                OP_KILL => (|| -> io::Result<()> {
                    let req_id = cur.u64()?;
                    let pid = cur.u32()?;
                    // SAFETY: killing the spawned command's process group (`pgrp == pid`).
                    let rc = unsafe { kill(-(pid as c_int), SIGKILL) };
                    if rc != 0 {
                        let err = io::Error::last_os_error();
                        if err.raw_os_error() != Some(ESRCH) {
                            let mut reply = vec![EV_ERR];
                            reply.extend_from_slice(&req_id.to_le_bytes());
                            push_str(&mut reply, &err.to_string());
                            return send_frame(&mut control, &reply);
                        }
                    }
                    reap_ready(&mut children, &mut control)?;
                    if let Some(mut child) = children.remove(&pid)
                        && let Ok(status) = child.wait()
                    {
                        let mut ev = Vec::with_capacity(9);
                        ev.push(EV_EXITED);
                        ev.extend_from_slice(&pid.to_le_bytes());
                        ev.extend_from_slice(&status.into_raw().to_le_bytes());
                        send_frame(&mut control, &ev)?;
                    }
                    let mut reply = vec![EV_ACK];
                    reply.extend_from_slice(&req_id.to_le_bytes());
                    send_frame(&mut control, &reply)
                })(),
                #[cfg(target_os = "macos")]
                OP_GRANT => (|| -> io::Result<()> {
                    let req_id = cur.u64()?;
                    let count = cur.u32()? as usize;
                    let mut tokens = Vec::with_capacity(count);
                    for _ in 0..count {
                        let s = cur.string()?;
                        tokens.push(
                            CString::new(s)
                                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                        );
                    }
                    match consume_tokens(&tokens) {
                        Ok(()) => {
                            let mut reply = vec![EV_ACK];
                            reply.extend_from_slice(&req_id.to_le_bytes());
                            send_frame(&mut control, &reply)
                        }
                        Err(err) => {
                            let mut reply = vec![EV_ERR];
                            reply.extend_from_slice(&req_id.to_le_bytes());
                            push_str(&mut reply, &err.to_string());
                            send_frame(&mut control, &reply)
                        }
                    }
                })(),
                #[cfg(target_os = "linux")]
                OP_SPAWN_CHILD_RUNNER => (|| -> io::Result<()> {
                    let req_id = cur.u64()?;
                    let mut iter = fds.into_iter();
                    let child_sock = iter.next().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "missing child runner socket")
                    })?;
                    match linux_ns::spawn_nested_child(child_sock, original_mask) {
                        Ok(()) => {
                            let mut reply = vec![EV_ACK];
                            reply.extend_from_slice(&req_id.to_le_bytes());
                            send_frame(&mut control, &reply)
                        }
                        Err(err) => {
                            let mut reply = vec![EV_ERR];
                            reply.extend_from_slice(&req_id.to_le_bytes());
                            push_str(&mut reply, &err.to_string());
                            send_frame(&mut control, &reply)
                        }
                    }
                })(),
                _ => break,
            };

            if res.is_err() {
                break;
            }
            if reap_ready(&mut children, &mut control).is_err() {
                break;
            }
        }
    }

    kill_all_remaining(&mut children);
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let mut args = std::env::args();
    let _exe = args.next();
    let Some(first) = args.next() else {
        return ExitCode::FAILURE;
    };

    #[cfg(target_os = "linux")]
    if first == "--supervise" {
        return supervise_mode::run(args);
    }

    let Ok(raw_fd) = first.parse::<RawFd>() else {
        return ExitCode::FAILURE;
    };
    let _ = set_cloexec_nonblock(raw_fd, false);
    // SAFETY: `raw_fd` is the control socket descriptor passed on the command line.
    let control = unsafe { UnixStream::from_raw_fd(raw_fd) };

    #[cfg(target_os = "linux")]
    {
        linux_ns::bootstrap_root(control)
    }
    #[cfg(target_os = "macos")]
    {
        let Ok(mut clone) = control.try_clone() else {
            return ExitCode::FAILURE;
        };
        let (original_mask, watcher) = match init_serve_watcher(&control) {
            Ok(pair) => pair,
            Err(err) => {
                let mut msg = vec![EV_ERR];
                push_str(&mut msg, &format!("watcher init failed: {err}"));
                let _ = send_frame(&mut clone, &msg);
                return ExitCode::FAILURE;
            }
        };
        let mut ready = vec![EV_ACK];
        ready.extend_from_slice(&std::process::id().to_le_bytes());
        if send_frame(&mut clone, &ready).is_err() {
            return ExitCode::FAILURE;
        }
        drop(clone);
        serve(control, original_mask, watcher)
    }
}
