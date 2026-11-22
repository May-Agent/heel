//! Resolving the paths of a stopped process without being fooled by it.
//!
//! The path is copied out of the process once, and only the copy is used
//! afterwards. It is resolved against directory descriptors this process holds,
//! never against a path string, so nothing the sandbox does to the filesystem
//! after the copy can change which directory a name is looked up in. What
//! remains is the final name, which the operation itself is performed on, by the
//! broker, in that held directory.
//!
//! Paths that mean something different to each reader are resolved for the
//! caller: `/proc/self`, `/dev/stdout` and `/dev/fd` would otherwise hand the
//! sandbox this process's own descriptors and memory.
//!
//! The thread that resolves has a descriptor table of its own, so a path to one
//! of its own descriptors is `/proc/thread-self/fd/N` and never `/proc/self/fd/N`,
//! which names the embedder's table (see [`super::table`]).

use std::cell::OnceCell;
use std::ffi::OsStr;
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags, ResolveFlags};

use super::notify::{self, Listener};
use super::table;

/// `AT_FDCWD`.
pub(crate) const AT_FDCWD: i32 = -100;

/// `PROC_SUPER_MAGIC`.
const PROC_SUPER_MAGIC: i64 = 0x9fa0;

/// Sibling threads in the caller's thread group held in `PTRACE_EVENT_STOP`
/// across a continued syscall so they cannot mutate the caller's memory or
/// descriptor table between validation and kernel entry.
pub(crate) struct FrozenSiblings {
    attached: Vec<(libc::pid_t, libc::c_int)>,
}

impl FrozenSiblings {
    pub(crate) fn had_siblings(&self) -> bool {
        !self.attached.is_empty()
    }
}

impl Drop for FrozenSiblings {
    fn drop(&mut self) {
        for &(tid, sig) in &self.attached {
            // SAFETY: `PTRACE_DETACH` takes integer arguments and detaches a
            // thread this worker seized, re-delivering any pending signal `sig`.
            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, tid, 0, sig);
            }
        }
    }
}

/// Symbolic links followed by hand before giving up, as in the kernel.
const MAX_SYMLINKS: usize = 40;

/// What `/proc/<tid>/status` says about the stopped task.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Status {
    /// The process the task belongs to.
    pub tgid: u32,
    /// The file creation mask the task's calls are made under.
    pub umask: u32,
    /// Number of threads in the task's thread group.
    pub threads: u32,
}

fn read_status(tid: u32) -> io::Result<Status> {
    let text = std::fs::read_to_string(format!("/proc/{tid}/status"))?;
    let field = |name: &str, radix: u32| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| u32::from_str_radix(value.trim(), radix).ok())
            .ok_or_else(|| io::Error::other(format!("no {name} in /proc/{tid}/status")))
    };
    Ok(Status {
        tgid: field("Tgid:", 10)?,
        umask: field("Umask:", 8)?,
        threads: field("Threads:", 10)?,
    })
}

/// The stopped task that made a call.
pub(crate) struct Caller<'a> {
    pub(crate) listener: &'a Listener,
    pub(crate) id: u64,
    pub(crate) tid: u32,
    status: OnceCell<Status>,
}

impl<'a> Caller<'a> {
    pub(crate) fn new(listener: &'a Listener, id: u64, tid: u32) -> Self {
        Self {
            listener,
            id,
            tid,
            status: OnceCell::new(),
        }
    }

    /// Fail unless the task is still the one that made the call, which must be
    /// checked after anything read from `/proc` or from its memory.
    pub(crate) fn still_valid(&self) -> io::Result<()> {
        if self.listener.is_valid(self.id) {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(libc::ESRCH))
        }
    }

    /// The task's process id and file creation mask.
    pub(crate) fn status(&self) -> io::Result<Status> {
        if let Some(status) = self.status.get() {
            return Ok(*status);
        }
        let status = read_status(self.tid)?;
        self.still_valid()?;
        Ok(*self.status.get_or_init(|| status))
    }

    /// Copy a path out of the task's memory.
    pub(crate) fn read_path(&self, address: u64) -> io::Result<Vec<u8>> {
        let bytes = notify::read_c_string(self.tid, address)?;
        self.still_valid()?;
        Ok(bytes)
    }

    /// Copy bytes out of the task's memory.
    pub(crate) fn read_bytes(&self, address: u64, length: usize) -> io::Result<Vec<u8>> {
        let bytes = notify::read_memory(self.tid, address, length)?;
        self.still_valid()?;
        Ok(bytes)
    }

    /// Verify `[address, address + length)` belongs to a readable `MAP_PRIVATE`
    /// mapping and, when the thread group has sibling threads, quiesce every
    /// sibling in `PTRACE_EVENT_STOP` so neither the buffer nor the descriptor
    /// table can change while this task remains stopped.
    pub(crate) fn freeze_for_private_buffer(
        &self,
        address: u64,
        length: usize,
    ) -> io::Result<Option<FrozenSiblings>> {
        if length == 0 {
            return Ok(None);
        }
        let status = self.status()?;
        let mut frozen = FrozenSiblings {
            attached: Vec::new(),
        };
        if status.threads > 1 && !self.seize_siblings(status.tgid, &mut frozen)? {
            return Ok(None);
        }
        if !self.is_private_mapping(address, length)? {
            return Ok(None);
        }
        Ok(Some(frozen))
    }

    fn is_private_mapping(&self, address: u64, length: usize) -> io::Result<bool> {
        let Some(end) = address.checked_add(length as u64) else {
            return Ok(false);
        };
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.tid))?;
        let mut cursor = address;
        for line in maps.lines() {
            let mut columns = line.split_whitespace();
            let Some(range) = columns.next() else {
                continue;
            };
            let Some(perms) = columns.next() else {
                continue;
            };
            let Some((lo_hex, hi_hex)) = range.split_once('-') else {
                continue;
            };
            let (Ok(lo), Ok(hi)) = (
                u64::from_str_radix(lo_hex, 16),
                u64::from_str_radix(hi_hex, 16),
            ) else {
                continue;
            };
            if hi <= cursor {
                continue;
            }
            if lo > cursor || !perms.starts_with('r') || !perms.ends_with('p') {
                self.still_valid()?;
                return Ok(false);
            }
            if hi >= end {
                self.still_valid()?;
                return Ok(true);
            }
            cursor = hi;
        }
        self.still_valid()?;
        Ok(false)
    }

    fn seize_siblings(&self, tgid: u32, frozen: &mut FrozenSiblings) -> io::Result<bool> {
        let task_dir = format!("/proc/{tgid}/task");
        for _ in 0..4 {
            let entries = std::fs::read_dir(&task_dir)?;
            let mut added_any = false;
            for entry in entries {
                let Ok(entry) = entry else {
                    continue;
                };
                let Some(tid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse::<u32>().ok())
                else {
                    continue;
                };
                if tid == self.tid {
                    continue;
                }
                let pid = tid as libc::pid_t;
                if frozen.attached.iter().any(|&(seen, _)| seen == pid) {
                    continue;
                }
                // SAFETY: `PTRACE_SEIZE` attaches without stopping or signaling.
                let rc = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, 0, 0) };
                if rc != 0 {
                    if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                        continue;
                    }
                    return Ok(false);
                }
                frozen.attached.push((pid, 0));
                added_any = true;
                // SAFETY: `PTRACE_INTERRUPT` places a seized tracee into `PTRACE_EVENT_STOP`.
                let rc = unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, pid, 0, 0) };
                if rc != 0 {
                    if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                        continue;
                    }
                    return Ok(false);
                }
                let pending_sig = loop {
                    let mut wait_status: libc::c_int = 0;
                    // SAFETY: `waitpid` writes one `c_int` for the seized tracee `pid`.
                    let waited = unsafe { libc::waitpid(pid, &raw mut wait_status, libc::__WALL) };
                    if waited < 0 {
                        let err = io::Error::last_os_error().raw_os_error();
                        if err == Some(libc::EINTR) {
                            continue;
                        }
                        if err == Some(libc::ECHILD) || err == Some(libc::ESRCH) {
                            break None;
                        }
                        return Ok(false);
                    }
                    if libc::WIFSTOPPED(wait_status) {
                        let event = (wait_status >> 16) & 0xffff;
                        if event == libc::PTRACE_EVENT_STOP {
                            break Some(0);
                        }
                        break Some(libc::WSTOPSIG(wait_status));
                    }
                    break None;
                };
                if let Some(sig) = pending_sig
                    && let Some(last) = frozen.attached.last_mut()
                {
                    last.1 = sig;
                }
            }
            if !added_any {
                self.still_valid()?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The directory a relative path is looked up in: the task's working
    /// directory, or the directory descriptor it passed.
    pub(crate) fn base(&self, dirfd: i32) -> io::Result<OwnedFd> {
        let path = if dirfd == AT_FDCWD {
            format!("/proc/{}/cwd", self.tid)
        } else if dirfd >= 0 {
            format!("/proc/{}/fd/{dirfd}", self.tid)
        } else {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        };
        let fd = rustix::fs::openat(
            CWD,
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| {
            if dirfd != AT_FDCWD && errno == rustix::io::Errno::NOENT {
                io::Error::from_raw_os_error(libc::EBADF)
            } else {
                errno.into()
            }
        })?;
        self.still_valid()?;
        Ok(fd)
    }

    /// An `O_PATH` descriptor on descriptor `fd` of the task, whatever it is.
    pub(crate) fn reopen(&self, fd: i32) -> io::Result<OwnedFd> {
        if fd < 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        let opened = rustix::fs::openat(
            CWD,
            format!("/proc/{}/fd/{fd}", self.tid),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| {
            if errno == rustix::io::Errno::NOENT {
                io::Error::from_raw_os_error(libc::EBADF)
            } else {
                errno.into()
            }
        })?;
        self.still_valid()?;
        Ok(opened)
    }
}

/// Where a relative path starts.
#[derive(Clone, Copy)]
pub(crate) enum Base<'a> {
    /// The descriptor the task passed, or the working directory.
    Dirfd(i32),
    /// A directory this process holds.
    Held(&'a OwnedFd),
}

/// A name in a directory this process holds.
pub(crate) struct Place {
    /// The directory, held as an `O_PATH` descriptor.
    pub parent: OwnedFd,
    /// The directory's real path.
    pub parent_path: PathBuf,
    /// The last component, which may be `.` or `..`.
    pub name: Vec<u8>,
    /// Whether the path ended in a slash, which the kernel then requires to name
    /// a directory.
    pub trailing_slash: bool,
    /// Whether the directory is on `procfs`, where a symbolic link may be a
    /// magic link that the kernel resolves for whoever follows it.
    pub in_proc: bool,
}

impl Place {
    /// The real path the name denotes.
    pub(crate) fn target(&self) -> PathBuf {
        match self.name.as_slice() {
            b"." | b"" => self.parent_path.clone(),
            b".." => self
                .parent_path
                .parent()
                .map_or_else(|| PathBuf::from("/"), Path::to_path_buf),
            name => self.parent_path.join(OsStr::from_bytes(name)),
        }
    }

    /// The name to hand the kernel when performing an operation.
    pub(crate) fn kernel_name(&self) -> Vec<u8> {
        let mut name = self.name.clone();
        if self.trailing_slash {
            name.push(b'/');
        }
        name
    }

    /// What the name is right now, without following a symbolic link.
    pub(crate) fn stat(&self) -> io::Result<rustix::fs::Stat> {
        Ok(rustix::fs::statat(
            &self.parent,
            self.kernel_name(),
            AtFlags::SYMLINK_NOFOLLOW,
        )?)
    }
}

/// The directory part, the last component, and whether a slash ended the path.
fn split(path: &[u8]) -> (&[u8], &[u8], bool) {
    let trailing = path.ends_with(b"/");
    let trimmed = path.trim_ascii_end_slashes();
    if trimmed.is_empty() {
        return (b"/", b".", trailing);
    }
    match trimmed.iter().rposition(|&byte| byte == b'/') {
        None => (b"", trimmed, trailing),
        Some(0) => (b"/", &trimmed[1..], trailing),
        Some(index) => (&trimmed[..index], &trimmed[index + 1..], trailing),
    }
}

trait TrimSlashes {
    fn trim_ascii_end_slashes(&self) -> &[u8];
}

impl TrimSlashes for [u8] {
    fn trim_ascii_end_slashes(&self) -> &[u8] {
        let mut end = self.len();
        while end > 0 && self[end - 1] == b'/' {
            end -= 1;
        }
        &self[..end]
    }
}

fn on_procfs(fd: &impl AsFd) -> io::Result<bool> {
    Ok(rustix::fs::fstatfs(fd)?.f_type as i64 == PROC_SUPER_MAGIC)
}

/// The real path of a descriptor this thread holds.
///
/// Read through `/proc/thread-self`: the thread's table is its own, and
/// `/proc/self/fd` would name the descriptor of that number in the embedder's.
pub(crate) fn real_path(fd: &impl AsRawFd) -> io::Result<PathBuf> {
    let link = rustix::fs::readlink(table::thread_fd_path(fd), Vec::new())?;
    Ok(PathBuf::from(OsStr::from_bytes(link.to_bytes())))
}

/// Resolve `path` to the directory that holds its last component.
///
/// `extra` carries the caller's `openat2` resolution flags, which apply to the
/// directories it walks through.
pub(crate) fn resolve(
    caller: &Caller<'_>,
    base: Base<'_>,
    path: &[u8],
    extra: ResolveFlags,
) -> io::Result<Place> {
    if path.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    let (directory, name, trailing_slash) = split(path);
    let parent = open_directory(caller, base, directory, extra)?;
    let parent_path = real_path(&parent)?;
    let in_proc = on_procfs(&parent)?;
    Ok(Place {
        parent,
        parent_path,
        name: name.to_vec(),
        trailing_slash,
        in_proc,
    })
}

fn open_directory(
    caller: &Caller<'_>,
    base: Base<'_>,
    directory: &[u8],
    extra: ResolveFlags,
) -> io::Result<OwnedFd> {
    let anchored = extra.intersects(ResolveFlags::BENEATH | ResolveFlags::IN_ROOT);
    let owned_base;
    let start: Option<&OwnedFd> = match base {
        Base::Held(fd) => Some(fd),
        Base::Dirfd(_) if directory.starts_with(b"/") && !anchored => None,
        Base::Dirfd(dirfd) => {
            owned_base = caller.base(dirfd)?;
            Some(&owned_base)
        }
    };
    if directory.is_empty() {
        return start
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?
            .as_fd()
            .try_clone_to_owned();
    }

    let from = start.map_or(CWD, |fd| fd.as_fd());
    // Not `RESOLVE_NO_SYMLINKS` or `RESOLVE_BENEATH`: either would change what
    // ordinary paths mean. Magic links are the exception, because they are the
    // only links whose target depends on who follows them.
    match rustix::fs::openat2(
        from,
        directory,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        extra | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) if !on_procfs(&fd)? => Ok(fd),
        Ok(_) => walk(caller, start, directory),
        Err(rustix::io::Errno::LOOP) if !extra.contains(ResolveFlags::NO_SYMLINKS) => {
            walk(caller, start, directory)
        }
        Err(errno) => Err(errno.into()),
    }
}

/// Walk `directory` one component at a time, following links by hand and
/// standing in the task for `self` and `thread-self`.
fn walk(caller: &Caller<'_>, start: Option<&OwnedFd>, directory: &[u8]) -> io::Result<OwnedFd> {
    let root = || {
        rustix::fs::openat(
            CWD,
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)
    };
    let mut current = match start {
        Some(fd) if !directory.starts_with(b"/") => fd.as_fd().try_clone_to_owned()?,
        _ => root()?,
    };
    let mut pending: Vec<Vec<u8>> = directory
        .split(|&byte| byte == b'/')
        .filter(|component| !component.is_empty())
        .map(<[u8]>::to_vec)
        .rev()
        .collect();
    let mut followed = 0;
    while let Some(component) = pending.pop() {
        if component == b"." {
            continue;
        }
        if component == b".." {
            current = open_dir_at(&current, b"..")?;
            continue;
        }
        let in_proc_root = real_path(&current)? == Path::new("/proc");
        let component = match (in_proc_root, component.as_slice()) {
            (true, b"self") => caller.status()?.tgid.to_string().into_bytes(),
            (true, b"thread-self") => {
                let status = caller.status()?;
                pending.push(format!("{}", caller.tid).into_bytes());
                pending.push(b"task".to_vec());
                status.tgid.to_string().into_bytes()
            }
            _ => component,
        };
        let stat = rustix::fs::statat(&current, component.as_slice(), AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink {
            followed += 1;
            if followed > MAX_SYMLINKS {
                return Err(io::Error::from_raw_os_error(libc::ELOOP));
            }
            let target = rustix::fs::readlinkat(&current, component.as_slice(), Vec::new())?;
            let target = target.to_bytes();
            if target.starts_with(b"/") {
                current = root()?;
            }
            pending.extend(
                target
                    .split(|&byte| byte == b'/')
                    .filter(|part| !part.is_empty())
                    .map(<[u8]>::to_vec)
                    .rev(),
            );
        } else {
            current = open_dir_at(&current, &component)?;
        }
        caller.still_valid()?;
    }
    Ok(current)
}

fn open_dir_at(parent: &OwnedFd, name: &[u8]) -> io::Result<OwnedFd> {
    Ok(rustix::fs::openat(
        parent,
        name,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Follow symbolic links at the last component by hand, as the kernel would for
/// an operation that follows them, so that the name checked is the name acted
/// on. A magic link is left alone: it is opened, not read.
pub(crate) fn follow(
    caller: &Caller<'_>,
    mut place: Place,
    extra: ResolveFlags,
) -> io::Result<Place> {
    for _ in 0..MAX_SYMLINKS {
        if place.in_proc {
            return Ok(place);
        }
        let stat = match place.stat() {
            Ok(stat) => stat,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(place),
            Err(error) => return Err(error),
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::Symlink {
            return Ok(place);
        }
        if extra.contains(ResolveFlags::NO_SYMLINKS) {
            return Err(io::Error::from_raw_os_error(libc::ELOOP));
        }
        let target = rustix::fs::readlinkat(&place.parent, place.name.as_slice(), Vec::new())?;
        place = resolve(caller, Base::Held(&place.parent), target.to_bytes(), extra)?;
    }
    Err(io::Error::from_raw_os_error(libc::ELOOP))
}

/// The real path of the object a descriptor denotes, and what it is.
pub(crate) fn identify(fd: &OwnedFd) -> io::Result<(PathBuf, rustix::fs::Stat)> {
    let stat = rustix::fs::fstat(fd)?;
    Ok((real_path(fd)?, stat))
}
