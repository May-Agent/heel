//! Host-side client for the persistent in-sandbox Unix runner (`runner_bin.rs`).

use std::collections::HashMap;
use std::ffi::c_int;
#[cfg(target_os = "linux")]
use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Read};
#[cfg(target_os = "linux")]
use std::os::fd::BorrowedFd;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use crate::command::StdioConfig;
use crate::error::{Error, Result};
#[cfg(target_os = "macos")]
use crate::grant::Grant;
use crate::platform::child::ProcessHandle;
use crate::workdir::{WorkingDir, generate_socket_dir_name};

/// Embedded `heel-unix-runner` executable compiled by `build.rs`.
const RUNNER_EXECUTABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/heel-unix-runner"));

const OP_SPAWN: u8 = 1;
const OP_KILL: u8 = 2;
#[cfg(target_os = "macos")]
const OP_SYNC_EXTENSIONS: u8 = 3;
#[cfg(target_os = "linux")]
const OP_SPAWN_CHILD_RUNNER: u8 = 4;

const EV_SPAWN_OK: u8 = 1;
const EV_SPAWN_ERR: u8 = 2;
const EV_EXITED: u8 = 3;
const EV_ACK: u8 = 4;
const EV_ERR: u8 = 5;

#[expect(
    dead_code,
    reason = "protocol tag reserved for runner-local inheritance; host inheritance sends host fds"
)]
const STDIO_INHERIT: u8 = 0;
const STDIO_NULL: u8 = 1;
const STDIO_PIPED: u8 = 2;

/// A private per-sandbox copy of `heel-unix-runner`, removed when dropped.
#[derive(Debug)]
pub(crate) struct StagedRunner {
    executable: PathBuf,
    _dir: WorkingDir,
}

impl StagedRunner {
    /// Stage the embedded runner binary into a private `0o700` directory.
    pub(crate) fn create() -> Result<Self> {
        let dir = WorkingDir::create(
            &crate::ipc::socket_root().join(generate_socket_dir_name()),
            true,
        )?;
        let executable = dir.path().join("heel-runner");
        std::fs::write(&executable, RUNNER_EXECUTABLE).map_err(|source| Error::WorkingDir {
            path: executable.clone(),
            source,
        })?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500)).map_err(
            |source| Error::WorkingDir {
                path: executable.clone(),
                source,
            },
        )?;
        Ok(Self {
            executable,
            _dir: dir,
        })
    }

    /// Path of the staged runner executable.
    pub(crate) fn path(&self) -> &Path {
        &self.executable
    }
}

/// Handle to an active [`Sandbox`](crate::Sandbox) that a child sandbox can
/// nest inside on Linux (`CLONE_NEWPID | CLONE_NEWNS`).
#[derive(Clone, Debug)]
pub struct SandboxHandle {
    #[cfg(target_os = "linux")]
    pub(crate) runner: Option<Arc<Runner>>,
}

#[derive(Debug)]
enum Reply {
    SpawnOk(u32),
    SpawnErr(io::Error),
    Ack,
    Err(String),
}

#[derive(Debug, Default)]
struct State {
    replies: HashMap<u64, Reply>,
    exited: HashMap<u32, ExitStatus>,
    closed: bool,
}

#[derive(Debug, Default)]
struct Mailbox {
    state: Mutex<State>,
    changed: Condvar,
}

impl Mailbox {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wait_reply(&self, req_id: u64) -> io::Result<Reply> {
        let mut guard = self
            .changed
            .wait_while(self.lock(), |s| {
                !s.replies.contains_key(&req_id) && !s.closed
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(reply) = guard.replies.remove(&req_id) {
            Ok(reply)
        } else {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sandbox runner exited before replying",
            ))
        }
    }

    fn wait_exit(&self, sandbox_pid: u32) -> io::Result<ExitStatus> {
        let mut guard = self
            .changed
            .wait_while(self.lock(), |s| {
                !s.exited.contains_key(&sandbox_pid) && !s.closed
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(status) = guard.exited.remove(&sandbox_pid) {
            Ok(status)
        } else {
            // Runner closed (sandbox teardown killed the container).
            Ok(ExitStatus::from_raw(libc::SIGKILL))
        }
    }

    fn try_exit(&self, sandbox_pid: u32) -> Option<ExitStatus> {
        self.lock().exited.remove(&sandbox_pid)
    }
}

/// Host connection to one persistent in-sandbox runner process.
#[derive(Debug)]
pub(crate) struct Runner {
    writer: Mutex<UnixStream>,
    mailbox: Arc<Mailbox>,
    next_id: AtomicU64,
    #[cfg(target_os = "linux")]
    init_host_pid: u32,
    #[cfg(target_os = "linux")]
    proc_fd: Option<OwnedFd>,
    outer_child: Mutex<Option<std::process::Child>>,
    #[cfg_attr(
        target_os = "macos",
        expect(dead_code, reason = "held so the staged directory outlives the runner")
    )]
    staged: Option<StagedRunner>,
}

impl Runner {
    /// Start a persistent macOS runner inside `/usr/bin/sandbox-exec`.
    #[cfg(target_os = "macos")]
    pub(crate) fn start_macos(
        staged: StagedRunner,
        profile: &str,
        setup: crate::platform::preexec::PreExecSetup,
    ) -> Result<Arc<Self>> {
        let (mut host_sock, child_sock) = UnixStream::pair()?;
        let child_fd = dup_above_stdio(&child_sock)?;
        drop(child_sock);
        let fd_num = child_fd.as_raw_fd();

        let mut cmd = Command::new("/usr/bin/sandbox-exec");
        cmd.arg("-p")
            .arg(profile)
            .arg(staged.path())
            .arg(fd_num.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        // SAFETY: detaches any inherited host controlling terminal via `setsid`
        // (which also creates a process group `pgid == pid` for `shutdown`),
        // clears `FD_CLOEXEC` on `fd_num`, and applies limits and priority
        // before `sandbox-exec` enters Seatbelt.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(fd_num, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                setup.apply()
            });
        }

        let mut child = crate::binary::retry_busy(|| cmd.spawn())
            .map_err(|e| Error::InitFailed(format!("cannot start macOS sandbox runner: {e}")))?;
        drop(child_fd);

        let _init_host_pid = match read_handshake(&mut host_sock) {
            Ok(pid) => pid,
            Err(err) => {
                let mut stderr = String::new();
                if let Some(mut err_pipe) = child.stderr.take() {
                    let _ = err_pipe.read_to_string(&mut stderr);
                }
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::InitFailed(format!(
                    "macOS sandbox runner failed handshake: {err} ({})",
                    stderr.trim()
                )));
            }
        };

        Self::from_connected(host_sock, Some(child), Some(staged))
    }

    /// Start a persistent Linux PID-namespace runner (root or nested inside `parent`).
    #[cfg(target_os = "linux")]
    pub(crate) fn start_linux(parent: Option<&SandboxHandle>) -> Result<Arc<Self>> {
        let staged = StagedRunner::create()?;
        if let Some(parent_runner) = parent.and_then(|h| h.runner.as_ref()) {
            return parent_runner.spawn_nested_linux_runner(staged);
        }

        let (host_sock, child_sock) = UnixStream::pair()?;
        enable_passcred(host_sock.as_raw_fd())?;
        let child_fd = dup_above_stdio(&child_sock)?;
        drop(child_sock);
        let fd_num = child_fd.as_raw_fd();

        let mut cmd = Command::new(staged.path());
        cmd.arg(fd_num.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        // SAFETY: clears `FD_CLOEXEC` on `fd_num` for the runner child.
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(fd_num, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = crate::binary::retry_busy(|| cmd.spawn())
            .map_err(|e| Error::InitFailed(format!("cannot start Linux namespace runner: {e}")))?;
        drop(child_fd);

        let (init_host_pid, proc_fd) = match read_linux_handshake(&host_sock) {
            Ok(res) => res,
            Err(err) => {
                let mut stderr = String::new();
                if let Some(mut err_pipe) = child.stderr.take() {
                    let _ = err_pipe.read_to_string(&mut stderr);
                }
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::InitFailed(format!(
                    "Linux namespace runner failed: {err} {}",
                    stderr.trim()
                )));
            }
        };

        Self::from_connected(
            host_sock,
            init_host_pid,
            Some(proc_fd),
            Some(child),
            Some(staged),
        )
    }

    #[cfg(target_os = "linux")]
    fn spawn_nested_linux_runner(&self, staged: StagedRunner) -> Result<Arc<Self>> {
        let (host_sock, child_sock) = UnixStream::pair()?;
        enable_passcred(host_sock.as_raw_fd())?;

        let req_id = self.alloc_id();
        let mut payload = Vec::with_capacity(9);
        payload.push(OP_SPAWN_CHILD_RUNNER);
        payload.extend_from_slice(&req_id.to_le_bytes());

        let child_owned: OwnedFd = child_sock.into();
        self.send_packet(&payload, &[child_owned.as_raw_fd()])?;
        drop(child_owned);

        match self.mailbox.wait_reply(req_id)? {
            Reply::Ack => {}
            Reply::Err(msg) => {
                return Err(Error::InitFailed(format!(
                    "nested Linux namespace runner failed: {msg}"
                )));
            }
            other => {
                return Err(Error::InitFailed(format!(
                    "unexpected nested runner reply: {other:?}"
                )));
            }
        }

        let (init_host_pid, proc_fd) = read_linux_handshake(&host_sock)
            .map_err(|e| Error::InitFailed(format!("nested Linux runner handshake failed: {e}")))?;

        Self::from_connected(host_sock, init_host_pid, Some(proc_fd), None, Some(staged))
    }

    fn from_connected(
        host_sock: UnixStream,
        #[cfg(target_os = "linux")] init_host_pid: u32,
        #[cfg(target_os = "linux")] proc_fd: Option<OwnedFd>,
        outer_child: Option<std::process::Child>,
        staged: Option<StagedRunner>,
    ) -> Result<Arc<Self>> {
        let reader_sock = host_sock.try_clone()?;
        let mailbox = Arc::new(Mailbox::default());
        let reader_mailbox = Arc::clone(&mailbox);

        std::thread::Builder::new()
            .name("heel-runner-reader".to_owned())
            .spawn(move || reader_loop(reader_sock, &reader_mailbox))
            .map_err(|e| Error::InitFailed(format!("cannot start runner reader thread: {e}")))?;

        Ok(Arc::new(Self {
            writer: Mutex::new(host_sock),
            mailbox,
            next_id: AtomicU64::new(1),
            #[cfg(target_os = "linux")]
            init_host_pid,
            #[cfg(target_os = "linux")]
            proc_fd,
            outer_child: Mutex::new(outer_child),
            staged,
        }))
    }

    /// Descriptor to the container's private `/proc` mount root inode.
    #[cfg(target_os = "linux")]
    pub(crate) fn proc_fd(&self) -> Option<BorrowedFd<'_>> {
        use std::os::fd::AsFd;
        self.proc_fd.as_ref().map(AsFd::as_fd)
    }

    /// Host PID of the container's PID 1 (`init`) on Linux.
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    pub(crate) fn init_host_pid(&self) -> u32 {
        self.init_host_pid
    }

    /// Path of the staged `heel-unix-runner` binary inside this sandbox's private directory.
    #[cfg(target_os = "linux")]
    pub(crate) fn runner_executable(&self) -> Option<&Path> {
        self.staged.as_ref().map(StagedRunner::path)
    }

    /// Translate a `sandbox_pid` inside this Linux container's PID namespace
    /// subtree into its host PID.
    #[cfg(target_os = "linux")]
    pub(crate) fn resolve_pid(&self, sandbox_pid: u32) -> Option<u32> {
        use rustix::fs::AtFlags;

        let proc_fd = self.proc_fd.as_ref()?;
        // Fast O(1) existence check inside this container's private `/proc`.
        rustix::fs::statat(proc_fd, sandbox_pid.to_string(), AtFlags::SYMLINK_NOFOLLOW).ok()?;

        let parse_status = |pid: u32| -> Option<(u32, Vec<u32>)> {
            let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
            let mut ppid = 0u32;
            let mut nspids = None;
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("PPid:") {
                    ppid = rest.trim().parse().unwrap_or(0);
                } else if let Some(rest) = line.strip_prefix("NSpid:") {
                    nspids = rest
                        .split_whitespace()
                        .map(|s| s.parse::<u32>().ok())
                        .collect();
                }
            }
            Some((ppid, nspids?))
        };

        let (_, init_chain) = parse_status(self.init_host_pid)?;
        let depth = init_chain.len().checked_sub(1)?;
        if sandbox_pid == 1 {
            return Some(self.init_host_pid);
        }

        let entries = std::fs::read_dir("/proc").ok()?;
        for entry in entries.flatten() {
            let Some(hpid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let Some((mut ppid, chain)) = parse_status(hpid) else {
                continue;
            };
            if chain.get(depth) != Some(&sandbox_pid) {
                continue;
            }
            // Verify `hpid` is a descendant of `self.init_host_pid` (distinguishes
            // sibling containers at the same namespace depth).
            let mut steps = 0;
            while ppid > 1 && steps < 64 {
                if ppid == self.init_host_pid {
                    return Some(hpid);
                }
                let Some((next_ppid, _)) = parse_status(ppid) else {
                    break;
                };
                ppid = next_ppid;
                steps += 1;
            }
        }
        None
    }

    /// Translate a host PID into the PID seen inside this container's PID
    /// namespace, returning `None` if `host_pid` is outside this subtree.
    #[cfg(target_os = "linux")]
    pub(crate) fn pid_in_sandbox(&self, host_pid: u32) -> Option<u32> {
        let parse_nspids = |pid: u32| -> Option<Vec<u32>> {
            let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
            let line = text.lines().find_map(|l| l.strip_prefix("NSpid:"))?;
            line.split_whitespace()
                .map(|part| part.parse::<u32>().ok())
                .collect()
        };
        let init_chain = parse_nspids(self.init_host_pid)?;
        let depth = init_chain.len().checked_sub(1)?;
        let target_chain = parse_nspids(host_pid)?;
        let candidate = *target_chain.get(depth)?;
        (self.resolve_pid(candidate) == Some(host_pid)).then_some(candidate)
    }

    fn alloc_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn send_packet(&self, payload: &[u8], fds: &[RawFd]) -> io::Result<()> {
        let len = u32::try_from(payload.len()).map_err(io::Error::other)?;
        let len_bytes = len.to_le_bytes();
        let writer = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        send_with_fds(writer.as_raw_fd(), &len_bytes, payload, fds)
    }

    /// Release `release_keys` and consume `add_entries` `(key, token)` inside
    /// the persistent macOS runner.
    #[cfg(target_os = "macos")]
    pub(crate) fn sync_extensions(
        &self,
        release_keys: &[String],
        add_entries: &[(String, String)],
    ) -> Result<()> {
        if release_keys.is_empty() && add_entries.is_empty() {
            return Ok(());
        }
        let req_id = self.alloc_id();
        let mut buf = Vec::new();
        buf.push(OP_SYNC_EXTENSIONS);
        buf.extend_from_slice(&req_id.to_le_bytes());
        buf.extend_from_slice(&(release_keys.len() as u32).to_le_bytes());
        for key in release_keys {
            push_str(&mut buf, key);
        }
        buf.extend_from_slice(&(add_entries.len() as u32).to_le_bytes());
        for (key, token) in add_entries {
            push_str(&mut buf, key);
            push_str(&mut buf, token);
        }
        self.send_packet(&buf, &[])?;
        match self.mailbox.wait_reply(req_id)? {
            Reply::Ack => Ok(()),
            Reply::Err(msg) => Err(Error::InitFailed(format!(
                "synchronizing macOS sandbox extensions failed: {msg}"
            ))),
            other => Err(Error::InitFailed(format!(
                "unexpected reply to OP_SYNC_EXTENSIONS: {other:?}"
            ))),
        }
    }

    /// Spawn a command inside the persistent runner.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn_command(
        self: &Arc<Self>,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        cwd: &Path,
        stdin_cfg: StdioConfig,
        stdout_cfg: StdioConfig,
        stderr_cfg: StdioConfig,
        limits: &[(i32, u64)],
        nice: Option<i32>,
        io_policy: Option<i32>,
        pty_slave_fd: Option<RawFd>,
        #[cfg(target_os = "linux")] linux_extra: LinuxSpawnExtra<'_>,
    ) -> io::Result<RunnerChild> {
        let (stdin_mode, host_stdin, child_stdin) = if pty_slave_fd.is_some() {
            (STDIO_NULL, None, None)
        } else {
            prepare_stdio(stdin_cfg, 0)?
        };
        let (stdout_mode, host_stdout, child_stdout) = if pty_slave_fd.is_some() {
            (STDIO_NULL, None, None)
        } else {
            prepare_stdio(stdout_cfg, 1)?
        };
        let (stderr_mode, host_stderr, child_stderr) = if pty_slave_fd.is_some() {
            (STDIO_NULL, None, None)
        } else {
            prepare_stdio(stderr_cfg, 2)?
        };

        let req_id = self.alloc_id();
        let mut buf = Vec::with_capacity(256);
        buf.push(OP_SPAWN);
        buf.extend_from_slice(&req_id.to_le_bytes());
        push_str(&mut buf, program);
        buf.extend_from_slice(&(args.len() as u32).to_le_bytes());
        for arg in args {
            push_str(&mut buf, arg);
        }
        buf.extend_from_slice(&(envs.len() as u32).to_le_bytes());
        for (k, v) in envs {
            push_str(&mut buf, k);
            push_str(&mut buf, v);
        }
        push_str(&mut buf, &cwd.to_string_lossy());
        buf.push(stdin_mode);
        buf.push(stdout_mode);
        buf.push(stderr_mode);
        buf.extend_from_slice(&(limits.len() as u32).to_le_bytes());
        for &(res, val) in limits {
            buf.extend_from_slice(&res.to_le_bytes());
            buf.extend_from_slice(&val.to_le_bytes());
        }
        push_opt_i32(&mut buf, nice);
        push_opt_i32(&mut buf, io_policy);
        buf.push(u8::from(pty_slave_fd.is_some()));

        let mut fds_to_send: Vec<RawFd> = Vec::with_capacity(8);
        if let Some(fd) = &child_stdin {
            fds_to_send.push(fd.as_raw_fd());
        }
        if let Some(fd) = &child_stdout {
            fds_to_send.push(fd.as_raw_fd());
        }
        if let Some(fd) = &child_stderr {
            fds_to_send.push(fd.as_raw_fd());
        }
        if let Some(slave_fd) = pty_slave_fd {
            fds_to_send.push(slave_fd);
        }

        #[cfg(target_os = "linux")]
        let cred_read = {
            let (cred_read, cred_write) = UnixStream::pair()?;
            enable_passcred(cred_read.as_raw_fd())?;
            let cred_write_fd: OwnedFd = cred_write.into();

            buf.push(u8::from(linux_extra.ruleset.is_some()));
            push_bytes(&mut buf, linux_extra.notif_filter);
            buf.extend_from_slice(&(linux_extra.seccomp_filters.len() as u32).to_le_bytes());
            for prog in linux_extra.seccomp_filters {
                push_bytes(&mut buf, prog);
            }
            buf.push(linux_extra.inherit_fds.len() as u8);
            for &(_, target) in linux_extra.inherit_fds {
                buf.extend_from_slice(&target.to_le_bytes());
            }

            fds_to_send.push(cred_write_fd.as_raw_fd());
            if let Some(rfd) = linux_extra.ruleset {
                fds_to_send.push(rfd.as_raw_fd());
            }
            if let Some(ref bf) = linux_extra.broker_child_sock {
                fds_to_send.push(bf.as_raw_fd());
            }
            for &(src, _) in linux_extra.inherit_fds {
                fds_to_send.push(src);
            }

            self.send_packet(&buf, &fds_to_send)?;
            drop((child_stdin, child_stdout, child_stderr, cred_write_fd));
            cred_read
        };

        #[cfg(target_os = "macos")]
        {
            self.send_packet(&buf, &fds_to_send)?;
            drop((child_stdin, child_stdout, child_stderr));
        }

        #[cfg(target_os = "linux")]
        if let Some((broker, listener_parent)) = linux_extra.broker_handoff {
            // Drop the child's end on the host before waiting on the listener handoff
            // so if `pre_exec` fails before sending the listener, `recv_fds` sees EOF!
            drop(linux_extra.broker_child_sock);
            let reply = self.mailbox.wait_reply(req_id)?;
            return match reply {
                Reply::SpawnOk(sandbox_pid) => {
                    broker.accept_listener(listener_parent, linux_extra.pty_slave_inode)?;
                    let host_pid = read_cred_pid(&cred_read)?;
                    Ok(RunnerChild {
                        runner: Arc::clone(self),
                        host_pid,
                        sandbox_pid,
                        stdin: host_stdin,
                        stdout: host_stdout,
                        stderr: host_stderr,
                        cached_status: None,
                    })
                }
                Reply::SpawnErr(err) => Err(err),
                other => Err(io::Error::other(format!(
                    "unexpected spawn reply: {other:?}"
                ))),
            };
        }

        match self.mailbox.wait_reply(req_id)? {
            Reply::SpawnOk(sandbox_pid) => {
                #[cfg(target_os = "linux")]
                let host_pid = read_cred_pid(&cred_read)?;
                #[cfg(target_os = "macos")]
                let host_pid = sandbox_pid;
                Ok(RunnerChild {
                    runner: Arc::clone(self),
                    host_pid,
                    sandbox_pid,
                    stdin: host_stdin,
                    stdout: host_stdout,
                    stderr: host_stderr,
                    cached_status: None,
                })
            }
            Reply::SpawnErr(err) => Err(err),
            other => Err(io::Error::other(format!(
                "unexpected spawn reply: {other:?}"
            ))),
        }
    }

    pub(crate) fn kill_in_runner(&self, sandbox_pid: u32) -> io::Result<()> {
        let req_id = self.alloc_id();
        let mut buf = Vec::with_capacity(13);
        buf.push(OP_KILL);
        buf.extend_from_slice(&req_id.to_le_bytes());
        buf.extend_from_slice(&sandbox_pid.to_le_bytes());
        if self.send_packet(&buf, &[]).is_err() {
            return Ok(());
        }
        match self.mailbox.wait_reply(req_id) {
            Ok(Reply::Ack) | Err(_) => Ok(()),
            Ok(Reply::Err(msg)) => Err(io::Error::other(msg)),
            Ok(other) => Err(io::Error::other(format!(
                "unexpected kill reply: {other:?}"
            ))),
        }
    }

    /// Shut down the persistent runner and reap its outer host process.
    pub(crate) fn shutdown(&self) {
        if let Ok(writer) = self.writer.lock() {
            let _ = writer.shutdown(std::net::Shutdown::Both);
        }
        #[cfg(target_os = "linux")]
        let init_pidfd = {
            // SAFETY: `pidfd_open` takes a positive PID and flags `0`.
            let rc = unsafe { libc::syscall(libc::SYS_pidfd_open, self.init_host_pid as i32, 0) };
            if rc >= 0 {
                // SAFETY: `rc` is a freshly returned owned file descriptor.
                Some(unsafe { OwnedFd::from_raw_fd(rc as RawFd) })
            } else {
                None
            }
        };
        #[cfg(target_os = "linux")]
        // Kill PID 1 of the namespace (`init_host_pid`) so the kernel runs
        // `zap_pid_ns_processes` across the entire namespace subtree.
        // SAFETY: `init_host_pid` belongs to this runner's namespace init.
        unsafe {
            let _ = libc::kill(self.init_host_pid as i32, libc::SIGKILL);
        }
        if let Some(mut child) = self
            .outer_child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            #[cfg(target_os = "macos")]
            {
                // SAFETY: runner was started in its own process group (`pgrp == pid`).
                unsafe {
                    let _ = libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        #[cfg(target_os = "linux")]
        if let Some(pidfd) = init_pidfd {
            let mut pfd = libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                // SAFETY: `pfd` is a valid 1-element `pollfd` slice.
                let rc = unsafe { libc::poll(&raw mut pfd, 1, 5_000) };
                if rc >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }
        }
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Extra Linux-specific descriptors and BPF payloads for one runner spawn.
#[cfg(target_os = "linux")]
pub(crate) struct LinuxSpawnExtra<'a> {
    pub ruleset: Option<BorrowedFd<'a>>,
    pub notif_filter: &'a [u8],
    pub seccomp_filters: &'a [Vec<u8>],
    pub broker_child_sock: Option<OwnedFd>,
    pub broker_handoff: Option<(&'a crate::platform::linux::broker::Broker, OwnedFd)>,
    pub inherit_fds: &'a [(RawFd, i32)],
    pub pty_slave_inode: Option<(u64, u64)>,
}

/// Process handle backed by a persistent [`Runner`].
#[derive(Debug)]
pub(crate) struct RunnerChild {
    runner: Arc<Runner>,
    host_pid: u32,
    sandbox_pid: u32,
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
    cached_status: Option<ExitStatus>,
}

impl RunnerChild {
    pub(crate) fn sandbox_id(&self) -> u32 {
        self.sandbox_pid
    }
}

impl ProcessHandle for RunnerChild {
    fn id(&self) -> u32 {
        self.host_pid
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.cached_status {
            return Ok(status);
        }
        let status = self.runner.mailbox.wait_exit(self.sandbox_pid)?;
        self.cached_status = Some(status);
        Ok(status)
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.cached_status {
            return Ok(Some(status));
        }
        if let Some(status) = self.runner.mailbox.try_exit(self.sandbox_pid) {
            self.cached_status = Some(status);
            return Ok(Some(status));
        }
        Ok(None)
    }

    fn kill(&mut self) -> io::Result<()> {
        self.runner.kill_in_runner(self.sandbox_pid)?;
        let _ = self.wait()?;
        Ok(())
    }

    fn stdin(&mut self) -> &mut Option<File> {
        &mut self.stdin
    }

    fn stdout(&mut self) -> &mut Option<File> {
        &mut self.stdout
    }

    fn stderr(&mut self) -> &mut Option<File> {
        &mut self.stderr
    }
}

fn prepare_stdio(
    cfg: StdioConfig,
    std_fd: RawFd,
) -> io::Result<(u8, Option<File>, Option<OwnedFd>)> {
    match cfg {
        StdioConfig::Inherit => {
            // Duplicate the host process's current standard stream (`0`, `1`, or `2`)
            // and transfer it over `SCM_RIGHTS` so the child inherits the caller's
            // actual stream while the persistent runner itself holds no copy open.
            // SAFETY: `F_DUPFD_CLOEXEC` either duplicates an open `std_fd` or fails with `EBADF`.
            let dup = unsafe { libc::fcntl(std_fd, libc::F_DUPFD_CLOEXEC, 3) };
            if dup < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EBADF) {
                    return Ok((STDIO_NULL, None, None));
                }
                return Err(err);
            }
            // SAFETY: `dup` is a freshly duplicated descriptor owned here.
            Ok((
                STDIO_PIPED,
                None,
                Some(unsafe { OwnedFd::from_raw_fd(dup) }),
            ))
        }
        StdioConfig::Null => Ok((STDIO_NULL, None, None)),
        StdioConfig::Piped => {
            let (read_end, write_end) = create_cloexec_pipe()?;
            if std_fd == 0 {
                Ok((STDIO_PIPED, Some(File::from(write_end)), Some(read_end)))
            } else {
                Ok((STDIO_PIPED, Some(File::from(read_end)), Some(write_end)))
            }
        }
    }
}

fn create_cloexec_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: `pipe` initializes `fds` with two fresh descriptors on success.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created by `pipe`.
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // SAFETY: setting `FD_CLOEXEC` on fresh descriptors.
    unsafe {
        let _ = libc::fcntl(r.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
        let _ = libc::fcntl(w.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
    }
    Ok((r, w))
}

fn dup_above_stdio(sock: &UnixStream) -> io::Result<OwnedFd> {
    // SAFETY: `F_DUPFD_CLOEXEC` duplicates `sock` to a descriptor >= 3 with `FD_CLOEXEC`.
    let dup = unsafe { libc::fcntl(sock.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `dup` is a newly created descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(dup) })
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(target_os = "linux")]
fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn push_opt_i32(out: &mut Vec<u8>, val: Option<i32>) {
    match val {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(&v.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn send_with_fds(sock: RawFd, header: &[u8; 4], body: &[u8], fds: &[RawFd]) -> io::Result<()> {
    let mut iovs = [
        libc::iovec {
            iov_base: header.as_ptr().cast_mut().cast(),
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: body.as_ptr().cast_mut().cast(),
            iov_len: body.len(),
        },
    ];

    let data_len = std::mem::size_of_val(fds);
    let space = if fds.is_empty() {
        0
    } else {
        // SAFETY: `CMSG_SPACE` is a pure size calculation macro.
        unsafe { libc::CMSG_SPACE(data_len as u32) as usize }
    };
    let mut cmsg_buf = vec![0u8; space];

    let mut msg: libc::msghdr = {
        // SAFETY: zero-initializing `msghdr` is valid on Unix.
        unsafe { std::mem::zeroed() }
    };
    msg.msg_iov = iovs.as_mut_ptr();
    msg.msg_iovlen = 2;

    if !fds.is_empty() {
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        // SAFETY: `msg` points at `cmsg_buf` of size `CMSG_SPACE(data_len)`.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(data_len as u32) as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(cmsg),
                data_len,
            );
        }
    }

    #[cfg(target_os = "macos")]
    const FLAGS: c_int = 0; // `UnixStream::pair` already sets `SO_NOSIGPIPE` on Darwin.
    #[cfg(target_os = "linux")]
    const FLAGS: c_int = libc::MSG_NOSIGNAL;

    // First sendmsg transfers all ancillary descriptors alongside at least 1 byte.
    let sent = loop {
        // SAFETY: `msg` and its `iovs`/`cmsg_buf` outlive `sendmsg`.
        let rc = unsafe { libc::sendmsg(sock, &raw const msg, FLAGS) };
        if rc >= 0 {
            break rc as usize;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    };

    // Finish any remaining bytes without resending descriptors.
    let total = header.len() + body.len();
    let mut offset = sent;
    while offset < total {
        let slice = if offset < header.len() {
            &header[offset..]
        } else {
            &body[offset - header.len()..]
        };
        // SAFETY: `slice` is valid readable memory; `send` with `FLAGS` suppresses SIGPIPE.
        let rc = unsafe { libc::send(sock, slice.as_ptr().cast(), slice.len(), FLAGS) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        offset += rc as usize;
    }
    Ok(())
}

fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(target_os = "macos")]
fn read_handshake(stream: &mut UnixStream) -> io::Result<u32> {
    let frame = read_frame(stream)?;
    parse_handshake_frame(&frame)
}

fn parse_handshake_frame(frame: &[u8]) -> io::Result<u32> {
    let (&tag, rest) = frame
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "empty runner handshake"))?;
    match tag {
        EV_ACK if rest.len() >= 4 => Ok(u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]])),
        EV_ERR => {
            let msg = read_len_str(rest).unwrap_or_else(|| "runner error".to_owned());
            Err(io::Error::other(msg))
        }
        other => Err(io::Error::other(format!(
            "unexpected runner handshake tag {other}"
        ))),
    }
}

fn read_len_str(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let s = bytes.get(4..4 + len)?;
    Some(String::from_utf8_lossy(s).into_owned())
}

fn reader_loop(mut stream: UnixStream, mailbox: &Mailbox) {
    while let Ok(frame) = read_frame(&mut stream) {
        let Some((&tag, rest)) = frame.split_first() else {
            break;
        };
        match tag {
            EV_SPAWN_OK if rest.len() >= 12 => {
                let req_id = u64::from_le_bytes(rest[0..8].try_into().unwrap_or_default());
                let pid = u32::from_le_bytes(rest[8..12].try_into().unwrap_or_default());
                mailbox.lock().replies.insert(req_id, Reply::SpawnOk(pid));
                mailbox.changed.notify_all();
            }
            EV_SPAWN_ERR if rest.len() >= 9 => {
                let req_id = u64::from_le_bytes(rest[0..8].try_into().unwrap_or_default());
                let has_os = rest[8] != 0;
                let (os_err, str_part) = if has_os && rest.len() >= 13 {
                    let code = i32::from_le_bytes(rest[9..13].try_into().unwrap_or_default());
                    (Some(code), &rest[13..])
                } else {
                    (None, &rest[9..])
                };
                let msg = read_len_str(str_part).unwrap_or_else(|| "spawn failed".to_owned());
                let err = match os_err {
                    Some(code) => io::Error::from_raw_os_error(code),
                    None => io::Error::other(msg),
                };
                mailbox.lock().replies.insert(req_id, Reply::SpawnErr(err));
                mailbox.changed.notify_all();
            }
            EV_EXITED if rest.len() >= 8 => {
                let pid = u32::from_le_bytes(rest[0..4].try_into().unwrap_or_default());
                let raw = i32::from_le_bytes(rest[4..8].try_into().unwrap_or_default());
                mailbox.lock().exited.insert(pid, ExitStatus::from_raw(raw));
                mailbox.changed.notify_all();
            }
            EV_ACK if rest.len() >= 8 => {
                let req_id = u64::from_le_bytes(rest[0..8].try_into().unwrap_or_default());
                mailbox.lock().replies.insert(req_id, Reply::Ack);
                mailbox.changed.notify_all();
            }
            EV_ERR if rest.len() >= 8 => {
                let req_id = u64::from_le_bytes(rest[0..8].try_into().unwrap_or_default());
                let msg = read_len_str(&rest[8..]).unwrap_or_else(|| "runner error".to_owned());
                mailbox.lock().replies.insert(req_id, Reply::Err(msg));
                mailbox.changed.notify_all();
            }
            _ => break,
        }
    }
    mailbox.lock().closed = true;
    mailbox.changed.notify_all();
}

#[cfg(target_os = "linux")]
pub(crate) fn enable_passcred(sock: RawFd) -> io::Result<()> {
    let one: c_int = 1;
    // SAFETY: `SO_PASSCRED` takes an `int` option value on `AF_UNIX` sockets.
    let rc = unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&raw const one).cast::<c_void>(),
            std::mem::size_of::<c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn read_cred_pid(sock: &UnixStream) -> io::Result<u32> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: `CMSG_SPACE` is a pure size macro for `ucred`.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::ucred>() as u32) as usize };
    let mut cmsg_buf = vec![0u8; space];
    let mut msg: libc::msghdr = {
        // SAFETY: zeroed `msghdr` is valid.
        unsafe { std::mem::zeroed() }
    };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = space;

    loop {
        // SAFETY: `msg` buffers outlive `recvmsg`.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &raw mut msg, 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "spawned child exited before announcing host PID",
            ));
        }
        // SAFETY: iterating ancillary messages returned by `recvmsg`.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET
                    && (*cmsg).cmsg_type == libc::SCM_CREDENTIALS
                {
                    let cred = libc::CMSG_DATA(cmsg).cast::<libc::ucred>().read_unaligned();
                    if cred.pid > 0 {
                        return Ok(cred.pid as u32);
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
            }
        }
        return Err(io::Error::other("missing SCM_CREDENTIALS on cred socket"));
    }
}

#[cfg(target_os = "linux")]
fn read_linux_handshake(sock: &UnixStream) -> io::Result<(u32, OwnedFd)> {
    let mut len_bytes = [0u8; 4];
    let mut peer_pid = None;
    let mut proc_fd: Option<OwnedFd> = None;
    let mut read_so_far = 0usize;
    // SAFETY: `CMSG_SPACE` is a pure size macro for `ucred` + one `RawFd`.
    let space = unsafe {
        (libc::CMSG_SPACE(std::mem::size_of::<libc::ucred>() as u32)
            + libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32)) as usize
    };
    let mut cmsg_buf = vec![0u8; space];

    while read_so_far < 4 {
        let mut iov = libc::iovec {
            iov_base: len_bytes[read_so_far..].as_mut_ptr().cast(),
            iov_len: 4 - read_so_far,
        };
        let mut msg: libc::msghdr = {
            // SAFETY: zeroed `msghdr` is valid.
            unsafe { std::mem::zeroed() }
        };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = space;
        // SAFETY: `msg` buffers outlive `recvmsg`.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "runner closed handshake socket",
            ));
        }
        // SAFETY: iterating ancillary messages returned by `recvmsg`.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET {
                    if (*cmsg).cmsg_type == libc::SCM_CREDENTIALS {
                        let cred = libc::CMSG_DATA(cmsg).cast::<libc::ucred>().read_unaligned();
                        if cred.pid > 0 {
                            peer_pid = Some(cred.pid as u32);
                        }
                    } else if (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                        let data_len = (*cmsg).cmsg_len as usize - (libc::CMSG_LEN(0) as usize);
                        let count = data_len / std::mem::size_of::<RawFd>();
                        let ptr = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                        for i in 0..count {
                            let fd = ptr.add(i).read_unaligned();
                            if proc_fd.is_none() {
                                proc_fd = Some(OwnedFd::from_raw_fd(fd));
                            } else {
                                let _ = libc::close(fd);
                            }
                        }
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
            }
        }
        read_so_far += n as usize;
    }

    let len = u32::from_le_bytes(len_bytes) as usize;
    let mut body = vec![0u8; len];
    let mut clone = sock.try_clone()?;
    clone.read_exact(&mut body)?;
    parse_handshake_frame(&body)?;
    let init_pid = peer_pid
        .ok_or_else(|| io::Error::other("kernel did not supply SCM_CREDENTIALS on handshake"))?;
    let pfd = proc_fd
        .ok_or_else(|| io::Error::other("runner did not supply private /proc descriptor"))?;
    Ok((init_pid, pfd))
}

/// Issue a macOS Seatbelt file extension token for `grant`.
#[cfg(target_os = "macos")]
pub(crate) fn issue_macos_extension(grant: &Grant) -> Result<String> {
    crate::platform::unresolved::verify(grant.path())?;
    let access = grant.access();
    let class = match (access.can_write(), access.can_execute()) {
        (true, true) => c"heel.grant.write-exec",
        (true, false) => c"heel.grant.write",
        (false, true) => c"heel.grant.exec",
        (false, false) => c"heel.grant.read",
    };
    issue_macos_extension_for_class(class, grant.path())
}

/// Issue a macOS Seatbelt read-denial extension token (`heel.deny.read`) for `path`.
#[cfg(target_os = "macos")]
pub(crate) fn issue_macos_deny_read(path: &Path) -> Result<String> {
    crate::platform::unresolved::verify(path)?;
    issue_macos_extension_for_class(c"heel.deny.read", path)
}

#[cfg(target_os = "macos")]
fn issue_macos_extension_for_class(class: &std::ffi::CStr, path: &Path) -> Result<String> {
    use std::ffi::{CStr, CString, c_char};
    use std::os::unix::ffi::OsStrExt;

    unsafe extern "C" {
        fn sandbox_extension_issue_file(
            extension_class: *const c_char,
            path: *const c_char,
            flags: u32,
        ) -> *mut c_char;
    }

    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        Error::InvalidProfile(format!(
            "granted path contains an interior NUL byte: {}",
            path.display()
        ))
    })?;
    // SAFETY: `class` and `c_path` are valid NUL-terminated C strings; the
    // returned buffer is allocated with `malloc` by `libSystem` and freed below.
    let raw = unsafe { sandbox_extension_issue_file(class.as_ptr(), c_path.as_ptr(), 0) };
    if raw.is_null() {
        return Err(Error::path(path, io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a non-null NUL-terminated string allocated by `libSystem`.
    let token = unsafe { CStr::from_ptr(raw).to_string_lossy().into_owned() };
    // SAFETY: `sandbox_extension_issue_file` documents `free` ownership on the caller.
    unsafe { libc::free(raw.cast()) };
    Ok(token)
}
