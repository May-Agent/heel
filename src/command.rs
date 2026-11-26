//! Builder for commands executed inside a sandbox.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output, Stdio};

use crate::config::SandboxConfigData;
use crate::error::Result;
use crate::platform::{Backend, Child, NativeBackend, PtyMaster, SpawnRequest, env_name_eq};
use crate::sandbox::ProcessTracker;

/// The `PATH` a sandboxed process gets when nothing else specifies one.
///
/// The host's `PATH` is deliberately not inherited: the backend clears the
/// environment, and silently re-importing the host's search path would both
/// undo that and make behaviour depend on the shell the sandbox was launched
/// from. Callers that want the host's `PATH` ask for it with
/// [`SandboxConfigBuilder::env_passthrough`](crate::SandboxConfigBuilder::env_passthrough).
#[cfg(target_os = "macos")]
pub const DEFAULT_SANDBOX_PATH: &str =
    "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
/// The `PATH` a sandboxed process gets when nothing else specifies one.
#[cfg(all(unix, not(target_os = "macos")))]
pub const DEFAULT_SANDBOX_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// Platform-native command search path without inheriting the host's PATH.
///
/// # Panics
///
/// On Windows, panics if the operating system's SystemRoot is unavailable or cannot form a PATH.
pub fn default_sandbox_path() -> String {
    #[cfg(unix)]
    {
        DEFAULT_SANDBOX_PATH.to_owned()
    }
    #[cfg(windows)]
    {
        let root = std::path::PathBuf::from(
            std::env::var_os("SystemRoot")
                .expect("Windows requires SystemRoot to prepare the sandbox PATH"),
        );
        std::env::join_paths([root.join("System32"), root])
            .expect("Windows system directories must form a PATH")
            .into_string()
            .expect("Windows system directories must be UTF-8")
    }
}

/// Standard I/O configuration for a sandboxed command.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StdioConfig {
    /// Inherit the corresponding stream from the parent process.
    #[default]
    Inherit,
    /// Connect the stream to a pipe.
    Piped,
    /// Connect the stream to the null device.
    Null,
}

impl From<StdioConfig> for Stdio {
    fn from(config: StdioConfig) -> Self {
        match config {
            StdioConfig::Inherit => Stdio::inherit(),
            StdioConfig::Piped => Stdio::piped(),
            StdioConfig::Null => Stdio::null(),
        }
    }
}

/// A command to run inside a sandbox.
///
/// The sandbox injects the environment a sandboxed process needs to reach the
/// facilities it is allowed to use: proxy variables when network access is
/// configured, and the IPC endpoint plus its command shims when IPC is.
pub struct Command<'a> {
    config: &'a SandboxConfigData,
    backend: &'a NativeBackend,
    process_tracker: &'a ProcessTracker,
    proxy: Option<ProxyEndpoint>,
    program: String,
    args: Vec<String>,
    envs: Vec<(String, String)>,
    current_dir: Option<PathBuf>,
    /// `None` until the caller chooses, so each run mode can pick the default
    /// that suits it.
    stdin: Option<StdioConfig>,
    stdout: Option<StdioConfig>,
    stderr: Option<StdioConfig>,
}

/// Where the sandbox proxy is listening.
#[derive(Debug, Clone)]
pub(crate) struct ProxyEndpoint {
    pub(crate) url: String,
    #[cfg(target_os = "windows")]
    pub(crate) port: u16,
}

impl<'a> Command<'a> {
    /// Create a command builder. Called by [`Sandbox`](crate::Sandbox).
    pub(crate) fn new(
        config: &'a SandboxConfigData,
        backend: &'a NativeBackend,
        process_tracker: &'a ProcessTracker,
        proxy: Option<ProxyEndpoint>,
        program: impl Into<String>,
    ) -> Self {
        Self {
            config,
            backend,
            process_tracker,
            proxy,
            program: program.into(),
            args: Vec::new(),
            envs: Vec::new(),
            current_dir: None,
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    /// Add one argument.
    pub fn arg(mut self, arg: impl AsRef<str>) -> Self {
        self.args.push(arg.as_ref().to_string());
        self
    }

    /// Add several arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_string()));
        self
    }

    /// Set an environment variable, overriding anything the sandbox injects.
    pub fn env(mut self, key: impl AsRef<str>, val: impl AsRef<str>) -> Self {
        self.envs
            .push((key.as_ref().to_string(), val.as_ref().to_string()));
        self
    }

    /// Set several environment variables.
    pub fn envs(
        mut self,
        envs: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
    ) -> Self {
        self.envs.extend(
            envs.into_iter()
                .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string())),
        );
        self
    }

    /// Run in a directory other than the sandbox working directory.
    pub fn current_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.current_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Configure standard input.
    pub fn stdin(mut self, cfg: StdioConfig) -> Self {
        self.stdin = Some(cfg);
        self
    }

    /// Configure standard output.
    pub fn stdout(mut self, cfg: StdioConfig) -> Self {
        self.stdout = Some(cfg);
        self
    }

    /// Configure standard error.
    pub fn stderr(mut self, cfg: StdioConfig) -> Self {
        self.stderr = Some(cfg);
        self
    }

    /// Build the environment the sandboxed process starts with.
    fn build_envs(&self) -> Vec<(String, String)> {
        sandbox_environment(
            self.config,
            self.proxy.as_ref().map(|proxy| proxy.url.as_str()),
            &self.envs,
        )
    }

    /// Build the environment for a PTY command, defaulting `TERM` to
    /// `xterm-256color` when neither the command nor an explicit passthrough
    /// supplies one.
    fn build_pty_envs(&self) -> Vec<(String, String)> {
        let mut envs = self.build_envs();
        let has_term = envs.iter().any(|(key, _)| env_name_eq(key, "TERM"))
            || self
                .config
                .env_passthrough()
                .iter()
                .any(|var| env_name_eq(var, "TERM") && std::env::var_os(var).is_some());
        if !has_term {
            envs.push(("TERM".to_owned(), "xterm-256color".to_owned()));
        }
        envs
    }

    /// Assemble the platform request for this command.
    fn request<'r>(
        &'r self,
        envs: &'r [(String, String)],
        stdin: StdioConfig,
        stdout: StdioConfig,
        stderr: StdioConfig,
    ) -> SpawnRequest<'r> {
        SpawnRequest {
            config: self.config,
            #[cfg(target_os = "windows")]
            proxy_port: self.proxy.as_ref().map(|proxy| proxy.port),
            program: &self.program,
            args: &self.args,
            envs,
            current_dir: self.current_dir.as_deref(),
            stdin,
            stdout,
            stderr,
            #[cfg(target_os = "linux")]
            inherit_fds: &[],
            #[cfg(target_os = "linux")]
            pty_slave_fd: None,
            #[cfg(target_os = "linux")]
            pty_slave_inode: None,
        }
    }

    /// Run to completion and collect all output.
    ///
    /// Standard output and error are captured. Standard input defaults to the
    /// null device rather than the caller's: a command that reads from an
    /// inherited stream would block until that stream closed, which for a
    /// long-lived parent means forever.
    pub async fn output(self) -> Result<Output> {
        let envs = self.build_envs();
        self.backend
            .execute(self.request(
                &envs,
                self.stdin.unwrap_or(StdioConfig::Null),
                StdioConfig::Piped,
                StdioConfig::Piped,
            ))
            .await
    }

    /// Run to completion and return only the exit status.
    ///
    /// The standard streams are inherited unless configured otherwise.
    pub async fn status(self) -> Result<ExitStatus> {
        let envs = self.build_envs();
        let output = self
            .backend
            .execute(self.request(
                &envs,
                self.stdio(self.stdin),
                self.stdio(self.stdout),
                self.stdio(self.stderr),
            ))
            .await?;
        Ok(output.status)
    }

    /// Resolve one stream, defaulting to an inherited stream.
    fn stdio(&self, config: Option<StdioConfig>) -> StdioConfig {
        config.unwrap_or(StdioConfig::Inherit)
    }

    /// Spawn the command for streaming I/O.
    pub async fn spawn(self) -> Result<Child> {
        let envs = self.build_envs();
        let child = self
            .backend
            .spawn(self.request(
                &envs,
                self.stdio(self.stdin),
                self.stdio(self.stdout),
                self.stdio(self.stderr),
            ))
            .await?;

        self.process_tracker.register(child.id());
        Ok(child.with_tracker(self.process_tracker.clone()))
    }

    /// Spawn the command attached to a new pseudo-terminal with initial
    /// `(cols, rows)` dimensions.
    ///
    /// The child runs in a new session with the PTY slave as its controlling
    /// terminal (`setsid` + `TIOCSCTTY`) and all three standard streams wired
    /// to that slave. `TERM` defaults to `xterm-256color` when unset. On
    /// confined Unix sandboxes, terminal device access is isolated to `/dev/tty`
    /// and this command's own slave PTY without opening unrelated host PTYs or
    /// sibling commands' slave PTYs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`](crate::Error::Unsupported) on platforms
    /// without per-command PTY support (Windows), or an error if allocating the
    /// PTY or spawning the child fails.
    pub async fn spawn_pty(self, cols: u16, rows: u16) -> Result<(Child, PtyMaster)> {
        let envs = self.build_pty_envs();
        let (child, master) = self
            .backend
            .spawn_pty(
                self.request(
                    &envs,
                    StdioConfig::Null,
                    StdioConfig::Null,
                    StdioConfig::Null,
                ),
                cols,
                rows,
            )
            .await?;

        self.process_tracker.register(child.id());
        Ok((child.with_tracker(self.process_tracker.clone()), master))
    }

    /// Spawn the command under a supervisor that owns its whole process tree.
    ///
    /// The sandbox must have been built with
    /// [`supervised_spawn(true)`](crate::SandboxConfigBuilder::supervised_spawn).
    /// The standard streams are inherited unless configured otherwise.
    ///
    /// # Errors
    ///
    /// Fails if the sandbox was not built for supervised spawns, or if the
    /// supervisor cannot be started.
    #[cfg(target_os = "linux")]
    pub async fn spawn_supervised<M: crate::supervisor::Supervision>(
        self,
        mode: M,
    ) -> Result<crate::supervisor::SupervisedChild<M>> {
        use std::os::fd::AsRawFd;

        if !self.config.supervised_spawn() {
            return Err(crate::error::Error::SupervisorNotConfigured);
        }

        let (host, supervisor_end) = std::os::unix::net::UnixStream::pair()?;
        let inherited_ctl =
            rustix::io::fcntl_dupfd_cloexec(&supervisor_end, 3).map_err(std::io::Error::from)?;
        drop(supervisor_end);
        let shared = crate::supervisor::Shared::new(host, mode.reap_timeout())?;
        let envs = self.build_envs();

        if let Some(runner_bin) = self.backend.runner_executable() {
            let runner_str = runner_bin.to_str().ok_or_else(|| {
                crate::error::Error::InitFailed(format!(
                    "runner binary path is not UTF-8: {}",
                    runner_bin.display()
                ))
            })?;
            let (cred_read, cred_write) = std::os::unix::net::UnixStream::pair()?;
            crate::platform::runner::enable_passcred(cred_read.as_raw_fd())?;
            let inherited_cred =
                rustix::io::fcntl_dupfd_cloexec(&cred_write, 4).map_err(std::io::Error::from)?;
            drop(cred_write);

            let ctl_target = 3i32;
            let cred_target = 4i32;
            let reap_ms = mode.reap_timeout().as_millis().to_string();
            let mut arguments = Vec::with_capacity(6 + self.args.len());
            arguments.push("--supervise".to_owned());
            arguments.push(mode.mode().as_str().to_owned());
            arguments.push(ctl_target.to_string());
            arguments.push(cred_target.to_string());
            arguments.push(reap_ms);
            arguments.push("--".to_owned());
            arguments.push(self.program.clone());
            arguments.extend_from_slice(&self.args);

            let inherit_pairs = [
                (inherited_ctl.as_raw_fd(), ctl_target),
                (inherited_cred.as_raw_fd(), cred_target),
            ];
            let request = SpawnRequest {
                config: self.config,
                program: runner_str,
                args: &arguments,
                envs: &envs,
                current_dir: self.current_dir.as_deref(),
                stdin: self.stdio(self.stdin),
                stdout: self.stdio(self.stdout),
                stderr: self.stdio(self.stderr),
                inherit_fds: &inherit_pairs,
                pty_slave_fd: None,
                pty_slave_inode: None,
            };
            let mut child = self.backend.spawn(request).await?;
            drop((inherited_ctl, inherited_cred));

            let sup_pid = child.id();
            let reaper = child.take_reaper()?;
            shared.set_reaper(reaper);

            let wait_shared = std::sync::Arc::clone(&shared);
            let (cmd_sandbox_pid, cmd_host_pid) = blocking::unblock(move || {
                if let Some(spid) = wait_shared.wait_started() {
                    let hpid =
                        crate::platform::runner::read_cred_pid(&cred_read).unwrap_or(sup_pid);
                    (spid, hpid)
                } else {
                    (sup_pid, sup_pid)
                }
            })
            .await;

            self.process_tracker
                .register_supervisor(sup_pid, std::sync::Arc::downgrade(&shared));
            return Ok(crate::supervisor::SupervisedChild::new(
                child,
                cmd_host_pid,
                cmd_sandbox_pid,
                shared,
            ));
        }

        let binary = self
            .config
            .supervisor_binary()
            .ok_or(crate::error::Error::SupervisorNotConfigured)?;
        let binary = binary.to_str().ok_or_else(|| {
            crate::error::Error::InitFailed(format!(
                "the heel binary path is not UTF-8: {}",
                binary.display()
            ))
        })?;
        let arguments = crate::supervisor::arguments(
            mode.mode(),
            inherited_ctl.as_raw_fd(),
            mode.reap_timeout(),
            &self.program,
            &self.args,
        );
        let inherit_pairs = [(inherited_ctl.as_raw_fd(), inherited_ctl.as_raw_fd())];
        let request = SpawnRequest {
            config: self.config,
            program: binary,
            args: &arguments,
            envs: &envs,
            current_dir: self.current_dir.as_deref(),
            stdin: self.stdio(self.stdin),
            stdout: self.stdio(self.stdout),
            stderr: self.stdio(self.stderr),
            inherit_fds: &inherit_pairs,
            pty_slave_fd: None,
            pty_slave_inode: None,
        };
        let child = self.backend.spawn(request).await?;
        drop(inherited_ctl);

        let sup_pid = child.id();
        let wait_shared = std::sync::Arc::clone(&shared);
        let cmd_pid =
            blocking::unblock(move || wait_shared.wait_started().unwrap_or(sup_pid)).await;

        self.process_tracker
            .register_supervisor(sup_pid, std::sync::Arc::downgrade(&shared));
        let child = child.with_tracker(self.process_tracker.clone());
        Ok(crate::supervisor::SupervisedChild::new(
            child, cmd_pid, cmd_pid, shared,
        ))
    }

    /// Spawn the command on a new pseudo-terminal under a supervisor that owns
    /// its whole process tree.
    ///
    /// The supervisor itself holds no controlling terminal and closes its copy
    /// of the slave descriptor immediately after spawning the command; the
    /// supervised command runs in a new session with the slave as its
    /// controlling terminal (`setsid` + `TIOCSCTTY`), receives `SIGWINCH` on
    /// [`PtyMaster::resize`], and is isolated to `/dev/tty` plus its own slave
    /// PTY inode on confined sandboxes.
    ///
    /// # Errors
    ///
    /// Fails if the sandbox was not built with
    /// [`supervised_spawn(true)`](crate::SandboxConfigBuilder::supervised_spawn),
    /// if the PTY cannot be allocated, or if the supervisor cannot be started.
    #[cfg(target_os = "linux")]
    pub async fn spawn_supervised_pty<M: crate::supervisor::Supervision>(
        self,
        mode: M,
        cols: u16,
        rows: u16,
    ) -> Result<(crate::supervisor::SupervisedChild<M>, PtyMaster)> {
        use std::os::fd::{AsFd, AsRawFd};

        if !self.config.supervised_spawn() {
            return Err(crate::error::Error::SupervisorNotConfigured);
        }

        let pty = crate::platform::pty::AllocatedPty::open(cols, rows)?;
        let (host, supervisor_end) = std::os::unix::net::UnixStream::pair()?;
        let inherited_ctl =
            rustix::io::fcntl_dupfd_cloexec(&supervisor_end, 3).map_err(std::io::Error::from)?;
        drop(supervisor_end);
        let (cred_read, cred_write) = std::os::unix::net::UnixStream::pair()?;
        crate::platform::runner::enable_passcred(cred_read.as_raw_fd())?;
        let inherited_cred =
            rustix::io::fcntl_dupfd_cloexec(&cred_write, 4).map_err(std::io::Error::from)?;
        drop(cred_write);

        let shared = crate::supervisor::Shared::new(host, mode.reap_timeout())?;
        let envs = self.build_pty_envs();
        let runner_path = match self.backend.runner_executable() {
            Some(path) => path.to_path_buf(),
            None => self.backend.host_runner_executable()?,
        };
        let runner_str = runner_path.to_str().ok_or_else(|| {
            crate::error::Error::InitFailed(format!(
                "runner binary path is not UTF-8: {}",
                runner_path.display()
            ))
        })?;

        let ctl_target = 3i32;
        let cred_target = 4i32;
        let pty_target = 5i32;
        let reap_ms = mode.reap_timeout().as_millis().to_string();
        let mut arguments = Vec::with_capacity(7 + self.args.len());
        arguments.push("--supervise-pty".to_owned());
        arguments.push(mode.mode().as_str().to_owned());
        arguments.push(ctl_target.to_string());
        arguments.push(cred_target.to_string());
        arguments.push(pty_target.to_string());
        arguments.push(reap_ms);
        arguments.push("--".to_owned());
        arguments.push(self.program.clone());
        arguments.extend_from_slice(&self.args);

        let inherit_pairs = [
            (inherited_ctl.as_raw_fd(), ctl_target),
            (inherited_cred.as_raw_fd(), cred_target),
            (pty.slave.as_raw_fd(), pty_target),
        ];
        let request = SpawnRequest {
            config: self.config,
            program: runner_str,
            args: &arguments,
            envs: &envs,
            current_dir: self.current_dir.as_deref(),
            stdin: StdioConfig::Null,
            stdout: StdioConfig::Null,
            stderr: StdioConfig::Null,
            inherit_fds: &inherit_pairs,
            pty_slave_fd: Some(pty.slave.as_fd()),
            pty_slave_inode: Some(pty.slave_inode),
        };
        let mut child = self.backend.spawn(request).await?;
        drop((inherited_ctl, inherited_cred, pty.slave));

        let sup_pid = child.id();
        let reaper = child.take_reaper()?;
        shared.set_reaper(reaper);

        let wait_shared = std::sync::Arc::clone(&shared);
        let (cmd_sandbox_pid, cmd_host_pid) = blocking::unblock(move || {
            if let Some(spid) = wait_shared.wait_started() {
                let hpid = crate::platform::runner::read_cred_pid(&cred_read).unwrap_or(sup_pid);
                (spid, hpid)
            } else {
                (sup_pid, sup_pid)
            }
        })
        .await;

        self.process_tracker
            .register_supervisor(sup_pid, std::sync::Arc::downgrade(&shared));
        Ok((
            crate::supervisor::SupervisedChild::new(child, cmd_host_pid, cmd_sandbox_pid, shared),
            pty.master,
        ))
    }
}

/// The variables that name the directory for temporary files.
///
/// Unix programs read `TMPDIR`, which this layer points at the working
/// directory. On Windows, the backend sets `TEMP`, `TMP` and `TMPDIR` to the
/// container's own temporary folder.
#[cfg(not(windows))]
const TEMP_DIR_VARS: &[&str] = &["TMPDIR"];

/// Build the environment a sandboxed process starts with.
///
/// The sandbox injects what a process needs to reach the facilities it is
/// allowed to use; explicit settings win, except PATH retains the IPC shim
/// directory ahead of the caller's entries. Shared by piped commands and interactive
/// sessions, which must not drift apart in what they expose.
pub(crate) fn sandbox_environment(
    config: &SandboxConfigData,
    proxy_url: Option<&str>,
    user_envs: &[(String, String)],
) -> Vec<(String, String)> {
    let mut envs: BTreeMap<String, String> = BTreeMap::new();

    if let Some(url) = proxy_url {
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            envs.insert(key.to_string(), url.to_string());
        }
    }

    // On Unix, the working directory is the one place a sandboxed process can
    // always write, so it is also where temporary files belong. Strict mode
    // denies the shared temp directories outright.
    #[cfg(not(windows))]
    let working_dir = config.working_dir().display().to_string();
    #[cfg(not(windows))]
    for key in TEMP_DIR_VARS {
        envs.insert((*key).to_string(), working_dir.clone());
    }

    for (key, value) in user_envs {
        // Windows compares environment names case-insensitively, so a `Path`
        // the caller spelled differently is stored under the canonical name:
        // left as spelled it would sit beside the computed `PATH` in one
        // block, and which of the two the child reads is not ours to say.
        let key = if env_name_eq(key, "PATH") {
            "PATH"
        } else {
            key.as_str()
        };
        envs.insert(key.to_string(), value.clone());
    }

    if let Some(socket) = config.ipc_socket() {
        envs.insert(
            "HEEL_IPC_ENDPOINT".to_string(),
            socket.display().to_string(),
        );
    }

    envs.insert("PATH".to_string(), sandbox_path(config, user_envs));
    envs.into_iter().collect()
}

/// Determine the sandboxed `PATH`.
///
/// The IPC shim directory is prepended so command shims resolve; the rest comes
/// from the caller, then the passthrough list, then the built-in default.
fn sandbox_path(config: &SandboxConfigData, user_envs: &[(String, String)]) -> String {
    let base = user_envs
        .iter()
        .rev()
        .find(|(key, _)| env_name_eq(key, "PATH"))
        .map(|(_, value)| value.clone())
        .or_else(|| {
            config
                .env_passthrough()
                .iter()
                .find(|var| env_name_eq(var, "PATH"))
                .and_then(|var| std::env::var(var).ok())
        })
        .unwrap_or_else(default_sandbox_path);

    let Some(bin_dir) = config.ipc_bin_dir() else {
        return base;
    };
    let bin_dir = bin_dir.to_path_buf();
    let entries = std::iter::once(bin_dir).chain(std::env::split_paths(&base));
    match std::env::join_paths(entries) {
        Ok(joined) => joined.to_string_lossy().into_owned(),
        Err(error) => {
            // Only possible if a PATH entry contains the separator itself.
            tracing::warn!(%error, "failed to extend PATH with the IPC shim directory");
            base
        }
    }
}
