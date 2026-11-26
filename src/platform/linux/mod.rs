//! Linux sandbox backend, built on nested namespaces, Landlock and Seccomp.

pub(crate) mod broker;
mod landlock_rules;
mod seccomp_filter;

use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, RwLock};

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::grant::{Access, Grant};
use crate::platform::child::unix::UnixChild;
use crate::platform::preexec::PreExecSetup;
use crate::platform::pty::{AllocatedPty, PtyMaster, attach_slave_in_child};
use crate::platform::runner::{LinuxSpawnExtra, Runner, SandboxHandle, StagedRunner};
use crate::platform::{Backend, Child, SpawnRequest};
use crate::resolve::ResolvedPath;

/// Lowest kernel version with Landlock ABI v4.
const MIN_KERNEL_VERSION: KernelVersion = KernelVersion::new(6, 7, 0);

struct LiveRules {
    /// Internal sandbox grants (runner executable, supervisor binary, IPC shims).
    internal_grants: Vec<Grant>,
    /// Base read denylist supplied at sandbox construction.
    base_read_denylist: Option<crate::policy::ReadDenylist>,
    proxy_port: Option<u16>,
    config: SandboxConfigData,
    ruleset: landlock_rules::PreparedRuleset,
}

/// Linux sandbox backend using a persistent namespace container (`userns` +
/// `pidns` + `mountns`) per sandbox, Landlock for files and network, and
/// Seccomp for syscalls.
pub struct LinuxBackend {
    /// Persistent in-namespace PID 1 runner (`None` under `host_access`).
    runner: Option<Arc<Runner>>,
    /// Lazily staged `heel-unix-runner` used by supervised PTY spawns under
    /// `host_access`, keeping wire compatibility with external `heel` binaries.
    host_runner: Mutex<Option<StagedRunner>>,
    /// The broker, when the configuration needs one.
    broker: Option<broker::Broker>,
    /// Live configuration and Landlock ruleset (`None` under `host_access`).
    live: Option<RwLock<LiveRules>>,
    /// Encoded seccomp filter programs installed on every confined command.
    seccomp_filters: Vec<Vec<u8>>,
    /// Where the denials the broker records are collected.
    sink: Arc<broker::sink::DenialSink>,
}

/// A parsed kernel release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct KernelVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl KernelVersion {
    const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse the numeric prefix of a release string such as `6.8.1-generic`.
    fn parse(release: &str) -> Result<Self> {
        let numeric = release.split('-').next().unwrap_or(release);
        let mut parts = numeric.split('.');

        let major = parts.next().and_then(|part| part.parse().ok());
        let minor = parts.next().and_then(|part| part.parse().ok());
        let patch = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);

        match (major, minor) {
            (Some(major), Some(minor)) => Ok(Self::new(major, minor, patch)),
            _ => Err(Error::InitFailed(format!(
                "unrecognized kernel version: {release}"
            ))),
        }
    }
}

impl std::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl LinuxBackend {
    /// Create the backend, verifying kernel support and starting the persistent
    /// PID-namespace container runner.
    pub fn new(config: &SandboxConfigData, proxy_port: Option<u16>) -> Result<Self> {
        let sink = Arc::new(broker::sink::DenialSink::default());

        if config.host_access() {
            tracing::info!("Linux sandbox backend initialized (host access)");
            return Ok(Self {
                runner: None,
                host_runner: Mutex::new(None),
                broker: None,
                live: None,
                seccomp_filters: Vec::new(),
                sink,
            });
        }

        let kernel = detect_kernel_version()?;
        if kernel < MIN_KERNEL_VERSION {
            return Err(Error::UnsupportedPlatformVersion {
                platform: "Linux",
                minimum: "6.7",
                current: kernel.to_string(),
            });
        }

        landlock_rules::probe_support()?;

        let runner = Runner::start_linux(config.parent())?;
        let mut config = config.clone();
        let mut internal_grants = Vec::new();
        if let Some(exec_path) = runner.runner_executable() {
            let resolved = ResolvedPath::new(exec_path)?;
            internal_grants.push(Grant::new(resolved.clone(), Access::EXEC));
            config.push_grant(resolved, Access::EXEC);
        }
        if let Some(sup_bin) = config.supervisor_binary() {
            let resolved = ResolvedPath::new(sup_bin)?;
            internal_grants.push(Grant::new(resolved, Access::EXEC));
        }
        if let Some(ipc_bin) = config.ipc_bin_dir() {
            let resolved = ResolvedPath::new(ipc_bin)?;
            internal_grants.push(Grant::new(resolved, Access::EXEC));
        }
        let base_read_denylist = config.read_denylist().cloned();

        let (broker, mut ruleset) =
            match broker::Broker::new(&config, proxy_port, Arc::clone(&sink))? {
                Some((broker, ruleset)) => (Some(broker), ruleset),
                None => (None, landlock_rules::build_ruleset(&config, proxy_port)?),
            };
        if let Some(proc_fd) = runner.proc_fd() {
            let proc_writable = config.writable_file_system() && broker.is_none();
            ruleset.grant_private_proc(proc_fd, proc_writable)?;
        }

        let seccomp_filters = seccomp_filter::build_filter(proxy_port.is_some())?.encode_programs();

        tracing::info!(%kernel, broker = broker.is_some(), "Linux sandbox backend initialized");
        Ok(Self {
            runner: Some(runner),
            host_runner: Mutex::new(None),
            broker,
            live: Some(RwLock::new(LiveRules {
                internal_grants,
                base_read_denylist,
                proxy_port,
                config,
                ruleset,
            })),
            seccomp_filters,
            sink,
        })
    }

    /// Handle to this sandbox's container runner, for nesting child sandboxes.
    pub(crate) fn handle(&self) -> SandboxHandle {
        SandboxHandle {
            runner: self.runner.clone(),
        }
    }

    /// Path of the staged `heel-unix-runner` executable, when confined.
    pub(crate) fn runner_executable(&self) -> Option<&Path> {
        self.runner.as_deref().and_then(Runner::runner_executable)
    }

    /// Lazily stage the embedded `heel-unix-runner` for supervised PTY spawns
    /// under `host_access` mode.
    pub(crate) fn host_runner_executable(&self) -> Result<PathBuf> {
        let mut slot = self
            .host_runner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(staged) = slot.as_ref() {
            return Ok(staged.path().to_path_buf());
        }
        let staged = StagedRunner::create()?;
        let path = staged.path().to_path_buf();
        *slot = Some(staged);
        Ok(path)
    }

    /// Translate a sandbox-local PID to its host PID, if currently alive.
    pub(crate) fn resolve_pid(&self, sandbox_pid: u32) -> Option<u32> {
        match &self.runner {
            Some(runner) => runner.resolve_pid(sandbox_pid),
            None => Path::new(&format!("/proc/{sandbox_pid}"))
                .exists()
                .then_some(sandbox_pid),
        }
    }

    /// Translate a host PID to the PID visible inside this sandbox's PID namespace.
    pub(crate) fn pid_in_sandbox(&self, host_pid: u32) -> Option<u32> {
        match &self.runner {
            Some(runner) => runner.pid_in_sandbox(host_pid),
            None => Path::new(&format!("/proc/{host_pid}"))
                .exists()
                .then_some(host_pid),
        }
    }

    /// Dynamically grant `grants` to subsequent commands in this sandbox.
    pub(crate) fn grant(&self, grants: &[Grant]) -> Result<()> {
        let Some(live) = &self.live else {
            return Ok(());
        };
        let mut guard = live
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for grant in grants {
            crate::platform::unresolved::verify(grant.path())?;
            guard
                .config
                .push_grant(grant.resolved_path().clone(), grant.access());
        }
        let ruleset = self.build_live_ruleset(&guard.config, guard.proxy_port)?;
        guard.ruleset = ruleset;
        Ok(())
    }

    /// Synchronize the live sandbox's grants and extra read denials to match
    /// `grants` and `read_denied` for subsequent commands, leaving commands
    /// already running on the ruleset and broker guard they launched with.
    pub(crate) fn set_grants(&self, grants: &[Grant], read_denied: &[ResolvedPath]) -> Result<()> {
        let Some(live) = &self.live else {
            return Ok(());
        };
        for grant in grants {
            crate::platform::unresolved::verify(grant.path())?;
        }
        for denied in read_denied {
            crate::platform::unresolved::verify(denied.as_path())?;
        }
        let mut guard = live
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let merged_grants = guard
            .internal_grants
            .iter()
            .cloned()
            .chain(grants.iter().cloned())
            .collect::<Vec<_>>();
        guard.config.replace_grants(merged_grants);

        let merged_denylist = if read_denied.is_empty() {
            guard.base_read_denylist.clone()
        } else {
            let mut list = guard
                .base_read_denylist
                .clone()
                .unwrap_or_else(crate::policy::ReadDenylist::credentials);
            for path in read_denied {
                list = list.deny(path.as_path());
            }
            Some(list)
        };
        guard.config.set_read_denylist(merged_denylist);

        let ruleset = self.build_live_ruleset(&guard.config, guard.proxy_port)?;
        guard.ruleset = ruleset;
        Ok(())
    }

    fn build_live_ruleset(
        &self,
        config: &SandboxConfigData,
        proxy_port: Option<u16>,
    ) -> Result<landlock_rules::PreparedRuleset> {
        let mut ruleset = match &self.broker {
            Some(broker) => broker.rebuild_policy(config, proxy_port)?,
            None => landlock_rules::build_ruleset(config, proxy_port)?,
        };
        if let Some(proc_fd) = self.runner.as_deref().and_then(Runner::proc_fd) {
            let proc_writable = config.writable_file_system() && self.broker.is_none();
            ruleset.grant_private_proc(proc_fd, proc_writable)?;
        }
        Ok(ruleset)
    }

    /// Shut down the persistent namespace container, triggering kernel
    /// `zap_pid_ns_processes` across the entire process and sub-container tree.
    pub(crate) fn shutdown(&self) {
        if let Some(runner) = &self.runner {
            runner.shutdown();
        }
    }

    /// Where the denials the broker records are collected.
    pub(crate) fn denial_sink(&self) -> &Arc<broker::sink::DenialSink> {
        &self.sink
    }

    fn build_host_command(&self, request: &SpawnRequest<'_>) -> Result<Command> {
        let setup = PreExecSetup::new(request.config)?;
        let mut cmd = Command::new(request.program);
        cmd.args(request.args);
        cmd.current_dir(request.working_dir());
        cmd.env_clear();
        for (key, value) in merged_envs(request.config, request.envs) {
            cmd.env(key, value);
        }

        let inherit_fds: Vec<(std::os::fd::RawFd, i32)> = request.inherit_fds.to_vec();
        // SAFETY: `pre_exec` only calls async-signal-safe `fcntl`, `dup2` and `setup.apply`.
        unsafe {
            cmd.pre_exec(move || {
                for &(src_fd, dst_fd) in &inherit_fds {
                    if src_fd == dst_fd {
                        if libc::fcntl(dst_fd, libc::F_SETFD, 0) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                    } else if libc::dup2(src_fd, dst_fd) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                setup.apply()
            });
        }
        Ok(cmd)
    }

    fn build_command_ruleset(
        &self,
        guard: &LiveRules,
        pty_slave_fd: Option<std::os::fd::BorrowedFd<'_>>,
    ) -> Result<landlock_rules::PreparedRuleset> {
        let mut ruleset = match &self.broker {
            Some(broker) => broker.build_command_ruleset(guard.proxy_port)?,
            None => landlock_rules::build_ruleset(&guard.config, guard.proxy_port)?,
        };
        if let Some(proc_fd) = self.runner.as_deref().and_then(Runner::proc_fd) {
            let proc_writable = guard.config.writable_file_system() && self.broker.is_none();
            ruleset.grant_private_proc(proc_fd, proc_writable)?;
        }
        if let Some(slave_fd) = pty_slave_fd {
            ruleset.grant_pty_slave(slave_fd)?;
        }
        Ok(ruleset)
    }

    fn spawn_sync(&self, request: &SpawnRequest<'_>) -> Result<Child> {
        if let (Some(runner), Some(live)) = (&self.runner, &self.live) {
            let envs = merged_envs(request.config, request.envs);
            let setup = PreExecSetup::new(request.config)?;
            let (limits, nice, io_policy) = setup.raw_parts();
            let ruleset_fd = {
                let guard = live
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(slave_fd) = request.pty_slave_fd {
                    self.build_command_ruleset(&guard, Some(slave_fd))?
                        .duplicate_fd()?
                } else {
                    guard.ruleset.duplicate_fd()?
                }
            };

            let (notif_filter, broker_child_sock, broker_handoff) = match &self.broker {
                Some(broker) => {
                    let (parent_sock, child_sock) = broker.prepare_sockets()?;
                    (
                        broker.program_bytes(),
                        Some(child_sock),
                        Some((broker, parent_sock)),
                    )
                }
                None => (Vec::new(), None, None),
            };

            let child = runner.spawn_command(
                request.program,
                request.args,
                &envs,
                request.working_dir(),
                request.stdin,
                request.stdout,
                request.stderr,
                &limits,
                nice,
                io_policy,
                None,
                LinuxSpawnExtra {
                    ruleset: Some(ruleset_fd.as_fd()),
                    notif_filter: &notif_filter,
                    seccomp_filters: &self.seccomp_filters,
                    broker_child_sock,
                    broker_handoff,
                    inherit_fds: request.inherit_fds,
                    pty_slave_inode: request.pty_slave_inode,
                },
            )?;
            return Ok(Child::new(UnixChild::from_runner(child)));
        }

        let mut cmd = self.build_host_command(request)?;
        cmd.stdin(Stdio::from(request.stdin));
        cmd.stdout(Stdio::from(request.stdout));
        cmd.stderr(Stdio::from(request.stderr));
        cmd.process_group(0);
        let child = cmd.spawn()?;
        Ok(Child::new(UnixChild::new(child)))
    }

    fn spawn_pty_sync(
        &self,
        request: &SpawnRequest<'_>,
        cols: u16,
        rows: u16,
    ) -> Result<(Child, PtyMaster)> {
        let pty = AllocatedPty::open(cols, rows)?;

        if let (Some(runner), Some(live)) = (&self.runner, &self.live) {
            let envs = merged_envs(request.config, request.envs);
            let setup = PreExecSetup::new(request.config)?;
            let (limits, nice, io_policy) = setup.raw_parts();
            let ruleset_fd = {
                let guard = live
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                self.build_command_ruleset(&guard, Some(pty.slave.as_fd()))?
                    .duplicate_fd()?
            };

            let (notif_filter, broker_child_sock, broker_handoff) = match &self.broker {
                Some(broker) => {
                    let (parent_sock, child_sock) = broker.prepare_sockets()?;
                    (
                        broker.program_bytes(),
                        Some(child_sock),
                        Some((broker, parent_sock)),
                    )
                }
                None => (Vec::new(), None, None),
            };

            let child = runner.spawn_command(
                request.program,
                request.args,
                &envs,
                request.working_dir(),
                request.stdin,
                request.stdout,
                request.stderr,
                &limits,
                nice,
                io_policy,
                Some(pty.slave.as_raw_fd()),
                LinuxSpawnExtra {
                    ruleset: Some(ruleset_fd.as_fd()),
                    notif_filter: &notif_filter,
                    seccomp_filters: &self.seccomp_filters,
                    broker_child_sock,
                    broker_handoff,
                    inherit_fds: request.inherit_fds,
                    pty_slave_inode: Some(pty.slave_inode),
                },
            )?;
            drop(pty.slave);
            return Ok((Child::new(UnixChild::from_runner(child)), pty.master));
        }

        let setup = PreExecSetup::new(request.config)?;
        let mut cmd = Command::new(request.program);
        cmd.args(request.args);
        cmd.current_dir(request.working_dir());
        cmd.env_clear();
        for (key, value) in merged_envs(request.config, request.envs) {
            cmd.env(key, value);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let slave_raw = pty.slave.as_raw_fd();
        let inherit_fds: Vec<(std::os::fd::RawFd, i32)> = request.inherit_fds.to_vec();
        // SAFETY: `pre_exec` runs in the forked child before `exec` and only
        // issues async-signal-safe PTY attachment, `dup2`/`fcntl`, and `setup.apply`.
        unsafe {
            cmd.pre_exec(move || {
                attach_slave_in_child(slave_raw)?;
                for &(src_fd, dst_fd) in &inherit_fds {
                    if src_fd == dst_fd {
                        if libc::fcntl(dst_fd, libc::F_SETFD, 0) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                    } else if libc::dup2(src_fd, dst_fd) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                setup.apply()
            });
        }
        let child = cmd.spawn()?;
        drop(pty.slave);
        Ok((Child::new(UnixChild::new(child)), pty.master))
    }
}

fn merged_envs(config: &SandboxConfigData, envs: &[(String, String)]) -> Vec<(String, String)> {
    let mut merged = Vec::with_capacity(config.env_passthrough().len() + envs.len());
    for var in config.env_passthrough() {
        if let Ok(value) = std::env::var(var) {
            merged.push((var.clone(), value));
        }
    }
    merged.extend_from_slice(envs);
    merged
}

/// Where the kernel publishes its release string.
const KERNEL_RELEASE_PATH: &str = "/proc/sys/kernel/osrelease";

/// Read the running kernel's version.
fn detect_kernel_version() -> Result<KernelVersion> {
    let release = std::fs::read_to_string(KERNEL_RELEASE_PATH)
        .map_err(|error| Error::path(KERNEL_RELEASE_PATH, error))?;
    KernelVersion::parse(release.trim())
}

impl Backend for LinuxBackend {
    async fn execute(&self, request: SpawnRequest<'_>) -> Result<Output> {
        tracing::debug!(program = %request.program, args = ?request.args, "sandbox: executing");

        let program_name = request.program.to_owned();
        let child = self.spawn(request).await?;
        let output = child.wait_with_output().await?;

        tracing::debug!(
            program = %program_name,
            exit_code = ?output.status.code(),
            success = output.status.success(),
            "sandbox: command completed"
        );

        Ok(output)
    }

    async fn spawn(&self, request: SpawnRequest<'_>) -> Result<Child> {
        tracing::debug!(program = %request.program, args = ?request.args, "sandbox: spawning");

        let child = self.spawn_sync(&request)?;
        tracing::debug!(
            program = %request.program,
            host_pid = child.id(),
            sandbox_pid = child.sandbox_id(),
            "sandbox: spawned"
        );

        Ok(child)
    }

    async fn spawn_pty(
        &self,
        request: SpawnRequest<'_>,
        cols: u16,
        rows: u16,
    ) -> Result<(Child, PtyMaster)> {
        tracing::debug!(
            program = %request.program,
            args = ?request.args,
            cols,
            rows,
            "sandbox: spawning PTY"
        );

        let (child, master) = self.spawn_pty_sync(&request, cols, rows)?;
        tracing::debug!(
            program = %request.program,
            host_pid = child.id(),
            sandbox_pid = child.sandbox_id(),
            "sandbox: spawned PTY"
        );

        Ok((child, master))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_versions_parse() {
        assert_eq!(
            KernelVersion::parse("6.7.0").unwrap(),
            KernelVersion::new(6, 7, 0)
        );
        assert_eq!(
            KernelVersion::parse("6.8.1-generic").unwrap(),
            KernelVersion::new(6, 8, 1)
        );
        assert_eq!(
            KernelVersion::parse("5.15.0-91-generic").unwrap(),
            KernelVersion::new(5, 15, 0)
        );
        assert_eq!(
            KernelVersion::parse("6.12").unwrap(),
            KernelVersion::new(6, 12, 0)
        );
    }

    #[test]
    fn unparsable_kernel_versions_are_rejected() {
        assert!(KernelVersion::parse("").is_err());
        assert!(KernelVersion::parse("linux").is_err());
    }

    #[test]
    fn kernel_versions_order_by_component() {
        assert!(KernelVersion::new(6, 7, 0) >= MIN_KERNEL_VERSION);
        assert!(KernelVersion::new(6, 8, 0) > MIN_KERNEL_VERSION);
        assert!(KernelVersion::new(5, 15, 0) < MIN_KERNEL_VERSION);
        assert!(KernelVersion::new(6, 6, 9) < MIN_KERNEL_VERSION);
    }
}
