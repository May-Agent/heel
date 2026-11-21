//! Linux sandbox backend, built on nested namespaces, Landlock and Seccomp.

pub(crate) mod broker;
mod landlock_rules;
mod seccomp_filter;

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, RwLock};

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::grant::{Access, Grant};
use crate::platform::child::unix::UnixChild;
use crate::platform::preexec::PreExecSetup;
use crate::platform::runner::{LinuxSpawnExtra, Runner, SandboxHandle};
use crate::platform::{Backend, Child, SpawnRequest};
use crate::resolve::ResolvedPath;

/// Lowest kernel version with Landlock ABI v4.
const MIN_KERNEL_VERSION: KernelVersion = KernelVersion::new(6, 7, 0);

struct LiveRules {
    config: SandboxConfigData,
    ruleset: landlock_rules::PreparedRuleset,
}

/// Linux sandbox backend using a persistent namespace container (`userns` +
/// `pidns` + `mountns`) per sandbox, Landlock for files and network, and
/// Seccomp for syscalls.
pub struct LinuxBackend {
    /// Persistent in-namespace PID 1 runner (`None` under `host_access`).
    runner: Option<Arc<Runner>>,
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
        if let Some(exec_path) = runner.runner_executable() {
            config.push_grant(ResolvedPath::new(exec_path)?, Access::EXEC);
        }

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
            broker,
            live: Some(RwLock::new(LiveRules { config, ruleset })),
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
        let mut new_writable = Vec::new();
        for grant in grants {
            crate::platform::unresolved::verify(grant.path())?;
            if grant.access().can_write() {
                new_writable.push(grant.path());
            }
            guard
                .config
                .push_grant(grant.resolved_path().clone(), grant.access());
        }
        let LiveRules {
            ref config,
            ref mut ruleset,
        } = *guard;
        match &self.broker {
            Some(broker) => broker.extend_ruleset(ruleset, config, &new_writable)?,
            None => {
                let plan = landlock_rules::plan(config);
                ruleset.add_planned(&plan, landlock_rules::REQUIRED_ABI)?;
            }
        }
        Ok(())
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

    fn spawn_sync(&self, request: &SpawnRequest<'_>) -> Result<Child> {
        if let (Some(runner), Some(live)) = (&self.runner, &self.live) {
            use std::os::fd::AsFd;
            let envs = merged_envs(request.config, request.envs);
            let setup = PreExecSetup::new(request.config)?;
            let (limits, nice, io_policy) = setup.raw_parts();
            let ruleset_fd = live
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .ruleset
                .duplicate_fd()?;

            let (notif_filter, broker_child_sock, broker_handoff) = match &self.broker {
                Some(broker) => {
                    let (parent_sock, child_sock) = broker.prepare_sockets()?;
                    (
                        broker.program_bytes(),
                        Some(child_sock),
                        Some((broker, parent_sock)),
                    )
                }
                None => (&[][..], None, None),
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
                LinuxSpawnExtra {
                    ruleset: Some(ruleset_fd.as_fd()),
                    notif_filter,
                    seccomp_filters: &self.seccomp_filters,
                    broker_child_sock,
                    broker_handoff,
                    inherit_fds: request.inherit_fds,
                },
            )?;
            return Ok(Child::new(UnixChild::from_runner(child)));
        }

        let mut cmd = self.build_host_command(request)?;
        cmd.stdin(std::process::Stdio::from(request.stdin));
        cmd.stdout(std::process::Stdio::from(request.stdout));
        cmd.stderr(std::process::Stdio::from(request.stderr));
        cmd.process_group(0);
        let child = cmd.spawn()?;
        Ok(Child::new(UnixChild::new(child)))
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
