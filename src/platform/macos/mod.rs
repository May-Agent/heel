//! macOS sandbox backend, built on `sandbox-exec` and SBPL profiles.

pub(crate) mod attribution;
mod profile;

pub use profile::generate_profile;

use std::os::unix::process::CommandExt;
use std::process::{Command, Output};
use std::sync::Arc;

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::grant::Grant;
use crate::platform::child::unix::UnixChild;
use crate::platform::preexec::PreExecSetup;
use crate::platform::runner::{Runner, SandboxHandle, StagedRunner, issue_macos_extension};
use crate::platform::{Backend, Child, SpawnRequest};

/// Absolute path to the system sandbox launcher.
///
/// Resolved absolutely rather than through `PATH`, so the sandbox cannot be
/// side-stepped by an attacker-controlled search path.
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// macOS sandbox backend using a persistent `sandbox-exec` runner per sandbox.
pub struct MacOSBackend {
    /// The SBPL profile every command of the sandbox runs under.
    profile: String,
    /// Persistent in-sandbox runner for confined sandboxes (`None` under `host_access`).
    runner: Option<Arc<Runner>>,
    /// Live Seatbelt extension tokens issued through [`Sandbox::grant`], also
    /// applied in each child's `pre_exec` so they survive `execve`.
    live_tokens: std::sync::Mutex<Vec<String>>,
}

impl MacOSBackend {
    /// Create the backend, checking that the OS is new enough, generating the
    /// sandbox profile, and starting the persistent in-sandbox runner.
    pub fn new(config: &SandboxConfigData, proxy_port: Option<u16>) -> Result<Self> {
        let version = Self::macos_version()?;
        if version < (10, 15) {
            return Err(Error::UnsupportedPlatformVersion {
                platform: "macOS",
                minimum: "10.15",
                current: format!("{}.{}", version.0, version.1),
            });
        }

        if config.host_access() {
            let profile = profile::generate_profile(config, proxy_port)?;
            return Ok(Self {
                profile,
                runner: None,
                live_tokens: std::sync::Mutex::new(Vec::new()),
            });
        }

        let staged = StagedRunner::create()?;
        let profile =
            profile::generate_profile_with_runner(config, proxy_port, Some(staged.path()))?;
        let setup = PreExecSetup::new(config)?;
        let runner = Runner::start_macos(staged, &profile, setup)?;
        Ok(Self {
            profile,
            runner: Some(runner),
            live_tokens: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Handle to this sandbox's runner.
    pub(crate) fn handle(&self) -> SandboxHandle {
        SandboxHandle {}
    }

    /// Dynamically grant `grants` to the persistent in-sandbox runner.
    pub(crate) fn grant(&self, grants: &[Grant]) -> Result<()> {
        let Some(runner) = &self.runner else {
            return Ok(());
        };
        let tokens = grants
            .iter()
            .map(issue_macos_extension)
            .collect::<Result<Vec<_>>>()?;
        runner.consume_extensions(&tokens)?;
        self.live_tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(tokens);
        Ok(())
    }

    /// Shut down the persistent runner before sweeping sandbox members.
    pub(crate) fn shutdown(&self) {
        if let Some(runner) = &self.runner {
            runner.shutdown();
        }
    }

    /// Translate a sandbox-local PID to its host PID, if currently alive.
    pub(crate) fn resolve_pid(&self, sandbox_pid: u32) -> Option<u32> {
        // SAFETY: signal 0 probes process existence without sending a signal.
        let rc = unsafe { libc::kill(sandbox_pid as libc::pid_t, 0) };
        (rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
            .then_some(sandbox_pid)
    }

    /// Return `host_pid` if currently alive (caller checks Seatbelt membership).
    pub(crate) fn pid_in_sandbox(&self, host_pid: u32) -> Option<u32> {
        self.resolve_pid(host_pid)
    }

    /// Read the host's macOS version.
    fn macos_version() -> Result<(u32, u32)> {
        let output = Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output()
            .map_err(|e| Error::InitFailed(format!("failed to run sw_vers: {e}")))?;

        if !output.status.success() {
            return Err(Error::InitFailed(format!(
                "sw_vers failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        let version = String::from_utf8_lossy(&output.stdout);
        parse_macos_version(version.trim())
    }

    /// Turn a host-access spawn request into a direct `sandbox-exec` invocation.
    fn build_host_command(&self, request: &SpawnRequest<'_>) -> Result<Command> {
        let mut cmd = Command::new(SANDBOX_EXEC);
        cmd.arg("-p").arg(&self.profile);
        cmd.arg(request.program);
        cmd.args(request.args);
        cmd.current_dir(request.working_dir());

        cmd.env_clear();
        for (key, value) in merged_envs(request.config, request.envs) {
            cmd.env(key, value);
        }

        let setup = PreExecSetup::new(request.config)?;
        if !setup.is_empty() {
            // SAFETY: the closure only issues `setrlimit`, `setpriority` and
            // `setiopolicy_np`, which are async-signal-safe and allocation-free.
            unsafe {
                cmd.pre_exec(move || setup.apply());
            }
        }

        Ok(cmd)
    }

    fn spawn_sync(&self, request: &SpawnRequest<'_>) -> Result<Child> {
        if let Some(runner) = &self.runner {
            let envs = merged_envs(request.config, request.envs);
            // Resource limits and scheduling priority were installed on the
            // persistent runner before `sandbox-exec` and are inherited across `fork`.
            let extra_tokens = self
                .live_tokens
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let child = runner.spawn_command(
                request.program,
                request.args,
                &envs,
                request.working_dir(),
                request.stdin,
                request.stdout,
                request.stderr,
                &[],
                None,
                None,
                &extra_tokens,
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

impl Backend for MacOSBackend {
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
        tracing::debug!(program = %request.program, pid = child.id(), "sandbox: spawned");

        Ok(child)
    }
}

/// Parse the `major.minor` prefix of a macOS version string.
fn parse_macos_version(version: &str) -> Result<(u32, u32)> {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse().ok());
    // Major-only releases such as "26" are reported without a minor component.
    let minor = parts.next().map_or(Some(0), |part| part.parse().ok());

    match (major, minor) {
        (Some(major), Some(minor)) => Ok((major, minor)),
        _ => Err(Error::InitFailed(format!(
            "unrecognized macOS version: {version}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_strings_parse() {
        assert_eq!(parse_macos_version("14.5").unwrap(), (14, 5));
        assert_eq!(parse_macos_version("10.15.7").unwrap(), (10, 15));
        assert_eq!(parse_macos_version("26").unwrap(), (26, 0));
    }

    #[test]
    fn unparsable_versions_are_rejected() {
        assert!(parse_macos_version("").is_err());
        assert!(parse_macos_version("sonoma").is_err());
    }

    #[test]
    fn version_ordering_covers_the_minimum() {
        assert!(parse_macos_version("10.14").unwrap() < (10, 15));
        assert!(parse_macos_version("10.15").unwrap() >= (10, 15));
        assert!(parse_macos_version("11.0").unwrap() >= (10, 15));
    }
}
