//! Host access: the sandbox confines nothing, but still provides IPC, process
//! tracking and limits.
//!
//! The contrast with the default configuration is asserted on the same files:
//! what host access opens, strict mode must refuse.

#![cfg(any(target_os = "macos", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

mod fixtures;

use std::process::Output;

use heel::{NetworkPolicy, Sandbox, SandboxConfig, SandboxConfigBuilder};

/// Run `script` with `/bin/sh` inside `sandbox`.
async fn sh(sandbox: &Sandbox<impl NetworkPolicy>, script: &str) -> Output {
    sandbox
        .command("/bin/sh")
        .arg("-c")
        .arg(script)
        .output()
        .await
        .expect("the shell runs")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_string()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// A sandbox with the invoking user's full access.
async fn host() -> Sandbox<heel::HostAccess> {
    Sandbox::with_config_and_executor(
        SandboxConfigBuilder::default().host_access().build(),
        executor_core::tokio::TokioGlobal,
    )
    .await
    .expect("sandbox starts")
}

/// A file outside every grant that a strict sandbox cannot read.
fn secret_file() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = fixtures::tempdir();
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, "token-value").expect("writes");
    (dir, path)
}

#[tokio::test]
async fn a_file_outside_every_grant_is_readable() {
    let (_dir, secret) = secret_file();
    let sandbox = host().await;

    let output = sh(&sandbox, &format!("cat {}", secret.display())).await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "token-value");
}

#[tokio::test]
async fn the_same_read_is_denied_in_the_default_sandbox() {
    let (_dir, secret) = secret_file();
    let sandbox =
        Sandbox::with_config_and_executor(SandboxConfig::new(), executor_core::tokio::TokioGlobal)
            .await
            .expect("sandbox starts");

    let output = sh(&sandbox, &format!("cat {}", secret.display())).await;

    assert!(
        !output.status.success(),
        "strict mode must deny the read: {}",
        stdout(&output)
    );
}

#[tokio::test]
async fn a_path_outside_every_grant_is_writable() {
    let dir = fixtures::tempdir();
    let probe = dir.path().join("written.txt");
    let sandbox = host().await;

    let output = sh(
        &sandbox,
        &format!("printf %s written > {}", probe.display()),
    )
    .await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        std::fs::read_to_string(&probe).expect("read back"),
        "written"
    );
}

#[tokio::test]
async fn a_program_written_to_the_temp_directory_executes() {
    // The shared temp directories are denied exec in every confined profile;
    // host access runs whatever its user could run. A copied platform binary
    // would be killed for signature reasons unrelated to the sandbox, so the
    // probe is a script.
    let dir = fixtures::tempdir();
    let probe = dir.path().join("probe.sh");
    let sandbox = host().await;

    let output = sh(
        &sandbox,
        &format!(
            "printf '#!/bin/sh\\necho executed\\n' > {0} && chmod +x {0} && {0}",
            probe.display()
        ),
    )
    .await;

    assert_eq!(stdout(&output), "executed", "{}", stderr(&output));
}

#[tokio::test]
async fn loopback_connects_directly_without_a_proxy() {
    // The probe binary lives in a temp directory, which also covers exec from
    // a location a confined sandbox cannot run.
    let dir = fixtures::tempdir();
    let probe = fixtures::compile(
        dir.path(),
        include_str!("fixtures/tcp_probe.rs"),
        "tcp-probe",
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    let sandbox = host().await;
    assert_eq!(sandbox.proxy_url(), None, "host access runs no proxy");

    let output = sandbox
        .command(probe.to_string_lossy().to_string())
        .arg(format!("127.0.0.1:{port}"))
        .output()
        .await
        .expect("the probe runs");

    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(feature = "shim")]
mod ipc_route {
    use std::borrow::Cow;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{sh, stderr, stdout};
    use heel::ipc::{IpcCommand, IpcContext, IpcError, IpcRouter, NoArgs};
    use heel::{Sandbox, SandboxConfigBuilder};

    /// Echoes its arguments back, and counts how often it was called.
    struct Echo {
        calls: Arc<AtomicUsize>,
    }

    impl IpcCommand for Echo {
        fn name(&self) -> Cow<'static, str> {
            "echo-args".into()
        }
        fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
            Cow::Borrowed(&[Cow::Borrowed("first")])
        }

        type Args = EchoArgs;
        type Response = String;

        async fn handle(&self, args: EchoArgs, _context: IpcContext) -> Result<String, IpcError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(format!("first={}", args.first))
        }
    }

    #[derive(Debug, serde::Deserialize)]
    struct EchoArgs {
        #[serde(default)]
        first: String,
    }

    #[derive(Debug)]
    struct Structured;

    impl IpcCommand for Structured {
        fn name(&self) -> Cow<'static, str> {
            "structured".into()
        }

        type Args = NoArgs;
        type Response = Vec<u32>;

        async fn handle(&self, _args: NoArgs, _context: IpcContext) -> Result<Vec<u32>, IpcError> {
            Ok(vec![1, 2, 3])
        }
    }

    #[tokio::test]
    async fn ipc_commands_still_route_through_the_shims() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = IpcRouter::new()
            .register(Echo {
                calls: Arc::clone(&calls),
            })
            .register(Structured);
        let config = SandboxConfigBuilder::default()
            .host_access()
            .ipc(router)
            .build();
        let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
            .await
            .expect("sandbox starts");

        let output = sh(&sandbox, "echo-args hello").await;
        assert_eq!(stdout(&output), "first=hello", "{}", stderr(&output));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn a_spawned_child_is_still_attributed_to_the_sandbox() {
    let sandbox = host().await;

    // A descendant the tracker never saw: `sh` exits after printing the pid
    // of a backgrounded sleep, which is reparented to launchd. Only the
    // kernel's answer about its profile ties it to this sandbox.
    // Its streams are redirected: left on the command's pipes the sleep would
    // hold them open and `output` would wait the whole 30 seconds for it.
    let output = sh(&sandbox, "sleep 30 >/dev/null 2>&1 & echo $!").await;
    let grandchild: u32 = stdout(&output).parse().expect("a pid");
    struct Kill(u32);
    impl Drop for Kill {
        fn drop(&mut self) {
            // SAFETY: a pid this test started; SIGKILL only ends that process.
            unsafe { libc::kill(self.0 as i32, libc::SIGKILL) };
        }
    }
    let _kill = Kill(grandchild);

    assert_eq!(
        sandbox.membership(grandchild).expect("membership answered"),
        heel::Membership::Member,
        "the reparented descendant runs under this sandbox's profile"
    );
    assert_eq!(
        sandbox
            .membership(std::process::id())
            .expect("membership answered"),
        heel::Membership::NotMember,
        "an unrelated process is not a member"
    );
}
