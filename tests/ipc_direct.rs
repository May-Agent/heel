//! The direct IPC route: a sandbox with no `heel` binary anywhere.
//!
//! The test executable plays every role. The outer test re-runs it as the host
//! (`host_without_a_heel_binary`) with `HEEL_BIN` removed and a `PATH` that
//! holds nothing, which are the only places `HeelBinary::locate` looks, so a
//! direct route that tried to locate a binary would fail the sandbox's
//! creation. The host then runs it once more inside the sandbox
//! (`sandboxed_client`), where it links `IpcClient` and connects to the
//! endpoint itself. Re-running rather than editing this process's environment
//! keeps the tests that share it unaffected. The two helpers are `#[ignore]`d
//! so that a plain run executes only the outer test.

use std::borrow::Cow;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[path = "fixtures/mod.rs"]
mod fixtures;

use heel::ipc::{IpcCommand, IpcContext, IpcError, IpcRouter};
use heel::{HeelBinary, IpcClient, Sandbox, SandboxConfigBuilder};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct EchoArgs {
    message: String,
}

struct Echo {
    calls: Arc<AtomicUsize>,
}

impl IpcCommand for Echo {
    fn name(&self) -> Cow<'static, str> {
        "echo".into()
    }

    type Args = EchoArgs;
    type Response = String;

    async fn handle(&self, args: EchoArgs, _context: IpcContext) -> Result<String, IpcError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(args.message)
    }
}

/// What the sandboxed client sends; CJK so the framing is exercised on more
/// than ASCII.
const MESSAGE: &str = "round trip 中文 日本語 한국어";

#[test]
fn a_direct_sandbox_needs_no_heel_binary() {
    let empty_path = tempfile::tempdir().expect("an empty directory for PATH");
    let output = Command::new(std::env::current_exe().expect("the test executable"))
        .args([
            "--ignored",
            "--exact",
            "host_without_a_heel_binary",
            "--nocapture",
        ])
        .env_remove("HEEL_BIN")
        .env("PATH", empty_path.path())
        .output()
        .expect("the host re-run starts");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The host side, run by `a_direct_sandbox_needs_no_heel_binary`.
#[tokio::test]
#[ignore = "run by a_direct_sandbox_needs_no_heel_binary, with no heel binary to find"]
async fn host_without_a_heel_binary() {
    // The condition the test stands on: there is no binary to locate.
    HeelBinary::locate().expect_err("no heel binary is reachable from this process");

    let client = std::env::current_exe().expect("the test executable");
    let calls = Arc::new(AtomicUsize::new(0));
    let config = SandboxConfigBuilder::default()
        .executable(fixtures::resolved(&client))
        .direct_ipc(IpcRouter::new().register(Echo {
            calls: Arc::clone(&calls),
        }))
        .build();
    assert!(config.ipc().is_some(), "the router is kept");
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("a direct sandbox is created with no heel binary to be found");

    assert!(sandbox.ipc_endpoint().is_some(), "the endpoint is served");
    assert!(
        sandbox.config().ipc_bin_dir().is_none(),
        "a direct sandbox has no shim directory"
    );

    let output = sandbox
        .command(client.to_str().expect("a UTF-8 path"))
        .args(["--ignored", "--exact", "sandboxed_client", "--nocapture"])
        .output()
        .await
        .expect("the sandboxed client runs");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1, "the handler ran once");
}

/// The sandboxed side, run by `host_without_a_heel_binary`.
#[test]
#[ignore = "run inside the sandbox by host_without_a_heel_binary"]
fn sandboxed_client() {
    let socket = std::env::var_os("HEEL_IPC_ENDPOINT").expect("the sandbox names its endpoint");
    let mut client = IpcClient::connect(&socket).expect("connects to the endpoint");
    let reply: String = client
        .call(
            "echo",
            &EchoArgs {
                message: MESSAGE.to_owned(),
            },
        )
        .expect("the call completes");
    assert_eq!(reply, MESSAGE);

    // Shims would sit in a directory beside the socket's, under the same
    // private root; none of that root may have reached `PATH`.
    let socket = std::path::Path::new(&socket);
    let root = socket
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the socket sits two levels under its private root");
    let path = std::env::var_os("PATH").expect("the sandbox sets PATH");
    for entry in std::env::split_paths(&path) {
        assert!(
            !entry.starts_with(root),
            "{} is a shim directory on PATH",
            entry.display()
        );
    }
}
