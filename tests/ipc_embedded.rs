//! The shimmed IPC route needs no `heel` executable: the library embeds the shim.
//!
//! The outer test re-runs this test executable as the host with `HEEL_BIN`
//! removed and a `PATH` that holds nothing, which are the only places
//! `HeelBinary::locate` looks, so a route that tried to locate, verify or run a
//! `heel` binary would fail the sandbox's creation or the command. The host
//! registers a router with `ipc` and runs a command from inside the sandbox
//! through the shim it wrote.

#![cfg(feature = "shim")]

use std::borrow::Cow;
use std::process::Command;

use heel::ipc::{IpcCommand, IpcContext, IpcError, IpcRouter};
use heel::{HeelBinary, Sandbox, SandboxConfigBuilder};
use serde::Deserialize;

/// What the sandboxed command sends; CJK so the framing is exercised on more
/// than ASCII.
const MESSAGE: &str = "embedded shim 中文 日本語 한국어";

struct Echo;

#[derive(Deserialize)]
struct EchoArgs {
    message: String,
}

impl IpcCommand for Echo {
    fn name(&self) -> Cow<'static, str> {
        "echo-embedded".into()
    }

    fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[Cow::Borrowed("message")])
    }

    type Args = EchoArgs;
    type Response = String;

    async fn handle(&self, args: EchoArgs, _context: IpcContext) -> Result<String, IpcError> {
        Ok(args.message)
    }
}

#[test]
fn a_shimmed_sandbox_needs_no_heel_binary() {
    let empty_path = tempfile::tempdir().expect("an empty directory for PATH");
    let output = Command::new(std::env::current_exe().expect("the test executable"))
        .args([
            "--ignored",
            "--exact",
            "host_without_any_heel_binary",
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

/// The host side, run by `a_shimmed_sandbox_needs_no_heel_binary`.
#[tokio::test]
#[ignore = "run by a_shimmed_sandbox_needs_no_heel_binary, with no heel binary to find"]
async fn host_without_any_heel_binary() {
    // The condition the test stands on: there is no binary to locate.
    HeelBinary::locate().expect_err("no heel binary is reachable from this process");

    let config = SandboxConfigBuilder::default()
        .ipc(IpcRouter::new().register(Echo))
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("a shimmed sandbox is created with no heel binary to be found");

    #[cfg(unix)]
    let output = sandbox
        .command("/bin/sh")
        .args(["-c", "echo-embedded \"$1\"", "sh", MESSAGE])
        .output()
        .await
        .expect("the shell runs");
    #[cfg(windows)]
    let output = sandbox
        .command("echo-embedded")
        .arg(MESSAGE)
        .output()
        .await
        .expect("the shim runs");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), MESSAGE);
}
