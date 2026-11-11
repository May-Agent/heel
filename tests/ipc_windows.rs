#![doc = "Native Windows IPC entrypoints, process resolution and argument fidelity."]
#![cfg(all(windows, feature = "shim"))]

use std::borrow::Cow;

use heel::ipc::{IpcCommand, IpcContext, IpcError, IpcRouter};
use heel::{Sandbox, SandboxConfigBuilder};
use serde::Deserialize;

struct Echo;

#[derive(Deserialize)]
struct EchoArgs {
    message: String,
}

impl IpcCommand for Echo {
    fn name(&self) -> Cow<'static, str> {
        "echo-native".into()
    }

    fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[Cow::Borrowed("message")])
    }

    type Args = EchoArgs;
    type Response = String;

    fn handle(
        &self,
        args: EchoArgs,
        _context: IpcContext,
    ) -> impl std::future::Future<Output = Result<String, IpcError>> {
        std::future::ready(Ok(args.message))
    }
}

async fn sandbox() -> Sandbox {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("heel=debug")
        .try_init();
    Sandbox::with_config_and_executor(
        SandboxConfigBuilder::default()
            .ipc(IpcRouter::new().register(Echo))
            .build(),
        executor_core::tokio::TokioGlobal,
    )
    .await
    .expect("sandbox starts")
}

#[tokio::test]
async fn native_command_resolves_through_the_sandbox_path_and_preserves_arguments() {
    let sandbox = sandbox().await;
    let message = "Unicode 中文 & %PATH% ! ^ \"quotes\"";
    let output = sandbox
        .command("echo-native")
        .arg(message)
        .output()
        .await
        .expect("native shim runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), message);
}

#[tokio::test]
async fn each_command_is_a_hard_link_of_the_shim_with_its_metadata_beside_it() {
    let sandbox = sandbox().await;
    let bin_dir = sandbox.config().ipc_bin_dir().expect("shims are written");

    let shim = std::fs::read(bin_dir.join("heel-shim.exe")).expect("the shim executable");
    assert!(!shim.is_empty());
    assert_eq!(
        std::fs::read(bin_dir.join("echo-native.exe")).expect("the command executable"),
        shim,
        "a command is the shim executable under its own name"
    );
    let metadata: heel::CommandMeta = serde_json::from_slice(
        &std::fs::read(bin_dir.join("echo-native.json")).expect("the command metadata"),
    )
    .expect("the metadata decodes");
    assert_eq!(metadata.positional_args.as_ref(), ["message"]);
}

#[tokio::test]
async fn cmd_invokes_the_native_ipc_handler() {
    let sandbox = sandbox().await;
    let output = sandbox
        .command("cmd.exe")
        .args(["/D", "/S", "/C", "echo-native native-ipc-ok"])
        .output()
        .await
        .expect("cmd runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "native-ipc-ok"
    );
}
