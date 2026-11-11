#![doc = "Shims `heel shims` writes reach a router served over TCP, as in a container."]
#![cfg(feature = "shim")]

use std::borrow::Cow;
use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};

use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use heel::ipc::{IpcCommand, IpcContext, IpcError, IpcRequest, IpcResponse, IpcRouter};
use serde::Deserialize;

#[path = "fixtures/mod.rs"]
mod fixtures;

/// A command with a positional argument and one taking standard input, so the
/// shim has to carry the declaration for the call to bind at all.
struct Greet;

#[derive(Deserialize)]
struct GreetArgs {
    name: String,
    note: Option<String>,
}

impl IpcCommand for Greet {
    fn name(&self) -> Cow<'static, str> {
        "greet".into()
    }
    fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[Cow::Borrowed("name")])
    }
    fn stdin_arg(&self) -> Option<Cow<'static, str>> {
        Some("note".into())
    }

    type Args = GreetArgs;
    type Response = String;

    fn handle(
        &self,
        args: GreetArgs,
        _context: IpcContext,
    ) -> impl std::future::Future<Output = Result<String, IpcError>> {
        std::future::ready(Ok(format!(
            "hello {} ({})",
            args.name,
            args.note.as_deref().unwrap_or("no note")
        )))
    }
}

/// Answer one request on `listener` from `router`, as an embedder's listener
/// on the container's host route does.
async fn serve_one(listener: &async_net::TcpListener, router: &IpcRouter) {
    let (mut stream, _) = listener.accept().await.expect("accepts");
    let mut length = [0; 4];
    stream.read_exact(&mut length).await.expect("reads length");
    let mut body = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut body).await.expect("reads request");
    let request = IpcRequest::decode(&body).expect("decodes request");
    let response = match router
        .handle(
            &request.method,
            IpcContext::new(request.working_dir),
            request.params,
        )
        .await
    {
        Ok(payload) => IpcResponse::success(payload),
        Err(error) => IpcResponse::error(&error.to_string()),
    };
    stream
        .write_all(&response.encode())
        .await
        .expect("writes response");
}

/// Write the shims of `router`'s commands into `dir` through the CLI.
fn write_shims(dir: &Path, router: &IpcRouter) {
    let commands = serde_json::to_string(router.commands()).expect("commands serialize");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_heel"))
        .arg("shims")
        .arg("--dir")
        .arg(dir)
        .args(["--commands", &commands])
        .output()
        .expect("heel shims runs");
    assert!(
        output.status.success(),
        "heel shims failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Run `command` with `stdin` piped in, off the executor.
async fn run(mut command: std::process::Command, stdin: &'static str) -> Output {
    blocking::unblock(move || {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawns");
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(stdin.as_bytes())
            .expect("writes stdin");
        child.wait_with_output().expect("waits")
    })
    .await
}

fn assert_greeted(output: &Output, expected: &str) {
    assert!(
        output.status.success(),
        "the shim failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), expected);
}

#[test]
fn a_written_shim_reaches_the_router_over_tcp() {
    smol::block_on(async {
        let router = IpcRouter::new().register(Greet);
        let dir = fixtures::tempdir();
        let bin = dir.path().join("bin");
        write_shims(&bin, &router);

        let listener = async_net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let address = listener.local_addr().expect("address");
        let mut command = std::process::Command::new(
            bin.join("greet")
                .with_extension(std::env::consts::EXE_EXTENSION),
        );
        command
            .arg("ada")
            .env("HEEL_IPC_ENDPOINT", format!("tcp://{address}"));
        let (output, ()) =
            futures_lite::future::zip(run(command, "from stdin"), serve_one(&listener, &router))
                .await;
        assert_greeted(&output, "hello ada (from stdin)");
    });
}

#[cfg(unix)]
#[test]
fn shims_are_owner_only_programs_beside_the_shim_executable() {
    use std::os::unix::fs::PermissionsExt;

    let router = IpcRouter::new().register(Greet);
    let dir = fixtures::tempdir();
    let bin = dir.path().join("bin");
    write_shims(&bin, &router);

    let executable = std::fs::read(bin.join("heel-shim")).expect("shim executable");
    assert!(!executable.is_empty(), "the shim executable is written");
    let shim = std::fs::read_to_string(bin.join("greet")).expect("shim");
    assert!(
        shim.contains("heel-shim\" greet --positional name --stdin-arg note -- \"$@\""),
        "the shim carries the declaration: {shim}"
    );
    for path in [bin.clone(), bin.join("heel-shim"), bin.join("greet")] {
        let mode = std::fs::metadata(&path)
            .expect("exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{} must be owner-only", path.display());
    }
}

/// A container exec that runs its process under `heel run`: the sandbox
/// relays its local IPC socket to the TCP endpoint, and the shims, granted
/// read and execute, reach the router through that relay.
#[cfg(unix)]
#[test]
fn a_written_shim_reaches_the_router_through_a_sandbox_relay() {
    smol::block_on(async {
        let router = IpcRouter::new().register(Greet);
        let dir = fixtures::tempdir();
        let bin = dir.path().join("bin");
        write_shims(&bin, &router);

        let listener = async_net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let address = listener.local_addr().expect("address");
        let path = std::env::join_paths(
            std::iter::once(bin.clone()).chain(std::env::split_paths(heel::DEFAULT_SANDBOX_PATH)),
        )
        .expect("joins PATH");
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_heel"));
        command
            .arg("run")
            .args(["--isolation", "permissive"])
            .args(["--env-passthrough", "PATH"])
            .args(["--ipc-endpoint", &format!("tcp://{address}")])
            .arg("--grant")
            .arg(format!("{}=rx", bin.display()))
            .args(["--", "greet", "grace"])
            .env("PATH", path);
        let (output, ()) = futures_lite::future::zip(
            run(command, "through the relay"),
            serve_one(&listener, &router),
        )
        .await;
        assert_greeted(&output, "hello grace (through the relay)");
    });
}
