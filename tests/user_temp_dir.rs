//! The per-user temporary directory must stay reachable from inside the sandbox.
//!
//! Xcode's `xcrun` shim, which `/usr/bin/python3` and the other developer-tool
//! stubs run through, keeps its `xcrun_db` cache in that directory. When the
//! lookup fails the shim falls back to the per-run `TMPDIR`, finds an empty
//! cache and repeats a slow SDK lookup on every start.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used)]

use std::time::{Duration, Instant};

use heel::{Sandbox, SandboxConfig};

/// How much slower than an unsandboxed start a sandboxed one may be. The slow
/// path costs two to five seconds.
const MARGIN: Duration = Duration::from_secs(1);

async fn sandbox(strict: bool) -> Sandbox {
    let config = SandboxConfig::builder().filesystem_strict(strict).build();
    Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts")
}

/// The start of `/usr/bin/python3`, run twice so the shim's cache is warm.
fn unsandboxed_start() -> Duration {
    let run = || {
        let started = Instant::now();
        let status = std::process::Command::new("/usr/bin/python3")
            .args(["-c", "pass"])
            .status()
            .expect("python3 runs");
        assert!(status.success(), "python3 must run unsandboxed");
        started.elapsed()
    };
    run();
    run()
}

async fn sandboxed_start(sandbox: &Sandbox<impl heel::NetworkPolicy>) -> Duration {
    let started = Instant::now();
    let output = sandbox
        .command("/usr/bin/python3")
        .args(["-c", "pass"])
        .output()
        .await
        .expect("python3 runs");
    let elapsed = started.elapsed();
    assert!(
        output.status.success(),
        "python3 must run in the sandbox: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    elapsed
}

async fn assert_fast_start(strict: bool) {
    let baseline = unsandboxed_start();
    let sandbox = sandbox(strict).await;
    // The first sandboxed run may populate nothing it cannot read back, so
    // every run is held to the bound.
    for _ in 0..2 {
        let elapsed = sandboxed_start(&sandbox).await;
        assert!(
            elapsed <= baseline + MARGIN,
            "strict={strict}: a sandboxed start took {elapsed:?} against {baseline:?} unsandboxed"
        );
    }
}

#[tokio::test]
async fn the_xcrun_shim_starts_fast_in_the_default_sandbox() {
    assert_fast_start(false).await;
}

#[tokio::test]
async fn the_xcrun_shim_starts_fast_in_the_strict_sandbox() {
    assert_fast_start(true).await;
}

#[tokio::test]
async fn the_user_temp_dir_resolves_without_tmpdir() {
    for strict in [false, true] {
        let sandbox = sandbox(strict).await;
        let output = sandbox
            .command("/usr/bin/env")
            .args(["-u", "TMPDIR", "/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"])
            .output()
            .await
            .expect("getconf runs");
        assert!(
            output.status.success(),
            "strict={strict}: confstr failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
