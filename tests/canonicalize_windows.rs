//! What `std::fs::canonicalize` meets inside the Windows sandbox, and that the
//! mount manager device stays closed to what changes mount points.
//!
//! `canonicalize` opens the path with access mode 0, then asks
//! `GetFinalPathNameByHandleW` for its DOS name, which consults the mount
//! manager device. The probe runs each of those steps alone inside the sandbox
//! and the report names the one a denial comes from.

#![cfg(target_os = "windows")]
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Output;

use heel::{Access, Sandbox, SandboxConfigBuilder};

#[path = "fixtures/mod.rs"]
mod fixtures;

/// `ERROR_ACCESS_DENIED` (winerror.h).
const ERROR_ACCESS_DENIED: i32 = 5;

/// A sandbox granting `tools` read and execute, and each of `grants` its access.
async fn sandbox_with(tools: &Path, grants: &[(&Path, Access)]) -> Sandbox {
    let mut builder = SandboxConfigBuilder::default()
        .grant(fixtures::resolved(tools), Access::READ | Access::EXEC);
    for (path, access) in grants {
        builder = builder.grant(fixtures::resolved(path), *access);
    }
    Sandbox::with_config_and_executor(builder.build(), executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts")
}

fn probe(tools: &Path) -> std::path::PathBuf {
    fixtures::compile(
        tools,
        include_str!("fixtures/canonicalize_probe.rs"),
        "canonicalize-probe",
    )
}

/// Run the probe inside `sandbox` with `args` and return its stdout.
async fn run(sandbox: &Sandbox, probe: &Path, args: &[&str]) -> String {
    let output: Output = sandbox
        .command(probe.to_str().expect("the staged path is UTF-8"))
        .args(args)
        .output()
        .await
        .expect("the probe launches");
    assert!(
        output.status.success(),
        "the probe must run: status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[tokio::test]
async fn canonicalize_resolves_paths_under_every_kind_of_grant() {
    let tools = fixtures::tempdir();
    let read = fixtures::tempdir();
    let write = fixtures::tempdir();
    let probe = probe(tools.path());
    let sandbox = sandbox_with(
        tools.path(),
        &[(read.path(), Access::READ), (write.path(), Access::WRITE)],
    )
    .await;

    let report = run(
        &sandbox,
        &probe,
        &[
            "report",
            "read",
            read.path().to_str().expect("the granted path is UTF-8"),
            "write",
            write.path().to_str().expect("the granted path is UTF-8"),
            "workdir",
            sandbox
                .working_dir()
                .to_str()
                .expect("the working directory is UTF-8"),
        ],
    )
    .await;

    // The whole report goes to the log first, so the step that failed is
    // visible whichever path it failed on. Nextest keeps the output of a
    // passing test out of the log; the report is also in the assertion
    // message, which a failure always shows.
    println!("{report}");
    for label in ["read", "write", "workdir"] {
        let line = format!("step=canonicalize path={label} ok");
        assert!(
            report.lines().any(|reported| reported.starts_with(&line)),
            "canonicalize of the {label} path was denied inside the sandbox; \
             each step of it, with its Win32 error code:\n{report}"
        );
    }
}

#[tokio::test]
async fn the_sandbox_cannot_open_the_mount_manager_to_change_mount_points() {
    // `IOCTL_MOUNTMGR_CREATE_POINT` and `IOCTL_MOUNTMGR_DELETE_POINTS` are
    // defined with `FILE_READ_ACCESS | FILE_WRITE_ACCESS`, so the handle they
    // are sent on must have been opened with `FILE_READ_DATA` and
    // `FILE_WRITE_DATA`. Asking for exactly that access and being refused
    // proves the sandbox cannot send either request, without sending one: a
    // mount point created or deleted by a test would be a side effect on the
    // machine. The refusal has to be access denied -- a missing device or any
    // other code would leave the question unanswered.
    let tools = fixtures::tempdir();
    let probe = probe(tools.path());
    let sandbox = sandbox_with(tools.path(), &[]).await;

    let report = run(&sandbox, &probe, &["mountmgr-write"]).await;

    println!("{report}");
    let line = format!("step=mountmgr_read_write_data path=none err={ERROR_ACCESS_DENIED}");
    assert!(
        report.lines().any(|reported| reported == line),
        "the mount manager must refuse read and write access to the sandbox: {report}"
    );
}
