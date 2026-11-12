//! The Linux broker, end to end: real system calls made by a probe inside a
//! sandbox that carries the host protection policies.
//!
//! Each test asserts on what the kernel answered the probe, and on the
//! filesystem afterwards, so a call that was refused but still took effect fails
//! too. They need a Linux kernel with Landlock ABI 4 and `ptrace_scope` of 1 or
//! lower; the x32 test needs a kernel with x32 enabled to mean anything.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

mod fixtures;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

use fixtures::host::{home_with, open_security, sh, start, stderr, stdout};
use heel::{
    AllowAll, DenyAll, InodePool, NetworkPolicy, ReadDenylist, Sandbox, SandboxConfigBuilder,
    WriteDenylist,
};

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EACCES: i32 = 13;
const EBUSY: i32 = 16;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const ENOSPC: i32 = 28;
const ENAMETOOLONG: i32 = 36;
#[cfg(target_arch = "x86_64")]
const ENOSYS: i32 = 38;
const ELOOP: i32 = 40;

/// The probe, compiled once into a directory that outlives the test.
struct Probe {
    _directory: tempfile::TempDir,
    binary: PathBuf,
}

fn probe() -> Probe {
    let directory = fixtures::tempdir();
    let binary = fixtures::compile(
        directory.path(),
        include_str!("fixtures/broker_probe.rs"),
        "broker-probe",
    );
    Probe {
        _directory: directory,
        binary,
    }
}

/// A canonical home directory of stand-ins, with a scratch directory in it.
fn home(files: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let home = home_with(files);
    let root = std::fs::canonicalize(home.path()).unwrap();
    std::fs::create_dir_all(root.join("scratch")).unwrap();
    (home, root)
}

/// Both denylists, aimed at `home`, with the probe runnable.
fn protected<N: NetworkPolicy>(network: N, home: &Path, probe: &Probe) -> SandboxConfigBuilder<N> {
    SandboxConfigBuilder::default()
        .network(network)
        .filesystem_strict(false)
        .security(open_security())
        .writable_file_system(true)
        .executable(fixtures::resolved(&probe.binary))
        .read_denylist(ReadDenylist::credentials().home(home))
        .write_denylist(WriteDenylist::persistence().home(home))
}

/// Run the probe and return what it printed.
async fn ask<N: NetworkPolicy>(sandbox: &Sandbox<N>, probe: &Probe, args: &[&str]) -> String {
    let output = sandbox
        .command(probe.binary.to_str().unwrap())
        .args(args)
        .output()
        .await
        .expect("the probe runs");
    assert!(
        output.status.success(),
        "probe {args:?}: {}",
        stderr(&output)
    );
    stdout(&output)
}

/// The errno in a probe's answer, if it failed.
fn errno(answer: &str) -> Option<i32> {
    answer.strip_prefix("errno ")?.parse().ok()
}

#[track_caller]
fn assert_errno(answer: &str, expected: i32, what: &str) {
    assert_eq!(errno(answer), Some(expected), "{what}: {answer}");
}

fn text(output: &Output) -> String {
    format!("{} {}", stdout(output), stderr(output))
}

/// A file the broker opens for writing is closed on the broker's side before
/// the caller resumes, so a script just written and made executable runs at
/// once instead of failing with `ETXTBSY`. The window was a few instructions
/// wide, so the shell repeats the cycle to make a regression show.
#[tokio::test]
async fn a_script_written_through_the_broker_runs_at_once() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe).executable_working_dir(true)).await;

    let output = sh(
        &sandbox,
        "i=0; while [ \"$i\" -lt 200 ]; do \
         printf '#!/bin/sh\\necho ok\\n' > run.sh && chmod +x run.sh && ./run.sh > /dev/null \
         || exit 1; i=$((i + 1)); done; echo done",
    )
    .await;

    assert_eq!(stdout(&output), "done", "{}", stderr(&output));
}

#[tokio::test]
async fn missing_persistence_files_cannot_be_created_by_any_route() {
    let probe = probe();
    let (_guard, root) = home(&[".cargo/bin/cargo", ".ssh/id_ed25519"]);
    std::fs::write(root.join("scratch/source"), "payload").unwrap();
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let scratch = root.join("scratch/source");
    let scratch = scratch.to_str().unwrap();
    let at = |name: &str| root.join(name).to_str().unwrap().to_owned();

    let attempts: Vec<(&str, Vec<String>, String)> = vec![
        (
            "open O_CREAT",
            vec!["create".into(), at(".zshrc")],
            ".zshrc".into(),
        ),
        (
            "creat",
            vec!["creat".into(), at(".bashrc")],
            ".bashrc".into(),
        ),
        (
            "openat2",
            vec!["openat2".into(), at(".zshenv")],
            ".zshenv".into(),
        ),
        (
            "mkdir",
            vec!["mkdir".into(), at(".cargo/bin/evil")],
            ".cargo/bin/evil".into(),
        ),
        (
            "mknod file",
            vec!["mknod-file".into(), at(".profile")],
            ".profile".into(),
        ),
        (
            "mknod fifo",
            vec!["mknod-fifo".into(), at(".bash_profile")],
            ".bash_profile".into(),
        ),
        (
            "symlink",
            vec!["symlink".into(), "/etc/passwd".into(), at(".bash_login")],
            ".bash_login".into(),
        ),
        (
            "link",
            vec!["link".into(), scratch.into(), at(".zlogin")],
            ".zlogin".into(),
        ),
        (
            "rename",
            vec!["rename".into(), scratch.into(), at(".zprofile")],
            ".zprofile".into(),
        ),
        (
            "socket bind",
            vec!["bind".into(), at(".inputrc")],
            ".inputrc".into(),
        ),
        (
            "O_TMPFILE and linkat",
            vec!["tmpfile".into(), at("scratch"), at(".vimrc")],
            ".vimrc".into(),
        ),
    ];
    for (what, args, created) in attempts {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let answer = ask(&sandbox, &probe, &args).await;
        assert_errno(&answer, EACCES, what);
        assert!(
            std::fs::symlink_metadata(root.join(&created)).is_err(),
            "{what} left {created} behind"
        );
    }
    assert!(
        root.join("scratch/source").exists(),
        "the rename moved its source"
    );
}

#[tokio::test]
async fn existing_persistence_files_cannot_be_changed_by_any_route() {
    let probe = probe();
    let (_guard, root) = home(&[".zshrc", ".bashrc", ".profile", ".zshenv"]);
    std::fs::write(root.join("scratch/other"), "other").unwrap();
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let target = root.join(".zshrc");
    let target = target.to_str().unwrap();
    let other = root.join("scratch/other");
    let other = other.to_str().unwrap();
    let mode_before = std::fs::metadata(target).unwrap().permissions().mode() & 0o777;

    for (what, args) in [
        ("append", vec!["write", target]),
        ("read-write open", vec!["read-write", target]),
        ("truncate", vec!["truncate", target]),
        ("chmod", vec!["chmod", target]),
        ("setxattr", vec!["setxattr", target]),
        ("utimes", vec!["utimes", target]),
        ("unlink", vec!["unlink", target]),
        ("rename away", vec!["rename", target, other]),
        ("exchange", vec!["exchange", target, other]),
        ("link", vec!["link", target, &format!("{other}.link")]),
    ] {
        let answer = ask(&sandbox, &probe, &args).await;
        assert_errno(&answer, EACCES, what);
    }
    assert_eq!(std::fs::read_to_string(target).unwrap(), "secret");
    assert_eq!(std::fs::read_to_string(other).unwrap(), "other");
    assert_eq!(
        std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
        mode_before,
        "the mode changed"
    );
}

#[tokio::test]
async fn a_denied_file_never_appears_while_the_path_changes_under_the_call() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let iterations = std::env::var("HEEL_RACE_ITERATIONS").unwrap_or_else(|_| "20000".into());
    std::fs::create_dir_all(root.join("scratch/ok")).unwrap();
    let sandbox = start(protected(DenyAll, &root, &probe)).await;

    let link = root.join("scratch/link");
    let answer = ask(
        &sandbox,
        &probe,
        &[
            "race-symlink",
            link.to_str().unwrap(),
            root.to_str().unwrap(),
            root.join("scratch/ok").to_str().unwrap(),
            &iterations,
        ],
    )
    .await;
    assert_eq!(answer, "ok");
    assert!(
        std::fs::symlink_metadata(root.join(".zshrc")).is_err(),
        "a symbolic link flipped under the call let a denied file be created"
    );

    let bad = root.join(".zshrc");
    let good = root.join("xzshrc");
    let answer = ask(
        &sandbox,
        &probe,
        &[
            "race-buffer",
            good.to_str().unwrap(),
            bad.to_str().unwrap(),
            &iterations,
        ],
    )
    .await;
    assert_eq!(answer, "ok");
    assert!(
        std::fs::symlink_metadata(&bad).is_err(),
        "a path rewritten under the call let a denied file be created"
    );
}

#[tokio::test]
async fn paths_that_mean_something_else_to_the_broker_mean_the_callers_thing() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;

    let output = sh(&sandbox, "echo through-stderr > /dev/stderr").await;
    assert!(
        stderr(&output).contains("through-stderr"),
        "{}",
        text(&output)
    );

    let output = sh(&sandbox, "echo through-proc > /proc/self/fd/1").await;
    assert_eq!(stdout(&output), "through-proc", "{}", text(&output));

    let before = std::fs::read_to_string("/proc/self/comm").unwrap();
    let output = sh(
        &sandbox,
        "echo renamed > /proc/self/comm; cat /proc/self/comm",
    )
    .await;
    assert!(!stdout(&output).is_empty(), "{}", text(&output));
    assert_eq!(std::fs::read_to_string("/proc/self/comm").unwrap(), before);
    assert!(
        !std::fs::read_dir("/proc/self/task")
            .unwrap()
            .flatten()
            .any(|task| std::fs::read_to_string(task.path().join("comm"))
                .is_ok_and(|comm| comm.trim() == "renamed")),
        "the broker's own thread was renamed"
    );
}

#[tokio::test]
async fn new_entries_above_a_denied_path_work_like_their_siblings() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519", ".config/gh/hosts.yml", "keep/file"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let root_text = root.display();

    let output = sh(
        &sandbox,
        &format!(
            "mkdir '{root_text}/made' && echo 'echo ran' > '{root_text}/made/run.sh' \
             && sh '{root_text}/made/run.sh' && mkdir '{root_text}/made/inner' \
             && echo x > '{root_text}/made/inner/file' && cat '{root_text}/made/inner/file' \
             && ls '{root_text}' > /dev/null && ls '{root_text}/.config' > /dev/null \
             && echo y > '{root_text}/note' && cat '{root_text}/note' \
             && mv '{root_text}/note' '{root_text}/note2' && rm '{root_text}/note2'"
        ),
    )
    .await;
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(stdout(&output), "ran\nx\ny");

    let credential = sh(&sandbox, &format!("cat '{root_text}/.ssh/id_ed25519'")).await;
    assert!(!credential.status.success());
}

#[tokio::test]
async fn sandboxes_in_one_process_each_get_a_pool_of_their_own() {
    async fn one(probe: &Probe) {
        let (_guard, root) = home(&[".ssh/id_ed25519"]);
        let sandbox = start(protected(DenyAll, &root, probe)).await;
        let root_text = root.display();
        for round in 0..3 {
            let output = sh(
                &sandbox,
                &format!(
                    "mkdir '{root_text}/made{round}' && echo x > '{root_text}/made{round}/file' \
                     && cat '{root_text}/made{round}/file'"
                ),
            )
            .await;
            assert!(output.status.success(), "{}", text(&output));
            assert_eq!(stdout(&output), "x");
        }
    }

    let probe = probe();
    tokio::join!(
        one(&probe),
        one(&probe),
        one(&probe),
        one(&probe),
        one(&probe),
        one(&probe)
    );
}

#[tokio::test]
async fn the_inode_pool_runs_out_with_enospc() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe).inode_pool(InodePool::new(2, 2))).await;

    let answer = ask(
        &sandbox,
        &probe,
        &["create-many", root.to_str().unwrap(), "3"],
    )
    .await;
    assert!(
        answer.starts_with("failed 1") && answer.contains(&format!("{ENOSPC}: 1")),
        "{answer}"
    );
}

#[tokio::test]
async fn calls_behave_as_they_do_without_the_broker() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519", "scratch/existing"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let at = |name: &str| root.join(name).to_str().unwrap().to_owned();

    let answer = ask(&sandbox, &probe, &["umask-create", &at("scratch/m"), "027"]).await;
    assert_eq!(answer, "mode 640");
    let answer = ask(&sandbox, &probe, &["umask-create", &at("m"), "077"]).await;
    assert_eq!(answer, "mode 600", "an entry above a denied path");

    assert_errno(
        &ask(&sandbox, &probe, &["create", &at("scratch/existing")]).await,
        EEXIST,
        "exists",
    );
    assert_errno(
        &ask(&sandbox, &probe, &["create", &at("scratch/no/such")]).await,
        ENOENT,
        "missing directory",
    );
    assert_errno(
        &ask(
            &sandbox,
            &probe,
            &["create", &at(&format!("scratch/{}", "n".repeat(300)))],
        )
        .await,
        ENAMETOOLONG,
        "long name",
    );
    assert_errno(
        &ask(&sandbox, &probe, &["write", &at("scratch")]).await,
        EISDIR,
        "directory",
    );
    assert_errno(
        &ask(&sandbox, &probe, &["create", &at("scratch/existing/x")]).await,
        ENOTDIR,
        "through a file",
    );
    std::os::unix::fs::symlink(root.join("scratch/b"), root.join("scratch/a")).unwrap();
    std::os::unix::fs::symlink(root.join("scratch/a"), root.join("scratch/b")).unwrap();
    assert_errno(
        &ask(&sandbox, &probe, &["write", &at("scratch/a")]).await,
        ELOOP,
        "symlink loop",
    );

    let answer = ask(&sandbox, &probe, &["cloexec", &at("scratch/c")]).await;
    assert_eq!(answer, "cloexec 1", "O_CLOEXEC is kept");
}

#[tokio::test]
async fn repository_files_are_protected_wherever_the_repository_is() {
    let probe = probe();
    let (_guard, root) = home(&[
        "work/repo/.git/hooks/pre-commit",
        "work/repo/.git/config",
        "work/repo/.git/modules/x/hooks/post-commit",
        "work/repo/.git/modules/x/config",
        "cache/git/checkout/.git/hooks/sample",
        "work/repo/.git/index",
    ]);
    let exempt = root.join("cache/git");
    let sandbox = start(
        protected(DenyAll, &root, &probe)
            .write_denylist(WriteDenylist::persistence().home(&root).except(&exempt)),
    )
    .await;
    let at = |name: &str| root.join(name).to_str().unwrap().to_owned();

    for denied in [
        "work/repo/.git/hooks/pre-commit",
        "work/repo/.git/config",
        "work/repo/.git/modules/x/hooks/post-commit",
        "work/repo/.git/modules/x/config",
    ] {
        assert_errno(
            &ask(&sandbox, &probe, &["write", &at(denied)]).await,
            EACCES,
            denied,
        );
    }
    assert_errno(
        &ask(
            &sandbox,
            &probe,
            &["create", &at("work/repo/.git/hooks/new")],
        )
        .await,
        EACCES,
        "a new hook",
    );
    assert_eq!(
        ask(&sandbox, &probe, &["write", &at("work/repo/.git/index")]).await,
        "ok"
    );
    assert_eq!(
        ask(
            &sandbox,
            &probe,
            &["write", &at("cache/git/checkout/.git/hooks/sample")]
        )
        .await,
        "ok",
        "an exempt directory"
    );
}

#[tokio::test]
async fn credential_agents_and_foreign_endpoints_cannot_be_connected_to() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let agent = root.join("scratch/agent.sock");
    let _agent = std::os::unix::net::UnixListener::bind(&agent).unwrap();
    let ordinary = root.join("scratch/ordinary.sock");
    let _ordinary = std::os::unix::net::UnixListener::bind(&ordinary).unwrap();
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let other_port = target.local_addr().unwrap().port();

    let sandbox = start(
        SandboxConfigBuilder::default()
            .network(AllowAll)
            .filesystem_strict(false)
            .security(open_security())
            .executable(fixtures::resolved(&probe.binary))
            .read_denylist(ReadDenylist::credentials().home(&root).socket(&agent)),
    )
    .await;
    let proxy_port: u16 = sandbox
        .proxy_url()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/')
        .parse()
        .unwrap();

    assert_errno(
        &ask(&sandbox, &probe, &["connect-unix", agent.to_str().unwrap()]).await,
        EACCES,
        "agent socket",
    );
    assert_eq!(
        ask(
            &sandbox,
            &probe,
            &["connect-unix", ordinary.to_str().unwrap()]
        )
        .await,
        "ok",
        "an ordinary socket"
    );
    assert_errno(
        &ask(&sandbox, &probe, &["connect-abstract", "heel-test"]).await,
        EACCES,
        "abstract socket",
    );
    assert_errno(
        &ask(
            &sandbox,
            &probe,
            &["connect", &format!("127.0.0.1:{other_port}")],
        )
        .await,
        EACCES,
        "loopback on another port",
    );
    assert_errno(
        &ask(
            &sandbox,
            &probe,
            &["connect", &format!("1.2.3.4:{proxy_port}")],
        )
        .await,
        EACCES,
        "another host on the proxy's port",
    );
    assert_eq!(
        ask(
            &sandbox,
            &probe,
            &["connect", &format!("127.0.0.1:{proxy_port}")]
        )
        .await,
        "ok",
        "the proxy"
    );
}

#[tokio::test]
async fn a_detached_descendant_is_still_served() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let output = sh(
        &sandbox,
        &format!(
            "(setsid sh -c 'sleep 1; echo daemon > \"{0}/scratch/daemon\"; echo x > \"{0}/.zshrc\"' \
             </dev/null >/dev/null 2>&1 &); sleep 3; cat '{0}/scratch/daemon'",
            root.display()
        ),
    )
    .await;
    assert_eq!(stdout(&output), "daemon", "{}", text(&output));
    assert!(!root.join(".zshrc").exists());
}

#[tokio::test]
async fn a_signal_storm_does_not_break_creation() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    std::fs::create_dir_all(root.join("scratch/many")).unwrap();
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let answer = ask(
        &sandbox,
        &probe,
        &[
            "storm",
            root.join("scratch/many").to_str().unwrap(),
            "20000",
        ],
    )
    .await;
    assert!(answer.starts_with("failed 0 "), "{answer}");
}

#[tokio::test]
async fn the_sandbox_cannot_get_around_the_broker() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    assert_errno(
        &ask(&sandbox, &probe, &["nested-filter"]).await,
        EBUSY,
        "a nested listener",
    );
    assert_errno(
        &ask(&sandbox, &probe, &["dumpable"]).await,
        EPERM,
        "PR_SET_DUMPABLE",
    );
}

#[tokio::test]
async fn denials_name_every_operation_and_path() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519", ".zshrc"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let recorder = sandbox.record_denials().await.unwrap();

    let secret = root.join(".ssh/id_ed25519");
    let created = root.join(".bashrc");
    let existing = root.join(".zshrc");
    for args in [
        vec!["read", secret.to_str().unwrap()],
        vec!["create", created.to_str().unwrap()],
        vec!["write", existing.to_str().unwrap()],
        vec!["unlink", existing.to_str().unwrap()],
        vec!["chmod", existing.to_str().unwrap()],
    ] {
        ask(&sandbox, &probe, &args).await;
    }
    let denials = recorder.finish().await.unwrap();
    for (operation, path) in [
        ("file-read-data", &secret),
        ("file-write-create", &created),
        ("file-write-data", &existing),
        ("file-write-unlink", &existing),
        ("file-write-mode", &existing),
    ] {
        assert!(
            denials
                .iter()
                .any(|d| d.operation == operation && d.target == path.display().to_string()),
            "no {operation} denial for {}: {denials:#?}",
            path.display()
        );
    }
}

// -- #107 -----------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn x32_system_calls_are_refused_in_every_filter() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    // The broker's filter, and the general filter on its own.
    let broker = start(protected(DenyAll, &root, &probe)).await;
    let plain = start(
        SandboxConfigBuilder::default()
            .filesystem_strict(false)
            .security(open_security())
            .executable(fixtures::resolved(&probe.binary)),
    )
    .await;
    for (sandbox, what) in [(&broker, "with the broker"), (&plain, "without it")] {
        assert_errno(&ask(sandbox, &probe, &["x32"]).await, ENOSYS, what);
    }
}

// -- #108 -----------------------------------------------------------------

#[tokio::test]
async fn terminal_injection_ioctls_are_refused() {
    let probe = probe();
    let sandbox = start(
        SandboxConfigBuilder::default()
            .filesystem_strict(false)
            .security(open_security())
            .executable(fixtures::resolved(&probe.binary)),
    )
    .await;
    // Not a terminal, so an ioctl that reached the kernel would say ENOTTY.
    assert_errno(&ask(&sandbox, &probe, &["tiocsti"]).await, EPERM, "TIOCSTI");
    assert_errno(
        &ask(&sandbox, &probe, &["tioclinux"]).await,
        EPERM,
        "TIOCLINUX",
    );
}

// -- #109 -----------------------------------------------------------------

#[tokio::test]
async fn outbound_tcp_reaches_only_the_proxy_address_and_port() {
    let probe = probe();
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let other_port = target.local_addr().unwrap().port();
    // No denylist: the connect-only broker is what limits the address.
    let sandbox = start(
        SandboxConfigBuilder::default()
            .network(AllowAll)
            .filesystem_strict(false)
            .security(open_security())
            .executable(fixtures::resolved(&probe.binary)),
    )
    .await;
    let proxy_port: u16 = sandbox
        .proxy_url()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/')
        .parse()
        .unwrap();

    assert_eq!(
        ask(
            &sandbox,
            &probe,
            &["connect", &format!("127.0.0.1:{proxy_port}")]
        )
        .await,
        "ok"
    );
    assert_errno(
        &ask(
            &sandbox,
            &probe,
            &["connect", &format!("1.2.3.4:{proxy_port}")],
        )
        .await,
        EACCES,
        "a non-loopback address on the proxy's port",
    );
    assert_errno(
        &ask(
            &sandbox,
            &probe,
            &["connect", &format!("127.0.0.1:{other_port}")],
        )
        .await,
        EACCES,
        "loopback on another port",
    );
}

// -- #217 -----------------------------------------------------------------
//
// A POSIX record lock belongs to the descriptor table of the thread that took
// it, and closing any descriptor of a file in that table releases every lock the
// table holds on the file. The broker opens files for the sandbox inside the
// embedder's process, so closing its own copy must never be the embedder's
// close. Each test here has the embedder (this process) hold a lock, lets the
// sandboxed child reach the file through the broker, and then asks the kernel
// whether the lock is still held: in `/proc/locks`, and by a process forked for
// the purpose, which the probe's own answer could not tell because the broker
// may close after the probe looked.

mod locks {
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    /// The lock kinds the embedder can hold.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Lock {
        /// `fcntl` `F_WRLCK`, owned by the descriptor table.
        PosixWrite,
        /// `fcntl` `F_RDLCK`, owned by the descriptor table.
        PosixRead,
        /// Open file description lock, write. Owned by the open file.
        OfdWrite,
        /// Open file description lock, read.
        OfdRead,
        /// `flock` exclusive. Owned by the open file.
        FlockExclusive,
        /// `flock` shared.
        FlockShared,
    }

    impl Lock {
        fn writes(self) -> bool {
            matches!(
                self,
                Self::PosixWrite | Self::OfdWrite | Self::FlockExclusive
            )
        }

        /// How `/proc/locks` names the lock: kind, mode and, for a lock owned
        /// by a process, whether it names the process.
        fn listing(self) -> (&'static str, &'static str, bool) {
            match self {
                Self::PosixWrite => ("POSIX", "WRITE", true),
                Self::PosixRead => ("POSIX", "READ", true),
                Self::OfdWrite => ("OFDLCK", "WRITE", false),
                Self::OfdRead => ("OFDLCK", "READ", false),
                Self::FlockExclusive => ("FLOCK", "WRITE", true),
                Self::FlockShared => ("FLOCK", "READ", true),
            }
        }
    }

    /// A lock the embedder holds, with the means to ask whether it still is.
    pub struct Held {
        _file: File,
        path: PathBuf,
        lock: Lock,
        inode: u64,
    }

    fn fcntl_lock(file: &File, command: libc::c_int, kind: libc::c_int) -> libc::c_int {
        // SAFETY: an all-zero `flock` is a valid request to fill in.
        let mut request: libc::flock = unsafe { std::mem::zeroed() };
        request.l_type = kind as libc::c_short;
        request.l_whence = libc::SEEK_SET as libc::c_short;
        // SAFETY: `request` outlives the call and the descriptor is open.
        unsafe { libc::fcntl(file.as_raw_fd(), command, &raw mut request) }
    }

    impl Held {
        /// Lock `path`, a file or, for the read kinds, a directory.
        pub fn take(path: &Path, lock: Lock) -> Self {
            let file = if lock.writes() {
                OpenOptions::new().read(true).write(true).open(path)
            } else {
                File::open(path)
            }
            .unwrap();
            let result = match lock {
                Lock::PosixWrite => fcntl_lock(&file, libc::F_SETLK, libc::F_WRLCK),
                Lock::PosixRead => fcntl_lock(&file, libc::F_SETLK, libc::F_RDLCK),
                Lock::OfdWrite => fcntl_lock(&file, libc::F_OFD_SETLK, libc::F_WRLCK),
                Lock::OfdRead => fcntl_lock(&file, libc::F_OFD_SETLK, libc::F_RDLCK),
                // SAFETY: the descriptor is open.
                Lock::FlockExclusive => unsafe {
                    libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)
                },
                // SAFETY: the descriptor is open.
                Lock::FlockShared => unsafe {
                    libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB)
                },
            };
            assert_eq!(
                result,
                0,
                "{lock:?} on {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
            let inode = std::os::unix::fs::MetadataExt::ino(&file.metadata().unwrap());
            Self {
                _file: file,
                path: path.to_owned(),
                lock,
                inode,
            }
        }

        /// The line of `/proc/locks` that lists this lock, if there is one.
        fn listed(&self) -> Option<String> {
            let (kind, mode, owned_by_process) = self.lock.listing();
            let pid = if owned_by_process {
                std::process::id().to_string()
            } else {
                "-1".to_owned()
            };
            std::fs::read_to_string("/proc/locks")
                .unwrap()
                .lines()
                .find(|line| {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    fields.len() >= 6
                        && fields[1] == kind
                        && fields[3] == mode
                        && fields[4] == pid
                        && fields[5].rsplit(':').next() == Some(&self.inode.to_string())
                })
                .map(str::to_owned)
        }

        /// Whether a process of its own is refused what conflicts with the lock.
        fn conflicts_for_another_process(&self) -> bool {
            let path = CString::new(self.path.as_os_str().as_bytes()).unwrap();
            let parent = std::process::id() as libc::pid_t;
            let lock = self.lock;
            // SAFETY: the child calls nothing but `open`, `fcntl`, `flock`,
            // `close` and `_exit`, which are async-signal-safe and allocate
            // nothing, and everything it needs was made before the fork.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
            if pid == 0 {
                // SAFETY: as above.
                let held = unsafe { child_sees(&path, lock, parent) };
                // SAFETY: as above.
                unsafe { libc::_exit(if held { 0 } else { 1 }) };
            }
            let mut status = 0;
            // SAFETY: `pid` is this process's child.
            unsafe { libc::waitpid(pid, &raw mut status, 0) };
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        }

        /// Why the lock is gone, if it is.
        pub fn check(&self) -> Result<(), String> {
            let Some(line) = self.listed() else {
                return Err(format!(
                    "{:?} on {} (inode {}) is no longer in /proc/locks:\n{}",
                    self.lock,
                    self.path.display(),
                    self.inode,
                    std::fs::read_to_string("/proc/locks").unwrap()
                ));
            };
            if !self.conflicts_for_another_process() {
                return Err(format!(
                    "{:?} on {} is listed ({line}) but another process is not refused",
                    self.lock,
                    self.path.display()
                ));
            }
            Ok(())
        }
    }

    /// Whether a lock held by `parent` conflicts with a write lock request
    /// made from here.
    ///
    /// # Safety
    ///
    /// Only for the child of a `fork`: it allocates nothing.
    unsafe fn child_sees(path: &CString, lock: Lock, parent: libc::pid_t) -> bool {
        // SAFETY: `path` is NUL-terminated.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return false;
        }
        match lock {
            Lock::PosixWrite | Lock::PosixRead | Lock::OfdWrite | Lock::OfdRead => {
                // SAFETY: an all-zero `flock` is a valid request.
                let mut request: libc::flock = unsafe { std::mem::zeroed() };
                request.l_type = libc::F_WRLCK as libc::c_short;
                request.l_whence = libc::SEEK_SET as libc::c_short;
                let ofd = matches!(lock, Lock::OfdWrite | Lock::OfdRead);
                let command = if ofd {
                    libc::F_OFD_GETLK
                } else {
                    libc::F_GETLK
                };
                // SAFETY: `request` outlives the call.
                let result = unsafe { libc::fcntl(fd, command, &raw mut request) };
                let expected = if ofd { -1 } else { parent };
                result == 0
                    && request.l_type != libc::F_UNLCK as libc::c_short
                    && request.l_pid == expected
            }
            Lock::FlockExclusive | Lock::FlockShared => {
                // SAFETY: the descriptor is open.
                unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) != 0 }
            }
        }
    }
}

use locks::{Held, Lock};

/// The paths one row of the matrix acts on, as strings for the probe.
struct Target {
    file: String,
    link: String,
    directory: String,
    name: String,
}

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

type Row = (&'static str, fn(&Target) -> Vec<String>);

/// Every way a child reaches a file through the broker, as the probe asks for it.
const FILE_ROWS: &[Row] = &[
    ("openat O_RDONLY", |t| argv(&["open", &t.file, "0"])),
    ("openat O_RDWR", |t| argv(&["open", &t.file, "2"])),
    ("openat O_WRONLY", |t| argv(&["open", &t.file, "1"])),
    ("O_CREAT on an existing file", |t| {
        argv(&["open", &t.file, "101"])
    }),
    ("O_TRUNC", |t| argv(&["open", &t.file, "1001"])),
    ("truncate(2)", |t| argv(&["truncate", &t.file])),
    ("creat(2)", |t| argv(&["creat", &t.file])),
    #[cfg(target_arch = "x86_64")]
    ("the creat system call", |t| argv(&["creat-raw", &t.file])),
    ("openat2", |t| argv(&["openat2-open", &t.file, "2"])),
    ("through a symbolic link", |t| argv(&["open", &t.link, "2"])),
    ("relative to the working directory", |t| {
        argv(&["chdir-open", &t.directory, &t.name, "2"])
    }),
    ("relative to a directory descriptor", |t| {
        argv(&["openat-dir", &t.directory, &t.name, "2"])
    }),
    ("through /proc/self/fd", |t| {
        argv(&["proc-fd-open", &t.file, "2"])
    }),
];

/// Make the file a row acts on, lock it, run the row, and say why the lock was
/// lost, if it was.
async fn lock_row<N: NetworkPolicy>(
    sandbox: &Sandbox<N>,
    probe: &Probe,
    root: &Path,
    lock: Lock,
    index: usize,
    row: &Row,
) -> Result<(), String> {
    let (what, arguments) = row;
    let name = format!("locked-{index}");
    let file = root.join("scratch").join(&name);
    std::fs::write(&file, "data").unwrap();
    let link = root.join(format!("scratch/link-{index}"));
    std::os::unix::fs::symlink(&file, &link).unwrap();
    let held = Held::take(&file, lock);
    held.check()
        .map_err(|why| format!("{what}: before the call: {why}"))?;
    let target = Target {
        file: file.display().to_string(),
        link: link.display().to_string(),
        directory: root.join("scratch").display().to_string(),
        name,
    };
    let answer = ask(
        sandbox,
        probe,
        &arguments(&target)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )
    .await;
    if answer != "ok" {
        return Err(format!("{what}: the call answered {answer}"));
    }
    held.check().map_err(|why| format!("{what}: {why}"))
}

/// The rows named in `only`, or all of them, under `lock`.
async fn rows_keep_the_lock(lock: Lock, only: &[&str]) {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let mut failures = Vec::new();
    let mut ran = 0;
    for (index, row) in FILE_ROWS.iter().enumerate() {
        if !only.is_empty() && !only.contains(&row.0) {
            continue;
        }
        ran += 1;
        if let Err(failure) = lock_row(&sandbox, &probe, &root, lock, index, row).await {
            failures.push(failure);
        }
    }
    assert!(ran > 0, "no row of {only:?}");
    assert!(
        failures.is_empty(),
        "the embedder's {lock:?} did not survive:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
async fn a_brokered_write_open_keeps_the_embedders_posix_write_lock() {
    rows_keep_the_lock(Lock::PosixWrite, &["openat O_RDWR", "openat O_WRONLY"]).await;
}

#[tokio::test]
async fn a_brokered_write_open_keeps_the_embedders_posix_read_lock() {
    rows_keep_the_lock(Lock::PosixRead, &["openat O_RDWR", "openat O_WRONLY"]).await;
}

#[tokio::test]
async fn a_brokered_truncate_keeps_the_embedders_posix_locks() {
    rows_keep_the_lock(Lock::PosixWrite, &["truncate(2)"]).await;
    rows_keep_the_lock(Lock::PosixRead, &["truncate(2)"]).await;
}

#[tokio::test]
async fn every_way_to_open_a_file_keeps_a_posix_write_lock() {
    rows_keep_the_lock(Lock::PosixWrite, &[]).await;
}

#[tokio::test]
async fn every_way_to_open_a_file_keeps_a_posix_read_lock() {
    rows_keep_the_lock(Lock::PosixRead, &[]).await;
}

#[tokio::test]
async fn every_way_to_open_a_file_keeps_an_ofd_lock() {
    rows_keep_the_lock(Lock::OfdWrite, &[]).await;
}

#[tokio::test]
async fn every_way_to_open_a_file_keeps_an_ofd_read_lock() {
    rows_keep_the_lock(Lock::OfdRead, &[]).await;
}

#[tokio::test]
async fn every_way_to_open_a_file_keeps_a_flock() {
    rows_keep_the_lock(Lock::FlockExclusive, &[]).await;
}

#[tokio::test]
async fn every_way_to_open_a_file_keeps_a_shared_flock() {
    rows_keep_the_lock(Lock::FlockShared, &[]).await;
}

/// Directories carry read locks only.
const DIRECTORY_LOCKS: [Lock; 3] = [Lock::PosixRead, Lock::OfdRead, Lock::FlockShared];

#[tokio::test]
async fn opening_a_directory_above_a_denied_path_keeps_the_embedders_locks() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let mut failures = Vec::new();
    for lock in DIRECTORY_LOCKS {
        let held = Held::take(&root, lock);
        if let Err(why) = held.check() {
            failures.push(format!("{lock:?}: before the call: {why}"));
            continue;
        }
        let answer = ask(&sandbox, &probe, &["open-dir", root.to_str().unwrap()]).await;
        if answer != "ok" {
            failures.push(format!("{lock:?}: the call answered {answer}"));
        } else if let Err(why) = held.check() {
            failures.push(format!("{lock:?}: {why}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn starting_a_sandbox_keeps_the_embedders_locks_on_the_directories_it_lists() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519", ".config/gh/hosts.yml"]);
    // Where the inode pool lives, which setup lists to clear what stale
    // sandboxes left.
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::home_dir().map(|home| home.join(".cache")))
        .unwrap()
        .join("heel");
    std::fs::create_dir_all(&cache).unwrap();

    let mut failures = Vec::new();
    for lock in DIRECTORY_LOCKS {
        // A directory inside a denied tree, a directory above one, and the cache.
        let held: Vec<Held> = [root.join(".ssh"), root.clone(), cache.clone()]
            .iter()
            .map(|directory| Held::take(directory, lock))
            .collect();
        let sandbox = start(protected(DenyAll, &root, &probe)).await;
        // And once the sandbox has served a command.
        ask(
            &sandbox,
            &probe,
            &["read", root.join(".config/gh/hosts.yml").to_str().unwrap()],
        )
        .await;
        failures.extend(held.iter().filter_map(|held| held.check().err()));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// Many children at once, some of them holding broker workers in a blocking
// call, while the embedder keeps taking and dropping locks of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_children_reach_locked_files_while_the_embedder_churns_locks() {
    const CHILDREN: usize = 32;
    let probe = std::sync::Arc::new(probe());
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = std::sync::Arc::new(start(protected(DenyAll, &root, &probe)).await);
    let scratch = root.join("scratch");
    let locked: Vec<PathBuf> = (0..4)
        .map(|number| scratch.join(format!("shared-{number}")))
        .collect();
    for path in &locked {
        std::fs::write(path, "data").unwrap();
    }
    let held: Vec<Held> = locked
        .iter()
        .map(|path| Held::take(path, Lock::PosixWrite))
        .collect();

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let churn = {
        let (stop, scratch) = (std::sync::Arc::clone(&stop), scratch.clone());
        std::thread::spawn(move || {
            let mut number = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let path = scratch.join(format!("churn-{}", number % 8));
                std::fs::write(&path, "x").unwrap();
                drop(Held::take(&path, Lock::PosixWrite));
                number += 1;
            }
        })
    };

    // More blocked writers than the broker has workers per child, so a spare
    // has to be started for the loop that follows to be served at all.
    let writers = std::thread::available_parallelism().map_or(2, usize::from) + 2;
    let mut children = tokio::task::JoinSet::new();
    for index in 0..CHILDREN {
        let mut arguments: Vec<String> = if index % 4 == 0 {
            let fifo = scratch.join(format!("fifo-{index}"));
            let made = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            // SAFETY: `made` is NUL-terminated.
            assert_eq!(unsafe { libc::mkfifo(made.as_ptr(), 0o600) }, 0);
            argv(&[
                "fifo-open",
                fifo.to_str().unwrap(),
                &writers.to_string(),
                "100",
            ])
        } else {
            argv(&["open-loop", "200"])
        };
        arguments.extend(locked.iter().map(|path| path.display().to_string()));
        let (sandbox, probe) = (
            std::sync::Arc::clone(&sandbox),
            std::sync::Arc::clone(&probe),
        );
        children.spawn(async move {
            let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
            ask(&sandbox, &probe, &arguments).await
        });
    }
    tokio::time::timeout(std::time::Duration::from_secs(180), async {
        while let Some(answer) = children.join_next().await {
            assert_eq!(answer.unwrap(), "ok");
        }
    })
    .await
    .expect("the children finish in time");

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    churn.join().unwrap();
    let failures: Vec<String> = held.iter().filter_map(|held| held.check().err()).collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// -- Descriptor numbers ----------------------------------------------------
//
// The broker's threads keep descriptor tables of their own, so a descriptor
// number means one thing to them and another to the embedder. Everything here
// fills the embedder's numbers with files that nothing may touch.

/// The embedder's descriptors 3 and up, each a file of its own.
struct Sentinels {
    directory: tempfile::TempDir,
    _files: Vec<std::fs::File>,
    paths: Vec<PathBuf>,
    /// The numbers the process already had open, which whatever started it
    /// left there.
    inherited: Vec<i32>,
}

/// What a sentinel looks like from outside, including everything the broker's
/// metadata calls would change.
#[derive(Debug, PartialEq, Eq)]
struct Fingerprint {
    mode: u32,
    owner: (u32, u32),
    modified: (i64, i64),
    changed: (i64, i64),
    links: u64,
    attributes: isize,
}

fn fingerprint(path: &Path) -> Fingerprint {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).unwrap();
    let name = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: a null list with size 0 only asks how long the list is.
    let attributes = unsafe { libc::listxattr(name.as_ptr(), std::ptr::null_mut(), 0) };
    Fingerprint {
        mode: metadata.mode(),
        owner: (metadata.uid(), metadata.gid()),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
        links: metadata.nlink(),
        attributes,
    }
}

impl Sentinels {
    const LAST: i32 = 512;

    fn fill() -> Self {
        // SAFETY: an all-zero `rlimit` is filled in by the call below.
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `limit` outlives both calls.
        unsafe {
            libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit);
            limit.rlim_cur = limit.rlim_max.min(8192);
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit), 0);
        }
        let directory = fixtures::tempdir();
        let inherited = (3..=Self::LAST)
            .filter(|number| std::fs::read_link(format!("/proc/self/fd/{number}")).is_ok())
            .collect();
        let mut files = Vec::new();
        let mut paths = Vec::new();
        loop {
            let path = directory.path().join(format!("sentinel-{}", paths.len()));
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let number = std::os::fd::AsRawFd::as_raw_fd(&file);
            files.push(file);
            paths.push(path);
            if number >= Self::LAST {
                break;
            }
        }
        Self {
            directory,
            _files: files,
            paths,
            inherited,
        }
    }

    fn state(&self) -> Vec<Fingerprint> {
        self.paths.iter().map(|path| fingerprint(path)).collect()
    }

    /// Descriptors 3 through the last are all sentinels, but for the ones the
    /// process was started with.
    #[track_caller]
    fn assert_dense(&self) {
        let directory = self.directory.path().canonicalize().unwrap();
        for number in (3..=Self::LAST).filter(|number| !self.inherited.contains(number)) {
            let target = std::fs::read_link(format!("/proc/self/fd/{number}"));
            assert!(
                target
                    .as_ref()
                    .is_ok_and(|target| target.starts_with(&directory)),
                "descriptor {number} is {target:?}, not a sentinel: something else of the \
                 process holds it"
            );
        }
    }
}

/// Every low descriptor number is a sentinel, so that a number the broker
/// resolves in the wrong table names a file that must not change, not whatever
/// the runtime happened to hold there. The runtime is built after the sentinels
/// for that reason, and the process must be one nothing else has opened
/// descriptors in, which a test run by `cargo nextest` is.
#[test]
fn descriptor_numbers_of_the_embedder_never_name_what_the_broker_acts_on() {
    let sentinels = Sentinels::fill();
    sentinels.assert_dense();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(numbers_name_nothing_of_the_embedders(&sentinels));
}

async fn numbers_name_nothing_of_the_embedders(sentinels: &Sentinels) {
    const ENOTSUP: i32 = 95;
    let before = sentinels.state();
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519", ".zshrc"]);
    std::fs::write(root.join("scratch/target"), "t").unwrap();
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let recorder = sandbox.record_denials().await.unwrap();
    let at = |name: &str| root.join(name).to_str().unwrap().to_owned();
    let target = at("scratch/target");
    // SAFETY: both calls only read the process's credentials.
    let (user, group) = unsafe {
        let mut groups = [0 as libc::gid_t; 64];
        let count = libc::getgroups(64, groups.as_mut_ptr()).max(0) as usize;
        let own = libc::getegid();
        (
            libc::geteuid(),
            groups[..count]
                .iter()
                .copied()
                .find(|&id| id != own)
                .unwrap_or(own),
        )
    };

    let steps: Vec<(&str, Vec<String>, Option<i32>)> = vec![
        ("chmod", argv(&["chmod", &target]), None),
        ("utimes", argv(&["utimes", &target]), None),
        ("setxattr", argv(&["setxattr", &target]), None),
        (
            "chown",
            argv(&["chown", &target, &user.to_string(), &group.to_string()]),
            None,
        ),
        (
            "linkat of a descriptor",
            argv(&["linkat-empty", &at("scratch"), &at("scratch/linked")]),
            None,
        ),
        (
            "a directory above a denied path",
            argv(&["open-dir", &at("")]),
            None,
        ),
        (
            "a new file above a denied path",
            argv(&["create", &at("newfile")]),
            None,
        ),
        (
            "a new directory above a denied path",
            argv(&["mkdir", &at("newdir")]),
            None,
        ),
        (
            "a credential read",
            argv(&["read", &at(".ssh/id_ed25519")]),
            Some(EACCES),
        ),
        (
            "a persistence write",
            argv(&["write", &at(".zshrc")]),
            Some(EACCES),
        ),
    ];
    for (what, arguments, refused) in steps {
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let answer = ask(&sandbox, &probe, &arguments).await;
        match refused {
            Some(errno) => assert_errno(&answer, errno, what),
            // An attribute the filesystem cannot hold is refused by the kernel
            // for the real target and a sentinel alike.
            None if what == "setxattr" && errno(&answer) == Some(ENOTSUP) => {}
            None => assert_eq!(answer, "ok", "{what}"),
        }
    }

    assert_eq!(
        std::fs::metadata(root.join("scratch/target"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o777,
        "the chmod did not reach its target"
    );
    assert_eq!(
        sentinels.state(),
        before,
        "a call changed a file the embedder holds, which a descriptor number of the \
         broker's resolved in the embedder's table"
    );
    let denials = recorder.finish().await.unwrap();
    for (operation, path) in [
        ("file-read-data", root.join(".ssh/id_ed25519")),
        ("file-write-data", root.join(".zshrc")),
    ] {
        assert!(
            denials
                .iter()
                .any(|d| d.operation == operation && d.target == path.display().to_string()),
            "no {operation} denial for {}: {denials:#?}",
            path.display()
        );
    }
}

/// The threads that serve a sandbox, with their `/proc/self/task` directory.
fn broker_threads() -> Vec<(PathBuf, String)> {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .flatten()
        .filter_map(|task| {
            let comm = std::fs::read_to_string(task.path().join("comm")).ok()?;
            let comm = comm.trim().to_owned();
            (comm.starts_with("heel-broker") || comm.starts_with("heel-launcher"))
                .then(|| (task.path(), comm))
        })
        .collect()
}

/// What `heel-broker-home` is called in `comm`, which the kernel cuts at 15 bytes.
const HOME_THREAD: &str = "heel-broker-hom";

/// The broker's threads with a descriptor table of their own: all of them but the
/// launcher and the thread that logs, which are in the embedder's.
fn serving_threads() -> Vec<(PathBuf, String)> {
    broker_threads()
        .into_iter()
        .filter(|(_, comm)| comm != "heel-launcher" && comm != "heel-broker-log")
        .collect()
}

/// What a thread's descriptor table holds, as the links say.
fn table_of(task: &Path) -> Vec<(i32, PathBuf)> {
    std::fs::read_dir(task.join("fd"))
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| {
                    let number = entry.file_name().to_str()?.parse().ok()?;
                    Some((number, std::fs::read_link(entry.path()).ok()?))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn the_threads_that_open_files_for_the_sandbox_hold_no_descriptor_of_the_embedder() {
    let sentinels = Sentinels::fill();
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let scratch = root.join("scratch/file");
    std::fs::write(&scratch, "x").unwrap();
    ask(&sandbox, &probe, &["open", scratch.to_str().unwrap(), "2"]).await;

    let serving = serving_threads();
    assert!(!serving.is_empty(), "no broker thread is running");
    for (task, comm) in serving {
        let table = table_of(&task);
        assert!(
            !table.is_empty(),
            "{comm}: the descriptors of {} cannot be read",
            task.display()
        );
        for (number, target) in &table {
            assert!(
                !target.starts_with(sentinels.directory.path()),
                "{comm} holds descriptor {number} of the embedder: {}",
                target.display()
            );
        }
        assert!(
            table.len() < sentinels.paths.len() / 2,
            "{comm} shares the embedder's table of {} descriptors",
            table.len()
        );
        for number in 0..3 {
            assert_eq!(
                table
                    .iter()
                    .find(|(held, _)| *held == number)
                    .map(|(_, target)| target.as_path()),
                Some(Path::new("/dev/null")),
                "{comm}: descriptor {number} is not /dev/null"
            );
        }
    }
}

fn pipe() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
    use std::os::fd::FromRawFd;
    let mut ends = [0 as libc::c_int; 2];
    // SAFETY: `pipe2` fills two descriptors.
    let made = unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(made, 0);
    // SAFETY: both are new descriptors nothing else owns.
    unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(ends[0]),
            std::os::fd::OwnedFd::from_raw_fd(ends[1]),
        )
    }
}

#[tokio::test]
async fn the_broker_keeps_no_descriptor_the_embedder_closed() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let file = root.join("scratch/file");
    std::fs::write(&file, "x").unwrap();
    // One pipe exists when the sandbox starts, one when it serves a command.
    let (read_early, write_early) = pipe();
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let (read_late, write_late) = pipe();
    ask(&sandbox, &probe, &["open", file.to_str().unwrap(), "2"]).await;
    drop((write_early, write_late));
    for (name, read) in [("early", read_early), ("late", read_late)] {
        let mut poll = libc::pollfd {
            fd: std::os::fd::AsRawFd::as_raw_fd(&read),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid `pollfd`.
        let ready = unsafe { libc::poll(&raw mut poll, 1, 5000) };
        let mut byte = 0u8;
        // SAFETY: one byte of a buffer that lives for the call.
        let count = unsafe { libc::read(poll.fd, (&raw mut byte).cast(), 1) };
        assert!(
            ready == 1 && count == 0,
            "the {name} pipe's write end is still open somewhere: poll {ready}, read {count}"
        );
    }
}

/// A `tracing` subscriber of the kind an embedder installs: it writes to a file
/// by descriptor number, which means something only in the table of the thread
/// that is emitting. Each write checks that the number names the log in the table
/// of the thread that makes it, and says which thread that was.
mod capture {
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Condvar, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    /// The threads whose writes `Log::stall` holds up: every thread of heel's
    /// that emits, whichever it is that does it.
    const STALLED_PREFIX: &str = "heel-";

    /// One write of the subscriber.
    pub struct Entry {
        pub thread: String,
        pub text: String,
    }

    struct Shared {
        _log: OwnedFd,
        number: RawFd,
        path: PathBuf,
        stalled: Mutex<bool>,
        released: Condvar,
        entries: Mutex<Vec<Entry>>,
        misplaced: Mutex<Vec<String>>,
    }

    /// The subscriber's log, as the test sees it.
    pub struct Log(Arc<Shared>);

    struct Writer(Arc<Shared>);

    impl std::io::Write for Writer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let shared = &*self.0;
            let thread = std::thread::current().name().unwrap_or("").to_owned();
            if thread.starts_with(STALLED_PREFIX) {
                let mut stalled = shared
                    .stalled
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                while *stalled {
                    stalled = shared
                        .released
                        .wait(stalled)
                        .unwrap_or_else(PoisonError::into_inner);
                }
            }
            let here = std::fs::read_link(format!("/proc/thread-self/fd/{}", shared.number)).ok();
            if here.as_deref() != Some(shared.path.as_path()) {
                shared
                    .misplaced
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(format!(
                        "{thread}: descriptor {} names {here:?}, not the log",
                        shared.number
                    ));
            }
            // By number, whatever it names, as the subscriber would.
            // SAFETY: a buffer that lives for the call.
            unsafe { libc::write(shared.number, buf.as_ptr().cast(), buf.len()) };
            shared
                .entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Entry {
                    thread,
                    text: String::from_utf8_lossy(buf).into_owned(),
                });
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Install the process's subscriber, writing to a file in `directory`.
    pub fn install(directory: &Path, level: tracing::Level) -> Log {
        let path = directory.join("log");
        let file = File::create(&path).unwrap();
        // A low number, as an embedder that opened its log early has: the
        // numbers a thread of a table of its own gives the files it opens.
        // SAFETY: duplicating a descriptor that is open.
        let low = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        assert!(low >= 0, "{}", std::io::Error::last_os_error());
        drop(file);
        let shared = Arc::new(Shared {
            // SAFETY: a new descriptor that nothing else owns.
            _log: unsafe { OwnedFd::from_raw_fd(low) },
            number: low,
            path: path.canonicalize().unwrap(),
            stalled: Mutex::new(false),
            released: Condvar::new(),
            entries: Mutex::new(Vec::new()),
            misplaced: Mutex::new(Vec::new()),
        });
        let writers = Arc::clone(&shared);
        tracing_subscriber::fmt()
            .with_writer(move || Writer(Arc::clone(&writers)))
            .with_ansi(false)
            .with_max_level(level)
            .try_init()
            .expect("the test's subscriber is the only one: run it alone, as nextest does");
        Log(shared)
    }

    impl Log {
        /// Hold up the broker's threads in their next write to the log.
        pub fn stall(&self) {
            *self
                .0
                .stalled
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = true;
        }

        pub fn release(&self) {
            *self
                .0
                .stalled
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = false;
            self.0.released.notify_all();
        }

        /// The writes whose text holds `needle`.
        pub fn with(&self, needle: &str) -> Vec<(String, String)> {
            self.0
                .entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .filter(|entry| entry.text.contains(needle))
                .map(|entry| (entry.thread.clone(), entry.text.clone()))
                .collect()
        }

        /// Wait for a write that holds `needle`, and return its thread and text.
        pub async fn appears(&self, needle: &str, within: Duration) -> (String, String) {
            let deadline = Instant::now() + within;
            loop {
                if let Some(found) = self.with(needle).into_iter().next() {
                    return found;
                }
                assert!(
                    Instant::now() < deadline,
                    "{needle:?} never reached the subscriber: {}",
                    std::fs::read_to_string(&self.0.path).unwrap_or_default()
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        /// Writes that went to a descriptor number that names something else in
        /// the table of the thread that made them.
        pub fn misplaced(&self) -> Vec<String> {
            self.0
                .misplaced
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }
}

#[tokio::test]
async fn the_brokers_diagnostics_reach_the_embedders_subscriber_from_a_thread_of_its_table() {
    let directory = fixtures::tempdir();
    let log = capture::install(directory.path(), tracing::Level::INFO);

    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe).inode_pool(InodePool::new(2, 2))).await;
    let answer = ask(
        &sandbox,
        &probe,
        &["create-many", root.to_str().unwrap(), "3"],
    )
    .await;
    assert!(answer.starts_with("failed 1"), "{answer}");

    let (thread, _) = log
        .appears(
            "the inode pool of 2 files is used up",
            std::time::Duration::from_secs(10),
        )
        .await;
    // Said by a thread of the embedder's table, where its descriptor is the log,
    // and by none of the broker's other threads, where that number is another
    // file or none.
    assert_eq!(thread, "heel-broker-log");
    assert_eq!(
        log.misplaced(),
        Vec::<String>::new(),
        "the subscriber ran where its descriptor number names something else"
    );
    // The files the sandbox opened through the broker hold what it wrote, which
    // is nothing, and certainly no log text.
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        if entry.file_type().unwrap().is_file() {
            let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
            assert!(
                !text.contains("broker") && !text.contains("inode pool"),
                "{} holds log text: {text}",
                entry.path().display()
            );
        }
    }
}

/// What the bound on the broker's queue of diagnostics is. A test of the
/// bound has to outrun it, so this follows `diag::CAPACITY` by hand.
const DIAGNOSTICS_QUEUED: u64 = 1024;

#[tokio::test]
async fn a_flood_of_refusals_while_the_subscriber_is_stuck_delays_nothing_and_is_counted() {
    const REFUSALS: u64 = 5000;
    let directory = fixtures::tempdir();
    let log = capture::install(directory.path(), tracing::Level::DEBUG);
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let secret = root.join(".ssh/id_ed25519");
    let file = root.join("scratch/file");
    std::fs::write(&file, "x").unwrap();
    let sandbox = start(protected(DenyAll, &root, &probe)).await;

    // The thread that emits takes the first refusal and sticks in the
    // subscriber; the queue behind it fills, and the rest cannot be held.
    log.stall();
    let count = REFUSALS.to_string();
    let flood = ["refuse-loop", &count, secret.to_str().unwrap()];
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        ask(&sandbox, &probe, &flood),
    )
    .await
    .expect("the broker answered every refusal while the subscriber was stuck");
    assert_eq!(answer, "ok");

    // A process started now is not behind the backlog.
    let open = ["open", file.to_str().unwrap(), "2"];
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        ask(&sandbox, &probe, &open),
    )
    .await
    .expect("a spawn after the flood waited for the subscriber");
    assert_eq!(answer, "ok");

    log.release();
    let (_, warning) = log
        .appears(
            "diagnostics were dropped",
            std::time::Duration::from_secs(30),
        )
        .await;
    assert!(warning.contains("WARN"), "{warning}");
    // Every refusal either reached the subscriber or is in a count it was told.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let dropped: u64 = log
            .with("diagnostics were dropped")
            .iter()
            .map(|(_, text)| {
                text.split("count=")
                    .nth(1)
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|count| count.parse::<u64>().ok())
                    .unwrap_or_else(|| panic!("no count in {text}"))
            })
            .sum();
        let delivered = log.with("broker: refused").len() as u64;
        if delivered + dropped >= REFUSALS {
            // The queue and the one the subscriber held are all that fit.
            assert!(
                delivered <= DIAGNOSTICS_QUEUED + 1 + 8,
                "{delivered} refusals reached a subscriber that was stuck"
            );
            assert!(
                dropped >= REFUSALS - DIAGNOSTICS_QUEUED - 1 - 8,
                "only {dropped} of the refusals were counted as dropped"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{delivered} refusals arrived and {dropped} were counted of {REFUSALS}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(log.misplaced(), Vec::<String>::new());
}

/// Once the sandbox is dropped the launcher is gone, and a descendant that
/// outlived it is still served, and still heard.
async fn sandbox_dropped_with_a_descendant_waiting<N: NetworkPolicy>(
    sandbox: Sandbox<N>,
    go: &Path,
    then: &str,
) -> Descendant {
    // The broker reads a caller's memory, which Yama's `ptrace_scope` 1 allows
    // only for a descendant. The descendant here outlives the sandbox's root
    // process, so it stays this process's descendant only if this process
    // adopts it: an embedder that wants to serve such a process is a subreaper.
    // SAFETY: `prctl` takes integers by value.
    let adopted = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    assert_eq!(adopted, 0);
    let output = sh(
        &sandbox,
        &format!(
            "(setsid sh -xc 'echo $$ > \"{0}.pid\"; while [ ! -e \"{0}\" ]; do sleep 0.1; done; {then}' </dev/null >/dev/null 2>\"{0}.trace\" &); \
             while [ ! -s \"{0}.pid\" ]; do sleep 0.05; done; echo started",
            go.display()
        ),
    )
    .await;
    assert_eq!(stdout(&output), "started", "{}", text(&output));
    let mut descendant = Descendant {
        pid: std::fs::read_to_string(go.with_extension("pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap(),
        trace: go.with_extension("trace"),
        history: Vec::new(),
    };
    descendant.note("before the drop");
    drop(sandbox);
    descendant.note("right after the drop");
    // The launcher and the home thread end with the sandbox; the descendant has
    // not been told to go yet, so everything it does is after they are gone.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while broker_threads()
        .iter()
        .any(|(_, comm)| comm == "heel-launcher" || comm == HOME_THREAD)
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the launcher is still running: {:?}",
            broker_threads()
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    descendant.note("once the launcher was gone");
    std::fs::write(go, "").unwrap();
    descendant
}

/// The process a sandbox left behind, by its pid in this namespace.
struct Descendant {
    pid: i32,
    /// What its shell traced.
    trace: PathBuf,
    /// Where it was at each step of the test.
    history: Vec<String>,
}

impl Descendant {
    fn note(&mut self, when: &str) {
        self.history.push(format!("{when}: {}", self.now()));
    }

    /// Where the process was at each step and is now, for a failure to say.
    fn whereabouts(&self) -> String {
        format!(
            "{}\nnow: {}\ntrace:\n{}",
            self.history.join("\n"),
            self.now(),
            std::fs::read_to_string(&self.trace).unwrap_or_else(|error| format!("<{error}>"))
        )
    }

    /// Its state, the system call it is in, and the broker's threads that are
    /// left to serve it.
    fn now(&self) -> String {
        let read = |name: &str| {
            std::fs::read_to_string(format!("/proc/{}/{name}", self.pid))
                .unwrap_or_else(|error| format!("<{error}>"))
        };
        let state = read("status")
            .lines()
            .find(|line| line.starts_with("State:"))
            .map_or_else(|| read("status"), str::to_owned);
        format!(
            "pid {}: {state}; syscall {}; broker threads {:?}",
            self.pid,
            read("syscall").trim(),
            broker_threads()
        )
    }
}

#[tokio::test]
async fn a_descendant_served_after_the_sandbox_is_dropped_is_still_heard() {
    let directory = fixtures::tempdir();
    let log = capture::install(directory.path(), tracing::Level::DEBUG);
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let secret = root.join(".ssh/id_ed25519");
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    sandbox_dropped_with_a_descendant_waiting(
        sandbox,
        &root.join("scratch/go"),
        &format!("cat \"{}\"", secret.display()),
    )
    .await;

    let (thread, text) = log
        .appears(
            &format!("target={}", secret.display()),
            std::time::Duration::from_secs(30),
        )
        .await;
    assert!(text.contains("broker: refused"), "{text}");
    assert_eq!(thread, "heel-broker-log");
    assert_eq!(log.misplaced(), Vec::<String>::new());
    broker_threads_end(std::time::Duration::from_secs(30)).await;
}

// -- Failure paths ---------------------------------------------------------

/// Make the calling thread, and every thread it starts, get `EPERM` from the
/// system call `number`.
fn refuse_system_call(number: libc::c_long) {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const RET_ERRNO: u32 = 0x0005_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    let line = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    // `seccomp_data.nr` is the first field.
    let filter = [
        line(BPF_LD_W_ABS, 0, 0, 0),
        line(BPF_JEQ_K, 0, 1, number as u32),
        line(BPF_RET_K, 0, 0, RET_ERRNO | libc::EPERM as u32),
        line(BPF_RET_K, 0, 0, RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: `prctl` takes integers and `program` outlives the `seccomp` call.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        let installed = libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &raw const program,
        );
        assert_eq!(installed, 0, "{}", std::io::Error::last_os_error());
    }
}

/// The descriptors this process holds, by number.
fn own_table() -> Vec<(i32, PathBuf)> {
    let mut numbers: Vec<i32> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect();
    numbers.sort_unstable();
    // The directory's own descriptor is closed by now, and no longer reads.
    numbers
        .into_iter()
        .filter_map(|number| {
            let target = std::fs::read_link(format!("/proc/self/fd/{number}")).ok()?;
            Some((number, target))
        })
        .collect()
}

/// Start a sandbox while the system call `number` is refused to the thread that
/// does it, and say what that left behind.
async fn creation_fails_cleanly_when_refused(number: libc::c_long, call: &str) {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sentinels = Sentinels::fill();
    let held_before = own_table();
    let state_before = sentinels.state();
    refuse_system_call(number);

    let created = Sandbox::with_config_and_executor(
        protected(DenyAll, &root, &probe).build(),
        executor_core::tokio::TokioGlobal,
    )
    .await;
    let Err(error) = created else {
        panic!("a sandbox was made although {call} was refused to its threads");
    };
    let message = error.to_string();
    assert!(
        message.contains(call),
        "the error does not name {call}: {message}"
    );
    assert!(
        message.contains("setup thread"),
        "the error does not say which thread: {message}"
    );

    broker_threads_end(std::time::Duration::from_secs(10)).await;
    let held_after: std::collections::HashMap<i32, PathBuf> = own_table().into_iter().collect();
    for (number, target) in held_before {
        assert_eq!(
            held_after.get(&number),
            Some(&target),
            "descriptor {number} of the embedder was closed or replaced"
        );
    }
    assert_eq!(
        sentinels.state(),
        state_before,
        "files the embedder holds were changed"
    );
}

#[tokio::test]
async fn a_kernel_without_close_range_unshare_fails_creation_and_closes_nothing() {
    creation_fails_cleanly_when_refused(libc::SYS_close_range, "close_range(CLOSE_RANGE_UNSHARE)")
        .await;
}

#[tokio::test]
async fn blocked_opens_make_the_broker_start_spare_workers() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let fifo = root.join("scratch/fifo");
    let made = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: `made` is NUL-terminated.
    assert_eq!(unsafe { libc::mkfifo(made.as_ptr(), 0o600) }, 0);
    // More blocked writers than the broker starts workers for each process.
    let writers = std::thread::available_parallelism().map_or(2, usize::from) + 2;
    let mut child = sandbox
        .command(probe.binary.to_str().unwrap())
        .args(["fifo-hold", fifo.to_str().unwrap(), &writers.to_string()])
        .spawn()
        .await
        .expect("the probe starts");
    // Each blocked write holds a worker, and the broker keeps one more listening.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let workers = serving_threads()
            .iter()
            .filter(|(_, comm)| comm == "heel-broker")
            .count();
        if workers > writers {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{workers} workers while {writers} writes are blocked: no spare was started"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    child.kill().unwrap();
    let _ = child.wait().await;
}

/// The number of descriptors in the table the home thread and the workers share.
fn broker_table_size() -> usize {
    serving_threads()
        .iter()
        .find(|(_, comm)| comm == HOME_THREAD || comm == "heel-broker")
        .map_or(0, |(task, _)| table_of(task).len())
}

#[tokio::test]
async fn children_killed_mid_request_leave_the_lock_held_and_no_descriptor_behind() {
    use rand::Rng;
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let locked = root.join("scratch/locked");
    std::fs::write(&locked, "data").unwrap();
    let held = Held::take(&locked, Lock::PosixWrite);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    // The table of a broker that has served nothing: the home thread is waiting
    // for the first listener, so what it holds is what stays open for good.
    let baseline = broker_table_size();
    assert!(baseline > 0, "no broker thread has a table to count");
    ask(&sandbox, &probe, &["open", locked.to_str().unwrap(), "2"]).await;
    // A child's listener and workers come and go; the table must come back.
    table_returns_to(baseline, "after one child").await;

    for _round in 0..3 {
        let mut children = Vec::new();
        for _ in 0..12 {
            let child = sandbox
                .command(probe.binary.to_str().unwrap())
                .args(["open-forever", locked.to_str().unwrap()])
                .spawn()
                .await
                .expect("the probe starts");
            children.push(child);
        }
        for mut child in children {
            let delay = rand::thread_rng().gen_range(0..300);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            child.kill().unwrap();
            let _ = child.wait().await;
        }
    }

    table_returns_to(baseline, "after the killed children").await;
    held.check().unwrap();
}

/// Wait for the home thread's table to hold `baseline` descriptors again.
async fn table_returns_to(baseline: usize, when: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let now = broker_table_size();
        if now == baseline {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the broker's table holds {now} descriptors {when}, {baseline} before any child"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Wait for every thread of the broker to end.
async fn broker_threads_end(within: std::time::Duration) {
    let deadline = std::time::Instant::now() + within;
    loop {
        let alive = broker_threads();
        if alive.is_empty() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "threads of the broker are still running: {alive:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn dropping_a_sandbox_with_children_running_ends_every_broker_thread() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let locked = root.join("scratch/locked");
    std::fs::write(&locked, "data").unwrap();
    let held = Held::take(&locked, Lock::PosixWrite);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let mut children = Vec::new();
    for _ in 0..4 {
        children.push(
            sandbox
                .command(probe.binary.to_str().unwrap())
                .args(["open-forever", locked.to_str().unwrap()])
                .spawn()
                .await
                .unwrap(),
        );
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(!broker_threads().is_empty());
    drop(sandbox);
    broker_threads_end(std::time::Duration::from_secs(30)).await;
    held.check().unwrap();
}

#[tokio::test]
async fn a_descendant_that_outlives_the_sandbox_is_served_until_it_ends() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let written = root.join("scratch/after-drop");
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let descendant = sandbox_dropped_with_a_descendant_waiting(
        sandbox,
        &root.join("scratch/go"),
        &format!("echo served > \"{}\"", written.display()),
    )
    .await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::fs::read_to_string(&written).unwrap_or_default().trim() != "served" {
        assert!(
            std::time::Instant::now() < deadline,
            "a descendant that outlived the sandbox lost its broker: {}",
            descendant.whereabouts()
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    broker_threads_end(std::time::Duration::from_secs(30)).await;
}
