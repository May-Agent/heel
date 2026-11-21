//! Persistent container / sandbox signal isolation, live grants, and nested
//! hierarchy tests on Unix.

#![cfg(any(target_os = "macos", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

mod fixtures;

use std::time::{Duration, Instant};

use fixtures::host::{sh, start, stderr, stdout};
use heel::{Access, Grant, SandboxConfigBuilder};

fn host_pid_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 only checks process existence.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[tokio::test]
async fn separate_commands_in_one_sandbox_signal_each_other_by_real_sandbox_pid() {
    let sandbox = start(SandboxConfigBuilder::default()).await;
    let marker = sandbox.working_dir().join("ready");
    let caught = sandbox.working_dir().join("caught");

    let mut target = sandbox
        .command("/bin/sh")
        .arg("-c")
        .arg(format!(
            "trap 'echo int > \"{}\"; exit 0' INT; echo $$ > \"{}\"; while :; do sleep 0.05; done",
            caught.display(),
            marker.display()
        ))
        .spawn()
        .await
        .expect("spawns target command");

    let sandbox_pid = target.sandbox_id();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "target shell never wrote its PID"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let self_reported: u32 = std::fs::read_to_string(&marker)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(
        sandbox_pid, self_reported,
        "Child::sandbox_id() must match $$ observed inside the sandbox"
    );

    let killer = sh(&sandbox, &format!("/bin/kill -INT {sandbox_pid}")).await;
    assert!(
        killer.status.success(),
        "sibling command in the same sandbox must signal {sandbox_pid}: {}",
        stderr(&killer)
    );

    let status = target.wait().await.expect("waits on target");
    assert!(
        status.success(),
        "target should exit cleanly after SIGINT trap"
    );
    assert_eq!(std::fs::read_to_string(&caught).unwrap().trim(), "int");
}

#[tokio::test]
async fn sandbox_cannot_signal_host_or_sibling_sandbox() {
    let sandbox_a = start(SandboxConfigBuilder::default()).await;
    let sandbox_b = start(SandboxConfigBuilder::default()).await;

    let mut victim_b = sandbox_b
        .command("/bin/sh")
        .arg("-c")
        .arg("sleep 60")
        .spawn()
        .await
        .expect("spawns victim in B");

    let host_pid = std::process::id();
    let b_sandbox_pid = victim_b.sandbox_id();
    let b_host_pid = victim_b.id();

    for forbidden in [host_pid, b_sandbox_pid, b_host_pid] {
        let attempt = sh(
            &sandbox_a,
            &format!("/bin/kill -TERM {forbidden} 2>/dev/null; echo $?"),
        )
        .await;
        assert_ne!(
            stdout(&attempt),
            "0",
            "sandbox A must not be able to signal PID {forbidden}"
        );
    }

    assert!(
        victim_b.try_wait().unwrap().is_none(),
        "victim in sibling sandbox B must still be running"
    );
    victim_b.kill().unwrap();
}

#[tokio::test]
async fn live_grant_enables_read_and_write_without_restarting_sandbox() {
    let extra = fixtures::tempdir();
    let extra_path = std::fs::canonicalize(extra.path()).unwrap();
    let file_in_extra = extra_path.join("hello.txt");
    std::fs::write(&file_in_extra, "before").unwrap();

    let sandbox = start(SandboxConfigBuilder::default().filesystem_strict(true)).await;

    let denied_write = sh(
        &sandbox,
        &format!(
            "echo nope > \"{}\" 2>/dev/null; echo $?",
            file_in_extra.display()
        ),
    )
    .await;
    assert_ne!(stdout(&denied_write), "0", "ungranted write must be denied");
    assert_eq!(std::fs::read_to_string(&file_in_extra).unwrap(), "before");

    sandbox
        .grant([Grant::new(fixtures::resolved(&extra_path), Access::WRITE)])
        .await
        .expect("live grant succeeds");

    let allowed = sh(
        &sandbox,
        &format!(
            "echo updated > \"{0}\" && cat \"{0}\"",
            file_in_extra.display()
        ),
    )
    .await;
    assert!(allowed.status.success(), "{}", stderr(&allowed));
    assert_eq!(stdout(&allowed).trim(), "updated");
    assert_eq!(
        std::fs::read_to_string(&file_in_extra).unwrap().trim(),
        "updated"
    );
}

#[tokio::test]
async fn dropping_sandbox_terminates_detached_background_descendants() {
    let dir = fixtures::tempdir();
    let dir_path = std::fs::canonicalize(dir.path()).unwrap();
    let pid_file = dir_path.join("detached.pid");

    let sandbox =
        start(SandboxConfigBuilder::default().writable(fixtures::resolved(&dir_path))).await;

    let launch = sh(
        &sandbox,
        &format!(
            "(nohup /bin/sh -c 'echo $$ > \"{0}\"; exec sleep 120' </dev/null >/dev/null 2>&1 &); \
             while [ ! -s \"{0}\" ]; do sleep 0.02; done; cat \"{0}\"",
            pid_file.display()
        ),
    )
    .await;
    assert!(launch.status.success(), "{}", stderr(&launch));
    let detached_sandbox_pid: u32 = stdout(&launch).trim().parse().unwrap();
    let detached_host_pid = sandbox
        .resolve_pid(detached_sandbox_pid)
        .expect("detached process is alive inside the sandbox");
    assert!(host_pid_alive(detached_host_pid));

    drop(sandbox);

    let deadline = Instant::now() + Duration::from_secs(5);
    while host_pid_alive(detached_host_pid) {
        assert!(
            Instant::now() < deadline,
            "detached process {detached_host_pid} survived sandbox drop"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn nested_linux_container_allows_parent_to_child_signals_denies_reverse_and_cascades_drop() {
    let parent = start(SandboxConfigBuilder::default()).await;
    let child = start(SandboxConfigBuilder::default().parent(parent.handle())).await;

    // Advance `parent`'s PID counter past `child`'s small namespace PIDs so
    // `parent_pid_in_parent` cannot coincide numerically with `child_proc`'s
    // own PID inside `child`.
    for _ in 0..5 {
        let _ = sh(&parent, ":").await;
    }

    let mut parent_proc = parent
        .command("/bin/sh")
        .arg("-c")
        .arg("sleep 120")
        .spawn()
        .await
        .expect("spawns parent command");
    let mut child_proc = child
        .command("/bin/sh")
        .arg("-c")
        .arg("sleep 120")
        .spawn()
        .await
        .expect("spawns child command");

    let parent_pid_in_parent = parent_proc.sandbox_id();
    let child_host_pid = child_proc.id();
    assert!(
        parent_pid_in_parent > child_proc.sandbox_id() + 2,
        "parent_pid_in_parent={parent_pid_in_parent}, child_sandbox_pid={}",
        child_proc.sandbox_id()
    );
    assert_eq!(
        child.pid_in_sandbox(parent_proc.id()),
        None,
        "parent process must have no PID mapping inside nested child container"
    );

    // Child container cannot signal parent container by any PID, and `kill -KILL 1`
    // inside the child cannot kill its own `SIGNAL_UNKILLABLE` namespace init.
    for target_pid in [parent_pid_in_parent, parent_proc.id()] {
        let rev = sh(
            &child,
            &format!("/bin/kill -TERM {target_pid} 2>/dev/null; echo $?"),
        )
        .await;
        assert_ne!(
            stdout(&rev).trim(),
            "0",
            "nested child container must not signal {target_pid}"
        );
    }
    let self_init = sh(&child, "/bin/kill -KILL 1 2>/dev/null; echo still_alive").await;
    assert_eq!(stdout(&self_init).trim(), "still_alive");
    assert!(parent_proc.try_wait().unwrap().is_none());

    // Parent container sees child process under its own PID namespace and can kill it natively.
    let child_pid_in_parent = parent
        .pid_in_sandbox(child_host_pid)
        .expect("parent container must see nested child process in its PID namespace");
    let forward = sh(&parent, &format!("/bin/kill -KILL {child_pid_in_parent}")).await;
    assert!(
        forward.status.success(),
        "parent container must signal nested child process {child_pid_in_parent}: {}",
        stderr(&forward)
    );
    let _ = child_proc
        .wait()
        .await
        .expect("child reaped after parent kill");

    // Spawn a second process in child, then drop `parent`: kernel must cascade teardown to `child`.
    let grandchild = child
        .command("/bin/sh")
        .arg("-c")
        .arg("sleep 120")
        .spawn()
        .await
        .expect("spawns second child command");
    let grandchild_host_pid = grandchild.id();
    assert!(host_pid_alive(grandchild_host_pid));

    drop(parent_proc);
    drop(parent);

    let deadline = Instant::now() + Duration::from_secs(5);
    while host_pid_alive(grandchild_host_pid) {
        assert!(
            Instant::now() < deadline,
            "nested child container process {grandchild_host_pid} survived parent container teardown"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(grandchild);
    drop(child);
}
