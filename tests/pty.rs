//! Per-command PTY spawn and controlling-terminal isolation tests on macOS and Linux.

#![cfg(any(target_os = "macos", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

mod fixtures;

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fixtures::host::{sh, start, stderr, stdout};
use heel::{PtyMaster, ReadDenylist, Sandbox, SandboxConfigBuilder, WriteDenylist};

const TIMEOUT: Duration = Duration::from_secs(15);

/// Read from a `PtyMaster` clone on a blocking thread until `needle` appears
/// in the accumulated output or `timeout` elapses.
async fn read_until(master: &PtyMaster, needle: &str, timeout: Duration) -> String {
    read_pty(master, Some(needle), timeout).await
}

/// Drain a `PtyMaster` clone until EOF/EIO (child exited) or `timeout` elapses.
async fn read_to_eof(master: &PtyMaster, timeout: Duration) -> String {
    read_pty(master, None, timeout).await
}

async fn read_pty(master: &PtyMaster, needle: Option<&str>, timeout: Duration) -> String {
    let mut file = master.try_clone_file().expect("clones PTY master");
    let needle = needle.map(str::to_owned);
    let handle = tokio::task::spawn_blocking(move || {
        // Set non-blocking on a short poll loop so we respect `timeout` even
        // when the child never writes the expected marker.
        let fd = file.as_raw_fd();
        // SAFETY: `fd` is an open PTY master owned by `file`.
        let prev = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        // SAFETY: enabling `O_NONBLOCK` on our master description.
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, prev | libc::O_NONBLOCK) };

        let deadline = Instant::now() + timeout;
        let mut acc = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    acc.extend_from_slice(&buf[..n]);
                    if let Some(ref target) = needle {
                        let text = String::from_utf8_lossy(&acc);
                        if text.contains(target.as_str()) {
                            break;
                        }
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    let rem_ms = deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .min(50) as libc::c_int;
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: `pfd` is a valid 1-element `pollfd`.
                    let _ = unsafe { libc::poll(&raw mut pfd, 1, rem_ms.max(1)) };
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                // On Linux, closing all slave fds makes master reads return EIO.
                Err(_) => break,
            }
        }
        // SAFETY: restore blocking flags so subsequent callers see default mode.
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, prev) };
        String::from_utf8_lossy(&acc).into_owned()
    });
    handle.await.expect("PTY reader task")
}

/// Allocate an unrelated host PTY outside any sandbox and keep both ends open
/// so its `/dev/ttysNNN` or `/dev/pts/N` device node exists and is active.
struct HostPty {
    _master: OwnedFd,
    _slave: OwnedFd,
    slave_path: PathBuf,
}

impl HostPty {
    fn open() -> Self {
        // SAFETY: `posix_openpt`, `grantpt`, and `unlockpt` are standard POSIX PTY calls.
        let master = unsafe {
            let raw = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(
                raw >= 0,
                "posix_openpt: {}",
                std::io::Error::last_os_error()
            );
            let fd = OwnedFd::from_raw_fd(raw);
            assert_eq!(libc::grantpt(fd.as_raw_fd()), 0);
            assert_eq!(libc::unlockpt(fd.as_raw_fd()), 0);
            fd
        };

        #[cfg(target_os = "macos")]
        let slave_path = {
            use std::ffi::{CStr, OsStr};
            use std::os::unix::ffi::OsStrExt;
            const TIOCPTYGNAME: libc::c_ulong = 0x4080_7453;
            let mut buf = [0u8; 128];
            // SAFETY: `buf` is a 128-byte writable buffer for `TIOCPTYGNAME`.
            let rc = unsafe { libc::ioctl(master.as_raw_fd(), TIOCPTYGNAME, buf.as_mut_ptr()) };
            assert_eq!(rc, 0);
            let name = CStr::from_bytes_until_nul(&buf).unwrap();
            PathBuf::from(OsStr::from_bytes(name.to_bytes()))
        };

        #[cfg(target_os = "linux")]
        let slave_path = {
            let mut ptn: libc::c_uint = 0;
            // SAFETY: `TIOCGPTN` writes the slave PTY index into `ptn`.
            let rc = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCGPTN, &raw mut ptn) };
            assert_eq!(rc, 0);
            PathBuf::from(format!("/dev/pts/{ptn}"))
        };

        let c_path = std::ffi::CString::new(slave_path.to_str().unwrap()).unwrap();
        // SAFETY: opening our newly created host slave with `O_NOCTTY`.
        let slave = unsafe {
            let raw = libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
            assert!(
                raw >= 0,
                "open({}): {}",
                slave_path.display(),
                std::io::Error::last_os_error()
            );
            OwnedFd::from_raw_fd(raw)
        };

        Self {
            _master: master,
            _slave: slave,
            slave_path,
        }
    }
}

#[tokio::test]
async fn pty_round_trip_and_default_term() {
    let sandbox = start(SandboxConfigBuilder::default()).await;

    let (mut child, mut master) = sandbox
        .command("/bin/sh")
        .args([
            "-c",
            "if test -t 0 && test -t 1 && test -t 2; then t=yes; else t=no; fi; \
             printf 'tty=%s term=%s\\n' \"$t\" \"$TERM\"; \
             read line; \
             printf 'echo:%s\\n' \"$line\"",
        ])
        .spawn_pty(80, 24)
        .await
        .expect("spawns PTY command");

    let banner = read_until(&master, "term=xterm-256color", TIMEOUT).await;
    assert!(
        banner.contains("tty=yes term=xterm-256color"),
        "expected TTY and default TERM, got: {banner:?}"
    );

    master.write_all(b"hello-pty\n").expect("writes to PTY");
    master.flush().expect("flushes PTY");

    let echoed = read_to_eof(&master, TIMEOUT).await;
    assert!(
        echoed.contains("echo:hello-pty"),
        "expected echoed input, got: {echoed:?}"
    );
    drop(master);

    let status = tokio::time::timeout(TIMEOUT, child.wait())
        .await
        .expect("waits in time")
        .expect("child waits");
    assert!(status.success(), "PTY child failed: {status:?}");

    // Explicit TERM overrides the default.
    let (mut custom_child, mut custom_master) = sandbox
        .command("/bin/sh")
        .args(["-c", "printf 'TERM=%s\\n' \"$TERM\"; read done"])
        .env("TERM", "vt100")
        .spawn_pty(80, 24)
        .await
        .expect("spawns PTY command with custom TERM");
    let custom_out = read_until(&custom_master, "TERM=vt100", TIMEOUT).await;
    assert!(custom_out.contains("TERM=vt100"), "got: {custom_out:?}");
    custom_master.write_all(b"ok\n").unwrap();
    let _ = read_to_eof(&custom_master, TIMEOUT).await;
    drop(custom_master);
    assert!(
        tokio::time::timeout(TIMEOUT, custom_child.wait())
            .await
            .expect("waits in time")
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn pty_resize_updates_winsize_and_delivers_sigwinch() {
    let sandbox = start(SandboxConfigBuilder::default()).await;

    let (mut child, master) = sandbox
        .command("/bin/sh")
        .args([
            "-c",
            "trap 'printf \"winch:%s\\n\" \"$(stty size)\"; exit 0' WINCH; \
             printf 'init:%s\\n' \"$(stty size)\"; \
             while :; do sleep 0.05; done",
        ])
        .spawn_pty(80, 24)
        .await
        .expect("spawns PTY command");

    assert_eq!(master.size().expect("reads initial size"), (80, 24));
    let init = read_until(&master, "init:24 80", TIMEOUT).await;
    assert!(
        init.contains("init:24 80"),
        "expected initial size 24x80, got: {init:?}"
    );

    master.resize(132, 43).expect("resizes PTY");
    assert_eq!(master.size().expect("reads resized size"), (132, 43));

    let resized = read_to_eof(&master, TIMEOUT).await;
    drop(master);
    assert!(
        resized.contains("winch:43 132"),
        "expected SIGWINCH with 43x132, got: {resized:?}"
    );

    let status = tokio::time::timeout(TIMEOUT, child.wait())
        .await
        .expect("waits in time")
        .expect("child waits");
    assert!(status.success(), "child failed: {status:?}");
}

async fn assert_dev_tty_behavior(sandbox: &Sandbox, probe: &std::path::Path) {
    // 1. Inside a PTY child, opening `/dev/tty` for read/write and issuing
    //    `TIOCGWINSZ` ioctl succeeds and reports the configured dimensions.
    let (mut pty_child, pty_master) = sandbox
        .command(probe.to_str().unwrap())
        .args(["rdwr", "/dev/tty"])
        .spawn_pty(96, 31)
        .await
        .expect("spawns PTY probe");
    let out = read_to_eof(&pty_master, TIMEOUT).await;
    drop(pty_master);
    let status = tokio::time::timeout(TIMEOUT, pty_child.wait())
        .await
        .expect("waits in time")
        .expect("waits");
    assert!(
        status.success() && out.contains("ok:96x31"),
        "/dev/tty rdwr + TIOCGWINSZ must succeed in PTY child: status={status:?} out={out:?}"
    );

    // 2. Inside a piped child in the same sandbox, opening `/dev/tty` fails
    //    with `ENXIO` because the persistent runner has no controlling terminal.
    let piped = sandbox
        .command(probe.to_str().unwrap())
        .args(["rdwr", "/dev/tty"])
        .output()
        .await
        .expect("runs piped probe");
    assert!(
        !piped.status.success(),
        "piped child must not open /dev/tty: stdout={} stderr={}",
        stdout(&piped),
        stderr(&piped)
    );
    assert_eq!(
        stdout(&piped),
        format!("err:{}", libc::ENXIO),
        "piped child /dev/tty open must return ENXIO"
    );
}

#[tokio::test]
async fn dev_tty_works_in_pty_child_and_returns_enxio_in_piped_child() {
    let dir = fixtures::tempdir();
    let probe = fixtures::compile(
        dir.path(),
        include_str!("fixtures/pty_probe.rs"),
        "pty-probe",
    );

    // Default confined sandbox (no broker on Linux, Seatbelt runner on macOS).
    let default_sb =
        start(SandboxConfigBuilder::default().executable(fixtures::resolved(&probe))).await;
    assert_dev_tty_behavior(&default_sb, &probe).await;

    // Brokered / host-protected sandbox (`ReadDenylist` + `WriteDenylist`).
    let home = fixtures::host::home_with(&[".ssh/id_rsa"]);
    let protected_sb = start(
        SandboxConfigBuilder::default()
            .filesystem_strict(false)
            .read_denylist(ReadDenylist::credentials().home(home.path()))
            .write_denylist(WriteDenylist::persistence().home(home.path()))
            .executable(fixtures::resolved(&probe)),
    )
    .await;
    assert_dev_tty_behavior(&protected_sb, &probe).await;
}

async fn assert_pty_isolation(sandbox: &Sandbox, probe: &std::path::Path) {
    let host_pty = HostPty::open();

    // Spawn two concurrent PTY commands in the SAME confined persistent sandbox.
    let (mut child_a, mut master_a) = sandbox
        .command("/bin/sh")
        .args([
            "-c",
            "printf 'SLAVE_A=%s\\n' \"$(tty)\"; read done; printf 'A_DONE=%s\\n' \"$done\"",
        ])
        .spawn_pty(80, 24)
        .await
        .expect("spawns PTY child A");

    let (mut child_b, mut master_b) = sandbox
        .command("/bin/sh")
        .args([
            "-c",
            "printf 'SLAVE_B=%s\\n' \"$(tty)\"; read done; printf 'B_DONE=%s\\n' \"$done\"",
        ])
        .spawn_pty(100, 30)
        .await
        .expect("spawns PTY child B");

    let out_a = read_until(&master_a, "\n", TIMEOUT).await;
    let out_b = read_until(&master_b, "\n", TIMEOUT).await;
    let slave_a = out_a
        .lines()
        .find_map(|l| l.trim().strip_prefix("SLAVE_A="))
        .unwrap_or_else(|| panic!("missing SLAVE_A in {out_a:?}"))
        .to_owned();
    let slave_b = out_b
        .lines()
        .find_map(|l| l.trim().strip_prefix("SLAVE_B="))
        .unwrap_or_else(|| panic!("missing SLAVE_B in {out_b:?}"))
        .to_owned();
    assert_ne!(
        slave_a, slave_b,
        "concurrent PTYs must have distinct slave devices"
    );

    // 1. A sibling PTY command in the SAME sandbox must be DENIED opening
    //    child A's slave device (read, write, and rdwr) and the unrelated host PTY.
    for target in [&slave_a, host_pty.slave_path.to_str().unwrap()] {
        for mode in ["rdonly", "wronly", "rdwr"] {
            let (mut attacker, attacker_master) = sandbox
                .command(probe.to_str().unwrap())
                .args([mode, target])
                .spawn_pty(80, 24)
                .await
                .expect("spawns sibling PTY attacker");
            let attack_out = read_to_eof(&attacker_master, TIMEOUT).await;
            drop(attacker_master);
            let status = tokio::time::timeout(TIMEOUT, attacker.wait())
                .await
                .expect("waits in time")
                .expect("waits");
            assert!(
                !status.success() && attack_out.trim().starts_with("err:"),
                "sibling PTY must be DENIED {mode} on {target}: status={status:?} out={attack_out:?}"
            );
        }
    }

    // 2. A piped sibling command in the SAME sandbox must also be DENIED
    //    opening child A's slave device and the unrelated host PTY.
    for target in [&slave_a, host_pty.slave_path.to_str().unwrap()] {
        for mode in ["rdonly", "wronly", "rdwr"] {
            let output = sandbox
                .command(probe.to_str().unwrap())
                .args([mode, target])
                .output()
                .await
                .expect("runs piped attacker");
            assert!(
                !output.status.success() && stdout(&output).starts_with("err:"),
                "piped sibling must be DENIED {mode} on {target}: status={:?} out={:?}",
                output.status,
                stdout(&output)
            );
        }
    }

    // 3. A PTY child CAN open + ioctl its controlling terminal via `/dev/tty`
    //    and `/dev/fd/0`, and on Linux also its own slave path via `tty` (on
    //    macOS Seatbelt blocks all `/dev/ttysNNN` opens so extensions never
    //    leak across siblings in the shared `sandbox_t`).
    #[cfg(target_os = "linux")]
    let self_cmd = format!(
        "me=\"$(tty)\"; \"{p}\" rdwr /dev/tty && \"{p}\" rdwr /dev/fd/0 && \"{p}\" rdwr \"$me\"",
        p = probe.display()
    );
    #[cfg(target_os = "macos")]
    let self_cmd = format!(
        "\"{p}\" rdwr /dev/tty && \"{p}\" rdwr /dev/fd/0",
        p = probe.display()
    );
    let (mut own_child, own_master) = sandbox
        .command("/bin/sh")
        .args(["-c", &self_cmd])
        .spawn_pty(84, 26)
        .await
        .expect("spawns self-tty probe");
    let own_out = read_to_eof(&own_master, TIMEOUT).await;
    drop(own_master);
    #[cfg(target_os = "linux")]
    let expected_probes = 3;
    #[cfg(target_os = "macos")]
    let expected_probes = 2;
    let own_status = tokio::time::timeout(TIMEOUT, own_child.wait())
        .await
        .expect("waits in time")
        .unwrap();
    assert!(
        own_status.success() && own_out.matches("ok:84x26").count() == expected_probes,
        "PTY child must be able to open+ioctl its own controlling terminal ({expected_probes} probes): status={own_status:?} out={own_out:?}"
    );

    // 4. Both concurrent PTY commands still round-trip cleanly and exit.
    master_a.write_all(b"alpha\n").unwrap();
    master_b.write_all(b"beta\n").unwrap();
    let done_a = read_to_eof(&master_a, TIMEOUT).await;
    let done_b = read_to_eof(&master_b, TIMEOUT).await;
    drop((master_a, master_b));
    assert!(done_a.contains("A_DONE=alpha"), "got: {done_a:?}");
    assert!(done_b.contains("B_DONE=beta"), "got: {done_b:?}");
    assert!(
        tokio::time::timeout(TIMEOUT, child_a.wait())
            .await
            .expect("waits in time")
            .unwrap()
            .success()
    );
    assert!(
        tokio::time::timeout(TIMEOUT, child_b.wait())
            .await
            .expect("waits in time")
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn concurrent_pty_commands_isolate_slave_devices_from_siblings_and_host() {
    let dir = fixtures::tempdir();
    let probe = fixtures::compile(
        dir.path(),
        include_str!("fixtures/pty_probe.rs"),
        "pty-probe",
    );

    // Default confined sandbox.
    let default_sb =
        start(SandboxConfigBuilder::default().executable(fixtures::resolved(&probe))).await;
    assert_pty_isolation(&default_sb, &probe).await;

    // Brokered confined sandbox (`ReadDenylist` + `WriteDenylist`).
    let home = fixtures::host::home_with(&[".ssh/id_rsa"]);
    let brokered_sb = start(
        SandboxConfigBuilder::default()
            .filesystem_strict(false)
            .read_denylist(ReadDenylist::credentials().home(home.path()))
            .write_denylist(WriteDenylist::persistence().home(home.path()))
            .executable(fixtures::resolved(&probe)),
    )
    .await;
    assert_pty_isolation(&brokered_sb, &probe).await;
}

#[tokio::test]
async fn pty_child_can_be_signaled_by_sandbox_pid_and_killed() {
    let sandbox = start(SandboxConfigBuilder::default()).await;

    let (mut target, master) = sandbox
        .command("/bin/sh")
        .args([
            "-c",
            "trap 'printf \"caught-int\\n\"; exit 0' INT; \
             printf 'pid=%d\\n' $$; \
             while :; do sleep 0.05; done",
        ])
        .spawn_pty(80, 24)
        .await
        .expect("spawns PTY child");

    let sandbox_pid = target.sandbox_id();
    let out = read_until(&master, &format!("pid={sandbox_pid}"), TIMEOUT).await;
    assert!(
        out.contains(&format!("pid={sandbox_pid}")),
        "sandbox_id() must match $$ inside PTY child: expected {sandbox_pid}, got {out:?}"
    );

    let killer = sh(&sandbox, &format!("/bin/kill -INT {sandbox_pid}")).await;
    assert!(
        killer.status.success(),
        "sibling command must signal PTY child by sandbox PID {sandbox_pid}: {}",
        stderr(&killer)
    );

    let caught = read_to_eof(&master, TIMEOUT).await;
    drop(master);
    assert!(caught.contains("caught-int"), "got: {caught:?}");
    let status = tokio::time::timeout(TIMEOUT, target.wait())
        .await
        .expect("waits in time")
        .expect("waits");
    assert!(
        status.success(),
        "expected clean exit after SIGINT trap: {status:?}"
    );

    // Direct `child.kill()` also terminates a PTY child cleanly.
    let (mut sleeper, _sleeper_master) = sandbox
        .command("/bin/sh")
        .args(["-c", "sleep 60"])
        .spawn_pty(80, 24)
        .await
        .expect("spawns sleeping PTY child");
    sleeper.kill().expect("kills PTY child");
}

#[tokio::test]
async fn host_access_pty_spawn_works() {
    let dir = fixtures::tempdir();
    let probe = fixtures::compile(
        dir.path(),
        include_str!("fixtures/pty_probe.rs"),
        "pty-probe",
    );

    let sandbox = start(SandboxConfigBuilder::default().host_access()).await;

    let (mut child, mut master) = sandbox
        .command("/bin/sh")
        .args([
            "-c",
            &format!(
                "trap 'printf \"winch:%s\\n\" \"$(stty size)\"; exit 0' WINCH; \
                 \"{}\" rdwr /dev/tty; \
                 read line; \
                 printf 'echo:%s\\n' \"$line\"; \
                 while :; do sleep 0.05; done",
                probe.display()
            ),
        ])
        .spawn_pty(88, 25)
        .await
        .expect("spawns host-access PTY child");

    let tty_out = read_until(&master, "ok:88x25", TIMEOUT).await;
    assert!(tty_out.contains("ok:88x25"), "got: {tty_out:?}");

    master.write_all(b"host-ok\n").unwrap();
    let echo_out = read_until(&master, "echo:host-ok", TIMEOUT).await;
    assert!(echo_out.contains("echo:host-ok"), "got: {echo_out:?}");

    master.resize(120, 40).expect("resizes host-access PTY");
    let winch_out = read_to_eof(&master, TIMEOUT).await;
    drop(master);
    assert!(winch_out.contains("winch:40 120"), "got: {winch_out:?}");

    let status = tokio::time::timeout(TIMEOUT, child.wait())
        .await
        .expect("waits in time")
        .expect("waits");
    assert!(status.success(), "host-access PTY child failed: {status:?}");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn supervised_pty_spawn_works_and_isolates_on_linux() {
    use heel::supervisor::{Background, Foreground};

    let dir = fixtures::tempdir();
    let probe = fixtures::compile(
        dir.path(),
        include_str!("fixtures/pty_probe.rs"),
        "pty-probe",
    );
    let home = fixtures::host::home_with(&[".ssh/id_rsa"]);
    let reap = Duration::from_secs(10);

    // 1. Confined supervised sandbox with broker.
    let sandbox = start(
        SandboxConfigBuilder::default()
            .filesystem_strict(false)
            .read_denylist(ReadDenylist::credentials().home(home.path()))
            .write_denylist(WriteDenylist::persistence().home(home.path()))
            .executable(fixtures::resolved(&probe))
            .supervised_spawn(true),
    )
    .await;

    let (mut fg, master) = sandbox
        .command("/bin/sh")
        .args([
            "-c",
            &format!(
                "trap 'printf \"winch:%s\\n\" \"$(stty size)\"; exit 0' WINCH; \
                 printf 'SLAVE=%s PID=%d\\n' \"$(tty)\" $$; \
                 \"{}\" rdwr /dev/tty; \
                 setsid sleep 300 & \
                 while :; do sleep 0.05; done",
                probe.display()
            ),
        ])
        .spawn_supervised_pty(Foreground { reap_timeout: reap }, 80, 24)
        .await
        .expect("spawns confined supervised PTY");

    let banner = read_until(&master, "ok:80x24", TIMEOUT).await;
    assert!(banner.contains("ok:80x24"), "got: {banner:?}");
    let slave = banner
        .lines()
        .find_map(|l| {
            let rest = l.trim().strip_prefix("SLAVE=")?;
            rest.split_whitespace().next()
        })
        .unwrap_or_else(|| panic!("missing SLAVE in {banner:?}"))
        .to_owned();
    assert!(
        banner.contains(&format!("PID={}", fg.sandbox_id())),
        "sandbox_id() must match $$: expected {}, got {banner:?}",
        fg.sandbox_id()
    );

    // Sibling piped command cannot open the supervised PTY's slave device.
    let attack = sandbox
        .command(probe.to_str().unwrap())
        .args(["rdwr", &slave])
        .output()
        .await
        .expect("runs sibling probe");
    assert!(
        !attack.status.success() && stdout(&attack).starts_with("err:"),
        "sibling must be denied opening supervised PTY slave {slave}: {}",
        stdout(&attack)
    );

    master.resize(110, 35).expect("resizes supervised PTY");
    let resized = read_to_eof(&master, TIMEOUT).await;
    drop(master);
    assert!(resized.contains("winch:35 110"), "got: {resized:?}");

    let exit = tokio::time::timeout(TIMEOUT, fg.wait())
        .await
        .expect("waits in time")
        .expect("foreground supervised PTY exits");
    assert!(exit.status.success(), "got: {exit:?}");
    assert!(
        exit.report.killed.iter().any(|p| p.name == "sleep"),
        "foreground supervisor must reap leftover setsid sleep: {:?}",
        exit.report
    );

    // 2. Background supervised PTY with tree kill.
    let (mut bg, bg_master) = sandbox
        .command("/bin/sh")
        .args(["-c", "printf 'bg-ready\\n'; sleep 60"])
        .spawn_supervised_pty(Background { reap_timeout: reap }, 80, 24)
        .await
        .expect("spawns background supervised PTY");
    let ready = read_until(&bg_master, "bg-ready", TIMEOUT).await;
    assert!(ready.contains("bg-ready"), "got: {ready:?}");
    let report = bg.kill_tree().await.expect("kills background PTY tree");
    assert!(report.survivors.is_empty(), "got: {report:?}");
    let bg_status = tokio::time::timeout(TIMEOUT, bg.wait())
        .await
        .expect("waits in time")
        .expect("waits");
    assert!(!bg_status.success());

    // 3. Host-access supervised PTY (uses staged runner without external binary skew).
    let host_sb = start(
        SandboxConfigBuilder::default()
            .host_access()
            .supervised_spawn(true),
    )
    .await;
    let (mut host_fg, host_master) = host_sb
        .command("/bin/sh")
        .args([
            "-c",
            "trap 'printf \"host-winch:%s\\n\" \"$(stty size)\"; exit 0' WINCH; \
             printf 'host-init:%s\\n' \"$(stty size)\"; \
             while :; do sleep 0.05; done",
        ])
        .spawn_supervised_pty(Foreground { reap_timeout: reap }, 90, 28)
        .await
        .expect("spawns host-access supervised PTY");
    let host_init = read_until(&host_master, "host-init:28 90", TIMEOUT).await;
    assert!(host_init.contains("host-init:28 90"), "got: {host_init:?}");
    host_master.resize(100, 32).expect("resizes");
    let host_winch = read_to_eof(&host_master, TIMEOUT).await;
    drop(host_master);
    assert!(
        host_winch.contains("host-winch:32 100"),
        "got: {host_winch:?}"
    );
    let host_exit = tokio::time::timeout(TIMEOUT, host_fg.wait())
        .await
        .expect("waits in time")
        .expect("waits");
    assert!(host_exit.status.success());
}
