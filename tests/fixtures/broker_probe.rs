//! A probe that makes one system call and says what the kernel answered.
//!
//! It prints `ok` or `errno <number>` and always exits 0, so the harness reads
//! the answer rather than a status. It uses only `std` and the C library.

use std::ffi::CString;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

extern "C" {
    fn creat(path: *const std::ffi::c_char, mode: u32) -> i32;
    fn mknod(path: *const std::ffi::c_char, mode: u32, dev: u64) -> i32;
    fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
    fn renameat2(old_fd: i32, old: *const std::ffi::c_char, new_fd: i32, new: *const std::ffi::c_char, flags: u32) -> i32;
    fn linkat(old_fd: i32, old: *const std::ffi::c_char, new_fd: i32, new: *const std::ffi::c_char, flags: i32) -> i32;
    fn truncate(path: *const std::ffi::c_char, length: i64) -> i32;
    fn setxattr(path: *const std::ffi::c_char, name: *const std::ffi::c_char, value: *const u8, size: usize, flags: i32)
        -> i32;
    fn utimes(path: *const std::ffi::c_char, times: *const [i64; 4]) -> i32;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn prctl(option: i32, a: u64, b: u64, c: u64, d: u64) -> i32;
    fn syscall(number: i64, ...) -> i64;
    fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    fn openat(dirfd: i32, path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn chdir(path: *const std::ffi::c_char) -> i32;
    fn chown(path: *const std::ffi::c_char, owner: u32, group: u32) -> i32;
    fn umask(mask: u32) -> u32;
    fn setitimer(which: i32, new: *const [i64; 4], old: *mut [i64; 4]) -> i32;
    fn signal(signal: i32, handler: usize) -> usize;
}

extern "C" fn on_alarm(_: i32) {}

const AT_FDCWD: i32 = -100;
// `__O_TMPFILE | O_DIRECTORY`; arm64 numbers `O_DIRECTORY` differently.
#[cfg(target_arch = "x86_64")]
const O_TMPFILE: i32 = 0o20_200_000;
#[cfg(target_arch = "aarch64")]
const O_TMPFILE: i32 = 0o20_040_000;
// `O_DIRECTORY`; arm64 numbers it differently, like `__O_TMPFILE`'s companion.
#[cfg(target_arch = "x86_64")]
const O_DIRECTORY: i32 = 0o200_000;
#[cfg(target_arch = "aarch64")]
const O_DIRECTORY: i32 = 0o40_000;
const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_RDWR: i32 = 2;
const AT_SYMLINK_FOLLOW: i32 = 0x400;
const AT_EMPTY_PATH: i32 = 0x1000;
const RENAME_EXCHANGE: u32 = 2;
const TIOCSTI: u64 = 0x5412;
const TIOCLINUX: u64 = 0x541C;
const PR_SET_DUMPABLE: i32 = 4;

#[cfg(target_arch = "x86_64")]
const SYS_SECCOMP: i64 = 317;
#[cfg(target_arch = "aarch64")]
const SYS_SECCOMP: i64 = 277;
const SYS_OPENAT2: i64 = 437;
#[cfg(target_arch = "x86_64")]
const SYS_CREAT: i64 = 85;
#[cfg(target_arch = "x86_64")]
const SYS_OPENAT: i64 = 257;
#[cfg(target_arch = "aarch64")]
const SYS_OPENAT: i64 = 56;
const EACCES: i32 = 13;
const ETIMEDOUT: i32 = 110;

fn c(path: &str) -> CString {
    CString::new(path).expect("no NUL in an argument")
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn report(result: std::io::Result<()>) {
    match result {
        Ok(()) => println!("ok"),
        Err(error) => println!("errno {}", error.raw_os_error().unwrap_or(-1)),
    }
}

fn check(result: i64) -> std::io::Result<()> {
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Create `path` over and over through a symbolic link that another thread
/// keeps pointing somewhere else.
fn race_symlink(link: &str, other: &str, good: &str, iterations: u64) {
    let (link_path, other_path, good_path) = (link.to_owned(), other.to_owned(), good.to_owned());
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flipper_stop = stop.clone();
    let flipper = std::thread::spawn(move || {
        let temp = format!("{link_path}.tmp");
        let mut toggle = false;
        while !flipper_stop.load(std::sync::atomic::Ordering::Relaxed) {
            let target = if toggle { &other_path } else { &good_path };
            let _ = std::fs::remove_file(&temp);
            if std::os::unix::fs::symlink(target, &temp).is_ok() {
                let _ = std::fs::rename(&temp, &link_path);
            }
            toggle = !toggle;
        }
    });
    for _ in 0..iterations {
        let file = format!("{link}/.zshrc");
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file);
        let _ = std::fs::remove_file(&file);
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    flipper.join().expect("flipper thread");
    println!("ok");
}

/// Call `open` on a buffer that another thread keeps rewriting between a good
/// and a bad path of the same length.
fn race_buffer(good: &str, bad: &str, iterations: u64) {
    assert_eq!(good.len(), bad.len(), "the paths must be the same length");
    struct Shared(*mut u8);
    // SAFETY: the pointer is only used to race on purpose with the call below.
    unsafe impl Send for Shared {}
    let mut buffer = c(good).into_bytes_with_nul();
    let shared = Shared(buffer.as_mut_ptr());
    let (good_bytes, bad_bytes) = (good.as_bytes().to_vec(), bad.as_bytes().to_vec());
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flipper_stop = stop.clone();
    let flipper = std::thread::spawn(move || {
        let shared = shared;
        let mut toggle = false;
        while !flipper_stop.load(std::sync::atomic::Ordering::Relaxed) {
            let source = if toggle { &bad_bytes } else { &good_bytes };
            for (offset, byte) in source.iter().enumerate() {
                // SAFETY: `offset` is inside the buffer, which outlives the thread.
                unsafe { shared.0.add(offset).write_volatile(*byte) };
            }
            toggle = !toggle;
        }
    });
    for _ in 0..iterations {
        // SAFETY: the buffer is NUL-terminated and lives for the whole loop.
        let fd = unsafe { open(buffer.as_ptr().cast(), 0o1 | 0o100 | 0o200, 0o600) };
        if fd >= 0 {
            // SAFETY: `fd` was just opened here.
            drop(unsafe { std::fs::File::from_raw_fd(fd) });
            let _ = std::fs::remove_file(Path::new(std::ffi::OsStr::from_bytes(
                &buffer[..buffer.len() - 1],
            )));
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    flipper.join().expect("flipper thread");
    println!("ok");
}

fn octal(text: &str) -> i32 {
    i32::from_str_radix(text, 8).expect("octal flags")
}

/// Open and close every path read-write, `iterations` times over. Stops at the
/// first failure and says its errno.
fn open_loop(iterations: u64, paths: &[String]) -> std::io::Result<()> {
    for _ in 0..iterations {
        for path in paths {
            let fd = unsafe { open(c(path).as_ptr(), O_RDWR) };
            check(i64::from(fd))?;
            unsafe { close(fd) };
        }
    }
    Ok(())
}

/// Read `path`, which the broker refuses, `count` times over. Stops at the first
/// answer that is not `EACCES`.
fn refuse_loop(count: u64, path: &str) -> std::io::Result<()> {
    for _ in 0..count {
        let fd = unsafe { open(c(path).as_ptr(), O_RDONLY) };
        if fd >= 0 {
            unsafe { close(fd) };
            return Err(std::io::Error::other("the open was not refused"));
        }
        if errno() != EACCES {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Start `writers` threads that each open `fifo` for writing, which blocks until
/// something reads it.
fn block_writers(fifo: &str, writers: usize) -> Vec<std::thread::JoinHandle<bool>> {
    (0..writers)
        .map(|_| {
            let fifo = fifo.to_owned();
            std::thread::spawn(move || {
                let fd = unsafe { open(c(&fifo).as_ptr(), O_WRONLY) };
                if fd >= 0 {
                    unsafe { close(fd) };
                }
                fd >= 0
            })
        })
        .collect()
}

/// Wait until `count` threads of this process are inside an `openat` that has
/// not returned. A write open of a FIFO nobody reads cannot return, so those
/// threads are waiting for the broker's answer, each holding a worker that is
/// blocked in the open (or a notification not yet taken, when none is left).
fn wait_until_blocked(count: usize) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let mut blocked = 0;
        for task in std::fs::read_dir("/proc/self/task")?.flatten() {
            let Ok(state) = std::fs::read_to_string(task.path().join("syscall")) else {
                continue;
            };
            if state.split_whitespace().next() == Some(&SYS_OPENAT.to_string()) {
                blocked += 1;
            }
        }
        if blocked >= count {
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            return Err(std::io::Error::from_raw_os_error(ETIMEDOUT));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Block `writers` threads in a write open of a FIFO nobody reads yet, which
/// ties up that many of the broker's workers, then do `open_loop` meanwhile and
/// finally read the FIFO to let the writers through.
fn fifo_then_open(fifo: &str, writers: usize, iterations: u64, paths: &[String]) {
    let handles = block_writers(fifo, writers);
    if let Err(error) = wait_until_blocked(writers) {
        // The writers stay blocked, and end with the process.
        println!("errno {}", error.raw_os_error().unwrap_or(-1));
        return;
    }
    let looped = open_loop(iterations, paths);
    let reader = unsafe { open(c(fifo).as_ptr(), O_RDONLY) };
    let released = handles
        .into_iter()
        .map(|handle| handle.join().expect("writer thread"))
        .all(|opened| opened);
    if reader >= 0 {
        unsafe { close(reader) };
    }
    if !released || reader < 0 {
        println!("errno {}", errno());
    } else {
        report(looped);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let operation = args.get(1).map_or("", String::as_str);
    let arg = |index: usize| args.get(index).map_or("", String::as_str);
    match operation {
        "create" => report(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(arg(2))
                .map(drop),
        ),
        "creat" => {
            let fd = unsafe { creat(c(arg(2)).as_ptr(), 0o600) };
            report(check(i64::from(fd)));
        }
        "openat2" => {
            let how = OpenHow {
                flags: (0o1 | 0o100) as u64,
                mode: 0o600,
                resolve: 0,
            };
            let fd = unsafe {
                syscall(
                    SYS_OPENAT2,
                    AT_FDCWD,
                    c(arg(2)).as_ptr(),
                    &how,
                    std::mem::size_of::<OpenHow>(),
                )
            };
            report(check(fd));
        }
        "write" => report(
            std::fs::OpenOptions::new()
                .append(true)
                .open(arg(2))
                .and_then(|mut file| file.write_all(b"x")),
        ),
        "read" => report(std::fs::read(arg(2)).map(drop)),
        "read-write" => report(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(arg(2))
                .map(drop),
        ),
        "truncate" => report(check(i64::from(unsafe { truncate(c(arg(2)).as_ptr(), 0) }))),
        // #217: opens the broker performs, whatever the flags the caller chose.
        "open" => report(check(i64::from(unsafe {
            open(c(arg(2)).as_ptr(), octal(arg(3)), 0o600)
        }))),
        "open-dir" => report(check(i64::from(unsafe {
            open(c(arg(2)).as_ptr(), O_RDONLY | O_DIRECTORY)
        }))),
        "openat2-open" => {
            let how = OpenHow {
                flags: octal(arg(3)) as u64,
                mode: 0o600,
                resolve: 0,
            };
            let fd = unsafe {
                syscall(
                    SYS_OPENAT2,
                    AT_FDCWD,
                    c(arg(2)).as_ptr(),
                    &how,
                    std::mem::size_of::<OpenHow>(),
                )
            };
            report(check(fd));
        }
        #[cfg(target_arch = "x86_64")]
        "creat-raw" => report(check(unsafe { syscall(SYS_CREAT, c(arg(2)).as_ptr(), 0o600) })),
        "chdir-open" => {
            let moved = unsafe { chdir(c(arg(2)).as_ptr()) };
            report(check(i64::from(moved)).and_then(|()| {
                check(i64::from(unsafe {
                    open(c(arg(3)).as_ptr(), octal(arg(4)), 0o600)
                }))
            }));
        }
        "openat-dir" => {
            let directory = unsafe { open(c(arg(2)).as_ptr(), O_RDONLY | O_DIRECTORY) };
            report(check(i64::from(directory)).and_then(|()| {
                check(i64::from(unsafe {
                    openat(directory, c(arg(3)).as_ptr(), octal(arg(4)), 0o600)
                }))
            }));
        }
        "proc-fd-open" => {
            let held = unsafe { open(c(arg(2)).as_ptr(), O_RDONLY) };
            report(check(i64::from(held)).and_then(|()| {
                check(i64::from(unsafe {
                    open(c(&format!("/proc/self/fd/{held}")).as_ptr(), octal(arg(3)), 0o600)
                }))
            }));
        }
        "linkat-empty" => {
            let result = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(O_TMPFILE)
                .mode(0o600)
                .open(arg(2))
                .and_then(|file| {
                    check(i64::from(unsafe {
                        linkat(
                            file.as_raw_fd(),
                            c("").as_ptr(),
                            AT_FDCWD,
                            c(arg(3)).as_ptr(),
                            AT_EMPTY_PATH,
                        )
                    }))
                });
            report(result);
        }
        "chown" => report(check(i64::from(unsafe {
            chown(
                c(arg(2)).as_ptr(),
                arg(3).parse().expect("a user id"),
                arg(4).parse().expect("a group id"),
            )
        }))),
        "open-loop" => report(open_loop(arg(2).parse().expect("a count"), &args[3..])),
        "fifo-open" => fifo_then_open(
            arg(2),
            arg(3).parse().expect("a count"),
            arg(4).parse().expect("a count"),
            &args[5..],
        ),
        "refuse-loop" => report(refuse_loop(arg(2).parse().expect("a count"), arg(3))),
        // Holds `writers` threads in a blocked open, and stays until it is killed.
        "fifo-hold" => {
            let _writers = block_writers(arg(2), arg(3).parse().expect("a count"));
            match wait_until_blocked(arg(3).parse().expect("a count")) {
                Ok(()) => loop {
                    std::thread::sleep(std::time::Duration::from_secs(60));
                },
                Err(error) => println!("errno {}", error.raw_os_error().unwrap_or(-1)),
            }
        }
        "open-forever" => loop {
            if let Err(error) = open_loop(1, &args[2..]) {
                println!("errno {}", error.raw_os_error().unwrap_or(-1));
                break;
            }
        },
        "mkdir" => report(std::fs::create_dir(arg(2))),
        "mknod-file" => report(check(i64::from(unsafe {
            mknod(c(arg(2)).as_ptr(), 0o100_600, 0)
        }))),
        "mknod-fifo" => report(check(i64::from(unsafe { mkfifo(c(arg(2)).as_ptr(), 0o600) }))),
        "symlink" => report(std::os::unix::fs::symlink(arg(2), arg(3))),
        "link" => report(std::fs::hard_link(arg(2), arg(3))),
        "rename" => report(std::fs::rename(arg(2), arg(3))),
        "exchange" => report(check(i64::from(unsafe {
            renameat2(
                AT_FDCWD,
                c(arg(2)).as_ptr(),
                AT_FDCWD,
                c(arg(3)).as_ptr(),
                RENAME_EXCHANGE,
            )
        }))),
        "bind" => report(UnixListener::bind(arg(2)).map(drop)),
        "tmpfile" => {
            let result = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(O_TMPFILE)
                .mode(0o600)
                .open(arg(2))
                .and_then(|file| {
                    let source = c(&format!("/proc/self/fd/{}", file.as_raw_fd()));
                    check(i64::from(unsafe {
                        linkat(
                            AT_FDCWD,
                            source.as_ptr(),
                            AT_FDCWD,
                            c(arg(3)).as_ptr(),
                            AT_SYMLINK_FOLLOW,
                        )
                    }))
                });
            report(result);
        }
        "chmod" => report(std::fs::set_permissions(
            arg(2),
            std::fs::Permissions::from_mode(0o777),
        )),
        "setxattr" => report(check(i64::from(unsafe {
            setxattr(c(arg(2)).as_ptr(), c("user.heel").as_ptr(), b"x".as_ptr(), 1, 0)
        }))),
        "utimes" => {
            let times = [1i64, 0, 1, 0];
            report(check(i64::from(unsafe { utimes(c(arg(2)).as_ptr(), &times) })));
        }
        "unlink" => report(std::fs::remove_file(arg(2))),
        "umask-create" => {
            let mask = u32::from_str_radix(arg(3), 8).expect("octal mask");
            unsafe { umask(mask) };
            let result = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o666)
                .open(arg(2));
            match result {
                Ok(_) => println!(
                    "mode {:o}",
                    std::fs::metadata(arg(2)).expect("created").permissions().mode() & 0o7777
                ),
                Err(error) => println!("errno {}", error.raw_os_error().unwrap_or(-1)),
            }
        }
        "cloexec" => {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(arg(2));
            match file {
                Ok(file) => {
                    // `std` opens with `O_CLOEXEC`; the descriptor must keep it.
                    let flags = unsafe { fcntl_getfd(file.as_raw_fd()) };
                    println!("cloexec {}", flags & 1);
                }
                Err(error) => println!("errno {}", error.raw_os_error().unwrap_or(-1)),
            }
        }
        "connect" => report(
            std::net::TcpStream::connect_timeout(
                &arg(2).parse().expect("an address"),
                std::time::Duration::from_secs(3),
            )
            .map(drop),
        ),
        "bind-tcp" => report(std::net::TcpListener::bind(arg(2)).map(drop)),
        "connect-unix" => report(UnixStream::connect(arg(2)).map(drop)),
        "connect-abstract" => {
            use std::os::linux::net::SocketAddrExt;
            let address = std::os::unix::net::SocketAddr::from_abstract_name(arg(2))
                .expect("an abstract name");
            report(UnixStream::connect_addr(&address).map(drop));
        }
        "tiocsti" | "tioclinux" => {
            let request = if operation == "tiocsti" { TIOCSTI } else { TIOCLINUX };
            let byte = 0u8;
            let result = unsafe { ioctl(0, request, &byte as *const u8) };
            if result < 0 {
                println!("errno {}", errno());
            } else {
                println!("ok");
            }
        }
        "dumpable" => report(check(i64::from(unsafe {
            prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        }))),
        "nested-filter" => {
            // A filter that allows everything, asking for a listener.
            let program = [SockFilter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x7fff_0000,
            }];
            let fprog = SockFprog {
                len: 1,
                filter: program.as_ptr(),
            };
            let result = unsafe { syscall(SYS_SECCOMP, 1, 1u64 << 3, &fprog) };
            if result < 0 {
                println!("errno {}", errno());
            } else {
                println!("ok");
            }
        }
        #[cfg(target_arch = "x86_64")]
        "x32" => {
            // getpid through its x32 number.
            let number: i64 = 39 | 0x4000_0000;
            let result: i64;
            unsafe {
                std::arch::asm!(
                    "syscall",
                    inlateout("rax") number => result,
                    lateout("rcx") _,
                    lateout("r11") _,
                    options(nostack)
                );
            }
            if result < 0 {
                println!("errno {}", -result);
            } else {
                println!("ok");
            }
        }
        "race-symlink" => race_symlink(arg(2), arg(3), arg(4), arg(5).parse().expect("a count")),
        "race-buffer" => race_buffer(arg(2), arg(3), arg(4).parse().expect("a count")),
        "create-many" | "storm" => {
            if operation == "storm" {
                // A timer signal every 100 microseconds, to interrupt the calls.
                unsafe {
                    signal(14, on_alarm as *const () as usize);
                    let timer = [0i64, 100, 0, 100];
                    setitimer(0, &timer, std::ptr::null_mut());
                }
            }
            let directory = arg(2);
            let count: u64 = arg(3).parse().expect("a count");
            let mut failed = 0u64;
            let mut errors = std::collections::BTreeMap::new();
            for index in 0..count {
                let path = format!("{directory}/f{index}");
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(_) => {}
                    Err(error) => {
                        failed += 1;
                        *errors.entry(error.raw_os_error().unwrap_or(-1)).or_insert(0u64) += 1;
                    }
                }
            }
            println!("failed {failed} {errors:?}");
        }
        other => {
            eprintln!("unknown operation {other}");
            std::process::exit(64);
        }
    }
}

extern "C" {
    #[link_name = "fcntl"]
    fn fcntl_raw(fd: i32, command: i32, ...) -> i32;
}

unsafe fn fcntl_getfd(fd: i32) -> i32 {
    fcntl_raw(fd, 1)
}
