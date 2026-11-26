//! Minimal zero-dependency TTY probe compiled by `tests/pty.rs`.
//!
//! Usage:
//! - `pty-probe open <rdonly|wronly|rdwr> <path>`: opens `<path>` with
//!   `O_NOCTTY`, runs `TIOCGWINSZ` if opened, prints `ok:<cols>x<rows>` or
//!   `err:<errno>` and exits 0 on open success or 1 on open failure.

use std::ffi::{CString, c_char, c_int, c_ulong, c_ushort, c_void};

const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_RDWR: c_int = 2;

#[cfg(target_os = "macos")]
const O_NOCTTY: c_int = 0x20000;
#[cfg(target_os = "linux")]
const O_NOCTTY: c_int = 0x100;

#[cfg(target_os = "macos")]
const TIOCGWINSZ: c_ulong = 0x4008_7468;
#[cfg(target_os = "linux")]
const TIOCGWINSZ: c_ulong = 0x5413;

#[repr(C)]
struct Winsize {
    ws_row: c_ushort,
    ws_col: c_ushort,
    ws_xpixel: c_ushort,
    ws_ypixel: c_ushort,
}

unsafe extern "C" {
    fn open(path: *const c_char, oflag: c_int, ...) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn tcdrain(fd: c_int) -> c_int;
}

fn drain_stdout_tty() {
    // Wait for the PTY master to read our output before a session-leader exit
    // can trigger Darwin's controlling-terminal revoke/flush. No-op on pipes.
    // SAFETY: `tcdrain(1)` only operates on stdout and returns ENOTTY on pipes.
    unsafe {
        let _ = tcdrain(1);
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().expect("mode");
    let path = args.next().expect("path");
    let flags = match mode.as_str() {
        "rdonly" => O_RDONLY | O_NOCTTY,
        "wronly" => O_WRONLY | O_NOCTTY,
        "rdwr" => O_RDWR | O_NOCTTY,
        other => panic!("unknown mode {other}"),
    };
    let c_path = CString::new(path).expect("path without NUL");
    // SAFETY: `c_path` is a valid NUL-terminated C string.
    let fd = unsafe { open(c_path.as_ptr(), flags) };
    if fd < 0 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(-1);
        println!("err:{errno}");
        drain_stdout_tty();
        std::process::exit(1);
    }
    let mut ws = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `fd` is open and `ws` is a valid writable `Winsize`.
    let rc = unsafe { ioctl(fd, TIOCGWINSZ, (&raw mut ws).cast::<c_void>()) };
    let ioctl_errno = if rc == 0 {
        0
    } else {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(-1)
    };
    // SAFETY: closing the descriptor opened above.
    unsafe { close(fd) };
    if rc == 0 {
        println!("ok:{}x{}", ws.ws_col, ws.ws_row);
    } else {
        println!("open_ok:ioctl_err:{ioctl_errno}");
    }
    drain_stdout_tty();
}
