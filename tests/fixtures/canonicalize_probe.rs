//! Take apart `std::fs::canonicalize` from inside the sandbox, one Win32 call
//! at a time, reporting each call's own error code so a denial names the step
//! that met it.
//!
//! Usage: `canonicalize-probe report <label> <path> [<label> <path>...]` runs
//! the whole sequence for every labelled path, and
//! `canonicalize-probe mountmgr-write` asks the mount manager device for the
//! access its mount-point-changing requests need.
//!
//! Every line is `step=<name> path=<label> ok`, `step=<name> path=<label>
//! err=<code>` or `step=<name> path=<label> skipped`; a successful step may
//! append ` value=<text>`. The program always exits 0, so the harness reads the
//! report rather than a status. It uses only `std` and the Win32 calls it
//! declares below, because fixtures are compiled with a bare `rustc`.

use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

type Handle = *mut c_void;

/// `INVALID_HANDLE_VALUE`, the `-1` handle `CreateFileW` returns on failure.
const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` (winnt.h), the share
/// mode `std::fs::canonicalize` opens with.
const SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;

/// `OPEN_EXISTING` (fileapi.h).
const OPEN_EXISTING: u32 = 3;

/// `FILE_FLAG_BACKUP_SEMANTICS` (winbase.h): lets `CreateFileW` open a
/// directory, which `std::fs::canonicalize` needs.
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// `SYNCHRONIZE` standard access right (winnt.h).
const SYNCHRONIZE: u32 = 0x0010_0000;

/// `FILE_READ_ATTRIBUTES` (winnt.h).
const FILE_READ_ATTRIBUTES: u32 = 0x80;

/// `FILE_READ_DATA` (winnt.h): the read half of the access the mount manager's
/// `IOCTL_MOUNTMGR_CREATE_POINT` and `IOCTL_MOUNTMGR_DELETE_POINTS` need.
const FILE_READ_DATA: u32 = 0x1;

/// `FILE_WRITE_DATA` (winnt.h): the write half of that access.
const FILE_WRITE_DATA: u32 = 0x2;

/// `GetFinalPathNameByHandleW` flag: the drive-letter (or UNC) spelling,
/// `VOLUME_NAME_DOS` (fileapi.h). The one `std::fs::canonicalize` asks for.
const VOLUME_NAME_DOS: u32 = 0x0;

/// `GetFinalPathNameByHandleW` flag: the volume GUID spelling,
/// `VOLUME_NAME_GUID` (fileapi.h).
const VOLUME_NAME_GUID: u32 = 0x1;

/// `GetFinalPathNameByHandleW` flag: the NT device spelling,
/// `VOLUME_NAME_NT` (fileapi.h).
const VOLUME_NAME_NT: u32 = 0x2;

/// The mount manager's DOS device name, `MOUNTMGR_DOS_DEVICE_NAME` (mountmgr.h).
const MOUNT_MANAGER: &str = r"\\.\MountPointManager";

/// Room for a path in UTF-16 units; the long-path limit, so no probed path
/// outgrows it.
const BUFFER: usize = 32_768;

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *mut c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: Handle,
    ) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetFinalPathNameByHandleW(handle: Handle, path: *mut u16, length: u32, flags: u32) -> u32;
    fn GetShortPathNameW(path: *const u16, buffer: *mut u16, length: u32) -> u32;
    fn GetLongPathNameW(path: *const u16, buffer: *mut u16, length: u32) -> u32;
}

/// A handle closed on drop.
struct Owned(Handle);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by `CreateFileW` and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(Some(0)).collect()
}

fn last_error() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// Print one step's outcome.
fn say(step: &str, label: &str, outcome: Result<Option<String>, i32>) {
    match outcome {
        Ok(None) => println!("step={step} path={label} ok"),
        Ok(Some(value)) => println!("step={step} path={label} ok value={value}"),
        Err(code) => println!("step={step} path={label} err={code}"),
    }
}

/// Open `path` as `std::fs::canonicalize` does, or any other way `access` asks.
fn open(path: &str, access: u32, flags: u32) -> Result<Owned, i32> {
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            SHARE_ALL,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(last_error())
    } else {
        Ok(Owned(handle))
    }
}

/// The text a path-returning call wrote into `buffer`, or its error.
///
/// These calls return the length written, 0 on failure, and the length needed
/// when the buffer is too small; nothing here probes a path that long.
fn text(length: u32, buffer: &[u16]) -> Result<Option<String>, i32> {
    if length == 0 {
        Err(last_error())
    } else {
        assert!((length as usize) < buffer.len(), "the buffer is too small");
        let text = std::ffi::OsString::from_wide(&buffer[..length as usize]);
        Ok(Some(text.to_string_lossy().into_owned()))
    }
}

fn final_path(handle: &Owned, flags: u32) -> Result<Option<String>, i32> {
    let mut buffer = vec![0u16; BUFFER];
    // SAFETY: `buffer` holds `BUFFER` units and the handle is open.
    let length =
        unsafe { GetFinalPathNameByHandleW(handle.0, buffer.as_mut_ptr(), BUFFER as u32, flags) };
    text(length, &buffer)
}

fn short_path(path: &str) -> Result<Option<String>, i32> {
    let name = wide(path);
    let mut buffer = vec![0u16; BUFFER];
    // SAFETY: `name` is NUL-terminated and `buffer` holds `BUFFER` units.
    let length = unsafe { GetShortPathNameW(name.as_ptr(), buffer.as_mut_ptr(), BUFFER as u32) };
    text(length, &buffer)
}

fn long_path(path: &str) -> Result<Option<String>, i32> {
    let name = wide(path);
    let mut buffer = vec![0u16; BUFFER];
    // SAFETY: `name` is NUL-terminated and `buffer` holds `BUFFER` units.
    let length = unsafe { GetLongPathNameW(name.as_ptr(), buffer.as_mut_ptr(), BUFFER as u32) };
    text(length, &buffer)
}

/// Every step of `std::fs::canonicalize` on `path`, each reported alone.
fn report(label: &str, path: &str) {
    // Step 1: the open `std::fs::canonicalize` performs.
    let opened = open(path, 0, FILE_FLAG_BACKUP_SEMANTICS);
    match &opened {
        Ok(_) => say("open", label, Ok(None)),
        Err(code) => say("open", label, Err(*code)),
    }

    // Step 2: the path query on that handle, in each volume-name form.
    for (name, flags) in [
        ("final_nt", VOLUME_NAME_NT),
        ("final_guid", VOLUME_NAME_GUID),
        ("final_dos", VOLUME_NAME_DOS),
    ] {
        match &opened {
            Ok(handle) => say(name, label, final_path(handle, flags)),
            Err(_) => println!("step={name} path={label} skipped"),
        }
    }
    drop(opened);

    // Step 4: the 8.3 and long spellings, which ask the filesystem rather than
    // the mount manager.
    say("short_path", label, short_path(path));
    say("long_path", label, long_path(path));

    // Step 5: the call itself.
    say(
        "canonicalize",
        label,
        std::fs::canonicalize(path)
            .map(|resolved| Some(resolved.display().to_string()))
            .map_err(|error| error.raw_os_error().unwrap_or(-1)),
    );
}

/// Step 3: open the mount manager device directly.
fn mount_manager() {
    say(
        "mountmgr_synchronize",
        "none",
        open(MOUNT_MANAGER, SYNCHRONIZE, 0).map(|_| None),
    );
    say(
        "mountmgr_read_attributes_synchronize",
        "none",
        open(MOUNT_MANAGER, FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0).map(|_| None),
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("report") => {
            let paths = &args[1..];
            assert!(
                paths.len() % 2 == 0,
                "usage: report <label> <path> [<label> <path>...]"
            );
            mount_manager();
            for pair in paths.chunks(2) {
                report(&pair[0], &pair[1]);
            }
        }
        Some("mountmgr-write") => say(
            "mountmgr_read_write_data",
            "none",
            open(MOUNT_MANAGER, FILE_READ_DATA | FILE_WRITE_DATA, 0).map(|_| None),
        ),
        other => {
            eprintln!("unknown operation {other:?}");
            std::process::exit(64);
        }
    }
}
