//! Per-command pseudo-terminal allocation, control, and master stream.

use std::fs::File;
use std::io::{self, Read, Write};

use crate::error::{Error, Result};

/// Host-side master end of a pseudo-terminal allocated for a spawned command.
///
/// Reading yields the terminal output produced by the child and its foreground
/// process group; writing delivers input bytes to the slave terminal. Calling
/// [`resize`](Self::resize) updates the kernel window size (`TIOCSWINSZ`) and
/// delivers `SIGWINCH` to the slave's foreground process group.
///
/// The master can be cloned ([`try_clone`](Self::try_clone) or
/// [`try_clone_file`](Self::try_clone_file)) so one task reads output, another
/// writes input, and a controller handle resizes the terminal concurrently. On
/// Unix it implements [`AsFd`](std::os::fd::AsFd) and
/// [`AsRawFd`](std::os::fd::AsRawFd) so async runtimes can register it directly.
#[derive(Debug)]
pub struct PtyMaster {
    #[cfg(unix)]
    file: File,
    #[cfg(not(unix))]
    _unconstructible: std::convert::Infallible,
}

impl PtyMaster {
    #[cfg(unix)]
    pub(crate) fn from_owned_fd(fd: std::os::fd::OwnedFd) -> Self {
        Self {
            file: File::from(fd),
        }
    }

    /// Update the pseudo-terminal window size (`TIOCSWINSZ`), delivering
    /// `SIGWINCH` to the child's foreground process group.
    ///
    /// # Errors
    ///
    /// Returns an error if the platform does not support PTYs or if the kernel
    /// rejects `TIOCSWINSZ`.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unix_pty::set_winsize(self.file.as_raw_fd(), cols, rows)
        }
        #[cfg(not(unix))]
        {
            let _ = (cols, rows);
            match self._unconstructible {}
        }
    }

    /// Query the current pseudo-terminal window size as `(cols, rows)`
    /// (`TIOCGWINSZ`).
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects `TIOCGWINSZ`.
    pub fn size(&self) -> Result<(u16, u16)> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unix_pty::get_winsize(self.file.as_raw_fd())
        }
        #[cfg(not(unix))]
        {
            match self._unconstructible {}
        }
    }

    /// Duplicate the underlying master descriptor into a new [`PtyMaster`].
    ///
    /// # Errors
    ///
    /// Returns an error if duplicating the descriptor fails.
    pub fn try_clone(&self) -> Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                file: self.file.try_clone()?,
            })
        }
        #[cfg(not(unix))]
        {
            match self._unconstructible {}
        }
    }

    /// Duplicate the underlying master descriptor as a [`File`] for streaming
    /// I/O on a reader or writer task while retaining `self` for [`resize`](Self::resize).
    ///
    /// # Errors
    ///
    /// Returns an error if duplicating the descriptor fails.
    pub fn try_clone_file(&self) -> Result<File> {
        #[cfg(unix)]
        {
            Ok(self.file.try_clone()?)
        }
        #[cfg(not(unix))]
        {
            match self._unconstructible {}
        }
    }

    /// Toggle `O_NONBLOCK` on the master file description.
    ///
    /// # Errors
    ///
    /// Returns an error if `fcntl` fails.
    #[cfg(unix)]
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        use std::os::fd::AsRawFd;
        unix_pty::set_nonblocking(self.file.as_raw_fd(), nonblocking)
    }
}

impl Read for PtyMaster {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            self.file.read(buf)
        }
        #[cfg(not(unix))]
        {
            let _ = buf;
            match self._unconstructible {}
        }
    }
}

impl Read for &PtyMaster {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            (&self.file).read(buf)
        }
        #[cfg(not(unix))]
        {
            let _ = buf;
            match self._unconstructible {}
        }
    }
}

impl Write for PtyMaster {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            self.file.write(buf)
        }
        #[cfg(not(unix))]
        {
            let _ = buf;
            match self._unconstructible {}
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.file.flush()
        }
        #[cfg(not(unix))]
        {
            match self._unconstructible {}
        }
    }
}

impl Write for &PtyMaster {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            (&self.file).write(buf)
        }
        #[cfg(not(unix))]
        {
            let _ = buf;
            match self._unconstructible {}
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        {
            (&self.file).flush()
        }
        #[cfg(not(unix))]
        {
            match self._unconstructible {}
        }
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for PtyMaster {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.file.as_fd()
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for PtyMaster {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }
}

#[cfg(unix)]
impl From<PtyMaster> for std::os::fd::OwnedFd {
    fn from(master: PtyMaster) -> Self {
        Self::from(master.file)
    }
}

#[cfg(unix)]
impl From<PtyMaster> for File {
    fn from(master: PtyMaster) -> Self {
        master.file
    }
}

#[cfg(unix)]
pub(crate) use unix_pty::{AllocatedPty, attach_slave_in_child};

#[cfg(unix)]
mod unix_pty {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    use super::{Error, PtyMaster, Result};

    /// Freshly allocated Unix PTY pair ready to attach to one spawned command.
    pub(crate) struct AllocatedPty {
        pub(crate) master: PtyMaster,
        pub(crate) slave: OwnedFd,
        #[cfg(target_os = "linux")]
        pub(crate) slave_inode: (u64, u64),
    }

    impl AllocatedPty {
        /// Allocate a PTY pair, configure initial `(cols, rows)` window size,
        /// and open the slave device with `O_NOCTTY | O_CLOEXEC`.
        pub(crate) fn open(cols: u16, rows: u16) -> Result<Self> {
            #[cfg(target_os = "linux")]
            let open_flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;
            #[cfg(not(target_os = "linux"))]
            let open_flags = libc::O_RDWR | libc::O_NOCTTY;

            // SAFETY: `posix_openpt` takes plain open flags and returns a new fd or -1.
            let master_raw = unsafe { libc::posix_openpt(open_flags) };
            if master_raw < 0 {
                return Err(Error::Pty(format!(
                    "posix_openpt failed: {}",
                    io::Error::last_os_error()
                )));
            }
            // SAFETY: `master_raw` is a newly created descriptor owned exclusively here.
            let master = unsafe { OwnedFd::from_raw_fd(master_raw) };

            #[cfg(not(target_os = "linux"))]
            // SAFETY: setting `FD_CLOEXEC` on our newly opened master fd.
            if unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
                return Err(Error::Pty(format!(
                    "fcntl(FD_CLOEXEC) on PTY master failed: {}",
                    io::Error::last_os_error()
                )));
            }

            // SAFETY: `master` is a valid PTY master fd.
            if unsafe { libc::grantpt(master.as_raw_fd()) } != 0 {
                return Err(Error::Pty(format!(
                    "grantpt failed: {}",
                    io::Error::last_os_error()
                )));
            }
            // SAFETY: `master` is a valid PTY master fd.
            if unsafe { libc::unlockpt(master.as_raw_fd()) } != 0 {
                return Err(Error::Pty(format!(
                    "unlockpt failed: {}",
                    io::Error::last_os_error()
                )));
            }

            #[cfg(target_os = "macos")]
            let slave = {
                use std::ffi::CStr;

                // `<sys/ttycom.h>` `TIOCPTYGNAME` (`_IOC(IOC_OUT, 't', 83, 128)`),
                // the thread-safe ioctl backing `ptsname_r` on Darwin.
                const TIOCPTYGNAME: libc::c_ulong = 0x4080_7453;
                let mut name_buf = [0u8; 128];
                // SAFETY: `name_buf` is a 128-byte writable buffer matching `TIOCPTYGNAME`.
                if unsafe { libc::ioctl(master.as_raw_fd(), TIOCPTYGNAME, name_buf.as_mut_ptr()) }
                    != 0
                {
                    return Err(Error::Pty(format!(
                        "TIOCPTYGNAME failed: {}",
                        io::Error::last_os_error()
                    )));
                }
                let c_name = CStr::from_bytes_until_nul(&name_buf).map_err(|_| {
                    Error::Pty("TIOCPTYGNAME returned an unterminated path".to_owned())
                })?;
                // SAFETY: `c_name` is a NUL-terminated slave device path; `O_NOCTTY`
                // prevents the host process from acquiring a controlling terminal.
                let slave_raw = unsafe {
                    libc::open(
                        c_name.as_ptr(),
                        libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
                    )
                };
                if slave_raw < 0 {
                    return Err(Error::Pty(format!(
                        "opening PTY slave {} failed: {}",
                        c_name.to_string_lossy(),
                        io::Error::last_os_error()
                    )));
                }
                // SAFETY: `slave_raw` is a newly opened descriptor owned here.
                unsafe { OwnedFd::from_raw_fd(slave_raw) }
            };

            #[cfg(target_os = "linux")]
            let (slave, slave_inode) = {
                // SAFETY: `TIOCGPTPEER` opens the slave peer directly from the master
                // fd without a `/dev/pts` path race, with `O_NOCTTY | O_CLOEXEC`.
                let slave_raw = unsafe {
                    libc::ioctl(
                        master.as_raw_fd(),
                        libc::TIOCGPTPEER,
                        libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
                    )
                };
                if slave_raw < 0 {
                    return Err(Error::Pty(format!(
                        "TIOCGPTPEER failed: {}",
                        io::Error::last_os_error()
                    )));
                }
                // SAFETY: `slave_raw` is a newly created descriptor owned here.
                let slave = unsafe { OwnedFd::from_raw_fd(slave_raw) };
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                // SAFETY: `slave` is open and `stat` is a valid destination.
                if unsafe { libc::fstat(slave.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                    return Err(Error::Pty(format!(
                        "fstat on PTY slave failed: {}",
                        io::Error::last_os_error()
                    )));
                }
                // SAFETY: `fstat` succeeded, initializing `stat`.
                let stat = unsafe { stat.assume_init() };
                (slave, (stat.st_dev, stat.st_ino))
            };

            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            let slave = {
                return Err(Error::UnsupportedPlatform);
            };

            // Darwin returns ENOTTY on `TIOCSWINSZ` until the slave peer has been opened.
            set_winsize(master.as_raw_fd(), cols, rows)?;

            Ok(Self {
                master: PtyMaster::from_owned_fd(master),
                slave,
                #[cfg(target_os = "linux")]
                slave_inode,
            })
        }
    }

    pub(super) fn set_winsize(fd: RawFd, cols: u16, rows: u16) -> Result<()> {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `fd` is an open PTY master and `ws` is an initialized `winsize`.
        if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &raw const ws) } != 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    pub(super) fn get_winsize(fd: RawFd) -> Result<(u16, u16)> {
        let mut ws = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `fd` is an open PTY master and `ws` is a valid writable `winsize`.
        if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &raw mut ws) } != 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        Ok((ws.ws_col, ws.ws_row))
    }

    pub(super) fn set_nonblocking(fd: RawFd, nonblocking: bool) -> Result<()> {
        // SAFETY: `fd` is an open descriptor owned by `PtyMaster`.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        let target = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        // SAFETY: `fd` is open and `target` updates only `O_NONBLOCK`.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, target) } == -1 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Attach `slave_fd` as the child's controlling terminal and standard
    /// streams inside a `pre_exec` hook.
    ///
    /// # Safety
    ///
    /// Must only be called in a forked child before `exec` (`pre_exec`) where
    /// `slave_fd` is an open PTY slave descriptor and the child is not already
    /// a process group leader.
    pub(crate) unsafe fn attach_slave_in_child(slave_fd: RawFd) -> io::Result<()> {
        // SAFETY: all calls below (`signal`, `setsid`, `ioctl`, `dup2`, `fcntl`,
        // `close`) are async-signal-safe and allocation-free.
        unsafe {
            for sig in [
                libc::SIGHUP,
                libc::SIGINT,
                libc::SIGQUIT,
                libc::SIGPIPE,
                libc::SIGTSTP,
                libc::SIGTTIN,
                libc::SIGTTOU,
            ] {
                libc::signal(sig, libc::SIG_DFL);
            }
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0 as libc::c_int) == -1 {
                return Err(io::Error::last_os_error());
            }
            for target in 0..=2 {
                if slave_fd == target {
                    if libc::fcntl(target, libc::F_SETFD, 0) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                } else if libc::dup2(slave_fd, target) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            if slave_fd > 2 {
                let _ = libc::close(slave_fd);
            }
        }
        Ok(())
    }
}
