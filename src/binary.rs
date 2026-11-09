//! The `heel` binary that IPC shims and the supervisor execute.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// A `heel` binary known to be the library's own version.
///
/// The binary is the IPC client inside the sandbox and speaks the request
/// frame of its own release, so a stale one fails every IPC command. Both
/// constructors run the binary with `--version` and refuse a mismatch; holding
/// a `HeelBinary` is the proof that the check passed. Verify once and share the
/// value: a configuration that carries one does no lookup and no check when a
/// sandbox is created.
///
/// Both constructors spawn a process and block, so call them off an async
/// executor's threads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeelBinary(PathBuf);

impl HeelBinary {
    /// Verify the binary at `path`.
    ///
    /// Fails with [`Error::InitFailed`] naming both versions and the path when
    /// the binary's version differs from this library's, or when it cannot be
    /// run or does not print a version.
    pub fn verify(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(Error::InitFailed(format!(
                "the heel binary is missing: {}",
                path.display()
            )));
        }
        check_version(path)?;
        Ok(Self(path.to_path_buf()))
    }

    /// Find a binary and verify it: `HEEL_BIN`, then this process if it is
    /// itself `heel`, then `PATH`. Nothing is built.
    pub fn locate() -> Result<Self> {
        if let Some(path) = std::env::var_os("HEEL_BIN") {
            let path = PathBuf::from(path);
            if !path.is_file() {
                return Err(Error::InitFailed(format!(
                    "HEEL_BIN points to a missing file: {}",
                    path.display()
                )));
            }
            return Self::verify(path);
        }

        let binary_name = format!("heel{}", std::env::consts::EXE_SUFFIX);

        // A sandbox created by the CLI can reuse the running binary directly;
        // it is this build, so its version matches by construction.
        if let Ok(current) = std::env::current_exe()
            && current
                .file_name()
                .is_some_and(|name| name == binary_name.as_str())
        {
            return Ok(Self(current));
        }

        let found = search_path_for_binary(&binary_name).ok_or_else(|| {
            Error::InitFailed(format!(
                "cannot find the '{binary_name}' binary, which sandboxed IPC commands execute; \
                 install it with `cargo install heel` or point HEEL_BIN at it"
            ))
        })?;
        Self::verify(found)
    }

    /// The path of the binary.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for HeelBinary {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// Compare the version `path --version` prints (`heel <version>`) with this
/// library's.
fn check_version(path: &Path) -> Result<()> {
    let output = retry_busy(|| {
        std::process::Command::new(path)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .output()
    })
    .map_err(|error| {
        Error::InitFailed(format!(
            "cannot run `{} --version` to check the heel binary: {error}",
            path.display()
        ))
    })?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let binary = output
        .status
        .success()
        .then(|| stdout.lines().next()?.split_whitespace().last())
        .flatten()
        .ok_or_else(|| {
            Error::InitFailed(format!(
                "`{} --version` did not print a version; it is not a heel binary",
                path.display()
            ))
        })?;
    let library = env!("CARGO_PKG_VERSION");
    if binary != library {
        return Err(Error::InitFailed(format!(
            "the heel binary {} is version {binary}, but the library is version {library}; \
             install the matching version or point HEEL_BIN at it",
            path.display()
        )));
    }
    Ok(())
}

/// Waits between attempts to run a binary that is still busy.
const BUSY_BACKOFF: [std::time::Duration; 5] = [
    std::time::Duration::from_millis(10),
    std::time::Duration::from_millis(20),
    std::time::Duration::from_millis(40),
    std::time::Duration::from_millis(80),
    std::time::Duration::from_millis(160),
];

/// Runs `attempt`, which executes a binary its caller may have just written.
///
/// A child forked by another thread while the file was open for writing holds
/// the write descriptor until it execs, and executing the file meanwhile fails
/// with `ETXTBSY`. That failure is retried with a short bounded backoff; any
/// other result, or a file still busy afterwards, is returned unchanged.
fn retry_busy<T>(mut attempt: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    for delay in BUSY_BACKOFF {
        match attempt() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(delay);
            }
            result => return result,
        }
    }
    attempt()
}

/// Find an executable by name on `PATH`.
fn search_path_for_binary(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A script that prints `--version` like a heel binary of `version`.
    fn fake_heel(dir: &Path, version: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("heel");
        std::fs::write(&path, format!("#!/bin/sh\necho 'heel {version}'\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn a_binary_of_another_version_is_refused_naming_both() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_heel(dir.path(), "0.0.1");

        let Err(Error::InitFailed(message)) = HeelBinary::verify(&path) else {
            panic!("a mismatched binary must be refused");
        };
        assert!(message.contains("version 0.0.1"), "{message}");
        assert!(
            message.contains(&format!("version {}", env!("CARGO_PKG_VERSION"))),
            "{message}"
        );
        assert!(message.contains(&path.display().to_string()), "{message}");
    }

    #[test]
    fn a_binary_of_the_library_version_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_heel(dir.path(), env!("CARGO_PKG_VERSION"));

        assert_eq!(HeelBinary::verify(&path).unwrap().as_path(), path);
    }

    #[test]
    fn a_binary_that_prints_no_version_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("heel");
        std::fs::write(&path, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(matches!(
            HeelBinary::verify(&path),
            Err(Error::InitFailed(_))
        ));
    }

    fn busy() -> std::io::Error {
        std::io::Error::from(std::io::ErrorKind::ExecutableFileBusy)
    }

    #[test]
    fn a_busy_binary_is_run_again_once_it_is_free() {
        let mut attempts = 0;
        let result = retry_busy(|| {
            attempts += 1;
            if attempts < 3 {
                Err(busy())
            } else {
                Ok(attempts)
            }
        });

        assert_eq!(result.unwrap(), 3);
    }

    #[test]
    fn a_binary_still_busy_after_the_backoff_returns_the_error() {
        let mut attempts = 0;
        let result: std::io::Result<()> = retry_busy(|| {
            attempts += 1;
            Err(busy())
        });

        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::ExecutableFileBusy
        );
        assert_eq!(attempts, BUSY_BACKOFF.len() + 1);
    }

    #[test]
    fn any_other_failure_is_returned_at_once() {
        let mut attempts = 0;
        let result: std::io::Result<()> = retry_busy(|| {
            attempts += 1;
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        });

        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(attempts, 1);
    }

    #[test]
    fn a_missing_binary_is_refused() {
        let dir = tempfile::tempdir().unwrap();

        assert!(matches!(
            HeelBinary::verify(dir.path().join("heel")),
            Err(Error::InitFailed(_))
        ));
    }
}
