//! Where a sandbox's IPC files live, by name.

use std::path::PathBuf;

/// Directory inside the working directory holding sandbox-private files.
pub const HEEL_DIR_NAME: &str = ".heel";
/// Directory inside [`HEEL_DIR_NAME`] holding the generated command shims.
pub const WRAPPER_DIR_NAME: &str = "bin";
/// File name of the IPC socket inside its private directory.
pub const SOCKET_NAME: &str = "s";

/// The directory to create the IPC socket in.
///
/// Unix socket paths are limited to about a hundred bytes, so the shortest
/// available temporary root is chosen rather than the conventional one: on
/// macOS the per-user temp directory alone is two thirds of the budget.
pub(crate) fn socket_root() -> PathBuf {
    let user_temp = std::env::temp_dir();
    let shared_temp = PathBuf::from("/tmp");

    if shared_temp.is_dir() && shared_temp.as_os_str().len() < user_temp.as_os_str().len() {
        shared_temp
    } else {
        user_temp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_root_leaves_room_for_the_socket_name() {
        let root = socket_root();
        assert!(root.is_dir(), "{} must exist", root.display());
        // A per-sandbox directory and the socket name still have to fit inside
        // the platform's sockaddr_un limit.
        assert!(
            root.as_os_str().len() + "/heel-0123abcd/s".len() < 100,
            "{} leaves no room for a socket path",
            root.display()
        );
    }
}
