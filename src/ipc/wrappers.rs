//! Generation of the command shims a sandboxed process sees on its `PATH`.
//!
//! A shim directory holds the `heel-shim` executable the library embeds, and
//! one program per registered IPC command that runs it with the command's
//! declared arguments: in a sandbox's `.heel/bin`, or in the directory
//! [`IpcCommands::write_shims`] is given. On Unix each command is a small script
//! beside the executable; on Windows it is a hard link to the executable
//! with the command's metadata in `<command>.json` beside it. Neither carries
//! argument-parsing logic of its own: that is `heel-shim`'s, in Rust, where it
//! can be tested.

#[cfg(unix)]
use std::borrow::Cow;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use askama::Template;

use crate::error::{Error, Result};
use crate::ipc::paths::{HEEL_DIR_NAME, WRAPPER_DIR_NAME};
use crate::ipc::router::IpcCommands;
use heel_shim::CommandMeta;

/// The `heel-shim` executable for the target this library is built for,
/// produced by the build script.
const SHIM_EXECUTABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/heel-shim"));

/// File name of the shim executable inside a shim directory.
const SHIM_FILE_NAME: &str = if cfg!(windows) {
    "heel-shim.exe"
} else {
    "heel-shim"
};

/// Wrapper script for one IPC command.
#[cfg(unix)]
#[derive(Template)]
#[template(path = "ipc/wrapper.sh", escape = "none")]
struct WrapperTemplate<'a> {
    command: &'a str,
    positional_args: &'a [Cow<'static, str>],
    stdin_arg: Option<&'a str>,
    raw_args: bool,
}

/// Where a sandbox's IPC files live.
///
/// The command shims sit inside the working directory so they land on `PATH`,
/// but the socket does not. Two reasons: `sockaddr_un` has room for barely a
/// hundred bytes, which a working directory under a per-user temp root can
/// exhaust on its own; and the working directory is writable by the sandboxed
/// process, which could otherwise unlink the socket it depends on.
#[derive(Debug, Clone)]
pub(crate) struct IpcLayout {
    heel_dir: PathBuf,
    bin_dir: PathBuf,
}

impl IpcLayout {
    /// Derive the layout for a working directory.
    pub(crate) fn new(working_dir: &Path) -> Self {
        let heel_dir = working_dir.join(HEEL_DIR_NAME);
        Self {
            bin_dir: heel_dir.join(WRAPPER_DIR_NAME),
            heel_dir,
        }
    }

    /// Directory holding the generated shims, which is added to `PATH`.
    pub(crate) fn bin_dir(&self) -> &Path {
        &self.bin_dir
    }

    /// Create the directories and write the shim executable and command shims.
    ///
    /// This is blocking work; callers run it off the async executor.
    pub(crate) fn write(&self, commands: &IpcCommands) -> Result<()> {
        create_private_dir(&self.heel_dir)?;
        write_shims(&self.bin_dir, commands)
    }
}

impl IpcCommands {
    /// Write the shims of these commands into `dir`, which is created
    /// owner-only if it does not exist.
    ///
    /// `dir` then holds what a sandbox's shim directory holds: the `heel-shim`
    /// executable, and one program per command that runs it with the command's
    /// declared arguments. Put on `PATH`, the commands are ordinary programs
    /// that reach the endpoint `HEEL_IPC_ENDPOINT` names. This is for a process
    /// that runs where the router does not, such as a container reaching the
    /// router's host through `tcp://`; a sandbox with a router writes its own
    /// shims.
    ///
    /// This is blocking work; run it off the async executor.
    pub fn write_shims(&self, dir: &Path) -> Result<()> {
        write_shims(dir, self)
    }
}

/// Create `bin_dir` and write the shim executable and the shims of `commands`
/// into it.
fn write_shims(bin_dir: &Path, commands: &IpcCommands) -> Result<()> {
    create_private_dir(bin_dir)?;

    let executable = bin_dir.join(SHIM_FILE_NAME);
    write_executable(&executable, SHIM_EXECUTABLE)?;

    #[cfg(unix)]
    for (command, meta) in commands.iter() {
        write_executable(
            &bin_dir.join(command),
            render_wrapper(command, meta)?.as_bytes(),
        )?;
    }
    #[cfg(windows)]
    for (command, meta) in commands.iter() {
        let linked = bin_dir.join(command).with_extension("exe");
        std::fs::hard_link(&executable, &linked).map_err(|source| Error::path(&linked, source))?;
        let metadata = bin_dir.join(command).with_extension("json");
        let contents = render_wrapper(command, meta)?;
        std::fs::write(&metadata, contents).map_err(|source| Error::path(&metadata, source))?;
    }

    tracing::debug!(bin_dir = %bin_dir.display(), "wrote IPC command shims");
    Ok(())
}

/// Render the shim for one command.
#[cfg(unix)]
fn render_wrapper(command: &str, meta: &CommandMeta) -> Result<String> {
    Ok(WrapperTemplate {
        command,
        positional_args: &meta.positional_args,
        stdin_arg: meta.stdin_arg.as_deref(),
        raw_args: meta.raw_args,
    }
    .render()?)
}

#[cfg(windows)]
fn render_wrapper(_command: &str, meta: &CommandMeta) -> Result<String> {
    serde_json::to_string(meta).map_err(|source| Error::InitFailed(source.to_string()))
}

/// Create a directory only its owner can enter.
fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|source| Error::path(path, source))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|source| Error::path(path, source))?;
    }

    Ok(())
}

/// Write a program only its owner can run.
fn write_executable(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).map_err(|source| Error::path(path, source))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|source| Error::path(path, source))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcCommand, IpcContext, IpcRouter, NoArgs};
    use serde::Deserialize;
    use std::borrow::Cow;

    struct Search;

    #[derive(Deserialize)]
    struct SearchArgs {
        #[allow(dead_code)]
        query: String,
    }

    impl IpcCommand for Search {
        fn name(&self) -> Cow<'static, str> {
            "search".into()
        }
        fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
            Cow::Borrowed(&[Cow::Borrowed("query")])
        }
        fn stdin_arg(&self) -> Option<Cow<'static, str>> {
            Some("input".into())
        }

        type Args = SearchArgs;
        type Response = ();

        async fn handle(
            &self,
            _args: SearchArgs,
            _context: IpcContext,
        ) -> std::result::Result<(), crate::ipc::IpcError> {
            Ok(())
        }
    }

    struct Plain;

    impl IpcCommand for Plain {
        fn name(&self) -> Cow<'static, str> {
            "plain".into()
        }

        type Args = NoArgs;
        type Response = ();

        async fn handle(
            &self,
            _args: NoArgs,
            _context: IpcContext,
        ) -> std::result::Result<(), crate::ipc::IpcError> {
            Ok(())
        }
    }

    #[test]
    fn wrapper_forwards_declared_argument_names() {
        let script = render_wrapper(
            "search",
            &CommandMeta {
                positional_args: Cow::Borrowed(&[Cow::Borrowed("query"), Cow::Borrowed("scope")]),
                stdin_arg: Some(Cow::Borrowed("input")),
                raw_args: false,
            },
        )
        .expect("renders");

        #[cfg(unix)]
        assert!(script.contains(
            "heel-shim\" search --positional query --positional scope --stdin-arg input -- \"$@\""
        ));
        #[cfg(windows)]
        {
            let metadata: CommandMeta = serde_json::from_str(&script).expect("metadata");
            assert_eq!(metadata.positional_args.as_ref(), ["query", "scope"]);
            assert_eq!(metadata.stdin_arg.as_deref(), Some("input"));
        }
    }

    #[test]
    fn wrapper_without_metadata_is_a_bare_forward() {
        let script = render_wrapper(
            "plain",
            &CommandMeta {
                positional_args: Cow::Borrowed(&[]),
                stdin_arg: None,
                raw_args: false,
            },
        )
        .expect("renders");

        #[cfg(unix)]
        {
            assert!(script.contains("heel-shim\" plain -- \"$@\""));
            assert!(!script.contains("--positional"));
            assert!(!script.contains("--stdin-arg"));
        }
        #[cfg(windows)]
        {
            let metadata: CommandMeta = serde_json::from_str(&script).expect("metadata");
            assert!(metadata.positional_args.is_empty());
            assert!(metadata.stdin_arg.is_none());
        }
    }

    #[test]
    fn raw_args_wrappers_forward_argv_verbatim() {
        let script = render_wrapper(
            "tool",
            &CommandMeta {
                positional_args: Cow::Borrowed(&[]),
                stdin_arg: Some(Cow::Borrowed("input")),
                raw_args: true,
            },
        )
        .expect("renders");

        #[cfg(unix)]
        {
            assert!(script.contains("heel-shim\" tool --raw-args --stdin-arg input -- \"$@\""));
            assert!(!script.contains("--positional"));
        }
        #[cfg(windows)]
        {
            let metadata: CommandMeta = serde_json::from_str(&script).expect("metadata");
            assert!(metadata.raw_args);
            assert_eq!(metadata.stdin_arg.as_deref(), Some("input"));
        }
    }

    #[test]
    fn layout_writes_executable_owner_only_shims() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = IpcLayout::new(dir.path());
        let router = IpcRouter::new().register(Search).register(Plain);

        layout.write(router.commands()).expect("writes");

        #[cfg(unix)]
        let names = ["heel-shim", "search", "plain"];
        #[cfg(windows)]
        let names = ["heel-shim.exe", "search.exe", "plain.exe"];
        for name in names {
            let path = layout.bin_dir().join(name);
            assert!(path.is_file(), "{name} must be written");

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                let mode = std::fs::metadata(&path)
                    .unwrap_or_else(|_| panic!("{name} exists"))
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o700, "{name} must be owner-only");
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(layout.bin_dir())
                .expect("bin dir exists")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn the_embedded_executable_is_written_whole() {
        let dir = tempfile::tempdir().expect("tempdir");
        IpcRouter::new()
            .register(Plain)
            .commands()
            .write_shims(dir.path())
            .expect("writes");

        let written = std::fs::read(dir.path().join(SHIM_FILE_NAME)).expect("reads");
        assert!(!written.is_empty(), "the embedded executable is empty");
        assert!(written == SHIM_EXECUTABLE);
        #[cfg(windows)]
        assert_eq!(
            written,
            std::fs::read(dir.path().join("plain.exe")).expect("the hard link")
        );
    }

    #[test]
    fn shims_live_inside_the_working_directory() {
        let layout = IpcLayout::new(Path::new("/work"));
        assert_eq!(layout.bin_dir(), Path::new("/work/.heel/bin"));
    }
}
