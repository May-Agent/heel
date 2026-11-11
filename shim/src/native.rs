//! The command this executable was started as.
//!
//! A hard-linked copy of `heel-shim.exe` acts as the command its file name
//! spells, and reads `<command>.json` beside it: Windows has no scripts a
//! sandboxed process finds on `PATH` the way a shell does, so each command is
//! the shim itself under another name.

use std::path::Path;

use clap::Parser;
use heel_shim::CommandMeta;

use crate::args::IpcArgs;
use crate::error::{CliError, CliResult};

/// The file stem the executable has when it is run as itself.
const OWN_NAME: &str = "heel-shim";

/// Parse the command line of the process.
pub fn parse() -> CliResult<IpcArgs> {
    let executable = std::env::current_exe()?;
    Ok(
        match command_arguments(&executable, std::env::args().skip(1))? {
            Some(arguments) => IpcArgs::parse_from(arguments),
            None => IpcArgs::parse(),
        },
    )
}

/// The arguments `executable` stands for when its file name spells a command,
/// or `None` when it is the shim itself and its command line is its own.
fn command_arguments(
    executable: &Path,
    forwarded: impl Iterator<Item = String>,
) -> CliResult<Option<Vec<String>>> {
    let command = executable
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or(CliError::InvalidCommandName)?;
    if command.eq_ignore_ascii_case(OWN_NAME) {
        return Ok(None);
    }
    let path = executable.with_extension("json");
    let metadata: CommandMeta = serde_json::from_slice(&std::fs::read(&path)?)
        .map_err(|source| CliError::Metadata { path, source })?;
    let mut arguments = vec![OWN_NAME.to_owned(), command.to_owned()];
    if metadata.raw_args {
        arguments.push("--raw-args".to_owned());
    } else {
        for positional in metadata.positional_args.iter() {
            arguments.extend(["--positional".to_owned(), positional.to_string()]);
        }
    }
    if let Some(stdin_arg) = metadata.stdin_arg {
        arguments.extend(["--stdin-arg".to_owned(), stdin_arg.into_owned()]);
    }
    arguments.push("--".to_owned());
    arguments.extend(forwarded);
    Ok(Some(arguments))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shim_under_its_own_name_takes_its_own_command_line() {
        let arguments =
            command_arguments(Path::new("/bin/heel-shim"), std::iter::empty()).expect("parses");
        assert!(arguments.is_none());
        let arguments =
            command_arguments(Path::new("/bin/HEEL-SHIM.EXE"), std::iter::empty()).expect("parses");
        assert!(arguments.is_none());
    }

    #[test]
    fn another_name_is_a_command_described_by_the_json_beside_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let executable = dir.path().join("search.exe");
        std::fs::write(
            dir.path().join("search.json"),
            r#"{"positional_args":["query","scope"],"stdin_arg":"input"}"#,
        )
        .expect("writes metadata");

        let arguments = command_arguments(
            &executable,
            ["rust", "--limit", "3"].into_iter().map(str::to_owned),
        )
        .expect("parses")
        .expect("a command");

        assert_eq!(
            arguments,
            [
                "heel-shim",
                "search",
                "--positional",
                "query",
                "--positional",
                "scope",
                "--stdin-arg",
                "input",
                "--",
                "rust",
                "--limit",
                "3"
            ]
        );
    }

    #[test]
    fn raw_args_commands_forward_every_word() {
        let dir = tempfile::tempdir().expect("tempdir");
        let executable = dir.path().join("tool");
        std::fs::write(
            dir.path().join("tool.json"),
            r#"{"positional_args":[],"stdin_arg":null,"raw_args":true}"#,
        )
        .expect("writes metadata");

        let arguments = command_arguments(&executable, ["open".to_owned()].into_iter())
            .expect("parses")
            .expect("a command");

        assert_eq!(arguments, ["heel-shim", "tool", "--raw-args", "--", "open"]);
    }

    #[test]
    fn a_command_without_metadata_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = command_arguments(&dir.path().join("nothing"), std::iter::empty())
            .expect_err("no metadata");
        assert!(matches!(error, CliError::Io(_)), "{error}");
    }
}
