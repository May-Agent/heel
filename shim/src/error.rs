use std::io;
use std::path::PathBuf;

use thiserror::Error;

pub type CliResult<T> = std::result::Result<T, CliError>;

/// Variants that exist purely to carry another error use tuple form: thiserror
/// derives the `From` impl either way, and a named `source` field makes the
/// generated code trip `clippy::redundant_field_names` on current nightlies.
#[derive(Debug, Error)]
pub enum CliError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("failed to decode command metadata at {path}: {source}")]
    Metadata {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[error("the executable's file name is not a UTF-8 command name")]
    InvalidCommandName,

    #[error(
        "HEEL_IPC_ENDPOINT is not set; `heel-shim` runs inside a sandbox that has IPC configured"
    )]
    MissingIpcEndpoint,

    #[error("IPC error: {0}")]
    Ipc(#[from] heel_shim::IpcError),

    #[error("failed to encode IPC arguments: {0}")]
    EncodeIpcArgs(#[from] rmp_serde::encode::Error),

    #[error("failed to decode the IPC response: {0}")]
    DecodeIpcResponse(#[from] rmp_serde::decode::Error),

    #[error("failed to render the IPC response: {0}")]
    RenderIpcResponse(#[from] serde_json::Error),

    #[error("{command} takes no positional argument here: {value}")]
    UnexpectedPositional { command: String, value: String },

    #[error("{command} received an argument that is not --name or --name=value: {value}")]
    UnexpectedArgument { command: String, value: String },
}
