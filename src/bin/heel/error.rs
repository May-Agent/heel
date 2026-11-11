use std::io;
use std::path::PathBuf;

use thiserror::Error;

pub type CliResult<T> = std::result::Result<T, CliError>;

/// Variants that exist purely to carry another error use tuple form: thiserror
/// derives the `From` impl either way, and a named `source` field makes the
/// generated code trip `clippy::redundant_field_names` on current nightlies.
#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Sandbox(#[from] heel::Error),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("failed to read config file {path}: {source}")]
    ReadConfig { path: PathBuf, source: io::Error },

    /// The parse error carries the source span and is by far the largest thing
    /// this enum holds, so it is boxed rather than widening every `CliResult`.
    #[error("failed to parse config file {path}: {source}")]
    ParseConfig {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },

    #[error("invalid --env value (expected KEY=VALUE): {value}")]
    InvalidEnvFormat { value: String },

    #[error("invalid --grant value (expected PATH=MODE, such as /opt/tools=rx): {value}")]
    InvalidGrantFormat { value: String },

    #[error("invalid --grant value {value}: {source}")]
    InvalidGrantMode {
        value: String,
        source: heel::ParseAccessError,
    },

    #[error("invalid --nice value: {0}")]
    InvalidNiceLevel(#[from] heel::InvalidNiceLevel),

    #[error("--network allow-list requires at least one --allow-domain")]
    MissingAllowDomains,

    #[error(
        "--audit-log records what the sandbox proxy decided, but --network deny (the default) \
         runs no proxy and denies every connection in the kernel, so nothing would be audited"
    )]
    AuditLogWithoutProxy,

    #[error(
        "--isolation host runs the process with the invoking user's full access, which an explicit --network deny contradicts"
    )]
    HostAccessWithDeny,

    #[error("IPC error: {0}")]
    Ipc(#[from] heel::IpcError),
}
