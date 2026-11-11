//! `heel shims`: write the shims of IPC commands served elsewhere.

use crate::cli::ShimsArgs;
use crate::error::CliResult;

/// Write the shims, with the `heel-shim` executable they run.
pub async fn execute(args: ShimsArgs) -> CliResult<()> {
    blocking::unblock(move || Ok(args.commands.write_shims(&args.dir)?)).await
}
