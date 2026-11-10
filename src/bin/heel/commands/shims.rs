//! `heel shims`: write the shims of IPC commands served elsewhere.

use crate::cli::ShimsArgs;
use crate::error::CliResult;

/// Write the shims, with a launcher for this binary.
pub async fn execute(args: ShimsArgs) -> CliResult<()> {
    blocking::unblock(move || {
        let binary = heel::HeelBinary::locate()?;
        args.commands.write_shims(&args.dir, &binary)?;
        Ok(())
    })
    .await
}
