use clap::Parser;

/// Invoke a host command over the sandbox IPC socket.
///
/// The generated command shims call this; the metadata flags come from the
/// command's declaration on the host, so all argument handling happens here
/// rather than in shell script.
#[derive(Parser)]
#[command(name = "heel-shim", version, about)]
pub struct IpcArgs {
    /// TCP IPC connection and request deadline.
    #[arg(long, default_value = "30s", value_parser = humantime::parse_duration)]
    pub timeout: std::time::Duration,

    /// IPC command name to invoke.
    pub command: String,

    /// Argument name that may be given positionally; repeated, in order.
    #[arg(long = "positional")]
    pub positional: Vec<String>,

    /// Forward every argument verbatim in `args` for the host-side parser.
    #[arg(long = "raw-args")]
    pub raw_args: bool,

    /// Argument name that receives piped standard input.
    #[arg(long = "stdin-arg")]
    pub stdin_arg: Option<String>,

    /// Arguments forwarded to the IPC command.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_metadata_is_separated_from_forwarded_arguments() {
        let args = IpcArgs::try_parse_from([
            "heel-shim",
            "search",
            "--positional",
            "query",
            "--stdin-arg",
            "input",
            "--",
            "rust",
            "--limit",
            "3",
        ])
        .expect("parses");

        assert_eq!(args.command, "search");
        assert_eq!(args.positional, ["query"]);
        assert_eq!(args.stdin_arg.as_deref(), Some("input"));
        assert_eq!(args.args, ["rust", "--limit", "3"]);
    }
}
