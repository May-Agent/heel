use std::borrow::Cow;

/// How a command's arguments may be written on the sandbox command line.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommandMeta {
    /// Argument names that may be given positionally, in order.
    pub positional_args: Cow<'static, [Cow<'static, str>]>,
    /// Argument that receives piped standard input, if any.
    pub stdin_arg: Option<Cow<'static, str>>,
    /// Whether every argument reaches the handler verbatim in `params["args"]`.
    #[serde(default)]
    pub raw_args: bool,
}
