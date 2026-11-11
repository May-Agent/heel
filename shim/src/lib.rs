//! What both sides of heel's IPC wire need.
//!
//! The `heel-shim` executable runs inside a sandbox and calls host commands;
//! the `heel` library serves them. This crate holds the wire protocol, the
//! naming of the endpoint, the client and the description of a command's
//! command line, so the two cannot drift apart. It never depends on `heel`.
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod client;
mod command;
pub mod endpoint;
mod protocol;
mod tcp;

pub use client::IpcClient;
pub use command::CommandMeta;
pub use protocol::{IpcError, IpcRequest, IpcResponse, MAX_FRAME_BYTES, PROTOCOL_VERSION};
pub use tcp::TcpIpcEndpoint;

/// The version of this crate, which is the version of the `heel-shim`
/// executable that speaks this wire protocol.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
