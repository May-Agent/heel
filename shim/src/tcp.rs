use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::protocol::IpcError;

/// A trusted TCP IPC peer resolved before sandbox execution.
#[derive(Debug, Clone, Copy)]
pub struct TcpIpcEndpoint {
    address: SocketAddr,
    timeout: Duration,
}

impl TcpIpcEndpoint {
    /// Use an explicit peer and deadline for connecting and serving a request.
    pub fn new(address: SocketAddr, timeout: Duration) -> Self {
        Self { address, timeout }
    }

    /// Resolve a `tcp://host:port` URI outside the sandbox.
    pub async fn resolve(value: &str, timeout: Duration) -> Result<Self, IpcError> {
        let uri: http::Uri = value.parse().map_err(|error| {
            IpcError::InvalidProtocol(format!("invalid TCP IPC endpoint: {error}"))
        })?;
        let authority = uri.authority().ok_or_else(|| {
            IpcError::InvalidProtocol("TCP IPC endpoint requires a host and port".into())
        })?;
        if uri.scheme_str() != Some("tcp")
            || authority.as_str().contains('@')
            || uri
                .path_and_query()
                .is_some_and(|path| !path.as_str().is_empty() && path.as_str() != "/")
        {
            return Err(IpcError::InvalidProtocol(
                "expected tcp://host:port without credentials or a path".into(),
            ));
        }
        let port = authority
            .port_u16()
            .filter(|port| *port != 0)
            .ok_or_else(|| {
                IpcError::InvalidProtocol("TCP IPC endpoint requires a nonzero port".into())
            })?;
        let host = authority.host().trim_matches(['[', ']']).to_owned();
        let address = blocking::unblock(move || {
            (host.as_str(), port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "IPC host resolved to no addresses",
                    )
                })
        })
        .await?;
        Ok(Self::new(address, timeout))
    }

    /// The resolved, immutable destination.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The deadline for one connection and request.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_resolution_rejects_non_ipc_uris() {
        for value in [
            "http://127.0.0.1:8000",
            "tcp://127.0.0.1",
            "tcp://127.0.0.1:0",
            "tcp://user@127.0.0.1:8000",
            "tcp://127.0.0.1:8000/path",
            "tcp://127.0.0.1:8000/?query=1",
        ] {
            assert!(
                matches!(
                    futures_lite::future::block_on(TcpIpcEndpoint::resolve(
                        value,
                        Duration::from_secs(1)
                    )),
                    Err(IpcError::InvalidProtocol(_))
                ),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn endpoint_resolution_preserves_ipv6_and_the_request_deadline() {
        let timeout = Duration::from_secs(7);
        let endpoint =
            futures_lite::future::block_on(TcpIpcEndpoint::resolve("tcp://[::1]:4567", timeout))
                .expect("resolves");
        assert_eq!(endpoint.address(), "[::1]:4567".parse().expect("address"));
        assert_eq!(endpoint.timeout(), timeout);
    }
}
