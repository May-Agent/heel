//! Relaying requests to a trusted TCP peer: the serving half of
//! [`TcpIpcEndpoint`], whose addressing the sandboxed client shares.

use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use heel_shim::{IpcError, IpcRequest, IpcResponse, MAX_FRAME_BYTES, TcpIpcEndpoint};

use super::command::IpcContext;
use super::server::IpcDispatcher;

/// Forward one request to `endpoint` and return the peer's payload.
async fn request(
    endpoint: &TcpIpcEndpoint,
    method: &str,
    context: &IpcContext,
    params: &[u8],
) -> Result<Vec<u8>, IpcError> {
    let operation = async {
        let mut stream = async_net::TcpStream::connect(endpoint.address()).await?;
        stream.set_nodelay(true)?;
        stream
            .write_all(&IpcRequest::encode(method, context.working_dir(), params)?)
            .await?;
        let mut length = [0; 4];
        stream.read_exact(&mut length).await?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            return Err(IpcError::InvalidProtocol(format!(
                "invalid IPC response length: {length}"
            )));
        }
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await?;
        let response = IpcResponse::decode(&body)?;
        if response.success {
            Ok(response.payload)
        } else {
            Err(IpcError::Remote(rmp_serde::from_slice(&response.payload)?))
        }
    };
    futures_lite::future::race(operation, async {
        smol::Timer::after(endpoint.timeout()).await;
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "TCP IPC request deadline exceeded",
        )
        .into())
    })
    .await
}

impl IpcDispatcher for TcpIpcEndpoint {
    async fn handle(
        &self,
        method: &str,
        context: IpcContext,
        params: Vec<u8>,
    ) -> Result<Vec<u8>, IpcError> {
        request(self, method, &context, &params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_peer_that_never_replies_is_bounded_by_the_deadline() {
        let listener = async_net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let endpoint = TcpIpcEndpoint::new(
            listener.local_addr().expect("address"),
            Duration::from_millis(25),
        );
        let peer = async {
            let (_stream, _) = listener.accept().await.expect("accepts");
            smol::Timer::after(Duration::from_millis(100)).await;
        };
        let (_, result) = futures_lite::future::zip(
            peer,
            request(&endpoint, "probe", &IpcContext::new("/"), &[]),
        )
        .await;
        assert!(
            matches!(result, Err(IpcError::Io(ref error)) if error.kind() == std::io::ErrorKind::TimedOut)
        );
    }
}
