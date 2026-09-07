//! A minimal framed TCP transport: `u32` big-endian length prefix + body.
//!
//! One [`Request`] gets one [`Response`] per frame exchange; a connection may
//! carry many. This is deliberately not libp2p — point-to-point client↔relay is
//! all the MVP needs. A DHT / gossip overlay for multi-relay decentralisation
//! is a later phase.

use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};

use crate::{
    error::NetError,
    wire::{Request, Response},
};

/// Largest frame this transport will read or write.
pub const MAX_FRAME: u32 = 8 * 1024 * 1024;

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, body: &[u8]) -> Result<(), NetError> {
    let len = u32::try_from(body.len()).map_err(|_| NetError::FrameTooLarge(u32::MAX))?;
    if len > MAX_FRAME {
        return Err(NetError::FrameTooLarge(len));
    }
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>, NetError> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(NetError::Closed),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(NetError::FrameTooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            NetError::Closed
        } else {
            e.into()
        }
    })?;
    Ok(body)
}

/// A client connection to a relay.
pub struct Client {
    stream: TcpStream,
}

impl Client {
    /// Connect to a relay at `addr`.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, NetError> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true).ok();
        Ok(Self { stream })
    }

    /// Send one request and await its response.
    pub async fn request(&mut self, req: &Request) -> Result<Response, NetError> {
        write_frame(&mut self.stream, &req.encode()).await?;
        let body = read_frame(&mut self.stream).await?;
        let res = Response::decode(&body)?;
        if let Response::Error(msg) = &res {
            return Err(NetError::Peer(msg.clone()));
        }
        Ok(res)
    }
}

/// Handles inbound relay requests. Implemented by `dante-relay`.
#[async_trait]
pub trait RequestHandler: Send + Sync + 'static {
    /// Produce a response for `req` from `peer_ip`.
    async fn handle(&self, req: Request, peer_ip: IpAddr) -> Response;
}

/// Accept connections on `listener` forever, dispatching each framed request to
/// `handler`. Returns only on a fatal accept error.
pub async fn serve<H: RequestHandler>(
    listener: TcpListener,
    handler: Arc<H>,
) -> Result<(), NetError> {
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            if let Err(e) = serve_conn(stream, peer.ip(), handler).await {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
        });
    }
}

async fn serve_conn<H: RequestHandler>(
    mut stream: TcpStream,
    peer_ip: IpAddr,
    handler: Arc<H>,
) -> Result<(), NetError> {
    loop {
        let body = match read_frame(&mut stream).await {
            Ok(b) => b,
            Err(NetError::Closed) => return Ok(()),
            Err(e) => return Err(e),
        };
        let response = match Request::decode(&body) {
            Ok(req) => handler.handle(req, peer_ip).await,
            Err(e) => Response::Error(format!("bad request: {e}")),
        };
        write_frame(&mut stream, &response.encode()).await?;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    struct Echo;

    #[async_trait]
    impl RequestHandler for Echo {
        async fn handle(&self, req: Request, _ip: IpAddr) -> Response {
            match req {
                Request::Ping => Response::Pong,
                Request::GetTreeHead => Response::TreeHead {
                    size: 3,
                    root: [1u8; 32],
                },
                Request::SubmitRecord(_) => Response::Ok,
                _ => Response::Error("unsupported".into()),
            }
        }
    }

    #[tokio::test]
    async fn client_server_request_response() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::new(Echo)));

        let mut client = Client::connect(addr).await.unwrap();
        assert_eq!(
            client.request(&Request::Ping).await.unwrap(),
            Response::Pong
        );
        assert_eq!(
            client.request(&Request::GetTreeHead).await.unwrap(),
            Response::TreeHead {
                size: 3,
                root: [1u8; 32]
            }
        );
        // multiple requests on one connection
        assert_eq!(
            client
                .request(&Request::SubmitRecord(vec![1]))
                .await
                .unwrap(),
            Response::Ok
        );
        // relay Error becomes a NetError::Peer
        let err = client.request(&Request::Deposit(vec![])).await.unwrap_err();
        assert!(matches!(err, NetError::Peer(_)));
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::new(Echo)));

        let mut raw = TcpStream::connect(addr).await.unwrap();
        raw.write_all(&(MAX_FRAME + 1).to_be_bytes()).await.unwrap();
        raw.flush().await.unwrap();
        // server drops the connection
        let mut buf = [0u8; 1];
        assert!(raw.read_exact(&mut buf).await.is_err());
    }
}
