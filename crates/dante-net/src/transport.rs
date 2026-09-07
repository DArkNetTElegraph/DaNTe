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
    net::{TcpListener, TcpStream},
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
///
/// Holds an ordered list of candidate relay endpoints and a lazily-(re)opened
/// TCP stream. [`Client::request`] transparently reconnects — and fails over to
/// the next endpoint — across a dropped connection, so a relay restart or a
/// single dead relay does not sink the engine. Application-level errors
/// ([`NetError::Peer`]) are returned as-is and never trigger a retry.
pub struct Client {
    addrs: Vec<String>,
    /// Index into `addrs` of the endpoint `stream` is (or was) connected to.
    current: usize,
    stream: Option<TcpStream>,
}

impl Client {
    /// Connect to a single relay at `addr` (`host:port`).
    pub async fn connect(addr: &str) -> Result<Self, NetError> {
        Self::connect_multi(&[addr.to_string()]).await
    }

    /// Connect to the first reachable relay in `addrs`, which is kept as the
    /// failover list (tried in order, wrapping from the last success).
    pub async fn connect_multi(addrs: &[String]) -> Result<Self, NetError> {
        let addrs: Vec<String> = addrs
            .iter()
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect();
        if addrs.is_empty() {
            return Err(NetError::Closed);
        }
        let mut client = Self {
            addrs,
            current: 0,
            stream: None,
        };
        client.reconnect().await?;
        Ok(client)
    }

    /// The relay endpoint the live stream is (or was last) connected to.
    pub fn endpoint(&self) -> &str {
        &self.addrs[self.current]
    }

    /// Drop any stream and open a fresh one, trying every endpoint once
    /// starting from the last-known-good.
    async fn reconnect(&mut self) -> Result<(), NetError> {
        self.stream = None;
        let n = self.addrs.len();
        let mut last = NetError::Closed;
        for step in 0..n {
            let idx = (self.current + step) % n;
            match TcpStream::connect(self.addrs[idx].as_str()).await {
                Ok(stream) => {
                    stream.set_nodelay(true).ok();
                    self.stream = Some(stream);
                    self.current = idx;
                    return Ok(());
                }
                Err(e) => last = e.into(),
            }
        }
        Err(last)
    }

    /// Send one request and await its response, reconnecting once (and failing
    /// over) if the connection is dead.
    pub async fn request(&mut self, req: &Request) -> Result<Response, NetError> {
        let bytes = req.encode();
        let mut last_err = NetError::Closed;
        for attempt in 0..2 {
            if self.stream.is_none() {
                if let Err(e) = self.reconnect().await {
                    last_err = e;
                    continue;
                }
            }
            let stream = self
                .stream
                .as_mut()
                .expect("reconnect populated the stream");
            match round_trip(stream, &bytes).await {
                Ok(res) => return Ok(res),
                // A relay-level error is a real answer — do not retry it.
                Err(e @ NetError::Peer(_)) => return Err(e),
                Err(e) => {
                    self.stream = None;
                    last_err = e;
                    if attempt == 1 {
                        break;
                    }
                }
            }
        }
        Err(last_err)
    }
}

async fn round_trip(stream: &mut TcpStream, bytes: &[u8]) -> Result<Response, NetError> {
    write_frame(stream, bytes).await?;
    let body = read_frame(stream).await?;
    let res = Response::decode(&body)?;
    if let Response::Error(msg) = &res {
        return Err(NetError::Peer(msg.clone()));
    }
    Ok(res)
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

        let mut client = Client::connect(&addr.to_string()).await.unwrap();
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
    async fn client_reconnects_after_the_relay_drops() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(serve(listener, Arc::new(Echo)));

        let mut client = Client::connect(&addr).await.unwrap();
        assert_eq!(
            client.request(&Request::Ping).await.unwrap(),
            Response::Pong
        );

        // Relay goes away, then a fresh one binds the same port.
        task.abort();
        loop {
            match TcpListener::bind(&*addr).await {
                Ok(l) => {
                    tokio::spawn(serve(l, Arc::new(Echo)));
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        }

        // The stale connection is dead; request() reconnects and succeeds.
        assert_eq!(
            client.request(&Request::Ping).await.unwrap(),
            Response::Pong
        );
    }

    #[tokio::test]
    async fn client_fails_over_to_a_live_endpoint() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let live = listener.local_addr().unwrap().to_string();
        tokio::spawn(serve(listener, Arc::new(Echo)));

        // First endpoint is a closed port; second is the live relay.
        let dead = {
            let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            l.local_addr().unwrap().to_string()
        };
        let mut client = Client::connect_multi(&[dead, live.clone()]).await.unwrap();
        assert_eq!(
            client.request(&Request::Ping).await.unwrap(),
            Response::Pong
        );
        assert_eq!(client.endpoint(), live);
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
