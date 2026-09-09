//! Client↔relay transport for the [`Request`]/[`Response`] wire.
//!
//! One [`Request`] gets one [`Response`] per exchange; a connection may carry
//! many. The default backend is a minimal framed TCP stream (`u32` big-endian
//! length prefix + body). With the `p2p` feature, [`Client::connect_p2p`]
//! carries the identical wire over a libp2p `/dante/relay/1` request-response
//! stream instead, so a client can reach a relay peer-to-peer. The relay's
//! serving side ([`serve`] / [`RequestHandler`]) is transport-agnostic —
//! `dante-relay` feeds it both TCP connections and libp2p inbound requests.

use std::{net::IpAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};

use crate::{
    error::NetError,
    wire::{Request, Response},
};

/// Largest frame this transport will read or write.
pub const MAX_FRAME: u32 = 8 * 1024 * 1024;

/// Max concurrent inbound connections a relay will service at once. Beyond this
/// new connections are dropped rather than piled on, so a flood of half-open
/// sockets can't exhaust file descriptors or task memory.
pub const MAX_CONNECTIONS: usize = 1024;

/// A connection must produce its next complete request frame within this. It
/// bounds a slowloris hold (a length prefix followed by a trickle of body, or an
/// idle socket parked forever); a client with nothing to send simply reconnects
/// when it next needs the relay.
const CONN_READ_TIMEOUT: Duration = Duration::from_secs(120);

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
/// The default backend is framed TCP: an ordered list of candidate relay
/// endpoints and a lazily-(re)opened stream, with transparent reconnect and
/// failover across a dropped connection. With the `p2p` feature and
/// [`Client::connect_p2p`] the same [`Request`]/[`Response`] wire instead
/// rides a libp2p `/dante/relay/1` stream to a relay peer. Either way,
/// application-level errors ([`NetError::Peer`]) are returned as-is and never
/// retried.
pub struct Client(Backend);

enum Backend {
    Tcp(TcpBackend),
    #[cfg(feature = "p2p")]
    P2p(p2p_client::P2pBackend),
}

struct TcpBackend {
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
        let mut tcp = TcpBackend {
            addrs,
            current: 0,
            stream: None,
        };
        tcp.reconnect().await?;
        Ok(Client(Backend::Tcp(tcp)))
    }

    /// Reach a relay over libp2p. `node` is a running [`dante_p2p::Node`];
    /// `relay_addr` is the relay's full multiaddr ending `/p2p/<peer-id>`.
    #[cfg(feature = "p2p")]
    pub async fn connect_p2p(node: dante_p2p::Node, relay_addr: &str) -> Result<Self, NetError> {
        Ok(Client(Backend::P2p(
            p2p_client::P2pBackend::connect(node, relay_addr).await?,
        )))
    }

    /// The relay endpoint this client is (or was last) talking to.
    pub fn endpoint(&self) -> &str {
        match &self.0 {
            Backend::Tcp(t) => &t.addrs[t.current],
            #[cfg(feature = "p2p")]
            Backend::P2p(p) => p.endpoint(),
        }
    }

    /// Send one request and await its response, reconnecting once (and, for
    /// TCP, failing over) if the connection is dead.
    pub async fn request(&mut self, req: &Request) -> Result<Response, NetError> {
        match &mut self.0 {
            Backend::Tcp(t) => t.request(req).await,
            #[cfg(feature = "p2p")]
            Backend::P2p(p) => p.request(req).await,
        }
    }
}

impl TcpBackend {
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

    async fn request(&mut self, req: &Request) -> Result<Response, NetError> {
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

#[cfg(feature = "p2p")]
mod p2p_client {
    use dante_p2p::{Multiaddr, Node, PeerId};

    use crate::{
        error::NetError,
        wire::{Request, Response},
    };

    /// A libp2p-backed relay connection: one `/dante/relay/1` request per
    /// [`Request`]. libp2p handles (re)dialing the relay peer on demand.
    pub struct P2pBackend {
        node: Node,
        peer: PeerId,
        addr: String,
    }

    impl P2pBackend {
        pub async fn connect(node: Node, relay_addr: &str) -> Result<Self, NetError> {
            let ma: Multiaddr = relay_addr
                .parse()
                .map_err(|e| NetError::Peer(format!("bad relay multiaddr: {e}")))?;
            let peer = ma
                .iter()
                .find_map(|p| match p {
                    dante_p2p::multiaddr::Protocol::P2p(id) => Some(id),
                    _ => None,
                })
                .ok_or_else(|| NetError::Peer("relay multiaddr has no /p2p/<peer-id>".into()))?;
            node.add_address(peer, ma.clone())
                .await
                .map_err(|e| NetError::Peer(e.to_string()))?;
            // Best-effort warm dial; request-response also dials on demand.
            let _ = node.dial(ma).await;
            Ok(Self {
                node,
                peer,
                addr: relay_addr.to_string(),
            })
        }

        pub fn endpoint(&self) -> &str {
            &self.addr
        }

        pub async fn request(&mut self, req: &Request) -> Result<Response, NetError> {
            let bytes = self
                .node
                .request(self.peer, req.encode())
                .await
                .map_err(|e| NetError::Peer(e.to_string()))?;
            let res = Response::decode(&bytes)?;
            if let Response::Error(msg) = &res {
                return Err(NetError::Peer(msg.clone()));
            }
            Ok(res)
        }
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
    let conn_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        // Hard-cap concurrency: at the limit, drop the newcomer instead of
        // queuing it, so a connection flood can't grow tasks/fds without bound.
        let Ok(permit) = Arc::clone(&conn_limit).try_acquire_owned() else {
            tracing::debug!(%peer, "connection limit reached, dropping");
            continue;
        };
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let _permit = permit; // released when the connection ends
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
        let body = match tokio::time::timeout(CONN_READ_TIMEOUT, read_frame(&mut stream)).await {
            Ok(Ok(b)) => b,
            Ok(Err(NetError::Closed)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            // Idle or dribbling past the deadline: drop the connection quietly.
            Err(_) => return Ok(()),
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

    #[cfg(feature = "p2p")]
    #[tokio::test]
    async fn client_talks_to_a_relay_over_libp2p() {
        use dante_p2p::Node;

        // The "relay": a p2p node that answers `/dante/relay/1` by running the
        // Echo handler over the decoded Request.
        let (relay, mut relay_evt, mut relay_in) = Node::spawn(&[9u8; 32]).unwrap();
        relay
            .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .await
            .unwrap();
        let relay_addr = loop {
            if let Some(dante_p2p::Event::Listening(a)) = relay_evt.recv().await {
                break a;
            }
        };
        let relay_ma = format!("{relay_addr}/p2p/{}", relay.peer_id());

        tokio::spawn(async move {
            let handler = Echo;
            while let Some(req) = relay_in.recv().await {
                let resp = match Request::decode(&req.body) {
                    Ok(r) => handler.handle(r, IpAddr::V4(Ipv4Addr::LOCALHOST)).await,
                    Err(e) => Response::Error(format!("bad request: {e}")),
                };
                req.respond(resp.encode()).await;
            }
        });

        // The client: its own p2p node, pointed at the relay's multiaddr.
        let (client_node, _c_evt, _c_in) = Node::spawn(&[10u8; 32]).unwrap();
        client_node
            .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .await
            .unwrap();
        let mut client = Client::connect_p2p(client_node, &relay_ma).await.unwrap();

        // request-response dials on demand; retry until the mesh is up.
        let mut pong = None;
        for _ in 0..20 {
            match client.request(&Request::Ping).await {
                Ok(r) => {
                    pong = Some(r);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(150)).await,
            }
        }
        assert_eq!(pong, Some(Response::Pong), "Ping over libp2p answered");

        assert_eq!(
            client.request(&Request::GetTreeHead).await.unwrap(),
            Response::TreeHead {
                size: 3,
                root: [1u8; 32]
            }
        );
        // A relay Error still surfaces as NetError::Peer over p2p.
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
