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

    /// Reach a relay over libp2p with no relay handed in: enter the DHT via
    /// `bootstrap` multiaddrs and discover relays from their `dante/relay/v1`
    /// provider records, keeping the rest as failover.
    #[cfg(feature = "p2p")]
    pub async fn connect_p2p_discover(
        node: dante_p2p::Node,
        bootstrap: &[String],
    ) -> Result<Self, NetError> {
        Ok(Client(Backend::P2p(
            p2p_client::P2pBackend::connect_discover(node, bootstrap).await?,
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
    use std::time::Duration;

    use dante_p2p::{Multiaddr, Node, PeerId, RELAY_CAPABILITY};

    use crate::{
        error::NetError,
        wire::{Request, Response},
    };

    /// A libp2p-backed relay connection. Each [`Request`] is one
    /// `/dante/relay/1` round trip; libp2p (re)dials the relay peer on demand.
    /// Holds one or more candidate relay `PeerId`s and rotates to the next on
    /// a transport failure (a relay-level [`Response::Error`] is a real answer
    /// and never triggers a rotation).
    pub struct P2pBackend {
        node: Node,
        candidates: Vec<PeerId>,
        current: usize,
        label: String,
    }

    fn peer_of(ma: &Multiaddr) -> Option<PeerId> {
        ma.iter().find_map(|p| match p {
            dante_p2p::multiaddr::Protocol::P2p(id) => Some(id),
            _ => None,
        })
    }

    impl P2pBackend {
        /// Connect to one relay given by its full multiaddr (`…/p2p/<peer-id>`).
        pub async fn connect(node: Node, relay_addr: &str) -> Result<Self, NetError> {
            let ma: Multiaddr = relay_addr
                .parse()
                .map_err(|e| NetError::Peer(format!("bad relay multiaddr: {e}")))?;
            let peer = peer_of(&ma)
                .ok_or_else(|| NetError::Peer("relay multiaddr has no /p2p/<peer-id>".into()))?;
            node.add_address(peer, ma.clone())
                .await
                .map_err(|e| NetError::Peer(e.to_string()))?;
            let _ = node.dial(ma).await; // warm dial; request-response also dials
            Ok(Self {
                node,
                candidates: vec![peer],
                current: 0,
                label: relay_addr.to_string(),
            })
        }

        /// Enter the DHT via `bootstrap` multiaddrs, then discover relays from
        /// their `dante/relay/v1` provider records — no relay handed in.
        pub async fn connect_discover(node: Node, bootstrap: &[String]) -> Result<Self, NetError> {
            if bootstrap.is_empty() {
                return Err(NetError::Peer(
                    "p2p relay discovery needs at least one --bootstrap multiaddr".into(),
                ));
            }
            for b in bootstrap {
                if let Ok(ma) = b.parse::<Multiaddr>() {
                    if let Some(p) = peer_of(&ma) {
                        let _ = node.add_address(p, ma.clone()).await;
                    }
                    let _ = node.dial(ma).await;
                }
            }
            let _ = node.bootstrap().await;

            let mut candidates = Vec::new();
            for _ in 0..25 {
                if let Ok(mut provs) = node.get_providers(RELAY_CAPABILITY.to_vec()).await {
                    if !provs.is_empty() {
                        provs.sort();
                        provs.dedup();
                        candidates = provs;
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
            if candidates.is_empty() {
                return Err(NetError::Peer(
                    "no relays found on the DHT (dante/relay/v1 providers)".into(),
                ));
            }
            Ok(Self {
                node,
                candidates,
                current: 0,
                label: "p2p-dht".into(),
            })
        }

        pub fn endpoint(&self) -> &str {
            &self.label
        }

        /// One request against a specific candidate. `Response::Error` becomes
        /// `NetError::Peer`.
        async fn one(&self, peer: PeerId, bytes: Vec<u8>) -> Result<Response, NetError> {
            let raw = self
                .node
                .request(peer, bytes)
                .await
                .map_err(|e| NetError::Peer(e.to_string()))?;
            match Response::decode(&raw)? {
                Response::Error(msg) => Err(NetError::Peer(msg)),
                res => Ok(res),
            }
        }

        pub async fn request(&mut self, req: &Request) -> Result<Response, NetError> {
            let bytes = req.encode();
            match FanOut::of(req) {
                // Write to every discovered relay so any of them can serve the
                // recipient later — the DHT-discovered relay set acts as one
                // redundant store with no server-side coordination.
                FanOut::Write => {
                    let mut ok = None;
                    let mut last = NetError::Closed;
                    for &peer in &self.candidates {
                        match self.one(peer, bytes.clone()).await {
                            Ok(r) => ok = Some(r),
                            Err(e @ NetError::Peer(_)) if ok.is_none() => last = e,
                            Err(e) => last = e,
                        }
                    }
                    ok.ok_or(last)
                }
                // Merge mailbox envelopes across every relay; the engine already
                // de-dups by envelope tag.
                FanOut::MergeEnvelopes => {
                    let mut all = Vec::new();
                    let mut any = false;
                    let mut last = NetError::Closed;
                    for &peer in &self.candidates {
                        match self.one(peer, bytes.clone()).await {
                            Ok(Response::Envelopes(v)) => {
                                any = true;
                                all.extend(v);
                            }
                            Ok(_) => any = true,
                            Err(e) => last = e,
                        }
                    }
                    if any {
                        Ok(Response::Envelopes(all))
                    } else {
                        Err(last)
                    }
                }
                // Everything else: one relay, rotate to the next on a transport
                // failure (a relay-level error is a real answer, no rotation).
                FanOut::One => {
                    let n = self.candidates.len();
                    let mut last = NetError::Closed;
                    for step in 0..n {
                        let idx = (self.current + step) % n;
                        match self.one(self.candidates[idx], bytes.clone()).await {
                            Ok(res) => {
                                self.current = idx;
                                return Ok(res);
                            }
                            Err(e @ NetError::Peer(_)) => return Err(e),
                            Err(e) => last = e,
                        }
                    }
                    Err(last)
                }
            }
        }
    }

    pub(super) enum FanOut {
        /// Send to every relay (idempotent / content-addressed writes).
        Write,
        /// Query every relay and concatenate the mailbox envelopes.
        MergeEnvelopes,
        /// One relay, with rotate-on-failure.
        One,
    }

    impl FanOut {
        pub(super) fn of(req: &Request) -> Self {
            match req {
                // Idempotent or content-addressed — safe to replicate.
                Request::Deposit(_)
                | Request::PutBlob(_)
                | Request::PublishPrekeys(_)
                | Request::SubmitRecord(_) => FanOut::Write,
                Request::Fetch { .. } => FanOut::MergeEnvelopes,
                // seq-bearing (channel log), single-use (key packages), or
                // stateful/ephemeral — must stay pinned to one relay.
                _ => FanOut::One,
            }
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
    #[test]
    fn fan_out_classification() {
        use super::p2p_client::FanOut;
        // Replicated to every relay.
        for r in [
            Request::Deposit(vec![1]),
            Request::PutBlob(vec![1]),
            Request::PublishPrekeys(vec![1]),
            Request::SubmitRecord(vec![1]),
        ] {
            assert!(matches!(FanOut::of(&r), FanOut::Write), "{r:?}");
        }
        // Merged across relays.
        assert!(matches!(
            FanOut::of(&Request::Fetch {
                hints: vec![],
                since_ms: 0
            }),
            FanOut::MergeEnvelopes
        ));
        // Pinned to one relay: seq-bearing, single-use, ephemeral, stateful.
        for r in [
            Request::PostToChannel {
                channel_id: [0; 32],
                blob: vec![1],
            },
            Request::FetchChannel {
                channel_id: [0; 32],
                since_seq: 0,
            },
            Request::GetKeyPackage([0; 32]),
            Request::GetTreeHead,
            Request::GetRecords { from: 0, to: 1 },
            Request::PostSignal {
                topic: [0; 32],
                blob: vec![1],
            },
            Request::GetBlob([0; 32]),
            Request::GetPrekeys([0; 32]),
        ] {
            assert!(matches!(FanOut::of(&r), FanOut::One), "{r:?}");
        }
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
