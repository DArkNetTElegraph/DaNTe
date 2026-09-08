//! libp2p transport for DaNTe.
//!
//! This crate is deliberately **detached** from the root Cargo workspace (see the
//! comment at the top of `Cargo.toml`). It is Phase-3 groundwork for a
//! peer-to-peer control plane and is not yet wired into `dante-core`.
//!
//! [`Node`] wraps a libp2p [`Swarm`] driven by a background Tokio task. Callers
//! talk to it through async methods that post a [`Command`] and (where a reply is
//! meaningful) await a `oneshot`. Swarm events that matter to DaNTe surface on
//! the [`Event`] receiver returned by [`Node::spawn`].
//!
//! Roles:
//! * **Kademlia** ([`put_record`](Node::put_record) / [`get_record`](Node::get_record)) —
//!   the decentralised key directory: prekey bundles and identity-key records,
//!   keyed by the 32-byte DaNTe identity hash.
//! * **gossipsub** ([`publish`](Node::publish) / [`subscribe`](Node::subscribe)) —
//!   fan-out for append-only logs: the transparency ledger and channel relay
//!   logs.
//! * **identify** / **ping** — connection bring-up and liveness only.
//!
//! The sealed-sender mailbox stays on `dante-relay`: offline delivery inherently
//! needs a storage supernode and does not belong on the DHT.

use std::collections::HashMap;
use std::time::Duration;

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{
    gossipsub, identify,
    kad::{self, store::MemoryStore},
    noise, ping, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use tokio::sync::{mpsc, oneshot};

/// Protocol string announced over libp2p `identify`.
const IDENTIFY_PROTO: &str = "/dante/p2p/1.0.0";
/// Kademlia protocol name. Distinct from the public IPFS DHT so DaNTe nodes only
/// ever store and answer for DaNTe records.
const KAD_PROTO: &str = "/dante/kad/1.0.0";

#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    #[error("transport build: {0}")]
    Build(String),
    #[error("invalid multiaddr: {0}")]
    Addr(#[from] libp2p::multiaddr::Error),
    #[error("dial: {0}")]
    Dial(#[from] libp2p::swarm::DialError),
    #[error("listen: {0}")]
    Listen(String),
    #[error("gossipsub subscribe: {0}")]
    Subscribe(String),
    #[error("gossipsub publish: {0}")]
    Publish(String),
    #[error("kademlia store: {0}")]
    Store(String),
    #[error("the node event loop has stopped")]
    Gone,
}

/// Events the driver task pushes up to the owner of the [`Node`].
#[derive(Debug, Clone)]
pub enum Event {
    /// A socket address we are now accepting connections on.
    Listening(Multiaddr),
    /// A peer entered the routing table (via identify + Kademlia).
    PeerRoutable(PeerId),
    /// A gossipsub message arrived on a subscribed topic.
    Message {
        topic: String,
        source: Option<PeerId>,
        data: Vec<u8>,
    },
}

/// Reply channel for a completed `get_record` query.
type GetReply = oneshot::Sender<Result<Option<Vec<u8>>, P2pError>>;
/// Reply channel for a fire-and-forget DHT write / bootstrap round.
type AckReply = oneshot::Sender<Result<(), P2pError>>;

enum Command {
    Listen(Multiaddr, oneshot::Sender<Result<(), P2pError>>),
    Dial(Multiaddr, oneshot::Sender<Result<(), P2pError>>),
    AddAddress(PeerId, Multiaddr),
    Bootstrap(oneshot::Sender<Result<(), P2pError>>),
    PutRecord(Vec<u8>, Vec<u8>, oneshot::Sender<Result<(), P2pError>>),
    GetRecord(Vec<u8>, oneshot::Sender<Result<Option<Vec<u8>>, P2pError>>),
    Subscribe(String, oneshot::Sender<Result<(), P2pError>>),
    Publish(String, Vec<u8>, oneshot::Sender<Result<(), P2pError>>),
}

#[derive(libp2p::swarm::NetworkBehaviour)]
struct Behaviour {
    kad: kad::Behaviour<MemoryStore>,
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

/// A handle to a running libp2p node. Cloneable; the node lives until every
/// clone is dropped and the driver task then exits.
#[derive(Clone)]
pub struct Node {
    peer_id: PeerId,
    cmd: mpsc::Sender<Command>,
}

impl Node {
    /// Build a node whose libp2p identity is derived from a DaNTe Ed25519 secret
    /// (32 raw bytes), spawn its driver task on the current Tokio runtime, and
    /// return the handle plus the [`Event`] stream.
    pub fn spawn(ed25519_secret: &[u8; 32]) -> Result<(Self, mpsc::Receiver<Event>), P2pError> {
        let mut secret = *ed25519_secret;
        let keypair = libp2p::identity::Keypair::ed25519_from_bytes(&mut secret)
            .map_err(|e| P2pError::Build(e.to_string()))?;
        let peer_id = keypair.public().to_peer_id();

        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| P2pError::Build(e.to_string()))?
            .with_behaviour(|key| {
                let peer = key.public().to_peer_id();

                let mut kad_cfg = kad::Config::new(
                    libp2p::StreamProtocol::try_from_owned(KAD_PROTO.to_owned())
                        .expect("static protocol string is valid"),
                );
                kad_cfg.set_query_timeout(Duration::from_secs(30));
                let kad = kad::Behaviour::with_config(peer, MemoryStore::new(peer), kad_cfg);

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub::ConfigBuilder::default()
                        .heartbeat_interval(Duration::from_secs(1))
                        .validation_mode(gossipsub::ValidationMode::Strict)
                        .build()
                        .expect("valid gossipsub config"),
                )?;

                let identify = identify::Behaviour::new(identify::Config::new(
                    IDENTIFY_PROTO.to_owned(),
                    key.public(),
                ));

                Ok(Behaviour {
                    kad,
                    gossipsub,
                    identify,
                    ping: ping::Behaviour::default(),
                })
            })
            .map_err(|e| P2pError::Build(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Every DaNTe node is a full DHT participant (stores records, answers
        // queries). Without this, libp2p-kad stays in client mode until it
        // observes an external address, and `put_record` fails the quorum.
        swarm
            .behaviour_mut()
            .kad
            .set_mode(Some(kad::Mode::Server));

        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (evt_tx, evt_rx) = mpsc::channel(256);

        tokio::spawn(Driver::new(swarm, cmd_rx, evt_tx).run());

        Ok((
            Node {
                peer_id,
                cmd: cmd_tx,
            },
            evt_rx,
        ))
    }

    /// This node's libp2p [`PeerId`].
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    async fn call<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<T>) -> Command,
    ) -> Result<T, P2pError> {
        let (tx, rx) = oneshot::channel();
        self.cmd.send(make(tx)).await.map_err(|_| P2pError::Gone)?;
        rx.await.map_err(|_| P2pError::Gone)
    }

    /// Start listening on `addr` (e.g. `/ip4/0.0.0.0/tcp/0`).
    pub async fn listen(&self, addr: Multiaddr) -> Result<(), P2pError> {
        self.call(|tx| Command::Listen(addr, tx)).await?
    }

    /// Dial a peer by multiaddr.
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), P2pError> {
        self.call(|tx| Command::Dial(addr, tx)).await?
    }

    /// Teach Kademlia a peer's address without dialing it now.
    pub async fn add_address(&self, peer: PeerId, addr: Multiaddr) -> Result<(), P2pError> {
        self.cmd
            .send(Command::AddAddress(peer, addr))
            .await
            .map_err(|_| P2pError::Gone)
    }

    /// Run one Kademlia bootstrap round against the known routing table.
    pub async fn bootstrap(&self) -> Result<(), P2pError> {
        self.call(Command::Bootstrap).await?
    }

    /// Store `value` under `key` in the DHT.
    pub async fn put_record(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), P2pError> {
        self.call(|tx| Command::PutRecord(key, value, tx)).await?
    }

    /// Look `key` up in the DHT. `Ok(None)` means the query finished with no record.
    pub async fn get_record(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, P2pError> {
        self.call(|tx| Command::GetRecord(key, tx)).await?
    }

    /// Subscribe to a gossipsub topic; matching messages arrive as [`Event::Message`].
    pub async fn subscribe(&self, topic: &str) -> Result<(), P2pError> {
        let topic = topic.to_owned();
        self.call(|tx| Command::Subscribe(topic, tx)).await?
    }

    /// Publish `data` to a gossipsub topic.
    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> Result<(), P2pError> {
        let topic = topic.to_owned();
        self.call(|tx| Command::Publish(topic, data, tx)).await?
    }
}

struct Driver {
    swarm: Swarm<Behaviour>,
    cmd_rx: mpsc::Receiver<Command>,
    evt_tx: mpsc::Sender<Event>,
    pending_put: HashMap<kad::QueryId, AckReply>,
    pending_get: HashMap<kad::QueryId, GetReply>,
    pending_bootstrap: HashMap<kad::QueryId, AckReply>,
}

impl Driver {
    fn new(
        swarm: Swarm<Behaviour>,
        cmd_rx: mpsc::Receiver<Command>,
        evt_tx: mpsc::Sender<Event>,
    ) -> Self {
        Driver {
            swarm,
            cmd_rx,
            evt_tx,
            pending_put: HashMap::new(),
            pending_get: HashMap::new(),
            pending_bootstrap: HashMap::new(),
        }
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(cmd) => self.on_command(cmd),
                    None => break, // every Node handle dropped
                },
                event = self.swarm.select_next_some() => self.on_swarm_event(event).await,
            }
        }
    }

    fn on_command(&mut self, cmd: Command) {
        match cmd {
            Command::Listen(addr, reply) => {
                let r = self
                    .swarm
                    .listen_on(addr)
                    .map(|_| ())
                    .map_err(|e| P2pError::Listen(e.to_string()));
                let _ = reply.send(r);
            }
            Command::Dial(addr, reply) => {
                let r = self.swarm.dial(addr).map_err(P2pError::Dial);
                let _ = reply.send(r);
            }
            Command::AddAddress(peer, addr) => {
                self.swarm.behaviour_mut().kad.add_address(&peer, addr);
            }
            Command::Bootstrap(reply) => match self.swarm.behaviour_mut().kad.bootstrap() {
                Ok(id) => {
                    self.pending_bootstrap.insert(id, reply);
                }
                Err(e) => {
                    let _ = reply.send(Err(P2pError::Store(e.to_string())));
                }
            },
            Command::PutRecord(key, value, reply) => {
                let record = kad::Record::new(kad::RecordKey::new(&key), value);
                match self
                    .swarm
                    .behaviour_mut()
                    .kad
                    .put_record(record, kad::Quorum::One)
                {
                    Ok(id) => {
                        self.pending_put.insert(id, reply);
                    }
                    Err(e) => {
                        let _ = reply.send(Err(P2pError::Store(e.to_string())));
                    }
                }
            }
            Command::GetRecord(key, reply) => {
                let id = self
                    .swarm
                    .behaviour_mut()
                    .kad
                    .get_record(kad::RecordKey::new(&key));
                self.pending_get.insert(id, reply);
            }
            Command::Subscribe(topic, reply) => {
                let t = gossipsub::IdentTopic::new(topic);
                let r = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&t)
                    .map(|_| ())
                    .map_err(|e| P2pError::Subscribe(e.to_string()));
                let _ = reply.send(r);
            }
            Command::Publish(topic, data, reply) => {
                let t = gossipsub::IdentTopic::new(topic);
                let r = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(t, data)
                    .map(|_| ())
                    .map_err(|e| P2pError::Publish(e.to_string()));
                let _ = reply.send(r);
            }
        }
    }

    async fn emit(&mut self, e: Event) {
        let _ = self.evt_tx.send(e).await;
    }

    async fn on_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                self.emit(Event::Listening(address)).await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                // Feed identify's address book into Kademlia so the DHT can route.
                for addr in info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer_id, addr);
                }
                self.emit(Event::PeerRoutable(peer_id)).await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                ..
            })) => {
                self.emit(Event::Message {
                    topic: message.topic.into_string(),
                    source: message.source,
                    data: message.data,
                })
                .await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                id,
                result,
                step,
                ..
            })) => self.on_kad_result(id, result, step.last),
            _ => {}
        }
    }

    fn on_kad_result(&mut self, id: kad::QueryId, result: kad::QueryResult, last: bool) {
        match result {
            kad::QueryResult::PutRecord(res) => {
                if let Some(reply) = self.pending_put.remove(&id) {
                    let _ = reply.send(res.map(|_| ()).map_err(|e| P2pError::Store(e.to_string())));
                }
            }
            kad::QueryResult::Bootstrap(res) => {
                // Bootstrap progresses in steps; only answer on the final one.
                if last {
                    if let Some(reply) = self.pending_bootstrap.remove(&id) {
                        let _ = reply
                            .send(res.map(|_| ()).map_err(|e| P2pError::Store(e.to_string())));
                    }
                }
            }
            kad::QueryResult::GetRecord(res) => match res {
                Ok(kad::GetRecordOk::FoundRecord(peer_record)) => {
                    if let Some(reply) = self.pending_get.remove(&id) {
                        let _ = reply.send(Ok(Some(peer_record.record.value)));
                    }
                }
                Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => {
                    // Query ended and we never took a FoundRecord out of the map.
                    if let Some(reply) = self.pending_get.remove(&id) {
                        let _ = reply.send(Ok(None));
                    }
                }
                Err(e) => {
                    if let Some(reply) = self.pending_get.remove(&id) {
                        let _ = reply.send(Err(P2pError::Store(e.to_string())));
                    }
                }
            },
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// Wait for the first listen address a node reports.
    async fn first_listen_addr(rx: &mut mpsc::Receiver<Event>) -> Multiaddr {
        loop {
            match rx.recv().await.expect("event stream open") {
                Event::Listening(a) => return a,
                _ => continue,
            }
        }
    }

    #[tokio::test]
    async fn two_nodes_dial_and_gossip() {
        let (a, mut a_rx) = Node::spawn(&secret(1)).expect("spawn a");
        let (b, mut b_rx) = Node::spawn(&secret(2)).expect("spawn b");

        a.listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .await
            .expect("a listen");
        let a_addr = first_listen_addr(&mut a_rx).await;

        b.subscribe("dante/test").await.expect("b subscribe");
        a.subscribe("dante/test").await.expect("a subscribe");

        b.dial(a_addr).await.expect("b dial a");

        // Let the mesh form.
        tokio::time::sleep(Duration::from_millis(800)).await;

        // Retry: gossipsub needs the mesh established before publish reaches peers.
        let mut got = None;
        for _ in 0..20 {
            let _ = a.publish("dante/test", b"ping".to_vec()).await;
            tokio::select! {
                ev = b_rx.recv() => {
                    if let Some(Event::Message { data, topic, .. }) = ev {
                        assert_eq!(topic, "dante/test");
                        got = Some(data);
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(200)) => {}
            }
        }
        assert_eq!(got.as_deref(), Some(&b"ping"[..]), "gossip message delivered");
    }

    #[tokio::test]
    async fn a_record_put_on_one_node_is_found_by_a_peer() {
        let (a, mut a_rx) = Node::spawn(&secret(3)).expect("spawn a");
        let (b, mut b_rx) = Node::spawn(&secret(4)).expect("spawn b");

        a.listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .await
            .expect("a listen");
        let a_addr = first_listen_addr(&mut a_rx).await;
        b.listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .await
            .expect("b listen");
        let _ = first_listen_addr(&mut b_rx).await;

        b.add_address(a.peer_id(), a_addr.clone()).await.unwrap();
        b.dial(a_addr).await.expect("b dial a");

        // Wait until identify has made the peer routable on b.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(Event::PeerRoutable(_)) = b_rx.recv().await {
                    return;
                }
            }
        })
        .await
        .expect("b sees a routable peer");

        let _ = b.bootstrap().await;

        let key = b"dante/idk/aaaa".to_vec();
        let val = b"prekey-bundle-bytes".to_vec();
        b.put_record(key.clone(), val.clone())
            .await
            .expect("b put_record");

        // a should be able to resolve it from the DHT.
        let mut found = None;
        for _ in 0..20 {
            if let Ok(Some(v)) = a.get_record(key.clone()).await {
                found = Some(v);
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert_eq!(found.as_deref(), Some(&val[..]), "record resolved via DHT");
    }
}
