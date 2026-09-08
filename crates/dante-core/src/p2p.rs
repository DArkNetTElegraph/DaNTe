//! Optional libp2p support (Cargo feature `p2p`).
//!
//! Two roles:
//!
//! * **Key-directory fallback (Kademlia).** When the relay has no prekey bundle
//!   for a peer, the engine looks it up on the DHT. Bundles are mirrored onto
//!   the DHT on every `publish_prekeys`.
//! * **Ledger gossip (gossipsub).** New identity records (`announce` /
//!   `prove_liveness` / `revoke`) are also published to a shared topic;
//!   `Engine::poll_p2p` folds records heard from peers into the local replica.
//!   This is an accelerant, not a source of truth — the relay remains the
//!   authoritative, ordered log and the only sealed-sender mailbox.

use std::time::Duration;

use dante_p2p::{Event, Node};
use tokio::sync::mpsc;

use crate::error::CoreError;

/// Gossipsub topic carrying encoded ledger [`Record`](dante_proto::record::Record)s.
pub(crate) const LEDGER_TOPIC: &str = "dante/ledger/v1";

/// Kademlia record key for an identity's prekey bundle: a fixed tag followed by
/// the 32-byte `IdentityId`.
pub(crate) fn prekey_key(identity_id: &[u8; 32]) -> Vec<u8> {
    const TAG: &[u8] = b"dante/prekey/v1:";
    let mut k = Vec::with_capacity(TAG.len() + 32);
    k.extend_from_slice(TAG);
    k.extend_from_slice(identity_id);
    k
}

fn p2p_err(e: dante_p2p::P2pError) -> CoreError {
    CoreError::P2p(e.to_string())
}

/// A running libp2p node plus the addresses it accepts connections on.
pub(crate) struct P2p {
    node: Node,
    listen_addrs: Vec<String>,
    events: mpsc::Receiver<Event>,
}

impl P2p {
    /// Spawn a node from `seed` (a 32-byte ed25519 seed — use
    /// `Identity::p2p_node_seed`), start listening on `listen` (a multiaddr such
    /// as `/ip4/0.0.0.0/tcp/0`), dial each `bootstrap` multiaddr, and run one
    /// Kademlia bootstrap round.
    pub(crate) async fn start(
        seed: &[u8; 32],
        listen: &str,
        bootstrap: &[String],
    ) -> Result<Self, CoreError> {
        let (node, mut events) = Node::spawn(seed).map_err(p2p_err)?;
        node.listen_str(listen).await.map_err(p2p_err)?;
        node.subscribe(LEDGER_TOPIC).await.map_err(p2p_err)?;

        // Collect the concrete listen addresses the OS assigned (needed so a
        // caller can advertise them). Events after this stay in the channel for
        // `Engine::poll_p2p` to drain; the swarm driver drops events rather than
        // block if that falls behind, so nothing stalls.
        let mut listen_addrs = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(600), events.recv()).await {
                Ok(Some(Event::Listening(a))) => {
                    let a = a.to_string();
                    if !listen_addrs.contains(&a) {
                        listen_addrs.push(a);
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => return Err(CoreError::P2p("node event loop stopped".into())),
                Err(_) => break, // no more addresses forthcoming
            }
        }

        for b in bootstrap {
            if let Err(e) = node.dial_str(b).await {
                tracing::warn!(addr = %b, error = %e, "p2p: bootstrap dial failed");
            }
        }
        let _ = node.bootstrap().await;

        Ok(P2p {
            node,
            listen_addrs,
            events,
        })
    }

    /// Mirror a prekey bundle onto the DHT. Best-effort.
    pub(crate) async fn put_prekey(&self, identity_id: &[u8; 32], bundle: &[u8]) {
        if let Err(e) = self
            .node
            .put_record(prekey_key(identity_id), bundle.to_vec())
            .await
        {
            tracing::debug!(error = %e, "p2p: prekey put_record failed");
        }
    }

    /// Resolve a prekey bundle from the DHT. `None` = not found / query failed.
    pub(crate) async fn get_prekey(&self, identity_id: &[u8; 32]) -> Option<Vec<u8>> {
        match self.node.get_record(prekey_key(identity_id)).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "p2p: prekey get_record failed");
                None
            }
        }
    }

    /// Broadcast an encoded ledger record to peers. Best-effort.
    pub(crate) async fn publish_ledger(&self, record: Vec<u8>) {
        if let Err(e) = self.node.publish(LEDGER_TOPIC, record).await {
            tracing::debug!(error = %e, "p2p: ledger publish failed");
        }
    }

    /// Non-blocking: take every ledger record heard from peers since the last
    /// call. Other event kinds are discarded.
    pub(crate) fn drain_ledger_records(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Ok(ev) = self.events.try_recv() {
            if let Event::Message { topic, data, .. } = ev {
                if topic == LEDGER_TOPIC {
                    out.push(data);
                }
            }
        }
        out
    }

    /// This node's `PeerId`, rendered as a string.
    pub(crate) fn peer_id(&self) -> String {
        self.node.peer_id().to_string()
    }

    /// Full dialable multiaddrs, each ending `/p2p/<peer-id>` — what another
    /// node passes as `bootstrap`.
    pub(crate) fn dial_addrs(&self) -> Vec<String> {
        let pid = self.peer_id();
        self.listen_addrs
            .iter()
            .map(|a| format!("{a}/p2p/{pid}"))
            .collect()
    }
}
