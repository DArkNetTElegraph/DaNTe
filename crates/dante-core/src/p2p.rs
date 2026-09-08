//! Optional libp2p support (Cargo feature `p2p`).
//!
//! A Kademlia DHT used as a **decentralised key-directory fallback**: when the
//! relay has no prekey bundle for a peer, the engine looks it up here. Prekey
//! bundles are also mirrored onto the DHT on every `publish_prekeys`, so a
//! client that has a DHT route can reach a peer whose relay it does not share.
//!
//! The relay stays primary and is the only path for the sealed-sender mailbox
//! (offline delivery needs a storage supernode). Gossip fan-out of the ledger
//! and channel logs is future work — see `docs/DESIGN.md` Phase 3.

use std::time::Duration;

use dante_p2p::Node;

use crate::error::CoreError;

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

        // Collect the concrete listen addresses the OS assigned (needed so a
        // caller can advertise them), then hand the event stream to a drain
        // task — the driver's `emit` awaits on this channel, so it must always
        // be consumed or the node stalls.
        let mut listen_addrs = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(600), events.recv()).await {
                Ok(Some(dante_p2p::Event::Listening(a))) => {
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
        tokio::spawn(async move { while events.recv().await.is_some() {} });

        for b in bootstrap {
            if let Err(e) = node.dial_str(b).await {
                tracing::warn!(addr = %b, error = %e, "p2p: bootstrap dial failed");
            }
        }
        let _ = node.bootstrap().await;

        Ok(P2p { node, listen_addrs })
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
