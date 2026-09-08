//! An optional in-process TURN server (`--turn-listen`), so a single
//! `dante-relay` gives calls NAT traversal with no separate coturn.
//!
//! It uses the standard time-windowed `use-auth-secret` scheme — the same
//! `--turn-secret` this relay hands to clients in [`Request::GetIceConfig`], and
//! the same scheme a stock coturn verifies — so operators can run either.

use std::{net::IpAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use turn::{
    auth::LongTermAuthHandler,
    relay::relay_static::RelayAddressGeneratorStatic,
    server::{
        config::{ConnConfig, ServerConfig},
        Server,
    },
};
use webrtc_util::vnet::net::Net;

/// A running TURN server. Dropping it does not stop the background tasks; call
/// [`TurnServer::close`].
pub struct TurnServer {
    inner: Server,
}

impl TurnServer {
    /// Bind `listen` (UDP) and start serving. `public_ip` is the address put
    /// into the `XOR-RELAYED-ADDRESS` the server reports to clients (and into
    /// the `turn:` URL the relay advertises), so it must be reachable by the
    /// call peers. `secret` is the `use-auth-secret` shared secret.
    pub async fn start(
        listen: &str,
        public_ip: IpAddr,
        realm: &str,
        secret: String,
    ) -> Result<Self> {
        let udp = tokio::net::UdpSocket::bind(listen)
            .await
            .with_context(|| format!("binding TURN UDP {listen}"))?;

        let inner = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn: Arc::new(udp),
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: public_ip,
                    address: "0.0.0.0".to_owned(),
                    net: Arc::new(Net::new(None)),
                }),
            }],
            realm: realm.to_owned(),
            auth_handler: Arc::new(LongTermAuthHandler::new(secret)),
            channel_bind_timeout: Duration::from_secs(600),
            alloc_close_notify: None,
        })
        .await
        .map_err(|e| anyhow::anyhow!("TURN server: {e}"))?;

        Ok(Self { inner })
    }

    /// Stop the server and free its allocations.
    pub async fn close(&self) {
        let _ = self.inner.close().await;
    }
}
