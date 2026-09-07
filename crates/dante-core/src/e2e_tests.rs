//! End-to-end integration: two engines exchange real E2E direct messages
//! through an in-process relay.

use std::{net::Ipv4Addr, sync::Arc};

use dante_crypto::pow::Difficulty;
use dante_dm::PreKeySecrets;
use dante_identity::Identity;
use dante_ledger::LedgerParams;
use dante_net::transport::serve;
use dante_relay::state::{Limits, RelayHandler, RelayState};
use tokio::net::TcpListener;

use crate::engine::Engine;

const D: Difficulty = Difficulty {
    m_cost_kib: 32,
    t_cost: 1,
    bits: 8,
};

/// Real wall clock — the relay checks records against its own `SystemTime`, so
/// tests must use a timestamp within its clock-skew window.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn test_params() -> LedgerParams {
    LedgerParams {
        min_announce_pow_bits: 8,
        min_liveness_pow_bits: 8,
        ..Default::default()
    }
}

async fn spawn_relay() -> String {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(RelayHandler::new(RelayState::new(
        test_params(),
        Limits::default(),
    )));
    tokio::spawn(serve(listener, handler));
    addr.to_string()
}

async fn engine(relay: &str) -> Engine {
    Engine::connect(
        Identity::generate(1_000),
        PreKeySecrets::generate(8),
        relay,
        test_params(),
        D,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn two_engines_exchange_e2e_dms_through_a_relay() {
    let now = now_ms();
    let relay = spawn_relay().await;

    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let alice_idk = alice.identity().sign_public().to_bytes();
    let bob_idk = bob.identity().sign_public().to_bytes();

    // Both announce and publish prekeys.
    alice.announce("alice", now).await.unwrap();
    bob.announce("bob", now).await.unwrap();
    alice.publish_prekeys().await.unwrap();
    bob.publish_prekeys().await.unwrap();

    // Each syncs the key directory from the relay.
    assert!(alice.sync(now).await.unwrap() >= 1);
    assert!(bob.sync(now).await.unwrap() >= 1);
    assert!(alice.knows(&bob_idk));
    assert!(bob.knows(&alice_idk));

    // Alice opens the conversation.
    alice
        .send_dm(&bob_idk, "hello bob, this is alice", now)
        .await
        .unwrap();
    let got = bob.receive(now).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].from_idk, alice_idk);
    assert_eq!(got[0].text, "hello bob, this is alice");

    // Bob replies; ratchet advances.
    bob.send_dm(&alice_idk, "hi alice!", now).await.unwrap();
    let got = alice.receive(now).await.unwrap();
    assert_eq!(
        got,
        vec![crate::ReceivedDm {
            from_idk: bob_idk,
            text: "hi alice!".into()
        }]
    );

    // A few more rounds.
    alice.send_dm(&bob_idk, "how are you", now).await.unwrap();
    alice.send_dm(&bob_idk, "still there?", now).await.unwrap();
    let got = bob.receive(now).await.unwrap();
    assert_eq!(
        got.iter().map(|d| d.text.clone()).collect::<Vec<_>>(),
        vec!["how are you", "still there?"]
    );

    // Re-polling returns nothing new (dedup).
    assert!(bob.receive(now).await.unwrap().is_empty());
}

#[tokio::test]
async fn send_dm_to_unknown_peer_fails_until_synced() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let bob_idk = bob.identity().sign_public().to_bytes();

    bob.announce("bob", now).await.unwrap();
    bob.publish_prekeys().await.unwrap();

    // Alice has not synced Bob's announce yet.
    assert!(matches!(
        alice.send_dm(&bob_idk, "hi", now).await,
        Err(crate::CoreError::UnknownPeer)
    ));

    alice.sync(now).await.unwrap();
    alice.send_dm(&bob_idk, "hi", now).await.unwrap();
    assert_eq!(bob.receive(now).await.unwrap()[0].text, "hi");
}
