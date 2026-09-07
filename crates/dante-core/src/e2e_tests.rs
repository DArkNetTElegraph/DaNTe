//! End-to-end integration: two engines exchange real E2E direct messages
//! through an in-process relay.

use std::{net::Ipv4Addr, sync::Arc};

use dante_crypto::pow::Difficulty;
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
    Engine::connect(Identity::generate(1_000), relay, test_params(), D, None)
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
    let alice_id = *alice.identity().id().as_bytes();
    let bob_id = *bob.identity().id().as_bytes();

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
        .send_dm(&bob_id, "hello bob, this is alice", now)
        .await
        .unwrap();
    let got = bob.receive(now).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].from_idk, alice_idk);
    assert_eq!(got[0].text, "hello bob, this is alice");

    // Bob replies; ratchet advances.
    bob.send_dm(&alice_id, "hi alice!", now).await.unwrap();
    let got = alice.receive(now).await.unwrap();
    assert_eq!(
        got,
        vec![crate::ReceivedDm {
            from_idk: bob_idk,
            text: "hi alice!".into()
        }]
    );

    // A few more rounds.
    alice.send_dm(&bob_id, "how are you", now).await.unwrap();
    alice.send_dm(&bob_id, "still there?", now).await.unwrap();
    let got = bob.receive(now).await.unwrap();
    assert_eq!(
        got.iter().map(|d| d.text.clone()).collect::<Vec<_>>(),
        vec!["how are you", "still there?"]
    );

    // Re-polling returns nothing new (dedup).
    assert!(bob.receive(now).await.unwrap().is_empty());
}

#[tokio::test]
async fn alice_sends_bob_an_encrypted_file() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let alice_idk = alice.identity().sign_public().to_bytes();
    let bob_id = *bob.identity().id().as_bytes();

    for e in [&mut alice, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    alice.sync(now).await.unwrap();

    let file: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 256) as u8).collect();
    alice
        .send_file(&bob_id, "report.bin", &file, now)
        .await
        .unwrap();

    let inbound = bob.receive_all(now).await.unwrap();
    assert_eq!(inbound.len(), 1);
    match &inbound[0] {
        crate::Inbound::File {
            from_idk,
            filename,
            data,
        } => {
            assert_eq!(*from_idk, alice_idk);
            assert_eq!(filename, "report.bin");
            assert_eq!(*data, file);
        }
        other => panic!("expected a file, got {other:?}"),
    }
    // receive() (text-only view) hides it
    assert!(bob.receive(now).await.unwrap().is_empty());
}

#[tokio::test]
async fn bob_restarts_and_resumes_the_conversation_from_disk() {
    use dante_identity::keystore;

    let now = now_ms();
    let relay = spawn_relay().await;
    let dir = std::env::temp_dir().join(format!("dante-e2e-persist-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("bob.state");

    let mut alice = engine(&relay).await;
    let alice_id = *alice.identity().id().as_bytes();

    // A persistent Bob identity we can reload byte-for-byte via a keystore blob.
    let bob_ks = keystore::seal(&Identity::generate(now), b"pw").unwrap();
    let bob_id = *keystore::open(&bob_ks, b"pw").unwrap().id().as_bytes();

    {
        let bob_identity = keystore::open(&bob_ks, b"pw").unwrap();
        let mut bob = Engine::connect(bob_identity, &relay, test_params(), D, Some(store.clone()))
            .await
            .unwrap();
        for e in [&mut alice, &mut bob] {
            e.announce("", now).await.unwrap();
            e.publish_prekeys().await.unwrap();
        }
        alice.sync(now).await.unwrap();

        alice.send_dm(&bob_id, "before restart", now).await.unwrap();
        assert_eq!(bob.receive(now).await.unwrap()[0].text, "before restart");
        bob.persist().unwrap();
        assert_eq!(bob.history().len(), 1);
    } // bob dropped — simulates the process exiting

    // Bob comes back from disk.
    let bob_identity = keystore::open(&bob_ks, b"pw").unwrap();
    let mut bob = Engine::connect(bob_identity, &relay, test_params(), D, Some(store.clone()))
        .await
        .unwrap();
    assert_eq!(bob.history().len(), 1, "history restored");
    // Announced recently -> skips the PoW entirely.
    assert!(!bob.announce_if_stale("", now).await.unwrap());
    // The existing ratchet session decrypts a follow-up without a new handshake.
    alice.send_dm(&bob_id, "after restart", now).await.unwrap();
    assert_eq!(bob.receive(now).await.unwrap()[0].text, "after restart");
    assert_eq!(bob.history().len(), 2);

    let _ = alice_id;
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn host_and_member_exchange_channel_messages() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut alice = engine(&relay).await;
    let host_id = *host.identity().id().as_bytes();
    let alice_id = *alice.identity().id().as_bytes();

    for e in [&mut host, &mut alice] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    host.sync(now).await.unwrap();
    alice.sync(now).await.unwrap();

    // Host builds a server + channel and invites Alice.
    let server = host.create_server("the lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();
    host.invite_to_channel(&chan, &alice_id, now).await.unwrap();

    // Alice receives the invite (a DM) -> joins, replies with her key bundle.
    let inbound = alice.receive_all(now).await.unwrap();
    assert!(inbound.is_empty(), "control messages are not user-visible");
    assert_eq!(alice.channels().len(), 1);
    assert_eq!(alice.channels()[0].channel_name, "general");
    // Host receives Alice's KeyBundle.
    host.receive_all(now).await.unwrap();

    // Host posts to the channel; Alice reads it.
    host.send_channel(&chan, "welcome everyone", now)
        .await
        .unwrap();
    let msgs = alice.poll_channels(now).await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].sender, host_id);
    assert_eq!(msgs[0].text, "welcome everyone");
    assert_eq!(msgs[0].channel_id, chan);

    // Alice replies; host reads it (and does not see its own message).
    alice
        .send_channel(&chan, "thanks for the invite", now)
        .await
        .unwrap();
    let msgs = host.poll_channels(now).await.unwrap();
    assert_eq!(
        msgs.iter().map(|m| m.text.clone()).collect::<Vec<_>>(),
        vec!["thanks for the invite"]
    );
    assert_eq!(
        host.poll_channels(now).await.unwrap().len(),
        0,
        "no re-delivery"
    );
}

#[tokio::test]
async fn channel_typing_signals_reach_members_without_burning_the_chain() {
    use crate::{TypingEvent, TypingScope};

    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut alice = engine(&relay).await;
    let host_id = *host.identity().id().as_bytes();
    let alice_id = *alice.identity().id().as_bytes();

    for e in [&mut host, &mut alice] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    host.sync(now).await.unwrap();
    alice.sync(now).await.unwrap();

    let server = host.create_server("the lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();
    host.invite_to_channel(&chan, &alice_id, now).await.unwrap();
    alice.receive_all(now).await.unwrap();
    host.receive_all(now).await.unwrap();

    // Host types; Alice sees it, host does not see its own.
    host.send_typing_channel(&chan, now).await.unwrap();
    assert_eq!(
        alice.poll_typing(now).await.unwrap(),
        vec![TypingEvent {
            scope: TypingScope::Channel(chan),
            who: host_id,
            at_ms: now,
        }]
    );
    assert!(host.poll_typing(now).await.unwrap().is_empty());

    // The signal did not advance the sender chain: the next real message is
    // still iteration 0 and decrypts cleanly.
    host.send_channel(&chan, "first real message", now)
        .await
        .unwrap();
    let msgs = alice.poll_channels(now).await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].text, "first real message");

    // The other direction.
    alice.send_typing_channel(&chan, now).await.unwrap();
    assert_eq!(
        host.poll_typing(now).await.unwrap(),
        vec![TypingEvent {
            scope: TypingScope::Channel(chan),
            who: alice_id,
            at_ms: now,
        }]
    );
}

#[tokio::test]
async fn channel_history_survives_a_restart() {
    use dante_identity::keystore;

    let now = now_ms();
    let relay = spawn_relay().await;
    let dir = std::env::temp_dir().join(format!("dante-e2e-chan-persist-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("alice.state");

    let mut host = engine(&relay).await;
    let host_id = *host.identity().id().as_bytes();

    let alice_ks = keystore::seal(&Identity::generate(now), b"pw").unwrap();
    let alice_id = *keystore::open(&alice_ks, b"pw").unwrap().id().as_bytes();

    let chan;
    {
        let alice_identity = keystore::open(&alice_ks, b"pw").unwrap();
        let mut alice = Engine::connect(
            alice_identity,
            &relay,
            test_params(),
            D,
            Some(store.clone()),
        )
        .await
        .unwrap();
        for e in [&mut host, &mut alice] {
            e.announce("", now).await.unwrap();
            e.publish_prekeys().await.unwrap();
        }
        host.sync(now).await.unwrap();
        alice.sync(now).await.unwrap();

        let server = host.create_server("the lodge", now).await.unwrap();
        chan = host.create_channel(&server, "general", true).unwrap();
        host.invite_to_channel(&chan, &alice_id, now).await.unwrap();
        alice.receive_all(now).await.unwrap();
        host.receive_all(now).await.unwrap();

        host.send_channel(&chan, "welcome", now).await.unwrap();
        assert_eq!(alice.poll_channels(now).await.unwrap().len(), 1);
        alice
            .send_channel(&chan, "hi from alice", now)
            .await
            .unwrap();

        assert_eq!(alice.channel_history().len(), 2);
        alice.persist().unwrap();
    } // alice's process exits

    let alice_identity = keystore::open(&alice_ks, b"pw").unwrap();
    let alice = Engine::connect(
        alice_identity,
        &relay,
        test_params(),
        D,
        Some(store.clone()),
    )
    .await
    .unwrap();
    let hist = alice.channel_history();
    assert_eq!(hist.len(), 2, "channel history restored");
    assert_eq!(hist[0].channel_id, chan);
    assert!(!hist[0].outgoing);
    assert_eq!(hist[0].sender, host_id);
    assert_eq!(hist[0].text, "welcome");
    assert!(hist[1].outgoing);
    assert_eq!(hist[1].text, "hi from alice");

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn dm_typing_signals_reach_the_peer_only() {
    use crate::{TypingEvent, TypingScope};

    let now = now_ms();
    let relay = spawn_relay().await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let alice_idk = alice.identity().sign_public().to_bytes();
    let bob_idk = bob.identity().sign_public().to_bytes();
    let bob_id = *bob.identity().id().as_bytes();
    let alice_id = *alice.identity().id().as_bytes();

    for e in [&mut alice, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    alice.sync(now).await.unwrap();
    bob.sync(now).await.unwrap();

    // A first message each way so both hold a session for the other.
    alice.send_dm(&bob_id, "hi", now).await.unwrap();
    bob.receive(now).await.unwrap();
    bob.send_dm(&alice_id, "hey", now).await.unwrap();
    alice.receive(now).await.unwrap();

    // Nothing typed yet.
    assert!(bob.poll_typing(now).await.unwrap().is_empty());

    alice.send_typing_dm(&bob_id, now).await.unwrap();

    // Bob sees exactly Alice typing; Alice never sees her own signal.
    assert_eq!(
        bob.poll_typing(now).await.unwrap(),
        vec![TypingEvent {
            scope: TypingScope::Dm(alice_idk),
            who: alice_idk,
            at_ms: now,
        }]
    );
    assert!(alice.poll_typing(now).await.unwrap().is_empty());

    // The other direction works too.
    bob.send_typing_dm(&alice_id, now).await.unwrap();
    assert_eq!(
        alice.poll_typing(now).await.unwrap(),
        vec![TypingEvent {
            scope: TypingScope::Dm(bob_idk),
            who: bob_idk,
            at_ms: now,
        }]
    );
}

#[tokio::test]
async fn send_dm_to_unknown_peer_fails_until_synced() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let bob_id = *bob.identity().id().as_bytes();

    bob.announce("bob", now).await.unwrap();
    bob.publish_prekeys().await.unwrap();

    // Alice has not synced Bob's announce yet.
    assert!(matches!(
        alice.send_dm(&bob_id, "hi", now).await,
        Err(crate::CoreError::UnknownPeer)
    ));

    alice.sync(now).await.unwrap();
    alice.send_dm(&bob_id, "hi", now).await.unwrap();
    assert_eq!(bob.receive(now).await.unwrap()[0].text, "hi");
}
