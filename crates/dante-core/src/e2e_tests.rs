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
    spawn_relay_with_ice(dante_relay::state::IcePolicy::default()).await
}

async fn spawn_relay_with_ice(ice: dante_relay::state::IcePolicy) -> String {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut state = RelayState::new(test_params(), Limits::default());
    state.set_ice_policy(ice);
    let handler = Arc::new(RelayHandler::new(state));
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
async fn engine_learns_ice_servers_from_the_relay() {
    let ice = dante_relay::state::IcePolicy {
        stun: vec!["stun:stun.example.org:3478".into()],
        turn: vec!["turn:turn.example.org:3478?transport=udp".into()],
        turn_secret: Some("a-shared-secret".into()),
        turn_ttl_secs: 600,
    };
    let relay = spawn_relay_with_ice(ice).await;
    let e = engine(&relay).await;

    let servers = e.ice_servers();
    assert_eq!(servers.len(), 2, "STUN + TURN");
    assert_eq!(
        servers[0].urls,
        vec!["stun:stun.example.org:3478".to_string()]
    );
    assert!(servers[0].username.is_empty());

    // coturn `use-auth-secret`: username = future Unix-seconds expiry,
    // credential = base64(HMAC-SHA1(secret, username)).
    let turn = &servers[1];
    assert!(turn.urls[0].starts_with("turn:"));
    let expiry: u64 = turn.username.parse().expect("numeric expiry username");
    let now_s = now_ms() / 1000;
    assert!(expiry > now_s && expiry <= now_s + 601);
    assert_eq!(turn.credential.len(), 28, "base64 of a 20-byte SHA-1 HMAC");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_one_to_one_call_connects_over_dm_signalling() {
    use crate::CallState;

    let now = now_ms();
    let relay = spawn_relay().await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let alice_id = *alice.identity().id().as_bytes();
    let bob_id = *bob.identity().id().as_bytes();

    for e in [&mut alice, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    for e in [&mut alice, &mut bob] {
        e.sync(now).await.unwrap();
    }

    // Alice rings Bob. The offer goes as a sealed-sender ratchet DM.
    alice.start_call(&bob_id, now).await.unwrap();

    // Pump both engines: receive_all carries offer/answer/ICE, poll_calls
    // relays locally-gathered candidates back out.
    let mut bob_saw_ring = false;
    let mut connected = false;
    for _ in 0..300 {
        for it in bob.receive_all(now).await.unwrap() {
            if matches!(it, crate::Inbound::IncomingCall { .. }) && !bob_saw_ring {
                bob_saw_ring = true;
                bob.accept_call(&alice_id, now).await.unwrap();
            }
        }
        alice.receive_all(now).await.unwrap();
        alice.poll_calls(now).await.unwrap();
        bob.poll_calls(now).await.unwrap();

        if alice.call_state(&bob_id) == Some(CallState::Connected)
            && bob.call_state(&alice_id) == Some(CallState::Connected)
        {
            connected = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(bob_saw_ring, "Bob got the IncomingCall");
    assert!(connected, "both ends reached CallState::Connected");
    assert!(alice.in_call(&bob_id) && bob.in_call(&alice_id));

    // Audio rides the negotiated Opus track: Alice pushes a frame, Bob receives
    // it through SRTP (the bytes are opaque to the transport).
    let mut bob_heard_audio = false;
    for _ in 0..400 {
        for _ in 0..3 {
            alice
                .send_call_audio(&bob_id, b"opus-frame-payload", 20)
                .await
                .unwrap();
        }
        bob.poll_calls(now).await.unwrap();
        if bob
            .take_call_audio(&alice_id)
            .iter()
            .any(|f| f == b"opus-frame-payload")
        {
            bob_heard_audio = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(bob_heard_audio, "Bob received Alice's audio frame");

    // Alice hangs up; Bob sees it and both tear down.
    alice.hangup(&bob_id, now).await.unwrap();
    let mut bob_saw_end = false;
    for _ in 0..40 {
        for it in bob.receive_all(now).await.unwrap() {
            if matches!(it, crate::Inbound::CallEnded { .. }) {
                bob_saw_end = true;
            }
        }
        if bob_saw_end {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(bob_saw_end, "Bob saw the hang-up");
    assert!(!alice.in_call(&bob_id) && !bob.in_call(&alice_id));
}

#[tokio::test]
async fn a_revoked_identity_can_no_longer_be_messaged() {
    use dante_identity::RevokeReason;

    let now = now_ms();
    let relay = spawn_relay().await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let bob_idk = bob.identity().sign_public().to_bytes();
    let bob_id = *bob.identity().id().as_bytes();

    for e in [&mut alice, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    alice.sync(now).await.unwrap();
    alice.send_dm(&bob_id, "hi bob", now).await.unwrap();
    assert_eq!(bob.receive(now).await.unwrap()[0].text, "hi bob");

    // Bob's key is compromised — he revokes it.
    bob.revoke_identity(RevokeReason::Compromised, now + 1_000)
        .await
        .unwrap();

    // Alice picks the revocation up on her next sync and refuses to send,
    // even though she already holds a ratchet session with Bob.
    assert!(alice.sync(now + 2_000).await.unwrap() >= 1);
    assert!(alice.is_revoked(&bob_idk));
    assert!(matches!(
        alice.send_dm(&bob_id, "you there?", now + 2_000).await,
        Err(crate::CoreError::UnknownPeer)
    ));

    // Bob himself can no longer prove liveness on the dead chain.
    assert!(bob.prove_liveness(now + 3_000).await.is_err());
}

#[tokio::test]
async fn safety_numbers_match_on_both_ends_and_verification_persists() {
    use dante_identity::keystore;

    let now = now_ms();
    let relay = spawn_relay().await;
    let dir = std::env::temp_dir().join(format!("dante-e2e-safety-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("alice.state");

    let mut bob = engine(&relay).await;
    let bob_id = *bob.identity().id().as_bytes();

    let alice_ks = keystore::seal(&Identity::generate(now), b"pw").unwrap();
    let alice_number;
    {
        let mut alice = Engine::connect(
            keystore::open(&alice_ks, b"pw").unwrap(),
            &relay,
            test_params(),
            D,
            Some(store.clone()),
        )
        .await
        .unwrap();
        let alice_id = *alice.identity().id().as_bytes();
        for e in [&mut alice, &mut bob] {
            e.announce("", now).await.unwrap();
            e.publish_prekeys().await.unwrap();
        }
        alice.sync(now).await.unwrap();
        bob.sync(now).await.unwrap();

        alice_number = alice.safety_number(&bob_id).unwrap();
        // Order-independent: Bob derives the identical string for Alice.
        assert_eq!(bob.safety_number(&alice_id).unwrap(), alice_number);
        // 12 groups of 5 digits.
        assert_eq!(alice_number.split(' ').count(), 12);
        assert!(alice_number
            .split(' ')
            .all(|g| g.len() == 5 && g.bytes().all(|b| b.is_ascii_digit())));

        assert!(!alice.is_verified(&bob_id));
        alice.set_verified(&bob_id, true).unwrap();
        assert!(alice.is_verified(&bob_id));
        alice.persist().unwrap();
    }

    let mut alice = Engine::connect(
        keystore::open(&alice_ks, b"pw").unwrap(),
        &relay,
        test_params(),
        D,
        Some(store.clone()),
    )
    .await
    .unwrap();
    alice.sync(now).await.unwrap();
    assert!(
        alice.is_verified(&bob_id),
        "verification survived the restart"
    );
    assert_eq!(alice.safety_number(&bob_id).unwrap(), alice_number);

    std::fs::remove_dir_all(&dir).ok();
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
async fn three_channel_members_all_key_each_other() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let alice_id = *alice.identity().id().as_bytes();
    let bob_id = *bob.identity().id().as_bytes();

    for e in [&mut host, &mut alice, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    for e in [&mut host, &mut alice, &mut bob] {
        e.sync(now).await.unwrap();
    }

    let server = host.create_server("lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();
    host.invite_to_channel(&chan, &alice_id, now).await.unwrap();
    host.invite_to_channel(&chan, &bob_id, now).await.unwrap();

    // Let the invite + bundle-exchange settle.
    for _ in 0..8 {
        for e in [&mut host, &mut alice, &mut bob] {
            e.sync(now).await.unwrap();
            e.receive_all(now).await.unwrap();
        }
    }
    assert!(
        alice.channels().iter().any(|c| c.channel_id == chan),
        "alice joined"
    );
    assert!(
        bob.channels().iter().any(|c| c.channel_id == chan),
        "bob joined"
    );

    // Alice posts; BOTH host and bob decrypt it (bob<->alice were never
    // directly introduced by the host).
    alice
        .send_channel(&chan, "hello from alice", now)
        .await
        .unwrap();
    assert_eq!(
        bob.poll_channels(now)
            .await
            .unwrap()
            .first()
            .map(|m| m.text.clone()),
        Some("hello from alice".to_string())
    );
    assert_eq!(
        host.poll_channels(now)
            .await
            .unwrap()
            .first()
            .map(|m| m.text.clone()),
        Some("hello from alice".to_string())
    );

    // And a typing signal from bob reaches alice.
    bob.send_typing_channel(&chan, now).await.unwrap();
    let ev = alice.poll_typing(now).await.unwrap();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].who, bob_id);
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

#[tokio::test]
async fn invite_link_redeem_flow_with_use_limit() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut joiner = engine(&relay).await;
    let mut latecomer = engine(&relay).await;

    for e in [&mut host, &mut joiner, &mut latecomer] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    for e in [&mut host, &mut joiner, &mut latecomer] {
        e.sync(now).await.unwrap();
    }

    let server = host.create_server("lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();

    // A one-use link.
    let link = host.create_invite_link(&chan, 3_600_000, 1, now).unwrap();
    assert!(link.starts_with("dante-invite:"));

    // Joiner redeems -> DMs the host a request.
    joiner.redeem_invite(&link, None, now).await.unwrap();
    // Host processes it and invites the joiner; settle the bundle exchange.
    for _ in 0..4 {
        for e in [&mut host, &mut joiner] {
            e.receive_all(now).await.unwrap();
        }
    }
    assert!(
        joiner.channels().iter().any(|c| c.channel_id == chan),
        "joiner is in the channel"
    );
    host.send_channel(&chan, "welcome", now).await.unwrap();
    assert_eq!(
        joiner
            .poll_channels(now)
            .await
            .unwrap()
            .first()
            .map(|m| m.text.clone()),
        Some("welcome".to_string())
    );

    // The link is spent: a second person redeeming it never joins.
    latecomer.redeem_invite(&link, None, now).await.unwrap();
    for _ in 0..4 {
        for e in [&mut host, &mut latecomer] {
            e.receive_all(now).await.unwrap();
        }
    }
    assert!(
        latecomer.channels().is_empty(),
        "spent link does not admit a second member"
    );
}

#[tokio::test]
async fn forged_invite_link_is_rejected() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut joiner = engine(&relay).await;
    joiner.announce("", now).await.unwrap();

    // A token signed by a key that is not any server root.
    use dante_crypto::sign::SignSecret;
    let bogus = SignSecret::from_bytes(&[3u8; 32]);
    let mut tok =
        crate::InviteToken::mint(&bogus, [1u8; 32], [2u8; 32], "", now + 10_000, 0, [4u8; 8]);
    // valid self-consistent sig, then claim someone else's server key
    tok.server_root = SignSecret::from_bytes(&[9u8; 32]).public().to_bytes();

    assert!(matches!(
        joiner.redeem_invite(&tok.to_link(), None, now).await,
        Err(crate::CoreError::Invite(_))
    ));
}

#[tokio::test]
async fn host_removes_a_member_from_a_channel() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let alice_id = *alice.identity().id().as_bytes();
    let bob_id = *bob.identity().id().as_bytes();

    for e in [&mut host, &mut alice, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    for e in [&mut host, &mut alice, &mut bob] {
        e.sync(now).await.unwrap();
    }

    let server = host.create_server("lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();
    host.invite_to_channel(&chan, &alice_id, now).await.unwrap();
    host.invite_to_channel(&chan, &bob_id, now).await.unwrap();
    for _ in 0..8 {
        for e in [&mut host, &mut alice, &mut bob] {
            e.receive_all(now).await.unwrap();
        }
    }

    // Everyone can read the host before the kick.
    host.send_channel(&chan, "before", now).await.unwrap();
    for e in [&mut alice, &mut bob] {
        assert_eq!(
            e.poll_channels(now)
                .await
                .unwrap()
                .first()
                .map(|m| m.text.clone()),
            Some("before".to_string())
        );
    }

    // Host kicks Bob (host only).
    assert!(matches!(
        alice.remove_from_channel(&chan, &bob_id, now).await,
        Err(crate::CoreError::NotServerHost)
    ));
    host.remove_from_channel(&chan, &bob_id, now).await.unwrap();
    for _ in 0..6 {
        for e in [&mut host, &mut alice, &mut bob] {
            e.receive_all(now).await.unwrap();
        }
    }

    // Post-kick: Alice still reads the host; Bob is locked out.
    host.send_channel(&chan, "after the kick", now)
        .await
        .unwrap();
    assert_eq!(
        alice
            .poll_channels(now)
            .await
            .unwrap()
            .first()
            .map(|m| m.text.clone()),
        Some("after the kick".to_string())
    );
    assert!(
        bob.poll_channels(now).await.unwrap().is_empty(),
        "removed member cannot decrypt new messages"
    );

    // And Bob is muted: his messages are dropped by the others.
    bob.send_channel(&chan, "let me back in", now)
        .await
        .unwrap();
    assert!(host.poll_channels(now).await.unwrap().is_empty());
    assert!(alice.poll_channels(now).await.unwrap().is_empty());
}

#[tokio::test]
async fn inactivity_auto_kick() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut alice = engine(&relay).await;
    let alice_id = *alice.identity().id().as_bytes();

    for e in [&mut host, &mut alice] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    host.sync(now).await.unwrap();
    alice.sync(now).await.unwrap();

    let server = host.create_server("lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();
    host.invite_to_channel(&chan, &alice_id, now).await.unwrap();
    for _ in 0..4 {
        host.receive_all(now).await.unwrap();
        alice.receive_all(now).await.unwrap();
    }
    host.send_channel(&chan, "hi", now).await.unwrap();
    assert_eq!(alice.poll_channels(now).await.unwrap().len(), 1);

    let window = 10_000u64;
    host.set_auto_kick(&server, Some(window)).unwrap();
    assert_eq!(host.auto_kick_window(&server), Some(window));

    // Within the window: nobody is swept.
    assert!(host
        .sweep_inactive_members(now + 5_000)
        .await
        .unwrap()
        .is_empty());

    // Past the window: Alice (no fresh ledger activity) is removed; the host is
    // never swept.
    let later = now + window + 5_000;
    let kicked = host.sweep_inactive_members(later).await.unwrap();
    assert_eq!(kicked, vec![alice_id]);

    for _ in 0..4 {
        alice.receive_all(later).await.unwrap();
    }
    host.send_channel(&chan, "after auto-kick", later)
        .await
        .unwrap();
    assert!(
        alice.poll_channels(later).await.unwrap().is_empty(),
        "auto-kicked member is locked out"
    );
    // Idempotent: a second sweep finds nothing to do.
    assert!(host.sweep_inactive_members(later).await.unwrap().is_empty());

    // Clearing the window disables it.
    host.set_auto_kick(&server, None).unwrap();
    assert_eq!(host.auto_kick_window(&server), None);
}

#[tokio::test]
async fn host_deletes_a_channel_then_the_server() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut alice = engine(&relay).await;
    let alice_id = *alice.identity().id().as_bytes();

    for e in [&mut host, &mut alice] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    for e in [&mut host, &mut alice] {
        e.sync(now).await.unwrap();
    }

    let server = host.create_server("lodge", now).await.unwrap();
    let a = host.create_channel(&server, "general", true).unwrap();
    let b = host.create_channel(&server, "random", true).unwrap();
    host.invite_to_channel(&a, &alice_id, now).await.unwrap();
    host.invite_to_channel(&b, &alice_id, now).await.unwrap();
    macro_rules! settle {
        () => {
            for _ in 0..8 {
                for e in [&mut host, &mut alice] {
                    e.receive_all(now).await.unwrap();
                }
            }
        };
    }
    settle!();
    assert_eq!(alice.channels().len(), 2);

    // Delete one channel.
    host.delete_channel(&a, now).await.unwrap();
    assert!(!host.channels().iter().any(|c| c.channel_id == a));
    settle!();
    assert_eq!(
        alice.channels().len(),
        1,
        "alice dropped the deleted channel"
    );
    assert_eq!(alice.channels()[0].channel_id, b);

    // A non-host cannot delete.
    assert!(matches!(
        alice.delete_channel(&b, now).await,
        Err(crate::CoreError::NotServerHost)
    ));

    // List the server publicly, then tear it all down.
    host.set_discoverable(&server, true, "come in", vec![], now + 500)
        .await
        .unwrap();
    host.sync(now + 600).await.unwrap();
    assert_eq!(host.discoverable_servers().len(), 1);

    host.delete_server(&server, now + 1_000).await.unwrap();
    assert!(host.channels().is_empty());
    settle!();
    assert!(alice.channels().is_empty(), "alice dropped every channel");

    // The delist landed: the server is gone from discovery.
    host.sync(now + 2_000).await.unwrap();
    assert!(host.discoverable_servers().is_empty());
}

#[tokio::test]
async fn a_member_can_leave_a_channel() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let alice_id = *alice.identity().id().as_bytes();
    let bob_id = *bob.identity().id().as_bytes();

    for e in [&mut host, &mut alice, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    for e in [&mut host, &mut alice, &mut bob] {
        e.sync(now).await.unwrap();
    }

    let server = host.create_server("lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();
    host.invite_to_channel(&chan, &alice_id, now).await.unwrap();
    host.invite_to_channel(&chan, &bob_id, now).await.unwrap();
    macro_rules! settle {
        () => {
            for _ in 0..8 {
                for e in [&mut host, &mut alice, &mut bob] {
                    e.receive_all(now).await.unwrap();
                }
            }
        };
    }
    settle!();

    host.send_channel(&chan, "welcome all", now).await.unwrap();
    for e in [&mut alice, &mut bob] {
        assert_eq!(
            e.poll_channels(now)
                .await
                .unwrap()
                .first()
                .map(|m| m.text.clone()),
            Some("welcome all".to_string()),
            "both members keyed before the leave"
        );
    }

    // Bob leaves.
    bob.leave_channel(&chan, now).await.unwrap();
    assert!(
        bob.channels().is_empty(),
        "channel dropped locally on leave"
    );
    settle!();

    // The host processed the leave and rekeyed; Alice stays in.
    host.send_channel(&chan, "just us now", now).await.unwrap();
    let got = alice.poll_channels(now).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].text, "just us now");

    // A host cannot "leave" its own server this way.
    assert!(matches!(
        host.leave_channel(&chan, now).await,
        Err(crate::CoreError::Channel(_))
    ));
}

#[tokio::test]
async fn blocking_hides_dms_and_channel_messages() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let host_id = *host.identity().id().as_bytes();
    let bob_id = *bob.identity().id().as_bytes();

    for e in [&mut host, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    for e in [&mut host, &mut bob] {
        e.sync(now).await.unwrap();
    }

    // A shared channel.
    let server = host.create_server("lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();
    host.invite_to_channel(&chan, &bob_id, now).await.unwrap();
    for _ in 0..6 {
        host.receive_all(now).await.unwrap();
        bob.receive_all(now).await.unwrap();
    }

    // Baseline: messages get through both ways.
    bob.send_dm(&host_id, "hi", now).await.unwrap();
    assert_eq!(host.receive(now).await.unwrap().len(), 1);
    bob.send_channel(&chan, "in channel", now).await.unwrap();
    assert_eq!(host.poll_channels(now).await.unwrap().len(), 1);

    // Host blocks Bob.
    assert!(!host.is_blocked(&bob_id));
    host.block(&bob_id);
    assert!(host.is_blocked(&bob_id));

    bob.send_dm(&host_id, "still there?", now).await.unwrap();
    bob.send_channel(&chan, "hello?", now).await.unwrap();
    assert!(
        host.receive_all(now).await.unwrap().is_empty(),
        "blocked DM dropped"
    );
    assert!(
        host.poll_channels(now).await.unwrap().is_empty(),
        "blocked member's channel message dropped"
    );
    // Host cannot DM a blocked peer.
    assert!(matches!(
        host.send_dm(&bob_id, "x", now).await,
        Err(crate::CoreError::Blocked)
    ));

    // Unblock restores delivery of *future* messages.
    host.unblock(&bob_id);
    bob.send_dm(&host_id, "back", now).await.unwrap();
    assert_eq!(host.receive(now).await.unwrap()[0].text, "back");
}

#[tokio::test]
async fn contacts_persist_and_sort_by_petname() {
    use dante_identity::keystore;

    let now = now_ms();
    let relay = spawn_relay().await;
    let dir = std::env::temp_dir().join(format!("dante-e2e-contacts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("me.state");
    let ks = keystore::seal(&Identity::generate(now), b"pw").unwrap();

    let carol = [3u8; 32];
    let bob = [1u8; 32];
    {
        let mut e = Engine::connect(
            keystore::open(&ks, b"pw").unwrap(),
            &relay,
            test_params(),
            D,
            Some(store.clone()),
        )
        .await
        .unwrap();
        e.add_contact(&carol, "Carol", now);
        e.add_contact(&bob, "  bob  ", now); // trimmed
        e.add_contact(&bob, "Bobby", now); // rename, not a dup
        assert!(e.is_contact(&bob));
        assert_eq!(e.petname(&bob), Some("Bobby"));
        assert_eq!(e.contacts().len(), 2);
        e.persist().unwrap();
    }

    let mut e = Engine::connect(
        keystore::open(&ks, b"pw").unwrap(),
        &relay,
        test_params(),
        D,
        Some(store.clone()),
    )
    .await
    .unwrap();
    let list = e.contacts();
    assert_eq!(
        list.iter()
            .map(|(_, c)| c.petname.as_str())
            .collect::<Vec<_>>(),
        vec!["Bobby", "Carol"],
        "restored and sorted by petname"
    );
    e.remove_contact(&bob);
    assert!(!e.is_contact(&bob));
    assert_eq!(e.petname(&carol), Some("Carol"));

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn engine_connects_past_a_dead_relay_in_the_list() {
    let now = now_ms();
    let live = spawn_relay().await;
    // A closed port, then the live relay — the client must fail over.
    let dead = {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        l.local_addr().unwrap().to_string()
    };

    let mut e = Engine::connect(
        Identity::generate(1_000),
        &format!("{dead}, {live}"),
        test_params(),
        D,
        None,
    )
    .await
    .unwrap();
    assert_eq!(e.relay_endpoints(), &[dead, live]);

    // The connection landed on a working relay: a real round-trip succeeds.
    e.announce("", now).await.unwrap();
    assert!(e.sync(now).await.unwrap() >= 1);
}

#[tokio::test]
async fn custom_server_emoji_reaches_a_member() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut alice = engine(&relay).await;
    let alice_id = *alice.identity().id().as_bytes();

    for e in [&mut host, &mut alice] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    for e in [&mut host, &mut alice] {
        e.sync(now).await.unwrap();
    }

    let server = host.create_server("lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();
    host.invite_to_channel(&chan, &alice_id, now).await.unwrap();
    macro_rules! settle {
        () => {
            for _ in 0..6 {
                for e in [&mut host, &mut alice] {
                    e.receive_all(now).await.unwrap();
                }
            }
        };
    }
    settle!();

    let img = b"\x89PNG\r\n\x1a\n-fake-emoji-bytes-".to_vec();
    host.set_server_emoji(&server, "blobwave", &img, now)
        .await
        .unwrap();
    // bad names are rejected before any blob is stored
    assert!(host
        .set_server_emoji(&server, "Bad Name", &img, now)
        .await
        .is_err());
    settle!();

    let seen = alice.server_emojis(&server);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "blobwave");
    let hash = seen[0].1;
    assert_eq!(alice.fetch_blob(&hash).await.unwrap(), Some(img));

    host.remove_server_emoji(&server, "blobwave", now)
        .await
        .unwrap();
    settle!();
    assert!(alice.server_emojis(&server).is_empty());
}

#[tokio::test]
async fn roles_muting_and_delegated_kick() {
    use crate::roles::PERM_KICK;

    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let alice_id = *alice.identity().id().as_bytes();
    let bob_id = *bob.identity().id().as_bytes();

    for e in [&mut host, &mut alice, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    for e in [&mut host, &mut alice, &mut bob] {
        e.sync(now).await.unwrap();
    }

    let server = host.create_server("lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();
    host.invite_to_channel(&chan, &alice_id, now).await.unwrap();
    host.invite_to_channel(&chan, &bob_id, now).await.unwrap();
    macro_rules! settle {
        () => {
            for _ in 0..6 {
                for e in [&mut host, &mut alice, &mut bob] {
                    e.receive_all(now).await.unwrap();
                }
            }
        };
    }
    settle!();

    // Mute Bob (a role with no permissions).
    let muted = host
        .set_role(&server, None, "Muted", 0, crate::roles::PERM_ALL, 1, now)
        .await
        .unwrap();
    host.assign_role(&server, &bob_id, muted, true, now)
        .await
        .unwrap();
    settle!();

    bob.send_channel(&chan, "can anyone hear me", now)
        .await
        .unwrap();
    assert!(
        alice.poll_channels(now).await.unwrap().is_empty(),
        "muted member is dropped"
    );
    assert!(host.poll_channels(now).await.unwrap().is_empty());

    // Alice without a mod role cannot kick.
    assert!(matches!(
        alice.request_kick(&chan, &bob_id, now).await,
        Err(crate::CoreError::Channel(_))
    ));

    // Give Alice a Mod role; now her kick request is honoured by the host.
    let mods = host
        .set_role(&server, None, "Mod", PERM_KICK, 0, 10, now)
        .await
        .unwrap();
    host.assign_role(&server, &alice_id, mods, true, now)
        .await
        .unwrap();
    settle!();

    alice.request_kick(&chan, &bob_id, now).await.unwrap();
    settle!();

    host.send_channel(&chan, "bob is gone", now).await.unwrap();
    assert_eq!(
        alice
            .poll_channels(now)
            .await
            .unwrap()
            .first()
            .map(|m| m.text.clone()),
        Some("bob is gone".to_string())
    );
    assert!(
        bob.poll_channels(now).await.unwrap().is_empty(),
        "kicked member locked out"
    );

    assert_eq!(
        host.server_policy(&server)
            .unwrap()
            .top_role_name(&alice_id),
        Some("Mod")
    );
}

#[tokio::test]
async fn password_gated_invite_link() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut joiner = engine(&relay).await;

    for e in [&mut host, &mut joiner] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    host.sync(now).await.unwrap();
    joiner.sync(now).await.unwrap();

    let server = host.create_server("lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();
    host.set_join_password(&server, Some("hunter2")).unwrap();
    assert!(host.has_join_password(&server));
    let link = host.create_invite_link(&chan, 3_600_000, 0, now).unwrap();

    // No password, then wrong password: the host ignores the redeem.
    joiner.redeem_invite(&link, None, now).await.unwrap();
    joiner
        .redeem_invite(&link, Some("wrong"), now)
        .await
        .unwrap();
    for _ in 0..4 {
        host.receive_all(now).await.unwrap();
        joiner.receive_all(now).await.unwrap();
    }
    assert!(
        joiner.channels().is_empty(),
        "no join without the right password"
    );

    // Correct password: the joiner is added.
    joiner
        .redeem_invite(&link, Some("hunter2"), now)
        .await
        .unwrap();
    for _ in 0..4 {
        host.receive_all(now).await.unwrap();
        joiner.receive_all(now).await.unwrap();
    }
    assert!(joiner.channels().iter().any(|c| c.channel_id == chan));
    host.send_channel(&chan, "welcome", now).await.unwrap();
    assert_eq!(
        joiner
            .poll_channels(now)
            .await
            .unwrap()
            .first()
            .map(|m| m.text.clone()),
        Some("welcome".to_string())
    );
}

#[tokio::test]
async fn server_discovery_and_public_join() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut joiner = engine(&relay).await;

    for e in [&mut host, &mut joiner] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    host.sync(now).await.unwrap();
    joiner.sync(now).await.unwrap();

    let server = host.create_server("Cartographers", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();

    // Not listed yet.
    joiner.sync(now).await.unwrap();
    assert!(joiner.discoverable_servers().is_empty());

    host.set_discoverable(
        &server,
        true,
        "maps, mostly",
        vec!["maps".into()],
        now + 1000,
    )
    .await
    .unwrap();

    joiner.sync(now).await.unwrap();
    let listed = joiner.discoverable_servers();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "Cartographers");
    assert!(listed[0].invite.starts_with("dante-invite:"));

    // Join straight from the directory.
    joiner.join_discovered(&server, None, now).await.unwrap();
    for _ in 0..4 {
        host.receive_all(now).await.unwrap();
        joiner.receive_all(now).await.unwrap();
    }
    assert!(joiner.channels().iter().any(|c| c.channel_id == chan));
    host.send_channel(&chan, "welcome", now).await.unwrap();
    assert_eq!(
        joiner
            .poll_channels(now)
            .await
            .unwrap()
            .first()
            .map(|m| m.text.clone()),
        Some("welcome".to_string())
    );

    // Un-list.
    host.set_discoverable(&server, false, "", vec![], now + 2000)
        .await
        .unwrap();
    joiner.sync(now).await.unwrap();
    assert!(joiner.discoverable_servers().is_empty());
}

#[tokio::test]
async fn channel_emoji_reactions() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut alice = engine(&relay).await;
    let alice_id = *alice.identity().id().as_bytes();

    for e in [&mut host, &mut alice] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    host.sync(now).await.unwrap();
    alice.sync(now).await.unwrap();

    let server = host.create_server("lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true).unwrap();
    host.invite_to_channel(&chan, &alice_id, now).await.unwrap();
    for _ in 0..4 {
        host.receive_all(now).await.unwrap();
        alice.receive_all(now).await.unwrap();
    }

    host.send_channel(&chan, "big news", now).await.unwrap();
    let got = alice.poll_channels(now).await.unwrap();
    assert_eq!(got.len(), 1);
    let target = got[0].seq;
    assert!(target > 0);

    // Alice reacts; the host sees it via take_reactions, not poll_channels.
    alice
        .send_react(&chan, target, "🎉", false, now)
        .await
        .unwrap();
    let msgs = host.poll_channels(now).await.unwrap();
    assert!(msgs.is_empty(), "a reaction is not a message");
    let reacts = host.take_reactions();
    assert_eq!(reacts.len(), 1);
    assert_eq!(reacts[0].target_seq, target);
    assert_eq!(reacts[0].emoji, "🎉");
    assert_eq!(reacts[0].member, alice_id);
    assert!(!reacts[0].removed);

    // Withdrawing it comes through as removed = true.
    alice
        .send_react(&chan, target, "🎉", true, now)
        .await
        .unwrap();
    host.poll_channels(now).await.unwrap();
    let reacts = host.take_reactions();
    assert_eq!(reacts.len(), 1);
    assert!(reacts[0].removed);

    // Draining twice yields nothing.
    assert!(host.take_reactions().is_empty());
}

#[tokio::test]
async fn channel_reactions_survive_a_restart() {
    use dante_identity::keystore;

    let now = now_ms();
    let relay = spawn_relay().await;
    let dir = std::env::temp_dir().join(format!("dante-e2e-react-persist-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("alice.state");

    let mut host = engine(&relay).await;
    let alice_ks = keystore::seal(&Identity::generate(now), b"pw").unwrap();
    let alice_id = *keystore::open(&alice_ks, b"pw").unwrap().id().as_bytes();

    let (chan, target);
    {
        let mut alice = Engine::connect(
            keystore::open(&alice_ks, b"pw").unwrap(),
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

        let server = host.create_server("lodge", now).await.unwrap();
        chan = host.create_channel(&server, "general", true).unwrap();
        host.invite_to_channel(&chan, &alice_id, now).await.unwrap();
        for _ in 0..4 {
            host.receive_all(now).await.unwrap();
            alice.receive_all(now).await.unwrap();
        }

        host.send_channel(&chan, "big news", now).await.unwrap();
        let got = alice.poll_channels(now).await.unwrap();
        target = got[0].seq;
        alice
            .send_react(&chan, target, "🔥", false, now)
            .await
            .unwrap();
        // Also fold in a reaction from the host so both sides are covered.
        alice
            .send_react(&chan, target, "👍", false, now)
            .await
            .unwrap();
        alice
            .send_react(&chan, target, "👍", true, now)
            .await
            .unwrap();

        let snap = alice.reaction_snapshot();
        assert_eq!(snap.len(), 1, "one standing reaction after the toggle");
        alice.persist().unwrap();
    } // alice's process exits

    let alice = Engine::connect(
        keystore::open(&alice_ks, b"pw").unwrap(),
        &relay,
        test_params(),
        D,
        Some(store.clone()),
    )
    .await
    .unwrap();
    let snap = alice.reaction_snapshot();
    assert_eq!(snap.len(), 1, "reaction restored from the store");
    assert_eq!(snap[0].channel_id, chan);
    assert_eq!(snap[0].target_seq, target);
    assert_eq!(snap[0].emoji, "🔥");
    assert_eq!(snap[0].member, alice_id);
    assert!(!snap[0].removed);

    std::fs::remove_dir_all(&dir).ok();
}
