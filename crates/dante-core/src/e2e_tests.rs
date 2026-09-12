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
        // The tests solve at the tiny `D` cost — no Argon2 floor.
        min_pow_m_cost_kib: 0,
        min_pow_t_cost: 0,
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

/// Direct channel invites are now offer/accept. This drives the full round trip
/// — `host` offers, `invitee` accepts, `host` MLS-adds, `invitee` gets the
/// Welcome — so the rest of a test can proceed as if the member had just joined.
async fn invite_accept(
    host: &mut Engine,
    invitee: &mut Engine,
    channel_id: &[u8; 32],
    invitee_id: &[u8; 32],
    now: u64,
) -> Vec<crate::Inbound> {
    let mut seen = Vec::new();
    host.invite_to_channel(channel_id, invitee_id, now)
        .await
        .unwrap();
    let mut saw_invite = false;
    for _ in 0..20 {
        seen.extend(invitee.receive_all(now).await.unwrap());
        host.receive_all(now).await.unwrap();
        if invitee
            .pending_channel_invites()
            .iter()
            .any(|(c, _, _)| c == channel_id)
        {
            saw_invite = true;
            break;
        }
    }
    assert!(saw_invite, "invitee received the channel invite");
    invitee
        .accept_channel_invite(channel_id, now)
        .await
        .unwrap();
    let mut joined = false;
    for _ in 0..20 {
        host.receive_all(now).await.unwrap();
        seen.extend(invitee.receive_all(now).await.unwrap());
        let _ = invitee.poll_channels(now).await;
        if invitee
            .channels()
            .iter()
            .any(|c| c.channel_id == *channel_id)
        {
            joined = true;
            break;
        }
    }
    assert!(joined, "invitee joined the channel after accepting");
    seen
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
            text: "hi alice!".into(),
            msg_id: got[0].msg_id,
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
async fn a_relay_without_an_ice_policy_does_not_wipe_known_servers() {
    // A relay whose operator configured no STUN/TURN. `client` can land here
    // after failing over from a sibling that did have one.
    let relay = spawn_relay_with_ice(dante_relay::state::IcePolicy::default()).await;
    let mut e = engine(&relay).await;
    assert!(
        e.ice_servers().is_empty(),
        "nothing to learn from this relay"
    );

    let known = vec![dante_voice::IceServer {
        urls: vec!["turn:turn.example.org:3478".into()],
        username: "1789000000".into(),
        credential: "c2VjcmV0".into(),
    }];
    e.set_ice_servers(known.clone());

    e.refresh_ice_servers().await.expect("refresh succeeds");

    // Dropping these would cost every peer behind a symmetric NAT its relay
    // candidate, silently, on a hop the user never sees.
    assert_eq!(e.ice_servers(), known.as_slice());
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_signal_relays_browser_webrtc_between_the_two_peers() {
    // The browser-audio path for 1:1 calls: the engine relays opaque WebRTC
    // signalling (SDP/ICE) between the two browsers, independent of its own
    // server-side Call. Assert an offer sent by Alice reaches Bob verbatim.
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let bob_id = *bob.identity().id().as_bytes();

    for e in [&mut alice, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    for e in [&mut alice, &mut bob] {
        e.sync(now).await.unwrap();
    }

    alice
        .send_call_signal(&bob_id, 0, "v=0\r\nOFFER", now)
        .await
        .unwrap();

    let mut relayed = None;
    for _ in 0..20 {
        for inb in bob.receive_all(now).await.unwrap() {
            if let crate::Inbound::CallSignal {
                from_idk,
                kind,
                data,
            } = inb
            {
                relayed = Some((from_idk, kind, data));
            }
        }
        if relayed.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let alice_idk = alice.identity().sign_public().to_bytes();
    assert_eq!(
        relayed,
        Some((alice_idk, 0u8, "v=0\r\nOFFER".to_string())),
        "Bob received Alice's relayed 1:1 call offer"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_voice_channel_connects_members_and_tracks_presence() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut alice = engine(&relay).await;
    let alice_id = *alice.identity().id().as_bytes();
    let host_id = *host.identity().id().as_bytes();

    for e in [&mut host, &mut alice] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    host.sync(now).await.unwrap();
    alice.sync(now).await.unwrap();

    let server = host.create_server("lodge", now).await.unwrap();
    let vchan = host.create_voice_channel(&server, "Lounge", true).unwrap();
    assert!(host
        .channels()
        .iter()
        .any(|c| c.channel_id == vchan && c.voice));
    invite_accept(&mut host, &mut alice, &vchan, &alice_id, now).await;
    for _ in 0..8 {
        for e in [&mut host, &mut alice] {
            e.receive_all(now).await.unwrap();
            let _ = e.poll_channels(now).await;
        }
    }
    assert!(alice
        .channels()
        .iter()
        .any(|c| c.channel_id == vchan && c.voice));
    for e in [&mut host, &mut alice] {
        e.refresh_mls_key_package().await.unwrap();
    }

    // Alice connects first — the room is empty, so she opens it.
    alice.join_voice_channel(&vchan, now).await.unwrap();
    assert!(alice.in_group_call(&vchan));
    // Host sees her beacon and asks to be let in.
    assert_eq!(host.voice_participants(&vchan, now).await, vec![alice_id]);
    host.join_voice_channel(&vchan, now).await.unwrap();

    // The request → Welcome → auto-join round-trips over the relay.
    let mut connected = false;
    for _ in 0..40 {
        for e in [&mut alice, &mut host] {
            e.receive_all(now).await.unwrap();
            let _ = e.send_voice_presence(now).await;
        }
        if host.in_group_call(&vchan) && host.group_call_key(&vchan) == alice.group_call_key(&vchan)
        {
            connected = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }
    assert!(
        connected,
        "host joined the voice channel and shares the call key"
    );

    // Presence lists both, from either side.
    let mut hp = host.voice_participants(&vchan, now).await;
    hp.sort();
    let mut want = vec![alice_id, host_id];
    want.sort();
    assert_eq!(hp, want);

    // The browser-owned WebRTC signalling relays opaquely between participants.
    alice
        .send_voice_signal(&host_id, &vchan, 0, "v=0\r\nOFFER", now)
        .await
        .unwrap();
    let mut relayed = None;
    for _ in 0..20 {
        for inb in host.receive_all(now).await.unwrap() {
            if let crate::Inbound::VoiceSignal {
                channel_id,
                kind,
                data,
                ..
            } = inb
            {
                relayed = Some((channel_id, kind, data));
            }
        }
        if relayed.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        relayed,
        Some((vchan, 0u8, "v=0\r\nOFFER".to_string())),
        "the host received Alice's relayed WebRTC offer"
    );

    // Alice disconnects; the host stays.
    alice.leave_voice_channel(&vchan, now).await.unwrap();
    assert!(!alice.in_group_call(&vchan));
    for _ in 0..20 {
        host.receive_all(now).await.unwrap();
        let _ = host.poll_group_calls(now).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(host.in_group_call(&vchan), "host is still connected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_group_call_shares_an_mls_key_that_rekeys_when_a_member_leaves() {
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
    invite_accept(&mut host, &mut bob, &chan, &bob_id, now).await;
    for _ in 0..8 {
        for e in [&mut host, &mut alice, &mut bob] {
            e.sync(now).await.unwrap();
            e.receive_all(now).await.unwrap();
        }
    }
    assert!(alice.channels().iter().any(|c| c.channel_id == chan));
    assert!(bob.channels().iter().any(|c| c.channel_id == chan));

    // Every member has an MLS KeyPackage on the relay (connect published one;
    // re-publish to be safe under test timing).
    for e in [&mut host, &mut alice, &mut bob] {
        e.refresh_mls_key_package().await.unwrap();
    }

    // Host opens the group call: adds alice + bob and DMs them one Welcome.
    host.start_group_call(&chan, now).await.unwrap();
    assert!(host.in_group_call(&chan));

    let mut joined = 0;
    for _ in 0..40 {
        for e in [&mut alice, &mut bob] {
            for it in e.receive_all(now).await.unwrap() {
                if let crate::Inbound::GroupCallInvite { channel_id, .. } = it {
                    if channel_id == chan && !e.in_group_call(&chan) {
                        e.join_group_call(&chan, now).await.unwrap();
                        joined += 1;
                    }
                }
            }
        }
        host.receive_all(now).await.unwrap();
        if joined >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_eq!(joined, 2, "alice and bob joined the group call");

    // All three land in the same MLS epoch off the one Welcome — same key.
    let key = host.group_call_key(&chan).expect("host derived a call key");
    assert_eq!(
        alice.group_call_key(&chan),
        Some(key),
        "alice shares the key"
    );
    assert_eq!(bob.group_call_key(&chan), Some(key), "bob shares the key");
    assert_eq!(host.group_call_peers(&chan).len(), 2);
    assert_eq!(alice.group_call_peers(&chan).len(), 2);

    // Bob leaves: the remaining members rekey and the media key rotates.
    bob.leave_group_call(&chan, now).await.unwrap();
    assert!(!bob.in_group_call(&chan));

    let mut rotated = false;
    for _ in 0..60 {
        for e in [&mut host, &mut alice] {
            e.receive_all(now).await.unwrap();
            let _ = e.poll_group_calls(now).await;
        }
        let hk = host.group_call_key(&chan);
        if hk.is_some()
            && hk != Some(key)
            && hk == alice.group_call_key(&chan)
            && host.group_call_peers(&chan).len() == 1
        {
            rotated = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(rotated, "the group-call key rotated after bob left");
}

#[tokio::test]
async fn a_group_call_survives_a_restart() {
    use dante_identity::keystore;

    let now = now_ms();
    let relay = spawn_relay().await;
    let dir = std::env::temp_dir().join(format!("dante-e2e-gc-persist-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("alice.state");

    let mut host = engine(&relay).await;

    let alice_ks = keystore::seal(&Identity::generate(now), b"pw").unwrap();
    let alice_id = *keystore::open(&alice_ks, b"pw").unwrap().id().as_bytes();

    let chan;
    let key_before;
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
        for e in [&mut host, &mut alice] {
            e.sync(now).await.unwrap();
        }

        let server = host.create_server("lodge", now).await.unwrap();
        chan = host.create_channel(&server, "general", true, None).unwrap();
        invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
        for _ in 0..8 {
            for e in [&mut host, &mut alice] {
                e.sync(now).await.unwrap();
                e.receive_all(now).await.unwrap();
            }
        }
        for e in [&mut host, &mut alice] {
            e.refresh_mls_key_package().await.unwrap();
        }

        host.start_group_call(&chan, now).await.unwrap();
        let mut joined = false;
        for _ in 0..40 {
            for it in alice.receive_all(now).await.unwrap() {
                if let crate::Inbound::GroupCallInvite { channel_id, .. } = it {
                    if channel_id == chan && !alice.in_group_call(&chan) {
                        alice.join_group_call(&chan, now).await.unwrap();
                        joined = true;
                    }
                }
            }
            host.receive_all(now).await.unwrap();
            if joined {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(joined, "alice joined the call before the restart");
        key_before = alice.group_call_key(&chan).expect("alice has a call key");
        assert_eq!(host.group_call_key(&chan), Some(key_before));
        alice.persist().unwrap();
    } // alice's process exits mid-call

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
    assert!(
        alice.in_group_call(&chan),
        "the group call was restored from disk"
    );
    assert_eq!(
        alice.group_call_key(&chan),
        Some(key_before),
        "same MLS epoch after the restart, so the same media key"
    );
    assert_eq!(
        host.group_call_key(&chan),
        Some(key_before),
        "and it still matches the host"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn startup_reports_each_step_as_it_begins() {
    use crate::BootStep;
    use std::sync::{Arc, Mutex};

    let relay = spawn_relay().await;
    let seen: Arc<Mutex<Vec<BootStep>>> = Arc::new(Mutex::new(Vec::new()));

    let sink = {
        let seen = Arc::clone(&seen);
        Arc::new(move |s: BootStep| seen.lock().unwrap().push(s)) as crate::BootProgress
    };

    let _e = Engine::connect_with_progress(
        Identity::generate(1_000),
        &relay,
        test_params(),
        D,
        None,
        Some(&sink),
    )
    .await
    .unwrap();

    let steps = seen.lock().unwrap().clone();

    // Reported in the order the work happens, and only for work that happened:
    // there is no local store here, so nothing is restored.
    assert_eq!(
        steps,
        vec![
            BootStep::ConnectingRelay { endpoints: 1 },
            BootStep::RelayConnected,
            BootStep::OpeningStore,
            BootStep::FetchingIce,
            BootStep::PublishingKeyPackage,
        ],
        "startup steps, in order"
    );

    // The remaining steps (Announcing / PublishingPrekeys / Syncing / Ready)
    // belong to `serve::run_on`, not to `connect`.
    assert!(!steps.contains(&BootStep::Ready));
}

#[tokio::test]
async fn startup_reports_restoring_state_when_there_is_a_store() {
    use crate::BootStep;
    use dante_identity::keystore;
    use std::sync::{Arc, Mutex};

    let now = now_ms();
    let relay = spawn_relay().await;
    let dir = std::env::temp_dir().join(format!("dante-e2e-boot-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("alice.state");
    let ks = keystore::seal(&Identity::generate(now), b"pw").unwrap();

    {
        let mut alice = Engine::connect(
            keystore::open(&ks, b"pw").unwrap(),
            &relay,
            test_params(),
            D,
            Some(store.clone()),
        )
        .await
        .unwrap();
        alice.announce("", now).await.unwrap();
        alice.persist().unwrap();
    }

    let seen: Arc<Mutex<Vec<BootStep>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let seen = Arc::clone(&seen);
        Arc::new(move |s: BootStep| seen.lock().unwrap().push(s)) as crate::BootProgress
    };

    let _alice = Engine::connect_with_progress(
        keystore::open(&ks, b"pw").unwrap(),
        &relay,
        test_params(),
        D,
        Some(store.clone()),
        Some(&sink),
    )
    .await
    .unwrap();

    let steps = seen.lock().unwrap().clone();
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, BootStep::RestoringState { .. })),
        "a second start rebuilds from the store and says so: {steps:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn channel_message_ids_survive_a_restart() {
    use dante_identity::keystore;

    let now = now_ms();
    let relay = spawn_relay().await;
    let dir = std::env::temp_dir().join(format!("dante-e2e-hist-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("alice.state");

    let mut host = engine(&relay).await;
    let alice_ks = keystore::seal(&Identity::generate(now), b"pw").unwrap();
    let alice_id = *keystore::open(&alice_ks, b"pw").unwrap().id().as_bytes();

    let chan;
    let (first_seq, reply_seq, fwd_seq);
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
        for e in [&mut host, &mut alice] {
            e.sync(now).await.unwrap();
        }

        let server = host.create_server("lodge", now).await.unwrap();
        chan = host.create_channel(&server, "general", true, None).unwrap();
        invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
        for _ in 0..8 {
            for e in [&mut host, &mut alice] {
                e.sync(now).await.unwrap();
                e.receive_all(now).await.unwrap();
            }
        }

        first_seq = alice.send_channel(&chan, "first", now).await.unwrap();
        reply_seq = alice
            .send_channel_reply(&chan, first_seq, "answering", now)
            .await
            .unwrap();
        fwd_seq = alice
            .forward_to_channel(&chan, "bob", "passed along", now)
            .await
            .unwrap();
        assert!(first_seq != 0, "the relay assigned a seq");

        alice.persist().unwrap();
    } // alice's process exits

    let mut alice = Engine::connect(
        keystore::open(&alice_ks, b"pw").unwrap(),
        &relay,
        test_params(),
        D,
        Some(store.clone()),
    )
    .await
    .unwrap();

    let mine: Vec<_> = alice
        .channel_history()
        .iter()
        .filter(|e| e.channel_id == chan && e.outgoing)
        .collect();
    assert_eq!(mine.len(), 3, "all three of our messages replayed");

    // Without the seq, reactions / pins / edits have nothing to key on after a
    // restart -- which is what made a restored message uneditable.
    assert_eq!(mine[0].seq, first_seq);
    assert_eq!(mine[1].seq, reply_seq);
    assert_eq!(mine[2].seq, fwd_seq);

    assert_eq!(mine[1].reply_to, Some(first_seq), "the reply still quotes");
    assert_eq!(
        mine[2].forwarded_from.as_deref(),
        Some("bob"),
        "the forwarded-from chip survives"
    );
    assert_eq!(mine[0].reply_to, None);
    assert_eq!(mine[0].forwarded_from, None);
    drop(mine);

    // The map that authorises an edit is reseeded from the replayed history,
    // so a message we sent before the restart is still ours to change. This
    // used to fail with "unknown message (or sent before restart)".
    alice
        .edit_channel_message(&chan, first_seq, "edited after the restart", now)
        .await
        .expect("the author can still edit a pre-restart message");

    let _ = std::fs::remove_dir_all(&dir);
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;

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
async fn a_direct_invite_only_adds_after_the_recipient_accepts() {
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();

    // Host invites both. Nothing is added yet.
    host.invite_to_channel(&chan, &alice_id, now).await.unwrap();
    host.invite_to_channel(&chan, &bob_id, now).await.unwrap();
    for _ in 0..10 {
        for e in [&mut host, &mut alice, &mut bob] {
            e.receive_all(now).await.unwrap();
        }
    }
    assert_eq!(
        host.channel_roster(&chan),
        vec![*host.identity().id().as_bytes()],
        "no one is in the channel before anyone accepts"
    );
    assert!(alice.channels().is_empty() && bob.channels().is_empty());
    assert!(alice
        .pending_channel_invites()
        .iter()
        .any(|(c, cn, sn)| *c == chan && cn == "general" && sn == "lodge"));

    // Alice accepts, Bob declines.
    alice.accept_channel_invite(&chan, now).await.unwrap();
    bob.decline_channel_invite(&chan, now).await.unwrap();
    for _ in 0..15 {
        for e in [&mut host, &mut alice, &mut bob] {
            e.receive_all(now).await.unwrap();
        }
    }

    let mut roster = host.channel_roster(&chan);
    roster.sort();
    let mut want = vec![*host.identity().id().as_bytes(), alice_id];
    want.sort();
    assert_eq!(roster, want, "only Alice joined");
    assert!(alice.channels().iter().any(|c| c.channel_id == chan));
    assert!(bob.channels().is_empty());
    assert!(
        bob.pending_channel_invites().is_empty(),
        "Bob's invite is gone"
    );

    // A late/forged accept from Bob (his invite was consumed by the decline)
    // does nothing.
    bob.receive_all(now).await.unwrap();
    // Re-inserting a pending invite locally and accepting is a no-op host-side
    // because `invites_sent` no longer holds (chan, bob).
    host.receive_all(now).await.unwrap();
    assert!(!host.channel_roster(&chan).contains(&bob_id));
}

#[tokio::test]
async fn a_new_member_gets_a_backlog_of_recent_messages() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let bob_id = *bob.identity().id().as_bytes();

    for e in [&mut host, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    host.sync(now).await.unwrap();
    bob.sync(now).await.unwrap();

    let server = host.create_server("lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    let first_seq = host.send_channel(&chan, "first", now).await.unwrap();
    let second_seq = host.send_channel(&chan, "second", now).await.unwrap();

    // Bob joins after those were sent — he can't decrypt the pre-join log, so
    // the host hands him a plaintext snapshot.
    let inbound = invite_accept(&mut host, &mut bob, &chan, &bob_id, now).await;
    let backlog = inbound.into_iter().find_map(|inb| match inb {
        crate::Inbound::ChannelBacklog {
            channel_id,
            entries,
        } => Some((channel_id, entries)),
        _ => None,
    });
    let (cid, entries) = backlog.expect("bob received a channel backlog");
    assert_eq!(cid, chan);
    assert_eq!(
        entries.iter().map(|e| e.text.clone()).collect::<Vec<_>>(),
        vec!["first", "second"]
    );

    // The snapshot carries each line's relay-log seq. Without it a backfilled
    // message renders as inert text — `serve` keys reactions, pins, replies and
    // edits off this id, and the SPA hides every hover action when it is 0.
    assert_eq!(
        entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![first_seq, second_seq],
        "backlog lines keep the seq the relay gave them"
    );

    // And they are usable: bob can react to a message he was backfilled,
    // which is the whole point of carrying the seq.
    bob.send_react(&chan, first_seq, "👍", false, now)
        .await
        .expect("a backfilled message can be reacted to");
}

#[tokio::test]
async fn a_password_protected_channel_wraps_the_relay_log() {
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
    let chan = host
        .create_channel(&server, "vault", true, Some("correct horse battery"))
        .unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;

    for _ in 0..6 {
        for e in [&mut host, &mut alice] {
            e.receive_all(now).await.unwrap();
            let _ = e.poll_channels(now).await;
        }
    }
    assert!(alice.channels().iter().any(|c| c.channel_id == chan));

    // The Welcome DM carried the log key, so both sides read wrapped messages.
    host.send_channel(&chan, "top secret", now).await.unwrap();
    let msgs = alice.poll_channels(now).await.unwrap();
    assert_eq!(
        msgs.first().map(|m| m.text.clone()),
        Some("top secret".into())
    );
    alice
        .send_channel(&chan, "acknowledged", now)
        .await
        .unwrap();
    assert_eq!(
        host.poll_channels(now)
            .await
            .unwrap()
            .first()
            .map(|m| m.text.clone()),
        Some("acknowledged".into())
    );

    // A holder of only the channel_id cannot strip the wrapper: the derived
    // key differs and every log frame fails to parse as a bare channel frame
    // (covered in depth by `channel::log_wrap_roundtrip_and_key_binding`).
    let wrong = crate::channel::derive_log_key(&server, &chan, "guessed wrong");
    let right = crate::channel::derive_log_key(&server, &chan, "correct horse battery");
    assert_ne!(wrong, right);
}

#[tokio::test]
async fn a_channel_message_can_be_edited_and_deleted_by_its_author() {
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
    for _ in 0..6 {
        for e in [&mut host, &mut alice] {
            e.receive_all(now).await.unwrap();
            let _ = e.poll_channels(now).await;
        }
    }

    // Host posts and learns the message's relay-log seq.
    let seq = host.send_channel(&chan, "helo wrold", now).await.unwrap();
    assert!(seq > 0);
    assert_eq!(
        alice
            .poll_channels(now)
            .await
            .unwrap()
            .first()
            .map(|m| m.text.clone()),
        Some("helo wrold".into())
    );

    // Host edits it; Alice sees the correction.
    host.edit_channel_message(&chan, seq, "hello world", now)
        .await
        .unwrap();
    alice.poll_channels(now).await.unwrap();
    let edits = alice.take_edits();
    assert_eq!(edits.len(), 1);
    assert_eq!(edits[0].target_seq, seq);
    assert_eq!(edits[0].text.as_deref(), Some("hello world"));
    assert!(!edits[0].deleted);

    // Only the author may edit — Alice cannot.
    assert!(alice
        .edit_channel_message(&chan, seq, "haha", now)
        .await
        .is_err());

    // Host deletes it; Alice sees the deletion.
    host.delete_channel_message(&chan, seq, now).await.unwrap();
    alice.poll_channels(now).await.unwrap();
    let edits = alice.take_edits();
    assert_eq!(edits.len(), 1);
    assert!(edits[0].deleted);

    // A later edit of a deleted message is ignored.
    assert!(host
        .edit_channel_message(&chan, seq, "back!", now)
        .await
        .is_err());

    // The snapshot reflects the final state (deleted).
    let snap = host.edit_snapshot();
    assert_eq!(snap.len(), 1);
    assert!(snap[0].deleted && snap[0].target_seq == seq);
}

#[tokio::test]
async fn a_channel_reply_carries_its_target_seq() {
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
    for _ in 0..6 {
        for e in [&mut host, &mut alice] {
            e.receive_all(now).await.unwrap();
            let _ = e.poll_channels(now).await;
        }
    }

    let seq = host
        .send_channel(&chan, "who's around?", now)
        .await
        .unwrap();
    assert_eq!(
        alice
            .poll_channels(now)
            .await
            .unwrap()
            .first()
            .map(|m| (m.text.clone(), m.reply_to)),
        Some(("who's around?".to_string(), None))
    );

    // Alice replies to that message.
    alice
        .send_channel_reply(&chan, seq, "me!", now)
        .await
        .unwrap();
    let got = host.poll_channels(now).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].text, "me!");
    assert_eq!(got[0].reply_to, Some(seq));

    // A reply is still editable / deletable by its author.
    let reply_seq = got[0].seq;
    let _ = alice.take_edits();
    alice
        .edit_channel_message(&chan, reply_seq, "me too!", now)
        .await
        .unwrap();
    host.poll_channels(now).await.unwrap();
    let edits = host.take_edits();
    assert_eq!(edits.len(), 1);
    assert_eq!(edits[0].target_seq, reply_seq);
    assert_eq!(edits[0].text.as_deref(), Some("me too!"));

    // Search finds both the DM and the channel text, newest first.
    host.send_dm(&alice_id, "lunch tomorrow?", now)
        .await
        .unwrap();
    alice.receive(now).await.unwrap();
    let hits = alice.search("tomorrow", 10);
    assert_eq!(hits.len(), 1);
    assert!(!hits[0].is_channel && hits[0].text.contains("tomorrow"));
    let chan_hits = alice.search("me", 10);
    assert!(chan_hits.iter().any(|h| h.is_channel && h.text == "me!"));
    assert!(alice.search("nothing-matches-xyz", 10).is_empty());
}

#[cfg(feature = "p2p")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dht_serves_as_a_prekey_directory_fallback() {
    use dante_dm::PreKeyBundle;

    let now = now_ms();
    let relay = spawn_relay().await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let alice_idk = alice.identity().sign_public().to_bytes();
    let alice_id = *alice.identity().id().as_bytes();
    let bob_id = *bob.identity().id().as_bytes();

    // Alice brings up a libp2p node and (inside enable_p2p) registers her
    // address with the relay. Bob passes NO explicit bootstrap — he discovers
    // Alice through the relay's GetP2pPeers.
    let alice_addrs = alice
        .enable_p2p("/ip4/127.0.0.1/tcp/0", &[])
        .await
        .expect("alice p2p");
    assert!(!alice_addrs.is_empty(), "alice has a dialable address");
    bob.enable_p2p("/ip4/127.0.0.1/tcp/0", &[])
        .await
        .expect("bob p2p");

    for e in [&mut alice, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap(); // relay + DHT
    }
    alice.sync(now).await.unwrap();
    bob.sync(now).await.unwrap();

    // Bob resolves Alice's bundle straight from the DHT (retry: Kad needs a
    // moment to replicate the record to Bob).
    let mut blob = None;
    for _ in 0..25 {
        if let Some(b) = bob.dht_prekey(&alice_id).await {
            blob = Some(b);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let blob = blob.expect("alice's prekey bundle resolved via the DHT");
    let bundle = PreKeyBundle::decode(&blob).expect("valid bundle");
    assert_eq!(bundle.idk_pub, alice_idk);
    assert_eq!(bundle.identity_id, alice_id);
    bundle.verify().expect("bundle signature");

    // The relay path is untouched: a normal DM still flows.
    bob.send_dm(&alice_id, "over the relay still", now)
        .await
        .unwrap();
    assert_eq!(
        alice.receive(now).await.unwrap()[0].text,
        "over the relay still"
    );
    let _ = bob_id;
}

#[cfg(feature = "p2p")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_learns_an_identity_from_ledger_gossip() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let alice_idk = alice.identity().sign_public().to_bytes();

    let alice_addrs = alice.enable_p2p("/ip4/127.0.0.1/tcp/0", &[]).await.unwrap();
    bob.enable_p2p("/ip4/127.0.0.1/tcp/0", &alice_addrs)
        .await
        .unwrap();

    // Give gossipsub a moment to form the mesh.
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;

    // Bob never syncs from the relay in this test.
    assert!(!bob.knows(&alice_idk), "bob starts out not knowing alice");

    // Alice announces (relay + gossip).
    alice.announce("alice", now).await.unwrap();

    // Bob hears it over gossip and folds it into his replica.
    let mut learned = false;
    for _ in 0..30 {
        let _ = bob.poll_p2p(now).await;
        if bob.knows(&alice_idk) {
            learned = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    assert!(learned, "bob learned alice's identity from ledger gossip");

    // The relay sync cursor is independent of gossip appends. Alice proves
    // liveness (relay only, as far as Bob is concerned — he won't poll_p2p
    // again). Bob's replica already holds Alice's announce from gossip, but a
    // sync must still re-scan the relay log from position 0 and pick up the new
    // liveness record rather than skip it because `ledger.len()` grew.
    let later = now + 60_000;
    alice.prove_liveness(later).await.unwrap();
    let accepted = bob.sync(later).await.unwrap();
    assert_eq!(
        accepted, 1,
        "sync picks up the liveness record (announce is a harmless dup)"
    );
    assert!(bob.knows(&alice_idk));
}

#[cfg(feature = "p2p")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_channel_message_arrives_over_gossip_and_is_not_double_delivered() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut alice = engine(&relay).await;
    let alice_id = *alice.identity().id().as_bytes();

    let host_addrs = host.enable_p2p("/ip4/127.0.0.1/tcp/0", &[]).await.unwrap();
    alice
        .enable_p2p("/ip4/127.0.0.1/tcp/0", &host_addrs)
        .await
        .unwrap();

    for e in [&mut host, &mut alice] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    for e in [&mut host, &mut alice] {
        e.sync(now).await.unwrap();
    }
    let server = host.create_server("lodge", now).await.unwrap();
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
    for _ in 0..6 {
        for e in [&mut host, &mut alice] {
            e.sync(now).await.unwrap();
            e.receive_all(now).await.unwrap();
            let _ = e.poll_channels(now).await;
            let _ = e.poll_p2p(now).await; // alice subscribes to the channel topic
        }
    }
    // Let the gossipsub mesh settle on the channel topic.
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    let _ = alice.poll_p2p(now).await;

    host.send_channel(&chan, "over gossip", now).await.unwrap();

    let mut got = Vec::new();
    for _ in 0..40 {
        let _ = alice.poll_p2p(now).await;
        got.extend(alice.poll_channels(now).await.unwrap());
        if got.iter().any(|m| m.text == "over gossip") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    }
    let hits = got.iter().filter(|m| m.text == "over gossip").count();
    assert_eq!(
        hits, 1,
        "delivered exactly once (gossip + relay copy deduped)"
    );

    // The authoritative relay copy must not re-emit it.
    let again = alice.poll_channels(now).await.unwrap();
    assert!(
        !again.iter().any(|m| m.text == "over gossip"),
        "the relay copy of an already-shown gossip message is not re-delivered"
    );
}

#[cfg(feature = "p2p")]
#[tokio::test]
async fn a_hostile_gossip_frame_cannot_suppress_the_real_message() {
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
    for _ in 0..6 {
        for e in [&mut host, &mut alice] {
            e.sync(now).await.unwrap();
            e.receive_all(now).await.unwrap();
            let _ = e.poll_channels(now).await;
        }
    }

    // A channel member gossips garbage claiming to be the next log entry.
    let last = alice.channel_last_seq(&chan);
    alice.inject_channel_gossip(chan, last + 1, vec![0xffu8; 48]);

    let junk = alice.poll_channels(now).await.unwrap();
    assert!(junk.is_empty(), "the junk gossip frame yields no message");
    assert_eq!(
        alice.channel_last_seq(&chan),
        last,
        "a gossip frame must not advance the log cursor"
    );

    // The real message the relay assigned `last + 1` still gets through.
    host.send_channel(&chan, "the real one", now).await.unwrap();
    let mut delivered = false;
    for _ in 0..10 {
        if alice
            .poll_channels(now)
            .await
            .unwrap()
            .iter()
            .any(|m| m.text == "the real one")
        {
            delivered = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        delivered,
        "the real message was not suppressed by the junk frame"
    );
}

#[tokio::test]
async fn a_direct_message_can_be_edited_and_deleted_by_its_sender() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut alice = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let alice_idk = alice.identity().sign_public().to_bytes();
    let alice_id = *alice.identity().id().as_bytes();
    let bob_id = *bob.identity().id().as_bytes();

    for e in [&mut alice, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    alice.sync(now).await.unwrap();
    bob.sync(now).await.unwrap();

    // Alice sends a message and gets its id back.
    let id = alice.send_dm(&bob_id, "helo", now).await.unwrap();
    assert_eq!(bob.receive(now).await.unwrap()[0].text, "helo");
    let _ = bob.take_dm_edits();

    // Alice edits it; Bob converges.
    alice.edit_dm(&bob_id, &id, "hello!", now).await.unwrap();
    bob.receive(now).await.unwrap();
    let edits = bob.take_dm_edits();
    assert_eq!(edits.len(), 1);
    assert_eq!(edits[0].msg_id, id);
    assert_eq!(edits[0].peer_idk, alice_idk);
    assert_eq!(edits[0].text.as_deref(), Some("hello!"));
    assert!(!edits[0].deleted);
    assert!(alice
        .dm_edit_snapshot()
        .iter()
        .any(|d| d.msg_id == id && d.text.as_deref() == Some("hello!")));

    // Alice deletes it; Bob converges.
    alice.delete_dm(&bob_id, &id, now).await.unwrap();
    bob.receive(now).await.unwrap();
    let d = bob.take_dm_edits();
    assert_eq!(d.len(), 1);
    assert!(d[0].deleted && d[0].msg_id == id);

    // A deleted message can't be edited again; an unknown id is rejected.
    assert!(alice.edit_dm(&bob_id, &id, "back", now).await.is_err());
    assert!(alice.edit_dm(&bob_id, &[9u8; 16], "x", now).await.is_err());
    // Bob can't edit a message Alice sent.
    assert!(bob.edit_dm(&alice_id, &id, "nope", now).await.is_err());
}

#[tokio::test]
async fn a_message_can_be_forwarded_into_a_channel() {
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
    for _ in 0..6 {
        for e in [&mut host, &mut alice] {
            e.receive_all(now).await.unwrap();
            let _ = e.poll_channels(now).await;
        }
    }

    host.send_channel(&chan, "keep this", now).await.unwrap();
    assert_eq!(alice.poll_channels(now).await.unwrap()[0].text, "keep this");

    // Alice forwards it back into the channel, tagged with its origin.
    let seq = alice
        .forward_to_channel(&chan, "the-host", "keep this", now)
        .await
        .unwrap();
    let got = host.poll_channels(now).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].text, "keep this");
    assert_eq!(got[0].forwarded_from.as_deref(), Some("the-host"));
    assert_eq!(got[0].reply_to, None);

    // A forward is an ordinary message: its author can still edit it.
    let _ = alice.take_edits();
    alice
        .edit_channel_message(&chan, seq, "keep this!!", now)
        .await
        .unwrap();
    host.poll_channels(now).await.unwrap();
    let edits = host.take_edits();
    assert_eq!(edits.len(), 1);
    assert_eq!(edits[0].text.as_deref(), Some("keep this!!"));
}

#[tokio::test]
async fn the_host_can_pin_and_unpin_a_channel_message() {
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
    for _ in 0..6 {
        for e in [&mut host, &mut alice] {
            e.receive_all(now).await.unwrap();
            let _ = e.poll_channels(now).await;
        }
    }

    // Alice posts; the host pins it.
    let seq = alice
        .send_channel(&chan, "read the rules", now)
        .await
        .unwrap();
    host.poll_channels(now).await.unwrap();
    let _ = host.take_pins();
    host.pin_channel_message(&chan, seq, now).await.unwrap();

    let pins = host.take_pins();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].target_seq, seq);
    assert!(pins[0].pinned);
    assert_eq!(host.pinned_messages(&chan).len(), 1);

    // Alice sees the pin land through the log.
    alice.poll_channels(now).await.unwrap();
    let seen = alice.take_pins();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].pinned && seen[0].target_seq == seq);
    assert_eq!(alice.pinned_messages(&chan).len(), 1);

    // A non-host non-author cannot pin.
    let other_seq = host.send_channel(&chan, "another one", now).await.unwrap();
    alice.poll_channels(now).await.unwrap();
    assert!(alice
        .pin_channel_message(&chan, other_seq, now)
        .await
        .is_err());

    // The host unpins; both sides converge to empty.
    host.unpin_channel_message(&chan, seq, now).await.unwrap();
    assert!(host.pinned_messages(&chan).is_empty());
    alice.poll_channels(now).await.unwrap();
    assert!(alice.pinned_messages(&chan).is_empty());
    assert!(alice.take_pins().iter().any(|p| !p.pinned));
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
    invite_accept(&mut host, &mut bob, &chan, &bob_id, now).await;

    // Let the Welcomes land and the members catch up on the MLS commits in
    // the channel log so everyone converges on the same epoch.
    for _ in 0..8 {
        for e in [&mut host, &mut alice, &mut bob] {
            e.sync(now).await.unwrap();
            e.receive_all(now).await.unwrap();
            let _ = e.poll_channels(now).await;
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

    // Alice posts; BOTH host and bob decrypt it.
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
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
        chan = host.create_channel(&server, "general", true, None).unwrap();
        invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();

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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
    invite_accept(&mut host, &mut bob, &chan, &bob_id, now).await;
    for _ in 0..8 {
        for e in [&mut host, &mut alice, &mut bob] {
            e.receive_all(now).await.unwrap();
            let _ = e.poll_channels(now).await;
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
            let _ = e.poll_channels(now).await;
        }
    }

    // Bob learned he was removed — the channel dropped out of his view.
    assert!(
        !bob.channels().iter().any(|c| c.channel_id == chan),
        "removed member's channel is gone"
    );

    // Post-kick: Alice still reads the host.
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

    // And Bob can no longer post — he is not in the channel.
    assert!(bob
        .send_channel(&chan, "let me back in", now)
        .await
        .is_err());
}

#[tokio::test]
async fn server_ban_removes_from_every_channel_and_blocks_return() {
    let now = now_ms();
    let relay = spawn_relay().await;
    let mut host = engine(&relay).await;
    let mut bob = engine(&relay).await;
    let bob_id = *bob.identity().id().as_bytes();

    for e in [&mut host, &mut bob] {
        e.announce("", now).await.unwrap();
        e.publish_prekeys().await.unwrap();
    }
    for e in [&mut host, &mut bob] {
        e.sync(now).await.unwrap();
    }

    let server = host.create_server("lodge", now).await.unwrap();
    let a = host.create_channel(&server, "general", true, None).unwrap();
    let b = host.create_channel(&server, "random", true, None).unwrap();
    invite_accept(&mut host, &mut bob, &a, &bob_id, now).await;
    invite_accept(&mut host, &mut bob, &b, &bob_id, now).await;
    assert_eq!(bob.channels().len(), 2);

    // Ban from the server — removed from both channels, added to the ban list.
    host.kick_from_server(&server, &bob_id, true, now)
        .await
        .unwrap();
    for _ in 0..10 {
        for e in [&mut host, &mut bob] {
            e.receive_all(now).await.unwrap();
            let _ = e.poll_channels(now).await;
        }
    }
    assert!(bob.channels().is_empty(), "removed from every channel");
    assert_eq!(host.server_bans(&server), vec![bob_id]);

    // A fresh invite to a banned identity is refused at the add path.
    host.invite_to_channel(&a, &bob_id, now).await.unwrap();
    let seen = {
        // pump the invite to Bob and have him accept
        let mut got = false;
        for _ in 0..15 {
            bob.receive_all(now).await.unwrap();
            host.receive_all(now).await.unwrap();
            if bob
                .pending_channel_invites()
                .iter()
                .any(|(c, _, _)| *c == a)
            {
                got = true;
                break;
            }
        }
        got
    };
    assert!(seen, "the invite DM still reaches a banned identity");
    bob.accept_channel_invite(&a, now).await.unwrap();
    for _ in 0..10 {
        for e in [&mut host, &mut bob] {
            e.receive_all(now).await.unwrap();
        }
    }
    assert!(
        bob.channels().is_empty(),
        "the host refuses to re-add a banned identity"
    );
    assert!(!host.channel_roster(&a).contains(&bob_id));

    // Unban, then a new invite works.
    assert!(host.unban_from_server(&server, &bob_id));
    assert!(host.server_bans(&server).is_empty());
    invite_accept(&mut host, &mut bob, &a, &bob_id, now).await;
    assert!(bob.channels().iter().any(|c| c.channel_id == a));
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
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
    let a = host.create_channel(&server, "general", true, None).unwrap();
    let b = host.create_channel(&server, "random", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &a, &alice_id, now).await;
    invite_accept(&mut host, &mut alice, &b, &alice_id, now).await;
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

    // #general is the always-there default and can't be deleted.
    assert!(matches!(
        host.delete_channel(&a, now).await,
        Err(crate::CoreError::Channel(_))
    ));

    // Delete the other channel.
    host.delete_channel(&b, now).await.unwrap();
    assert!(!host.channels().iter().any(|c| c.channel_id == b));
    settle!();
    assert_eq!(
        alice.channels().len(),
        1,
        "alice dropped the deleted channel"
    );
    assert_eq!(alice.channels()[0].channel_id, a);

    // A non-host cannot delete.
    assert!(matches!(
        alice.delete_channel(&a, now).await,
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
    invite_accept(&mut host, &mut bob, &chan, &bob_id, now).await;
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut bob, &chan, &bob_id, now).await;
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
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
    // only PNG / JPEG, and at most 1 MiB
    assert!(host
        .set_server_emoji(&server, "gif", b"GIF89a-nope", now)
        .await
        .is_err());
    let mut too_big = b"\x89PNG\r\n\x1a\n".to_vec();
    too_big.resize(1024 * 1024 + 1, 0);
    assert!(host
        .set_server_emoji(&server, "huge", &too_big, now)
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
async fn server_stickers_reach_a_member_and_coexist_with_emoji() {
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
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

    // A sticker and an emoji can share a server; a GIF sticker is allowed.
    let png = b"\x89PNG\r\n\x1a\n-emoji-".to_vec();
    host.set_server_emoji(&server, "wave", &png, now)
        .await
        .unwrap();
    let gif = b"GIF89a\x01\x00\x01\x00-fake-sticker-".to_vec();
    host.set_server_sticker(&server, "big_wave", &gif, now)
        .await
        .unwrap();

    // A name already taken by an emoji is refused for a sticker.
    assert!(host
        .set_server_sticker(&server, "wave", &gif, now)
        .await
        .is_err());
    // Charset and size are enforced.
    assert!(host
        .set_server_sticker(&server, "Bad Name", &gif, now)
        .await
        .is_err());
    let mut too_big = b"GIF89a".to_vec();
    too_big.resize(512 * 1024 + 1, 0);
    assert!(host
        .set_server_sticker(&server, "huge", &too_big, now)
        .await
        .is_err());
    settle!();

    let seen = alice.server_stickers(&server);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "big_wave");
    assert_eq!(alice.fetch_blob(&seen[0].1).await.unwrap(), Some(gif));
    // The emoji list is untouched by the sticker traffic.
    assert_eq!(alice.server_emojis(&server).len(), 1);

    host.remove_server_sticker(&server, "big_wave", now)
        .await
        .unwrap();
    settle!();
    assert!(alice.server_stickers(&server).is_empty());
    assert_eq!(alice.server_emojis(&server).len(), 1);
}

#[tokio::test]
async fn server_soundboard_reaches_a_member() {
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
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

    // An OGG clip is accepted; junk and oversize are refused.
    let ogg = b"OggS\x00\x02-fake-airhorn-".to_vec();
    host.set_server_sound(&server, "airhorn", &ogg, now)
        .await
        .unwrap();
    assert!(host
        .set_server_sound(&server, "airhorn", b"not audio", now)
        .await
        .is_err());
    let mut too_big = b"OggS".to_vec();
    too_big.resize(256 * 1024 + 1, 0);
    assert!(host
        .set_server_sound(&server, "huge", &too_big, now)
        .await
        .is_err());
    // A name already used by an emoji is refused for a sound.
    host.set_server_emoji(&server, "wave", b"\x89PNG\r\n\x1a\n-x-", now)
        .await
        .unwrap();
    assert!(host
        .set_server_sound(&server, "wave", &ogg, now)
        .await
        .is_err());
    settle!();

    let seen = alice.server_sounds(&server);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "airhorn");
    assert_eq!(alice.fetch_blob(&seen[0].1).await.unwrap(), Some(ogg));

    host.remove_server_sound(&server, "airhorn", now)
        .await
        .unwrap();
    settle!();
    assert!(alice.server_sounds(&server).is_empty());
}

#[tokio::test]
async fn host_set_nickname_reaches_a_member_host_only() {
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
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

    // A non-host (even one who can see the policy) cannot set a nickname.
    assert!(alice
        .set_member_nickname(&server, &alice_id, Some("Ali"), now)
        .await
        .is_err());
    // A control character is refused.
    assert!(host
        .set_member_nickname(&server, &alice_id, Some("bad\nname"), now)
        .await
        .is_err());

    host.set_member_nickname(&server, &alice_id, Some("Ali"), now)
        .await
        .unwrap();
    settle!();
    assert_eq!(
        alice.member_nickname(&server, &alice_id),
        Some("Ali".into())
    );
    assert_eq!(host.member_nickname(&server, &alice_id), Some("Ali".into()));

    // Clearing it (None) removes the entry for everyone.
    host.set_member_nickname(&server, &alice_id, None, now)
        .await
        .unwrap();
    settle!();
    assert_eq!(alice.member_nickname(&server, &alice_id), None);
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
    invite_accept(&mut host, &mut bob, &chan, &bob_id, now).await;
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
        alice.request_kick(&chan, &bob_id, false, now).await,
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

    alice
        .request_kick(&chan, &bob_id, false, now)
        .await
        .unwrap();
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    host.set_join_password(&server, Some("hunter2"), None)
        .unwrap();
    assert!(host.has_join_password(&server));
    // Changing it now requires the current password.
    assert!(host
        .set_join_password(&server, Some("hunter3"), Some("wrong"))
        .is_err());
    host.set_join_password(&server, Some("hunter2"), Some("hunter2"))
        .unwrap();
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
    let chan = host.create_channel(&server, "general", true, None).unwrap();

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
    let chan = host.create_channel(&server, "general", true, None).unwrap();
    invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
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
        chan = host.create_channel(&server, "general", true, None).unwrap();
        invite_accept(&mut host, &mut alice, &chan, &alice_id, now).await;
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
