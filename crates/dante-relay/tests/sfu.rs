//! Three participants join one SFU room **through the relay wire**
//! (`SfuJoin`/`SfuIce`/`SfuPull`), exchange SDP and trickled ICE with the
//! relay-hosted SFU, and hear each other's distinct audio markers through it —
//! real DTLS-SRTP, real RTP, no direct peer-to-peer connections. Gated on the
//! relay's `sfu` feature; run with `--all-features`.

#![cfg(feature = "sfu")]

use std::{
    collections::HashSet,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use dante_ledger::LedgerParams;
use dante_net::{
    sync,
    transport::{serve, Client},
};
use dante_relay::state::{Limits, RelayHandler, RelayState};
use dante_voice::{Call, CallEvent, CallState};
use tokio::net::TcpListener;

const N: usize = 3;
const MARKERS: [&[u8]; N] = [b"sfu-wire-from-0", b"sfu-wire-from-1", b"sfu-wire-from-2"];

fn test_params() -> LedgerParams {
    LedgerParams {
        min_announce_pow_bits: 8,
        min_liveness_pow_bits: 8,
        min_pow_m_cost_kib: 0,
        min_pow_t_cost: 0,
        ..Default::default()
    }
}

async fn spawn_relay() -> String {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = RelayState::new(test_params(), Limits::default());
    let handler = Arc::new(RelayHandler::new(state));
    tokio::spawn(serve(listener, handler));
    addr.to_string()
}

/// Drive one participant: negotiate with the SFU over the relay wire, apply
/// its ICE, and once connected keep pushing this participant's marker and
/// pulling the SFU's candidates until the test says everyone heard everyone.
#[allow(clippy::too_many_arguments)]
async fn drive_peer(
    mut call: Call,
    mut client: Client,
    room: [u8; 32],
    slot: u8,
    marker: &'static [u8],
    heard: Arc<Mutex<HashSet<Vec<u8>>>>,
    connected: Arc<AtomicUsize>,
    done: Arc<AtomicBool>,
) {
    let mut is_connected = false;
    let deadline = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(deadline);
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    loop {
        if done.load(Ordering::SeqCst) {
            break;
        }
        tokio::select! {
            _ = &mut deadline => break,
            _ = tick.tick(), if is_connected => {
                for _ in 0..3 {
                    let _ = call.push_audio(marker, 20).await;
                }
                if let Ok(candidates) = sync::sfu_pull(&mut client, &room, slot).await {
                    for c in candidates {
                        let _ = call.add_ice(&c).await;
                    }
                }
            }
            ev = call.next_event() => match ev {
                Some(CallEvent::LocalIce(c)) => {
                    let _ = sync::sfu_ice(&mut client, &room, slot, &c).await;
                }
                Some(CallEvent::State(CallState::Connected)) => {
                    if !is_connected {
                        is_connected = true;
                        connected.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Some(CallEvent::State(CallState::Failed)) => break,
                Some(CallEvent::RemoteAudio(b)) => {
                    heard.lock().unwrap().insert(b);
                }
                Some(_) => {}
                None => break,
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn three_peers_forward_through_the_relay_hosted_sfu() {
    let relay = spawn_relay().await;
    let room = [0xAB_u8; 32];

    let mut calls = Vec::new();
    let mut clients = Vec::new();
    let mut slots = Vec::new();
    for _ in 0..N {
        let (call, offer) = Call::offer_for_sfu(N - 1, &[]).await.unwrap();
        let mut client = Client::connect(&relay).await.unwrap();
        let (slot, answer) = sync::sfu_join(&mut client, &room, &offer).await.unwrap();
        call.set_answer(&answer).await.unwrap();
        calls.push(call);
        clients.push(client);
        slots.push(slot);
    }
    assert_eq!(slots, vec![0, 1, 2], "SFU assigns slots in join order");

    let connected = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let mut heard_sets = Vec::new();
    let mut drivers = Vec::new();
    for (i, (call, client)) in calls.into_iter().zip(clients).enumerate() {
        let heard = Arc::new(Mutex::new(HashSet::new()));
        heard_sets.push(Arc::clone(&heard));
        drivers.push(tokio::spawn(drive_peer(
            call,
            client,
            room,
            slots[i],
            MARKERS[i],
            heard,
            Arc::clone(&connected),
            Arc::clone(&done),
        )));
    }

    // Wait until every participant has heard every other participant's marker.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let all_heard = (0..N).all(|s| {
            let h = heard_sets[s].lock().unwrap();
            (0..N).filter(|&o| o != s).all(|o| h.contains(MARKERS[o]))
        });
        if all_heard || tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    done.store(true, Ordering::SeqCst);
    for d in drivers {
        let _ = tokio::time::timeout(Duration::from_secs(10), d).await;
    }

    assert_eq!(
        connected.load(Ordering::SeqCst),
        N,
        "all {N} participants reached Connected through the relay-hosted SFU"
    );
    for (s, heard) in heard_sets.iter().enumerate() {
        let h = heard.lock().unwrap();
        for (o, marker) in MARKERS.iter().enumerate() {
            if o == s {
                assert!(
                    !h.contains(*marker),
                    "participant {s} heard its own audio looped back"
                );
            } else {
                assert!(
                    h.contains(*marker),
                    "participant {s} never heard participant {o} through the SFU"
                );
            }
        }
    }
}
