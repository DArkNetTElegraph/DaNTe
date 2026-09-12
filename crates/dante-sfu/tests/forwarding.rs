//! Three `dante_voice::Call` participants negotiate DTLS-SRTP with one `Sfu`,
//! each pushes a distinct audio payload, and each receives exactly the other
//! two participants' payloads **through the SFU** — real RTP, opaque payloads,
//! no direct peer connection between participants.

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use dante_sfu::{Sfu, SfuEvent};
use dante_voice::{Call, CallEvent, CallState};
use tokio::sync::mpsc;

const N: usize = 3;
const MARKERS: [&[u8]; N] = [b"sfu-test-from-0", b"sfu-test-from-1", b"sfu-test-from-2"];

/// Drive one participant: relay its ICE to the SFU, apply the SFU's ICE, and
/// once connected keep pushing this participant's marker until the test says
/// everyone has heard everyone.
#[allow(clippy::too_many_arguments)]
async fn drive_peer(
    mut call: Call,
    slot: usize,
    sfu: Arc<Sfu>,
    mut ice_in: mpsc::UnboundedReceiver<String>,
    heard: Arc<Mutex<HashSet<Vec<u8>>>>,
    connected: Arc<AtomicUsize>,
    done: Arc<AtomicBool>,
) {
    let marker = MARKERS[slot];
    let mut is_connected = false;
    let deadline = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(deadline);
    let mut send = tokio::time::interval(Duration::from_millis(50));
    loop {
        if done.load(Ordering::SeqCst) {
            break;
        }
        tokio::select! {
            _ = &mut deadline => break,
            _ = send.tick(), if is_connected => {
                // A few copies per tick: the SFU drops early packets while a
                // subscriber is still binding.
                for _ in 0..3 {
                    let _ = call.push_audio(marker, 20).await;
                }
            }
            ev = call.next_event() => match ev {
                Some(CallEvent::LocalIce(c)) => { let _ = sfu.add_ice(slot, &c).await; }
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
            },
            Some(cand) = ice_in.recv() => { let _ = call.add_ice(&cand).await; }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn three_peers_hear_each_other_only_through_the_sfu() {
    let (mut sfu, mut events) = Sfu::new(N);

    let mut ice_tx = Vec::new();
    let mut calls = Vec::new();
    let mut slots = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..N {
        // One receive slot per other participant: an SDP answer cannot add
        // m-lines the offer did not carry.
        let (call, offer) = Call::offer_for_sfu(N - 1, &[]).await.unwrap();
        let (slot, answer) = sfu.add_peer(&offer).await.unwrap();
        call.set_answer(&answer).await.unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        ice_tx.push(tx);
        receivers.push(rx);
        slots.push(slot);
        calls.push(call);
    }
    let sfu = Arc::new(sfu);

    // Route the SFU's ICE candidates to the participant in that slot.
    let router = ice_tx.clone();
    let events_task = tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            if let SfuEvent::Ice { slot, candidate } = ev {
                if let Some(tx) = router.get(slot) {
                    let _ = tx.send(candidate);
                }
            }
        }
    });

    let connected = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let mut heard_sets = Vec::new();
    let mut drivers = Vec::new();
    for (slot, (call, rx)) in slots.into_iter().zip(calls.into_iter().zip(receivers)) {
        let heard = Arc::new(Mutex::new(HashSet::new()));
        heard_sets.push(Arc::clone(&heard));
        drivers.push(tokio::spawn(drive_peer(
            call,
            slot,
            Arc::clone(&sfu),
            rx,
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
    events_task.abort();
    sfu.close().await;

    assert_eq!(
        connected.load(Ordering::SeqCst),
        N,
        "all {N} participants reached Connected"
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
