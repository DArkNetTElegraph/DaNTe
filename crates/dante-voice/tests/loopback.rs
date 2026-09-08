//! Two `Call`s connect over loopback, exchanging SDP + ICE as plain strings
//! (in the real client these ride sealed-sender DMs). Proves DTLS-SRTP comes
//! up and the control channel carries bytes both ways.

use std::time::Duration;

use dante_voice::{Call, CallEvent, CallState};
use tokio::sync::mpsc;

struct Outcome {
    connected: bool,
    ctl_open: bool,
    heard: Option<Vec<u8>>,
    heard_audio: Option<Vec<u8>>,
}

/// Drive one side: relay its ICE to the peer, apply the peer's ICE, and once
/// the control channel is open keep sending `probe` (ctl) and `audio_probe`
/// (an Opus-frame-shaped payload on the media track) until it has heard both.
async fn drive(
    mut call: Call,
    probe: &'static [u8],
    audio_probe: &'static [u8],
    to_peer: mpsc::UnboundedSender<String>,
    mut from_peer: mpsc::UnboundedReceiver<String>,
    done: mpsc::UnboundedSender<Outcome>,
) {
    let mut connected = false;
    let mut ctl_open = false;
    let mut heard: Option<Vec<u8>> = None;
    let mut heard_audio: Option<Vec<u8>> = None;
    let deadline = tokio::time::sleep(Duration::from_secs(25));
    tokio::pin!(deadline);
    let mut resend = tokio::time::interval(Duration::from_millis(120));

    loop {
        if ctl_open && heard.is_some() && heard_audio.is_some() {
            break;
        }
        tokio::select! {
            _ = &mut deadline => break,
            _ = resend.tick(), if connected => {
                if ctl_open && heard.is_none() { let _ = call.send_ctl(probe).await; }
                if heard_audio.is_none() { let _ = call.push_audio(audio_probe, 20).await; }
            }
            ev = call.next_event() => match ev {
                Some(CallEvent::LocalIce(c)) => { let _ = to_peer.send(c); }
                Some(CallEvent::State(CallState::Connected)) => connected = true,
                Some(CallEvent::State(CallState::Failed)) => break,
                Some(CallEvent::State(_)) => {}
                Some(CallEvent::CtlOpen) => { ctl_open = true; }
                Some(CallEvent::Ctl(b)) => { heard = Some(b); }
                Some(CallEvent::RemoteAudio(b)) => { heard_audio = Some(b); }
                None => break,
            },
            Some(cand) = from_peer.recv() => { let _ = call.add_ice(&cand).await; }
        }
    }
    let _ = done.send(Outcome {
        connected,
        ctl_open,
        heard,
        heard_audio,
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_calls_connect_and_exchange_control_and_audio() {
    let (a_ice_tx, a_ice_rx) = mpsc::unbounded_channel::<String>();
    let (b_ice_tx, b_ice_rx) = mpsc::unbounded_channel::<String>();
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<Outcome>();

    let (caller, offer) = Call::offer().await.unwrap();
    let (callee, answer) = Call::answer(&offer).await.unwrap();
    caller.set_answer(&answer).await.unwrap();

    tokio::spawn(drive(
        caller,
        b"caller",
        b"opus-from-caller",
        b_ice_tx,
        a_ice_rx,
        done_tx.clone(),
    ));
    tokio::spawn(drive(
        callee,
        b"callee",
        b"opus-from-callee",
        a_ice_tx,
        b_ice_rx,
        done_tx,
    ));

    let mut outcomes = Vec::new();
    for _ in 0..2 {
        outcomes.push(
            tokio::time::timeout(Duration::from_secs(30), done_rx.recv())
                .await
                .expect("a side finished in time")
                .expect("done channel open"),
        );
    }

    assert!(
        outcomes.iter().all(|o| o.connected),
        "both sides reached Connected"
    );
    assert!(
        outcomes.iter().all(|o| o.ctl_open),
        "both control channels opened"
    );
    let mut heard: Vec<_> = outcomes.iter().filter_map(|o| o.heard.clone()).collect();
    heard.sort();
    let mut want = vec![b"caller".to_vec(), b"callee".to_vec()];
    want.sort();
    assert_eq!(
        heard, want,
        "each side received the other's control-channel probe"
    );

    let audio: Vec<_> = outcomes
        .iter()
        .filter_map(|o| o.heard_audio.clone())
        .collect();
    assert_eq!(
        audio.len(),
        2,
        "each side received an audio-track RTP payload"
    );
    let mut aw: Vec<Vec<u8>> = vec![b"opus-from-caller".to_vec(), b"opus-from-callee".to_vec()];
    aw.sort();
    let mut ag = audio.clone();
    ag.sort();
    assert_eq!(ag, aw, "the audio payloads round-trip through SRTP intact");
}
