//! The opt-in relay-side link unfurler, exercised over a **real** relay wire
//! connection (a real `TcpListener`/`Client`, not an in-process function
//! call) — gated on the relay's `unfurl` feature; run with `--all-features`.
//!
//! Does not reach the public internet: every case here uses a target the
//! SSRF guard must refuse (loopback), so the assertions are deterministic.
//! That still proves the full path end to end — wire → `RelayHandler` →
//! `UnfurlGate` → `dante_net::unfurl::unfurl` → the SSRF guard — because a
//! request that never reached the real fetcher would come back with the
//! gate's own "not enabled" / "rate limited" wording, not the fetcher's.

#![cfg(feature = "unfurl")]

use std::net::Ipv4Addr;

use dante_ledger::LedgerParams;
use dante_net::{
    sync,
    transport::{serve, Client},
    wire::Response,
};
use dante_relay::state::{Limits, RelayHandler, RelayState};
use tokio::net::TcpListener;

fn test_params() -> LedgerParams {
    LedgerParams {
        min_announce_pow_bits: 8,
        min_liveness_pow_bits: 8,
        min_pow_m_cost_kib: 0,
        min_pow_t_cost: 0,
        ..Default::default()
    }
}

async fn spawn_relay(unfurl_enabled: bool) -> String {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut state = RelayState::new(test_params(), Limits::default());
    state.set_unfurl_enabled(unfurl_enabled);
    let handler = std::sync::Arc::new(RelayHandler::new(state));
    tokio::spawn(serve(listener, handler));
    addr.to_string()
}

#[tokio::test]
async fn disabled_relay_refuses_over_the_real_wire() {
    let addr = spawn_relay(false).await;
    let mut client = Client::connect(&addr).await.unwrap();
    let err = sync::unfurl_link(&mut client, "http://127.0.0.1:1/x")
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("not enabled"), "got: {err:?}");
}

#[tokio::test]
async fn enabled_relay_really_attempts_the_fetch_and_the_ssrf_guard_fires() {
    let addr = spawn_relay(true).await;
    let mut client = Client::connect(&addr).await.unwrap();
    // A loopback target: if this reaches the real fetcher (not just the
    // gate's own checks), the SSRF guard must refuse it with its own wording
    // — proving the request actually left `UnfurlGate` and hit
    // `dante_net::unfurl::unfurl` over a real relay wire connection.
    let err = sync::unfurl_link(&mut client, "http://127.0.0.1:1/x")
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("non-public"),
        "expected the SSRF guard's own message, got: {msg}"
    );
}

#[tokio::test]
async fn oversized_url_is_refused_over_the_real_wire_before_any_fetch() {
    let addr = spawn_relay(true).await;
    let mut client = Client::connect(&addr).await.unwrap();
    let long = "http://example.org/".to_string() + &"a".repeat(3000);
    let err = sync::unfurl_link(&mut client, &long).await.unwrap_err();
    assert!(format!("{err:?}").contains("too long"), "got: {err:?}");
}

#[tokio::test]
async fn a_request_that_is_not_unfurl_still_reaches_the_state_normally() {
    // Confirms adding the unfurl intercept in `RelayHandler` did not break
    // the fallthrough to ordinary (non-unfurl) request handling.
    let addr = spawn_relay(true).await;
    let mut client = Client::connect(&addr).await.unwrap();
    let ice = sync::get_ice_config(&mut client).await.unwrap();
    assert!(ice.is_empty(), "no ICE policy configured on this relay");
    // And Ping-shaped behaviour: use a raw request to be sure the plain
    // request/response cycle round-trips through the same handler.
    let resp = client
        .request(&dante_net::wire::Request::GetTreeHead)
        .await
        .unwrap();
    assert!(matches!(resp, Response::TreeHead { .. }));
}
