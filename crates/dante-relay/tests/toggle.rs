//! `dante serve --also-relay` embeds `dante_relay::run()` in-process and needs
//! to be able to stop and restart it at runtime (`POST /api/also-relay`)
//! without restarting the whole client. The only stop mechanism available to
//! an embedder is aborting the `JoinHandle` the task runs as — `run()` takes
//! no shutdown signal of its own. This only works if `run()` keeps no
//! detached background tasks: a `tokio::spawn` inside it that outlives the
//! aborted parent would leak forever and, if it held the listening socket,
//! would leave the port bound so a same-address restart fails.

use dante_relay::RunConfig;

#[tokio::test]
async fn aborting_run_frees_its_port_for_an_immediate_restart() {
    // Bind once to grab a free port, then let `run()` bind it for real.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap().to_string();
    drop(probe);

    let cfg = RunConfig {
        listen: addr.clone(),
        min_pow_bits: Some(1),
        ..Default::default()
    };
    let handle = tokio::spawn(dante_relay::run(cfg));

    // Give the listener a moment to actually bind.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        !handle.is_finished(),
        "relay task exited before it was stopped"
    );

    handle.abort();
    let _ = handle.await; // resolves to a JoinError (Cancelled); that's expected

    // If `run()` left anything detached holding the socket, this bind fails.
    let cfg2 = RunConfig {
        listen: addr,
        min_pow_bits: Some(1),
        ..Default::default()
    };
    let handle2 = tokio::spawn(dante_relay::run(cfg2));
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        !handle2.is_finished(),
        "restart on the same address failed — aborting the first run() didn't fully free it \
         (a detached background task, e.g. the maintenance loop, is still holding the port)"
    );
    handle2.abort();
}
