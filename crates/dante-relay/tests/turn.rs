//! The in-process TURN server accepts the relay's own time-windowed
//! credentials, hands out an allocation, and relays a datagram to a peer.

use std::sync::Arc;
use std::time::Duration;

use dante_relay::turn_server::TurnServer;
use tokio::net::UdpSocket;
use turn::client::{Client, ClientConfig};
use webrtc_util::conn::Conn;

#[tokio::test]
async fn turn_server_authenticates_and_relays() {
    const SECRET: &str = "a-shared-turn-secret";

    // Bind the server first so we know its port.
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let listen = addr.to_string();

    let server = TurnServer::start(&listen, addr.ip(), "dante", SECRET.to_owned())
        .await
        .expect("TURN server starts");

    // Mint credentials exactly as `GetIceConfig` would.
    let (username, password) =
        turn::auth::generate_long_term_credentials(SECRET, Duration::from_secs(300)).unwrap();

    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = Client::new(ClientConfig {
        stun_serv_addr: listen.clone(),
        turn_serv_addr: listen.clone(),
        username,
        password,
        realm: "dante".to_owned(),
        software: String::new(),
        rto_in_ms: 0,
        conn: client_sock,
        vnet: None,
    })
    .await
    .expect("client connects");
    client.listen().await.unwrap();

    // A valid credential yields an allocation.
    let allocation = client.allocate().await.expect("allocation granted");

    // The server relays a datagram from the allocated address to a peer.
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    allocation
        .send_to(b"hello via turn", peer_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 64];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .expect("peer receives the relayed datagram in time")
        .unwrap();
    assert_eq!(&buf[..n], b"hello via turn");

    client.close().await.unwrap();
    server.close().await;
}

#[tokio::test]
async fn turn_server_rejects_a_bad_credential() {
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let listen = addr.to_string();

    let server = TurnServer::start(&listen, addr.ip(), "dante", "the-real-secret".to_owned())
        .await
        .unwrap();

    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = Client::new(ClientConfig {
        stun_serv_addr: listen.clone(),
        turn_serv_addr: listen.clone(),
        username: "99999999999".to_owned(),
        password: "not-the-right-hmac".to_owned(),
        realm: "dante".to_owned(),
        software: String::new(),
        rto_in_ms: 0,
        conn: client_sock,
        vnet: None,
    })
    .await
    .unwrap();
    client.listen().await.unwrap();

    assert!(
        client.allocate().await.is_err(),
        "a forged credential is refused"
    );

    let _ = client.close().await;
    server.close().await;
}
