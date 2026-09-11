//! A minimal SOCKS5 client — just enough to reach a relay through Tor.
//!
//! An `.onion` address is not resolvable by DNS and not routable by TCP: it is
//! a public key, and only a Tor daemon knows how to reach it. So a client that
//! wants network-level anonymity does not dial the relay at all — it hands the
//! hostname to Tor's SOCKS port and lets Tor build the circuit. The relay then
//! never learns a client IP, because there isn't one to learn: it sees a
//! connection arriving from the Tor network.
//!
//! That is also why the hostname is sent as a **domain name** (ATYP 0x03) and
//! never resolved locally. Resolving it here would both fail (`.onion` has no
//! DNS record) and leak the intended destination to the local resolver.
//!
//! Only the no-authentication method is offered. Tor's SOCKS port does not
//! require credentials; a proxy that demands them is not one we can use, and
//! says so as a clean error rather than hanging.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::NetError;

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const CMD_CONNECT: u8 = 1;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

/// Open a connection to `host:port` through the SOCKS5 proxy at `proxy`.
///
/// `host` is passed through untouched for the proxy to resolve.
pub async fn connect_via(proxy: &str, host: &str, port: u16) -> Result<TcpStream, NetError> {
    // A SOCKS5 request encodes the host length in one byte.
    if host.is_empty() || host.len() > 255 {
        return Err(NetError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socks5: host must be 1..=255 bytes",
        )));
    }

    let mut s = TcpStream::connect(proxy).await?;
    s.set_nodelay(true).ok();

    // Greeting: one method on offer, no authentication.
    s.write_all(&[VERSION, 1, NO_AUTH]).await?;
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).await?;
    if greeting[0] != VERSION {
        return Err(proxy_err("not a SOCKS5 proxy"));
    }
    if greeting[1] != NO_AUTH {
        return Err(proxy_err("proxy demands authentication we cannot provide"));
    }

    // CONNECT to the host by name, so the proxy does the resolving.
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[VERSION, CMD_CONNECT, 0, ATYP_DOMAIN, host.len() as u8]);
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(proxy_err("malformed SOCKS5 reply"));
    }
    if head[1] != 0 {
        return Err(proxy_err(reply_reason(head[1])));
    }

    // The bound address the proxy reports is of no use to us, but it has to be
    // drained before the tunnel carries our own bytes.
    match head[3] {
        ATYP_IPV4 => drain(&mut s, 4 + 2).await?,
        ATYP_IPV6 => drain(&mut s, 16 + 2).await?,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            drain(&mut s, len[0] as usize + 2).await?;
        }
        _ => return Err(proxy_err("SOCKS5 reply had an unknown address type")),
    }

    Ok(s)
}

async fn drain(s: &mut TcpStream, n: usize) -> Result<(), NetError> {
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await?;
    Ok(())
}

fn proxy_err(msg: &str) -> NetError {
    NetError::Io(std::io::Error::other(format!("socks5: {msg}")))
}

/// RFC 1928 §6 reply codes, in words an operator can act on.
fn reply_reason(code: u8) -> &'static str {
    match code {
        1 => "general proxy failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable — for an .onion this usually means the service is down",
        5 => "connection refused by the destination",
        6 => "TTL expired",
        7 => "command not supported by the proxy",
        8 => "address type not supported by the proxy",
        _ => "unknown SOCKS5 failure",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A stub proxy that speaks just enough SOCKS5 to accept one CONNECT and
    /// then echo. Lets the handshake be tested without a Tor daemon.
    async fn stub_proxy(auth_ok: bool, reply: u8) -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [VERSION, 1, NO_AUTH]);
            s.write_all(&[VERSION, if auth_ok { NO_AUTH } else { 2 }])
                .await
                .unwrap();
            if !auth_ok {
                return;
            }

            let mut head = [0u8; 5];
            s.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], VERSION);
            assert_eq!(head[1], CMD_CONNECT);
            // The host must arrive as a name — resolving an .onion locally is
            // impossible and would leak the destination to the resolver.
            assert_eq!(head[3], ATYP_DOMAIN);
            let mut host = vec![0u8; head[4] as usize];
            s.read_exact(&mut host).await.unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            assert_eq!(host, b"relayxyz.onion");
            assert_eq!(u16::from_be_bytes(port), 9944);

            s.write_all(&[VERSION, reply, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            if reply != 0 {
                return;
            }
            // Tunnel established: echo one byte so the caller can prove the
            // stream is usable afterwards.
            let mut b = [0u8; 1];
            if s.read_exact(&mut b).await.is_ok() {
                let _ = s.write_all(&b).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn connects_through_the_proxy_and_hands_back_a_usable_stream() {
        let proxy = stub_proxy(true, 0).await;
        let mut s = connect_via(&proxy, "relayxyz.onion", 9944)
            .await
            .expect("tunnel established");
        s.write_all(b"x").await.unwrap();
        let mut back = [0u8; 1];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"x", "the stream carries our bytes, not the reply");
    }

    #[tokio::test]
    async fn a_proxy_demanding_authentication_fails_clearly() {
        let proxy = stub_proxy(false, 0).await;
        let e = connect_via(&proxy, "relayxyz.onion", 9944)
            .await
            .expect_err("no credentials to offer");
        assert!(e.to_string().contains("authentication"), "{e}");
    }

    #[tokio::test]
    async fn a_refused_connection_names_the_reason() {
        // 4 = host unreachable, what a down onion service looks like.
        let proxy = stub_proxy(true, 4).await;
        let e = connect_via(&proxy, "relayxyz.onion", 9944)
            .await
            .expect_err("proxy refused");
        assert!(e.to_string().contains("host unreachable"), "{e}");
    }
}
