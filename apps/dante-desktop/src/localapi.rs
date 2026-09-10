//! A very small HTTP/1.1 client for the localhost UI service.
//!
//! The desktop shell's background threads (`audio`, `notify`) cannot touch the
//! `Engine` — it moved into the serve task — so they talk to it the same way
//! the web UI does, over `127.0.0.1`. The payloads are tiny JSON and the socket
//! is `Connection: close`, so a hand-rolled request is cheaper and has fewer
//! moving parts than pulling in an HTTP client crate.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// One request/response against the local service. `body` may be empty.
pub fn http(port: u16, method: &str, path: &str, body: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_millis(1500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(1500)))?;
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    Ok(raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or(raw))
}
