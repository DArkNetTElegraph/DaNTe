//! Opt-in link-preview unfurler for `dante serve`.
//!
//! Privacy note: fetching a URL's metadata reveals this machine's IP address
//! to the linked site. The feature is **off by default** and is enabled per
//! session by the SPA (`POST /api/embeds`). When on, `dante serve` — never the
//! browser — makes at most one HTTPS `GET` per link: no cookies, no
//! JavaScript, capped body size and wall-clock time, and every connection
//! target (the initial host and every redirect hop) is checked to be a public
//! unicast address, so a hostile link cannot point the fetcher at a
//! loopback / LAN / cloud-metadata endpoint (SSRF).

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::rustls::{self, pki_types::ServerName};
use tokio_rustls::TlsConnector;

const MAX_BODY: usize = 512 * 1024;
const MAX_IMAGE: usize = 256 * 1024;
const BUDGET: Duration = Duration::from_secs(6);
const MAX_REDIRECTS: u8 = 3;
const UA: &str = "DaNTe-unfurl/1";

/// A resolved link preview.
#[derive(Debug)]
pub struct Preview {
    /// The final URL after any redirects.
    pub url: String,
    /// Site name (`og:site_name`, else the host).
    pub site: String,
    /// Page title (`og:title`, else `<title>`, else the host).
    pub title: String,
    /// Short description (`og:description`, else `<meta name=description>`).
    pub description: String,
    /// `og:image`, fetched and inlined as a `data:` URI (capped, `image/*`).
    pub image_data_uri: Option<String>,
}

/// Fetch `raw_url` and extract a preview. `Err` on a bad URL, a non-public
/// target, a timeout, an oversized response, or a transport error.
pub async fn unfurl(raw_url: &str) -> Result<Preview, String> {
    if raw_url.len() > 2048 {
        return Err("url too long".into());
    }
    let deadline = Instant::now() + BUDGET;
    let (final_url, body, _ct) = fetch(raw_url, deadline, MAX_BODY, Some("text/html")).await?;
    let html = String::from_utf8_lossy(&body);
    let host = host_of(&final_url).unwrap_or_default();

    let mut site = meta(&html, "og:site_name").unwrap_or_default();
    let mut title = meta(&html, "og:title")
        .or_else(|| meta(&html, "twitter:title"))
        .or_else(|| title_tag(&html))
        .unwrap_or_default();
    let description = meta(&html, "og:description")
        .or_else(|| meta(&html, "twitter:description"))
        .or_else(|| meta(&html, "description"))
        .unwrap_or_default();
    let image = meta(&html, "og:image")
        .or_else(|| meta(&html, "og:image:url"))
        .or_else(|| meta(&html, "twitter:image"))
        .and_then(|src| absolutize(&final_url, &src));

    if site.is_empty() {
        site = host.clone();
    }
    if title.is_empty() {
        title = host.clone();
    }

    // The thumbnail gets its own fresh budget so a slow page fetch does not
    // starve it.
    let image_data_uri = match image {
        Some(img_url) => fetch(&img_url, Instant::now() + BUDGET, MAX_IMAGE, Some("image/"))
            .await
            .ok()
            .filter(|(_u, bytes, _ct)| !bytes.is_empty())
            .map(|(_u, bytes, ct)| {
                let mime = ct.split(';').next().unwrap_or("image/jpeg").trim();
                format!("data:{};base64,{}", mime, b64(&bytes))
            }),
        None => None,
    };

    Ok(Preview {
        url: final_url,
        site: clip(&decode_entities(&site), 120),
        title: clip(&decode_entities(&title), 300),
        description: clip(&decode_entities(&description), 600),
        image_data_uri,
    })
}

/// One `GET` with redirect-following. Returns `(final_url, body, content_type)`.
/// `want` (a content-type prefix) is enforced on the final response.
async fn fetch(
    start_url: &str,
    deadline: Instant,
    cap: usize,
    want: Option<&str>,
) -> Result<(String, Vec<u8>, String), String> {
    let mut url = start_url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let (parts, host, port, tls) = split_url(&url)?;
        let addr = resolve_public(&host, port).await?;

        let raw = tokio::time::timeout_at(deadline, async {
            let tcp = TcpStream::connect(addr).await?;
            if tls {
                let name = ServerName::try_from(host.clone())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad sni"))?;
                let mut s = tls_connector().connect(name, tcp).await?;
                http_roundtrip(&mut s, &host, &parts, cap).await
            } else {
                let mut s = tcp;
                http_roundtrip(&mut s, &host, &parts, cap).await
            }
        })
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| e.to_string())?;

        match raw {
            Response::Redirect(loc) => {
                url = absolutize(&url, &loc).ok_or("bad redirect location")?;
            }
            Response::Body { content_type, body } => {
                if let Some(w) = want {
                    if !content_type.trim_start().starts_with(w) {
                        return Err(format!("unexpected content type: {content_type}"));
                    }
                }
                return Ok((url, body, content_type));
            }
        }
    }
    Err("too many redirects".into())
}

enum Response {
    Redirect(String),
    Body { content_type: String, body: Vec<u8> },
}

async fn http_roundtrip<S>(
    stream: &mut S,
    host: &str,
    path_and_query: &str,
    cap: usize,
) -> io::Result<Response>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let req = format!(
        "GET {p} HTTP/1.1\r\nHost: {h}\r\nUser-Agent: {ua}\r\nAccept: text/html,*/*\r\n\
         Accept-Encoding: identity\r\nConnection: close\r\n\r\n",
        p = path_and_query,
        h = host,
        ua = UA,
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // Read headers (bounded) then the body (bounded).
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no headers"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 32 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    };

    let header_txt = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = header_txt.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);

    let mut location = None;
    let mut content_type = String::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match k.as_str() {
            "location" => location = Some(v.to_string()),
            "content-type" => content_type = v.to_ascii_lowercase(),
            "content-length" => content_length = v.parse().ok(),
            "transfer-encoding" if v.to_ascii_lowercase().contains("chunked") => chunked = true,
            _ => {}
        }
    }

    if (300..400).contains(&code) {
        if let Some(loc) = location {
            return Ok(Response::Redirect(loc));
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "redirect without location",
        ));
    }
    if !(200..300).contains(&code) {
        return Err(io::Error::other(format!("http status {code}")));
    }

    let mut body = buf.split_off(head_end);
    let limit = content_length.map(|n| n.min(cap)).unwrap_or(cap);
    while body.len() < limit + 64 {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > cap + 64 {
            break;
        }
    }
    if chunked {
        body = dechunk(&body);
    }
    body.truncate(cap);
    Ok(Response::Body { content_type, body })
}

/// Minimal `Transfer-Encoding: chunked` decoder (best effort).
fn dechunk(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut rest = input;
    while let Some(nl) = find(rest, b"\r\n") {
        let size_txt = String::from_utf8_lossy(&rest[..nl]);
        let size =
            usize::from_str_radix(size_txt.trim().split(';').next().unwrap_or("").trim(), 16)
                .unwrap_or(0);
        rest = &rest[nl + 2..];
        if size == 0 || rest.len() < size {
            if size > 0 && !rest.is_empty() {
                out.extend_from_slice(&rest[..rest.len().min(size)]);
            }
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
    }
    out
}

// ---- URL handling ---------------------------------------------------------

/// `(path_and_query, host, port, is_tls)`.
fn split_url(url: &str) -> Result<(String, String, u16, bool), String> {
    let (scheme, rest) = url.split_once("://").ok_or("url needs a scheme")?;
    let tls = match scheme.to_ascii_lowercase().as_str() {
        "https" => true,
        "http" => false,
        _ => return Err("only http and https links are previewed".into()),
    };
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let authority = authority.rsplit('@').next().unwrap_or(authority); // drop userinfo
    let (host, port) = if let Some(h) = authority.strip_prefix('[') {
        // IPv6 literal: [::1]:443
        let (h6, tail) = h.split_once(']').ok_or("bad ipv6 authority")?;
        let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
        (h6.to_string(), port.unwrap_or(if tls { 443 } else { 80 }))
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse().map_err(|_| "bad port")?)
    } else {
        (authority.to_string(), if tls { 443 } else { 80 })
    };
    if host.is_empty() {
        return Err("url has no host".into());
    }
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    Ok((path, host, port, tls))
}

fn host_of(url: &str) -> Option<String> {
    split_url(url).ok().map(|(_, h, _, _)| h)
}

/// Resolve `host:port` and return the first address that is a public unicast
/// IP. Refuses if every resolved address is private / loopback / link-local /
/// CGNAT / multicast — the SSRF guard.
async fn resolve_public(host: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("dns: {e}"))?;
    for a in addrs {
        if ip_is_public(&a.ip()) {
            return Ok(a);
        }
    }
    Err("link points at a non-public address".into())
}

/// Whether `ip` is a globally routable unicast address we are willing to fetch.
fn ip_is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)      // 100.64.0.0/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)    // 192.0.0.0/24
                || (o[0] == 198 && (o[1] & 0xfe) == 18)       // 198.18.0.0/15 benchmarking
                || o[0] >= 240) // 240.0.0.0/4 reserved
        }
        IpAddr::V6(v6) => {
            if let Some(m) = v6.to_ipv4_mapped() {
                return ip_is_public(&IpAddr::V4(m));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00     // fc00::/7 unique-local
                || (s[0] & 0xffc0) == 0xfe80     // fe80::/10 link-local
                || (s[0] == 0x2001 && s[1] == 0x0db8)) // 2001:db8::/32 documentation
        }
    }
}

/// Resolve `href` against `base` (handles absolute, `//host`, `/path`, and
/// simple relative paths).
fn absolutize(base: &str, href: &str) -> Option<String> {
    let href = href.trim();
    if href.is_empty() {
        return None;
    }
    if href.contains("://") {
        return Some(href.to_string());
    }
    let (scheme, rest) = base.split_once("://")?;
    if let Some(sf) = href.strip_prefix("//") {
        return Some(format!("{scheme}://{sf}"));
    }
    let authority = match rest.find(['/', '?', '#']) {
        Some(i) => &rest[..i],
        None => rest,
    };
    if let Some(abs) = href.strip_prefix('/') {
        return Some(format!("{scheme}://{authority}/{abs}"));
    }
    // relative to the base's directory
    let dir = match rest.rfind('/') {
        Some(i) if i >= authority.len() => &rest[..i + 1],
        _ => return Some(format!("{scheme}://{authority}/{href}")),
    };
    Some(format!("{scheme}://{dir}{href}"))
}

// ---- HTML scraping (no parser dependency) --------------------------------

/// Extract `<meta property|name="<key>" content="...">` (order-insensitive).
fn meta(html: &str, key: &str) -> Option<String> {
    let hay = html.as_bytes();
    let mut i = 0;
    let needle = b"<meta";
    while let Some(rel) = find(&hay[i..], needle) {
        let start = i + rel;
        let end = find(&hay[start..], b">")
            .map(|e| start + e)
            .unwrap_or(hay.len());
        let tag = &html[start..end];
        i = end + 1;
        let tag_l = tag.to_ascii_lowercase();
        let matches_key = attr(&tag_l, "property").as_deref() == Some(key)
            || attr(&tag_l, "name").as_deref() == Some(key)
            || attr(&tag_l, "itemprop").as_deref() == Some(key);
        if matches_key {
            if let Some(content) = attr(tag, "content") {
                let c = content.trim();
                if !c.is_empty() {
                    return Some(c.to_string());
                }
            }
        }
        if i >= hay.len() {
            break;
        }
    }
    None
}

fn title_tag(html: &str) -> Option<String> {
    let l = html.to_ascii_lowercase();
    let open = l.find("<title")?;
    let gt = l[open..].find('>')? + open + 1;
    let close = l[gt..].find("</title>")? + gt;
    let t = html[gt..close].trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Read attribute `name` from a single tag string (quoted or bare value).
fn attr(tag: &str, name: &str) -> Option<String> {
    let b = tag.as_bytes();
    let mut i = 0;
    loop {
        let rel = find(&b[i..], name.as_bytes())?;
        let at = i + rel;
        // require a boundary before the name (space, quote or tag start)
        let ok_before = at == 0 || matches!(b[at - 1], b' ' | b'\t' | b'\n' | b'"' | b'\'' | b'<');
        let after = at + name.len();
        let mut j = after;
        while j < b.len() && matches!(b[j], b' ' | b'\t' | b'\n') {
            j += 1;
        }
        if ok_before && j < b.len() && b[j] == b'=' {
            j += 1;
            while j < b.len() && matches!(b[j], b' ' | b'\t' | b'\n') {
                j += 1;
            }
            if j >= b.len() {
                return None;
            }
            let val = match b[j] {
                q @ (b'"' | b'\'') => {
                    let s = j + 1;
                    let e = find(&b[s..], &[q])? + s;
                    &tag[s..e]
                }
                _ => {
                    let s = j;
                    let e = b[s..]
                        .iter()
                        .position(|c| matches!(c, b' ' | b'\t' | b'\n' | b'>' | b'/'))
                        .map(|p| s + p)
                        .unwrap_or(b.len());
                    &tag[s..e]
                }
            };
            return Some(val.to_string());
        }
        i = at + name.len();
        if i >= b.len() {
            return None;
        }
    }
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&#38;", "&")
        .replace("&lt;", "<")
        .replace("&#60;", "<")
        .replace("&gt;", ">")
        .replace("&#62;", ">")
        .replace("&quot;", "\"")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&hellip;", "…")
        .replace("&mdash;", "—")
        .replace("&ndash;", "–")
}

fn clip(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

// ---- small helpers ------------------------------------------------------

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Standard base64 (no line breaks).
fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn tls_connector() -> TlsConnector {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let cfg = CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();
        for cert in loaded.certs {
            let _ = roots.add(cert);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("rustls default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    });
    TlsConnector::from(cfg.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_non_public_addresses() {
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "172.16.9.9",
            "169.254.7.7",
            "100.64.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                !ip_is_public(&bad.parse().unwrap()),
                "{bad} must be blocked"
            );
        }
        for ok in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(ip_is_public(&ok.parse().unwrap()), "{ok} must be allowed");
        }
    }

    #[tokio::test]
    async fn refuses_to_fetch_a_loopback_link() {
        // The SSRF guard must fire before any connection is attempted.
        let e = unfurl("http://127.0.0.1:9/secret").await.unwrap_err();
        assert!(e.contains("non-public"), "got: {e}");
    }

    #[test]
    fn scrapes_opengraph_tags() {
        let html = r#"<!doctype html><html><head>
            <title>Fallback Title</title>
            <meta property="og:site_name" content="Example News">
            <meta property="og:title" content="A Big Story &amp; More">
            <meta name="og:description" content='Something happened today.'>
            <meta property="og:image" content="/img/hero.jpg">
          </head><body>x</body></html>"#;
        assert_eq!(meta(html, "og:site_name").as_deref(), Some("Example News"));
        assert_eq!(
            decode_entities(&meta(html, "og:title").unwrap()),
            "A Big Story & More"
        );
        assert_eq!(
            meta(html, "og:description").as_deref(),
            Some("Something happened today.")
        );
        assert_eq!(
            absolutize("https://ex.com/news/1", &meta(html, "og:image").unwrap()).as_deref(),
            Some("https://ex.com/img/hero.jpg")
        );
        assert_eq!(title_tag(html).as_deref(), Some("Fallback Title"));
    }

    #[test]
    fn absolutize_forms() {
        let b = "https://a.com/x/y/z";
        assert_eq!(
            absolutize(b, "https://other.com/p").unwrap(),
            "https://other.com/p"
        );
        assert_eq!(
            absolutize(b, "//cdn.com/p.png").unwrap(),
            "https://cdn.com/p.png"
        );
        assert_eq!(
            absolutize(b, "/root.png").unwrap(),
            "https://a.com/root.png"
        );
        assert_eq!(
            absolutize(b, "sibling.png").unwrap(),
            "https://a.com/x/y/sibling.png"
        );
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
    }
}
