//! Invite links — a server-signed, self-describing capability to join one
//! channel.
//!
//! The host mints an [`InviteToken`] (signed by the server root key), renders
//! it to a `dante-invite:<hex>` string, and shares it out of band. Anyone with
//! the string calls [`crate::Engine::redeem_invite`], which verifies the
//! signature/expiry locally and then DMs the host a redeem request; the host
//! checks the use count and runs the normal channel-invite flow.
//!
//! The relay is never involved — a link is just a signed blob.

use dante_crypto::{
    hash::sha256,
    sign::{SignPublic, SignSecret, SIG_LEN},
};
use dante_proto::enc::{Reader, WireError, Writer};

use crate::error::CoreError;

const TOKEN_VERSION: u8 = 1;
const SIG_DOMAIN: &[u8] = b"dante/invite-token/v1";
const LINK_PREFIX: &str = "dante-invite:";

/// A signed capability to join [`Self::channel_id`] on the server identified by
/// [`Self::server_root`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteToken {
    /// The owning server's root public key (also the signature verifier).
    pub server_root: [u8; 32],
    /// `IdentityId` of the host to send the redeem request to.
    pub host_id: [u8; 32],
    /// The channel being joined.
    pub channel_id: [u8; 32],
    /// A relay address the joiner can use (informational; the joiner may
    /// already be connected elsewhere).
    pub relay_hint: String,
    /// Unix-ms after which the token is refused.
    pub expires_ms: u64,
    /// Maximum redemptions; `0` means unlimited.
    pub max_uses: u32,
    /// Random token id — the host counts redemptions against this.
    pub nonce: [u8; 8],
    /// `server_root` over `SHA-256(SIG_DOMAIN || body)`.
    pub sig: [u8; SIG_LEN],
}

impl InviteToken {
    /// Mint and sign a token with `root` (the server root secret key).
    pub fn mint(
        root: &SignSecret,
        host_id: [u8; 32],
        channel_id: [u8; 32],
        relay_hint: &str,
        expires_ms: u64,
        max_uses: u32,
        nonce: [u8; 8],
    ) -> Self {
        let mut t = Self {
            server_root: root.public().to_bytes(),
            host_id,
            channel_id,
            relay_hint: relay_hint.to_owned(),
            expires_ms,
            max_uses,
            nonce,
            sig: [0u8; SIG_LEN],
        };
        t.sig = root.sign(&challenge(&t.body()));
        t
    }

    /// Everything the signature covers.
    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(TOKEN_VERSION)
            .fixed(&self.server_root)
            .fixed(&self.host_id)
            .fixed(&self.channel_id)
            .string(&self.relay_hint)
            .u64(self.expires_ms)
            .u32(self.max_uses)
            .fixed(&self.nonce);
        w.into_vec()
    }

    /// Check the signature against the embedded server root key.
    pub fn verify(&self) -> Result<(), CoreError> {
        let pk = SignPublic::from_bytes(&self.server_root)
            .map_err(|_| CoreError::Invite("bad server key"))?;
        pk.verify(&challenge(&self.body()), &self.sig)
            .map_err(|_| CoreError::Invite("bad signature"))
    }

    /// True once `now_ms` is past [`Self::expires_ms`].
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_ms
    }

    /// Encode (body + signature).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.body()).fixed(&self.sig);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let body = r.bytes()?;
        let sig = r.fixed::<SIG_LEN>()?;
        r.finish()?;

        let mut b = Reader::new(body);
        if b.u8()? != TOKEN_VERSION {
            return Err(WireError::Invalid("invite token version"));
        }
        let out = Self {
            server_root: b.fixed::<32>()?,
            host_id: b.fixed::<32>()?,
            channel_id: b.fixed::<32>()?,
            relay_hint: b.string()?,
            expires_ms: b.u64()?,
            max_uses: b.u32()?,
            nonce: b.fixed::<8>()?,
            sig,
        };
        b.finish()?;
        Ok(out)
    }

    /// Render as a shareable `dante-invite:<hex>` string.
    pub fn to_link(&self) -> String {
        let mut s = String::with_capacity(LINK_PREFIX.len() + 2);
        s.push_str(LINK_PREFIX);
        for byte in self.encode() {
            s.push(nibble(byte >> 4));
            s.push(nibble(byte & 0xf));
        }
        s
    }

    /// Parse a `dante-invite:<hex>` string (the prefix is optional). Does **not**
    /// verify the signature — call [`Self::verify`].
    pub fn from_link(s: &str) -> Result<Self, CoreError> {
        let hex = s.trim().strip_prefix(LINK_PREFIX).unwrap_or(s.trim());
        let hex = hex.trim();
        if !hex.len().is_multiple_of(2) || hex.is_empty() {
            return Err(CoreError::Invite("not a link"));
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        let raw = hex.as_bytes();
        for pair in raw.chunks(2) {
            let hi = unnibble(pair[0]).ok_or(CoreError::Invite("not hex"))?;
            let lo = unnibble(pair[1]).ok_or(CoreError::Invite("not hex"))?;
            bytes.push((hi << 4) | lo);
        }
        Self::decode(&bytes).map_err(|_| CoreError::Invite("malformed token"))
    }
}

fn challenge(body: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(SIG_DOMAIN.len() + body.len());
    buf.extend_from_slice(SIG_DOMAIN);
    buf.extend_from_slice(body);
    sha256(&buf)
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}

fn unnibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> SignSecret {
        SignSecret::from_bytes(&[7u8; 32])
    }

    fn sample() -> InviteToken {
        InviteToken::mint(
            &root(),
            [1u8; 32],
            [2u8; 32],
            "relay.example:9944",
            1_000_000,
            5,
            [9u8; 8],
        )
    }

    #[test]
    fn mint_verify_roundtrip_link() {
        let t = sample();
        t.verify().unwrap();
        let back = InviteToken::from_link(&t.to_link()).unwrap();
        assert_eq!(back, t);
        back.verify().unwrap();
        // the prefix is optional
        let bare = t.to_link().strip_prefix(LINK_PREFIX).unwrap().to_owned();
        assert_eq!(InviteToken::from_link(&bare).unwrap(), t);
    }

    #[test]
    fn tampering_breaks_the_signature() {
        let mut t = sample();
        t.channel_id[0] ^= 1;
        assert!(t.verify().is_err());

        let mut t2 = sample();
        t2.max_uses = 999;
        assert!(t2.verify().is_err());
    }

    #[test]
    fn wrong_signer_rejected() {
        let mut t = sample();
        // keep a valid self-consistent sig but claim a different server key
        let other = SignSecret::from_bytes(&[8u8; 32]);
        t.server_root = other.public().to_bytes();
        assert!(t.verify().is_err());
    }

    #[test]
    fn expiry() {
        let t = sample();
        assert!(!t.is_expired(999_999));
        assert!(t.is_expired(1_000_000));
    }

    #[test]
    fn garbage_links_are_rejected() {
        assert!(InviteToken::from_link("").is_err());
        assert!(InviteToken::from_link("dante-invite:zzzz").is_err());
        assert!(InviteToken::from_link("dante-invite:abc").is_err()); // odd length
        assert!(InviteToken::from_link("dante-invite:deadbeef").is_err());
    }
}
