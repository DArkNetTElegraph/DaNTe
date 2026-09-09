//! Server roles & permissions (v1).
//!
//! A server's roles and per-member assignments are one signed blob — the
//! [`ServerPolicy`] — minted by the host (server root key) and broadcast to
//! members over authenticated DMs (`ChannelControl::Policy`). Members verify
//! the signature and keep the highest `version` they have seen.
//!
//! Enforcement in this host-centric model:
//! - `PERM_SEND` is checked by *receivers* in `poll_channels` — a member whose
//!   effective permissions lack it has their channel messages dropped.
//! - `PERM_KICK` gates a member's `ChannelControl::KickRequest`, which the host
//!   validates before running the removal.
//!
//! The other bits are advisory today; the host still performs every privileged
//! mutation because only it holds the root key.

use dante_crypto::{
    hash::sha256,
    sign::{SignPublic, SignSecret, SIG_LEN},
};
use dante_proto::enc::{Reader, WireError, Writer};

use crate::error::CoreError;

/// Post messages to the server's channels.
pub const PERM_SEND: u32 = 1 << 0;
/// Ask the host to remove a member (`ChannelControl::KickRequest`).
pub const PERM_KICK: u32 = 1 << 1;
/// Create / delete channels (advisory — host performs it).
pub const PERM_MANAGE_CHANNELS: u32 = 1 << 2;
/// Create / edit roles and assignments (advisory — host performs it).
pub const PERM_MANAGE_ROLES: u32 = 1 << 3;
/// Create invite links (advisory — only the host can sign one).
pub const PERM_INVITE: u32 = 1 << 4;
/// Everything.
pub const PERM_ALL: u32 = u32::MAX;
/// What a member with no explicit role can do (`@everyone`).
pub const PERM_DEFAULT: u32 = PERM_SEND;

const SIG_DOMAIN: &[u8] = b"dante/server-policy/v1";

/// Max bytes of a custom-emoji shortcode (the `name` in `:name:`).
pub const EMOJI_NAME_MAX: usize = 32;
/// Max custom emoji a single server may register.
pub const MAX_SERVER_EMOJIS: usize = 200;
/// Max stickers a single server may register (fewer than emoji — each is a
/// much larger image).
pub const MAX_SERVER_STICKERS: usize = 100;

/// Whether `name` is a valid custom-emoji shortcode: 1..=[`EMOJI_NAME_MAX`]
/// bytes of `[a-z0-9_]`. Enforced both when an emoji is set and when a received
/// policy is decoded, so a peer cannot smuggle markup (`"><img onerror=...>`)
/// through a shortcode that a client later renders.
pub fn valid_emoji_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= EMOJI_NAME_MAX
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// One named role. Permissions are allow/deny masks layered over the
/// `@everyone` default ([`PERM_DEFAULT`]); denies win, so a zero-`allow`
/// full-`deny` role is a mute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Role {
    /// Stable id, allocated by the host (1..). `0` is the implicit `@everyone`.
    pub id: u16,
    /// Display name.
    pub name: String,
    /// Bits this role grants.
    pub allow: u32,
    /// Bits this role revokes (applied after every `allow`).
    pub deny: u32,
    /// Higher rank sorts first in the member list.
    pub rank: u16,
}

impl Role {
    fn write(&self, w: &mut Writer) {
        w.u16(self.id)
            .string(&self.name)
            .u32(self.allow)
            .u32(self.deny)
            .u16(self.rank);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            id: r.u16()?,
            name: r.string()?,
            allow: r.u32()?,
            deny: r.u32()?,
            rank: r.u16()?,
        })
    }
}

/// A server's whole role configuration, signed by the server root key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerPolicy {
    /// The server root public key (also the signature verifier).
    pub server_root: [u8; 32],
    /// `IdentityId` of the owner (host) — always has [`PERM_ALL`].
    pub owner_id: [u8; 32],
    /// Bumped on every change; members keep the highest they have seen.
    pub version: u64,
    /// Named roles (excludes the implicit `@everyone`).
    pub roles: Vec<Role>,
    /// `member -> role ids`.
    pub assignments: Vec<([u8; 32], Vec<u16>)>,
    /// Custom emoji: `shortcode -> SHA-256 of the (plaintext) image blob on the
    /// relay blob store`. Rendered client-side as `:shortcode:`.
    pub emojis: Vec<(String, [u8; 32])>,
    /// Stickers: `name -> SHA-256 of the (plaintext) image blob`. Like custom
    /// emoji but a larger image, sent as a message of its own rather than
    /// inline. Name charset matches an emoji shortcode.
    pub stickers: Vec<(String, [u8; 32])>,
    /// When it was issued (Unix ms).
    pub issued_ms: u64,
    /// `server_root` over `SHA-256(SIG_DOMAIN || body)`.
    pub sig: [u8; SIG_LEN],
}

impl ServerPolicy {
    /// A fresh empty policy for a newly-created server.
    pub fn genesis(root: &SignSecret, owner_id: [u8; 32], now_ms: u64) -> Self {
        Self::signed(
            root,
            owner_id,
            1,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            now_ms,
        )
    }

    /// Build and sign a policy at `version`.
    #[allow(clippy::too_many_arguments)]
    pub fn signed(
        root: &SignSecret,
        owner_id: [u8; 32],
        version: u64,
        roles: Vec<Role>,
        assignments: Vec<([u8; 32], Vec<u16>)>,
        emojis: Vec<(String, [u8; 32])>,
        stickers: Vec<(String, [u8; 32])>,
        now_ms: u64,
    ) -> Self {
        let mut p = Self {
            server_root: root.public().to_bytes(),
            owner_id,
            version,
            roles,
            assignments,
            emojis,
            stickers,
            issued_ms: now_ms,
            sig: [0u8; SIG_LEN],
        };
        p.sig = root.sign(&challenge(&p.body()));
        p
    }

    /// The relay blob hash for a custom emoji shortcode, if the server has one.
    pub fn emoji_hash(&self, name: &str) -> Option<[u8; 32]> {
        self.emojis.iter().find(|(n, _)| n == name).map(|(_, h)| *h)
    }

    /// The relay blob hash for a sticker name, if the server has one.
    pub fn sticker_hash(&self, name: &str) -> Option<[u8; 32]> {
        self.stickers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, h)| *h)
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.server_root)
            .fixed(&self.owner_id)
            .u64(self.version)
            .u64(self.issued_ms)
            .u32(self.roles.len() as u32);
        for role in &self.roles {
            role.write(&mut w);
        }
        w.u32(self.assignments.len() as u32);
        for (m, ids) in &self.assignments {
            w.fixed(m).u32(ids.len() as u32);
            for id in ids {
                w.u16(*id);
            }
        }
        // Tail-appended so a policy signed before custom emoji existed still
        // verifies (its body ends after `assignments`, `emojis` is empty).
        // The sticker list is a further tail after that; when it is present the
        // emoji count is always written (possibly 0) so the reader can tell the
        // two sections apart.
        if !self.emojis.is_empty() || !self.stickers.is_empty() {
            w.u32(self.emojis.len() as u32);
            for (name, hash) in &self.emojis {
                w.string(name).fixed(hash);
            }
        }
        if !self.stickers.is_empty() {
            w.u32(self.stickers.len() as u32);
            for (name, hash) in &self.stickers {
                w.string(name).fixed(hash);
            }
        }
        w.into_vec()
    }

    /// Verify the signature against the embedded server root key.
    pub fn verify(&self) -> Result<(), CoreError> {
        let pk = SignPublic::from_bytes(&self.server_root)
            .map_err(|_| CoreError::Channel("bad server key in policy"))?;
        pk.verify(&challenge(&self.body()), &self.sig)
            .map_err(|_| CoreError::Channel("bad policy signature"))
    }

    /// A member's effective permission mask: `(PERM_DEFAULT | Σ allow) & !Σ deny`.
    /// The owner always has [`PERM_ALL`].
    pub fn effective_perms(&self, member: &[u8; 32]) -> u32 {
        if *member == self.owner_id {
            return PERM_ALL;
        }
        let (mut allow, mut deny) = (0u32, 0u32);
        if let Some((_, ids)) = self.assignments.iter().find(|(m, _)| m == member) {
            for id in ids {
                if let Some(role) = self.roles.iter().find(|r| r.id == *id) {
                    allow |= role.allow;
                    deny |= role.deny;
                }
            }
        }
        (PERM_DEFAULT | allow) & !deny
    }

    /// The highest-rank role name for a member (for member-list grouping), or
    /// `None` for a plain `@everyone` member.
    pub fn top_role_name(&self, member: &[u8; 32]) -> Option<&str> {
        if *member == self.owner_id {
            return Some("Owner");
        }
        let (_, ids) = self.assignments.iter().find(|(m, _)| m == member)?;
        self.roles
            .iter()
            .filter(|r| ids.contains(&r.id))
            .max_by_key(|r| r.rank)
            .map(|r| r.name.as_str())
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
        let server_root = b.fixed::<32>()?;
        let owner_id = b.fixed::<32>()?;
        let version = b.u64()?;
        let issued_ms = b.u64()?;
        let nr = bounded(&mut b)?;
        let mut roles = Vec::with_capacity(nr);
        for _ in 0..nr {
            roles.push(Role::read(&mut b)?);
        }
        let na = bounded(&mut b)?;
        let mut assignments = Vec::with_capacity(na);
        for _ in 0..na {
            let m = b.fixed::<32>()?;
            let ni = bounded(&mut b)?;
            let mut ids = Vec::with_capacity(ni);
            for _ in 0..ni {
                ids.push(b.u16()?);
            }
            assignments.push((m, ids));
        }
        let mut emojis = Vec::new();
        if b.remaining() > 0 {
            let ne = bounded(&mut b)?;
            emojis.reserve(ne);
            for _ in 0..ne {
                let name = b.string()?;
                // Reject a shortcode a peer could weaponise at the render sink,
                // regardless of the (validly signed) policy carrying it.
                if !valid_emoji_name(&name) {
                    return Err(WireError::Invalid("emoji shortcode"));
                }
                emojis.push((name, b.fixed::<32>()?));
            }
        }
        let mut stickers = Vec::new();
        if b.remaining() > 0 {
            let ns = bounded(&mut b)?;
            stickers.reserve(ns);
            for _ in 0..ns {
                let name = b.string()?;
                if !valid_emoji_name(&name) {
                    return Err(WireError::Invalid("sticker name"));
                }
                stickers.push((name, b.fixed::<32>()?));
            }
        }
        b.finish()?;
        Ok(Self {
            server_root,
            owner_id,
            version,
            roles,
            assignments,
            emojis,
            stickers,
            issued_ms,
            sig,
        })
    }
}

fn challenge(body: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(SIG_DOMAIN.len() + body.len());
    buf.extend_from_slice(SIG_DOMAIN);
    buf.extend_from_slice(body);
    sha256(&buf)
}

fn bounded(r: &mut Reader<'_>) -> Result<usize, WireError> {
    let n = r.u32()? as usize;
    if n > r.remaining() {
        return Err(WireError::LengthTooLarge(n as u64));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> SignSecret {
        SignSecret::from_bytes(&[3u8; 32])
    }

    #[test]
    fn genesis_and_effective_perms() {
        let owner = [1u8; 32];
        let p = ServerPolicy::genesis(&root(), owner, 0);
        p.verify().unwrap();
        assert_eq!(p.effective_perms(&owner), PERM_ALL);
        assert_eq!(p.effective_perms(&[9u8; 32]), PERM_DEFAULT);
    }

    #[test]
    fn roles_union_and_ranking() {
        let owner = [1u8; 32];
        let mod_role = Role {
            id: 1,
            name: "Mod".into(),
            allow: PERM_KICK,
            deny: 0,
            rank: 10,
        };
        let muted = Role {
            id: 2,
            name: "Muted".into(),
            allow: 0,
            deny: PERM_ALL,
            rank: 1,
        };
        let alice = [7u8; 32];
        let p = ServerPolicy::signed(
            &root(),
            owner,
            5,
            vec![mod_role, muted],
            vec![(alice, vec![1, 2])],
            vec![],
            vec![],
            0,
        );
        p.verify().unwrap();
        // Mod grants KICK, Muted denies everything -> deny wins.
        assert_eq!(p.effective_perms(&alice), 0);
        // ... but a member with only Mod keeps SEND and gains KICK.
        let carol = [8u8; 32];
        let p2 = ServerPolicy::signed(
            &root(),
            owner,
            6,
            p.roles.clone(),
            vec![(carol, vec![1])],
            vec![],
            vec![],
            0,
        );
        assert_eq!(p2.effective_perms(&carol), PERM_DEFAULT | PERM_KICK);
        assert_eq!(p.top_role_name(&alice), Some("Mod"));
        assert_eq!(p.top_role_name(&owner), Some("Owner"));
        assert_eq!(p.top_role_name(&[0u8; 32]), None);

        assert_eq!(ServerPolicy::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn custom_emoji_roundtrips_and_is_signed() {
        let owner = [1u8; 32];
        let emojis = vec![
            ("blobwave".to_string(), [9u8; 32]),
            ("party_parrot".to_string(), [8u8; 32]),
        ];
        let p = ServerPolicy::signed(&root(), owner, 3, vec![], vec![], emojis.clone(), vec![], 0);
        p.verify().unwrap();
        assert_eq!(p.emoji_hash("party_parrot"), Some([8u8; 32]));
        assert_eq!(p.emoji_hash("nope"), None);
        assert_eq!(ServerPolicy::decode(&p.encode()).unwrap(), p);

        // An emoji-free policy still encodes to the pre-emoji body layout.
        let plain = ServerPolicy::genesis(&root(), owner, 0);
        assert!(plain.emojis.is_empty());
        assert!(plain.stickers.is_empty());
        assert_eq!(ServerPolicy::decode(&plain.encode()).unwrap(), plain);
    }

    #[test]
    fn stickers_roundtrip_and_survive_an_empty_emoji_list() {
        let owner = [1u8; 32];
        let stickers = vec![
            ("wave".to_string(), [4u8; 32]),
            ("shrug_dog".to_string(), [5u8; 32]),
        ];
        // No emoji, only stickers — the emoji count (0) must still be written
        // so decode can split the two tail sections.
        let p = ServerPolicy::signed(
            &root(),
            owner,
            7,
            vec![],
            vec![],
            vec![],
            stickers.clone(),
            0,
        );
        p.verify().unwrap();
        assert_eq!(p.sticker_hash("wave"), Some([4u8; 32]));
        assert_eq!(p.sticker_hash("nope"), None);
        assert_eq!(ServerPolicy::decode(&p.encode()).unwrap(), p);

        // Both lists populated.
        let both = ServerPolicy::signed(
            &root(),
            owner,
            8,
            vec![],
            vec![],
            vec![("blob".to_string(), [9u8; 32])],
            stickers,
            0,
        );
        both.verify().unwrap();
        assert_eq!(ServerPolicy::decode(&both.encode()).unwrap(), both);

        // A hostile sticker name is refused at decode, like an emoji shortcode.
        let evil = ServerPolicy::signed(
            &root(),
            owner,
            9,
            vec![],
            vec![],
            vec![],
            vec![(r#"x"><img src=x>"#.to_string(), [1u8; 32])],
            0,
        );
        assert!(matches!(
            ServerPolicy::decode(&evil.encode()),
            Err(WireError::Invalid("sticker name"))
        ));
    }

    #[test]
    fn decode_rejects_a_malicious_emoji_shortcode() {
        // A (validly signed) policy whose shortcode carries markup must be
        // refused at decode, before it can reach a client's render sink.
        let owner = [1u8; 32];
        let evil = vec![(r#"x"><img src=x onerror=alert(1)>"#.to_string(), [9u8; 32])];
        let p = ServerPolicy::signed(&root(), owner, 3, vec![], vec![], evil, vec![], 0);
        // The signature is valid over the hostile bytes...
        p.verify().unwrap();
        // ...but decode refuses the shortcode.
        assert!(matches!(
            ServerPolicy::decode(&p.encode()),
            Err(WireError::Invalid("emoji shortcode"))
        ));
        // A normal shortcode still decodes.
        assert!(valid_emoji_name("party_parrot"));
        assert!(!valid_emoji_name("Party"));
        assert!(!valid_emoji_name(""));
    }

    #[test]
    fn tampering_breaks_signature() {
        let mut p = ServerPolicy::genesis(&root(), [1u8; 32], 0);
        p.version = 999;
        assert!(p.verify().is_err());
    }

    #[test]
    fn decode_is_total_on_garbage() {
        assert!(ServerPolicy::decode(&[]).is_err());
        assert!(ServerPolicy::decode(&[0u8; 40]).is_err());
    }
}
