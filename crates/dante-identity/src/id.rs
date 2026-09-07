//! [`IdentityId`] and its human-facing renderings.
//!
//! An identity's unique id is `SHA-256(idk_pub)` — 32 bytes, not chosen by the
//! user, not squattable. It renders two ways over the *same* value:
//!
//! - **Crockford base32**, in 4-character groups: `K7F3-9QW2-…`
//! - **BIP39 word phrase** (24 words), for reading aloud or writing down
//!
//! [`safety_number`] derives a 60-digit code from a *pair* of ids for
//! out-of-band verification ("are we really talking to each other").

use dante_crypto::{
    hash::{sha256, sha512},
    sign::SignPublic,
};

use crate::error::IdentityError;

/// A DaNTe identity id: `SHA-256(idk_pub)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IdentityId([u8; 32]);

impl IdentityId {
    /// Derive the id of the identity owning `idk_pub`.
    pub fn of(idk_pub: &SignPublic) -> Self {
        Self(sha256(&idk_pub.to_bytes()))
    }

    /// Wrap raw id bytes (e.g. read from a ledger record).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Render as Crockford base32 in 4-character groups.
    pub fn to_base32(&self) -> String {
        crockford_encode_grouped(&self.0)
    }

    /// Parse a Crockford-base32 rendering. Tolerates lowercase, `I`/`L`→`1`,
    /// `O`→`0`, and any interspersed `-` or whitespace.
    pub fn from_base32(s: &str) -> Result<Self, IdentityError> {
        let bytes = crockford_decode(s).ok_or(IdentityError::BadFingerprint)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::BadFingerprint)?;
        Ok(Self(arr))
    }

    /// Render as a 24-word BIP39 phrase encoding the same 32 bytes.
    pub fn to_words(&self) -> String {
        bip39::Mnemonic::from_entropy(&self.0)
            .expect("32 bytes is valid BIP39 entropy")
            .to_string()
    }

    /// Parse a 24-word BIP39 phrase. Word case and spacing are normalised.
    pub fn from_words(s: &str) -> Result<Self, IdentityError> {
        let normalised = s
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        let mnemonic =
            bip39::Mnemonic::parse(&normalised).map_err(|_| IdentityError::BadFingerprint)?;
        let (entropy, len) = mnemonic.to_entropy_array();
        if len != 32 {
            return Err(IdentityError::BadFingerprint);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&entropy[..32]);
        Ok(Self(out))
    }
}

impl core::fmt::Display for IdentityId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_base32())
    }
}

impl core::fmt::Debug for IdentityId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IdentityId({})", self.to_base32())
    }
}

/// Order-independent 60-digit safety number for two identities, rendered as 12
/// groups of 5 digits.
///
/// Method (domain-separated, deliberately slow like Signal's): for each party
/// `x` with peer `y`, iterate `h = SHA-512(h || x)` 5200 times starting from
/// `SHA-512(DOMAIN || min(a,b) || max(a,b))`, take the first 30 bytes as six
/// 40-bit big-endian groups each reduced mod 100000. Concatenate the
/// lexicographically smaller id's 30 digits first.
pub fn safety_number(a: &IdentityId, b: &IdentityId) -> String {
    const DOMAIN: &[u8] = b"DaNTe-safety-number-v1";
    const ITERS: usize = 5200;

    let (lo, hi) = if a.0 <= b.0 { (a, b) } else { (b, a) };

    let party_digits = |me: &IdentityId| -> String {
        let mut h = sha512(&[DOMAIN, &lo.0, &hi.0, &me.0].concat());
        for _ in 0..ITERS {
            h = sha512(&[h.as_slice(), &me.0].concat());
        }
        let mut s = String::with_capacity(30);
        for chunk in h[..30].chunks_exact(5) {
            let mut v: u64 = 0;
            for &byte in chunk {
                v = (v << 8) | u64::from(byte);
            }
            s.push_str(&format!("{:05}", v % 100_000));
        }
        s
    };

    let digits = format!("{}{}", party_digits(lo), party_digits(hi));
    digits
        .as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn crockford_encode_grouped(data: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u16 = 0;
    let mut bits: u32 = 0;
    let mut symbols = 0usize;
    for &byte in data {
        acc = (acc << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & 0x1f) as usize;
            if symbols > 0 && symbols % 4 == 0 {
                out.push('-');
            }
            out.push(CROCKFORD[idx] as char);
            symbols += 1;
        }
    }
    if bits > 0 {
        let idx = ((acc << (5 - bits)) & 0x1f) as usize;
        if symbols > 0 && symbols % 4 == 0 {
            out.push('-');
        }
        out.push(CROCKFORD[idx] as char);
    }
    out
}

fn crockford_symbol(c: char) -> Option<u8> {
    let up = c.to_ascii_uppercase();
    let norm = match up {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    CROCKFORD
        .iter()
        .position(|&x| x as char == norm)
        .map(|p| p as u8)
}

fn crockford_decode(s: &str) -> Option<Vec<u8>> {
    let mut acc: u16 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(32);
    let mut symbols = 0usize;
    for c in s.chars() {
        if c == '-' || c.is_whitespace() {
            continue;
        }
        let val = crockford_symbol(c)?;
        acc = (acc << 5) | u16::from(val);
        bits += 5;
        symbols += 1;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // 32 bytes come from exactly 52 base32 symbols (260 bits, 4 padding bits).
    if symbols != 52 || out.len() != 32 {
        return None;
    }
    // The 4 trailing bits must be zero for a canonical encoding.
    if bits != 4 || (acc & 0x0f) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use dante_crypto::sign::SignSecret;

    use super::*;

    fn sample_id(seed: u8) -> IdentityId {
        IdentityId::of(&SignSecret::from_bytes(&[seed; 32]).public())
    }

    #[test]
    fn base32_roundtrips_and_groups() {
        let id = sample_id(1);
        let s = id.to_base32();
        assert_eq!(s.len(), 52 + 12, "52 symbols + 12 group separators");
        assert_eq!(s.chars().filter(|c| *c == '-').count(), 12);
        assert_eq!(IdentityId::from_base32(&s).unwrap(), id);
    }

    #[test]
    fn base32_input_normalisation() {
        let id = sample_id(2);
        let canonical = id.to_base32();
        let messy = canonical
            .to_lowercase()
            .replace('-', "  ")
            .replace('0', "O")
            .replace('1', "I");
        assert_eq!(IdentityId::from_base32(&messy).unwrap(), id);
    }

    #[test]
    fn base32_rejects_garbage_and_wrong_length() {
        assert!(IdentityId::from_base32("not base 32 !!").is_err());
        assert!(IdentityId::from_base32("K7F3").is_err());
    }

    #[test]
    fn words_roundtrip_24_words() {
        let id = sample_id(3);
        let phrase = id.to_words();
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert_eq!(IdentityId::from_words(&phrase).unwrap(), id);
        // case / spacing tolerance
        let upper = phrase.to_uppercase().replace(' ', "   ");
        assert_eq!(IdentityId::from_words(&upper).unwrap(), id);
    }

    #[test]
    fn words_reject_bad_checksum() {
        let id = sample_id(4);
        let phrase = id.to_words();
        let mut words: Vec<&str> = phrase.split(' ').collect();
        // swap first two words -> checksum fails
        words.swap(0, 1);
        assert!(IdentityId::from_words(&words.join(" ")).is_err());
    }

    #[test]
    fn base32_and_words_encode_the_same_bytes() {
        let id = sample_id(5);
        assert_eq!(
            IdentityId::from_words(&id.to_words()).unwrap(),
            IdentityId::from_base32(&id.to_base32()).unwrap()
        );
    }

    #[test]
    fn safety_number_is_order_independent_and_shaped() {
        let a = sample_id(10);
        let b = sample_id(20);
        let ab = safety_number(&a, &b);
        let ba = safety_number(&b, &a);
        assert_eq!(ab, ba);
        assert_eq!(ab.chars().filter(|c| c.is_ascii_digit()).count(), 60);
        assert_eq!(ab.split(' ').count(), 12);
    }

    #[test]
    fn safety_number_differs_for_different_peers() {
        let a = sample_id(10);
        let b = sample_id(20);
        let c = sample_id(30);
        assert_ne!(safety_number(&a, &b), safety_number(&a, &c));
    }
}
