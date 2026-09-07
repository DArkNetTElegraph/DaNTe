//! The Double Ratchet (Signal), with un-encrypted headers.

use std::collections::HashMap;

use dante_crypto::{
    aead,
    agree::{AgreePublic, AgreeSecret},
};
use dante_proto::enc::{Reader, WireError, Writer};
use zeroize::Zeroize;

use crate::{
    error::DmError,
    kdf::{kdf_ck, kdf_rk, message_keys},
};

/// Maximum message keys the ratchet will skip (and retain) across a gap.
pub const MAX_SKIP: u32 = 1000;

/// The per-message ratchet header, sent alongside the ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Sender's current ratchet public key.
    pub dh: [u8; 32],
    /// Number of messages in the previous sending chain.
    pub pn: u32,
    /// Message index in the current sending chain.
    pub n: u32,
}

impl Header {
    /// 40-byte fixed encoding.
    pub fn encode(&self) -> [u8; 40] {
        let mut w = Writer::with_capacity(40);
        w.fixed(&self.dh).u32(self.pn).u32(self.n);
        w.into_vec().try_into().unwrap()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let dh = r.fixed::<32>()?;
        let pn = r.u32()?;
        let n = r.u32()?;
        r.finish()?;
        Ok(Self { dh, pn, n })
    }
}

/// Double Ratchet state for one peer. Chain/root keys zeroize on drop.
pub struct Ratchet {
    dhs: AgreeSecret,
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl Ratchet {
    /// Initiator side: `sk` from X3DH, `their_ratchet_pub` is the peer's signed
    /// prekey public.
    pub fn init_alice(sk: &[u8; 32], their_ratchet_pub: &[u8; 32]) -> Result<Self, DmError> {
        let dhs = AgreeSecret::generate();
        let dh_out = dhs.agree(&AgreePublic::from_bytes(their_ratchet_pub))?;
        let (rk, cks) = kdf_rk(sk, &dh_out);
        Ok(Self {
            dhs,
            dhr: Some(*their_ratchet_pub),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        })
    }

    /// Responder side: `sk` from X3DH, `ratchet_secret` is our signed prekey
    /// keypair. No sending chain until the first inbound message.
    pub fn init_bob(sk: &[u8; 32], ratchet_secret: AgreeSecret) -> Self {
        Self {
            dhs: ratchet_secret,
            dhr: None,
            rk: *sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    /// Encrypt `plaintext`. `ad` is the session associated data.
    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<(Header, Vec<u8>), DmError> {
        let cks = self.cks.ok_or(DmError::NotReady("send"))?;
        let (next_ck, mk) = kdf_ck(&cks);
        let header = Header {
            dh: self.dhs.public().to_bytes(),
            pn: self.pn,
            n: self.ns,
        };
        self.cks = Some(next_ck);
        self.ns += 1;

        let (key, nonce) = message_keys(&mk);
        let ct = aead::xchacha_seal(&key, &nonce, plaintext, &aad_with_header(ad, &header));
        Ok((header, ct))
    }

    /// Decrypt a message with `header` and `ct`.
    pub fn decrypt(&mut self, header: &Header, ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, DmError> {
        if let Some(mk) = self.skipped.remove(&(header.dh, header.n)) {
            return open(&mk, header, ct, ad);
        }
        if self.dhr != Some(header.dh) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header)?;
        }
        self.skip_message_keys(header.n)?;

        let ckr = self.ckr.ok_or(DmError::NotReady("receive"))?;
        let (next_ck, mk) = kdf_ck(&ckr);
        self.ckr = Some(next_ck);
        self.nr += 1;
        open(&mk, header, ct, ad)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), DmError> {
        let Some(mut ck) = self.ckr else {
            return Ok(());
        };
        if self.nr + MAX_SKIP < until {
            return Err(DmError::TooManySkipped);
        }
        let dhr = self.dhr.expect("ckr implies dhr");
        while self.nr < until {
            let (next_ck, mk) = kdf_ck(&ck);
            self.skipped.insert((dhr, self.nr), mk);
            ck = next_ck;
            self.nr += 1;
        }
        self.ckr = Some(ck);
        Ok(())
    }

    fn dh_ratchet(&mut self, header: &Header) -> Result<(), DmError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh);

        let dh1 = self.dhs.agree(&AgreePublic::from_bytes(&header.dh))?;
        let (rk, ckr) = kdf_rk(&self.rk, &dh1);
        self.rk = rk;
        self.ckr = Some(ckr);

        self.dhs = AgreeSecret::generate();
        let dh2 = self.dhs.agree(&AgreePublic::from_bytes(&header.dh))?;
        let (rk, cks) = kdf_rk(&self.rk, &dh2);
        self.rk = rk;
        self.cks = Some(cks);
        Ok(())
    }
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.rk.zeroize();
        if let Some(c) = &mut self.cks {
            c.zeroize();
        }
        if let Some(c) = &mut self.ckr {
            c.zeroize();
        }
        for mk in self.skipped.values_mut() {
            mk.zeroize();
        }
    }
}

fn aad_with_header(ad: &[u8], header: &Header) -> Vec<u8> {
    let mut v = Vec::with_capacity(ad.len() + 40);
    v.extend_from_slice(ad);
    v.extend_from_slice(&header.encode());
    v
}

fn open(mk: &[u8; 32], header: &Header, ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, DmError> {
    let (key, nonce) = message_keys(mk);
    aead::xchacha_open(&key, &nonce, ct, &aad_with_header(ad, header)).map_err(|_| DmError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal harness: skip X3DH, seed both sides with a shared `sk` and Bob's
    // ratchet keypair.
    fn pair() -> (Ratchet, Ratchet) {
        let sk = [42u8; 32];
        let bob_spk = AgreeSecret::generate();
        let alice = Ratchet::init_alice(&sk, &bob_spk.public().to_bytes()).unwrap();
        let bob = Ratchet::init_bob(&sk, bob_spk);
        (alice, bob)
    }

    const AD: &[u8] = b"alice||bob";

    #[test]
    fn header_roundtrip() {
        let h = Header {
            dh: [5u8; 32],
            pn: 7,
            n: 12,
        };
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn basic_back_and_forth() {
        let (mut a, mut b) = pair();
        let (h, c) = a.encrypt(b"hello bob", AD).unwrap();
        assert_eq!(b.decrypt(&h, &c, AD).unwrap(), b"hello bob");

        let (h, c) = b.encrypt(b"hi alice", AD).unwrap();
        assert_eq!(a.decrypt(&h, &c, AD).unwrap(), b"hi alice");

        let (h, c) = a.encrypt(b"how are you", AD).unwrap();
        assert_eq!(b.decrypt(&h, &c, AD).unwrap(), b"how are you");
    }

    #[test]
    fn out_of_order_within_a_chain() {
        let (mut a, mut b) = pair();
        let m0 = a.encrypt(b"0", AD).unwrap();
        let m1 = a.encrypt(b"1", AD).unwrap();
        let m2 = a.encrypt(b"2", AD).unwrap();
        // deliver 2, 0, 1
        assert_eq!(b.decrypt(&m2.0, &m2.1, AD).unwrap(), b"2");
        assert_eq!(b.decrypt(&m0.0, &m0.1, AD).unwrap(), b"0");
        assert_eq!(b.decrypt(&m1.0, &m1.1, AD).unwrap(), b"1");
    }

    #[test]
    fn dropped_message_across_a_dh_step() {
        let (mut a, mut b) = pair();
        let _lost = a.encrypt(b"lost", AD).unwrap();
        let kept = a.encrypt(b"kept", AD).unwrap();
        assert_eq!(b.decrypt(&kept.0, &kept.1, AD).unwrap(), b"kept");
        // b replies -> dh step; a's next message is a new chain
        let reply = b.encrypt(b"reply", AD).unwrap();
        assert_eq!(a.decrypt(&reply.0, &reply.1, AD).unwrap(), b"reply");
        let after = a.encrypt(b"after", AD).unwrap();
        assert_eq!(b.decrypt(&after.0, &after.1, AD).unwrap(), b"after");
        // the lost message can still be recovered from a skipped key
        assert_eq!(b.decrypt(&_lost.0, &_lost.1, AD).unwrap(), b"lost");
    }

    #[test]
    fn tampered_ciphertext_and_ad_are_rejected() {
        let (mut a, mut b) = pair();
        let (h, mut c) = a.encrypt(b"secret", AD).unwrap();
        let mut c2 = c.clone();
        c2[0] ^= 1;
        assert!(matches!(b.decrypt(&h, &c2, AD), Err(DmError::Decrypt)));
        c[0] ^= 0; // unchanged
        assert!(matches!(
            b.decrypt(&h, &c, b"wrong-ad"),
            Err(DmError::Decrypt)
        ));
    }

    #[test]
    fn excessive_skip_is_refused() {
        let (mut a, mut b) = pair();
        let first = a.encrypt(b"x", AD).unwrap();
        b.decrypt(&first.0, &first.1, AD).unwrap();
        // forge a header claiming a huge index in the same chain
        let mut forged = a.encrypt(b"y", AD).unwrap();
        forged.0.n = MAX_SKIP + 50;
        assert!(matches!(
            b.decrypt(&forged.0, &forged.1, AD),
            Err(DmError::TooManySkipped)
        ));
    }
}
