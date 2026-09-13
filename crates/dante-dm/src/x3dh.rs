//! X3DH: the initial shared secret for a Double Ratchet session
//! (`docs/PROTOCOL.md` §4.3).

use dante_crypto::{
    agree::{AgreePublic, AgreeSecret},
    hash::sha256_parts,
    kdf,
    sign::SignPublic,
};
use dante_identity::Identity;
use dante_proto::enc::{Reader, WireError, Writer};

use crate::error::DmError;

const SPK_SIG_DOMAIN: &[u8] = b"dante/x3dh/signed-prekey/v1";
/// Each one-time prekey is signed individually (not as part of one signature
/// over the whole list) because the relay legitimately hands out a **subset**
/// of the published OTPs — one per fetch, so two initiators never race for
/// the same key (`dante-relay`'s `GetPrekeys` handler slices the stored
/// bundle down to a single OTP per response). A whole-list signature would
/// have to cover every OTP that was ever published to still verify, which
/// breaks the moment the relay serves fewer than all of them. Per-OTP
/// signatures let a single `(otp, sig)` pair verify on its own regardless of
/// how many others were originally published alongside it, while still
/// making it impossible to substitute in an OTP the real owner never signed
/// — the concrete gap a relay-directory-writes security audit found: the OTP
/// list used to carry no signature at all, so a bundle could be
/// re-published with the OTPs swapped for the attacker's own, and
/// `bundle.verify()` (which only ever checked `spk_sig` over `spk_pub`)
/// passed regardless. See `docs/THREAT_MODEL.md` §6.
const OTP_SIG_DOMAIN: &[u8] = b"dante/x3dh/signed-otp/v1";
const X3DH_INFO: &[u8] = b"dante/x3dh/v1";
/// Max one-time prekeys in a published bundle.
pub const MAX_OTPS: usize = 100;

/// A peer's published prekeys. Fetched from the ledger/relay before initiating.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreKeyBundle {
    /// Peer's `IdentityId`.
    pub identity_id: [u8; 32],
    /// Peer's Ed25519 identity key.
    pub idk_pub: [u8; 32],
    /// Peer's long-term X25519 key.
    pub ik_pub: [u8; 32],
    /// Peer's signed prekey (X25519).
    pub spk_pub: [u8; 32],
    /// `idk_pub` over `SHA-256(domain || spk_pub)`.
    pub spk_sig: [u8; 64],
    /// Unused one-time prekeys (X25519) each paired with `idk_pub`'s own
    /// signature over it (see [`Self::otp_sig_challenge`]); one pair is
    /// consumed per new session.
    pub otps: Vec<([u8; 32], [u8; 64])>,
}

impl PreKeyBundle {
    /// The bytes `spk_sig` covers.
    pub fn spk_sig_challenge(spk_pub: &[u8; 32]) -> [u8; 32] {
        sha256_parts(&[SPK_SIG_DOMAIN, spk_pub])
    }

    /// The bytes an individual OTP's own signature covers — bound to
    /// `spk_pub` too, so an OTP signed for one bundle can't be replayed
    /// alongside a different `spk_pub` from the same identity.
    pub fn otp_sig_challenge(spk_pub: &[u8; 32], otp: &[u8; 32]) -> [u8; 32] {
        sha256_parts(&[OTP_SIG_DOMAIN, spk_pub, otp])
    }

    /// Verify `spk_sig` and every individual OTP signature.
    pub fn verify(&self) -> Result<(), DmError> {
        let idk = SignPublic::from_bytes(&self.idk_pub).map_err(|_| DmError::BadPrekeySignature)?;
        idk.verify(&Self::spk_sig_challenge(&self.spk_pub), &self.spk_sig)
            .map_err(|_| DmError::BadPrekeySignature)?;
        for (otp, sig) in &self.otps {
            idk.verify(&Self::otp_sig_challenge(&self.spk_pub, otp), sig)
                .map_err(|_| DmError::BadPrekeySignature)?;
        }
        Ok(())
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.identity_id)
            .fixed(&self.idk_pub)
            .fixed(&self.ik_pub)
            .fixed(&self.spk_pub)
            .fixed(&self.spk_sig)
            .u32(self.otps.len() as u32);
        for (otp, sig) in &self.otps {
            w.fixed(otp).fixed(sig);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let identity_id = r.fixed::<32>()?;
        let idk_pub = r.fixed::<32>()?;
        let ik_pub = r.fixed::<32>()?;
        let spk_pub = r.fixed::<32>()?;
        let spk_sig = r.fixed::<64>()?;
        let n = r.u32()? as usize;
        if n > r.remaining() {
            return Err(WireError::LengthTooLarge(n as u64));
        }
        let mut otps = Vec::with_capacity(n);
        for _ in 0..n {
            otps.push((r.fixed::<32>()?, r.fixed::<64>()?));
        }
        r.finish()?;
        Ok(Self {
            identity_id,
            idk_pub,
            ik_pub,
            spk_pub,
            spk_sig,
            otps,
        })
    }
}

/// The secret halves of one's own published prekeys.
pub struct PreKeySecrets {
    spk: AgreeSecret,
    otps: Vec<AgreeSecret>,
}

impl PreKeySecrets {
    /// Generate a signed prekey and `n_otps` one-time prekeys.
    pub fn generate(n_otps: usize) -> Self {
        Self {
            spk: AgreeSecret::generate(),
            otps: (0..n_otps.min(MAX_OTPS))
                .map(|_| AgreeSecret::generate())
                .collect(),
        }
    }

    /// The signed-prekey public value.
    pub fn spk_public(&self) -> [u8; 32] {
        self.spk.public().to_bytes()
    }

    /// Build the publishable bundle for `identity`.
    pub fn bundle(&self, identity: &Identity) -> PreKeyBundle {
        let spk_pub = self.spk.public().to_bytes();
        let otps = self
            .otps
            .iter()
            .map(|o| {
                let pub_key = o.public().to_bytes();
                let sig = identity.sign(&PreKeyBundle::otp_sig_challenge(&spk_pub, &pub_key));
                (pub_key, sig)
            })
            .collect();
        PreKeyBundle {
            identity_id: identity.id().as_bytes().to_owned(),
            idk_pub: identity.sign_public().to_bytes(),
            ik_pub: identity.agree_public().to_bytes(),
            spk_pub,
            spk_sig: identity.sign(&PreKeyBundle::spk_sig_challenge(&spk_pub)),
            otps,
        }
    }

    /// Consume the one-time prekey whose public value is `otp_pub`.
    pub fn take_otp(&mut self, otp_pub: &[u8; 32]) -> Option<AgreeSecret> {
        let idx = self
            .otps
            .iter()
            .position(|o| &o.public().to_bytes() == otp_pub)?;
        Some(self.otps.remove(idx))
    }

    /// How many one-time prekeys remain.
    pub fn otps_remaining(&self) -> usize {
        self.otps.len()
    }

    /// Top the one-time-prekey pool back up to `target` (capped at [`MAX_OTPS`]).
    /// Returns the number minted. Call before re-publishing so the relay, which
    /// hands out one OTP per fetch, keeps a fresh supply.
    pub fn replenish(&mut self, target: usize) -> usize {
        let want = target.min(MAX_OTPS);
        let mut minted = 0;
        while self.otps.len() < want {
            self.otps.push(AgreeSecret::generate());
            minted += 1;
        }
        minted
    }

    /// Snapshot the secret halves for the encrypted local store. **Secret.**
    pub fn export(&self) -> PreKeySecretsState {
        PreKeySecretsState {
            spk_secret: self.spk.to_bytes(),
            otp_secrets: self.otps.iter().map(|o| o.to_bytes()).collect(),
        }
    }

    /// Restore from a snapshot.
    pub fn import(state: PreKeySecretsState) -> Self {
        Self {
            spk: AgreeSecret::from_bytes(&state.spk_secret),
            otps: state
                .otp_secrets
                .iter()
                .map(AgreeSecret::from_bytes)
                .collect(),
        }
    }
}

/// A serializable snapshot of [`PreKeySecrets`].
#[derive(Clone)]
pub struct PreKeySecretsState {
    spk_secret: [u8; 32],
    otp_secrets: Vec<[u8; 32]>,
}

impl PreKeySecretsState {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.spk_secret).u32(self.otp_secrets.len() as u32);
        for s in &self.otp_secrets {
            w.fixed(s);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let spk_secret = r.fixed::<32>()?;
        let n = r.u32()? as usize;
        if n > r.remaining() {
            return Err(WireError::LengthTooLarge(n as u64));
        }
        let mut otp_secrets = Vec::with_capacity(n);
        for _ in 0..n {
            otp_secrets.push(r.fixed::<32>()?);
        }
        r.finish()?;
        Ok(Self {
            spk_secret,
            otp_secrets,
        })
    }
}

impl Drop for PreKeySecretsState {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.spk_secret.zeroize();
        for s in &mut self.otp_secrets {
            s.zeroize();
        }
    }
}

/// Output of a successful handshake, on either side.
pub struct X3dhResult {
    /// The 32-byte shared secret to seed the Double Ratchet.
    pub sk: [u8; 32],
    /// Ratchet associated data: `initiator_ik_pub || responder_ik_pub`.
    pub ad: Vec<u8>,
}

/// The initiator's handshake output: the shared result plus what the responder
/// needs to reconstruct it.
pub struct InitiatorHandshake {
    /// Shared secret + associated data.
    pub result: X3dhResult,
    /// Ephemeral X25519 public to send in the init message.
    pub ephemeral_pub: [u8; 32],
    /// One-time prekey consumed from the bundle, if any.
    pub used_otp: Option<[u8; 32]>,
}

fn derive_sk(dhs: &[&[u8; 32]]) -> [u8; 32] {
    // 32 0xFF bytes for domain separation, then the concatenated DH outputs.
    let mut ikm = vec![0xFFu8; 32];
    for d in dhs {
        ikm.extend_from_slice(*d);
    }
    let prk = kdf::extract(&[0u8; 32], &ikm);
    let mut sk = [0u8; 32];
    kdf::expand(&prk, X3DH_INFO, &mut sk).expect("32");
    sk
}

fn ad_of(initiator_ik: &[u8; 32], responder_ik: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(initiator_ik);
    v.extend_from_slice(responder_ik);
    v
}

/// Run X3DH as the initiator against `bundle`.
pub fn initiator(me: &Identity, bundle: &PreKeyBundle) -> Result<InitiatorHandshake, DmError> {
    bundle.verify()?;

    let ek = AgreeSecret::generate();
    let spk = AgreePublic::from_bytes(&bundle.spk_pub);

    let dh1 = me.agree(&spk)?; // IK_a · SPK_b
    let dh2 = ek.agree(&AgreePublic::from_bytes(&bundle.ik_pub))?; // EK_a · IK_b
    let dh3 = ek.agree(&spk)?; // EK_a · SPK_b

    let used_otp = bundle.otps.first().map(|(otp, _sig)| *otp);
    let dh4 = match &used_otp {
        Some(o) => Some(ek.agree(&AgreePublic::from_bytes(o))?),
        None => None,
    };

    let mut dhs: Vec<&[u8; 32]> = vec![&dh1, &dh2, &dh3];
    if let Some(d) = &dh4 {
        dhs.push(d);
    }
    let sk = derive_sk(&dhs);
    let ad = ad_of(&me.agree_public().to_bytes(), &bundle.ik_pub);

    Ok(InitiatorHandshake {
        result: X3dhResult { sk, ad },
        ephemeral_pub: ek.public().to_bytes(),
        used_otp,
    })
}

/// Run X3DH as the responder. `ek_a_pub` / `ik_a_pub` come from the init
/// message; `used_otp`, if set, names the one-time prekey to consume.
pub fn responder(
    me: &Identity,
    prekeys: &mut PreKeySecrets,
    ek_a_pub: &[u8; 32],
    ik_a_pub: &[u8; 32],
    used_otp: Option<[u8; 32]>,
) -> Result<(X3dhResult, AgreeSecret), DmError> {
    let spk = prekeys.spk.clone();
    let ek_a = AgreePublic::from_bytes(ek_a_pub);
    let ik_a = AgreePublic::from_bytes(ik_a_pub);

    let dh1 = spk.agree(&ik_a)?; // SPK_b · IK_a
    let dh2 = me.agree(&ek_a)?; // IK_b · EK_a
    let dh3 = spk.agree(&ek_a)?; // SPK_b · EK_a

    let dh4 = match used_otp {
        Some(o) => {
            let otp = prekeys.take_otp(&o).ok_or(DmError::UnknownOneTimePrekey)?;
            Some(otp.agree(&ek_a)?)
        }
        None => None,
    };

    let mut dhs: Vec<&[u8; 32]> = vec![&dh1, &dh2, &dh3];
    if let Some(d) = &dh4 {
        dhs.push(d);
    }
    let sk = derive_sk(&dhs);
    let ad = ad_of(ik_a_pub, &me.agree_public().to_bytes());

    Ok((X3dhResult { sk, ad }, spk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replenish_tops_up_and_respects_the_cap() {
        let mut pks = PreKeySecrets::generate(3);
        assert_eq!(pks.replenish(10), 7);
        assert_eq!(pks.otps_remaining(), 10);
        assert_eq!(pks.replenish(10), 0, "already at target");
        assert_eq!(pks.replenish(MAX_OTPS + 50), MAX_OTPS - 10);
        assert_eq!(pks.otps_remaining(), MAX_OTPS);
    }

    #[test]
    fn bundle_roundtrip_and_signature() {
        let id = Identity::generate(0);
        let pks = PreKeySecrets::generate(5);
        let bundle = pks.bundle(&id);
        assert_eq!(PreKeyBundle::decode(&bundle.encode()).unwrap(), bundle);
        bundle.verify().unwrap();

        let mut tampered = bundle.clone();
        tampered.spk_pub[0] ^= 1;
        assert!(tampered.verify().is_err());
    }

    /// Swapping in a foreign OTP value while keeping the original OTP's
    /// signature must fail — the concrete substitution a relay-directory-
    /// writes security audit found silently accepted, back when the OTP list
    /// carried no signature at all: a bundle could be re-published with the
    /// OTPs swapped for the attacker's own, and `bundle.verify()` (which only
    /// ever checked `spk_sig` over `spk_pub`) passed regardless.
    #[test]
    fn otp_substitution_is_rejected() {
        let id = Identity::generate(0);
        let bundle = PreKeySecrets::generate(3).bundle(&id);
        bundle.verify().unwrap();

        let foreign_otp = AgreeSecret::generate().public().to_bytes();
        let mut swapped = bundle.clone();
        swapped.otps[0].0 = foreign_otp; // keep the original signature
        assert!(
            swapped.verify().is_err(),
            "an OTP value not matching its own signature must be rejected"
        );

        // A self-consistent (otp, sig) pair lifted from a *different*
        // identity's bundle must not verify against this one — the
        // signature has to be checked against *this* bundle's own idk_pub.
        let other_id = Identity::generate(0);
        let other_bundle = PreKeySecrets::generate(1).bundle(&other_id);
        let mut cross_identity = bundle.clone();
        cross_identity.otps[0] = other_bundle.otps[0];
        assert!(cross_identity.verify().is_err());
    }

    /// The relay legitimately hands out one OTP per fetch, re-encoding the
    /// bundle with just that one `(otp, sig)` pair kept
    /// (`dante-relay/src/state.rs`'s `GetPrekeys` handler) — this must still
    /// verify, or every real prekey fetch would fail closed the moment more
    /// than one OTP was ever published.
    #[test]
    fn a_bundle_sliced_down_to_one_otp_still_verifies() {
        let id = Identity::generate(0);
        let mut bundle = PreKeySecrets::generate(5).bundle(&id);
        let one = bundle.otps[2]; // as if the relay served an arbitrary one
        bundle.otps = vec![one];
        bundle.verify().unwrap();
    }

    #[test]
    fn both_sides_agree_on_sk_and_ad_with_otp() {
        let alice = Identity::generate(0);
        let bob = Identity::generate(0);
        let mut bob_pks = PreKeySecrets::generate(3);
        let bundle = bob_pks.bundle(&bob);

        let hs = initiator(&alice, &bundle).unwrap();
        assert!(hs.used_otp.is_some());
        let (b_res, _spk) = responder(
            &bob,
            &mut bob_pks,
            &hs.ephemeral_pub,
            &alice.agree_public().to_bytes(),
            hs.used_otp,
        )
        .unwrap();

        assert_eq!(hs.result.sk, b_res.sk);
        assert_eq!(hs.result.ad, b_res.ad);
        assert_eq!(bob_pks.otps_remaining(), 2); // one consumed
    }

    #[test]
    fn works_without_one_time_prekeys() {
        let alice = Identity::generate(0);
        let bob = Identity::generate(0);
        let mut bob_pks = PreKeySecrets::generate(0);
        let bundle = bob_pks.bundle(&bob);

        let hs = initiator(&alice, &bundle).unwrap();
        assert!(hs.used_otp.is_none());
        let (b_res, _) = responder(
            &bob,
            &mut bob_pks,
            &hs.ephemeral_pub,
            &alice.agree_public().to_bytes(),
            None,
        )
        .unwrap();
        assert_eq!(hs.result.sk, b_res.sk);
    }

    #[test]
    fn different_initiators_get_different_secrets() {
        let bob = Identity::generate(0);
        let bob_pks = PreKeySecrets::generate(5);
        let bundle = bob_pks.bundle(&bob);
        let sk1 = initiator(&Identity::generate(0), &bundle)
            .unwrap()
            .result
            .sk;
        let sk2 = initiator(&Identity::generate(0), &bundle)
            .unwrap()
            .result
            .sk;
        assert_ne!(sk1, sk2);
    }
}
