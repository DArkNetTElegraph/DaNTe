//! Property tests: every public decoder is total on arbitrary bytes, and the
//! Double Ratchet tolerates arbitrary in-order-preserving reordering.

use dante_identity::Identity;
use proptest::prelude::*;

use crate::{
    content::Content,
    file::FileManifest,
    ratchet::{Header, RatchetState},
    session::{DmMessage, InitMessage, Packet, SessionState},
    x3dh::{PreKeyBundle, PreKeySecrets, PreKeySecretsState},
    Session,
};

fn arb_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..max)
}

proptest! {
    #[test]
    fn content_decode_is_total_and_canonical(buf in arb_bytes(1024)) {
        if let Ok(c) = Content::decode(&buf) {
            prop_assert_eq!(c.encode(), buf);
        }
    }

    #[test]
    fn header_decode_is_total(buf in arb_bytes(128)) {
        let _ = Header::decode(&buf);
    }

    #[test]
    fn packet_decode_is_total_and_canonical(buf in arb_bytes(2048)) {
        if let Ok(p) = Packet::decode(&buf) {
            prop_assert_eq!(p.encode(), buf);
        }
    }

    #[test]
    fn message_decoders_are_total(buf in arb_bytes(2048)) {
        let _ = DmMessage::decode(&buf);
        let _ = InitMessage::decode(&buf);
    }

    #[test]
    fn state_decoders_are_total(buf in arb_bytes(4096)) {
        let _ = RatchetState::decode(&buf);
        let _ = SessionState::decode(&buf);
        let _ = PreKeySecretsState::decode(&buf);
    }

    #[test]
    fn prekey_bundle_decode_is_total_and_canonical(buf in arb_bytes(1024)) {
        if let Ok(b) = PreKeyBundle::decode(&buf) {
            prop_assert_eq!(b.encode(), buf);
        }
    }

    #[test]
    fn file_manifest_decode_is_total(buf in arb_bytes(4096)) {
        let _ = FileManifest::decode(&buf);
    }

    /// A batch of messages from one side, delivered to the other in an arbitrary
    /// order, all decrypt to the right plaintext exactly once. Replays fail.
    #[test]
    fn ratchet_survives_arbitrary_reordering(
        texts in proptest::collection::vec("[a-z ]{0,40}", 1..24),
        seed in any::<u64>(),
    ) {
        let alice = Identity::generate(1);
        let bob = Identity::generate(2);
        let mut bob_pks = PreKeySecrets::generate(4);
        let bundle = bob_pks.bundle(&bob);

        let (mut a_sess, init) = Session::initiate(&alice, &bundle, texts[0].as_bytes()).unwrap();
        let (mut b_sess, first) = Session::accept(&bob, &mut bob_pks, &init).unwrap();
        prop_assert_eq!(first, texts[0].as_bytes());

        // Encrypt the rest in order (chain order is preserved on the wire).
        let mut wire: Vec<(usize, DmMessage)> = Vec::new();
        for (i, t) in texts.iter().enumerate().skip(1) {
            wire.push((i, a_sess.encrypt(t.as_bytes()).unwrap()));
        }

        // Shuffle deterministically (xorshift) — reordering only, no dup here.
        let mut s = seed | 1;
        for i in (1..wire.len()).rev() {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            let j = (s as usize) % (i + 1);
            wire.swap(i, j);
        }

        for (i, msg) in &wire {
            prop_assert_eq!(b_sess.decrypt(msg).unwrap(), texts[*i].as_bytes());
        }
        // Every delivered message is now a replay and must be rejected.
        for (_, msg) in &wire {
            prop_assert!(b_sess.decrypt(msg).is_err());
        }
    }
}
