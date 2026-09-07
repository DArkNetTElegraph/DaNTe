//! Property tests: decoders are total on arbitrary bytes, the sender-keys
//! ratchet tolerates reordering within `MAX_SKIP`, and ephemeral signals
//! round-trip for any plaintext.

use dante_crypto::hash::sha256;
use proptest::prelude::*;

use crate::{Group, GroupMessage, GroupState, SenderKeyBundle};

fn arb_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..max)
}

fn member(seed: u8) -> [u8; 32] {
    sha256(&[seed; 32])
}

/// A keyed pair: `a` and `b` can each decrypt the other.
fn pair() -> (Group, Group) {
    let (mut a, ba) = Group::create([9u8; 32], member(0));
    let (mut b, bb) = Group::create([9u8; 32], member(1));
    a.upsert_member(&bb).unwrap();
    b.upsert_member(&ba).unwrap();
    (a, b)
}

proptest! {
    #[test]
    fn decoders_are_total(buf in arb_bytes(4096)) {
        let _ = GroupMessage::decode(&buf);
        let _ = SenderKeyBundle::decode(&buf);
        let _ = GroupState::decode(&buf);
    }

    #[test]
    fn group_message_decode_is_canonical(buf in arb_bytes(2048)) {
        if let Ok(m) = GroupMessage::decode(&buf) {
            prop_assert_eq!(m.encode(), buf);
        }
    }

    #[test]
    fn sender_key_bundle_decode_is_canonical(buf in arb_bytes(512)) {
        if let Ok(b) = SenderKeyBundle::decode(&buf) {
            prop_assert_eq!(b.encode(), buf);
        }
    }

    /// Messages delivered out of order within one chain all decrypt once.
    #[test]
    fn reordering_within_a_chain(
        texts in proptest::collection::vec("[a-z]{0,32}", 1..40),
        seed in any::<u64>(),
    ) {
        let (mut a, mut b) = pair();
        let mut wire: Vec<(usize, GroupMessage)> =
            texts.iter().enumerate().map(|(i, t)| (i, a.encrypt(t.as_bytes()))).collect();

        let mut s = seed | 1;
        for i in (1..wire.len()).rev() {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            wire.swap(i, (s as usize) % (i + 1));
        }

        for (i, m) in &wire {
            prop_assert_eq!(b.decrypt(m).unwrap(), texts[*i].as_bytes());
        }
        for (_, m) in &wire {
            prop_assert!(b.decrypt(m).is_err(), "replay rejected");
        }
    }

    /// `seal_signal` / `open_signal` round-trips any plaintext and never leaks
    /// past the sealing member.
    #[test]
    fn signal_roundtrips_any_plaintext(pt in arb_bytes(2048)) {
        let (a, b) = pair();
        let blob = a.seal_signal(&pt);
        let (who, got) = b.open_signal(&blob).expect("member b can open a's signal");
        prop_assert_eq!(who, *a.me());
        prop_assert_eq!(got, pt);
    }

    #[test]
    fn open_signal_is_total_on_garbage(buf in arb_bytes(2048)) {
        let (_a, b) = pair();
        let _ = b.open_signal(&buf);
    }
}
