use dante_crypto::sign::SignSecret;

use super::*;

fn idk(seed: u8) -> SignSecret {
    SignSecret::from_bytes(&[seed; 32])
}

/// `Member::create`, but threading `idk`'s public key + signing closure
/// through — the shape every real caller (`dante-core`) uses, saving each
/// test the boilerplate.
fn create_member(identity: &[u8], idk: &SignSecret, group_id: &[u8]) -> Member {
    Member::create(identity, idk.public().to_bytes(), |m| idk.sign(m), group_id).unwrap()
}

/// `Member::publish_key_package`, same rationale as [`create_member`].
fn publish_kp(identity: &[u8], idk: &SignSecret) -> (Pending, KeyPkg) {
    Member::publish_key_package(identity, idk.public().to_bytes(), |m| idk.sign(m)).unwrap()
}

/// `key_package_identity` reads back the identity a KeyPackage was published
/// with — the check callers use to catch one published for a different
/// identity than the peer it was fetched for — the fetched credential's
/// binding really does verify.
#[test]
fn key_package_identity_reads_back_the_publisher() {
    let (alice_idk, bob_idk) = (idk(1), idk(2));
    let alice = create_member(b"alice", &alice_idk, b"channel-1");
    let (_bob_pending, bob_kp) = publish_kp(b"bob", &bob_idk);
    let (identity, idk_pub) = alice.key_package_identity(&bob_kp).unwrap();
    assert_eq!(identity, b"bob");
    assert_eq!(idk_pub, bob_idk.public().to_bytes());
    assert_ne!(identity, b"alice");
}

/// `key_package_identity` only proves self-consistency (this `idk_pub` really
/// did sign for this identity + this exact leaf key) — it can't by itself
/// catch an attacker's own real `idk` claiming someone else's identity bytes,
/// since this crate has no ledger to check `idk_pub` against. That cross-check
/// is `dante-core`'s job. Confirm the self-consistency proof at least reads
/// back faithfully so that outer check has something correct to check.
#[test]
fn key_package_identity_returns_exactly_who_idk_pub_signed_for() {
    let (alice_idk, attacker_idk) = (idk(1), idk(3));
    let alice = create_member(b"alice", &alice_idk, b"channel-1");
    let (_pending, kp) = publish_kp(b"victim", &attacker_idk);
    let (identity, idk_pub) = alice.key_package_identity(&kp).unwrap();
    assert_eq!(identity, b"victim");
    assert_eq!(idk_pub, attacker_idk.public().to_bytes());
    assert_ne!(idk_pub, alice_idk.public().to_bytes());
}

/// Bytes that aren't even a well-formed KeyPackage at all (never mind a
/// DanteCredential inside one) are refused at the KeyPackage-parsing step,
/// before credential decoding is ever reached.
#[test]
fn key_package_identity_rejects_non_key_package_bytes() {
    let alice_idk = idk(1);
    let alice = create_member(b"alice", &alice_idk, b"channel-1");
    assert!(alice.key_package_identity(&KeyPkg(vec![])).is_err());
}

/// A structurally real, validly-signed KeyPackage whose credential is a
/// plain OpenMLS `BasicCredential` (no DanteCredential at all — the
/// pre-this-feature shape) is refused: `key_package_identity` requires the
/// credential to decode as a DanteCredential specifically, not just be
/// present. This is the exact "a real KeyPackage whose credential doesn't
/// carry a valid DaNTe binding" case, built directly against OpenMLS's own
/// KeyPackage builder rather than through `dante-mls`'s own minting (which
/// can no longer produce anything but a DanteCredential).
#[test]
fn key_package_identity_rejects_a_real_key_package_with_no_dante_binding() {
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
    signer.store(provider.storage()).unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"nobody".to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let bundle = KeyPackage::builder()
        .build(CIPHERSUITE, &provider, &signer, credential)
        .unwrap();
    let bytes = bundle.key_package().tls_serialize_detached().unwrap();

    let alice_idk = idk(1);
    let alice = create_member(b"alice", &alice_idk, b"channel-1");
    assert!(alice.key_package_identity(&KeyPkg(bytes)).is_err());
}

/// The whole point of binding the credential to the leaf's own MLS signature
/// key: a validly-signed credential can't be spliced from one KeyPackage
/// onto a different one. Verifying it against the leaf key it was actually
/// signed for succeeds; verifying the exact same bytes against a different
/// leaf key must fail.
#[test]
fn a_credential_cannot_be_spliced_onto_a_different_leaf_key() {
    let signer_idk = idk(1);
    let cred = DanteCredential::new(
        b"alice",
        signer_idk.public().to_bytes(),
        |m| signer_idk.sign(m),
        b"leaf-key-a",
    );
    let bytes = cred.encode();
    assert!(DanteCredential::decode_and_verify(&bytes, b"leaf-key-a").is_some());
    assert!(DanteCredential::decode_and_verify(&bytes, b"leaf-key-b").is_none());
}

/// Add two members to a founder's group; everyone lands in the same epoch with
/// the same group-call key, and it rotates when a member leaves.
#[test]
fn group_shares_a_call_key_that_rekeys_on_leave() {
    let (alice_idk, bob_idk, carol_idk) = (idk(1), idk(2), idk(3));
    let mut alice = create_member(b"alice", &alice_idk, b"channel-1");

    let (bob_pending, bob_kp) = publish_kp(b"bob", &bob_idk);
    let (carol_pending, carol_kp) = publish_kp(b"carol", &carol_idk);

    let hs = alice.add(&[bob_kp, carol_kp]).unwrap();
    let welcome = hs.welcome.clone().unwrap();
    let mut bob = bob_pending
        .join(&welcome)
        .unwrap_or_else(|(_, e)| panic!("join: {e}"));
    let carol = carol_pending
        .join(&welcome)
        .unwrap_or_else(|(_, e)| panic!("join: {e}"));

    assert_eq!(alice.epoch(), bob.epoch());
    assert_eq!(alice.epoch(), carol.epoch());

    // Every member sees the same three identities.
    let mut ids: Vec<Vec<u8>> = alice.members().into_iter().map(|(_, id)| id).collect();
    ids.sort();
    assert_eq!(
        ids,
        vec![b"alice".to_vec(), b"bob".to_vec(), b"carol".to_vec()]
    );

    let ka = alice.call_key().unwrap();
    assert_eq!(ka, bob.call_key().unwrap());
    assert_eq!(ka, carol.call_key().unwrap());

    // Alice removes Carol; Bob catches up from the commit.
    let carol_idx = carol.own_index();
    let hs = alice.remove(&[carol_idx]).unwrap();
    assert!(matches!(
        bob.process(&hs.commit).unwrap(),
        Processed::EpochChanged
    ));

    assert_eq!(alice.epoch(), bob.epoch());
    let ka2 = alice.call_key().unwrap();
    assert_eq!(ka2, bob.call_key().unwrap());
    assert_ne!(ka, ka2, "the call key must rotate when membership changes");
}

/// A member survives an export / import round-trip: same epoch, same call key,
/// still able to send, receive, and commit membership changes.
#[test]
fn member_survives_export_import() {
    let (alice_idk, bob_idk, carol_idk) = (idk(1), idk(2), idk(3));
    let mut alice = create_member(b"alice", &alice_idk, b"chan");
    let (bob_pending, bob_kp) = publish_kp(b"bob", &bob_idk);
    let hs = alice.add(&[bob_kp]).unwrap();
    let mut bob = bob_pending
        .join(&hs.welcome.unwrap())
        .unwrap_or_else(|(_, e)| panic!("join: {e}"));

    let blob = alice.export().unwrap();
    let mut alice = Member::import(&blob).unwrap();

    assert_eq!(alice.epoch(), bob.epoch());
    assert_eq!(alice.call_key().unwrap(), bob.call_key().unwrap());

    // The reloaded member can still originate traffic...
    let ct = alice.encrypt(b"after reload").unwrap();
    match bob.process(&ct).unwrap() {
        Processed::Application { plaintext, .. } => assert_eq!(plaintext, b"after reload"),
        other => panic!("expected application message, got {other:?}"),
    }

    // ...and still drive the group with its signature key.
    let (carol_pending, carol_kp) = publish_kp(b"carol", &carol_idk);
    let hs = alice.add(&[carol_kp]).unwrap();
    assert!(matches!(
        bob.process(&hs.commit).unwrap(),
        Processed::EpochChanged
    ));
    let carol = carol_pending
        .join(&hs.welcome.unwrap())
        .unwrap_or_else(|(_, e)| panic!("join: {e}"));
    assert_eq!(alice.call_key().unwrap(), carol.call_key().unwrap());
}

/// Application messages round-trip through the group.
#[test]
fn members_exchange_application_messages() {
    let (alice_idk, bob_idk) = (idk(1), idk(2));
    let mut alice = create_member(b"alice", &alice_idk, b"chan");
    let (bob_pending, bob_kp) = publish_kp(b"bob", &bob_idk);

    let hs = alice.add(&[bob_kp]).unwrap();
    let mut bob = bob_pending
        .join(&hs.welcome.unwrap())
        .unwrap_or_else(|(_, e)| panic!("join: {e}"));

    let ct = alice.encrypt(b"hello bob").unwrap();
    match bob.process(&ct).unwrap() {
        Processed::Application { plaintext, .. } => assert_eq!(plaintext, b"hello bob"),
        other => panic!("expected application message, got {other:?}"),
    }

    // And the other direction.
    let ct = bob.encrypt(b"hi alice").unwrap();
    match alice.process(&ct).unwrap() {
        Processed::Application { plaintext, .. } => assert_eq!(plaintext, b"hi alice"),
        other => panic!("expected application message, got {other:?}"),
    }
}
