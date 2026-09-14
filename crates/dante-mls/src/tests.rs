use super::*;

fn idk(seed: u8) -> SignSecret {
    SignSecret::from_bytes(&[seed; 32])
}

/// `key_package_identity` reads back the identity a KeyPackage was published
/// with — the check callers use to catch one published for a different
/// identity than the peer it was fetched for — the fetched credential's
/// binding really does verify (a made-up credential is rejected outright).
#[test]
fn key_package_identity_reads_back_the_publisher() {
    let (alice_idk, bob_idk) = (idk(1), idk(2));
    let alice = Member::create(b"alice", &alice_idk, b"channel-1").unwrap();
    let (_bob_pending, bob_kp) = Member::publish_key_package(b"bob", &bob_idk).unwrap();
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
    let alice = Member::create(b"alice", &alice_idk, b"channel-1").unwrap();
    let (_pending, kp) = Member::publish_key_package(b"victim", &attacker_idk).unwrap();
    let (identity, idk_pub) = alice.key_package_identity(&kp).unwrap();
    assert_eq!(identity, b"victim");
    assert_eq!(idk_pub, attacker_idk.public().to_bytes());
    assert_ne!(idk_pub, alice_idk.public().to_bytes());
}

/// A key package with a structurally-present but non-decodable /
/// non-verifying credential (not one of ours) is refused outright rather
/// than silently trusted.
#[test]
fn key_package_identity_rejects_garbage_credentials() {
    let alice_idk = idk(1);
    let alice = Member::create(b"alice", &alice_idk, b"channel-1").unwrap();
    assert!(alice.key_package_identity(&KeyPkg(vec![])).is_err());
}

/// Add two members to a founder's group; everyone lands in the same epoch with
/// the same group-call key, and it rotates when a member leaves.
#[test]
fn group_shares_a_call_key_that_rekeys_on_leave() {
    let (alice_idk, bob_idk, carol_idk) = (idk(1), idk(2), idk(3));
    let mut alice = Member::create(b"alice", &alice_idk, b"channel-1").unwrap();

    let (bob_pending, bob_kp) = Member::publish_key_package(b"bob", &bob_idk).unwrap();
    let (carol_pending, carol_kp) = Member::publish_key_package(b"carol", &carol_idk).unwrap();

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
    let mut alice = Member::create(b"alice", &alice_idk, b"chan").unwrap();
    let (bob_pending, bob_kp) = Member::publish_key_package(b"bob", &bob_idk).unwrap();
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
    let (carol_pending, carol_kp) = Member::publish_key_package(b"carol", &carol_idk).unwrap();
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
    let mut alice = Member::create(b"alice", &alice_idk, b"chan").unwrap();
    let (bob_pending, bob_kp) = Member::publish_key_package(b"bob", &bob_idk).unwrap();

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
