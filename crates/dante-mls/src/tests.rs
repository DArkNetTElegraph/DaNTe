use super::*;

/// Add two members to a founder's group; everyone lands in the same epoch with
/// the same group-call key, and it rotates when a member leaves.
#[test]
fn group_shares_a_call_key_that_rekeys_on_leave() {
    let mut alice = Member::create(b"alice", b"channel-1").unwrap();

    let (bob_pending, bob_kp) = Member::publish_key_package(b"bob").unwrap();
    let (carol_pending, carol_kp) = Member::publish_key_package(b"carol").unwrap();

    let hs = alice.add(&[bob_kp, carol_kp]).unwrap();
    let welcome = hs.welcome.clone().unwrap();
    let mut bob = bob_pending.join(&welcome).unwrap();
    let carol = carol_pending.join(&welcome).unwrap();

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
    let mut alice = Member::create(b"alice", b"chan").unwrap();
    let (bob_pending, bob_kp) = Member::publish_key_package(b"bob").unwrap();
    let hs = alice.add(&[bob_kp]).unwrap();
    let mut bob = bob_pending.join(&hs.welcome.unwrap()).unwrap();

    let blob = alice.export().unwrap();
    let mut alice = Member::import(&blob).unwrap();

    assert_eq!(alice.epoch(), bob.epoch());
    assert_eq!(alice.call_key().unwrap(), bob.call_key().unwrap());

    // The reloaded member can still originate traffic...
    let ct = alice.encrypt(b"after reload").unwrap();
    match bob.process(&ct).unwrap() {
        Processed::Application(pt) => assert_eq!(pt, b"after reload"),
        other => panic!("expected application message, got {other:?}"),
    }

    // ...and still drive the group with its signature key.
    let (carol_pending, carol_kp) = Member::publish_key_package(b"carol").unwrap();
    let hs = alice.add(&[carol_kp]).unwrap();
    assert!(matches!(
        bob.process(&hs.commit).unwrap(),
        Processed::EpochChanged
    ));
    let carol = carol_pending.join(&hs.welcome.unwrap()).unwrap();
    assert_eq!(alice.call_key().unwrap(), carol.call_key().unwrap());
}

/// Application messages round-trip through the group.
#[test]
fn members_exchange_application_messages() {
    let mut alice = Member::create(b"alice", b"chan").unwrap();
    let (bob_pending, bob_kp) = Member::publish_key_package(b"bob").unwrap();

    let hs = alice.add(&[bob_kp]).unwrap();
    let mut bob = bob_pending.join(&hs.welcome.unwrap()).unwrap();

    let ct = alice.encrypt(b"hello bob").unwrap();
    match bob.process(&ct).unwrap() {
        Processed::Application(pt) => assert_eq!(pt, b"hello bob"),
        other => panic!("expected application message, got {other:?}"),
    }

    // And the other direction.
    let ct = bob.encrypt(b"hi alice").unwrap();
    match alice.process(&ct).unwrap() {
        Processed::Application(pt) => assert_eq!(pt, b"hi alice"),
        other => panic!("expected application message, got {other:?}"),
    }
}
