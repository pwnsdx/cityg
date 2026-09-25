//! Delivery-service rules that the scenario tests of `session` do not reach.

use super::*;
use crate::admission::Invite;
use crate::cover::CoverFailureReason;
use crate::identity::DeviceIdentity;
use crate::session::{CommitOptions, GroupSession};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

struct Fixture {
    rng: ChaCha20Rng,
    ledger: GroupLedger,
    alice: DeviceIdentity,
    session: GroupSession,
}

fn fixture(seed: u8) -> Fixture {
    let mut rng = ChaCha20Rng::seed_from_u64(u64::from(seed));
    let alice = DeviceIdentity::from_seed(&[seed; 32]);
    let (pending, published) = GroupSession::create(&alice, 4, &mut rng).unwrap();
    let (ledger, _) = GroupLedger::create(&published.commit, &published.group_info, 0).unwrap();
    Fixture {
        rng,
        ledger,
        alice,
        session: pending.into_session().unwrap(),
    }
}

fn request(f: &mut Fixture, seed: u8) -> SignedJoinRequest {
    let joiner = DeviceIdentity::from_seed(&[seed; 32]);
    let admission = f
        .session
        .admit(&f.alice, joiner.public_key(), 10, &mut f.rng)
        .unwrap();
    GroupSession::request_join(&joiner, &admission, &mut f.rng)
        .unwrap()
        .0
}

#[test]
fn join_requests_are_recorded_once_per_device() {
    let mut f = fixture(1);
    let first = request(&mut f, 2);
    let (reference, status) = f.ledger.submit_join_request(first.encoded(), 0).unwrap();
    assert_eq!(status, ProposalStatus::Recorded);
    assert_eq!(
        f.ledger.submit_join_request(first.encoded(), 0).unwrap(),
        (reference, ProposalStatus::AlreadyRecorded)
    );
    // A second request of the same device is refused while one is pending.
    let second = request(&mut f, 2);
    assert_eq!(
        f.ledger.submit_join_request(second.encoded(), 0).err(),
        Some(CoreError::Invalid("a request of this device is pending"))
    );
    assert_eq!(f.ledger.join_status(&[0; 32]), JoinStatus::Unknown);
    assert_eq!(f.ledger.pending()[0].proposal.encoded(), first.encoded());
    assert!(f.ledger.submit_join_request(&[0x80], 0).is_err());
}

#[test]
fn commits_come_with_matching_welcomes() {
    let mut f = fixture(3);
    let bob = request(&mut f, 4);
    f.ledger.submit_join_request(bob.encoded(), 0).unwrap();
    let joins = vec![bob.clone()];
    let (_, published) = f
        .session
        .commit(
            &f.alice,
            CommitOptions {
                joins: &joins,
                ..CommitOptions::default()
            },
            &mut f.rng,
        )
        .unwrap();
    // A welcome for another request, or re-encoded, is refused.
    let mut other = Welcome::decode(&published.welcomes[0]).unwrap();
    other.request_ref = [9; 32];
    assert_eq!(
        f.ledger
            .apply_commit(
                &published.commit,
                &published.group_info,
                &[other.encode().unwrap()],
                0
            )
            .err(),
        Some(CoreError::Invalid("welcome does not match its request"))
    );
    f.ledger
        .apply_commit(
            &published.commit,
            &published.group_info,
            &published.welcomes,
            5,
        )
        .unwrap();
    let reference = bob.reference().unwrap();
    assert_eq!(
        f.ledger.join_status(&reference),
        JoinStatus::Committed {
            epoch: 1,
            welcome: published.welcomes[0].clone()
        }
    );
    assert_eq!(f.ledger.epoch_started_at_ms(), 5);

    // The ledger keeps a bounded number of welcomes, oldest out first.
    for index in 0..MAX_WELCOMES {
        let mut filler = [0u8; 32];
        filler[..8].copy_from_slice(&(index as u64).to_be_bytes());
        f.ledger.store_welcome(
            filler,
            StoredWelcome {
                epoch: 1,
                welcome: Vec::new(),
                device_pk: Vec::new(),
            },
        );
    }
    assert_eq!(f.ledger.join_status(&reference), JoinStatus::Unknown);
    assert_eq!(f.ledger.welcomes.len(), MAX_WELCOMES);
}

#[test]
fn messages_need_a_current_member_of_an_active_epoch() {
    let mut f = fixture(5);
    let envelope = f
        .session
        .encrypt(&f.alice, 1, b"", b"hi", 0, &mut f.rng)
        .unwrap();
    let accepted = f.ledger.accept_message(&envelope, 0).unwrap();
    assert_eq!(accepted.sender, MemberRef { leaf: 0, since: 0 });
    assert_eq!(accepted.epoch, 0);
    assert_eq!(
        f.ledger.accept_message(&envelope, 0),
        Err(CoreError::Replay)
    );
    // A sender that is not a member, or an unknown epoch, is refused.
    let mut forged = crate::message::Envelope::decode(&envelope).unwrap();
    forged.header.sender = MemberRef { leaf: 0, since: 3 };
    assert_eq!(
        f.ledger.accept_message(&forged.encode().unwrap(), 0),
        Err(CoreError::Unauthorized("sender is not a member"))
    );
    let mut stray = crate::message::Envelope::decode(&envelope).unwrap();
    stray.header.epoch_ref = [7; 32];
    assert_eq!(
        f.ledger.accept_message(&stray.encode().unwrap(), 0),
        Err(CoreError::Invalid("message for an inactive epoch"))
    );
    assert!(f.ledger.accept_message(&[0x80], 0).is_err());
}

#[test]
fn cover_failures_name_the_current_epoch_and_are_bounded() {
    let mut f = fixture(6);
    let stale = f
        .session
        .report_cover_failure(&f.alice, 3, CoverFailureReason::StateLost, &mut f.rng)
        .unwrap();
    assert_eq!(
        f.ledger.submit_cover_failure(stale.encoded()),
        Err(CoreError::EpochMismatch {
            expected: 0,
            got: 3
        })
    );
    let report = f
        .session
        .report_cover_failure(&f.alice, 0, CoverFailureReason::StateLost, &mut f.rng)
        .unwrap();
    for _ in 0..=MAX_COVER_FAILURES {
        f.ledger.submit_cover_failure(report.encoded()).unwrap();
    }
    assert_eq!(f.ledger.cover_failures().len(), MAX_COVER_FAILURES);
    let outsider = DeviceIdentity::from_seed(&[60; 32]);
    let foreign = CoverFailureReport::sign(
        f.ledger.gid(),
        0,
        CoverFailureReason::NotCovered,
        &outsider,
        &mut f.rng,
    )
    .unwrap();
    assert!(matches!(
        f.ledger.submit_cover_failure(foreign.encoded()),
        Err(CoreError::Unauthorized(_))
    ));
}

#[test]
fn invites_are_bounded_and_revocations_remembered() {
    let mut f = fixture(7);
    let gid = *f.ledger.gid();
    let invite = Invite::from_seed(&gid, &[1; 32], 100, 1, f.alice.public_key())
        .sign(&f.alice, &mut f.rng)
        .unwrap();
    let id = f.ledger.publish_invite(invite.encoded(), 0).unwrap();
    assert_eq!(f.ledger.publish_invite(invite.encoded(), 0).unwrap(), id);
    assert!(f.ledger.invite(&id, 101).is_none(), "expired");
    assert_eq!(f.ledger.invite_uses(&id), 0);
    // Fill the store; expired invites make room again.
    for index in 1..MAX_INVITES {
        let mut stored = f.ledger.invites[&id].clone();
        stored.invite = invite.clone();
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&(index as u64).to_be_bytes());
        f.ledger.invites.insert(key, stored);
    }
    let other = Invite::from_seed(&gid, &[2; 32], 100, 1, f.alice.public_key())
        .sign(&f.alice, &mut f.rng)
        .unwrap();
    assert_eq!(
        f.ledger.publish_invite(other.encoded(), 0),
        Err(CoreError::TooLarge("invites"))
    );
    f.ledger.publish_invite(other.encoded(), 101).unwrap_err();
    let fresh = Invite::from_seed(&gid, &[3; 32], 1_000, 1, f.alice.public_key())
        .sign(&f.alice, &mut f.rng)
        .unwrap();
    f.ledger.publish_invite(fresh.encoded(), 101).unwrap();
    assert_eq!(f.ledger.invites.len(), 1);

    // Revocations are remembered, the oldest going first.
    for index in 0..MAX_REVOKED_INVITES {
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&(index as u64).to_be_bytes());
        f.ledger.revoked_invites.push_back(key);
    }
    let revocation =
        SignedInviteRevocation::sign(&gid, &fresh.id().unwrap(), &f.alice, &mut f.rng).unwrap();
    assert!(
        f.ledger
            .revoke_invite(revocation.encoded())
            .unwrap()
            .is_empty()
    );
    assert_eq!(f.ledger.revoked_invites.len(), MAX_REVOKED_INVITES);
    assert_eq!(f.ledger.revoked_invites.back(), Some(&fresh.id().unwrap()));
    // Revoking twice changes nothing.
    f.ledger.revoke_invite(revocation.encoded()).unwrap();
    assert_eq!(f.ledger.revoked_invites.len(), MAX_REVOKED_INVITES);
}

#[test]
fn malformed_snapshots_are_rejected() {
    let f = fixture(8);
    let encoded = f.ledger.to_cbor().unwrap();
    let restored = GroupLedger::from_cbor(&encoded).unwrap();
    assert_eq!(restored.to_cbor().unwrap(), encoded);
    let Value::Array(mut items) = decode(&encoded, 1 << 24, "t").unwrap() else {
        panic!("array")
    };
    // A pending entry of an unknown kind.
    items[6] = array(vec![array(vec![uint(7), bytes(b"x"), uint(0)])]);
    assert!(GroupLedger::from_cbor(&encode(&array(items.clone())).unwrap()).is_err());
    // Too many previous epochs.
    let previous = array(vec![uint(0), array(vec![]), uint(0), array(vec![])]);
    items[6] = array(vec![]);
    items[4] = array(vec![previous; MAX_GRACE_EPOCHS + 1]);
    assert_eq!(
        GroupLedger::from_cbor(&encode(&array(items.clone())).unwrap()).err(),
        Some(CoreError::Malformed("ledger previous"))
    );
    // A GroupInfo of another epoch.
    items[4] = array(vec![]);
    let (_, other) = GroupSession::create(
        &DeviceIdentity::from_seed(&[9; 32]),
        4,
        &mut ChaCha20Rng::seed_from_u64(9),
    )
    .unwrap();
    items[2] = bytes(&other.group_info);
    assert!(GroupLedger::from_cbor(&encode(&array(items)).unwrap()).is_err());
}
