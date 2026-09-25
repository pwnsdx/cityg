//! Scenario tests: members ([`GroupSession`]) and the delivery service
//! ([`GroupLedger`]) running the v0.2 profile end to end.

use super::*;
use crate::ledger::{GroupLedger, ProposalStatus};
use crate::message::GRACE_WINDOW_MS;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const N_MAX: u32 = 8;

struct Device {
    identity: DeviceIdentity,
    session: GroupSession,
}

struct World {
    rng: ChaCha20Rng,
    ledger: GroupLedger,
    /// Accepted `(commit, group_info)` by epoch.
    log: Vec<(Vec<u8>, Vec<u8>)>,
    now: u64,
}

impl World {
    fn create(seed: u8) -> (Self, Device) {
        let mut rng = ChaCha20Rng::seed_from_u64(u64::from(seed));
        let identity = DeviceIdentity::from_seed(&[seed; 32]);
        let (pending, published) = GroupSession::create(&identity, N_MAX, &mut rng).unwrap();
        assert_eq!(published.epoch, 0);
        let (ledger, accepted) =
            GroupLedger::create(&published.commit, &published.group_info, 1_000).unwrap();
        assert_eq!(accepted.kind, CommitKind::Genesis);
        let session = pending.into_session().unwrap();
        assert_eq!(
            session.group_context(),
            &ledger.state().group_context().unwrap()
        );
        (
            Self {
                rng,
                ledger,
                log: vec![(published.commit, published.group_info)],
                now: 1_000,
            },
            Device { identity, session },
        )
    }

    fn pending(&self) -> Vec<SignedRemoveProposal> {
        self.ledger.pending_removals().cloned().collect()
    }

    fn publish(&mut self, published: &PublishedCommit) -> CoreResult<()> {
        self.ledger
            .apply_commit(&published.commit, &published.group_info, self.now)?;
        self.log
            .push((published.commit.clone(), published.group_info.clone()));
        assert_eq!(self.log.len() as u64, self.ledger.epoch() + 1);
        Ok(())
    }

    /// `device` commits the pending removals plus `removals` and `changes`.
    fn commit(
        &mut self,
        device: &mut Device,
        removals: &[SignedRemoveProposal],
        changes: &[AdminChange],
    ) -> CoreResult<()> {
        let mut all = self.pending();
        all.extend_from_slice(removals);
        let (pending, published) =
            device
                .session
                .commit(&device.identity, &all, changes, &mut self.rng)?;
        self.publish(&published)?;
        device.session.apply_own_commit(pending)
    }

    /// Process every accepted commit the device has not seen yet.
    fn sync(&self, device: &mut Device) -> Vec<ProcessedCommit> {
        let mut outcomes = Vec::new();
        while device.session.epoch() < self.ledger.epoch() {
            let (commit, group_info) = &self.log[device.session.epoch() as usize + 1];
            let outcome = device
                .session
                .process_commit(commit, Some(group_info))
                .unwrap();
            let removed = matches!(outcome, ProcessedCommit::Removed(_));
            outcomes.push(outcome);
            if removed {
                break;
            }
        }
        outcomes
    }

    fn invite(&mut self, admin: &Device, invite_seed: [u8; 32]) -> SignedInvite {
        let invite = admin
            .session
            .create_invite(
                &admin.identity,
                &invite_seed,
                self.now + 60_000,
                &mut self.rng,
            )
            .unwrap();
        let id = self
            .ledger
            .publish_invite(invite.encoded(), self.now)
            .unwrap();
        assert_eq!(self.ledger.invite(&id, self.now).unwrap(), &invite);
        invite
    }

    fn join_with(&mut self, seed: u8, admission: SignedAdmission) -> CoreResult<Device> {
        let identity = DeviceIdentity::from_seed(&[seed; 32]);
        let snapshot = self.ledger.snapshot()?;
        let (pending, published) = GroupSession::join(
            &identity,
            &snapshot,
            &self.pending(),
            admission,
            &mut self.rng,
        )?;
        self.publish(&published)?;
        Ok(Device {
            identity,
            session: pending.into_session()?,
        })
    }

    /// Join `seed` through an invite link created by `admin`.
    fn join_by_invite(&mut self, admin: &Device, seed: u8) -> Device {
        let invite_seed = [seed.wrapping_add(100); 32];
        let invite = self.invite(admin, invite_seed);
        let identity = DeviceIdentity::from_seed(&[seed; 32]);
        let gid = *admin.session.gid();
        let admission = SignedAdmission::with_invite(
            &identity.leaf_id(&gid).unwrap(),
            &invite,
            &invite_seed,
            &mut self.rng,
        )
        .unwrap();
        self.join_with(seed, admission).unwrap()
    }

    fn send(&mut self, device: &mut Device, text: &[u8]) -> Vec<u8> {
        let envelope = device
            .session
            .encrypt(&device.identity, 1, b"", text, self.now, &mut self.rng)
            .unwrap();
        self.ledger.accept_message(&envelope, self.now).unwrap();
        envelope
    }
}

fn assert_agree(world: &World, devices: &[&Device]) {
    let expected = world.ledger.state().group_context().unwrap();
    for device in devices {
        assert_eq!(device.session.group_context(), &expected);
        assert_eq!(
            device.session.transcript_fingerprint(),
            world.ledger.state().interim_transcript_hash
        );
        assert_eq!(device.session.public_state(), world.ledger.state());
    }
}

#[test]
fn members_join_talk_and_leave() {
    let (mut world, mut alice) = World::create(1);
    let mut bob = world.join_by_invite(&alice, 2);
    world.sync(&mut alice);
    let admission = alice
        .session
        .admit(
            &alice.identity,
            DeviceIdentity::from_seed(&[3; 32]).public_key(),
            &mut world.rng,
        )
        .unwrap();
    let mut carol = world.join_with(3, admission).unwrap();
    world.sync(&mut alice);
    world.sync(&mut bob);
    assert_agree(&world, &[&alice, &bob, &carol]);
    assert_eq!(world.ledger.roster().len(), 3);
    assert_eq!(bob.session.my_slot(), 1);
    assert_eq!(carol.session.my_slot(), 2);

    let hello = world.send(&mut alice, b"hello");
    let received = bob.session.decrypt(&hello).unwrap();
    assert_eq!(received.plaintext, b"hello");
    assert_eq!(received.sender_device_pk, alice.identity.public_key());
    assert_eq!(received.signed_timestamp_ms, world.now);
    assert_eq!(carol.session.decrypt(&hello).unwrap().plaintext, b"hello");
    assert_eq!(bob.session.decrypt(&hello), Err(CoreError::Replay));
    let reply = world.send(&mut bob, b"hi alice");
    assert_eq!(
        alice.session.decrypt(&reply).unwrap().plaintext,
        b"hi alice"
    );

    // Bob leaves: his signed proposal is recorded and blocks his messages.
    let leave = bob
        .session
        .propose_leave(&bob.identity, &mut world.rng)
        .unwrap();
    assert_eq!(
        world
            .ledger
            .submit_remove_proposal(leave.encoded())
            .unwrap(),
        ProposalStatus::Recorded
    );
    assert_eq!(
        world
            .ledger
            .submit_remove_proposal(leave.encoded())
            .unwrap(),
        ProposalStatus::AlreadyRecorded
    );
    let late = bob
        .session
        .encrypt(
            &bob.identity,
            1,
            b"",
            b"still here",
            world.now,
            &mut world.rng,
        )
        .unwrap();
    assert!(matches!(
        world.ledger.accept_message(&late, world.now),
        Err(CoreError::Unauthorized(_))
    ));
    let pending = world.pending();
    assert_eq!(alice.session.set_pending_removals(&pending).len(), 1);
    assert!(matches!(
        alice.session.decrypt(&late),
        Err(CoreError::Unauthorized(_))
    ));
    // Bob cannot commit his own removal (C-03).
    assert!(matches!(
        bob.session
            .commit(&bob.identity, &pending, &[], &mut world.rng),
        Err(CoreError::Unauthorized(_))
    ));

    world.commit(&mut carol, &[], &[]).unwrap();
    world.sync(&mut alice);
    let outcome = world.sync(&mut bob);
    let Some(ProcessedCommit::Removed(summary)) = outcome.last() else {
        panic!("bob must see his removal")
    };
    assert_eq!(summary.removed[0].leaf_id, *bob.session.my_leaf_id());
    assert_agree(&world, &[&alice, &carol]);
    assert!(
        world
            .ledger
            .roster()
            .member_by_leaf(bob.session.my_leaf_id())
            .is_none()
    );

    // Bob's keys no longer open anything, and he cannot post any more.
    let after = world.send(&mut carol, b"bob is gone");
    assert!(bob.session.decrypt(&after).is_err());
    assert_eq!(
        alice.session.decrypt(&after).unwrap().plaintext,
        b"bob is gone"
    );
    let from_bob = bob
        .session
        .encrypt(&bob.identity, 1, b"", b"ghost", world.now, &mut world.rng)
        .unwrap();
    assert!(world.ledger.accept_message(&from_bob, world.now).is_err());
    assert!(alice.session.decrypt(&from_bob).is_err());
}

#[test]
fn recorded_removals_must_be_committed() {
    let (mut world, mut alice) = World::create(4);
    let bob = world.join_by_invite(&alice, 5);
    world.sync(&mut alice);
    let leave = bob
        .session
        .propose_leave(&bob.identity, &mut world.rng)
        .unwrap();
    world
        .ledger
        .submit_remove_proposal(leave.encoded())
        .unwrap();
    assert!(!world.ledger.is_vacant());
    // A commit that ignores the recorded proposal is refused.
    let (_, published) = alice
        .session
        .commit(&alice.identity, &[], &[], &mut world.rng)
        .unwrap();
    assert_eq!(
        world.publish(&published),
        Err(CoreError::Invalid(
            "pending removal proposals must be committed"
        ))
    );
    world.commit(&mut alice, &[], &[]).unwrap();
    assert_eq!(world.ledger.roster().len(), 1);
    assert_eq!(world.pending().len(), 0);
}

#[test]
fn admins_remove_members_and_manage_rights() {
    let (mut world, mut alice) = World::create(6);
    let mut bob = world.join_by_invite(&alice, 7);
    world.sync(&mut alice);
    let mut carol = world.join_by_invite(&alice, 8);
    world.sync(&mut alice);
    world.sync(&mut bob);

    // A non-admin can neither remove, invite nor admit.
    assert!(matches!(
        bob.session
            .propose_removal(&bob.identity, 2, &mut world.rng),
        Err(CoreError::Unauthorized(_))
    ));
    assert!(matches!(
        bob.session
            .create_invite(&bob.identity, &[1; 32], world.now + 1, &mut world.rng),
        Err(CoreError::Unauthorized(_))
    ));
    assert!(
        bob.session
            .admit(&bob.identity, carol.identity.public_key(), &mut world.rng)
            .is_err()
    );
    assert!(
        bob.session
            .commit(
                &bob.identity,
                &[],
                &[AdminChange::Grant(bob.identity.public_key().to_vec())],
                &mut world.rng
            )
            .is_err()
    );

    // Alice removes Carol in one commit and grants Bob admin rights.
    let removal = alice
        .session
        .propose_removal(&alice.identity, carol.session.my_slot(), &mut world.rng)
        .unwrap();
    world
        .commit(
            &mut alice,
            &[removal],
            &[AdminChange::Grant(bob.identity.public_key().to_vec())],
        )
        .unwrap();
    world.sync(&mut bob);
    assert!(matches!(
        world.sync(&mut carol).last(),
        Some(ProcessedCommit::Removed(_))
    ));
    assert!(world.ledger.roster().is_admin(bob.identity.public_key()));
    assert_agree(&world, &[&alice, &bob]);

    // Bob revokes Alice; the last admin cannot be revoked.
    world
        .commit(
            &mut bob,
            &[],
            &[AdminChange::Revoke(alice.identity.public_key().to_vec())],
        )
        .unwrap();
    world.sync(&mut alice);
    assert!(!world.ledger.roster().is_admin(alice.identity.public_key()));
    assert!(
        bob.session
            .commit(
                &bob.identity,
                &[],
                &[AdminChange::Revoke(bob.identity.public_key().to_vec())],
                &mut world.rng
            )
            .is_err()
    );

    // When the last admin leaves, the lowest remaining slot is promoted.
    let leave = bob
        .session
        .propose_leave(&bob.identity, &mut world.rng)
        .unwrap();
    world
        .ledger
        .submit_remove_proposal(leave.encoded())
        .unwrap();
    world.commit(&mut alice, &[], &[]).unwrap();
    assert!(world.ledger.roster().is_admin(alice.identity.public_key()));
    let outcome = world.sync(&mut bob);
    let Some(ProcessedCommit::Removed(summary)) = outcome.last() else {
        panic!("bob left")
    };
    assert_eq!(
        summary.promoted_admin.as_deref(),
        Some(alice.identity.public_key())
    );
}

#[test]
fn joins_need_an_admission_from_a_current_admin() {
    let (mut world, mut alice) = World::create(9);
    let mut bob = world.join_by_invite(&alice, 10);
    world.sync(&mut alice);

    // An admission signed by a non-admin member is refused by everyone.
    let joiner = DeviceIdentity::from_seed(&[11; 32]);
    let gid = *alice.session.gid();
    let rogue = SignedAdmission::by_admin(
        &gid,
        &joiner.leaf_id(&gid).unwrap(),
        &bob.identity,
        &mut world.rng,
    )
    .unwrap();
    assert!(matches!(
        world.join_with(11, rogue),
        Err(CoreError::Unauthorized(_))
    ));
    // A server cannot store an invite from a non-admin either.
    let rogue_invite = Invite::from_seed(&gid, &[1; 32], world.now + 10, bob.identity.public_key())
        .sign(&bob.identity, &mut world.rng)
        .unwrap();
    assert!(
        world
            .ledger
            .publish_invite(rogue_invite.encoded(), world.now)
            .is_err()
    );

    // Expired invites are refused by the ledger clock.
    let invite_seed = [77; 32];
    let invite = alice
        .session
        .create_invite(&alice.identity, &invite_seed, world.now + 5, &mut world.rng)
        .unwrap();
    let admission = SignedAdmission::with_invite(
        &joiner.leaf_id(&gid).unwrap(),
        &invite,
        &invite_seed,
        &mut world.rng,
    )
    .unwrap();
    world.now += 10;
    assert_eq!(
        world.join_with(11, admission.clone()).err(),
        Some(CoreError::Invalid("invite expired"))
    );
    assert!(
        world
            .ledger
            .publish_invite(invite.encoded(), world.now)
            .is_err()
    );

    // A member cannot join twice; its device must resync instead.
    let again = alice
        .session
        .admit(&alice.identity, bob.identity.public_key(), &mut world.rng)
        .unwrap();
    assert_eq!(
        world.join_with(10, again).err(),
        Some(CoreError::Invalid("joiner is already a member"))
    );
    world.sync(&mut bob);
    assert_agree(&world, &[&alice, &bob]);
}

#[test]
fn a_member_that_lost_its_state_resyncs() {
    let (mut world, mut alice) = World::create(12);
    let mut bob = world.join_by_invite(&alice, 13);
    world.sync(&mut alice);
    let mut carol = world.join_by_invite(&alice, 14);
    world.sync(&mut alice);
    world.sync(&mut bob);
    let old_carol_generation = world.ledger.roster().member_in_slot(2).unwrap().generation;

    // Carol loses her private keys: she cannot process Bob's next commit.
    carol.session.private = PrivatePath::default();
    world.commit(&mut bob, &[], &[]).unwrap();
    world.sync(&mut alice);
    let (commit, _) = world.log.last().unwrap().clone();
    assert!(matches!(
        carol.session.process_commit(&commit, None),
        Err(CoreError::Decrypt(_))
    ));
    let report = carol
        .session
        .report_cover_failure(
            &carol.identity,
            world.ledger.epoch(),
            CoverFailureReason::NotCovered,
            &mut world.rng,
        )
        .unwrap();
    world.ledger.submit_cover_failure(report.encoded()).unwrap();
    assert_eq!(world.ledger.cover_failures().len(), 1);

    // She re-enters her slot with an external commit.
    let snapshot = world.ledger.snapshot().unwrap();
    let (pending, published) =
        GroupSession::resync(&carol.identity, &snapshot, &world.pending(), &mut world.rng).unwrap();
    world.publish(&published).unwrap();
    carol.session = pending.into_session().unwrap();
    world.sync(&mut alice);
    world.sync(&mut bob);
    assert_agree(&world, &[&alice, &bob, &carol]);
    let renewed = world.ledger.roster().member_in_slot(2).unwrap();
    assert_eq!(renewed.generation, old_carol_generation + 1);
    assert_eq!(carol.session.my_slot(), 2);

    let hello = world.send(&mut carol, b"back");
    assert_eq!(alice.session.decrypt(&hello).unwrap().plaintext, b"back");
    assert_eq!(bob.session.decrypt(&hello).unwrap().plaintext, b"back");
    // A non-member cannot resync.
    let stranger = DeviceIdentity::from_seed(&[99; 32]);
    assert!(
        GroupSession::resync(
            &stranger,
            &world.ledger.snapshot().unwrap(),
            &[],
            &mut world.rng
        )
        .is_err()
    );
}

#[test]
fn concurrent_commits_are_ordered_by_the_ledger() {
    let (mut world, mut alice) = World::create(15);
    let mut bob = world.join_by_invite(&alice, 16);
    world.sync(&mut alice);

    let (alice_pending, alice_commit) = alice
        .session
        .commit(&alice.identity, &[], &[], &mut world.rng)
        .unwrap();
    let (bob_pending, bob_commit) = bob
        .session
        .commit(&bob.identity, &[], &[], &mut world.rng)
        .unwrap();
    world.publish(&alice_commit).unwrap();
    alice.session.apply_own_commit(alice_pending).unwrap();
    assert!(matches!(
        world.publish(&bob_commit),
        Err(CoreError::EpochMismatch { .. })
    ));
    // Bob's stale pending state cannot be installed after processing.
    world.sync(&mut bob);
    assert!(bob.session.apply_own_commit(bob_pending).is_err());
    world.commit(&mut bob, &[], &[]).unwrap();
    world.sync(&mut alice);
    assert_agree(&world, &[&alice, &bob]);
    assert_eq!(bob.session.epochs_since_own_update(), 0);
    assert_eq!(alice.session.epochs_since_own_update(), 1);
}

impl Device {
    fn clone_session(&self) -> Device {
        Device {
            identity: self.identity.clone(),
            session: self.session.clone(),
        }
    }
}

#[test]
fn forks_and_foreign_commits_are_rejected() {
    let (mut world, mut alice) = World::create(17);
    let mut bob = world.join_by_invite(&alice, 18);
    world.sync(&mut alice);

    // Two different commits for the same epoch fork the history: members
    // on the two branches hold different transcripts, and a member on one
    // branch rejects the other branch's next commit.
    let mut on_a = alice.clone_session();
    let (pending_a, _) = on_a
        .session
        .commit(&alice.identity, &[], &[], &mut world.rng)
        .unwrap();
    on_a.session.apply_own_commit(pending_a).unwrap();
    let mut on_b = bob.clone_session();
    let (pending_b, _) = on_b
        .session
        .commit(&bob.identity, &[], &[], &mut world.rng)
        .unwrap();
    on_b.session.apply_own_commit(pending_b).unwrap();
    assert_eq!(on_a.session.epoch(), on_b.session.epoch());
    assert_ne!(
        on_a.session.transcript_fingerprint(),
        on_b.session.transcript_fingerprint()
    );
    let (_, next_on_b) = on_b
        .session
        .commit(&bob.identity, &[], &[], &mut world.rng)
        .unwrap();
    assert_eq!(
        on_a.session.process_commit(&next_on_b.commit, None).err(),
        Some(CoreError::TranscriptMismatch)
    );

    // A commit for another group, or for a past epoch, is rejected.
    let (_, other) = World::create(19);
    let (_, foreign) = other
        .session
        .commit(&other.identity, &[], &[], &mut world.rng)
        .unwrap();
    assert!(alice.session.process_commit(&foreign.commit, None).is_err());
    assert!(world.publish(&foreign).is_err());
    let stale = world.log[1].0.clone();
    assert!(matches!(
        alice.session.process_commit(&stale, None),
        Err(CoreError::EpochMismatch { .. })
    ));
    world.sync(&mut bob);
    assert_agree(&world, &[&alice, &bob]);
}

#[test]
fn late_messages_use_the_previous_epoch_during_the_grace_window() {
    let (mut world, mut alice) = World::create(20);
    let mut bob = world.join_by_invite(&alice, 21);
    world.sync(&mut alice);
    let mut carol = world.join_by_invite(&alice, 22);
    world.sync(&mut alice);
    world.sync(&mut bob);

    let late = world.send(&mut bob, b"sent before the commit");
    world.commit(&mut alice, &[], &[]).unwrap();
    world.sync(&mut carol);
    world.sync(&mut bob);
    assert!(carol.session.has_previous_epoch());
    assert_eq!(
        carol.session.decrypt(&late).unwrap().plaintext,
        b"sent before the commit"
    );
    // The delivery service still relays late messages during the window.
    let late2 = {
        let mut stale_bob = bob.clone_session();
        stale_bob.session = at_previous_epoch(&bob);
        stale_bob
            .session
            .encrypt(&bob.identity, 1, b"", b"late 2", world.now, &mut world.rng)
            .unwrap()
    };
    world.ledger.accept_message(&late2, world.now).unwrap();
    world.now += GRACE_WINDOW_MS + 1;
    let late3 = {
        let mut stale_bob = bob.clone_session();
        stale_bob.session = at_previous_epoch(&bob);
        stale_bob
            .session
            .encrypt(&bob.identity, 1, b"", b"late 3", world.now, &mut world.rng)
            .unwrap()
    };
    assert!(world.ledger.accept_message(&late3, world.now).is_err());
    carol.session.expire_previous_epoch();
    assert!(!carol.session.has_previous_epoch());
    assert!(carol.session.decrypt(&late2).is_err());
}

/// Bob's session with the message keys of the epoch before his last
/// processed commit, to emit late messages of that epoch.
fn at_previous_epoch(bob: &Device) -> GroupSession {
    let mut session = bob.session.clone();
    let previous = session.previous.take().unwrap();
    session.messages = previous.messages;
    session
}

#[test]
fn sessions_persist_and_resume() {
    let (mut world, mut alice) = World::create(23);
    let mut bob = world.join_by_invite(&alice, 24);
    world.sync(&mut alice);
    let first = world.send(&mut alice, b"one");
    let second = world.send(&mut alice, b"two");
    assert_eq!(bob.session.decrypt(&second).unwrap().plaintext, b"two");

    let exported = bob.session.export().unwrap();
    let mut restored = GroupSession::import(&exported).unwrap();
    assert_eq!(restored.public_state(), bob.session.public_state());
    assert_eq!(restored.decrypt(&first).unwrap().plaintext, b"one");
    assert_eq!(restored.decrypt(&second), Err(CoreError::Replay));
    assert!(format!("{restored:?}").contains("GroupSession"));

    // The restored session keeps committing and sending.
    let mut bob2 = Device {
        identity: bob.identity.clone(),
        session: restored,
    };
    world.commit(&mut bob2, &[], &[]).unwrap();
    world.sync(&mut alice);
    let hello = world.send(&mut bob2, b"after restore");
    assert_eq!(
        alice.session.decrypt(&hello).unwrap().plaintext,
        b"after restore"
    );
    assert_eq!(bob2.session.next_own_generation(), 1);
    assert_eq!(
        bob2.session.external_public_key().unwrap(),
        crate::group_info::SignedGroupInfo::decode_unverified(world.ledger.group_info())
            .unwrap()
            .info()
            .external_public_key
    );
    let exported = alice.session.export().unwrap();
    let restored = GroupSession::import(&exported).unwrap();
    assert!(restored.has_previous_epoch());
    assert!(GroupSession::import(&exported[..exported.len() - 1]).is_err());

    // The ledger restores from its snapshot too.
    let snapshot = world.ledger.to_cbor().unwrap();
    let restored_ledger = GroupLedger::from_cbor(&snapshot).unwrap();
    assert_eq!(restored_ledger.state(), world.ledger.state());
    assert_eq!(restored_ledger.to_cbor().unwrap(), snapshot);
    assert_eq!(restored_ledger.group_info(), world.ledger.group_info());
    assert_eq!(
        restored_ledger.epoch_started_at_ms(),
        world.ledger.epoch_started_at_ms()
    );
}

#[test]
fn identities_and_pending_states_are_checked() {
    let (mut world, mut alice) = World::create(25);
    let bob_identity = DeviceIdentity::from_seed(&[26; 32]);
    assert!(
        alice
            .session
            .commit(&bob_identity, &[], &[], &mut world.rng)
            .is_err()
    );
    assert!(
        alice
            .session
            .encrypt(&bob_identity, 1, b"", b"x", 0, &mut world.rng)
            .is_err()
    );
    let (pending, published) = alice
        .session
        .commit(&alice.identity, &[], &[], &mut world.rng)
        .unwrap();
    assert_eq!(pending.epoch(), 1);
    assert_eq!(pending.gid(), alice.session.gid());
    // Member commits apply to their session; this consumes the pending state.
    assert!(pending.into_session().is_err());
    world.publish(&published).unwrap();

    // Without its pending state a member cannot process its own commit: it
    // resyncs from the delivery service.
    assert_eq!(
        alice.session.process_commit(&published.commit, None).err(),
        Some(CoreError::Invalid("own commit without its pending state"))
    );
    let snapshot = world.ledger.snapshot().unwrap();
    let (pending, resync) =
        GroupSession::resync(&alice.identity, &snapshot, &[], &mut world.rng).unwrap();
    world.publish(&resync).unwrap();
    alice.session = pending.into_session().unwrap();
    assert_agree(&world, &[&alice]);

    // The ledger only takes the GroupInfo of the epoch a commit creates.
    let (_, next) = alice
        .session
        .commit(&alice.identity, &[], &[], &mut world.rng)
        .unwrap();
    let (_, other) = World::create(27);
    let (_, foreign) = other
        .session
        .commit(&other.identity, &[], &[], &mut world.rng)
        .unwrap();
    assert!(
        world
            .ledger
            .apply_commit(&next.commit, &foreign.group_info, world.now)
            .is_err()
    );
    assert!(
        world
            .ledger
            .apply_commit(&next.commit, &resync.group_info, world.now)
            .is_err()
    );
    world.publish(&next).unwrap();
}

#[test]
fn full_groups_refuse_joiners() {
    let (mut world, mut alice) = World::create(28);
    let mut members = Vec::new();
    for seed in 29..(29 + N_MAX as u8 - 1) {
        let device = world.join_by_invite(&alice, seed);
        world.sync(&mut alice);
        members.push(device);
    }
    assert_eq!(world.ledger.roster().len(), N_MAX as usize);
    let joiner = DeviceIdentity::from_seed(&[60; 32]);
    let admission = alice
        .session
        .admit(&alice.identity, joiner.public_key(), &mut world.rng)
        .unwrap();
    assert_eq!(
        world.join_with(60, admission).err(),
        Some(CoreError::Invalid("the group is full"))
    );
    // Everyone agrees after the join storm.
    for member in &mut members {
        world.sync(member);
    }
    let refs: Vec<&Device> = std::iter::once(&alice).chain(members.iter()).collect();
    assert_agree(&world, &refs);
    let hello = world.send(&mut alice, b"all here");
    for member in &mut members {
        assert_eq!(
            member.session.decrypt(&hello).unwrap().plaintext,
            b"all here"
        );
    }
}

#[test]
fn a_vacant_group_cannot_be_taken_over_with_a_stale_invite() {
    let (mut world, alice) = World::create(61);
    let invite_seed = [62; 32];
    let invite = world.invite(&alice, invite_seed);
    let leave = alice
        .session
        .propose_leave(&alice.identity, &mut world.rng)
        .unwrap();
    world
        .ledger
        .submit_remove_proposal(leave.encoded())
        .unwrap();
    assert!(world.ledger.is_vacant());
    let joiner = DeviceIdentity::from_seed(&[63; 32]);
    let gid = *alice.session.gid();
    let admission = SignedAdmission::with_invite(
        &joiner.leaf_id(&gid).unwrap(),
        &invite,
        &invite_seed,
        &mut world.rng,
    )
    .unwrap();
    assert!(matches!(
        world.join_with(63, admission),
        Err(CoreError::Unauthorized(_))
    ));
}
