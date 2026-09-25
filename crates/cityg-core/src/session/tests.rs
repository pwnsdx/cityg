//! Scenario tests: members ([`GroupSession`]) and the delivery service
//! ([`GroupLedger`]) running the v0.3 profile end to end.

use super::*;
use crate::ledger::{GroupLedger, JoinStatus, ProposalStatus};
use crate::message::GRACE_WINDOW_MS;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

pub(crate) const CAPACITY: u32 = 8;
/// Validity of the admissions the tests sign, in epochs.
pub(crate) const VALIDITY: u64 = 100;

pub(crate) struct Device {
    pub(crate) identity: DeviceIdentity,
    pub(crate) session: GroupSession,
}

impl Device {
    pub(crate) fn clone_session(&self) -> Device {
        Device {
            identity: self.identity.clone(),
            session: self.session.clone(),
        }
    }
}

/// A device whose join request is recorded, waiting for its welcome.
pub(crate) struct Joiner {
    pub(crate) identity: DeviceIdentity,
    pub(crate) secrets: JoinSecrets,
    pub(crate) reference: Digest,
}

pub(crate) struct World {
    pub(crate) rng: ChaCha20Rng,
    pub(crate) ledger: GroupLedger,
    /// Accepted commits by epoch.
    pub(crate) log: Vec<PublishedCommit>,
    /// The light-member proofs of each accepted commit, by epoch.
    pub(crate) lights: Vec<Vec<u8>>,
    pub(crate) now: u64,
}

impl World {
    pub(crate) fn create(seed: u8) -> (Self, Device) {
        Self::create_with_capacity(seed, CAPACITY)
    }

    pub(crate) fn create_with_capacity(seed: u8, capacity: u32) -> (Self, Device) {
        let mut rng = ChaCha20Rng::seed_from_u64(u64::from(seed));
        let identity = DeviceIdentity::from_seed(&[seed; 32]);
        let (pending, published) = GroupSession::create(&identity, capacity, &mut rng).unwrap();
        assert_eq!(published.epoch, 0);
        assert!(published.welcomes.is_empty());
        let (ledger, accepted) =
            GroupLedger::create(&published.commit, &published.group_info, 1_000).unwrap();
        assert_eq!(accepted.kind, CommitKind::Genesis);
        let session = pending.into_session().unwrap();
        assert_eq!(
            session.group_context(),
            &ledger.state().group_context().unwrap()
        );
        assert_eq!(session.me(), MemberRef { leaf: 0, since: 0 });
        (
            Self {
                rng,
                ledger,
                log: vec![published],
                lights: vec![accepted.light],
                now: 1_000,
            },
            Device { identity, session },
        )
    }

    pub(crate) fn removals(&self) -> Vec<SignedRemoveProposal> {
        self.ledger.pending_removals().cloned().collect()
    }

    pub(crate) fn joins(&self) -> Vec<SignedJoinRequest> {
        self.ledger.pending_joins().cloned().collect()
    }

    pub(crate) fn publish(
        &mut self,
        published: &PublishedCommit,
    ) -> CoreResult<crate::ledger::AcceptedCommit> {
        let accepted = self.ledger.apply_commit(
            &published.commit,
            &published.group_info,
            &published.welcomes,
            self.now,
        )?;
        self.log.push(published.clone());
        self.lights.push(accepted.light.clone());
        assert_eq!(self.log.len() as u64, self.ledger.epoch() + 1);
        Ok(accepted)
    }

    /// `device` commits every recorded proposal plus `removals`, `changes`
    /// and an optional rotation of its device key.
    pub(crate) fn commit_with(
        &mut self,
        device: &mut Device,
        removals: &[SignedRemoveProposal],
        changes: &[AdminChange],
        rotate_to: Option<DeviceIdentity>,
    ) -> CoreResult<()> {
        let mut all = self.removals();
        all.extend_from_slice(removals);
        let joins = self.joins();
        let (pending, published) = device.session.commit(
            &device.identity,
            CommitOptions {
                removals: &all,
                joins: &joins,
                admin_changes: changes,
                new_identity: rotate_to.as_ref(),
            },
            &mut self.rng,
        )?;
        self.publish(&published)?;
        device.session.apply_own_commit(pending)?;
        if let Some(new_identity) = rotate_to {
            device.identity = new_identity;
        }
        Ok(())
    }

    pub(crate) fn commit(&mut self, device: &mut Device) -> CoreResult<()> {
        self.commit_with(device, &[], &[], None)
    }

    /// Process every accepted commit the device has not seen yet.
    pub(crate) fn sync(&self, device: &mut Device) -> Vec<ProcessedCommit> {
        let mut outcomes = Vec::new();
        while device.session.epoch() < self.ledger.epoch() {
            let published = &self.log[device.session.epoch() as usize + 1];
            let outcome = device
                .session
                .process_commit(&published.commit, Some(&published.group_info))
                .unwrap();
            let removed = matches!(outcome, ProcessedCommit::Removed(_));
            outcomes.push(outcome);
            if removed {
                break;
            }
        }
        outcomes
    }

    pub(crate) fn invite(
        &mut self,
        admin: &Device,
        invite_seed: [u8; 32],
        max_uses: u64,
    ) -> SignedInvite {
        let invite = admin
            .session
            .create_invite(
                &admin.identity,
                &invite_seed,
                self.now + 60_000,
                max_uses,
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

    /// Admission of the device `seed` through a fresh invite of `admin`.
    pub(crate) fn admission_by_invite(&mut self, admin: &Device, seed: u8) -> SignedAdmission {
        let invite_seed = [seed.wrapping_add(100); 32];
        let invite = self.invite(admin, invite_seed, 1);
        let identity = DeviceIdentity::from_seed(&[seed; 32]);
        SignedAdmission::with_invite(
            &identity.device_id(self.ledger.gid()).unwrap(),
            self.ledger.epoch() + VALIDITY,
            &invite,
            &invite_seed,
            &mut self.rng,
        )
        .unwrap()
    }

    pub(crate) fn admission_by_admin(&mut self, admin: &Device, seed: u8) -> SignedAdmission {
        admin
            .session
            .admit(
                &admin.identity,
                DeviceIdentity::from_seed(&[seed; 32]).public_key(),
                self.ledger.epoch() + VALIDITY,
                &mut self.rng,
            )
            .unwrap()
    }

    /// Record the join request of the device `seed`.
    pub(crate) fn request(&mut self, seed: u8, admission: &SignedAdmission) -> CoreResult<Joiner> {
        let identity = DeviceIdentity::from_seed(&[seed; 32]);
        let (request, secrets) = GroupSession::request_join(&identity, admission, &mut self.rng)?;
        let (reference, status) = self
            .ledger
            .submit_join_request(request.encoded(), self.now)?;
        assert_eq!(status, ProposalStatus::Recorded);
        assert_eq!(reference, request.reference().unwrap());
        assert_eq!(self.ledger.join_status(&reference), JoinStatus::Pending);
        Ok(Joiner {
            identity,
            secrets,
            reference,
        })
    }

    /// Open the welcome of a committed join request, at the current epoch.
    pub(crate) fn welcome(&self, joiner: &Joiner) -> CoreResult<Device> {
        let JoinStatus::Committed { epoch, welcome } = self.ledger.join_status(&joiner.reference)
        else {
            return Err(CoreError::Invalid("join request not committed"));
        };
        let session = GroupSession::join_with_welcome(
            &joiner.identity,
            &joiner.secrets,
            &self.ledger.snapshot()?,
            &self.log[epoch as usize].commit,
            &welcome,
        )?;
        Ok(Device {
            identity: joiner.identity.clone(),
            session,
        })
    }

    /// External join of the device `seed`, bringing every recorded proposal.
    pub(crate) fn join_external(
        &mut self,
        seed: u8,
        admission: SignedAdmission,
    ) -> CoreResult<Device> {
        let identity = DeviceIdentity::from_seed(&[seed; 32]);
        let snapshot = self.ledger.snapshot()?;
        let (pending, published) = GroupSession::join_external(
            &identity,
            &snapshot,
            admission,
            &self.removals(),
            &self.joins(),
            &mut self.rng,
        )?;
        self.publish(&published)?;
        Ok(Device {
            identity,
            session: pending.into_session()?,
        })
    }

    /// Join `seed` through an invite link created by `admin`, externally.
    pub(crate) fn join_by_invite(&mut self, admin: &Device, seed: u8) -> Device {
        let admission = self.admission_by_invite(admin, seed);
        self.join_external(seed, admission).unwrap()
    }

    pub(crate) fn send(&mut self, device: &mut Device, text: &[u8]) -> Vec<u8> {
        let envelope = device
            .session
            .encrypt(&device.identity, 1, b"", text, self.now, &mut self.rng)
            .unwrap();
        self.ledger.accept_message(&envelope, self.now).unwrap();
        envelope
    }
}

pub(crate) fn assert_agree(world: &World, devices: &[&Device]) {
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
    assert_eq!(bob.session.me(), MemberRef { leaf: 1, since: 1 });

    // Carol and Dave request to join; Bob commits both requests at once.
    let admission = world.admission_by_admin(&alice, 3);
    let carol_request = world.request(3, &admission).unwrap();
    let admission = world.admission_by_invite(&alice, 4);
    let dave_request = world.request(4, &admission).unwrap();
    world.commit(&mut bob).unwrap();
    let mut carol = world.welcome(&carol_request).unwrap();
    let mut dave = world.welcome(&dave_request).unwrap();
    world.sync(&mut alice);
    assert_agree(&world, &[&alice, &bob, &carol, &dave]);
    assert_eq!(world.ledger.state().tree.member_count(), 4);
    assert_eq!(carol.session.me(), MemberRef { leaf: 2, since: 2 });
    assert_eq!(dave.session.me(), MemberRef { leaf: 3, since: 2 });
    assert!(world.joins().is_empty());

    let hello = world.send(&mut alice, b"hello");
    let received = bob.session.decrypt(&hello).unwrap();
    assert_eq!(received.plaintext, b"hello");
    assert_eq!(received.sender_device_pk, alice.identity.public_key());
    assert_eq!(received.sender, alice.session.me());
    assert_eq!(received.signed_timestamp_ms, world.now);
    assert_eq!(carol.session.decrypt(&hello).unwrap().plaintext, b"hello");
    assert_eq!(dave.session.decrypt(&hello).unwrap().plaintext, b"hello");
    assert_eq!(bob.session.decrypt(&hello), Err(CoreError::Replay));
    let reply = world.send(&mut dave, b"hi alice");
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
    let pending = world.removals();
    assert_eq!(
        carol.session.add_pending_removal(&pending[0]),
        Some(bob.session.me())
    );
    assert!(matches!(
        carol.session.decrypt(&late),
        Err(CoreError::Unauthorized(_))
    ));
    assert_eq!(alice.session.set_pending_removals(&pending).len(), 1);
    assert!(matches!(
        alice.session.decrypt(&late),
        Err(CoreError::Unauthorized(_))
    ));
    // Bob cannot commit his own removal (C-03).
    assert!(matches!(
        bob.session.commit(
            &bob.identity,
            CommitOptions {
                removals: &pending,
                ..CommitOptions::default()
            },
            &mut world.rng
        ),
        Err(CoreError::Unauthorized(_))
    ));

    world.commit(&mut carol).unwrap();
    world.sync(&mut alice);
    world.sync(&mut dave);
    let outcome = world.sync(&mut bob);
    let Some(ProcessedCommit::Removed(summary)) = outcome.last() else {
        panic!("bob must see his removal")
    };
    assert_eq!(summary.removed[0].member, bob.session.me());
    assert_agree(&world, &[&alice, &carol, &dave]);
    assert!(
        world
            .ledger
            .state()
            .tree
            .find_device(bob.identity.public_key())
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
fn batched_joins_enter_in_one_commit_and_grow_the_tree() {
    let (mut world, mut alice) = World::create_with_capacity(30, 16);
    let requests: Vec<Joiner> = (31..37)
        .map(|seed| {
            let admission = world.admission_by_admin(&alice, seed);
            world.request(seed, &admission).unwrap()
        })
        .collect();
    assert_eq!(world.ledger.pending().len(), 6);
    let width_before = world.ledger.state().tree.width();
    world.commit(&mut alice).unwrap();
    assert_eq!(world.ledger.epoch(), 1, "one commit for six joins");
    assert_eq!(width_before, 1);
    assert_eq!(world.ledger.state().tree.width(), 8);
    let mut joined: Vec<Device> = requests
        .iter()
        .map(|joiner| world.welcome(joiner).unwrap())
        .collect();
    let mut everyone: Vec<&Device> = joined.iter().collect();
    everyone.push(&alice);
    assert_agree(&world, &everyone);

    // Everyone can talk to everyone, and the joiners commit normally.
    let hello = world.send(&mut joined[5], b"from the last joiner");
    assert_eq!(
        alice.session.decrypt(&hello).unwrap().plaintext,
        b"from the last joiner"
    );
    for device in &mut joined[..5] {
        assert_eq!(
            device.session.decrypt(&hello).unwrap().plaintext,
            b"from the last joiner"
        );
    }
    let mut first = joined.remove(0);
    world.commit(&mut first).unwrap();
    world.sync(&mut alice);
    for device in &mut joined {
        world.sync(device);
    }
    let mut everyone: Vec<&Device> = joined.iter().collect();
    everyone.push(&alice);
    everyone.push(&first);
    assert_agree(&world, &everyone);
}

#[test]
fn an_external_join_brings_the_other_requests() {
    let (mut world, mut alice) = World::create(40);
    let admission = world.admission_by_invite(&alice, 41);
    let bob_request = world.request(41, &admission).unwrap();
    let admission = world.admission_by_admin(&alice, 42);
    let carol_request = world.request(42, &admission).unwrap();
    // Nobody commits; Dave joins externally and brings Bob and Carol.
    let admission = world.admission_by_invite(&alice, 43);
    let mut dave = world.join_external(43, admission).unwrap();
    assert_eq!(dave.session.me(), MemberRef { leaf: 1, since: 1 });
    let mut bob = world.welcome(&bob_request).unwrap();
    let mut carol = world.welcome(&carol_request).unwrap();
    world.sync(&mut alice);
    assert_agree(&world, &[&alice, &bob, &carol, &dave]);
    assert_eq!(bob.session.me().leaf, 2);
    assert_eq!(carol.session.me().leaf, 3);
    let hello = world.send(&mut dave, b"welcome");
    assert_eq!(bob.session.decrypt(&hello).unwrap().plaintext, b"welcome");
    assert_eq!(carol.session.decrypt(&hello).unwrap().plaintext, b"welcome");
    world.commit(&mut bob).unwrap();
    world.sync(&mut alice);
    world.sync(&mut carol);
    world.sync(&mut dave);
    assert_agree(&world, &[&alice, &bob, &carol, &dave]);
}

#[test]
fn overdue_proposals_must_be_committed() {
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
    let admission = world.admission_by_admin(&alice, 6);
    let carol = world.request(6, &admission).unwrap();

    // Recorded during the current epoch, the proposals may wait one commit.
    let (pending, published) = alice
        .session
        .commit(&alice.identity, CommitOptions::default(), &mut world.rng)
        .unwrap();
    world.publish(&published).unwrap();
    alice.session.apply_own_commit(pending).unwrap();
    assert_eq!(world.ledger.pending().len(), 2);
    // Now they are overdue: a commit that leaves either out is refused.
    let removals = world.removals();
    for options in [
        CommitOptions::default(),
        CommitOptions {
            removals: &removals,
            ..CommitOptions::default()
        },
    ] {
        let (_, published) = alice
            .session
            .commit(&alice.identity, options, &mut world.rng)
            .unwrap();
        assert_eq!(
            world.publish(&published).err(),
            Some(CoreError::Invalid("overdue proposals must be committed"))
        );
    }
    world.commit(&mut alice).unwrap();
    assert_eq!(world.ledger.state().tree.member_count(), 2);
    assert!(world.ledger.pending().is_empty());
    let carol = world.welcome(&carol).unwrap();
    assert_agree(&world, &[&alice, &carol]);
}

#[test]
fn admins_remove_members_and_manage_rights() {
    let (mut world, mut alice) = World::create(6);
    let mut bob = world.join_by_invite(&alice, 7);
    world.sync(&mut alice);
    let mut carol = world.join_by_invite(&alice, 8);
    world.sync(&mut alice);
    world.sync(&mut bob);

    // A non-admin can neither remove, invite, admit nor change admins.
    assert!(matches!(
        bob.session
            .propose_removal(&bob.identity, 2, &mut world.rng),
        Err(CoreError::Unauthorized(_))
    ));
    assert!(matches!(
        bob.session
            .create_invite(&bob.identity, &[1; 32], world.now + 1, 1, &mut world.rng),
        Err(CoreError::Unauthorized(_))
    ));
    assert!(
        bob.session
            .admit(
                &bob.identity,
                carol.identity.public_key(),
                9,
                &mut world.rng
            )
            .is_err()
    );
    assert!(
        bob.session
            .revoke_invite(&bob.identity, &[0; 32], &mut world.rng)
            .is_err()
    );
    let grant_bob = [AdminChange::Grant {
        leaf: bob.session.me().leaf,
        since: bob.session.me().since,
    }];
    assert!(
        bob.session
            .commit(
                &bob.identity,
                CommitOptions {
                    admin_changes: &grant_bob,
                    ..CommitOptions::default()
                },
                &mut world.rng
            )
            .is_err()
    );

    // Alice removes Carol in one commit and grants Bob admin rights.
    let removal = alice
        .session
        .propose_removal(&alice.identity, carol.session.my_leaf(), &mut world.rng)
        .unwrap();
    world
        .commit_with(&mut alice, &[removal], &grant_bob, None)
        .unwrap();
    world.sync(&mut bob);
    assert!(matches!(
        world.sync(&mut carol).last(),
        Some(ProcessedCommit::Removed(_))
    ));
    assert!(world.ledger.state().registry.is_admin(1));
    assert!(bob.session.is_admin());
    assert_agree(&world, &[&alice, &bob]);
    // A grant to someone who is not a member of that occupancy is refused.
    let stale = [AdminChange::Grant { leaf: 1, since: 0 }];
    assert!(
        alice
            .session
            .commit(
                &alice.identity,
                CommitOptions {
                    admin_changes: &stale,
                    ..CommitOptions::default()
                },
                &mut world.rng
            )
            .is_err()
    );

    // Bob revokes Alice.
    let revoke_alice = [AdminChange::Revoke { leaf: 0, since: 0 }];
    world
        .commit_with(&mut bob, &[], &revoke_alice, None)
        .unwrap();
    world.sync(&mut alice);
    assert!(!alice.session.is_admin());

    // When the last admin leaves, the author of the commit that removes it
    // becomes admin.
    let leave = bob
        .session
        .propose_leave(&bob.identity, &mut world.rng)
        .unwrap();
    world
        .ledger
        .submit_remove_proposal(leave.encoded())
        .unwrap();
    world.commit(&mut alice).unwrap();
    assert!(world.ledger.state().registry.is_admin(0));
    let outcome = world.sync(&mut bob);
    let Some(ProcessedCommit::Removed(summary)) = outcome.last() else {
        panic!("bob left")
    };
    assert_eq!(summary.promoted_admin, Some(0));
    // The last admin revoking itself is promoted back as the author.
    let revoke_self = [AdminChange::Revoke { leaf: 0, since: 0 }];
    world
        .commit_with(&mut alice, &[], &revoke_self, None)
        .unwrap();
    assert!(alice.session.is_admin());
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
        &joiner.device_id(&gid).unwrap(),
        VALIDITY,
        &bob.identity,
        &mut world.rng,
    )
    .unwrap();
    assert!(matches!(
        world.request(11, &rogue),
        Err(CoreError::Unauthorized(_))
    ));
    assert!(matches!(
        world.join_external(11, rogue),
        Err(CoreError::Unauthorized(_))
    ));
    // A server cannot store an invite from a non-admin either.
    let rogue_invite =
        Invite::from_seed(&gid, &[1; 32], world.now + 10, 1, bob.identity.public_key())
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
        .create_invite(
            &alice.identity,
            &invite_seed,
            world.now + 5,
            3,
            &mut world.rng,
        )
        .unwrap();
    let admission = SignedAdmission::with_invite(
        &joiner.device_id(&gid).unwrap(),
        VALIDITY,
        &invite,
        &invite_seed,
        &mut world.rng,
    )
    .unwrap();
    world.now += 10;
    assert_eq!(
        world.join_external(11, admission.clone()).err(),
        Some(CoreError::Invalid("invite expired"))
    );
    assert_eq!(
        world.request(11, &admission).err(),
        Some(CoreError::Invalid("invite expired"))
    );
    assert!(
        world
            .ledger
            .publish_invite(invite.encoded(), world.now)
            .is_err()
    );

    // An admission is only good within its epoch window.
    let late = alice
        .session
        .admit(&alice.identity, joiner.public_key(), 1, &mut world.rng)
        .unwrap();
    assert_eq!(
        world.request(11, &late).err(),
        Some(CoreError::Invalid("admission outside its validity"))
    );

    // A member cannot join twice; its device resyncs instead.
    let again = world.admission_by_admin(&alice, 10);
    assert_eq!(
        world.join_external(10, again.clone()).err(),
        Some(CoreError::Invalid("joiner is already a member"))
    );
    assert_eq!(
        world.request(10, &again).err(),
        Some(CoreError::Invalid("joiner is already a member"))
    );
    world.sync(&mut bob);
    assert_agree(&world, &[&alice, &bob]);
}

#[test]
fn invites_count_their_uses_and_can_be_revoked() {
    let (mut world, mut alice) = World::create(50);
    let invite_seed = [51; 32];
    let invite = world.invite(&alice, invite_seed, 2);
    let id = invite.id().unwrap();
    let gid = *alice.session.gid();
    let admission_for = |world: &mut World, seed: u8| {
        SignedAdmission::with_invite(
            &DeviceIdentity::from_seed(&[seed; 32])
                .device_id(&gid)
                .unwrap(),
            VALIDITY,
            &invite,
            &invite_seed,
            &mut world.rng,
        )
        .unwrap()
    };
    let admission = admission_for(&mut world, 52);
    let first = world.request(52, &admission).unwrap();
    let admission = admission_for(&mut world, 53);
    let mut second = world.join_external(53, admission).unwrap();
    assert_eq!(world.ledger.invite_uses(&id), 2);
    let admission = admission_for(&mut world, 54);
    assert_eq!(
        world.request(54, &admission).err(),
        Some(CoreError::Unauthorized("invite has no use left"))
    );
    let mut first = world.welcome(&first).unwrap();
    world.sync(&mut alice);
    assert_agree(&world, &[&alice, &first, &second]);

    // A revoked invite drops the requests relying on it and cannot be
    // published again.
    let invite_seed = [55; 32];
    let invite = world.invite(&alice, invite_seed, 5);
    let id = invite.id().unwrap();
    let admission = SignedAdmission::with_invite(
        &DeviceIdentity::from_seed(&[56; 32])
            .device_id(&gid)
            .unwrap(),
        VALIDITY,
        &invite,
        &invite_seed,
        &mut world.rng,
    )
    .unwrap();
    let pending = world.request(56, &admission).unwrap();
    // Only an admin revokes.
    let by_member =
        SignedInviteRevocation::sign(&gid, &id, &second.identity, &mut world.rng).unwrap();
    assert!(world.ledger.revoke_invite(by_member.encoded()).is_err());
    let revocation = alice
        .session
        .revoke_invite(&alice.identity, &id, &mut world.rng)
        .unwrap();
    assert_eq!(
        world.ledger.revoke_invite(revocation.encoded()).unwrap(),
        vec![pending.reference]
    );
    assert_eq!(
        world.ledger.join_status(&pending.reference),
        JoinStatus::Unknown
    );
    assert!(world.ledger.invite(&id, world.now).is_none());
    assert_eq!(
        world.ledger.publish_invite(invite.encoded(), world.now),
        Err(CoreError::Unauthorized("invite revoked"))
    );
    assert_eq!(
        world.request(56, &admission).err(),
        Some(CoreError::Unauthorized("invite revoked"))
    );
    world.commit(&mut second).unwrap();
    world.sync(&mut first);
    world.sync(&mut alice);
    assert_agree(&world, &[&alice, &first, &second]);
}

#[test]
fn a_member_that_lost_its_state_resyncs() {
    let (mut world, mut alice) = World::create(12);
    let mut bob = world.join_by_invite(&alice, 13);
    world.sync(&mut alice);
    let mut carol = world.join_by_invite(&alice, 14);
    world.sync(&mut alice);
    world.sync(&mut bob);
    let old_carol = carol.session.me();

    // Carol loses her private keys: she cannot process Bob's next commit.
    carol.session.private = PrivatePath::default();
    world.commit(&mut bob).unwrap();
    world.sync(&mut alice);
    let commit = world.log.last().unwrap().commit.clone();
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

    // She re-enters her leaf with an external commit: a new occupancy.
    let snapshot = world.ledger.snapshot().unwrap();
    let (pending, published) = GroupSession::resync(
        &carol.identity,
        &snapshot,
        &world.removals(),
        &world.joins(),
        &mut world.rng,
    )
    .unwrap();
    world.publish(&published).unwrap();
    carol.session = pending.into_session().unwrap();
    world.sync(&mut alice);
    world.sync(&mut bob);
    assert_agree(&world, &[&alice, &bob, &carol]);
    assert_eq!(carol.session.my_leaf(), old_carol.leaf);
    assert_eq!(carol.session.me().since, world.ledger.epoch());

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
        .commit(&alice.identity, CommitOptions::default(), &mut world.rng)
        .unwrap();
    let (bob_pending, bob_commit) = bob
        .session
        .commit(&bob.identity, CommitOptions::default(), &mut world.rng)
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
    world.commit(&mut bob).unwrap();
    world.sync(&mut alice);
    assert_agree(&world, &[&alice, &bob]);
    assert_eq!(bob.session.epochs_since_own_update(), 0);
    assert_eq!(alice.session.epochs_since_own_update(), 1);
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
        .commit(&alice.identity, CommitOptions::default(), &mut world.rng)
        .unwrap();
    on_a.session.apply_own_commit(pending_a).unwrap();
    let mut on_b = bob.clone_session();
    let (pending_b, _) = on_b
        .session
        .commit(&bob.identity, CommitOptions::default(), &mut world.rng)
        .unwrap();
    on_b.session.apply_own_commit(pending_b).unwrap();
    assert_eq!(on_a.session.epoch(), on_b.session.epoch());
    assert_ne!(
        on_a.session.transcript_fingerprint(),
        on_b.session.transcript_fingerprint()
    );
    let (_, next_on_b) = on_b
        .session
        .commit(&bob.identity, CommitOptions::default(), &mut world.rng)
        .unwrap();
    assert_eq!(
        on_a.session.process_commit(&next_on_b.commit, None).err(),
        Some(CoreError::TranscriptMismatch)
    );

    // A commit for another group, or for a past epoch, is rejected.
    let (_, other) = World::create(19);
    let (_, foreign) = other
        .session
        .commit(&other.identity, CommitOptions::default(), &mut world.rng)
        .unwrap();
    assert!(alice.session.process_commit(&foreign.commit, None).is_err());
    assert!(world.publish(&foreign).is_err());
    let stale = world.log[1].commit.clone();
    assert!(matches!(
        alice.session.process_commit(&stale, None),
        Err(CoreError::EpochMismatch { .. })
    ));
    world.sync(&mut bob);
    assert_agree(&world, &[&alice, &bob]);
}

/// Bob's session with the message keys of the epoch `back` commits before
/// his current one, to emit late messages of that epoch.
fn at_previous_epoch(bob: &Device, back: usize) -> GroupSession {
    let mut session = bob.session.clone();
    session.messages = session.previous[back].messages.clone();
    session
}

#[test]
fn late_messages_are_accepted_for_several_epochs_during_the_grace_window() {
    let (mut world, mut alice) = World::create(20);
    let mut bob = world.join_by_invite(&alice, 21);
    world.sync(&mut alice);
    let mut carol = world.join_by_invite(&alice, 22);
    world.sync(&mut alice);
    world.sync(&mut bob);

    let late = world.send(&mut bob, b"sent before three commits");
    for _ in 0..3 {
        world.commit(&mut alice).unwrap();
    }
    world.sync(&mut carol);
    world.sync(&mut bob);
    // Carol joined at epoch 2: she holds the keys of epochs 2 to 4.
    assert_eq!(
        carol.session.previous_epochs().collect::<Vec<_>>(),
        vec![4, 3, 2]
    );
    assert_eq!(bob.session.previous_epochs().count(), MAX_GRACE_EPOCHS);
    assert_eq!(
        carol.session.decrypt(&late).unwrap().plaintext,
        b"sent before three commits"
    );
    // The delivery service still relays late messages of recent epochs.
    let late2 = at_previous_epoch(&bob, 2)
        .encrypt(&bob.identity, 1, b"", b"late 2", world.now, &mut world.rng)
        .unwrap();
    world.ledger.accept_message(&late2, world.now).unwrap();
    assert_eq!(carol.session.decrypt(&late2).unwrap().plaintext, b"late 2");
    // Beyond the grace window or the number of epochs, it refuses them.
    world.commit(&mut alice).unwrap();
    world.sync(&mut bob);
    let too_old = at_previous_epoch(&bob, 3)
        .encrypt(&bob.identity, 1, b"", b"too old", world.now, &mut world.rng)
        .unwrap();
    world.commit(&mut alice).unwrap();
    assert!(world.ledger.accept_message(&too_old, world.now).is_err());
    world.now += GRACE_WINDOW_MS + 1;
    let late3 = at_previous_epoch(&bob, 0)
        .encrypt(&bob.identity, 1, b"", b"late 3", world.now, &mut world.rng)
        .unwrap();
    assert!(world.ledger.accept_message(&late3, world.now).is_err());
    let newest = carol.session.epoch();
    carol.session.expire_epochs_through(newest - 2);
    assert_eq!(
        carol.session.previous_epochs().collect::<Vec<_>>(),
        vec![newest - 1]
    );
    carol.session.expire_previous_epochs();
    assert!(carol.session.decrypt(&late2).is_err());
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
    world.commit(&mut bob2).unwrap();
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
    assert_eq!(restored.previous_epochs().collect::<Vec<_>>(), vec![1, 0]);
    assert!(GroupSession::import(&exported[..exported.len() - 1]).is_err());

    // The ledger restores from its snapshot too, with its pending
    // proposals, invites, revocations and welcomes.
    let admission = world.admission_by_admin(&alice, 25);
    let carol = world.request(25, &admission).unwrap();
    let invite = world.invite(&alice, [26; 32], 1);
    let revocation = alice
        .session
        .revoke_invite(&alice.identity, &invite.id().unwrap(), &mut world.rng)
        .unwrap();
    world.ledger.revoke_invite(revocation.encoded()).unwrap();
    world.invite(&alice, [27; 32], 1);
    let leave = bob2
        .session
        .propose_leave(&bob2.identity, &mut world.rng)
        .unwrap();
    world
        .ledger
        .submit_remove_proposal(leave.encoded())
        .unwrap();
    let snapshot = world.ledger.to_cbor().unwrap();
    let restored_ledger = GroupLedger::from_cbor(&snapshot).unwrap();
    assert_eq!(restored_ledger.state(), world.ledger.state());
    assert_eq!(restored_ledger.to_cbor().unwrap(), snapshot);
    assert_eq!(restored_ledger.group_info(), world.ledger.group_info());
    assert_eq!(restored_ledger.pending(), world.ledger.pending());
    assert_eq!(
        restored_ledger.epoch_started_at_ms(),
        world.ledger.epoch_started_at_ms()
    );
    world.commit(&mut alice).unwrap();
    let snapshot = world.ledger.to_cbor().unwrap();
    let restored_ledger = GroupLedger::from_cbor(&snapshot).unwrap();
    assert_eq!(
        restored_ledger.join_status(&carol.reference),
        world.ledger.join_status(&carol.reference)
    );
    assert!(GroupLedger::from_cbor(&snapshot[..snapshot.len() - 1]).is_err());
}

#[test]
fn identities_and_pending_states_are_checked() {
    let (mut world, mut alice) = World::create(25);
    let bob_identity = DeviceIdentity::from_seed(&[26; 32]);
    assert!(
        alice
            .session
            .commit(&bob_identity, CommitOptions::default(), &mut world.rng)
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
        .commit(&alice.identity, CommitOptions::default(), &mut world.rng)
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
        GroupSession::resync(&alice.identity, &snapshot, &[], &[], &mut world.rng).unwrap();
    world.publish(&resync).unwrap();
    alice.session = pending.into_session().unwrap();
    assert_agree(&world, &[&alice]);

    // The ledger only takes the GroupInfo of the epoch a commit creates.
    let (_, next) = alice
        .session
        .commit(&alice.identity, CommitOptions::default(), &mut world.rng)
        .unwrap();
    let (_, other) = World::create(27);
    let (_, foreign) = other
        .session
        .commit(&other.identity, CommitOptions::default(), &mut world.rng)
        .unwrap();
    assert!(
        world
            .ledger
            .apply_commit(&next.commit, &foreign.group_info, &[], world.now)
            .is_err()
    );
    assert!(
        world
            .ledger
            .apply_commit(&next.commit, &resync.group_info, &[], world.now)
            .is_err()
    );
    assert_eq!(
        world
            .ledger
            .apply_commit(&next.commit, &next.group_info, &[vec![1]], world.now)
            .err(),
        Some(CoreError::Invalid("one welcome per join request"))
    );
    world.publish(&next).unwrap();
}

#[test]
fn full_groups_refuse_joiners() {
    let (mut world, mut alice) = World::create(28);
    let mut members = Vec::new();
    for seed in 29..(29 + CAPACITY as u8 - 2) {
        let device = world.join_by_invite(&alice, seed);
        world.sync(&mut alice);
        members.push(device);
    }
    // One place left: a request takes it, the next one is refused.
    let admission = world.admission_by_admin(&alice, 59);
    let last = world.request(59, &admission).unwrap();
    let admission = world.admission_by_admin(&alice, 60);
    assert_eq!(
        world.request(60, &admission).err(),
        Some(CoreError::TooLarge("the group is full"))
    );
    world.commit(&mut alice).unwrap();
    members.push(world.welcome(&last).unwrap());
    assert_eq!(world.ledger.state().tree.member_count(), CAPACITY as usize);
    assert_eq!(
        world.join_external(60, admission).err(),
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
fn a_group_without_admin_cannot_be_taken_over_with_a_stale_invite() {
    let (mut world, alice) = World::create(61);
    let invite_seed = [62; 32];
    let invite = world.invite(&alice, invite_seed, 1);
    let leave = alice
        .session
        .propose_leave(&alice.identity, &mut world.rng)
        .unwrap();
    world
        .ledger
        .submit_remove_proposal(leave.encoded())
        .unwrap();
    let joiner = DeviceIdentity::from_seed(&[63; 32]);
    let gid = *alice.session.gid();
    let admission = SignedAdmission::with_invite(
        &joiner.device_id(&gid).unwrap(),
        VALIDITY,
        &invite,
        &invite_seed,
        &mut world.rng,
    )
    .unwrap();
    // The joiner has to commit Alice's leave, which ends her admin rights.
    assert!(matches!(
        world.join_external(63, admission),
        Err(CoreError::Unauthorized(_))
    ));
}

#[test]
fn removed_devices_cannot_rejoin_with_their_old_admission() {
    let (mut world, mut alice) = World::create(40);
    let mut bob = world.join_by_invite(&alice, 41);
    world.sync(&mut alice);
    // Alice admits Carol's device directly: an admin admission names the
    // device, not an occupancy.
    let admission = world.admission_by_admin(&alice, 42);
    let mut carol = world.join_external(42, admission.clone()).unwrap();
    world.sync(&mut alice);
    world.sync(&mut bob);

    // Alice expels Carol.
    let removal = alice
        .session
        .propose_removal(&alice.identity, carol.session.my_leaf(), &mut world.rng)
        .unwrap();
    world
        .commit_with(&mut alice, &[removal], &[], None)
        .unwrap();
    world.sync(&mut bob);
    assert!(matches!(
        world.sync(&mut carol).last(),
        Some(ProcessedCommit::Removed(_))
    ));
    assert!(world.ledger.state().registry.is_retired(&admission.hash()));

    // Her old admission does not bring her back, by either path.
    assert!(matches!(
        world.join_external(42, admission.clone()),
        Err(CoreError::Unauthorized(_))
    ));
    assert!(matches!(
        world.request(42, &admission),
        Err(CoreError::Unauthorized(_))
    ));
    assert_eq!(world.ledger.state().tree.member_count(), 2);
    // A new admission from an admin does.
    let fresh = world.admission_by_admin(&alice, 42);
    let carol = world.join_external(42, fresh).unwrap();
    world.sync(&mut alice);
    world.sync(&mut bob);
    assert_agree(&world, &[&alice, &bob, &carol]);
}

#[test]
fn a_member_rotates_its_device_key() {
    let (mut world, mut alice) = World::create(70);
    let mut bob = world.join_by_invite(&alice, 71);
    world.sync(&mut alice);
    let mut carol = world.join_by_invite(&alice, 72);
    world.sync(&mut alice);
    world.sync(&mut bob);
    let bob_ref = bob.session.me();
    let old_identity = bob.identity.clone();

    // A message of the epoch before the rotation, signed with the old key.
    let before = world.send(&mut bob, b"with the old key");
    let new_identity = DeviceIdentity::from_seed(&[73; 32]);
    world
        .commit_with(&mut bob, &[], &[], Some(new_identity.clone()))
        .unwrap();
    let outcome = world.sync(&mut alice);
    let Some(ProcessedCommit::Advanced(summary)) = outcome.last() else {
        panic!("alice processes the rotation")
    };
    assert_eq!(
        summary.rotated_device_pk.as_deref(),
        Some(new_identity.public_key())
    );
    world.sync(&mut carol);
    assert_agree(&world, &[&alice, &bob, &carol]);
    assert_eq!(bob.session.me(), bob_ref, "the occupancy stays");
    assert_eq!(
        world
            .ledger
            .state()
            .tree
            .leaf(bob_ref.leaf)
            .unwrap()
            .device_pk,
        new_identity.public_key()
    );
    // Late messages signed with the old key still verify for their epoch.
    assert_eq!(
        carol.session.decrypt(&before).unwrap().plaintext,
        b"with the old key"
    );
    // New messages are signed with the new key; the old key is useless.
    let after = world.send(&mut bob, b"with the new key");
    assert_eq!(
        alice.session.decrypt(&after).unwrap().plaintext,
        b"with the new key"
    );
    assert!(
        bob.session
            .encrypt(&old_identity, 1, b"", b"x", 0, &mut world.rng)
            .is_err()
    );
    let mut stale = bob.clone_session();
    stale.identity = old_identity.clone();
    assert!(world.commit(&mut stale).is_err());
    let snapshot = world.ledger.snapshot().unwrap();
    assert!(GroupSession::resync(&old_identity, &snapshot, &[], &[], &mut world.rng).is_err());
    // Nobody can rotate to a key already in the group.
    let duplicate = alice.identity.clone();
    assert!(
        bob.session
            .commit(
                &bob.identity,
                CommitOptions {
                    new_identity: Some(&duplicate),
                    ..CommitOptions::default()
                },
                &mut world.rng
            )
            .is_err()
    );
    // Bob keeps committing with the new key.
    world.commit(&mut bob).unwrap();
    world.sync(&mut alice);
    world.sync(&mut carol);
    assert_agree(&world, &[&alice, &bob, &carol]);
    let exported = carol.session.export().unwrap();
    let mut restored = GroupSession::import(&exported).unwrap();
    assert!(restored.decrypt(&before).is_err(), "already read");
}

#[test]
fn welcomes_are_bound_to_their_request_and_epoch() {
    let (mut world, mut alice) = World::create(80);
    let admission = world.admission_by_admin(&alice, 81);
    let bob = world.request(81, &admission).unwrap();
    let admission = world.admission_by_admin(&alice, 82);
    let carol = world.request(82, &admission).unwrap();
    world.commit(&mut alice).unwrap();
    let JoinStatus::Committed { epoch, welcome } = world.ledger.join_status(&bob.reference) else {
        panic!("bob's request is committed")
    };
    let JoinStatus::Committed {
        welcome: carol_welcome,
        ..
    } = world.ledger.join_status(&carol.reference)
    else {
        panic!("carol's request is committed")
    };
    let snapshot = world.ledger.snapshot().unwrap();
    let commit = world.log[epoch as usize].commit.clone();
    // Another joiner's welcome, secrets or identity do not open it.
    assert!(
        GroupSession::join_with_welcome(
            &bob.identity,
            &bob.secrets,
            &snapshot,
            &commit,
            &carol_welcome
        )
        .is_err()
    );
    assert!(
        GroupSession::join_with_welcome(
            &bob.identity,
            &carol.secrets,
            &snapshot,
            &commit,
            &welcome
        )
        .is_err()
    );
    assert!(
        GroupSession::join_with_welcome(
            &carol.identity,
            &bob.secrets,
            &snapshot,
            &commit,
            &welcome
        )
        .is_err()
    );
    // Nor another epoch's commit or snapshot.
    let genesis = world.log[0].commit.clone();
    assert!(
        GroupSession::join_with_welcome(&bob.identity, &bob.secrets, &snapshot, &genesis, &welcome)
            .is_err()
    );
    let mut bob_device =
        GroupSession::join_with_welcome(&bob.identity, &bob.secrets, &snapshot, &commit, &welcome)
            .unwrap();
    assert_eq!(bob_device.epochs_since_own_update(), 0);
    world.commit(&mut alice).unwrap();
    // Carol fetched her welcome too late: the group moved on, so she enters
    // through a resync of the leaf the commit gave her.
    assert!(world.welcome(&carol).is_err());
    let snapshot = world.ledger.snapshot().unwrap();
    let (pending, published) =
        GroupSession::resync(&carol.identity, &snapshot, &[], &[], &mut world.rng).unwrap();
    world.publish(&published).unwrap();
    let carol = Device {
        identity: carol.identity.clone(),
        session: pending.into_session().unwrap(),
    };
    let mut bob = Device {
        identity: bob.identity.clone(),
        session: {
            // Bob follows the log from his join epoch.
            while bob_device.epoch() < world.ledger.epoch() {
                let published = &world.log[bob_device.epoch() as usize + 1];
                bob_device
                    .process_commit(&published.commit, Some(&published.group_info))
                    .unwrap();
            }
            bob_device
        },
    };
    world.sync(&mut alice);
    assert_agree(&world, &[&alice, &bob, &carol]);
    let hello = world.send(&mut bob, b"hi");
    assert_eq!(alice.session.decrypt(&hello).unwrap().plaintext, b"hi");
}

#[test]
fn a_removed_admin_cannot_admit_in_the_same_commit() {
    let (mut world, mut alice) = World::create(90);
    let mut bob = world.join_by_invite(&alice, 91);
    world.sync(&mut alice);
    let grant = [AdminChange::Grant { leaf: 1, since: 1 }];
    world.commit_with(&mut alice, &[], &grant, None).unwrap();
    world.sync(&mut bob);
    // Bob admits Carol, then Alice removes Bob in the commit that would
    // bring Carol in: Carol's admission no longer has an admin behind it.
    let admission = world.admission_by_admin(&bob, 92);
    let carol = world.request(92, &admission).unwrap();
    let removal = alice
        .session
        .propose_removal(&alice.identity, 1, &mut world.rng)
        .unwrap();
    let joins = world.joins();
    assert!(matches!(
        alice.session.commit(
            &alice.identity,
            CommitOptions {
                removals: std::slice::from_ref(&removal),
                joins: &joins,
                ..CommitOptions::default()
            },
            &mut world.rng
        ),
        Err(CoreError::Unauthorized(_))
    ));
    // Without Carol's request the removal goes through, and the ledger drops
    // the request, which can no longer enter.
    let (pending, published) = alice
        .session
        .commit(
            &alice.identity,
            CommitOptions {
                removals: &[removal],
                ..CommitOptions::default()
            },
            &mut world.rng,
        )
        .unwrap();
    let accepted = world.publish(&published).unwrap();
    alice.session.apply_own_commit(pending).unwrap();
    assert_eq!(accepted.dropped_requests, vec![carol.reference]);
    assert_eq!(
        world.ledger.join_status(&carol.reference),
        JoinStatus::Unknown
    );
}

#[test]
fn a_recorded_joiner_can_commit_its_own_entry() {
    let (mut world, mut alice) = World::create(95);
    // A single-use invite: the request uses it, the joiner's own external
    // commit does not use it again.
    let invite_seed = [96; 32];
    let invite = world.invite(&alice, invite_seed, 1);
    let bob_identity = DeviceIdentity::from_seed(&[97; 32]);
    let admission = SignedAdmission::with_invite(
        &bob_identity.device_id(world.ledger.gid()).unwrap(),
        VALIDITY,
        &invite,
        &invite_seed,
        &mut world.rng,
    )
    .unwrap();
    let request = world.request(97, &admission).unwrap();
    let snapshot = world.ledger.snapshot().unwrap();
    let others: Vec<SignedJoinRequest> = world
        .joins()
        .into_iter()
        .filter(|pending| pending.device_pk != bob_identity.public_key())
        .collect();
    let (pending, published) = GroupSession::join_external(
        &bob_identity,
        &snapshot,
        admission,
        &world.removals(),
        &others,
        &mut world.rng,
    )
    .unwrap();
    world.publish(&published).unwrap();
    let bob = Device {
        identity: bob_identity,
        session: pending.into_session().unwrap(),
    };
    assert!(world.ledger.pending().is_empty(), "the request is obsolete");
    assert_eq!(
        world.ledger.join_status(&request.reference),
        JoinStatus::Unknown
    );
    assert_eq!(world.ledger.invite_uses(&invite.id().unwrap()), 1);
    world.sync(&mut alice);
    assert_agree(&world, &[&alice, &bob]);
}
