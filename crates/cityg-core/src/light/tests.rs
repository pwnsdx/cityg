//! Light-member scenarios: every light session is checked against a full
//! member following the same group.

use super::*;
use crate::commit::AdminChange;
use crate::ledger::JoinStatus;
use crate::session::tests::{Device, Joiner, World, assert_agree};
use crate::session::{CommitOptions, GroupSession};

struct Light {
    identity: DeviceIdentity,
    session: LightSession,
}

fn light_of(device: &Device) -> Light {
    Light {
        identity: device.identity.clone(),
        session: device.session.to_light().unwrap(),
    }
}

/// The light session agrees with the full session of the same member.
fn assert_same(light: &Light, full: &Device) {
    let (light, full) = (&light.session, &full.session);
    assert_eq!(light.group_context(), full.group_context());
    assert_eq!(
        light.transcript_fingerprint(),
        full.transcript_fingerprint()
    );
    assert_eq!(light.registry(), full.registry());
    assert!(light.members().eq(full.tree().member_refs()));
    assert_eq!(light.member_count(), full.tree().member_count());
    assert_eq!(light.me(), full.me());
    assert_eq!(light.is_admin(), full.is_admin());
    assert_eq!(light.next_own_generation(), full.next_own_generation());
    assert!(light.previous_epochs().eq(full.previous_epochs()));
}

/// Process every accepted commit the light member has not seen yet.
fn sync_light(world: &World, light: &mut Light) -> Vec<ProcessedCommit> {
    let mut outcomes = Vec::new();
    while light.session.epoch() < world.ledger.epoch() {
        let epoch = light.session.epoch() as usize + 1;
        let proofs = LightCommit::decode(&world.lights[epoch]).unwrap();
        let outcome = light
            .session
            .process_commit(
                &world.log[epoch].commit,
                Some(&world.log[epoch].group_info),
                &proofs,
            )
            .unwrap();
        let removed = matches!(outcome, ProcessedCommit::Removed(_));
        outcomes.push(outcome);
        if removed {
            break;
        }
    }
    outcomes
}

/// Decrypt as a light member, proving the sender's leaf first when needed.
fn light_decrypt(world: &World, light: &mut Light, envelope: &[u8]) -> ReceivedMessage {
    if let Some(sender) = light.session.unknown_sender(envelope).unwrap() {
        let proofs = world
            .ledger
            .state()
            .tree
            .leaf_proofs([sender.leaf])
            .unwrap();
        assert_eq!(light.session.learn_members(&proofs).unwrap(), 1);
    }
    light.session.decrypt(envelope).unwrap()
}

/// The light join of a committed request.
fn light_welcome(world: &World, joiner: &Joiner) -> CoreResult<Light> {
    let JoinStatus::Committed { epoch, welcome } = world.ledger.join_status(&joiner.reference)
    else {
        return Err(CoreError::Invalid("join request not committed"));
    };
    let join = LightJoin::decode(
        &world
            .ledger
            .light_join(&joiner.reference)?
            .ok_or(CoreError::Invalid("no light join"))?,
    )?;
    let session = LightSession::join_with_welcome(
        &joiner.identity,
        &joiner.secrets,
        &world.log[epoch as usize].commit,
        &world.log[epoch as usize].group_info,
        &welcome,
        &join,
    )?;
    Ok(Light {
        identity: joiner.identity.clone(),
        session,
    })
}

#[test]
fn a_light_member_follows_every_kind_of_commit() {
    let (mut world, mut alice) = World::create(31);
    let mut bob = world.join_by_invite(&alice, 32);
    let mut carol = world.join_by_invite(&alice, 33);
    world.sync(&mut alice);
    world.sync(&mut bob);
    // Carol goes light; a full copy of her session follows alongside.
    let mut light = light_of(&carol);
    assert_same(&light, &carol);

    // Batched joins (by admin and by invite), committed by Bob.
    let admission = world.admission_by_admin(&alice, 34);
    let dave_request = world.request(34, &admission).unwrap();
    let admission = world.admission_by_invite(&alice, 35);
    let erin_request = world.request(35, &admission).unwrap();
    world.commit(&mut bob).unwrap();
    let mut dave = world.welcome(&dave_request).unwrap();
    let mut erin = world.welcome(&erin_request).unwrap();
    let outcomes = sync_light(&world, &mut light);
    let full_outcomes = world.sync(&mut carol);
    assert_eq!(outcomes, full_outcomes);
    assert_same(&light, &carol);
    world.sync(&mut alice);

    // Messages from members the light session proves on first contact.
    let hello = world.send(&mut alice, b"hello");
    let received = light_decrypt(&world, &mut light, &hello);
    assert_eq!(received.plaintext, b"hello");
    assert_eq!(received.sender_device_pk, alice.identity.public_key());
    assert_eq!(light.session.decrypt(&hello), Err(CoreError::Replay));
    let from_dave = world.send(&mut dave, b"from dave");
    // Dave entered with the commit the light member processed: it learnt
    // his key from the join request itself.
    assert_eq!(light.session.unknown_sender(&from_dave).unwrap(), None);
    assert_eq!(
        light.session.decrypt(&from_dave).unwrap().plaintext,
        b"from dave"
    );
    let mine = light
        .session
        .encrypt(
            &light.identity,
            1,
            b"",
            b"light says hi",
            world.now,
            &mut world.rng,
        )
        .unwrap();
    world.ledger.accept_message(&mine, world.now).unwrap();
    assert_eq!(
        alice.session.decrypt(&mine).unwrap().plaintext,
        b"light says hi"
    );
    assert_eq!(
        erin.session.decrypt(&mine).unwrap().sender,
        light.session.me()
    );
    carol.session.expire_previous_epochs();
    light.session.expire_previous_epochs();

    // Admin changes and an admin removal of Dave, committed by Alice.
    let dave_leaf = dave.session.my_leaf();
    let removal = alice
        .session
        .propose_removal(&alice.identity, dave_leaf, &mut world.rng)
        .unwrap();
    let bob_ref = bob.session.me();
    world.sync(&mut alice);
    world
        .commit_with(
            &mut alice,
            &[removal],
            &[AdminChange::Grant {
                leaf: bob_ref.leaf,
                since: bob_ref.since,
            }],
            None,
        )
        .unwrap();
    assert_eq!(sync_light(&world, &mut light), world.sync(&mut carol));
    assert_same(&light, &carol);
    world.sync(&mut bob);
    world.sync(&mut erin);
    assert!(light.session.registry().is_admin(bob_ref.leaf));

    // Erin leaves (a self-removal committed by Bob).
    let leave = erin
        .session
        .propose_leave(&erin.identity, &mut world.rng)
        .unwrap();
    world
        .ledger
        .submit_remove_proposal(leave.encoded())
        .unwrap();
    assert_eq!(
        light.session.add_pending_removal(&leave),
        Some(erin.session.me())
    );
    carol.session.add_pending_removal(&leave);
    // The ledger refuses it too; the light member checks on its own.
    let blocked = erin
        .session
        .encrypt(
            &erin.identity,
            1,
            b"",
            b"still here",
            world.now,
            &mut world.rng,
        )
        .unwrap();
    assert!(light.session.decrypt(&blocked).is_err());
    world.commit(&mut bob).unwrap();
    assert_eq!(sync_light(&world, &mut light), world.sync(&mut carol));
    assert_same(&light, &carol);
    world.sync(&mut alice);

    // Bob rotates his device key; his message of the previous epoch still
    // verifies under his old key, the next one under the new key.
    let before = world.send(&mut bob, b"before rotation");
    let new_bob = DeviceIdentity::from_seed(&[132; 32]);
    world
        .commit_with(&mut bob, &[], &[], Some(new_bob))
        .unwrap();
    assert_eq!(sync_light(&world, &mut light), world.sync(&mut carol));
    assert_same(&light, &carol);
    world.sync(&mut alice);
    assert_eq!(
        light_decrypt(&world, &mut light, &before).plaintext,
        b"before rotation"
    );
    let after = world.send(&mut bob, b"after rotation");
    let received = light_decrypt(&world, &mut light, &after);
    assert_eq!(received.sender_device_pk, bob.identity.public_key());

    // An external join by Frank, and a resync by Alice.
    let admission = world.admission_by_invite(&alice, 36);
    let mut frank = world.join_external(36, admission).unwrap();
    assert_eq!(sync_light(&world, &mut light), world.sync(&mut carol));
    assert_same(&light, &carol);
    world.sync(&mut alice);
    world.sync(&mut bob);
    let snapshot = world.ledger.snapshot().unwrap();
    let (pending, published) = GroupSession::resync(
        &alice.identity,
        &snapshot,
        &world.removals(),
        &world.joins(),
        &mut world.rng,
    )
    .unwrap();
    world.publish(&published).unwrap();
    alice.session = pending.into_session().unwrap();
    let outcomes = sync_light(&world, &mut light);
    assert_eq!(outcomes, world.sync(&mut carol));
    assert!(matches!(
        &outcomes[0],
        ProcessedCommit::Advanced(summary) if summary.kind == CommitKind::Resync
    ));
    assert_same(&light, &carol);
    world.sync(&mut bob);
    world.sync(&mut frank);
    assert_agree(&world, &[&alice, &bob, &carol, &frank]);
    let hi = world.send(&mut alice, b"after resync");
    assert_eq!(
        light_decrypt(&world, &mut light, &hi).plaintext,
        b"after resync"
    );

    // Finally Bob, now an admin, removes Carol: the light session learns it.
    let removal = bob
        .session
        .propose_removal(&bob.identity, carol.session.my_leaf(), &mut world.rng)
        .unwrap();
    world.commit_with(&mut bob, &[removal], &[], None).unwrap();
    let outcomes = sync_light(&world, &mut light);
    assert!(matches!(outcomes.as_slice(), [ProcessedCommit::Removed(_)]));
    assert_eq!(outcomes, world.sync(&mut carol));
}

#[test]
fn a_light_joiner_enters_talks_and_becomes_full_to_commit() {
    let (mut world, mut alice) = World::create(41);
    let mut bob = world.join_by_invite(&alice, 42);
    world.sync(&mut alice);

    let admission = world.admission_by_invite(&alice, 43);
    let carol_request = world.request(43, &admission).unwrap();
    let admission = world.admission_by_admin(&alice, 44);
    let dave_request = world.request(44, &admission).unwrap();
    // Not committed yet: no welcome, no light join.
    assert!(light_welcome(&world, &carol_request).is_err());
    world.commit(&mut alice).unwrap();
    let mut carol = light_welcome(&world, &carol_request).unwrap();
    let mut dave = world.welcome(&dave_request).unwrap();
    world.sync(&mut bob);
    assert_eq!(carol.session.group_context(), dave.session.group_context());
    assert_eq!(carol.session.me(), MemberRef { leaf: 2, since: 2 });
    assert!(
        carol
            .session
            .members()
            .eq(dave.session.tree().member_refs())
    );
    assert_eq!(carol.session.epochs_since_own_update(), 0);
    assert_eq!(
        carol.session.known_key(alice.session.me()),
        Some(alice.identity.public_key())
    );
    assert_eq!(
        carol.session.known_key(carol.session.me()),
        Some(carol.identity.public_key())
    );

    // Messages both ways.
    let hello = world.send(&mut bob, b"hello carol");
    assert_eq!(
        light_decrypt(&world, &mut carol, &hello).plaintext,
        b"hello carol"
    );
    let reply = carol
        .session
        .encrypt(
            &carol.identity,
            1,
            b"",
            b"hi all",
            world.now,
            &mut world.rng,
        )
        .unwrap();
    world.ledger.accept_message(&reply, world.now).unwrap();
    assert_eq!(dave.session.decrypt(&reply).unwrap().plaintext, b"hi all");
    assert_eq!(bob.session.decrypt(&reply).unwrap().plaintext, b"hi all");

    // A later commit, followed light.
    world.commit(&mut dave).unwrap();
    sync_light(&world, &mut carol);
    world.sync(&mut alice);
    world.sync(&mut bob);
    assert_eq!(carol.session.group_context(), dave.session.group_context());

    // Carol becomes full with the snapshot of her epoch, re-keys, and goes
    // light again.
    let snapshot = world.ledger.snapshot().unwrap();
    let identity = carol.identity.clone();
    let mut full = Device {
        identity: identity.clone(),
        session: carol.session.clone().upgrade(&snapshot).unwrap(),
    };
    world.commit(&mut full).unwrap();
    world.sync(&mut alice);
    world.sync(&mut bob);
    world.sync(&mut dave);
    assert_agree(&world, &[&alice, &bob, &dave, &full]);
    let mut carol = light_of(&full);
    assert_eq!(carol.session.epochs_since_own_update(), 0);
    let message = world.send(&mut alice, b"after the update");
    assert_eq!(
        light_decrypt(&world, &mut carol, &message).plaintext,
        b"after the update"
    );

    // A snapshot of another epoch does not upgrade.
    let stale = world.ledger.snapshot().unwrap();
    world.commit(&mut bob).unwrap();
    let mut behind = carol.session.clone();
    behind.expire_previous_epochs();
    sync_light(&world, &mut carol);
    assert!(behind.upgrade(&world.ledger.snapshot().unwrap()).is_err());
    assert!(carol.session.clone().upgrade(&stale).is_err());
    assert!(
        carol
            .session
            .clone()
            .upgrade(&world.ledger.snapshot().unwrap())
            .is_ok()
    );
}

#[test]
fn light_sessions_reject_what_they_cannot_prove() {
    let (mut world, mut alice) = World::create(51);
    let mut bob = world.join_by_invite(&alice, 52);
    let carol = world.join_by_invite(&alice, 53);
    world.sync(&mut alice);
    world.sync(&mut bob);
    let mut light = light_of(&carol);
    let hello = world.send(&mut alice, b"hello");

    // An unproven sender is refused; a proof of another tree is refused.
    assert_eq!(
        light.session.unknown_sender(&hello).unwrap(),
        Some(alice.session.me())
    );
    assert_eq!(
        light.session.decrypt(&hello),
        Err(CoreError::Unauthorized("sender key not proven"))
    );
    let mut forged = world.ledger.state().tree.leaf_proof(0).unwrap();
    forged.path[0].sibling[0] ^= 1;
    assert!(light.session.learn_members(&[forged]).is_err());
    let blank = world.ledger.state().tree.leaf_proofs([3]).unwrap();
    assert_eq!(light.session.learn_members(&blank).unwrap(), 0);

    // A commit whose proofs are missing, forged or of another epoch.
    world.commit(&mut bob).unwrap();
    let epoch = world.ledger.epoch() as usize;
    let published = world.log[epoch].clone();
    let proofs = LightCommit::decode(&world.lights[epoch]).unwrap();
    assert_eq!(proofs.proofs.len(), 1, "only the author's record is needed");
    let missing = LightCommit { proofs: Vec::new() };
    assert!(
        light
            .session
            .clone()
            .process_commit(&published.commit, None, &missing)
            .is_err()
    );
    let mut forged = proofs.clone();
    forged.proofs[0].node.as_mut().unwrap().since += 1;
    assert!(
        light
            .session
            .clone()
            .process_commit(&published.commit, None, &forged)
            .is_err()
    );
    let stale = LightCommit::decode(&world.lights[epoch - 1]).unwrap();
    assert!(
        light
            .session
            .clone()
            .process_commit(&published.commit, None, &stale)
            .is_err()
    );
    // A GroupInfo of another epoch, a commit of another epoch.
    assert!(
        light
            .session
            .clone()
            .process_commit(
                &published.commit,
                Some(&world.log[epoch - 1].group_info),
                &proofs
            )
            .is_err()
    );
    assert!(
        light
            .session
            .clone()
            .process_commit(&world.log[epoch - 1].commit, None, &proofs)
            .is_err()
    );
    light
        .session
        .process_commit(&published.commit, Some(&published.group_info), &proofs)
        .unwrap();
    assert!(
        light
            .session
            .clone()
            .process_commit(&published.commit, None, &proofs)
            .is_err(),
        "the same commit twice"
    );

    // Encodings round-trip and reject garbage.
    assert_eq!(
        LightCommit::decode(&proofs.encode().unwrap()).unwrap(),
        proofs
    );
    assert!(LightCommit::decode(&[0x80]).is_err());
    let mut unsorted = proofs.clone();
    unsorted.proofs.push(proofs.proofs[0].clone());
    assert!(LightCommit::decode(&unsorted.encode().unwrap()).is_err());
    let exported = light.session.export().unwrap();
    let restored = LightSession::import(&exported).unwrap();
    assert_eq!(restored.group_context(), light.session.group_context());
    assert_eq!(restored.export().unwrap(), exported);
    assert!(LightSession::import(&exported[..exported.len() - 1]).is_err());
    assert!(format!("{:?}", light.session).contains("LightSession"));

    // Signing needs the member's own identity.
    assert!(
        light
            .session
            .encrypt(&bob.identity, 1, b"", b"x", 0, &mut world.rng)
            .is_err()
    );
    assert!(
        light
            .session
            .propose_leave(&bob.identity, &mut world.rng)
            .is_err()
    );
    let report = light
        .session
        .report_cover_failure(
            &light.identity,
            1,
            CoverFailureReason::NotCovered,
            &mut world.rng,
        )
        .unwrap();
    assert_eq!(report.epoch, 1);
    let leave = light
        .session
        .propose_leave(&light.identity, &mut world.rng)
        .unwrap();
    assert!(light.session.add_pending_removal(&leave).is_some());
    light.session.expire_epochs_through(world.ledger.epoch());
    assert_eq!(light.session.previous_epochs().count(), 0);
}

#[test]
fn light_join_data_is_checked() {
    let (mut world, mut alice) = World::create(61);
    let admission = world.admission_by_invite(&alice, 62);
    let request = world.request(62, &admission).unwrap();
    let other_secrets = crate::join::JoinSecrets::generate(&mut world.rng);
    world.commit(&mut alice).unwrap();
    let JoinStatus::Committed { epoch, welcome } = world.ledger.join_status(&request.reference)
    else {
        panic!("committed");
    };
    let encoded = world
        .ledger
        .light_join(&request.reference)
        .unwrap()
        .unwrap();
    let join = LightJoin::decode(&encoded).unwrap();
    assert_eq!(join.encode().unwrap(), encoded);
    let published = &world.log[epoch as usize];
    let enter = |join: &LightJoin, secrets: &crate::join::JoinSecrets| {
        LightSession::join_with_welcome(
            &request.identity,
            secrets,
            &published.commit,
            &published.group_info,
            &welcome,
            join,
        )
    };
    assert!(enter(&join, &request.secrets).is_ok());
    assert!(
        enter(&join, &other_secrets).is_err(),
        "another request's keys"
    );
    let mut wrong = join.clone();
    wrong.members.pop();
    assert!(enter(&wrong, &request.secrets).is_err());
    let mut wrong = join.clone();
    wrong.members.push(MemberRef { leaf: 7, since: 99 });
    assert!(enter(&wrong, &request.secrets).is_err());
    let mut wrong = join.clone();
    wrong.joiner_proof = world.ledger.state().tree.leaf_proof(0).unwrap();
    assert!(enter(&wrong, &request.secrets).is_err());
    let mut wrong = join.clone();
    wrong.registry.grant_admin(1).unwrap();
    assert!(enter(&wrong, &request.secrets).is_err());
    assert!(
        LightSession::join_with_welcome(
            &request.identity,
            &request.secrets,
            &published.commit,
            &world.log[0].group_info,
            &welcome,
            &join,
        )
        .is_err()
    );
    assert!(LightJoin::decode(&[0x80]).is_err());

    // Once the group moved on, a light joiner resyncs instead.
    let mut joined = world.welcome(&request).unwrap();
    world.commit(&mut joined).unwrap();
    assert_eq!(world.ledger.light_join(&request.reference).unwrap(), None);
    assert_eq!(world.ledger.light_join(&[0; 32]).unwrap(), None);
}

#[test]
fn full_and_light_members_share_commits_in_a_larger_group() {
    let (mut world, mut alice) = World::create_with_capacity(71, 32);
    // Twenty members join in batches; every other one goes light.
    let mut full = Vec::new();
    let mut light = Vec::new();
    for batch in 0..4u8 {
        let requests: Vec<Joiner> = (0..5u8)
            .map(|index| {
                let seed = 72 + batch * 5 + index;
                let admission = world.admission_by_admin(&alice, seed);
                world.request(seed, &admission).unwrap()
            })
            .collect();
        world.commit(&mut alice).unwrap();
        for member in &mut full {
            world.sync(member);
        }
        for member in &mut light {
            sync_light(&world, member);
        }
        for (index, request) in requests.iter().enumerate() {
            if index % 2 == 0 {
                full.push(world.welcome(request).unwrap());
            } else {
                light.push(light_welcome(&world, request).unwrap());
            }
        }
    }
    // Members of both kinds leave and commit; everyone keeps agreeing.
    for round in 0..3 {
        let leaver = full.remove(round);
        let leave = leaver
            .session
            .propose_leave(&leaver.identity, &mut world.rng)
            .unwrap();
        world
            .ledger
            .submit_remove_proposal(leave.encoded())
            .unwrap();
        let committer = &mut full[round];
        world.sync(committer);
        world.commit(committer).unwrap();
        world.sync(&mut alice);
        for member in &mut full {
            world.sync(member);
        }
        for member in &mut light {
            sync_light(&world, member);
        }
        let context = world.ledger.state().group_context().unwrap();
        assert!(
            light
                .iter()
                .all(|member| member.session.group_context() == &context)
        );
    }
    let hello = world.send(&mut alice, b"to everyone");
    for member in &mut light {
        assert_eq!(
            light_decrypt(&world, member, &hello).plaintext,
            b"to everyone"
        );
    }
    let options = CommitOptions::default();
    assert!(options.removals.is_empty());
}
