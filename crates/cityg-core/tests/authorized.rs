//! The authorized mode of the v0.5 draft (docs/specs-v0.5-draft.md section
//! 4.9): the authorizer named by the group policy authorizes the joins of
//! each window in one signed batch, and may remove members.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use cityg_core::audit::{self, Verdict};
use cityg_core::authorizer::{Authorizer, SealedWindow, authorizer_pk_hash};
use cityg_core::card::{CardKey, LeafKeys};
use cityg_core::error::CoreError;
use cityg_core::identity::DeviceIdentity;
use cityg_core::kem::KemSecret;
use cityg_core::member::Joiner;
use cityg_core::objects::{AdmissionMode, JoinRequest, PolicyTerms, Request};
use cityg_core::tree::Occupancy;
use cityg_core::window::check_entry;
use common::Sim;

/// A group of three whose admin then names an authorizer in the policy,
/// which a window applies.
fn authorized_group(seed: u64) -> (Sim, Authorizer) {
    let mut sim = Sim::new(2, seed);
    sim.request_joins(2);
    sim.run_window();
    let authorizer = Authorizer::new(sim.ds.state().gid, DeviceIdentity::generate(&mut sim.rng));
    let policy = sim.members[&common::CREATOR]
        .group_policy(
            &PolicyTerms::authorized(authorizer.public_key().to_vec()),
            &mut sim.rng,
        )
        .unwrap();
    sim.ds.submit_policy(policy, sim.now).unwrap();
    sim.run_window();
    sim.assert_agreement();
    (sim, authorizer)
}

/// The authorizer authorizes every join that waits for the next window.
fn authorize_all(sim: &mut Sim, authorizer: &Authorizer) -> usize {
    let (epoch, joins) = sim.ds.awaiting_authorization();
    let authorized = authorizer.authorize(epoch, joins, &mut sim.rng).unwrap();
    sim.ds.submit_authorizations(authorized).unwrap()
}

/// A device's join request, with no admission.
fn bare_join(sim: &mut Sim) -> JoinRequest {
    let device = DeviceIdentity::generate(&mut sim.rng);
    let leaf = KemSecret::generate(&mut sim.rng).public_key();
    let card = CardKey::generate(&mut sim.rng).card();
    JoinRequest::sign(
        &sim.ds.state().gid,
        &device,
        LeafKeys {
            encryption_key: &leaf,
            card: &card,
        },
        &KemSecret::generate(&mut sim.rng).public_key(),
        sim.ds.epoch() + 50,
        None,
        &mut sim.rng,
    )
    .unwrap()
}

#[test]
fn an_authorized_group_admits_the_joins_its_authorizer_signs() {
    let (mut sim, authorizer) = authorized_group(101);
    let hash = authorizer_pk_hash(authorizer.public_key()).unwrap();
    let registry = sim.ds.state().registry.header().unwrap();
    assert_eq!(
        (registry.admission, registry.authorizer),
        (AdmissionMode::Authorized, Some(hash))
    );
    assert!(
        sim.members
            .values()
            .all(|member| member.header().registry.authorizer == Some(hash))
    );
    // Three devices ask to join without admission; the DS asks the
    // authorizer, which authorizes two of them for the next window.
    sim.request_open_joins(3);
    let (epoch, mut waiting) = sim.ds.awaiting_authorization();
    assert_eq!((epoch, waiting.len()), (sim.ds.epoch() + 1, 3));
    let later = waiting.pop().unwrap();
    let authorized = authorizer.authorize(epoch, waiting, &mut sim.rng).unwrap();
    assert_eq!(sim.ds.submit_authorizations(authorized).unwrap(), 2);
    let before = sim.members.len();
    sim.run_window();
    sim.assert_agreement();
    assert_eq!(sim.members.len(), before + 2);
    // The third still waits; a batch for a past window does not pass.
    let (next, waiting) = sim.ds.awaiting_authorization();
    assert_eq!(waiting, vec![later]);
    let stale = authorizer
        .authorize(next - 1, waiting, &mut sim.rng)
        .unwrap();
    assert_eq!(
        sim.ds.submit_authorizations(stale).unwrap_err(),
        CoreError::Invalid("authorization for another window")
    );
    assert_eq!(authorize_all(&mut sim, &authorizer), 1);
    sim.run_window();
    sim.assert_agreement();
    assert_eq!(sim.members.len(), before + 3);
}

#[test]
fn nobody_lets_in_a_join_its_authorizer_did_not_sign() {
    let (mut sim, authorizer) = authorized_group(102);
    let state = sim.ds.state().clone();
    let epoch = state.epoch + 1;
    // An admin's admission no longer lets a device in.
    let identity = DeviceIdentity::generate(&mut sim.rng);
    let admission = sim.members[&common::CREATOR]
        .admit(identity.public_key(), epoch + 10, &mut sim.rng)
        .unwrap();
    let admitted = cityg_core::member::Joiner::new(
        identity,
        Some(&admission),
        epoch + 10,
        sim.anchor(),
        &mut sim.rng,
    )
    .unwrap();
    assert_eq!(
        sim.ds
            .submit_join(admitted.request().clone(), sim.now)
            .unwrap_err(),
        CoreError::Invalid("an admission in an authorized group")
    );
    // Another key's batch is refused by the DS.
    let join = bare_join(&mut sim);
    sim.ds.submit_join(join.clone(), sim.now).unwrap();
    let posing = Authorizer::new(state.gid, DeviceIdentity::generate(&mut sim.rng));
    let forged = posing
        .authorize(epoch, vec![join.clone()], &mut sim.rng)
        .unwrap();
    assert_eq!(
        sim.ds.submit_authorizations(forged.clone()).unwrap_err(),
        CoreError::BadSignature("authorization batch")
    );
    // A committer that checks the entry refuses it without the authorizer's
    // batch, and an auditor finds the fraud in a commit that placed it.
    let blank = (0..u32::MAX)
        .find(|leaf| state.tree.leaf(*leaf).is_none())
        .unwrap();
    for request in [join.clone(), forged[0].clone()] {
        assert!(check_entry(&state, epoch, blank, &Request::Join(request), true).is_err());
    }
    let genuine = authorizer
        .authorize(epoch, vec![join.clone()], &mut sim.rng)
        .unwrap();
    check_entry(
        &state,
        epoch,
        blank,
        &Request::Join(genuine[0].clone()),
        true,
    )
    .unwrap();
    let previous = state.header().unwrap();
    let record = |request: JoinRequest| audit::AuditRecord {
        epoch,
        district: 0,
        committer: common::CREATOR,
        change: cityg_core::commit::Change {
            leaf: blank,
            kind: cityg_core::objects::ChangeKind::Join,
            request: request.reference(),
        },
        proofs: audit::EntryProofs {
            subject: None,
            device: Some(
                state
                    .registry
                    .device_proof(&request.device_id().unwrap())
                    .unwrap(),
            ),
            admission: Some(state.registry.admission_proof(&request.token()).unwrap()),
            policy: None,
            keys: [
                cityg_core::tree::leaf_key_hash(&request.encryption_key).unwrap(),
                request.card.hash().unwrap(),
            ]
            .iter()
            .map(|key| state.registry.key_proof(key).unwrap())
            .collect(),
            authorizer_pk: Some(authorizer.public_key().to_vec()),
        },
        request: Request::Join(request),
    };
    assert_eq!(
        audit::check_record(&previous, &record(forged[0].clone())).unwrap(),
        Verdict::Fraud("join request or admission")
    );
    assert_eq!(
        audit::check_record(&previous, &record(genuine[0].clone())).unwrap(),
        Verdict::Valid
    );
    // A record that names another authorizer proves nothing.
    let mut other = record(genuine[0].clone());
    other.proofs.authorizer_pk = Some(posing.public_key().to_vec());
    assert!(audit::check_record(&previous, &other).is_err());
}

#[test]
fn the_authorizer_removes_members_urgently() {
    let (mut sim, authorizer) = authorized_group(103);
    let target = *sim.members.keys().nth(2).unwrap();
    let removal = authorizer.remove_proposal(target, &mut sim.rng).unwrap();
    // The same removal under another key is refused.
    let posing = Authorizer::new(sim.ds.state().gid, DeviceIdentity::generate(&mut sim.rng));
    assert!(
        sim.ds
            .submit_removal(
                posing.remove_proposal(target, &mut sim.rng).unwrap(),
                sim.now
            )
            .is_err()
    );
    sim.ds.submit_removal(removal, sim.now).unwrap();
    assert!(sim.ds.pending_removals().iter().any(|pending| {
        pending.target == target && pending.urgency == cityg_core::objects::Urgency::Urgent
    }));
    sim.run_window();
    sim.assert_agreement();
    assert!(!sim.ds.state().tree.is_member(target));
    assert!(!sim.members.contains_key(&target));
}

#[test]
fn an_authorized_joiner_seals_the_window_when_nobody_is_online() {
    let (mut sim, authorizer) = authorized_group(104);
    sim.set_all_online(false);
    sim.request_open_joins(2);
    assert_eq!(authorize_all(&mut sim, &authorizer), 2);
    let task = sim.run_entrant_window();
    // The members that were offline check the entrant's authorization, with
    // the authorizer's key that its evidence carries, before they follow.
    sim.assert_agreement();
    assert_eq!(sim.members.len(), 5);
    let seal = &sim.ds.window(sim.ds.epoch()).unwrap().seal;
    assert!(seal.header.entrant.is_some());
    let entrant: Occupancy = task.sealer;
    assert!(sim.ds.state().tree.is_member(entrant));
}

/// The authorizer checks the window of `epoch` as the DS keeps it, and
/// signs its checkpoint, which the DS keeps.
fn checkpoint(sim: &mut Sim, authorizer: &mut Authorizer, epoch: u64) {
    let stored = sim.ds.window(epoch).unwrap().clone();
    let checkpoint = authorizer
        .checkpoint(
            &SealedWindow {
                commits: &stored.commits,
                city_tasks: &stored.city_tasks,
                seal: &stored.seal,
                requests: &stored.requests,
            },
            &mut sim.rng,
        )
        .unwrap();
    sim.ds.submit_authorizer_checkpoint(checkpoint).unwrap();
}

#[test]
fn the_authorizer_checkpoints_the_windows_it_checks() {
    let (mut sim, mut authorizer) = authorized_group(105);
    authorizer.follow_from(sim.ds.state().clone()).unwrap();
    sim.request_open_joins(2);
    authorize_all(&mut sim, &authorizer);
    let before = sim.ds.state().clone();
    sim.run_window();
    let epoch = sim.ds.epoch();
    // A window whose joins lost their authorizations does not pass the
    // authorizer's check: the commits bind the requests, not their proofs.
    let stored = sim.ds.window(epoch).unwrap().clone();
    let stripped: cityg_core::window::Requests = stored
        .requests
        .values()
        .cloned()
        .map(|request| match request {
            Request::Join(mut join) => {
                join.authorization = None;
                Request::Join(join)
            }
            other => other,
        })
        .collect();
    let unchecked = SealedWindow {
        commits: &stored.commits,
        city_tasks: &stored.city_tasks,
        seal: &stored.seal,
        requests: &stripped,
    };
    assert_eq!(
        authorizer.checkpoint(&unchecked, &mut sim.rng).unwrap_err(),
        CoreError::Unauthorized("join without authorization")
    );
    assert_eq!(authorizer.epoch(), Some(epoch - 1));
    checkpoint(&mut sim, &mut authorizer, epoch);
    assert_eq!(authorizer.epoch(), Some(epoch));
    // It signs one checkpoint per epoch.
    let again = SealedWindow {
        requests: &stored.requests,
        ..unchecked
    };
    assert!(authorizer.checkpoint(&again, &mut sim.rng).is_err());
    // The DS keeps it; one moved to another epoch is refused.
    let signed = sim.ds.authorizer_checkpoint(epoch).unwrap().clone();
    assert_eq!(signed.tag, stored.seal.tag);
    let mut moved = signed;
    moved.epoch -= 1;
    assert!(sim.ds.submit_authorizer_checkpoint(moved).is_err());
    assert!(sim.ds.checkpointed_epoch(epoch - 1).is_err());
    // A key the group does not name signs nothing.
    let mut posing = Authorizer::new(before.gid, DeviceIdentity::generate(&mut sim.rng));
    posing.follow_from(before).unwrap();
    assert_eq!(
        posing.checkpoint(&again, &mut sim.rng).unwrap_err(),
        CoreError::Unauthorized("the group names another authorizer")
    );
}

#[test]
fn a_member_that_requires_checkpoints_waits_for_the_authorizers() {
    let (mut sim, mut authorizer) = authorized_group(106);
    authorizer.follow_from(sim.ds.state().clone()).unwrap();
    let careful = *sim.members.keys().nth(1).unwrap();
    let key = authorizer.public_key().to_vec();
    let posing = DeviceIdentity::generate(&mut sim.rng);
    assert!(
        sim.members
            .get_mut(&careful)
            .unwrap()
            .require_checkpoints(posing.public_key().to_vec())
            .is_err()
    );
    sim.members
        .get_mut(&careful)
        .unwrap()
        .require_checkpoints(key)
        .unwrap();
    // The simulation leaves it be; it follows by hand.
    sim.absent.insert(careful);
    sim.request_open_joins(1);
    authorize_all(&mut sim, &authorizer);
    sim.run_window();
    let epoch = sim.ds.epoch();
    let packet = sim.ds.packet(epoch, careful).unwrap();
    let member = sim.members.get_mut(&careful).unwrap();
    assert_eq!(
        member.process(&packet).unwrap_err(),
        CoreError::Invalid("the authorizer's checkpoint is required")
    );
    checkpoint(&mut sim, &mut authorizer, epoch);
    let signed = sim.ds.authorizer_checkpoint(epoch).unwrap().clone();
    let member = sim.members.get_mut(&careful).unwrap();
    // A checkpoint of the epoch before does not do.
    let mut stale = signed.clone();
    stale.epoch -= 1;
    assert!(member.process_checkpointed(&packet, &stale).is_err());
    member.process_checkpointed(&packet, &signed).unwrap();
    sim.absent.remove(&careful);
    sim.assert_agreement();
}

#[test]
fn a_joiner_enters_with_the_authorizers_checkpoint_instead_of_seals() {
    let (mut sim, mut authorizer) = authorized_group(107);
    sim.set_joiner_tasks(false);
    authorizer.follow_from(sim.ds.state().clone()).unwrap();
    // A joiner anchored at the current epoch, which several windows will
    // pass before its own.
    let anchor = sim.anchor();
    let mut joiner = Joiner::new(
        DeviceIdentity::generate(&mut sim.rng),
        None,
        sim.ds.epoch() + 50,
        anchor,
        &mut sim.rng,
    )
    .unwrap();
    for _ in 0..3 {
        sim.request_open_joins(1);
        authorize_all(&mut sim, &authorizer);
        sim.run_window();
        let epoch = sim.ds.epoch();
        checkpoint(&mut sim, &mut authorizer, epoch);
    }
    let reference = sim
        .ds
        .submit_join(joiner.request().clone(), sim.now)
        .unwrap();
    authorize_all(&mut sim, &authorizer);
    sim.run_window();
    let epoch = sim.ds.epoch();
    checkpoint(&mut sim, &mut authorizer, epoch);
    // Its entry carries the checkpoint of its epoch, not the four seals
    // since its anchor.
    let entry = sim.ds.checkpointed_entry(&reference).unwrap();
    assert!(entry.links.is_empty());
    let chained = sim.ds.entry(&reference, joiner.anchor().epoch).unwrap();
    assert_eq!(chained.links.len(), 4);
    assert!(entry.encoded_len() < chained.encoded_len());
    // Only a joiner that trusts the authorizer's key takes it.
    assert!(joiner.check_entry(&entry).is_err());
    joiner.trust_authorizer(DeviceIdentity::generate(&mut sim.rng).public_key().to_vec());
    assert!(joiner.check_entry(&entry).is_err());
    joiner.trust_authorizer(authorizer.public_key().to_vec());
    let member = joiner.enter(&entry).unwrap();
    assert_eq!(member.epoch(), epoch);
    assert_eq!(
        member.epoch_authenticator(),
        sim.member(common::CREATOR).epoch_authenticator()
    );
    assert!(member.previous_header().is_none());
    sim.ds.set_online(member.occupancy(), true);
    sim.members.insert(member.occupancy(), member);
    sim.request_open_joins(1);
    authorize_all(&mut sim, &authorizer);
    sim.run_window();
    sim.assert_agreement();
}
