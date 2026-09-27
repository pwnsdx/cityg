//! The authorized mode of the v0.5 draft (docs/specs-v0.5-draft.md section
//! 4.9): the authorizer named by the group policy authorizes the joins of
//! each window in one signed batch, and may remove members.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use cityg_core::audit::{self, Verdict};
use cityg_core::authorizer::{Authorizer, authorizer_pk_hash};
use cityg_core::card::{CardKey, LeafKeys};
use cityg_core::error::CoreError;
use cityg_core::identity::DeviceIdentity;
use cityg_core::kem::KemSecret;
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
