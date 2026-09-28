//! Stage 3 of the v0.5 draft (docs/specs-v0.5-draft.md section 4): cards in
//! leaves, hashed by their summary, unique keys, and the membership log.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use cityg_core::audit::{AuditRecord, EntryProofs, Verdict, check_record};
use cityg_core::card::{CARD_ML_DSA_65, Card, CardKey, LeafKeys};
use cityg_core::commit::Change;
use cityg_core::error::CoreError;
use cityg_core::identity::DeviceIdentity;
use cityg_core::kem::KemSecret;
use cityg_core::objects::{ChangeKind, JoinRequest, Request, UpdateRequest};
use cityg_core::tree::leaf_key_hash;
use cityg_core::window::{Requests, WindowShape, check_entry, needed_height, registry_delta};
use common::Sim;

#[test]
fn a_leaf_holds_its_members_card_which_changes_with_the_leaf_key() {
    let mut sim = Sim::new(2, 81);
    sim.request_joins(3);
    sim.run_window();
    sim.assert_agreement();
    // Every leaf holds its member's card, joiners' included.
    for (occupancy, member) in &sim.members {
        let leaf = sim.ds.state().tree.member(*occupancy).unwrap();
        assert_eq!(leaf.card, member.card());
        assert_eq!(leaf.card.algorithm, CARD_ML_DSA_65);
    }
    // An update brings a fresh card with the new leaf key.
    let member = *sim.members.keys().nth(1).unwrap();
    let before = sim.member(member).card();
    let request = sim
        .members
        .get_mut(&member)
        .unwrap()
        .update_request(&mut sim.rng)
        .unwrap();
    assert_ne!(request.card, before);
    assert_eq!(
        sim.member(member).card(),
        before,
        "until the window applies it"
    );
    sim.ds.submit_update(request.clone(), sim.now).unwrap();
    sim.run_window();
    sim.assert_agreement();
    let after = sim.member(member).card();
    assert_eq!(after, request.card);
    let leaf = sim.ds.state().tree.member(member).unwrap();
    assert_eq!(leaf.card, after);
    assert_eq!(leaf.updated, sim.ds.epoch());
}

#[test]
fn a_leaf_hash_takes_the_summary_of_the_leaf() {
    let mut sim = Sim::new(2, 82);
    sim.request_joins(1);
    sim.run_window();
    let state = sim.ds.state();
    let (index, leaf) = state.tree.leaves().next().unwrap();
    let proof = state.tree.leaf_proof(index).unwrap();
    proof.verify(&state.tree.tree_hash().unwrap()).unwrap();
    // The summary names the device and the leaf key by their hashes.
    let summary = leaf.summary().unwrap();
    let encoded = cityg_core::cbor::encode(&summary).unwrap();
    assert!(encoded.len() < cityg_core::cbor::encode(&leaf.value()).unwrap().len());
    // Another card, or another leaf key, is another leaf.
    let mut other = leaf.clone();
    other.card = Card {
        algorithm: CARD_ML_DSA_65,
        public_key: vec![9; leaf.card.public_key.len()],
    };
    let mut forged = proof.clone();
    forged.leaf = Some(other);
    assert!(forged.verify(&state.tree.tree_hash().unwrap()).is_err());
    let mut other = leaf.clone();
    other.encryption_key[0] ^= 1;
    let mut forged = proof;
    forged.leaf = Some(other);
    assert!(forged.verify(&state.tree.tree_hash().unwrap()).is_err());
}

#[test]
fn no_leaf_key_or_card_is_set_twice() {
    let mut sim = Sim::with_policy(2, 83, true);
    sim.request_open_joins(2);
    sim.run_window();
    sim.assert_agreement();
    let state = sim.ds.state().clone();
    let (gid, epoch) = (state.gid, state.epoch + 1);
    let join = |sim: &mut Sim, leaf_key: &[u8], card: &Card| {
        let device = DeviceIdentity::generate(&mut sim.rng);
        JoinRequest::sign(
            &gid,
            &device,
            LeafKeys {
                encryption_key: leaf_key,
                card,
            },
            &KemSecret::generate(&mut sim.rng).public_key(),
            epoch + 10,
            None,
            &mut sim.rng,
        )
        .unwrap()
    };
    let fresh_key = |sim: &mut Sim| KemSecret::generate(&mut sim.rng).public_key();
    let fresh_card = |sim: &mut Sim| CardKey::generate(&mut sim.rng).card();
    // A join that copies a member's card, or its leaf key, is refused.
    let creator = state.tree.member(common::CREATOR).unwrap().clone();
    let key = fresh_key(&mut sim);
    let copied = join(&mut sim, &key, &creator.card);
    let in_use = CoreError::Invalid("a leaf key or card already in use");
    assert_eq!(
        sim.ds.submit_join(copied.clone(), sim.now).unwrap_err(),
        in_use
    );
    // So does a committer that checks it as an entry of its district.
    let blank = (0..u32::MAX)
        .find(|leaf| state.tree.leaf(*leaf).is_none())
        .unwrap();
    assert_eq!(
        check_entry(&state, epoch, blank, &Request::Join(copied), true).unwrap_err(),
        in_use
    );
    let card = fresh_card(&mut sim);
    let copied = join(&mut sim, &creator.encryption_key, &card);
    assert_eq!(sim.ds.submit_join(copied, sim.now).unwrap_err(), in_use);
    // An update must bring a card of its own too.
    let key = fresh_key(&mut sim);
    let identity = sim.member(common::CREATOR).identity().clone();
    let stale = UpdateRequest::sign(
        &gid,
        common::CREATOR,
        &creator.encryption_key,
        LeafKeys {
            encryption_key: &key,
            card: &creator.card,
        },
        &identity,
        &mut sim.rng,
    )
    .unwrap();
    assert_eq!(
        sim.ds.submit_update(stale.clone(), sim.now).unwrap_err(),
        in_use
    );
    assert_eq!(
        check_entry(
            &state,
            epoch,
            common::CREATOR.leaf,
            &Request::Update(stale),
            true
        )
        .unwrap_err(),
        in_use
    );
    // Two queued requests with one card: the second is refused.
    let shared = fresh_card(&mut sim);
    let (key_a, key_b) = (fresh_key(&mut sim), fresh_key(&mut sim));
    let first = join(&mut sim, &key_a, &shared);
    let second = join(&mut sim, &key_b, &shared);
    sim.ds.submit_join(first.clone(), sim.now).unwrap();
    assert_eq!(
        sim.ds.submit_join(second.clone(), sim.now).unwrap_err(),
        CoreError::Invalid("a leaf key or card already queued")
    );
    // Whoever builds it, a window that sets one card twice is refused.
    let blank: Vec<u32> = (0..u32::MAX)
        .filter(|leaf| state.tree.leaf(*leaf).is_none())
        .take(2)
        .collect();
    let changes: Vec<Change> = blank
        .iter()
        .zip([&first, &second])
        .map(|(leaf, request)| Change {
            leaf: *leaf,
            kind: ChangeKind::Join,
            request: request.reference(),
        })
        .collect();
    let requests: Requests = [Request::Join(first), Request::Join(second)]
        .into_iter()
        .collect();
    let height = needed_height(state.tree.height(), blank.iter().max().copied());
    let shape = state.tree.shape().grown(height).unwrap();
    let window = WindowShape::new(&state.tree, epoch, shape, changes.iter().copied()).unwrap();
    assert_eq!(
        registry_delta(
            &state,
            &window,
            &requests,
            None,
            common::CREATOR,
            &creator.device_pk
        )
        .unwrap_err(),
        CoreError::Invalid("a leaf key or card already in use")
    );
    // Every leaf key and card of the tree is in the registry's map.
    for (leaf, node) in state.tree.leaves() {
        let occupancy = node.occupancy(leaf);
        assert_eq!(
            state.registry.key(&node.key_hash().unwrap()),
            Some(occupancy)
        );
        assert_eq!(
            state.registry.key(&node.card.hash().unwrap()),
            Some(occupancy)
        );
    }
}

#[test]
fn an_audit_finds_a_leaf_key_or_card_already_in_use() {
    let mut sim = Sim::with_policy(2, 84, true);
    sim.request_open_joins(2);
    sim.run_window();
    let state = sim.ds.state().clone();
    let previous = state.header().unwrap();
    let (gid, epoch) = (state.gid, state.epoch + 1);
    let creator = state.tree.member(common::CREATOR).unwrap().clone();
    let key_proofs = |encryption_key: &[u8], card: &Card| {
        vec![
            state
                .registry
                .key_proof(&leaf_key_hash(encryption_key).unwrap())
                .unwrap(),
            state.registry.key_proof(&card.hash().unwrap()).unwrap(),
        ]
    };
    let blank = (0..u32::MAX)
        .find(|leaf| state.tree.leaf(*leaf).is_none())
        .unwrap();
    let record = |change: Change, request: Request, proofs: EntryProofs| AuditRecord {
        epoch,
        district: 0,
        committer: common::CREATOR,
        change,
        request,
        proofs,
    };
    let join_record = |join: JoinRequest| {
        let proofs = EntryProofs {
            subject: None,
            device: Some(
                state
                    .registry
                    .device_proof(&join.device_id().unwrap())
                    .unwrap(),
            ),
            admission: Some(state.registry.admission_proof(&join.token()).unwrap()),
            policy: None,
            authorizer_pk: None,
            keys: key_proofs(&join.encryption_key, &join.card),
        };
        let change = Change {
            leaf: blank,
            kind: ChangeKind::Join,
            request: Request::Join(join.clone()).reference(),
        };
        record(change, Request::Join(join), proofs)
    };
    let join = |sim: &mut Sim, card: &Card| {
        let device = DeviceIdentity::generate(&mut sim.rng);
        let leaf_key = KemSecret::generate(&mut sim.rng).public_key();
        JoinRequest::sign(
            &gid,
            &device,
            LeafKeys {
                encryption_key: &leaf_key,
                card,
            },
            &KemSecret::generate(&mut sim.rng).public_key(),
            epoch + 10,
            None,
            &mut sim.rng,
        )
        .unwrap()
    };
    // A join with a card of its own is valid; one with the creator's is a
    // fraud, which the proof of the card's presence shows.
    let card = CardKey::generate(&mut sim.rng).card();
    let honest = join_record(join(&mut sim, &card));
    assert_eq!(check_record(&previous, &honest).unwrap(), Verdict::Valid);
    let copied = join_record(join(&mut sim, &creator.card));
    assert_eq!(
        check_record(&previous, &copied).unwrap(),
        Verdict::Fraud("a leaf key or card already in use")
    );
    // Without the proofs nothing follows; proofs taken for other keys fail,
    // or still show the card (the map's root binds every key's value).
    let mut bare = copied.clone();
    bare.proofs.keys.clear();
    assert!(check_record(&previous, &bare).is_err());
    let mut swapped = copied.clone();
    swapped.proofs.keys.swap(0, 1);
    let mut other = copied;
    let absent = CardKey::generate(&mut sim.rng).card();
    other.proofs.keys[1] = state.registry.key_proof(&absent.hash().unwrap()).unwrap();
    for forged in [swapped, other] {
        assert_ne!(check_record(&previous, &forged).ok(), Some(Verdict::Valid));
    }
    // An update that keeps its card is a fraud too.
    let key = KemSecret::generate(&mut sim.rng).public_key();
    let identity = sim.member(common::CREATOR).identity().clone();
    let stale = UpdateRequest::sign(
        &gid,
        common::CREATOR,
        &creator.encryption_key,
        LeafKeys {
            encryption_key: &key,
            card: &creator.card,
        },
        &identity,
        &mut sim.rng,
    )
    .unwrap();
    let proofs = EntryProofs {
        subject: Some(state.tree.leaf_proof(common::CREATOR.leaf).unwrap()),
        device: None,
        admission: None,
        policy: None,
        keys: key_proofs(&stale.encryption_key, &stale.card),
        authorizer_pk: None,
    };
    let request = Request::Update(stale);
    let change = Change {
        leaf: common::CREATOR.leaf,
        kind: ChangeKind::Update,
        request: request.reference(),
    };
    assert_eq!(
        check_record(&previous, &record(change, request, proofs)).unwrap(),
        Verdict::Fraud("a leaf key or card already in use")
    );
}

#[test]
fn members_check_the_changes_of_a_window_against_its_log() {
    use cityg_core::commit::Seal;
    use cityg_core::membership::{MembershipLog, genesis};
    use cityg_core::objects::Urgency;
    use cityg_core::tree::Occupancy;

    let mut sim = Sim::new(2, 85);
    // The genesis seal logs the creator's join.
    let creator = sim.member(common::CREATOR);
    let first = genesis(
        creator.gid(),
        creator.identity().public_key(),
        &creator.card(),
    )
    .unwrap();
    creator.membership_log().check(&first).unwrap();
    sim.request_joins(3);
    sim.run_window();
    // A window with a removal, an update and a join.
    let members: Vec<Occupancy> = sim.members.keys().copied().collect();
    let (removed, updater) = (members[1], members[2]);
    let old_leaf = sim.ds.state().tree.member(removed).unwrap().clone();
    let removal = sim.members[&common::CREATOR]
        .remove_proposal(removed, Urgency::Urgent, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(removal, sim.now).unwrap();
    let update = sim
        .members
        .get_mut(&updater)
        .unwrap()
        .update_request(&mut sim.rng)
        .unwrap();
    sim.ds.submit_update(update.clone(), sim.now).unwrap();
    sim.request_joins(1);
    sim.run_window();
    let epoch = sim.ds.epoch();
    let records = sim.ds.membership_records(epoch).unwrap().to_vec();
    // One record per change, in change order: the leaving device and card,
    // the updated card, the joining device.
    assert_eq!(records.len(), 3);
    let removal = records
        .iter()
        .find(|record| record.kind == ChangeKind::Removal)
        .unwrap();
    assert_eq!(
        (removal.leaf, removal.device_id),
        (removed.leaf, old_leaf.device_id)
    );
    assert!(removal.names_card(&old_leaf.card).unwrap());
    let updated = records
        .iter()
        .find(|record| record.kind == ChangeKind::Update)
        .unwrap();
    assert_eq!(updated.leaf, updater.leaf);
    assert!(updated.names_card(&update.card).unwrap());
    assert_eq!(sim.member(updater).card(), update.card);
    let joined = records
        .iter()
        .find(|record| record.kind == ChangeKind::Join)
        .unwrap();
    let newcomer = sim.ds.state().tree.leaf(joined.leaf).unwrap();
    assert_eq!(joined.device_id, newcomer.device_id);
    let leaves: Vec<u32> = records.iter().map(|record| record.leaf).collect();
    assert!(leaves.windows(2).all(|pair| pair[0] <= pair[1]));
    // Every member checks them against the log of its seal header; a record
    // changed or left out does not pass.
    for member in sim.members.values() {
        member.membership_log().check(&records).unwrap();
    }
    let log: MembershipLog = sim.member(common::CREATOR).membership_log();
    let mut altered = records.clone();
    altered[0].leaf += 1;
    assert!(log.check(&altered).is_err());
    assert!(log.check(&records[1..]).is_err());
    // One record, with its proof.
    let proof = sim.ds.membership_proof(epoch, 1).unwrap();
    log.verify_inclusion(1, &records[1], &proof).unwrap();
    assert!(log.verify_inclusion(1, &records[0], &proof).is_err());
    // A seal whose log differs from the window's changes is refused.
    sim.request_joins(1);
    let task = sim.open_window();
    sim.commit_open(&task);
    let seal = sim.seal_open(&task);
    let mut header = seal.header.clone();
    header.membership_log.count += 1;
    let forged = Seal::sign(
        header,
        seal.body.clone(),
        seal.tag,
        seal.external_pk.clone(),
        sim.members[&task.sealer].identity(),
        &mut sim.rng,
    )
    .unwrap();
    assert_eq!(
        sim.ds.submit_seal(forged).unwrap_err(),
        CoreError::Invalid("seal membership log")
    );
    let epoch = sim.ds.submit_seal(seal).unwrap();
    sim.follow(epoch);
    sim.welcome_and_enter(epoch);
    sim.assert_agreement();
}
