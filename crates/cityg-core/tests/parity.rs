//! Stage 3 of the v0.5 draft (docs/specs-v0.5-draft.md section 4): cards in
//! leaves, hashed by their summary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use cityg_core::card::{CARD_ML_DSA_65, Card};
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
