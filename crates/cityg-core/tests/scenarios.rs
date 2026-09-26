//! Scenarios of profile v0.4-draft on the in-memory delivery service, with
//! districts of four leaves (L = 2).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::Sim;

#[test]
fn a_group_grows_over_several_districts() {
    let mut sim = Sim::new(2, 1);
    sim.request_joins(1);
    sim.run_window();
    assert_eq!(sim.members.len(), 2);
    sim.assert_agreement();
    sim.request_joins(5);
    let task = sim.run_window();
    assert_eq!(task.height, 3);
    assert_eq!(sim.members.len(), 7);
    sim.assert_agreement();
    sim.request_joins(9);
    let task = sim.run_window();
    assert_eq!(task.height, 4);
    assert!(task.committers.len() >= 2, "several districts committed");
    assert_eq!(sim.members.len(), 16);
    sim.assert_agreement();
    assert_eq!(sim.ds.state().tree.member_count(), 16);
}

#[test]
fn a_joiner_seals_the_window_when_nobody_is_online() {
    let mut sim = Sim::new(2, 2);
    sim.request_joins(3);
    sim.run_window();
    sim.set_all_online(false);
    sim.request_joins(2);
    let task = sim.run_entrant_window();
    // The entrant committed every district and welcomed the other joiner.
    assert!(
        task.committers
            .values()
            .all(|committer| *committer == task.sealer)
    );
    assert_eq!(task.welcomes.len(), 1);
    assert_eq!(sim.members.len(), 6);
    // The members that were offline follow it later with the external key,
    // after checking the entrant's admission.
    sim.assert_agreement();
    let seal = &sim.ds.window(sim.ds.epoch()).unwrap().seal;
    assert!(seal.header.entrant.is_some());
    // The next window is sealed by members again.
    sim.set_all_online(true);
    sim.request_joins(1);
    sim.run_window();
    sim.assert_agreement();
}

#[test]
fn a_removal_waits_for_the_first_participant_and_is_enforced_meanwhile() {
    let mut sim = Sim::new(2, 3);
    sim.request_joins(4);
    sim.run_window();
    sim.set_all_online(false);
    let target = *sim.members.keys().nth(2).unwrap();
    let proposal = sim.members[&common::CREATOR]
        .remove_proposal(target, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(proposal, sim.now).unwrap();
    let epoch = sim.ds.epoch();
    // Nobody online and no entrant: the window stays open, the removal is
    // enforced at delivery.
    sim.now += 10_000;
    assert!(sim.ds.due(sim.now));
    assert!(sim.ds.open_window(sim.now).unwrap().is_none());
    assert!(!sim.ds.accepts_from(target));
    assert!(sim.ds.packet(epoch, target).is_err());
    // A member coming online does not send while the removal waits.
    let pending = sim.ds.pending_removals();
    let window_removal = sim.ds.config().window_removal_ms;
    assert!(
        !sim.member(common::CREATOR)
            .may_send(&pending, sim.now, window_removal)
    );
    // It applies the removal first.
    sim.ds.set_online(common::CREATOR, true);
    sim.run_window();
    assert!(!sim.members.contains_key(&target));
    assert!(!sim.ds.state().tree.is_member(target));
    sim.assert_agreement();
    assert!(sim.member(common::CREATOR).may_send(
        &sim.ds.pending_removals(),
        sim.now,
        window_removal
    ));
}

#[test]
fn a_joiner_applies_a_pending_removal_when_nobody_is_online() {
    let mut sim = Sim::new(2, 4);
    sim.request_joins(4);
    sim.run_window();
    sim.set_all_online(false);
    let target = *sim.members.keys().nth(3).unwrap();
    let proposal = sim.members[&common::CREATOR]
        .remove_proposal(target, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(proposal, sim.now).unwrap();
    sim.request_joins(1);
    let task = sim.run_entrant_window();
    // The joiner took the removed member's leaf.
    assert!(
        task.changes
            .iter()
            .any(|c| c.leaf == target.leaf && c.kind == cityg_core::objects::ChangeKind::Join)
    );
    assert!(!sim.members.contains_key(&target));
    assert!(!sim.ds.state().tree.is_member(target));
    sim.assert_agreement();
}

mod forged {
    use cityg_core::commit::{Change, DistrictCommit, DistrictCommitContent, EntrantInit};
    use cityg_core::crypto::kem_pk_hash;
    use cityg_core::error::CoreError;
    use cityg_core::identity::DeviceIdentity;
    use cityg_core::kem::KemSecret;
    use cityg_core::objects::{Admission, ChangeKind, JoinRequest, Request, device_id};
    use cityg_core::packet::{EntrantEvidence, EntrantProof, Packet, RegistryUpdate};
    use cityg_core::rekey::{KeySource, WindowIndex, generate, plan_district};
    use cityg_core::roles::{SealDraft, build_city, finish_seal, with_city};
    use cityg_core::schedule::external_init;
    use cityg_core::tree::{Occupancy, Overlay, TreeDelta};
    use cityg_core::window::{
        PublicState, Requests, SealerInfo, WindowShape, check_districts, check_window,
        district_leaves, district_roots, keyed_parents, needed_height, prev_district_hash,
    };
    use rand_chacha::ChaCha20Rng;

    /// A window the delivery service seals itself, posing as an entrant with
    /// an admission it signed: it knows the external key, so it can compute
    /// every secret of the window and a correct confirmation tag.
    pub struct Forged {
        pub state: PublicState,
        pub commits: Vec<DistrictCommit>,
        pub seal: cityg_core::commit::Seal,
        pub requests: Requests,
        pub evidence: EntrantEvidence,
        pub index: WindowIndex,
        pub registry: cityg_core::registry::RegistryHeader,
        /// The device the forger joined, and the epoch's message secret, which
        /// it knows.
        pub forger: DeviceIdentity,
        pub msg_secret: [u8; 32],
    }

    /// A district commit whose committer skipped the entry checks.
    #[allow(clippy::too_many_arguments)]
    pub fn unchecked_commit(
        state: &PublicState,
        window: &WindowShape,
        district: u32,
        requests: &Requests,
        committer: Occupancy,
        identity: &DeviceIdentity,
        hedge: &[u8; 32],
        rng: &mut ChaCha20Rng,
    ) -> (DistrictCommit, cityg_core::rekey::Rekeyed) {
        let shape = window.shape;
        let leaves = district_leaves(state, window, district, requests, false).unwrap();
        let plan = plan_district(
            &state.tree,
            shape,
            district,
            &leaves,
            &window.forced(district),
        )
        .unwrap();
        let keys = KeySource {
            tree: &state.tree,
            shape,
            leaves: &leaves,
            roots: None,
        };
        let drawn = generate(&plan, &keys, &state.gid, window.epoch, hedge, rng).unwrap();
        let delta = TreeDelta {
            leaves: leaves.clone(),
            parents: keyed_parents(&drawn.updates, committer),
        };
        let district_hash = Overlay::new(&state.tree, shape, &delta)
            .unwrap()
            .district_hash(district)
            .unwrap();
        let commit = DistrictCommit::sign(
            DistrictCommitContent {
                gid: state.gid,
                epoch: window.epoch,
                district,
                height: shape.height,
                prev_district_hash: prev_district_hash(state, shape, district).unwrap(),
                committer,
                changes: window.district_changes(district).to_vec(),
                updates: drawn.updates.clone(),
                wraps: drawn.wraps.clone(),
                district_hash,
            },
            identity,
            rng,
        )
        .unwrap();
        (commit, drawn)
    }

    /// `with_admission`: the forger signs an admission itself, claiming to
    /// be the creator; otherwise its request carries none (as in an open
    /// group).
    pub fn forge(state: &PublicState, with_admission: bool, rng: &mut ChaCha20Rng) -> Forged {
        let forger = DeviceIdentity::generate(rng);
        let epoch = state.epoch + 1;
        let id = device_id(&state.gid, forger.public_key()).unwrap();
        let creator = Occupancy { leaf: 0, since: 0 };
        let admission = with_admission.then(|| {
            Admission::by_admin(&state.gid, &id, epoch + 10, creator, &forger, rng).unwrap()
        });
        let leaf_key = KemSecret::generate(rng);
        let init_key = KemSecret::generate(rng);
        let join = JoinRequest::sign(
            &state.gid,
            &forger,
            &leaf_key.public_key(),
            &init_key.public_key(),
            epoch + 10,
            admission.as_ref(),
            rng,
        )
        .unwrap();
        let reference = join.reference();
        let leaf = (0..).find(|leaf| state.tree.leaf(*leaf).is_none()).unwrap();
        let changes = [Change {
            leaf,
            kind: ChangeKind::Join,
            request: reference,
        }];
        let shape = state
            .tree
            .shape()
            .grown(needed_height(state.tree.height(), Some(leaf)))
            .unwrap();
        let window = WindowShape::new(&state.tree, epoch, shape, changes.iter().copied()).unwrap();
        let requests: Requests = [(reference, Request::Join(join.clone()))].into();
        let occupancy = Occupancy { leaf, since: epoch };
        let (kem_output, init_prev) = external_init(&state.external_pk, rng).unwrap();
        let mut commits = Vec::new();
        let mut path = std::collections::BTreeMap::new();
        for district in &window.districts {
            let (commit, drawn) = unchecked_commit(
                state, &window, *district, &requests, occupancy, &forger, &init_prev, rng,
            );
            path.extend(drawn.path_secrets(leaf));
            commits.push(commit);
        }
        let sealer = SealerInfo {
            occupancy,
            device_pk: forger.public_key().to_vec(),
            entrant: true,
        };
        let delta = check_districts(state, &window, &commits, &requests, &sealer, false).unwrap();
        let roots = district_roots(shape, &commits).unwrap();
        let city = build_city(state, &window, &roots, &init_prev, rng).unwrap();
        path.extend(city.path_secrets(leaf));
        let root_secret = path[&shape.height].clone();
        let sealed = finish_seal(
            SealDraft {
                state,
                window: &window,
                commits: &commits,
                requests: &requests,
                sealer: &sealer,
                entrant: Some(EntrantInit {
                    kem_output,
                    request: reference,
                }),
                delta: with_city(delta, &city, occupancy),
                city: &city,
                policy: None,
                time_ms: state.time_ms + 1,
                init_prev: &init_prev,
                root_secret: &root_secret,
            },
            &forger,
            rng,
        )
        .unwrap();
        let mut index = WindowIndex::default();
        for commit in &commits {
            index.add(&commit.updates, &commit.wraps);
        }
        index.add(&sealed.seal.body.city_updates, &sealed.seal.body.city_wraps);
        let evidence = EntrantEvidence::Join {
            device: state.registry.device_proof(&id).unwrap(),
            admission: state.registry.admission_proof(&join.token()).unwrap(),
            request: Box::new(join),
        };
        Forged {
            state: state.clone(),
            commits,
            msg_secret: *sealed.secrets.msg_secret(),
            seal: sealed.seal,
            requests,
            evidence,
            index,
            registry: sealed.header.registry,
            forger,
        }
    }

    impl Forged {
        pub fn packet(&self, leaf: u32, leaf_pk: &[u8]) -> Packet {
            Packet {
                header: self.seal.header.clone(),
                tag: self.seal.tag,
                entrant: Some(EntrantProof {
                    signature: self.seal.signature.clone(),
                    evidence: self.evidence.clone(),
                }),
                registry: RegistryUpdate::between(
                    &self.state.registry.header().unwrap(),
                    &self.registry,
                    None,
                ),
                leaf_key: kem_pk_hash(leaf_pk).unwrap(),
                path: self.index.steps(leaf, self.seal.header.height).unwrap(),
            }
        }
    }

    pub fn check_rejects(forged: &Forged) -> CoreError {
        check_window(
            &forged.state,
            &forged.commits,
            &forged.seal,
            &forged.requests,
            false,
        )
        .unwrap_err()
    }
}

#[test]
fn a_forged_external_epoch_is_rejected() {
    let mut sim = Sim::new(2, 5);
    sim.request_joins(3);
    sim.run_window();
    let state = sim.ds.state().clone();
    let forged = forged::forge(&state, true, &mut sim.rng);
    let not_admin = cityg_core::error::CoreError::Unauthorized("admission signer is not an admin");
    // The delivery service's own check refuses it.
    assert_eq!(forged::check_rejects(&forged), not_admin);
    for member in sim.members.values_mut() {
        let before = *member.msg_secret();
        let packet = forged.packet(member.occupancy().leaf, member.leaf_public_key());
        // The confirmation tag is right (the error comes from the admission,
        // which is checked after the tag), and the member refuses the epoch.
        assert_eq!(member.process(&packet).unwrap_err(), not_admin);
        assert_eq!(*member.msg_secret(), before);
    }
    // The group goes on.
    sim.request_joins(1);
    sim.run_window();
    sim.assert_agreement();
}

#[test]
fn an_absent_member_replays_or_jumps() {
    let mut sim = Sim::new(2, 6);
    sim.request_joins(5);
    sim.run_window();
    let replayer = *sim.members.keys().nth(1).unwrap();
    let jumper = *sim.members.keys().nth(2).unwrap();
    for absent in [replayer, jumper] {
        sim.absent.insert(absent);
        sim.ds.set_online(absent, false);
    }
    for _ in 0..3 {
        sim.request_joins(2);
        sim.run_window();
    }
    assert_eq!(sim.members[&replayer].epoch() + 3, sim.ds.epoch());
    // Replay: every missed window, in order.
    sim.replay(replayer);
    sim.assert_agreement();
    // Jump: a welcome into the next window, and the latest wrap of each
    // node of its path.
    let member = sim.take(jumper);
    let interim = sim.ds.state().interim;
    let (returning, request) = member.catch_up(&interim, &mut sim.rng).unwrap();
    let reference = sim.ds.submit_catch_up(request, sim.now).unwrap();
    sim.returning.insert(reference, returning);
    let task = sim.run_window();
    assert!(task.changes.is_empty() && task.committers.is_empty());
    assert!(sim.members.contains_key(&jumper));
    sim.assert_agreement();
    // The jumper follows the next windows like any member.
    sim.request_joins(3);
    sim.run_window();
    sim.assert_agreement();
}

#[test]
fn a_returning_member_re_enters_its_leaf() {
    let mut sim = Sim::new(2, 7);
    sim.request_joins(6);
    sim.run_window();
    let first = *sim.members.keys().nth(3).unwrap();
    let second = *sim.members.keys().nth(5).unwrap();
    let away_first = sim.take(first);
    let away_second = sim.take(second);
    sim.request_joins(2);
    sim.run_window();
    // With members online, a committer welcomes the re-entry.
    let (returning, request) = away_first.re_enter(&mut sim.rng).unwrap();
    let reference = sim.ds.submit_re_entry(request, sim.now).unwrap();
    sim.returning.insert(reference, returning);
    sim.run_window();
    assert!(sim.members.contains_key(&first));
    sim.assert_agreement();
    // With nobody online, the returning member seals the window itself.
    sim.set_all_online(false);
    let (returning, request) = away_second.re_enter(&mut sim.rng).unwrap();
    let reference = sim.ds.submit_re_entry(request, sim.now).unwrap();
    sim.returning.insert(reference, returning);
    let task = sim.run_entrant_window();
    assert_eq!(task.sealer, second);
    assert!(sim.members.contains_key(&second));
    sim.assert_agreement();
}

/// Run the open window with `committer` committing every district while
/// keeping the secrets it draws (a dishonest committer), sealed by `sealer`.
fn run_window_keeping_secrets(
    sim: &mut Sim,
    committer: cityg_core::tree::Occupancy,
) -> Vec<cityg_core::rekey::Rekeyed> {
    use cityg_core::roles::build_district;
    sim.now += 60_000;
    let task = sim.ds.open_window(sim.now).unwrap().expect("a window");
    let (_, requests, _) = sim.ds.open_window_data().unwrap();
    let requests = requests.clone();
    let window = task.window(sim.ds.state()).unwrap();
    let mut kept = Vec::new();
    for (district, assigned) in &task.committers {
        assert_eq!(*assigned, committer);
        let member = &sim.members[&committer];
        let (commit, drawn) = build_district(
            sim.ds.state(),
            &window,
            *district,
            &requests,
            committer,
            member.identity(),
            &[0; 32],
            &mut sim.rng,
        )
        .unwrap();
        sim.ds.submit_district_commit(commit).unwrap();
        kept.push(drawn);
    }
    let commits = sim.ds.open_commits();
    let seal = sim.members[&task.sealer]
        .seal(sim.ds.state(), &task, &commits, &requests, &mut sim.rng)
        .unwrap();
    let epoch = sim.ds.submit_seal(seal).unwrap();
    sim.follow(epoch);
    sim.welcome_and_enter(epoch);
    kept
}

#[test]
fn removing_a_committer_rekeys_the_nodes_it_drew() {
    use cityg_core::crypto::{node_key, unwrap};
    let mut sim = Sim::new(2, 9);
    sim.request_joins(11);
    sim.run_window();
    let shape = sim.ds.state().tree.shape();
    assert_eq!(shape.height, 4);
    // Only C (district 0) and one other member are online; a member of
    // district 2 leaves, so C commits district 2, which is not its own.
    let c = *sim.members.keys().nth(1).unwrap();
    let sealer = *sim.members.keys().nth(2).unwrap();
    let leaving = *sim
        .members
        .keys()
        .find(|m| shape.district_of(m.leaf) == 2)
        .unwrap();
    assert_eq!(shape.district_of(c.leaf), 0);
    sim.set_all_online(false);
    sim.ds.set_online(c, true);
    sim.ds.set_online(sealer, true);
    let proposal = sim.members[&leaving]
        .remove_proposal(leaving, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(proposal, sim.now).unwrap();
    // C keeps what it draws.
    let kept = run_window_keeping_secrets(&mut sim, c);
    let root2 = shape.district_root(2);
    let tainted = sim.ds.state().tree.tainted_by(c);
    assert!(tainted.contains(&root2), "C drew district 2's root");
    let secret = kept[0].secret(root2).unwrap().clone();
    assert_eq!(
        node_key(&secret).unwrap().public_key(),
        sim.ds.state().tree.parent(root2).unwrap().encryption_key,
        "C knows the current secret of a node off its path"
    );
    // From the secret of district 2's root, C also opens the city's wrap
    // of node (3, 1) of that window.
    let gid = sim.ds.state().gid;
    let c_epoch = sim.ds.epoch();
    let n31 = cityg_core::tree::NodeId { level: 3, index: 1 };
    let wrap31 = sim
        .ds
        .window(c_epoch)
        .unwrap()
        .seal
        .body
        .city_wraps
        .iter()
        .find(|wrapped| wrapped.node == n31 && wrapped.target == root2)
        .unwrap()
        .clone();
    let root2_key = node_key(&secret).unwrap();
    let s31 = unwrap(&gid, c_epoch, &wrap31, &root2_key, &root2_key.public_key()).unwrap();
    // Now C is removed. District 2 has no change, but C's taints force it
    // into the window.
    let before = sim.ds.state().clone();
    assert_eq!(
        node_key(&s31).unwrap().public_key(),
        before.tree.parent(n31).unwrap().encryption_key
    );
    sim.set_all_online(true);
    let admin = sim.members[&common::CREATOR]
        .remove_proposal(c, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(admin, sim.now).unwrap();
    let task = sim.run_window();
    assert!(task.committers.contains_key(&2));
    assert!(
        !task
            .changes
            .iter()
            .any(|change| shape.district_of(change.leaf) == 2)
    );
    assert!(sim.ds.state().tree.tainted_by(c).is_empty());
    sim.assert_agreement();
    // Nothing C drew or opened opens a wrap of that window.
    let stored = sim.ds.window(sim.ds.epoch()).unwrap();
    let mut known: Vec<cityg_core::crypto::Secret> = vec![s31.clone()];
    for drawn in &kept {
        for level in 1..=shape.height {
            for index in 0..(1u32 << (shape.height - level)) {
                let node = cityg_core::tree::NodeId { level, index };
                if let Some(secret) = drawn.secret(node) {
                    known.push(secret.clone());
                }
            }
        }
    }
    for secret in &known {
        let key = node_key(secret).unwrap();
        let pk = key.public_key();
        let wraps = stored
            .commits
            .iter()
            .flat_map(|commit| commit.wraps.iter())
            .chain(stored.seal.body.city_wraps.iter());
        for wrapped in wraps {
            assert!(unwrap(&gid, sim.ds.epoch(), wrapped, &key, &pk).is_err());
        }
    }
    assert!(
        stored
            .seal
            .body
            .city_updates
            .iter()
            .any(|update| update.node == n31)
    );
    // Sanity: without the rule, the window would re-key district 0 and the
    // city path above it only, and wrap the new root to (3, 1), whose
    // secret C holds.
    let without_rule = cityg_core::rekey::plan_city(
        &before.tree,
        shape,
        &std::collections::BTreeMap::from([(0u32, true)]),
        &std::collections::BTreeSet::new(),
    )
    .unwrap();
    let root = without_rule.top().unwrap();
    assert_eq!(root.node, shape.root());
    assert_eq!(root.wrap_to, vec![n31]);
}

#[test]
fn an_update_rekeys_the_members_path_and_taints() {
    let mut sim = Sim::new(2, 11);
    sim.request_joins(7);
    sim.run_window();
    let updater = *sim.members.keys().nth(4).unwrap();
    // The updater commits a window alone, so it taints nodes.
    sim.set_all_online(false);
    sim.ds.set_online(updater, true);
    sim.request_joins(1);
    sim.run_window();
    assert!(!sim.ds.state().tree.tainted_by(updater).is_empty());
    sim.set_all_online(true);
    let old_key = sim.members[&updater].leaf_public_key().to_vec();
    let request = sim
        .members
        .get_mut(&updater)
        .unwrap()
        .update_request(&mut sim.rng)
        .unwrap();
    sim.ds.submit_update(request.clone(), sim.now).unwrap();
    sim.run_window();
    assert_ne!(sim.members[&updater].leaf_public_key(), old_key.as_slice());
    assert!(sim.ds.state().tree.tainted_by(updater).is_empty());
    assert_eq!(
        sim.ds.state().tree.leaf(updater.leaf).unwrap().updated,
        sim.ds.epoch()
    );
    sim.assert_agreement();
    // The same request cannot be replayed: it replaces a key that is gone.
    assert!(sim.ds.submit_update(request, sim.now).is_err());
}

#[test]
fn a_join_takes_the_leaf_a_removal_empties() {
    let mut sim = Sim::new(2, 12);
    sim.request_joins(7);
    sim.run_window();
    let leaving = *sim.members.keys().nth(5).unwrap();
    let proposal = sim.members[&common::CREATOR]
        .remove_proposal(leaving, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(proposal, sim.now).unwrap();
    sim.request_joins(1);
    let task = sim.run_window();
    let at_leaf: Vec<_> = task
        .changes
        .iter()
        .filter(|c| c.leaf == leaving.leaf)
        .collect();
    assert_eq!(at_leaf.len(), 2, "removal and join paired on one leaf");
    assert_eq!(sim.ds.state().tree.member_count(), 8);
    assert!(!sim.ds.state().tree.is_member(leaving));
    assert_eq!(
        sim.ds.state().tree.occupancy(leaving.leaf).unwrap().since,
        sim.ds.epoch()
    );
    sim.assert_agreement();
}

#[test]
fn the_delivery_service_evicts_only_under_an_admin_policy() {
    let mut sim = Sim::new(2, 13);
    sim.request_joins(3);
    sim.run_window();
    assert_eq!(
        sim.ds.evict_idle(sim.now).unwrap(),
        0,
        "no policy, no eviction"
    );
    // The admin sets a policy and refreshes its own key in the same window.
    let policy = sim.members[&common::CREATOR]
        .group_policy(false, Some(2), &mut sim.rng)
        .unwrap();
    sim.ds.submit_policy(policy.clone(), sim.now).unwrap();
    let update = sim
        .members
        .get_mut(&common::CREATOR)
        .unwrap()
        .update_request(&mut sim.rng)
        .unwrap();
    sim.ds.submit_update(update, sim.now).unwrap();
    sim.run_window();
    assert_eq!(sim.ds.state().registry.policy(), Some(&policy.hash()));
    sim.request_joins(1);
    sim.run_window();
    // Members whose key dates from epoch 1 are idle at epoch 4.
    let idle: Vec<_> = sim
        .ds
        .state()
        .tree
        .leaves()
        .filter(|(_, leaf)| leaf.updated == 1)
        .map(|(index, leaf)| leaf.occupancy(index))
        .collect();
    assert_eq!(idle.len(), 3);
    assert_eq!(sim.ds.evict_idle(sim.now).unwrap(), 3);
    let task = sim.run_window();
    assert_eq!(
        task.changes
            .iter()
            .filter(|c| c.kind == cityg_core::objects::ChangeKind::Eviction)
            .count(),
        3
    );
    for member in idle {
        assert!(!sim.ds.state().tree.is_member(member));
        assert!(!sim.members.contains_key(&member));
    }
    assert!(sim.members.contains_key(&common::CREATOR));
    sim.assert_agreement();
}

#[test]
fn a_failed_committer_is_replaced() {
    let mut sim = Sim::new(2, 14);
    sim.request_joins(7);
    sim.run_window();
    sim.request_joins(2);
    sim.now += 60_000;
    let task = sim.ds.open_window(sim.now).unwrap().unwrap();
    let (district, failed) = task
        .committers
        .iter()
        .next()
        .map(|(d, c)| (*d, *c))
        .unwrap();
    let replacement = *sim
        .members
        .keys()
        .find(|member| **member != failed && **member != task.sealer)
        .unwrap();
    let task = sim.ds.reassign(district, replacement).unwrap();
    let (_, requests, _) = sim.ds.open_window_data().unwrap();
    let requests = requests.clone();
    // The failed committer's commit is refused now.
    let late = sim.members[&failed].commit_district(
        sim.ds.state(),
        &task,
        district,
        &requests,
        &mut sim.rng,
    );
    assert!(late.is_err());
    for (district, committer) in &task.committers {
        let commit = sim.members[committer]
            .commit_district(sim.ds.state(), &task, *district, &requests, &mut sim.rng)
            .unwrap();
        sim.ds.submit_district_commit(commit).unwrap();
    }
    let commits = sim.ds.open_commits();
    let seal = sim.members[&task.sealer]
        .seal(sim.ds.state(), &task, &commits, &requests, &mut sim.rng)
        .unwrap();
    let epoch = sim.ds.submit_seal(seal).unwrap();
    sim.follow(epoch);
    sim.welcome_and_enter(epoch);
    assert_eq!(sim.members.len(), 10);
    sim.assert_agreement();
}

#[test]
fn audits_expose_a_committer_that_placed_an_invalid_join() {
    use cityg_core::audit::{self, FraudProof, Verdict};
    use cityg_core::commit::Change;
    use cityg_core::identity::DeviceIdentity;
    use cityg_core::kem::KemSecret;
    use cityg_core::objects::{Admission, ChangeKind, JoinRequest, Request, device_id};
    use cityg_core::roles::WindowTask;
    use cityg_core::window::{Requests, WindowShape, check_window, needed_height};

    let mut sim = Sim::new(2, 15);
    sim.request_joins(5);
    sim.run_window();
    let state = sim.ds.state().clone();
    let epoch = state.epoch + 1;
    let committer = *sim.members.keys().nth(1).unwrap();
    let sealer = *sim.members.keys().nth(2).unwrap();
    // An intruder, with an admission the dishonest committer signed while
    // claiming to be an admin; and an honest joiner.
    let join = |admitted_by: &DeviceIdentity, as_admin, rng: &mut rand_chacha::ChaCha20Rng| {
        let device = DeviceIdentity::generate(rng);
        let id = device_id(&state.gid, device.public_key()).unwrap();
        let admission =
            Admission::by_admin(&state.gid, &id, epoch + 10, as_admin, admitted_by, rng).unwrap();
        let leaf = KemSecret::generate(rng).public_key();
        let init = KemSecret::generate(rng).public_key();
        JoinRequest::sign(
            &state.gid,
            &device,
            &leaf,
            &init,
            epoch + 10,
            Some(&admission),
            rng,
        )
        .unwrap()
    };
    let bad = join(sim.members[&committer].identity(), committer, &mut sim.rng);
    let good = join(
        sim.members[&common::CREATOR].identity(),
        common::CREATOR,
        &mut sim.rng,
    );
    let changes = vec![
        Change {
            leaf: 6,
            kind: ChangeKind::Join,
            request: bad.reference(),
        },
        Change {
            leaf: 7,
            kind: ChangeKind::Join,
            request: good.reference(),
        },
    ];
    let requests: Requests = [
        (bad.reference(), Request::Join(bad.clone())),
        (good.reference(), Request::Join(good.clone())),
    ]
    .into();
    let height = needed_height(state.tree.height(), Some(7));
    let shape = state.tree.shape().grown(height).unwrap();
    let window = WindowShape::new(&state.tree, epoch, shape, changes.iter().copied()).unwrap();
    let task = WindowTask {
        gid: state.gid,
        epoch,
        height,
        changes,
        committers: window.districts.iter().map(|d| (*d, committer)).collect(),
        sealer,
        entrant: None,
        policy: None,
        welcomes: Vec::new(),
        time_ms: state.time_ms + 1,
    };
    let identity = sim.members[&committer].identity();
    let commits: Vec<_> = window
        .districts
        .iter()
        .map(|d| {
            forged::unchecked_commit(
                &state,
                &window,
                *d,
                &requests,
                committer,
                identity,
                &[0; 32],
                &mut sim.rng,
            )
            .0
        })
        .collect();
    // The honest sealer checks the structure of every district commit, not
    // every entry (E-12), and seals.
    let seal = sim.members[&sealer]
        .seal(&state, &task, &commits, &requests, &mut sim.rng)
        .unwrap();
    assert!(check_window(&state, &commits, &seal, &requests, true).is_err());
    let outcome = check_window(&state, &commits, &seal, &requests, false).unwrap();
    let mut after = state.clone();
    after.apply(&outcome).unwrap();
    // Every member audits both entries here (20 audits per entry among 7).
    let records = audit::records(&state, &window, &commits, &requests).unwrap();
    assert_eq!(
        audit::picks(records.len(), 7, audit::AUDIT_K, &mut sim.rng).len(),
        2
    );
    let previous = state.header().unwrap();
    let verdicts: Vec<Verdict> = records
        .iter()
        .map(|record| audit::check_record(&previous, record).unwrap())
        .collect();
    assert_eq!(
        verdicts,
        vec![Verdict::Fraud("join request or admission"), Verdict::Valid]
    );
    // The fraud proof names the committer, for anyone holding both headers.
    let next = after.header().unwrap();
    let proof = |record: &audit::AuditRecord| FraudProof {
        commit: commits
            .iter()
            .find(|c| c.district == record.district)
            .unwrap()
            .clone(),
        record: record.clone(),
        committer_leaf: after.tree.leaf_proof(committer.leaf).unwrap(),
    };
    assert_eq!(
        proof(&records[0]).verify(&previous, &next).unwrap(),
        committer
    );
    assert!(proof(&records[1]).verify(&previous, &next).is_err());
    // A record whose proofs do not check proves nothing.
    let mut altered = records[0].clone();
    let device = bad.device_id().unwrap();
    altered.proofs.device.as_mut().unwrap().terminal = Some((device, committer));
    assert!(audit::check_record(&previous, &altered).is_err());
}

#[test]
fn invites_admit_joiners_up_to_their_uses_and_expiry() {
    use cityg_core::identity::DeviceIdentity;
    use cityg_core::member::Joiner;
    use cityg_core::objects::Admission;

    let mut sim = Sim::new(2, 16);
    let seed = sim.random_seed();
    let expires = sim.now + 3_600_000;
    let invite = sim.members[&common::CREATOR]
        .invite(&seed, expires, 2, &mut sim.rng)
        .unwrap();
    let anchor = sim.anchor();
    let submit = |sim: &mut Sim, at: u64| {
        let device = DeviceIdentity::generate(&mut sim.rng);
        let id = cityg_core::objects::device_id(&invite.gid, device.public_key()).unwrap();
        let admission = Admission::with_invite(&invite, &seed, &id, 50, &mut sim.rng).unwrap();
        let joiner =
            Joiner::new(device, Some(&admission), 50, anchor.clone(), &mut sim.rng).unwrap();
        let result = sim.ds.submit_join(joiner.request().clone(), at);
        if let Ok(reference) = result {
            sim.joiners.insert(reference, joiner);
        }
        result.is_ok()
    };
    let now = sim.now;
    assert!(submit(&mut sim, now));
    assert!(submit(&mut sim, now));
    assert!(!submit(&mut sim, now), "the invite is used up");
    sim.run_window();
    assert_eq!(sim.members.len(), 3);
    sim.assert_agreement();
    assert!(!submit(&mut sim, expires + 1), "the invite expired");
}

#[test]
fn joiners_check_the_chain_of_seals_from_their_checkpoint() {
    use cityg_core::identity::DeviceIdentity;
    use cityg_core::member::Joiner;
    use cityg_core::packet::SealerEvidence;
    use cityg_core::window::EpochHeader;

    let mut sim = Sim::new(2, 17);
    sim.request_joins(3);
    sim.run_window();
    // Two devices anchor on this epoch and ask to join two windows later.
    let anchor = sim.anchor();
    let mut late = Vec::new();
    for _ in 0..2 {
        let device = DeviceIdentity::generate(&mut sim.rng);
        let admission = sim.members[&common::CREATOR]
            .admit(device.public_key(), anchor.epoch + 100, &mut sim.rng)
            .unwrap();
        let not_after = anchor.epoch + 100;
        late.push(
            Joiner::new(
                device,
                Some(&admission),
                not_after,
                anchor.clone(),
                &mut sim.rng,
            )
            .unwrap(),
        );
    }
    for _ in 0..2 {
        sim.request_joins(1);
        sim.run_window();
    }
    let references: Vec<_> = late
        .iter()
        .map(|joiner| {
            sim.ds
                .submit_join(joiner.request().clone(), sim.now)
                .unwrap()
        })
        .collect();
    sim.run_window();
    let entry = sim.ds.entry(&references[0], anchor.epoch).unwrap();
    assert_eq!(entry.links.len(), 3, "three seals from the checkpoint");
    // A link whose sealer evidence shows another leaf is refused.
    let mut tampered = entry.links[0].clone();
    if let SealerEvidence::Member(leaf) = &mut tampered.sealer {
        leaf.index ^= 1;
    }
    assert!(anchor.follow(&tampered).is_err());
    assert!(anchor.follow(&entry.links[0]).is_ok());
    // Another joiner cannot use this entry.
    let mut late = late.into_iter();
    let first = late.next().unwrap();
    let second = late.next().unwrap();
    assert!(second.enter(&entry).is_err());
    // The joiner it is for enters, three epochs after its checkpoint.
    let member = first.enter(&entry).unwrap();
    assert_eq!(member.epoch(), sim.ds.epoch());
    sim.members.insert(member.occupancy(), member);
    sim.assert_agreement();
    // A checkpoint signed by a non-admin is refused.
    let checkpoint = sim.ds.latest_checkpoint().unwrap().clone();
    let (registry, external_pk) = sim.ds.anchor_material(checkpoint.content.epoch).unwrap();
    let other = *sim.members.keys().nth(1).unwrap();
    let not_admin = sim.members[&other].identity().public_key().to_vec();
    assert!(
        EpochHeader::from_checkpoint(
            &checkpoint.gid,
            &checkpoint,
            &not_admin,
            registry,
            external_pk
        )
        .is_err()
    );
}

#[test]
fn an_open_group_admits_devices_without_any_admin_signature() {
    use cityg_core::objects::Request;

    let mut sim = Sim::with_policy(2, 20, true);
    assert!(sim.ds.state().registry.is_open());
    sim.request_open_joins(3);
    sim.run_window();
    assert_eq!(sim.members.len(), 4);
    sim.assert_agreement();
    let stored = sim.ds.window(1).unwrap();
    assert!(
        stored
            .requests
            .values()
            .all(|request| matches!(request, Request::Join(join) if join.admission.is_none()))
    );
    // A wave over several districts.
    sim.request_open_joins(9);
    let task = sim.run_window();
    assert!(task.committers.len() >= 2);
    assert_eq!(sim.members.len(), 13);
    sim.assert_agreement();
    // Every member sees who came in, checked against the seal it accepted.
    let stored = sim.ds.window(sim.ds.epoch()).unwrap();
    for member in sim.members.values() {
        let joins = member
            .window_joins(&stored.seal, &stored.commits, &stored.requests)
            .unwrap();
        assert_eq!(joins.len(), 9);
    }
    // A list the seal does not commit to is refused.
    let mut fewer = stored.commits.clone();
    fewer.pop();
    assert!(
        sim.member(common::CREATOR)
            .window_joins(&stored.seal, &fewer, &stored.requests)
            .is_err()
    );
}

#[test]
fn a_closed_group_refuses_joins_without_admission() {
    use cityg_core::error::CoreError;
    use cityg_core::identity::DeviceIdentity;
    use cityg_core::member::Joiner;

    let mut sim = Sim::new(2, 21);
    sim.request_joins(2);
    sim.run_window();
    let anchor = sim.anchor();
    let device = DeviceIdentity::generate(&mut sim.rng);
    let joiner = Joiner::new(device, None, anchor.epoch + 100, anchor, &mut sim.rng).unwrap();
    let refused = CoreError::Unauthorized("join without admission in a closed group");
    assert_eq!(
        sim.ds
            .submit_join(joiner.request().clone(), sim.now)
            .unwrap_err(),
        refused
    );
    // Sealed by the delivery service itself as an entrant, the join is
    // refused by the service's own check and by every member.
    let state = sim.ds.state().clone();
    let forged = forged::forge(&state, false, &mut sim.rng);
    assert_eq!(forged::check_rejects(&forged), refused);
    for member in sim.members.values_mut() {
        let packet = forged.packet(member.occupancy().leaf, member.leaf_public_key());
        assert_eq!(member.process(&packet).unwrap_err(), refused);
    }
}

#[test]
fn in_an_open_group_the_service_can_join_but_is_visible_and_cannot_pose_as_a_member() {
    use cityg_core::cbor::{array, bytes, encode, text, uint};
    use cityg_core::crypto::kem_pk_hash;
    use cityg_core::error::CoreError;
    use cityg_core::kem::KemSecret;
    use cityg_core::objects::{JoinRequest, UpdateRequest};
    use cityg_core::window::check_entry;
    use cityg_pqc::SignatureContext;

    let mut sim = Sim::with_policy(2, 22, true);
    sim.request_open_joins(3);
    sim.run_window();
    // With nobody online, the delivery service joins a device of its own
    // and seals the window itself. In an open group that is a join like any
    // other: the members accept it, and the service reads the new epoch.
    let state = sim.ds.state().clone();
    let forged = forged::forge(&state, false, &mut sim.rng);
    cityg_core::window::check_window(
        &forged.state,
        &forged.commits,
        &forged.seal,
        &forged.requests,
        true,
    )
    .unwrap();
    for member in sim.members.values_mut() {
        let packet = forged.packet(member.occupancy().leaf, member.leaf_public_key());
        member.process(&packet).unwrap();
        assert_eq!(*member.msg_secret(), forged.msg_secret);
    }
    // It is visible: its device is among the window's joins, checked by
    // every member against the seal it accepted.
    let forger_pk = forged.forger.public_key().to_vec();
    for member in sim.members.values() {
        let joins = member
            .window_joins(&forged.seal, &forged.commits, &forged.requests)
            .unwrap();
        assert_eq!(joins.len(), 1);
        assert_eq!(joins[0].1, forger_pk);
    }
    // It cannot pose as a member: a request in a member's name needs that
    // member's device key.
    let victim = *sim.members.keys().nth(1).unwrap();
    let victim_leaf = state.tree.member(victim).unwrap().clone();
    let gid = state.gid;
    let epoch = state.epoch + 1;
    let leaf = KemSecret::generate(&mut sim.rng).public_key();
    let init = KemSecret::generate(&mut sim.rng).public_key();
    let fields = vec![
        text(cityg_core::objects::JOIN_REQUEST_LABEL),
        bytes(&gid),
        bytes(&victim_leaf.device_pk),
        bytes(&leaf),
        bytes(&init),
        uint(epoch + 10),
        ciborium::value::Value::Null,
    ];
    let tbs = encode(&array(fields.clone())).unwrap();
    let signature = forged
        .forger
        .sign(SignatureContext::JOIN_REQUEST, &tbs, &mut sim.rng)
        .unwrap();
    let mut signed = fields;
    signed.push(bytes(&signature));
    let posing = JoinRequest::decode(&encode(&array(signed)).unwrap()).unwrap();
    assert_eq!(
        posing
            .verify(&gid, epoch, state.registry.admins(), true)
            .unwrap_err(),
        CoreError::BadSignature("join request")
    );
    assert_eq!(
        check_entry(
            &state,
            epoch,
            0,
            &cityg_core::objects::Request::Join(posing),
            true
        )
        .unwrap_err(),
        CoreError::Invalid("device already a member")
    );
    let update = UpdateRequest::sign(
        &gid,
        victim,
        &victim_leaf.encryption_key,
        &leaf,
        &forged.forger,
        &mut sim.rng,
    )
    .unwrap();
    assert_eq!(
        update.replaces,
        kem_pk_hash(&victim_leaf.encryption_key).unwrap()
    );
    assert_eq!(
        update.verify(&gid, &victim_leaf.device_pk).unwrap_err(),
        CoreError::BadSignature("update request")
    );
}

#[test]
fn only_an_admin_policy_opens_a_group() {
    use cityg_core::error::CoreError;
    use cityg_core::objects::GroupPolicy;

    let mut sim = Sim::new(2, 23);
    sim.request_joins(3);
    sim.run_window();
    let member = *sim.members.keys().nth(1).unwrap();
    // A member that is not an admin cannot open the group.
    assert!(
        sim.members[&member]
            .group_policy(true, None, &mut sim.rng)
            .is_err()
    );
    let gid = *sim.member(member).gid();
    let posing = GroupPolicy::sign(
        &gid,
        true,
        None,
        member,
        sim.members[&member].identity(),
        &mut sim.rng,
    )
    .unwrap();
    assert_eq!(
        sim.ds.submit_policy(posing, sim.now).unwrap_err(),
        CoreError::Unauthorized("policy signer is not an admin")
    );
    // A member refuses a window that opens the group without the admins'
    // policy, whoever sealed it.
    sim.absent.insert(member);
    sim.request_joins(1);
    sim.run_window();
    let mut packet = sim.ds.packet(sim.ds.epoch(), member).unwrap();
    packet.registry.open = true;
    assert_eq!(
        sim.members
            .get_mut(&member)
            .unwrap()
            .process(&packet)
            .unwrap_err(),
        CoreError::Invalid("admission mode changed without a policy")
    );
    sim.replay(member);
    // The admin opens it.
    let policy = sim.members[&common::CREATOR]
        .group_policy(true, None, &mut sim.rng)
        .unwrap();
    sim.ds.submit_policy(policy, sim.now).unwrap();
    sim.run_window();
    assert!(sim.ds.state().registry.is_open());
    assert!(sim.members.values().all(|m| m.header().registry.open));
    sim.request_open_joins(2);
    sim.run_window();
    assert_eq!(sim.members.len(), 7);
    sim.assert_agreement();
}
