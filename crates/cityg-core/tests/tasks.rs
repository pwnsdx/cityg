//! Stage 2 of the v0.5 draft (docs/specs-v0.5-draft.md section 3): the
//! city re-keyed by one task per sub-city and one for the top, tasks
//! performed by the window's joiners first, and a sealer that draws
//! nothing. Districts of two leaves (L = 1), islands of two (c = 1),
//! sub-cities of two districts (S = 1): sixteen members give four sub-cities
//! under a top of two levels.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;

use cityg_core::card::{CardKey, LeafKeys};
use cityg_core::commit::{
    CityTask, CityTaskContent, DistrictCommit, DistrictCommitContent, SealKind,
};
use cityg_core::crypto::{Wrap, h, wrap};
use cityg_core::dispute::{DisputeKind, DisputeStatement, DisputeVerifier};
use cityg_core::ds::TopChoice;
use cityg_core::error::CoreError;
use cityg_core::identity::DeviceIdentity;
use cityg_core::kem::KemSecret;
use cityg_core::member::Joiner;
use cityg_core::objects::{JoinRequest, RepairRequest, Request, Urgency};
use cityg_core::roles::{WindowTask, WindowWork, build_district};
use cityg_core::top::{RelayContext, RelayElement, Top};
use cityg_core::tree::{CityPart, Divisions, NodeId, Occupancy};
use cityg_core::window::{Requests, check_committer, check_sealer};
use common::Sim;
use rand_chacha::ChaCha20Rng;

/// A group of `size` members with districts, islands and sub-cities of two.
fn group(seed: u64, size: usize) -> Sim {
    let mut sim = Sim::with_divisions(Divisions::new(1, 1, 1).unwrap(), seed);
    let mut joined = 1;
    while joined < size {
        let count = (size - joined).min(7);
        sim.request_joins(count);
        sim.run_window();
        joined += count;
    }
    assert_eq!(sim.members.len(), size);
    sim.assert_agreement();
    sim
}

/// The creator proposes to remove `target` at once.
fn remove(sim: &mut Sim, target: Occupancy) {
    let proposal = sim.members[&common::CREATOR]
        .remove_proposal(target, Urgency::Urgent, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(proposal, sim.now).unwrap();
}

/// The creator proposes to remove a member of sub-city `subcity` at once.
fn remove_in(sim: &mut Sim, subcity: u32) -> Occupancy {
    let target = member_of(sim, subcity);
    remove(sim, target);
    target
}

/// A member of sub-city `subcity` other than the creator.
fn member_of(sim: &Sim, subcity: u32) -> Occupancy {
    let shape = sim.ds.state().tree.shape();
    *sim.members
        .keys()
        .find(|member| {
            **member != common::CREATOR
                && shape.subcity_of(shape.district_of(member.leaf)) == subcity
        })
        .unwrap()
}

/// The district commits of the open window `task` whose district
/// `select` accepts, submitted by their committers.
fn commit_districts(sim: &mut Sim, task: &WindowTask, select: impl Fn(u32) -> bool) {
    let (_, requests, _) = sim.ds.open_window_data().unwrap();
    let requests = requests.clone();
    for (district, committer) in &task.committers {
        if !select(*district) {
            continue;
        }
        let commit = sim.members[committer]
            .commit_district(sim.ds.state(), task, *district, &requests, &mut sim.rng)
            .unwrap();
        sim.ds.submit_district_commit(commit).unwrap();
    }
}

/// The task of `part` of the open window, as its performer in `task`
/// builds it on what the DS shows.
fn perform(sim: &mut Sim, task: &WindowTask, part: CityPart) -> cityg_core::commit::CityTask {
    let (_, requests, _) = sim.ds.open_window_data().unwrap();
    let requests = requests.clone();
    let commits = sim.ds.open_commits();
    let city_tasks = sim.ds.open_city_tasks();
    let work = WindowWork {
        commits: &commits,
        city_tasks: &city_tasks,
        requests: &requests,
    };
    sim.members[&task.city[&part]]
        .commit_city(sim.ds.state(), task, part, &work, &mut sim.rng)
        .unwrap()
}

/// Seal the open window `task` once its tasks are in, follow it, and let
/// its joiners enter.
fn seal_and_follow(sim: &mut Sim, task: &WindowTask) -> u64 {
    let seal = sim.seal_open(task);
    let epoch = sim.ds.submit_seal(seal).unwrap();
    sim.follow(epoch);
    sim.welcome_and_enter(epoch);
    epoch
}

#[test]
fn sub_cities_and_the_top_are_rekeyed_by_their_own_tasks() {
    let mut sim = group(61, 16);
    let shape = sim.ds.state().tree.shape();
    assert!(shape.has_top());
    assert_eq!(
        (shape.subcity_level(), shape.subcity_count(), shape.height),
        (2, 4, 4)
    );
    // Removals in sub-cities 0 and 3.
    let targets = [member_of(&sim, 0), member_of(&sim, 3)];
    for target in targets {
        remove(&mut sim, target);
    }
    let task = sim.run_window();
    sim.assert_agreement();
    assert_eq!(sim.members.len(), 14);
    for part in [CityPart::SubCity(0), CityPart::SubCity(3), CityPart::Top] {
        assert!(task.city.contains_key(&part), "{part:?}");
    }
    // With enough members online, every task has its own performer, and the
    // sealer performs none: it only followed the tasks along its path.
    let mut performers: BTreeSet<Occupancy> = task.committers.values().copied().collect();
    performers.insert(task.sealer);
    for performer in task.city.values() {
        assert!(performers.insert(*performer), "{performer:?} has two tasks");
    }
    let epoch = sim.ds.epoch();
    let stored = sim.ds.window(epoch).unwrap();
    let parts: Vec<CityPart> = stored.city_tasks.iter().map(|t| t.part).collect();
    let listed: Vec<CityPart> = stored.seal.body.city.iter().map(|(p, _)| *p).collect();
    assert_eq!(parts, listed, "the seal lists the tasks, the top last");
    assert_eq!(parts.last(), Some(&CityPart::Top));
    // Each task re-keys its part only, and its nodes take its performer's
    // taint.
    let tree = &sim.ds.state().tree;
    for city_task in &stored.city_tasks {
        for update in &city_task.updates {
            assert_eq!(shape.part_of(update.node), city_task.part);
            if update.public_key.is_some() {
                assert_eq!(tree.parent(update.node).unwrap().taint, city_task.performer);
            }
        }
    }
    let top = stored.city_tasks.last().unwrap();
    assert_eq!(top.updates.last().unwrap().node, shape.root());
}

#[test]
fn city_tasks_wait_for_what_they_build_on() {
    let mut sim = group(62, 16);
    let shape = sim.ds.state().tree.shape();
    remove_in(&mut sim, 1);
    remove_in(&mut sim, 2);
    let task = sim.open_window();
    let (one, two) = (CityPart::SubCity(1), CityPart::SubCity(2));
    assert!(task.city.contains_key(&one) && task.city.contains_key(&two));
    // Only the districts of sub-city 1 are in.
    commit_districts(&mut sim, &task, |district| shape.subcity_of(district) == 1);
    let early_top = perform(&mut sim, &task, CityPart::Top);
    assert!(sim.ds.submit_city_task(early_top).is_err());
    let early_two = perform(&mut sim, &task, two);
    assert!(sim.ds.submit_city_task(early_two).is_err());
    // Sub-city 1 need not wait for sub-city 2's districts.
    let first = perform(&mut sim, &task, one);
    sim.ds.submit_city_task(first.clone()).unwrap();
    // The same task again changes nothing; another one for the part is
    // refused.
    sim.ds.submit_city_task(first).unwrap();
    let other = perform(&mut sim, &task, one);
    assert!(sim.ds.submit_city_task(other).is_err());
    // The rest, then the top over both sub-cities.
    commit_districts(&mut sim, &task, |district| shape.subcity_of(district) == 2);
    let second = perform(&mut sim, &task, two);
    sim.ds.submit_city_task(second).unwrap();
    // A different commit for a district already committed is refused.
    let (district, committer) = task
        .committers
        .iter()
        .next()
        .map(|(d, c)| (*d, *c))
        .unwrap();
    let (_, requests, _) = sim.ds.open_window_data().unwrap();
    let requests = requests.clone();
    let again = sim.members[&committer]
        .commit_district(sim.ds.state(), &task, district, &requests, &mut sim.rng)
        .unwrap();
    assert!(sim.ds.submit_district_commit(again).is_err());
    let top = perform(&mut sim, &task, CityPart::Top);
    sim.ds.submit_city_task(top).unwrap();
    seal_and_follow(&mut sim, &task);
    sim.assert_agreement();
    assert_eq!(sim.members.len(), 14);
}

#[test]
fn a_failed_city_performer_is_replaced() {
    let mut sim = group(63, 16);
    remove_in(&mut sim, 2);
    let task = sim.open_window();
    commit_districts(&mut sim, &task, |_| true);
    let part = CityPart::SubCity(2);
    let failed = task.city[&part];
    // A task built before the reassignment arrives late.
    let late = perform(&mut sim, &task, part);
    let busy: BTreeSet<Occupancy> = task
        .committers
        .values()
        .chain(task.city.values())
        .chain([&task.sealer])
        .copied()
        .collect();
    let replacement = *sim
        .members
        .keys()
        .find(|member| !busy.contains(member) && sim.ds.accepts_from(**member))
        .unwrap();
    let task = sim.ds.reassign_city(part, replacement).unwrap();
    assert_eq!(task.city[&part], replacement);
    assert!(sim.ds.submit_city_task(late).is_err());
    let (_, requests, _) = sim.ds.open_window_data().unwrap();
    let requests = requests.clone();
    let commits = sim.ds.open_commits();
    let work = WindowWork {
        commits: &commits,
        city_tasks: &[],
        requests: &requests,
    };
    assert!(
        sim.members[&failed]
            .commit_city(sim.ds.state(), &task, part, &work, &mut sim.rng)
            .is_err()
    );
    // A removed member cannot take a task.
    let removed = *task_removed(&sim).first().unwrap();
    assert!(sim.ds.reassign_city(CityPart::Top, removed).is_err());
    sim.perform_city_tasks(&task);
    seal_and_follow(&mut sim, &task);
    sim.assert_agreement();
    assert_eq!(sim.members.len(), 15);
    let epoch = sim.ds.epoch();
    let stored = sim.ds.window(epoch).unwrap();
    let performed = stored
        .city_tasks
        .iter()
        .find(|city_task| city_task.part == part)
        .unwrap();
    assert_eq!(performed.performer, replacement);
}

/// Members the open window removes.
fn task_removed(sim: &Sim) -> Vec<Occupancy> {
    let (task, _, _) = sim.ds.open_window_data().unwrap();
    let tree = &sim.ds.state().tree;
    task.changes
        .iter()
        .filter(|change| matches!(change.kind, cityg_core::objects::ChangeKind::Removal))
        .filter_map(|change| tree.occupancy(change.leaf))
        .collect()
}

#[test]
fn a_district_reassigned_drops_only_the_tasks_built_on_it() {
    let mut sim = group(64, 16);
    let shape = sim.ds.state().tree.shape();
    remove_in(&mut sim, 0);
    remove_in(&mut sim, 3);
    let task = sim.open_window();
    commit_districts(&mut sim, &task, |_| true);
    // Every sub-city of the window (the removed members' taints may add
    // some), then the top.
    let subcities: Vec<CityPart> = task
        .city
        .keys()
        .copied()
        .filter(|part| *part != CityPart::Top)
        .collect();
    assert!(subcities.contains(&CityPart::SubCity(0)));
    assert!(subcities.contains(&CityPart::SubCity(3)));
    for part in subcities.iter().copied().chain([CityPart::Top]) {
        let city_task = perform(&mut sim, &task, part);
        sim.ds.submit_city_task(city_task).unwrap();
    }
    // A district of sub-city 3 changes hands: its sub-city's task and the
    // top are dropped, the others are kept.
    let district = *task
        .committers
        .keys()
        .find(|district| shape.subcity_of(**district) == 3)
        .unwrap();
    let removed = task_removed(&sim);
    let replacement = *sim
        .members
        .keys()
        .find(|member| !removed.contains(member) && **member != task.committers[&district])
        .unwrap();
    let task = sim.ds.reassign(district, replacement).unwrap();
    let kept: Vec<CityPart> = sim
        .ds
        .open_city_tasks()
        .iter()
        .map(|city_task| city_task.part)
        .collect();
    let expected: Vec<CityPart> = subcities
        .iter()
        .copied()
        .filter(|part| *part != CityPart::SubCity(3))
        .collect();
    assert_eq!(kept, expected);
    commit_districts(&mut sim, &task, |d| d == district);
    for part in [CityPart::SubCity(3), CityPart::Top] {
        let city_task = perform(&mut sim, &task, part);
        sim.ds.submit_city_task(city_task).unwrap();
    }
    seal_and_follow(&mut sim, &task);
    sim.assert_agreement();
    assert_eq!(sim.members.len(), 14);
}

#[test]
fn removing_a_performer_rekeys_the_parts_it_drew() {
    let mut sim = group(65, 16);
    let shape = sim.ds.state().tree.shape();
    // A window in sub-city 3; its sub-city task goes to a member outside it.
    remove_in(&mut sim, 3);
    let task = sim.run_window();
    sim.assert_agreement();
    let performer = task.city[&CityPart::SubCity(3)];
    let own = shape.subcity_of(shape.district_of(performer.leaf));
    assert_ne!(own, 3, "the performer lives in another sub-city");
    let tainted = sim.ds.state().tree.tainted_by(performer);
    assert!(tainted.contains(&shape.part_root(CityPart::SubCity(3))));
    // Removing it re-keys sub-city 3, where nothing else changes.
    remove(&mut sim, performer);
    let task = sim.run_window();
    sim.assert_agreement();
    assert!(task.city.contains_key(&CityPart::SubCity(3)));
    assert!(
        !task
            .changes
            .iter()
            .any(|change| shape.subcity_of(shape.district_of(change.leaf)) == 3)
    );
    assert!(sim.ds.state().tree.tainted_by(performer).is_empty());
    assert_eq!(sim.members.len(), 14);
}

#[test]
fn an_entrant_performs_every_task_when_nobody_is_online() {
    let mut sim = group(66, 16);
    sim.set_all_online(false);
    remove_in(&mut sim, 1);
    sim.request_joins(1);
    let task = sim.run_entrant_window();
    assert!(task.city.contains_key(&CityPart::Top));
    assert!(
        task.city
            .values()
            .all(|performer| *performer == task.sealer)
    );
    assert!(
        task.committers
            .values()
            .all(|committer| *committer == task.sealer)
    );
    sim.assert_agreement();
    assert_eq!(sim.members.len(), 16);
    // Members seal again once they are back.
    sim.set_all_online(true);
    remove_in(&mut sim, 2);
    sim.run_window();
    sim.assert_agreement();
    assert_eq!(sim.members.len(), 15);
}

/// The occupancies the members at `leaves` hold.
fn at(sim: &Sim, leaves: &[u32]) -> Vec<Occupancy> {
    leaves
        .iter()
        .map(|leaf| sim.ds.state().tree.occupancy(*leaf).unwrap())
        .collect()
}

/// `commit`, with the wrap of its first level to `victim`'s leaf replaced by
/// a wrap of another secret, signed again by its committer.
fn cut_off(sim: &mut Sim, commit: &DistrictCommit, victim: Occupancy) -> DistrictCommit {
    let victim_pk = sim
        .ds
        .state()
        .tree
        .leaf(victim.leaf)
        .unwrap()
        .encryption_key
        .clone();
    let (gid, epoch) = (commit.gid, commit.epoch);
    tamper(sim, commit, victim, |wrapped, rng| {
        *wrapped = wrap(
            &gid,
            epoch,
            wrapped.node,
            wrapped.target,
            &victim_pk,
            &[7; 32],
            &[0; 32],
            rng,
        )
        .unwrap();
    })
}

/// `commit`, with the wrap of its first level to `victim`'s leaf changed by
/// `change`, signed again by its committer.
fn tamper(
    sim: &mut Sim,
    commit: &DistrictCommit,
    victim: Occupancy,
    change: impl FnOnce(&mut Wrap, &mut ChaCha20Rng),
) -> DistrictCommit {
    let node = NodeId::of_leaf(victim.leaf, 1);
    let target = NodeId::leaf(victim.leaf);
    let mut wraps = commit.wraps.clone();
    let slot = wraps
        .iter_mut()
        .find(|wrapped| wrapped.node == node && wrapped.target == target)
        .unwrap();
    change(slot, &mut sim.rng);
    DistrictCommit::sign(
        DistrictCommitContent {
            gid: commit.gid,
            epoch: commit.epoch,
            district: commit.district,
            height: commit.height,
            prev_district_hash: commit.prev_district_hash,
            committer: commit.committer,
            changes: commit.changes.clone(),
            updates: commit.updates.clone(),
            wraps,
            district_hash: commit.district_hash,
        },
        sim.members[&commit.committer].identity(),
        &mut sim.rng,
    )
    .unwrap()
}

/// A stand-in for a proof system: the proof of a statement is the hash of
/// its encoding, which checks that the member and the service state the same
/// public inputs. A real verifier runs the public checks and checks a
/// zero-knowledge proof (docs/research/dispute-zk).
struct StandIn;

impl DisputeVerifier for StandIn {
    fn verify(&self, statement: &DisputeStatement, proof: &[u8]) -> bool {
        statement
            .encode()
            .is_ok_and(|encoded| h(&encoded).as_slice() == proof)
    }
}

/// What the stand-in accepts as the proof of `statement`.
fn stand_in_proof(statement: &DisputeStatement) -> Vec<u8> {
    h(&statement.encode().unwrap()).to_vec()
}

#[test]
fn joiners_perform_the_tasks_of_the_window_they_enter() {
    let mut sim = group(67, 16);
    let shape = sim.ds.state().tree.shape();
    // Leaves 1, 14 and 15 are freed, then three devices join and take them:
    // districts 0 and 7, in sub-cities 0 and 3.
    for target in at(&sim, &[1, 14, 15]) {
        remove(&mut sim, target);
    }
    sim.run_window();
    sim.request_joins(3);
    let task = sim.open_window();
    let epoch = task.epoch;
    let joiners: BTreeSet<Occupancy> = [1, 14, 15]
        .into_iter()
        .map(|leaf| Occupancy { leaf, since: epoch })
        .collect();
    // Each district goes to a joiner that takes one of its leaves; the third
    // joiner gets the first city task; members take the rest, and seal.
    assert_eq!(task.committers.len(), 2);
    for (district, committer) in &task.committers {
        assert!(joiners.contains(committer));
        assert_eq!(shape.district_of(committer.leaf), *district);
    }
    let idle: Vec<Occupancy> = joiners
        .iter()
        .copied()
        .filter(|joiner| !task.committers.values().any(|c| c == joiner))
        .collect();
    assert_eq!(idle.len(), 1);
    let first_part = *task.city.keys().next().unwrap();
    assert_eq!(task.city[&first_part], idle[0]);
    assert!(
        task.city
            .iter()
            .filter(|(part, _)| **part != first_part)
            .all(|(_, performer)| performer.since < epoch)
    );
    assert!(task.sealer.since < epoch);
    // A joiner cannot welcome: members welcome the joins.
    assert_eq!(task.welcomes.len(), 3);
    assert!(task.welcomes.iter().all(|w| w.welcomer.since < epoch));
    let epoch = sim.complete_window(&task);
    sim.welcome_and_enter(epoch);
    assert!(sim.joiners.is_empty());
    assert_eq!(sim.members.len(), 16);
    sim.assert_agreement();
    // What a joiner drew is tainted by the occupancy it took.
    let tree = &sim.ds.state().tree;
    for joiner in &joiners {
        assert!(tree.is_member(*joiner));
        assert!(!tree.tainted_by(*joiner).is_empty(), "{joiner:?}");
    }
    let idle = idle[0];
    let root = shape.part_root(first_part);
    assert_eq!(tree.parent(root).unwrap().taint, idle);
    // Removing it re-keys the part it drew.
    remove(&mut sim, idle);
    let task = sim.run_window();
    sim.assert_agreement();
    assert!(task.city.contains_key(&first_part));
    assert!(sim.ds.state().tree.tainted_by(idle).is_empty());
    assert_eq!(sim.members.len(), 15);
}

#[test]
fn a_joiner_performs_only_on_the_state_its_chain_of_seals_gives() {
    let mut sim = group(68, 16);
    let shape = sim.ds.state().tree.shape();
    remove_in(&mut sim, 2);
    // A device anchors on this epoch; the group moves on before it asks.
    let anchor = sim.anchor();
    let device = DeviceIdentity::generate(&mut sim.rng);
    let admission = sim.members[&common::CREATOR]
        .admit(device.public_key(), anchor.epoch + 100, &mut sim.rng)
        .unwrap();
    let not_after = anchor.epoch + 100;
    let joiner = Joiner::new(device, Some(&admission), not_after, anchor, &mut sim.rng).unwrap();
    sim.run_window();
    let reference = sim
        .ds
        .submit_join(joiner.request().clone(), sim.now)
        .unwrap();
    sim.joiners.insert(reference, joiner);
    let task = sim.open_window();
    let occupancy = sim.joiners[&reference].occupancy_in(&task).unwrap();
    let district = shape.district_of(occupancy.leaf);
    assert_eq!(task.committers[&district], occupancy);
    let (_, requests, _) = sim.ds.open_window_data().unwrap();
    let requests = requests.clone();
    let state = sim.ds.state().clone();
    // Its chain of seals stops an epoch short: it trusts no state yet.
    assert!(
        sim.joiners[&reference]
            .commit_district(&state, &task, district, &requests, &mut sim.rng)
            .is_err()
    );
    // Once it has followed the chain, it refuses a state that differs from
    // the last seal's.
    sim.ready_joiner(&task, occupancy);
    let mut forged = state.clone();
    forged.interim = [9; 32];
    assert!(
        sim.joiners[&reference]
            .commit_district(&forged, &task, district, &requests, &mut sim.rng)
            .is_err()
    );
    // Its device key is that of its join, which the checks verify; an
    // occupancy [leaf, n] without a join of the window is no performer.
    let window = task.window(&state).unwrap();
    let sealer = check_sealer(
        &state,
        &window,
        SealKind::Member,
        task.sealer,
        None,
        &requests,
    )
    .unwrap();
    let device_pk = sim.joiners[&reference].request().device_pk.clone();
    assert_eq!(
        check_committer(&state, &window, occupancy, &sealer, &requests).unwrap(),
        device_pk
    );
    let stranger = Occupancy {
        leaf: occupancy.leaf ^ 1,
        since: task.epoch,
    };
    assert!(check_committer(&state, &window, stranger, &sealer, &requests).is_err());
    let mut missing = requests.clone();
    missing.remove(&reference);
    assert!(check_committer(&state, &window, occupancy, &sealer, &missing).is_err());
    // A commit in its name signed by another device is refused.
    let impostor = DeviceIdentity::generate(&mut sim.rng);
    let (forged_commit, _) = build_district(
        &state,
        &window,
        district,
        &requests,
        occupancy,
        &impostor,
        &[0; 32],
        &mut sim.rng,
    )
    .unwrap();
    assert!(sim.ds.submit_district_commit(forged_commit).is_err());
    // It commits on the real state, and enters.
    let epoch = sim.complete_window(&task);
    sim.welcome_and_enter(epoch);
    assert!(sim.joiners.is_empty());
    assert!(sim.members.contains_key(&occupancy));
    sim.assert_agreement();
}

#[test]
fn a_failed_joiner_is_replaced_by_a_member_that_welcomes_it() {
    let mut sim = group(69, 16);
    let shape = sim.ds.state().tree.shape();
    remove_in(&mut sim, 3);
    sim.run_window();
    let references = sim.request_joins(1);
    let task = sim.open_window();
    let joiner = sim.joiners[&references[0]].occupancy_in(&task).unwrap();
    let district = shape.district_of(joiner.leaf);
    assert_eq!(task.committers[&district], joiner);
    let welcomer = task.welcomes[0].welcomer;
    assert!(welcomer.since < task.epoch);
    // The joiner's commit does not come; the district goes to a member,
    // which now welcomes the join as the committer of its district.
    let busy: BTreeSet<Occupancy> = task
        .committers
        .values()
        .chain(task.city.values())
        .chain([&task.sealer])
        .copied()
        .collect();
    let replacement = *sim
        .members
        .keys()
        .find(|member| !busy.contains(member) && **member != welcomer)
        .unwrap();
    sim.ready_joiner(&task, joiner);
    let (_, requests, _) = sim.ds.open_window_data().unwrap();
    let requests = requests.clone();
    let late = sim.joiners[&references[0]]
        .commit_district(sim.ds.state(), &task, district, &requests, &mut sim.rng)
        .unwrap();
    let task = sim.ds.reassign(district, replacement).unwrap();
    assert_eq!(task.committers[&district], replacement);
    assert_eq!(task.welcomes[0].welcomer, replacement);
    assert!(sim.ds.submit_district_commit(late).is_err());
    assert!(
        sim.joiners[&references[0]]
            .commit_district(sim.ds.state(), &task, district, &requests, &mut sim.rng)
            .is_err()
    );
    let epoch = sim.complete_window(&task);
    sim.welcome_and_enter(epoch);
    assert!(sim.joiners.is_empty());
    assert!(sim.members.contains_key(&joiner));
    assert_eq!(sim.members.len(), 16);
    sim.assert_agreement();
}

#[test]
fn a_member_welcomes_a_join_only_from_its_own_commit_or_a_joiners() {
    let mut sim = group(70, 16);
    remove_in(&mut sim, 1);
    sim.run_window();
    // Members commit this window: the join is in a member's commit.
    sim.set_joiner_tasks(false);
    sim.request_joins(1);
    let task = sim.open_window();
    let committer = task.welcomes[0].welcomer;
    assert!(task.committers.values().any(|c| *c == committer));
    let epoch = sim.complete_window(&task);
    let stored = sim.ds.window(epoch).unwrap().clone();
    // Another member asked to welcome it refuses: it did not commit it, and
    // no joiner did.
    let other = *sim
        .members
        .keys()
        .find(|member| **member != committer && sim.member(**member).epoch() == epoch)
        .unwrap();
    let mut asked = stored.task.clone();
    asked.welcomes[0].welcomer = other;
    assert!(
        sim.members[&other]
            .welcomes(
                sim.ds.state(),
                &stored.seal,
                &stored.commits,
                &asked,
                &stored.requests,
                &stored.catch_ups,
                &mut sim.rng,
            )
            .is_err()
    );
    sim.welcome_and_enter(epoch);
    assert!(sim.joiners.is_empty());
    sim.assert_agreement();
}

#[test]
fn a_welcomer_takes_the_init_key_of_the_request_the_commit_names() {
    let mut sim = group(72, 16);
    remove_in(&mut sim, 1);
    sim.run_window();
    sim.request_joins(1);
    let task = sim.open_window();
    let welcomer = task.welcomes[0].welcomer;
    let epoch = sim.complete_window(&task);
    let stored = sim.ds.window(epoch).unwrap().clone();
    // The service hands the welcomer, for the join the commit names, a
    // join of its own with its init key. Requests are filed under their own
    // reference: the named one is not among them, and the welcomer refuses
    // rather than seal the joiner secret to the service's key.
    let named = task.welcomes[0].request;
    let device = DeviceIdentity::generate(&mut sim.rng);
    let card = CardKey::generate(&mut sim.rng).card();
    let own = JoinRequest::sign(
        &stored.seal.header.gid,
        &device,
        LeafKeys {
            encryption_key: &KemSecret::generate(&mut sim.rng).public_key(),
            card: &card,
        },
        &KemSecret::generate(&mut sim.rng).public_key(),
        epoch + 10,
        None,
        &mut sim.rng,
    )
    .unwrap();
    let handed: Requests = stored
        .requests
        .values()
        .filter(|request| request.reference() != named)
        .cloned()
        .chain([Request::Join(own)])
        .collect();
    assert!(handed.get(&named).is_none());
    let welcome = |requests: &Requests, sim: &mut Sim| {
        sim.members[&welcomer].welcomes(
            sim.ds.state(),
            &stored.seal,
            &stored.commits,
            &stored.task,
            requests,
            &stored.catch_ups,
            &mut sim.rng,
        )
    };
    assert!(welcome(&handed, &mut sim).is_err());
    assert!(welcome(&stored.requests, &mut sim).is_ok());
    sim.welcome_and_enter(epoch);
    assert!(sim.joiners.is_empty());
    sim.assert_agreement();
}

#[test]
fn a_sealer_refuses_a_task_whose_wrap_opens_to_another_secret() {
    let mut sim = group(71, 16);
    remove_in(&mut sim, 0);
    let task = sim.open_window();
    commit_districts(&mut sim, &task, |_| true);
    let subcities: Vec<CityPart> = task
        .city
        .keys()
        .copied()
        .filter(|part| *part != CityPart::Top)
        .collect();
    for part in subcities {
        let city_task = perform(&mut sim, &task, part);
        sim.ds.submit_city_task(city_task).unwrap();
    }
    // The top's performer wraps another secret to the sealer's sub-city,
    // and signs: nobody but a holder of that sub-city's root can tell.
    let honest = perform(&mut sim, &task, CityPart::Top);
    let sealer = task.sealer;
    let node = NodeId::of_leaf(sealer.leaf, 3);
    let target = NodeId::of_leaf(sealer.leaf, 2);
    let target_pk = sim
        .ds
        .open_city_tasks()
        .iter()
        .flat_map(|city_task| city_task.updates.iter())
        .find(|update| update.node == target)
        .and_then(|update| update.public_key.clone())
        .or_else(|| sim.ds.state().tree.public_key(target).map(<[u8]>::to_vec))
        .unwrap();
    let mut wraps = honest.wraps.clone();
    let slot = wraps
        .iter_mut()
        .find(|wrapped| wrapped.node == node && wrapped.target == target)
        .unwrap();
    *slot = wrap(
        &honest.gid,
        honest.epoch,
        node,
        target,
        &target_pk,
        &[7; 32],
        &[0; 32],
        &mut sim.rng,
    )
    .unwrap();
    let faulty = CityTask::sign(
        CityTaskContent {
            gid: honest.gid,
            epoch: honest.epoch,
            part: honest.part,
            height: honest.height,
            prev_part_hash: honest.prev_part_hash,
            performer: honest.performer,
            updates: honest.updates.clone(),
            wraps,
            part_hash: honest.part_hash,
        },
        sim.members[&honest.performer].identity(),
        &mut sim.rng,
    )
    .unwrap();
    sim.ds.submit_city_task(faulty).unwrap();
    // The sealer follows it to a secret whose key is not the published one,
    // and does not seal.
    if !sim.members[&sealer].knows_path() {
        let steps = sim.ds.refresh_steps(sealer).unwrap();
        sim.members
            .get_mut(&sealer)
            .unwrap()
            .refresh(&steps)
            .unwrap();
    }
    let (_, requests, _) = sim.ds.open_window_data().unwrap();
    let requests = requests.clone();
    let commits = sim.ds.open_commits();
    let city_tasks = sim.ds.open_city_tasks();
    let work = WindowWork {
        commits: &commits,
        city_tasks: &city_tasks,
        requests: &requests,
    };
    assert_eq!(
        sim.members[&sealer]
            .seal(sim.ds.state(), &task, &work, &mut sim.rng)
            .unwrap_err(),
        CoreError::Invalid("path key differs from the published one")
    );
    // The top goes to another performer, and the window completes.
    let busy: BTreeSet<Occupancy> = task
        .committers
        .values()
        .chain(task.city.values())
        .chain([&sealer])
        .copied()
        .collect();
    let replacement = *sim
        .members
        .keys()
        .find(|member| !busy.contains(member) && sim.ds.accepts_from(**member))
        .unwrap();
    let task = sim.ds.reassign_city(CityPart::Top, replacement).unwrap();
    let top = perform(&mut sim, &task, CityPart::Top);
    sim.ds.submit_city_task(top).unwrap();
    seal_and_follow(&mut sim, &task);
    sim.assert_agreement();
    assert_eq!(sim.members.len(), 15);
}

/// A window in which one device joins the leaf a removal freed in
/// sub-city 1; the window is sealed and followed, and its welcome sealed.
/// Returns the join's request and the joiner's anchor.
fn joined_window(seed: u64) -> (Sim, [u8; 32], u64) {
    let mut sim = group(seed, 16);
    remove_in(&mut sim, 1);
    sim.run_window();
    let reference = sim.request_joins(1)[0];
    let task = sim.open_window();
    let epoch = sim.complete_window(&task);
    sim.seal_welcomes(epoch);
    let anchor = sim.joiners[&reference].anchor().epoch;
    (sim, reference, anchor)
}

#[test]
fn a_joiner_enters_by_island_through_the_relay_of_its_island() {
    let (mut sim, reference, anchor) = joined_window(73);
    let shape = sim.ds.state().tree.shape();
    let entry = sim
        .ds
        .island_entry(&reference, anchor, TopChoice::Best)
        .unwrap();
    let whole = sim.ds.entry(&reference, anchor).unwrap();
    // Its path up to its island root, the root's node, and the relay
    // element of its island, instead of its whole path.
    let top = entry.top.clone().unwrap();
    assert!(matches!(top.top, Top::Relay(_)));
    assert!(
        entry
            .steps
            .keys()
            .all(|level| *level <= shape.island_level())
    );
    assert_eq!(entry.nodes.len(), usize::from(shape.island_level()));
    assert!(whole.top.is_none() && whole.nodes.len() == usize::from(shape.height));
    assert!(entry.encoded_len() < whole.encoded_len());
    let joiner = &sim.joiners[&reference];
    joiner.check_entry(&entry).unwrap();
    // A root node the leaf proof does not cover, a relay element that does
    // not open, or the element of another island are refused.
    let mut forged = entry.clone();
    let mut root = top.root.clone();
    root.encryption_key = entry.nodes[0].clone().unwrap().encryption_key;
    forged.top.as_mut().unwrap().root = root;
    assert!(joiner.check_entry(&forged).is_err());
    let mut forged = entry.clone();
    let context = RelayContext {
        gid: sim.ds.state().gid,
        epoch: entry.welcome.epoch,
        island_bits: shape.island_bits,
        island: shape.island_of(entry.leaf.index),
        interim: [9; 32],
    };
    forged.top.as_mut().unwrap().top =
        Top::Relay(RelayElement::seal(&context, &[9; 32], &[9; 32]).unwrap());
    assert!(joiner.check_entry(&forged).is_err());
    let other = *sim
        .members
        .keys()
        .find(|member| shape.island_of(member.leaf) != shape.island_of(entry.leaf.index))
        .unwrap();
    let elsewhere = sim
        .ds
        .island_packet(entry.welcome.epoch, other, TopChoice::Best)
        .unwrap()
        .top
        .unwrap();
    let mut forged = entry.clone();
    forged.top.as_mut().unwrap().top = elsewhere;
    assert!(joiner.check_entry(&forged).is_err());
    let mut forged = entry.clone();
    forged.steps.clear();
    assert!(joiner.check_entry(&forged).is_err());
    // It enters as an island follower, and follows the next window so.
    sim.enter_joiners();
    assert!(sim.joiners.is_empty());
    let occupancy = Occupancy {
        leaf: entry.leaf.index,
        since: entry.welcome.epoch,
    };
    assert!(!sim.member(occupancy).knows_path());
    sim.assert_agreement();
    remove_in(&mut sim, 3);
    sim.run_window();
    sim.assert_agreement();
    assert_eq!(sim.member(occupancy).epoch(), sim.ds.epoch());
}

#[test]
fn an_entrant_falls_back_to_its_whole_path_when_its_relay_lies() {
    let mut sim = group(74, 16);
    remove_in(&mut sim, 1);
    sim.run_window();
    let reference = sim.request_joins(1)[0];
    let task = sim.open_window();
    let epoch = sim.seal_window(&task);
    let shape = sim.ds.state().tree.shape();
    let leaf = sim.joiners[&reference].occupancy_in(&task).unwrap().leaf;
    let island = shape.island_of(leaf);
    let hostile = sim.ds.window(epoch).unwrap().top_task().relays[&island];
    // The joiner's island relay follows, then sends an element it made up.
    let packet = sim
        .ds
        .island_packet(epoch, hostile, TopChoice::Refresh)
        .unwrap();
    sim.members
        .get_mut(&hostile)
        .unwrap()
        .process(&packet)
        .unwrap();
    let context = RelayContext {
        gid: sim.ds.state().gid,
        epoch,
        island_bits: shape.island_bits,
        island,
        interim: [9; 32],
    };
    let garbage = RelayElement::seal(&context, &[9; 32], &[9; 32]).unwrap();
    sim.ds.submit_relay(hostile, garbage).unwrap();
    sim.follow(epoch);
    sim.seal_welcomes(epoch);
    let anchor = sim.joiners[&reference].anchor().epoch;
    let entry = sim
        .ds
        .island_entry(&reference, anchor, TopChoice::Best)
        .unwrap();
    assert!(sim.joiners[&reference].check_entry(&entry).is_err());
    // The island has no flat element: it takes its whole path instead.
    let fallback = sim
        .ds
        .island_entry(&reference, anchor, TopChoice::AvoidRelay)
        .unwrap();
    assert!(fallback.top.is_none());
    sim.enter_joiners();
    assert!(sim.joiners.is_empty());
    let occupancy = Occupancy { leaf, since: epoch };
    assert!(sim.member(occupancy).knows_path());
    sim.assert_agreement();
}

#[test]
fn a_member_that_a_faulty_commit_cut_off_is_repaired_then_updates() {
    let mut sim = group(75, 16);
    let shape = sim.ds.state().tree.shape();
    let (gone, victim) = (at(&sim, &[8])[0], at(&sim, &[9])[0]);
    // The victim is offline, so that another member commits its district
    // when its neighbour leaves; so is a bystander of another district.
    let bystander = at(&sim, &[3])[0];
    sim.ds.set_online(victim, false);
    sim.ds.set_online(bystander, false);
    remove(&mut sim, gone);
    let task = sim.open_window();
    let district = shape.district_of(victim.leaf);
    let committer = task.committers[&district];
    assert_ne!(committer, victim);
    // The committer wraps another secret to the victim's leaf, and signs.
    let (_, requests, _) = sim.ds.open_window_data().unwrap();
    let requests = requests.clone();
    for (d, c) in &task.committers {
        let mut commit = sim.members[c]
            .commit_district(sim.ds.state(), &task, *d, &requests, &mut sim.rng)
            .unwrap();
        if *d == district {
            commit = cut_off(&mut sim, &commit, victim);
        }
        sim.ds.submit_district_commit(commit).unwrap();
    }
    sim.perform_city_tasks(&task);
    let seal = sim.seal_open(&task);
    let epoch = sim.ds.submit_seal(seal).unwrap();
    sim.absent.insert(victim);
    sim.absent.insert(bystander);
    sim.follow(epoch);
    sim.welcome_and_enter(epoch);
    // The bystander, whose path the window lets it derive, from its island
    // path and a refresh above it, has nothing to ask for.
    let refresh = sim
        .ds
        .island_packet(epoch, bystander, TopChoice::Refresh)
        .unwrap();
    let (leaf, nodes) = sim.ds.path_proof(bystander).unwrap();
    assert!(matches!(
        sim.members[&bystander].repair_request(&refresh, &leaf, &nodes, &mut sim.rng),
        Err(CoreError::Invalid(reason)) if reason.contains("every key")
    ));
    sim.members
        .get_mut(&bystander)
        .unwrap()
        .process(&refresh)
        .unwrap();
    sim.absent.remove(&bystander);
    // No top and no whole path lets it follow.
    for choice in [TopChoice::Best, TopChoice::AvoidRelay, TopChoice::Refresh] {
        let packet = sim.ds.island_packet(epoch, victim, choice).unwrap();
        assert!(
            sim.members
                .get_mut(&victim)
                .unwrap()
                .process(&packet)
                .is_err()
        );
    }
    let whole = sim.ds.packet(epoch, victim).unwrap();
    assert!(
        sim.members
            .get_mut(&victim)
            .unwrap()
            .process(&whole)
            .is_err()
    );
    // It asks for a repair. Its path, proven against the tree hash, shows
    // that the first level it cannot derive is its leaf's parent, which the
    // committer drew.
    let (leaf, nodes) = sim.ds.path_proof(victim).unwrap();
    let request = sim.members[&victim]
        .repair_request(&whole, &leaf, &nodes, &mut sim.rng)
        .unwrap();
    assert_eq!(request.level, 1);
    assert_eq!(RepairRequest::decode(request.encoded()).unwrap(), request);
    // Only its own device key signs it, and only for the window's seal.
    let impostor = RepairRequest::sign(
        &request.gid,
        epoch,
        &request.seal_hash,
        victim,
        1,
        sim.members[&committer].identity(),
        &mut sim.rng,
    )
    .unwrap();
    assert!(sim.ds.request_repair(&impostor).is_err());
    let stale = RepairRequest::sign(
        &request.gid,
        epoch,
        &[0; 32],
        victim,
        1,
        sim.members[&victim].identity(),
        &mut sim.rng,
    )
    .unwrap();
    assert!(sim.ds.request_repair(&stale).is_err());
    assert_eq!(sim.ds.blame(committer), 0);
    // The service counts it against the committer and asks a member of the
    // epoch, neither the victim nor the committer.
    let maker = sim.ds.request_repair(&request).unwrap().expect("a maker");
    assert!(maker != victim && maker != committer);
    assert_eq!(sim.ds.blame(committer), 1);
    assert!(!sim.ds.is_excluded(committer));
    // It keeps the repair of that maker alone, addressed to the victim's leaf.
    let other = *sim
        .members
        .keys()
        .find(|member| ![victim, maker].contains(*member) && sim.member(**member).epoch() == epoch)
        .unwrap();
    let unasked = sim.members[&other]
        .repair(sim.ds.state(), victim.leaf, &mut sim.rng)
        .unwrap();
    assert!(sim.ds.submit_repair(other, unasked).is_err());
    let elsewhere = sim.members[&maker]
        .repair(sim.ds.state(), victim.leaf ^ 2, &mut sim.rng)
        .unwrap();
    let mut misdirected = elsewhere.clone();
    misdirected.leaf = victim.leaf;
    let repair = sim.members[&maker]
        .repair(sim.ds.state(), victim.leaf, &mut sim.rng)
        .unwrap();
    assert!(sim.ds.submit_repair(maker, misdirected).is_err());
    sim.ds.submit_repair(maker, repair.clone()).unwrap();
    let packet = sim.ds.repair_packet(epoch, victim).unwrap();
    assert!(packet.path.is_empty());
    sim.members
        .get_mut(&victim)
        .unwrap()
        .process(&packet)
        .unwrap();
    sim.absent.remove(&victim);
    sim.assert_agreement();
    // It holds the epoch but no valid path, and asks for an update at once.
    assert!(sim.member(victim).needs_update());
    assert!(!sim.member(victim).knows_path());
    let request = sim
        .members
        .get_mut(&victim)
        .unwrap()
        .update_request(&mut sim.rng)
        .unwrap();
    assert!(!sim.member(victim).needs_update());
    sim.ds.submit_update(request, sim.now).unwrap();
    // The window of its update re-keys its path: it follows as usual.
    sim.run_window();
    sim.assert_agreement();
    assert_eq!(sim.member(victim).epoch(), sim.ds.epoch());
    assert!(!sim.member(victim).needs_update());
    // And a repair encodes and decodes.
    assert_eq!(
        cityg_core::top::Repair::decode(&repair.encode().unwrap()).unwrap(),
        repair
    );
}

#[test]
fn a_performer_two_members_blame_gets_no_role_until_pardoned() {
    let mut sim = group(73, 16);
    sim.set_joiner_tasks(false);
    let shape = sim.ds.state().tree.shape();
    let faulty = common::CREATOR;
    let gone = at(&sim, &[8, 12]);
    let victims = at(&sim, &[9, 13]);
    let everyone: Vec<Occupancy> = sim.members.keys().copied().collect();
    // Alone online, the creator performs every task of the window that
    // removes two members, and cuts off the other member of each district.
    for member in &everyone {
        sim.ds.set_online(*member, *member == faulty);
    }
    for target in &gone {
        remove(&mut sim, *target);
    }
    let task = sim.open_window();
    assert!(task.committers.values().all(|c| *c == faulty));
    let (_, requests, _) = sim.ds.open_window_data().unwrap();
    let requests = requests.clone();
    for district in task.committers.keys().copied() {
        let mut commit = sim.members[&faulty]
            .commit_district(sim.ds.state(), &task, district, &requests, &mut sim.rng)
            .unwrap();
        if let Some(victim) = victims
            .iter()
            .find(|victim| shape.district_of(victim.leaf) == district)
        {
            commit = cut_off(&mut sim, &commit, *victim);
        }
        sim.ds.submit_district_commit(commit).unwrap();
    }
    sim.perform_city_tasks(&task);
    let seal = sim.seal_open(&task);
    let epoch = sim.ds.submit_seal(seal).unwrap();
    sim.absent.extend(victims.iter().copied());
    sim.follow(epoch);
    for member in &everyone {
        sim.ds
            .set_online(*member, !gone.contains(member) && !victims.contains(member));
    }
    // Each victim asks for its repair, which another member makes.
    let mut requests_made = Vec::new();
    for victim in &victims {
        let whole = sim.ds.packet(epoch, *victim).unwrap();
        assert!(
            sim.members
                .get_mut(victim)
                .unwrap()
                .process(&whole)
                .is_err()
        );
        let (leaf, nodes) = sim.ds.path_proof(*victim).unwrap();
        let request = sim.members[victim]
            .repair_request(&whole, &leaf, &nodes, &mut sim.rng)
            .unwrap();
        let maker = sim.ds.request_repair(&request).unwrap().expect("a maker");
        assert!(maker != faulty && !victims.contains(&maker));
        let repair = sim.members[&maker]
            .repair(sim.ds.state(), victim.leaf, &mut sim.rng)
            .unwrap();
        sim.ds.submit_repair(maker, repair).unwrap();
        let packet = sim.ds.repair_packet(epoch, *victim).unwrap();
        sim.members
            .get_mut(victim)
            .unwrap()
            .process(&packet)
            .unwrap();
        sim.absent.remove(victim);
        requests_made.push(request);
    }
    sim.assert_agreement();
    // Two members blame it: it is excluded. Asking again counts once.
    assert_eq!(sim.ds.blame(faulty), 2);
    assert!(sim.ds.is_excluded(faulty));
    assert!(sim.ds.request_repair(&requests_made[0]).unwrap().is_some());
    assert_eq!(sim.ds.blame(faulty), 2);
    // The repaired members ask for their updates. The next window gives the
    // creator no role, online though it is, nor a district it would take
    // over.
    for victim in &victims {
        let update = sim
            .members
            .get_mut(victim)
            .unwrap()
            .update_request(&mut sim.rng)
            .unwrap();
        sim.ds.submit_update(update, sim.now).unwrap();
    }
    sim.ds.set_online(faulty, true);
    let task = sim.open_window();
    assert!(task.committers.values().all(|c| *c != faulty));
    assert!(task.city.values().all(|p| *p != faulty));
    assert_ne!(task.sealer, faulty);
    let district = *task.committers.keys().next().unwrap();
    assert!(sim.ds.reassign(district, faulty).is_err());
    let epoch = sim.complete_window(&task);
    assert!(
        sim.ds
            .window(epoch)
            .unwrap()
            .top_task()
            .relays
            .values()
            .all(|relay| *relay != faulty)
    );
    sim.assert_agreement();
    for victim in &victims {
        assert!(!sim.member(*victim).needs_update());
    }
    // Pardoned, it may take roles again.
    sim.ds.pardon(faulty);
    assert!(!sim.ds.is_excluded(faulty));
    assert_eq!(sim.ds.blame(faulty), 0);
}

#[test]
fn a_dispute_convicts_the_performer_of_a_faulty_wrap() {
    let mut sim = group(76, 16);
    sim.set_joiner_tasks(false);
    let shape = sim.ds.state().tree.shape();
    let gone = at(&sim, &[8, 12]);
    let victims = at(&sim, &[9, 13]);
    // The victims are offline, so that members commit their districts when
    // their neighbours leave. One committer wraps another secret to the
    // first victim, the other breaks the tag of its wrap to the second.
    for victim in &victims {
        sim.ds.set_online(*victim, false);
    }
    for target in &gone {
        remove(&mut sim, *target);
    }
    let task = sim.open_window();
    let districts: Vec<u32> = victims
        .iter()
        .map(|victim| shape.district_of(victim.leaf))
        .collect();
    let committers: Vec<Occupancy> = districts.iter().map(|d| task.committers[d]).collect();
    let (_, requests, _) = sim.ds.open_window_data().unwrap();
    let requests = requests.clone();
    for (district, committer) in &task.committers {
        let mut commit = sim.members[committer]
            .commit_district(sim.ds.state(), &task, *district, &requests, &mut sim.rng)
            .unwrap();
        if *district == districts[0] {
            commit = cut_off(&mut sim, &commit, victims[0]);
        } else if *district == districts[1] {
            commit = tamper(&mut sim, &commit, victims[1], |wrapped, _| {
                wrapped.sealed[40] ^= 1;
            });
        }
        sim.ds.submit_district_commit(commit).unwrap();
    }
    sim.perform_city_tasks(&task);
    let seal = sim.seal_open(&task);
    let epoch = sim.ds.submit_seal(seal).unwrap();
    sim.absent.extend(victims.iter().copied());
    sim.follow(epoch);
    // Each victim finds the wrap it cannot use, the statement that holds,
    // and the task that holds the wrap.
    let mut claims = Vec::new();
    for (victim, kind) in victims
        .iter()
        .zip([DisputeKind::KeyDiffersShort, DisputeKind::DoesNotOpen])
    {
        let whole = sim.ds.packet(epoch, *victim).unwrap();
        assert!(
            sim.members
                .get_mut(victim)
                .unwrap()
                .process(&whole)
                .is_err()
        );
        let (leaf, nodes) = sim.ds.path_proof(*victim).unwrap();
        let (wrapped, statement) = sim.members[victim]
            .dispute_claim(&whole, &leaf, &nodes)
            .unwrap();
        assert_eq!(statement.kind, kind);
        assert_eq!(wrapped.target, NodeId::leaf(victim.leaf));
        assert_eq!(statement.node_key.is_some(), kind.names_node_key());
        let (task_hash, index) = sim.ds.wrap_origin(wrapped.node, wrapped.target).unwrap();
        claims.push((*victim, whole, task_hash, index, statement));
    }
    let sign = |sim: &mut Sim, claim: usize, index: u32, proof: Vec<u8>| {
        let (victim, whole, task_hash, _, statement) = &claims[claim];
        sim.members[victim]
            .dispute(whole, *task_hash, index, statement, proof, &mut sim.rng)
            .unwrap()
    };
    let (_, _, _, index, statement) = &claims[0];
    let dispute = sign(&mut sim, 0, *index, stand_in_proof(statement));
    // A service without a proof system refuses disputes.
    assert!(sim.ds.submit_dispute(&dispute).is_err());
    sim.ds.set_dispute_verifier(Box::new(StandIn));
    // A proof of another statement, or of a wrap off the member's path,
    // convicts no one.
    let mut other = statement.clone();
    other.kind = DisputeKind::KeyDiffers;
    let unproven = sign(&mut sim, 0, *index, stand_in_proof(&other));
    assert!(sim.ds.submit_dispute(&unproven).is_err());
    let missing = sign(&mut sim, 0, index + 100, stand_in_proof(statement));
    assert!(sim.ds.submit_dispute(&missing).is_err());
    // The sub-city task wraps its root to the victim's district and to the
    // one beside it, which is off the victim's path.
    let district_root = NodeId::of_leaf(victims[0].leaf, 1);
    let beside = NodeId {
        level: 1,
        index: district_root.index ^ 1,
    };
    let (city_task, off_index) = sim
        .ds
        .wrap_origin(NodeId::of_leaf(victims[0].leaf, 2), beside)
        .unwrap();
    let (victim, whole, _, _, statement) = &claims[0];
    let off_path = sim.members[victim]
        .dispute(
            whole,
            city_task,
            off_index,
            statement,
            stand_in_proof(statement),
            &mut sim.rng,
        )
        .unwrap();
    assert!(sim.ds.submit_dispute(&off_path).is_err());
    assert!(!sim.ds.is_convicted(committers[0]));
    // Nor does a dispute signed by another member in the victim's name.
    let (_, whole, task_hash, index, statement) = &claims[0];
    let forged = cityg_core::dispute::Dispute::sign(
        cityg_core::dispute::DisputeContent {
            gid: sim.ds.state().gid,
            epoch,
            seal_hash: whole.header.hash().unwrap(),
            member: victims[0],
            task: *task_hash,
            wrap_index: *index,
            kind: statement.kind,
            proof: stand_in_proof(statement),
        },
        sim.members[&committers[1]].identity(),
        &mut sim.rng,
    )
    .unwrap();
    assert!(sim.ds.submit_dispute(&forged).is_err());
    // The victims' disputes convict both committers, at once excluded.
    assert_eq!(sim.ds.submit_dispute(&dispute).unwrap(), committers[0]);
    let (_, _, _, index, statement) = &claims[1];
    let second = sign(&mut sim, 1, *index, stand_in_proof(statement));
    assert_eq!(sim.ds.submit_dispute(&second).unwrap(), committers[1]);
    for committer in &committers {
        assert!(sim.ds.is_convicted(*committer) && sim.ds.is_excluded(*committer));
        assert_eq!(sim.ds.blame(*committer), 0);
    }
    // The disputes stay with the window, as evidence anyone can check.
    let evidence = sim.ds.window(epoch).unwrap().disputes().to_vec();
    assert_eq!(evidence, vec![dispute.clone(), second]);
    assert_eq!(
        cityg_core::dispute::Dispute::decode(dispute.encoded()).unwrap(),
        dispute
    );
    // The next window gives them no role.
    sim.request_joins(1);
    let next = sim.open_window();
    for committer in &committers {
        assert!(next.committers.values().all(|c| c != committer));
        assert!(next.city.values().all(|p| p != committer));
        assert_ne!(next.sealer, *committer);
    }
    sim.ds.abort_window();
    // Pardoned, they may take roles again; the evidence stays.
    sim.ds.pardon(committers[0]);
    assert!(!sim.ds.is_excluded(committers[0]));
    assert_eq!(sim.ds.window(epoch).unwrap().disputes().len(), 2);
}
