//! Stage 2 of the v0.5 draft (docs/specs-v0.5-draft.md section 3): the
//! city re-keyed by one task per sub-city and one for the top, and a sealer
//! that draws nothing. Districts of two leaves (L = 1), islands of two
//! (c = 1), sub-cities of two districts (S = 1): sixteen members give four
//! sub-cities under a top of two levels.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;

use cityg_core::objects::Urgency;
use cityg_core::roles::{WindowTask, WindowWork};
use cityg_core::tree::{CityPart, Divisions, Occupancy};
use common::Sim;

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
