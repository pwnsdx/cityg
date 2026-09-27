//! Stage 1 of the v0.5 draft (docs/specs-v0.5-draft.md section 2): island
//! followers, relays, flat elements, refreshes, and urgent and ordinary
//! removals. Districts of eight leaves (L = 3), islands of two or four.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;

use cityg_core::crypto::kem_pk_hash;
use cityg_core::ds::TopChoice;
use cityg_core::objects::Urgency;
use cityg_core::rekey::WindowIndex;
use cityg_core::roles::WindowWork;
use cityg_core::top::{RelayContext, RelayElement, Top};
use cityg_core::tree::Occupancy;
use common::Sim;

/// A group of `size` members whose members follow by island.
fn group(island_bits: u8, seed: u64, size: usize) -> Sim {
    let mut sim = Sim::with_islands(3, island_bits, seed);
    let mut joined = 1;
    while joined < size {
        let count = (size - joined).min(15);
        sim.request_joins(count);
        sim.run_window();
        joined += count;
    }
    sim.assert_agreement();
    sim
}

fn island_of(sim: &Sim, member: Occupancy) -> u32 {
    sim.ds.state().tree.shape().island_of(member.leaf)
}

/// A member other than the creator updates its leaf key.
fn some_update(sim: &mut Sim, member: Occupancy) {
    let request = sim
        .members
        .get_mut(&member)
        .unwrap()
        .update_request(&mut sim.rng)
        .unwrap();
    sim.ds.submit_update(request, sim.now).unwrap();
}

#[test]
fn island_followers_take_the_root_from_their_relays() {
    let mut sim = group(2, 41, 32);
    let shape = sim.ds.state().tree.shape();
    assert!(shape.has_city() && shape.has_islands() && shape.island_count() == 8);
    // A window of removals, joins and an update among 32 members.
    let targets: Vec<Occupancy> = sim
        .members
        .keys()
        .copied()
        .filter(|member| *member != common::CREATOR)
        .step_by(9)
        .take(3)
        .collect();
    for target in &targets {
        let proposal = sim.members[&common::CREATOR]
            .remove_proposal(*target, Urgency::Urgent, &mut sim.rng)
            .unwrap();
        sim.ds.submit_removal(proposal, sim.now).unwrap();
    }
    let updater = *sim.members.keys().nth(20).unwrap();
    some_update(&mut sim, updater);
    sim.request_joins(2);
    let before: BTreeSet<Occupancy> = sim.members.keys().copied().collect();
    sim.run_window();
    sim.assert_agreement();
    let epoch = sim.ds.epoch();
    let stored = sim.ds.window(epoch).unwrap();
    let task = stored.top_task();
    // Every island has an online member: each has a relay, and every relay
    // sent its element.
    assert_eq!(task.relays.len(), 8);
    assert!(task.flats.is_empty());
    assert_eq!(stored.topped_islands().len(), 8);
    let relays: BTreeSet<Occupancy> = task.relays.values().copied().collect();
    // Island packets carry no step above the island root, and a relay
    // element; in all they weigh less than the members' whole paths.
    let (mut island_bytes, mut whole_bytes) = (0, 0);
    for (member, state) in &sim.members {
        let island = sim
            .ds
            .island_packet(epoch, *member, TopChoice::Best)
            .unwrap();
        assert!(
            island
                .path
                .keys()
                .all(|level| *level <= shape.island_level())
        );
        assert!(matches!(island.top, Some(Top::Relay(_))));
        island_bytes += island.encoded_len();
        whole_bytes += sim.ds.packet(epoch, *member).unwrap().encoded_len();
        // Members that followed from a relay element hold their island path
        // only; the relays refreshed theirs, and the joiners entered with
        // their whole path.
        let joined = !before.contains(member);
        assert_eq!(
            state.knows_path(),
            relays.contains(member) || joined,
            "{member:?}"
        );
    }
    assert!(island_bytes < whole_bytes);
    // The next window goes the same way, the joiners now island followers.
    sim.request_joins(1);
    sim.run_window();
    sim.assert_agreement();
}

#[test]
fn a_relay_element_opens_only_under_the_transcript_of_its_window() {
    // The branches of a fork share the epoch and the islands a window leaves
    // alone. A relay element binds the interim transcript hash of its epoch,
    // which covers the seal and the tag: under another tag, as when an
    // insider leads a member into a root of its choice under the real seal,
    // the element does not open (docs/specs-v0.5-draft.md section 2.3).
    let mut sim = group(2, 47, 16);
    let updater = *sim.members.keys().nth(5).unwrap();
    some_update(&mut sim, updater);
    let task = sim.open_window();
    let epoch = sim.seal_window(&task);
    sim.make_tops(epoch);
    let relays: BTreeSet<Occupancy> = sim
        .ds
        .window(epoch)
        .unwrap()
        .top_task()
        .relays
        .values()
        .copied()
        .collect();
    let follower = *sim
        .members
        .keys()
        .find(|member| !relays.contains(*member) && sim.members[*member].epoch() + 1 == epoch)
        .unwrap();
    let packet = sim
        .ds
        .island_packet(epoch, follower, TopChoice::Best)
        .unwrap();
    assert!(matches!(packet.top, Some(Top::Relay(_))));
    let mut forked = packet.clone();
    forked.tag[0] ^= 1;
    let member = sim.members.get_mut(&follower).unwrap();
    assert_eq!(
        member.process(&forked).unwrap_err(),
        cityg_core::CoreError::Decrypt("relay element")
    );
    member.process(&packet).unwrap();
    assert_eq!(member.epoch(), epoch);
}

#[test]
fn an_island_with_no_member_online_gets_a_flat_element() {
    let mut sim = group(2, 42, 16);
    // The members of island 1 go offline; they still follow when they look.
    let quiet: Vec<Occupancy> = sim
        .members
        .keys()
        .copied()
        .filter(|member| island_of(&sim, *member) == 1)
        .collect();
    assert_eq!(quiet.len(), 4);
    for member in &quiet {
        sim.ds.set_online(*member, false);
    }
    let updater = *sim.members.keys().nth(1).unwrap();
    some_update(&mut sim, updater);
    sim.run_window();
    sim.assert_agreement();
    let epoch = sim.ds.epoch();
    let task = sim.ds.window(epoch).unwrap().top_task().clone();
    assert!(!task.relays.contains_key(&1));
    let (maker, _) = task
        .flats
        .iter()
        .find(|(_, islands)| islands.contains(&1))
        .expect("island 1 has a flat element");
    assert!(task.relays.values().any(|relay| relay == maker));
    let packet = sim
        .ds
        .island_packet(epoch, quiet[0], TopChoice::Best)
        .unwrap();
    assert!(matches!(packet.top, Some(Top::Flat(_))));
    // Only the member asked for it may deliver it.
    let flats = match packet.top {
        Some(Top::Flat(flat)) => vec![flat],
        _ => Vec::new(),
    };
    assert!(sim.ds.submit_flats(quiet[1], epoch, flats).is_err());
}

#[test]
fn a_relay_that_sends_garbage_only_makes_its_island_fall_back() {
    let mut sim = group(2, 43, 16);
    let updater = *sim.members.keys().nth(2).unwrap();
    some_update(&mut sim, updater);
    let task = sim.open_window();
    let epoch = sim.seal_window(&task);
    let top = sim.ds.window(epoch).unwrap().top_task().clone();
    let (&island, &hostile) = top.relays.iter().nth(2).unwrap();
    // The hostile relay follows, then sends an element under a key it made
    // up; the service cannot tell.
    let packet = sim
        .ds
        .island_packet(epoch, hostile, TopChoice::Refresh)
        .unwrap();
    sim.members
        .get_mut(&hostile)
        .unwrap()
        .process(&packet)
        .unwrap();
    let gid = sim.ds.state().gid;
    let context = RelayContext {
        gid,
        epoch,
        island_bits: 2,
        island,
        interim: [9; 32],
    };
    let garbage = RelayElement::seal(&context, &[9; 32], &[9; 32]).unwrap();
    sim.ds.submit_relay(hostile, garbage.clone()).unwrap();
    // No one but the island's relay may send its element.
    let victim = *sim
        .members
        .keys()
        .find(|member| island_of(&sim, **member) == island && **member != hostile)
        .unwrap();
    assert!(sim.ds.submit_relay(victim, garbage).is_err());
    // The other relays act as usual.
    sim.make_tops(epoch);
    // The element does not open for the island's members, and a failed
    // packet changes nothing: the member falls back to a refresh (the
    // island has no flat element).
    let packet = sim
        .ds
        .island_packet(epoch, victim, TopChoice::Best)
        .unwrap();
    assert!(matches!(packet.top, Some(Top::Relay(_))));
    assert!(
        sim.members
            .get_mut(&victim)
            .unwrap()
            .process(&packet)
            .is_err()
    );
    assert_eq!(sim.member(victim).epoch() + 1, epoch);
    let fallback = sim
        .ds
        .island_packet(epoch, victim, TopChoice::AvoidRelay)
        .unwrap();
    assert!(matches!(fallback.top, Some(Top::Refresh(_))));
    sim.members
        .get_mut(&victim)
        .unwrap()
        .process(&fallback)
        .unwrap();
    // Everyone else follows, the rest of the island falling back too.
    sim.follow(epoch);
    sim.welcome_and_enter(epoch);
    sim.assert_agreement();
}

#[test]
fn an_island_follower_replays_the_windows_it_missed() {
    let mut sim = group(2, 44, 16);
    let away = *sim.members.keys().nth(5).unwrap();
    sim.absent.insert(away);
    sim.ds.set_online(away, false);
    // A window with relays, one where the away member's island has none (a
    // flat element), an entrant window without any relay, and one more.
    let mate: Vec<Occupancy> = sim
        .members
        .keys()
        .copied()
        .filter(|member| *member != away && island_of(&sim, *member) == island_of(&sim, away))
        .collect();
    let updater = *sim.members.keys().nth(1).unwrap();
    some_update(&mut sim, updater);
    sim.run_window();
    for member in &mate {
        sim.ds.set_online(*member, false);
    }
    sim.request_joins(1);
    sim.run_window();
    let flat_epoch = sim.ds.epoch();
    sim.set_all_online(false);
    sim.request_joins(1);
    sim.run_entrant_window();
    let bare_epoch = sim.ds.epoch();
    assert!(
        sim.ds
            .window(bare_epoch)
            .unwrap()
            .top_task()
            .relays
            .is_empty()
    );
    sim.set_all_online(true);
    sim.ds.set_online(away, false);
    sim.request_joins(1);
    sim.run_window();
    assert_eq!(sim.member(away).epoch() + 4, sim.ds.epoch());
    // What the away member gets for the windows it missed.
    let flat = sim
        .ds
        .island_packet(flat_epoch, away, TopChoice::Best)
        .unwrap();
    assert!(matches!(flat.top, Some(Top::Flat(_))));
    let bare = sim
        .ds
        .island_packet(bare_epoch, away, TopChoice::Best)
        .unwrap();
    assert!(matches!(bare.top, Some(Top::Refresh(_))));
    sim.replay(away);
    sim.assert_agreement();
}

#[test]
fn a_sealer_without_a_city_refreshes_its_path_first() {
    // Districts of eight leaves and islands of two: a group of seven has no
    // city, and its sealer takes the root from the district commit along
    // its own path.
    let mut sim = group(1, 45, 7);
    let mut refreshed = false;
    for round in 0..6 {
        let updater = *sim.members.keys().nth(1 + round % 5).unwrap();
        some_update(&mut sim, updater);
        let task = sim.open_window();
        assert!(!sim.ds.state().tree.shape().has_city());
        let sealer = task.sealer;
        if !sim.member(sealer).knows_path() {
            // Without its path the sealer cannot seal; the latest re-key of
            // each node above its island gives it back, and must lead to the
            // root it holds.
            let (_, requests, _) = sim.ds.open_window_data().unwrap();
            let requests = requests.clone();
            for (district, committer) in &task.committers {
                let commit = sim.members[committer]
                    .commit_district(sim.ds.state(), &task, *district, &requests, &mut sim.rng)
                    .unwrap();
                sim.ds.submit_district_commit(commit).unwrap();
            }
            let commits = sim.ds.open_commits();
            let work = WindowWork {
                commits: &commits,
                city_tasks: &[],
                requests: &requests,
            };
            assert!(
                sim.members[&sealer]
                    .seal(sim.ds.state(), &task, &work, &mut sim.rng)
                    .is_err()
            );
            let other = *sim
                .members
                .keys()
                .find(|member| island_of(&sim, **member) != island_of(&sim, sealer))
                .unwrap();
            let wrong = sim.ds.refresh_steps(other).unwrap();
            assert!(
                sim.members
                    .get_mut(&sealer)
                    .unwrap()
                    .refresh(&wrong)
                    .is_err()
            );
            let steps = sim.ds.refresh_steps(sealer).unwrap();
            let member = sim.members.get_mut(&sealer).unwrap();
            member.refresh(&steps).unwrap();
            assert!(member.knows_path());
            let seal = member
                .seal(sim.ds.state(), &task, &work, &mut sim.rng)
                .unwrap();
            let epoch = sim.ds.submit_seal(seal).unwrap();
            sim.follow(epoch);
            sim.welcome_and_enter(epoch);
            refreshed = true;
        } else {
            let epoch = sim.complete_window(&task);
            sim.welcome_and_enter(epoch);
        }
        sim.assert_agreement();
    }
    assert!(refreshed, "some window had a sealer without its path");
}

#[test]
fn ordinary_removals_wait_for_the_scheduled_window() {
    let mut sim = Sim::new(2, 46);
    sim.request_joins(4);
    sim.run_window();
    let config = *sim.ds.config();
    let leaving = *sim.members.keys().nth(1).unwrap();
    let removed = *sim.members.keys().nth(2).unwrap();
    // A member leaves: an ordinary removal. It is enforced at delivery at
    // once, but does not close a window within WINDOW_URGENT, and nobody
    // stops sending.
    let departure = sim.members[&leaving]
        .remove_proposal(leaving, Urgency::Ordinary, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(departure, sim.now).unwrap();
    sim.now += config.window_urgent_ms + 1;
    assert!(!sim.ds.due(sim.now));
    assert!(!sim.ds.accepts_from(leaving));
    let creator = sim.member(common::CREATOR);
    assert!(creator.may_send(&sim.ds.pending_removals(), sim.now, config.window_urgent_ms));
    // An admin removes another member: urgent. The window is due within
    // WINDOW_URGENT, and members do not send once it has waited longer.
    let urgent = sim.members[&common::CREATOR]
        .remove_proposal(removed, Urgency::Urgent, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(urgent, sim.now).unwrap();
    assert!(!sim.ds.due(sim.now + config.window_urgent_ms - 1));
    assert!(sim.ds.due(sim.now + config.window_urgent_ms));
    let later = sim.now + config.window_urgent_ms + 1;
    let pending = sim.ds.pending_removals();
    assert!(
        !sim.member(common::CREATOR)
            .may_send(&pending, later, config.window_urgent_ms)
    );
    // The window applies both.
    sim.run_window();
    assert!(!sim.ds.state().tree.is_member(leaving));
    assert!(!sim.ds.state().tree.is_member(removed));
    sim.assert_agreement();
    // Alone, an ordinary removal is applied by the window its age closes.
    let next = *sim.members.keys().nth(1).unwrap();
    let departure = sim.members[&next]
        .remove_proposal(next, Urgency::Ordinary, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(departure, sim.now).unwrap();
    assert!(!sim.ds.due(sim.now + config.window_ordinary_ms - 1));
    assert!(sim.ds.due(sim.now + config.window_ordinary_ms));
    // An urgent removal of the same member replaces the ordinary one.
    let raised = sim.members[&common::CREATOR]
        .remove_proposal(next, Urgency::Urgent, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(raised, sim.now + 1).unwrap();
    let pending = sim.ds.pending_removals();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].urgency, Urgency::Urgent);
    assert!(sim.ds.due(sim.now + 1 + config.window_urgent_ms));
}

#[test]
fn a_removed_member_opens_no_top_of_the_window_that_removes_it() {
    let mut sim = group(2, 47, 16);
    let removed = *sim
        .members
        .keys()
        .find(|member| island_of(&sim, **member) == 1)
        .unwrap();
    let mate = *sim
        .members
        .keys()
        .find(|member| island_of(&sim, **member) == 1 && **member != removed)
        .unwrap();
    let mut gone = sim.take(removed);
    let proposal = sim.members[&common::CREATOR]
        .remove_proposal(removed, Urgency::Urgent, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(proposal, sim.now).unwrap();
    sim.run_window();
    sim.assert_agreement();
    let epoch = sim.ds.epoch();
    assert!(sim.ds.packet(epoch, removed).is_err());
    // A colluding service hands it what its island mates get: the relay
    // element, the flat element, the refresh. With the window's steps along
    // its old path, or keeping its old island path, nothing opens.
    let stored = sim.ds.window(epoch).unwrap();
    let mut index = WindowIndex::default();
    for commit in &stored.commits {
        index.add(&commit.updates, &commit.wraps);
    }
    for task in &stored.city_tasks {
        index.add(&task.updates, &task.wraps);
    }
    let shape = sim.ds.state().tree.shape();
    let mut steps = index.steps(removed.leaf, shape.height).unwrap();
    steps.retain(|level, _| *level <= shape.island_level());
    let leaf_key = kem_pk_hash(gone.leaf_public_key()).unwrap();
    for choice in [TopChoice::Best, TopChoice::AvoidRelay, TopChoice::Refresh] {
        let mut packet = sim.ds.island_packet(epoch, mate, choice).unwrap();
        packet.leaf_key = leaf_key;
        packet.path.clone_from(&steps);
        assert!(gone.process(&packet).is_err(), "{choice:?}");
        packet.path.clear();
        assert!(gone.process(&packet).is_err(), "{choice:?}, old path");
    }
}

#[test]
fn with_nobody_online_members_follow_an_entrant_window_by_refresh() {
    let mut sim = group(2, 48, 16);
    sim.set_all_online(false);
    sim.request_joins(1);
    sim.run_entrant_window();
    sim.assert_agreement();
    let epoch = sim.ds.epoch();
    let task = sim.ds.window(epoch).unwrap().top_task().clone();
    assert!(task.relays.is_empty() && task.flats.is_empty());
    let member = *sim.members.keys().nth(3).unwrap();
    let packet = sim
        .ds
        .island_packet(epoch, member, TopChoice::Best)
        .unwrap();
    assert!(matches!(packet.top, Some(Top::Refresh(_))));
    assert!(sim.member(member).knows_path());
}

#[test]
fn a_window_that_rekeys_nothing_needs_no_top() {
    let mut sim = group(2, 49, 16);
    // Members follow once by island, so that most hold their island path
    // only.
    let updater = *sim.members.keys().nth(4).unwrap();
    some_update(&mut sim, updater);
    sim.run_window();
    let jumper = *sim.members.keys().nth(6).unwrap();
    let member = sim.take(jumper);
    let interim = sim.ds.state().interim;
    let (returning, request) = member.catch_up(&interim, &mut sim.rng).unwrap();
    let reference = sim.ds.submit_catch_up(request, sim.now).unwrap();
    sim.returning.insert(reference, returning);
    let task = sim.run_window();
    assert!(task.changes.is_empty());
    let epoch = sim.ds.epoch();
    let stored = sim.ds.window(epoch).unwrap();
    assert!(stored.top_task().relays.is_empty());
    let follower = *sim
        .members
        .keys()
        .find(|member| !sim.member(**member).knows_path())
        .expect("an island follower");
    let packet = sim
        .ds
        .island_packet(epoch, follower, TopChoice::Best)
        .unwrap();
    assert!(packet.top.is_none() && packet.path.is_empty());
    assert!(sim.members.contains_key(&jumper));
    sim.assert_agreement();
}
