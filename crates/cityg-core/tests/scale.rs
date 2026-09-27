//! A window of many changes on a full group, checked against the cost model
//! of `docs/research/rekey_sim.py` (ignored by default; run in release):
//!
//! ```text
//! cargo test -p cityg-core --release --test scale -- --ignored --nocapture
//! CITYG_SCALE_HEIGHT=16 CITYG_SCALE_BITS=12 CITYG_SCALE_CHANGES=4000 cargo test ...
//! ```
//!
//! The group is built directly (every leaf occupied, keyed by one
//! committer); the window goes through the protocol's functions: entries
//! checked by the committers, district commits, the city tasks (sub-cities
//! of `2^CITYG_SCALE_SUBCITY_BITS` districts, 8 by default, and the top
//! above them) and the seal, the delivery service's full check, and one
//! packet per member, whole or by island (`CITYG_SCALE_ISLAND_BITS`, 8 by
//! default).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::cast_precision_loss)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Instant;

use cityg_core::card::{CARD_ML_DSA_65, Card, CardKey, LeafKeys};
use cityg_core::commit::{Change, CityTask};
use cityg_core::crypto::Digest;
use cityg_core::identity::DeviceIdentity;
use cityg_core::kem::KemSecret;
use cityg_core::message::MessageLog;
use cityg_core::objects::{
    Admission, ChangeKind, JoinRequest, RemoveProposal, Request, Urgency, device_id, group_id,
};
use cityg_core::packet::{Packet, RegistryUpdate, SealLink, SealerEvidence};
use cityg_core::registry::{Registry, RegistryDelta};
use cityg_core::rekey::{
    KeySource, LeafChanges, NewRoots, WindowIndex, generate, plan_district, plan_part,
};
use cityg_core::roles::{
    CityTaskInput, SealDraft, WindowWork, build_city_task, build_district, finish_seal, with_city,
};
use cityg_core::top::{RelayContext, RelayElement, Top, flat_element};
use cityg_core::tree::{CityPart, Divisions, LeafNode, Occupancy, PublicTree};
use cityg_core::window::{
    PublicState, Requests, WindowShape, check_districts, check_sealer, check_window, keyed_parents,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

struct Group {
    state: PublicState,
    admin: DeviceIdentity,
    committers: BTreeMap<u32, (Occupancy, DeviceIdentity)>,
}

/// Key a part of the city over the new roots `below` of the tier under it,
/// tainted by `performer`; returns the part's new root key.
fn key_part(
    tree: &mut PublicTree,
    part: CityPart,
    below: &NewRoots,
    gid: &Digest,
    performer: Occupancy,
    rng: &mut ChaCha20Rng,
) -> Option<Vec<u8>> {
    let shape = tree.shape();
    let live = below
        .iter()
        .map(|(index, key)| (*index, key.is_some()))
        .collect();
    let plan = plan_part(tree, shape, part, &live, &BTreeSet::new()).unwrap();
    let empty = LeafChanges::new();
    let keys = KeySource {
        tree,
        shape,
        leaves: &empty,
        below: Some((shape.part_base(part), below)),
    };
    let drawn = generate(&plan, &keys, gid, 0, &[0; 32], rng).unwrap();
    for (node, parent) in keyed_parents(&drawn.updates, performer) {
        tree.set_parent(node, parent).unwrap();
    }
    tree.parent(shape.part_root(part))
        .map(|parent| parent.encryption_key.clone())
}

/// A group of `2^height` members with `divisions`, keyed by one committer
/// (the admin at leaf 0): its districts, then its sub-cities and its top.
fn full_group(height: u8, divisions: Divisions, rng: &mut ChaCha20Rng) -> Group {
    let bits = divisions.district_bits;
    let admin = DeviceIdentity::generate(rng);
    let gid = group_id(admin.public_key(), &[1; 32]).unwrap();
    let mut tree = PublicTree::new(height, divisions).unwrap();
    let shape = tree.shape();
    let admin_occupancy = Occupancy { leaf: 0, since: 0 };
    let mut committers = BTreeMap::new();
    for district in 1..shape.district_count() {
        let leaf = district << bits;
        committers.insert(
            district,
            (Occupancy { leaf, since: 0 }, DeviceIdentity::generate(rng)),
        );
    }
    let mut leaves = LeafChanges::new();
    let mut devices = Vec::new();
    for leaf in 0..(1u32 << height) {
        let device_pk = if leaf == 0 {
            admin.public_key().to_vec()
        } else if let Some((_, identity)) = committers
            .get(&(leaf >> bits))
            .filter(|(o, _)| o.leaf == leaf)
        {
            identity.public_key().to_vec()
        } else {
            // Members that sign nothing here: distinct keys of the right length.
            let mut key = vec![0u8; cityg_pqc::PUBLIC_KEY_BYTES];
            key[..4].copy_from_slice(&leaf.to_be_bytes());
            key
        };
        let id = device_id(&gid, &device_pk).unwrap();
        devices.push((id, Occupancy { leaf, since: 0 }));
        // Cards that sign nothing here: distinct keys of the right length.
        let mut card = vec![1u8; cityg_pqc::PUBLIC_KEY_BYTES];
        card[..4].copy_from_slice(&leaf.to_be_bytes());
        leaves.insert(
            leaf,
            Some(LeafNode {
                device_pk,
                device_id: id,
                since: 0,
                encryption_key: KemSecret::generate(rng).public_key(),
                card: Card {
                    algorithm: CARD_ML_DSA_65,
                    public_key: card,
                },
                admission_hash: [0; 32],
                updated: 0,
            }),
        );
    }
    let mut roots = BTreeMap::new();
    for district in 0..shape.district_count() {
        let root = shape.district_root(district);
        let mine: LeafChanges = leaves
            .iter()
            .filter(|(leaf, _)| root.covers(**leaf))
            .map(|(leaf, node)| (*leaf, node.clone()))
            .collect();
        let plan = plan_district(&tree, shape, district, &mine, &BTreeSet::new()).unwrap();
        let keys = KeySource {
            tree: &tree,
            shape,
            leaves: &mine,
            below: None,
        };
        let drawn = generate(&plan, &keys, &gid, 0, &[0; 32], rng).unwrap();
        for (leaf, node) in &mine {
            tree.set_leaf(*leaf, node.clone()).unwrap();
        }
        for (node, parent) in keyed_parents(&drawn.updates, admin_occupancy) {
            tree.set_parent(node, parent).unwrap();
        }
        roots.insert(
            district,
            tree.parent(root).map(|p| p.encryption_key.clone()),
        );
    }
    let mut subcities = BTreeMap::new();
    for subcity in 0..shape.subcity_count() {
        let below: NewRoots = roots
            .iter()
            .filter(|(district, _)| shape.subcity_of(**district) == subcity)
            .map(|(district, key)| (*district, key.clone()))
            .collect();
        let part = CityPart::SubCity(subcity);
        let key = key_part(&mut tree, part, &below, &gid, admin_occupancy, rng);
        subcities.insert(subcity, key);
    }
    if shape.has_top() {
        key_part(
            &mut tree,
            CityPart::Top,
            &subcities,
            &gid,
            admin_occupancy,
            rng,
        );
    }
    let mut registry = Registry::new();
    let mut delta = RegistryDelta::default();
    delta
        .admins_added
        .insert(admin_occupancy, admin.public_key().to_vec());
    for (id, occupancy) in devices {
        delta.devices.insert(id, Some(occupancy));
    }
    // Every leaf key and card, unique (docs/specs-v0.5-draft.md section 4.2).
    for (leaf, node) in tree.leaves() {
        let occupancy = node.occupancy(leaf);
        delta.keys.insert(node.key_hash().unwrap(), Some(occupancy));
        delta
            .keys
            .insert(node.card.hash().unwrap(), Some(occupancy));
    }
    registry.apply(&delta);
    let state = PublicState {
        gid,
        epoch: 1,
        tree,
        registry,
        policy: None,
        interim: [2; 32],
        external_pk: KemSecret::generate(rng).public_key(),
        time_ms: 0,
    };
    Group {
        state,
        admin,
        committers,
    }
}

/// The model's count (`mark_levels` and `rekey_cost` of rekey_sim.py):
/// chained wraps and new keys of re-keying every ancestor of `changed`,
/// with a boundary above the leaves, the districts and the sub-cities.
fn model_count(
    height: u8,
    divisions: Divisions,
    changed: &[u32],
    blank: &HashSet<u32>,
) -> (usize, usize) {
    let bits = divisions.district_bits;
    let subcity_top = bits + divisions.subcity_bits;
    let mut levels: Vec<HashSet<u32>> = vec![HashSet::new(); usize::from(height) + 1];
    levels[0] = changed.iter().copied().collect();
    for leaf in changed {
        for k in 1..=height {
            if !levels[usize::from(k)].insert(leaf >> k) {
                break;
            }
        }
    }
    let (mut wraps, mut nodes) = (0, 0);
    for k in 1..=height {
        for node in &levels[usize::from(k)] {
            let children: Vec<u32> = [2 * node, 2 * node + 1]
                .into_iter()
                .filter(|c| !(k == 1 && blank.contains(c)))
                .collect();
            let boundary = k == 1 || k == bits + 1 || k == subcity_top + 1;
            let chained = !boundary
                && children
                    .iter()
                    .any(|c| levels[usize::from(k - 1)].contains(c));
            wraps += if chained {
                children.len() - 1
            } else {
                children.len()
            };
            nodes += 1;
        }
    }
    (wraps, nodes)
}

fn human(bytes: f64) -> String {
    if bytes >= 1e6 {
        format!("{:.1} MB", bytes / 1e6)
    } else if bytes >= 1e3 {
        format!("{:.1} KB", bytes / 1e3)
    } else {
        format!("{bytes:.0} B")
    }
}

#[test]
#[ignore = "builds a full group; run in release with --ignored --nocapture"]
fn a_large_window_on_a_full_group_matches_the_model() {
    let height = u8::try_from(env("CITYG_SCALE_HEIGHT", 14)).unwrap();
    let bits = u8::try_from(env("CITYG_SCALE_BITS", 10)).unwrap();
    let changes = usize::try_from(env("CITYG_SCALE_CHANGES", 2000)).unwrap();
    let island_bits = u8::try_from(env("CITYG_SCALE_ISLAND_BITS", 8))
        .unwrap()
        .min(bits);
    let subcity_bits = u8::try_from(env("CITYG_SCALE_SUBCITY_BITS", 8)).unwrap();
    let divisions = Divisions::new(bits, island_bits, subcity_bits).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let start = Instant::now();
    let group = full_group(height, divisions, &mut rng);
    let state = &group.state;
    let n = 1usize << height;
    println!(
        "group: N = 2^{height} = {n}, {} districts of 2^{bits} in {} sub-cities of 2^{subcity_bits}{}, built in {:.1?}",
        state.tree.shape().district_count(),
        state.tree.shape().subcity_count(),
        if state.tree.shape().has_top() {
            " under a top"
        } else {
            ""
        },
        start.elapsed()
    );

    // D/2 removals, and D/2 joins placed in the removed leaves (paired).
    let removals = changes / 2;
    let joins = changes - removals;
    let protected: HashSet<u32> = group
        .committers
        .values()
        .map(|(o, _)| o.leaf)
        .chain([0])
        .collect();
    // The leaves come from a generator of their own, so that the sample does
    // not depend on how much randomness building the group took.
    let mut pick = ChaCha20Rng::seed_from_u64(8);
    let mut removed = Vec::new();
    let mut taken = HashSet::new();
    while removed.len() < removals {
        let leaf = u32::try_from(pick.next_u64() % n as u64).unwrap();
        if !protected.contains(&leaf) && taken.insert(leaf) {
            removed.push(leaf);
        }
    }
    let admin_occupancy = Occupancy { leaf: 0, since: 0 };
    let epoch = state.epoch + 1;
    let mut requests = Requests::new();
    let mut list = Vec::new();
    let start = Instant::now();
    for (index, leaf) in removed.iter().enumerate() {
        let target = Occupancy {
            leaf: *leaf,
            since: 0,
        };
        let proposal = RemoveProposal::sign(
            &state.gid,
            target,
            admin_occupancy,
            Urgency::Urgent,
            &group.admin,
            &mut rng,
        )
        .unwrap();
        let request = Request::Removal(proposal);
        list.push(Change {
            leaf: *leaf,
            kind: ChangeKind::Removal,
            request: request.reference(),
        });
        requests.insert(request);
        if index < joins {
            let device = DeviceIdentity::generate(&mut rng);
            let id = device_id(&state.gid, device.public_key()).unwrap();
            let admission = Admission::by_admin(
                &state.gid,
                &id,
                epoch + 10,
                admin_occupancy,
                &group.admin,
                &mut rng,
            )
            .unwrap();
            let card = CardKey::generate(&mut rng).card();
            let join = JoinRequest::sign(
                &state.gid,
                &device,
                LeafKeys {
                    encryption_key: &KemSecret::generate(&mut rng).public_key(),
                    card: &card,
                },
                &KemSecret::generate(&mut rng).public_key(),
                epoch + 10,
                Some(&admission),
                &mut rng,
            )
            .unwrap();
            let request = Request::Join(join);
            list.push(Change {
                leaf: *leaf,
                kind: ChangeKind::Join,
                request: request.reference(),
            });
            requests.insert(request);
        }
    }
    list.sort();
    println!(
        "window: {removals} removals and {joins} paired joins, requests signed in {:.1?}",
        start.elapsed()
    );
    let shape = state.tree.shape();
    let window = WindowShape::new(&state.tree, epoch, shape, list.iter().copied()).unwrap();

    // District commits (entries checked by each committer).
    let start = Instant::now();
    let mut commits = Vec::new();
    for district in &window.districts {
        let (committer, identity) = match group.committers.get(district) {
            Some((occupancy, identity)) => (*occupancy, identity),
            None => (admin_occupancy, &group.admin),
        };
        let (commit, _) = build_district(
            state, &window, *district, &requests, committer, identity, &[0; 32], &mut rng,
        )
        .unwrap();
        commits.push(commit);
    }
    let district_time = start.elapsed();
    let start = Instant::now();
    let sealer = check_sealer(
        state,
        &window,
        cityg_core::commit::SealKind::Member,
        admin_occupancy,
        None,
        &requests,
    )
    .unwrap();
    let delta = check_districts(state, &window, &commits, &requests, &sealer, false).unwrap();
    // The city tasks, sub-cities first, then the top; one performer here.
    let mut city_tasks: Vec<CityTask> = Vec::new();
    let mut root_secret = None;
    for part in &window.parts {
        let work = WindowWork {
            commits: &commits,
            city_tasks: &city_tasks,
            requests: &requests,
        };
        let (below, before) = work.base(state, &window, *part).unwrap();
        let (task, drawn) = build_city_task(
            &CityTaskInput {
                state,
                window: &window,
                part: *part,
                below: &below,
                before: &before,
                performer: admin_occupancy,
            },
            &group.admin,
            &[0; 32],
            &mut rng,
        )
        .unwrap();
        if let Some(secret) = drawn.secret(shape.root()) {
            root_secret = Some(secret.clone());
        }
        city_tasks.push(task);
    }
    let city_time = start.elapsed();
    let start = Instant::now();
    let root_secret = root_secret.unwrap();
    let sealed = finish_seal(
        SealDraft {
            state,
            window: &window,
            commits: &commits,
            requests: &requests,
            sealer: &sealer,
            entrant: None,
            delta: with_city(delta, &city_tasks),
            city_tasks: &city_tasks,
            policy: None,
            time_ms: 1,
            message_log: MessageLog::empty().unwrap(),
            init_prev: &[3; 32],
            root_secret: &root_secret,
        },
        &group.admin,
        &mut rng,
    )
    .unwrap();
    let seal_time = start.elapsed();
    let start = Instant::now();
    let outcome =
        check_window(state, &commits, &city_tasks, &sealed.seal, &requests, true).unwrap();
    let check_time = start.elapsed();
    assert_eq!(outcome.epoch, epoch);

    // Against the model.
    let city_wraps: usize = city_tasks.iter().map(|task| task.wraps.len()).sum();
    let city_nodes: usize = city_tasks.iter().map(|task| task.updates.len()).sum();
    let wraps: usize = commits.iter().map(|c| c.wraps.len()).sum::<usize>() + city_wraps;
    let nodes: usize = commits.iter().map(|c| c.updates.len()).sum::<usize>() + city_nodes;
    let (model_wraps, model_nodes) = model_count(height, divisions, &removed, &HashSet::new());
    assert_eq!(
        (wraps, nodes),
        (model_wraps, model_nodes),
        "the plan follows the model"
    );
    let d = changes as f64;
    let bound = d * ((n as f64) / d).ln();
    let district_bytes: Vec<usize> = commits.iter().map(|c| c.encoded().len()).collect();
    let busiest = commits.iter().max_by_key(|c| c.wraps.len()).unwrap();
    let model_bytes = |w: usize, k: usize| (w * (1120 + 48) + k * 1216 + 200 + 3309) as f64;
    let busiest_actual = busiest.encoded().len() as f64;
    let busiest_model = model_bytes(busiest.wraps.len(), busiest.updates.len());
    let seal_bytes = sealed.seal.encode().unwrap().len() as f64;
    println!(
        "re-key: {wraps} wraps and {nodes} new keys (model: {model_wraps} and {model_nodes}); lower bound D ln(N/D) = {bound:.0} (x{:.2})",
        wraps as f64 / bound
    );
    println!(
        "district commits: {} commits, {} in all; busiest {} ({} wraps; model {}); committed in {district_time:.1?}",
        commits.len(),
        human(district_bytes.iter().sum::<usize>() as f64),
        human(busiest_actual),
        busiest.wraps.len(),
        human(busiest_model),
    );
    let city_bytes: usize = city_tasks.iter().map(|task| task.encoded().len()).sum();
    println!(
        "city tasks: {} tasks, {} in all ({city_wraps} wraps); performed (structure check, city re-key) in {city_time:.1?}",
        city_tasks.len(),
        human(city_bytes as f64),
    );
    println!(
        "seal: {}; sealed (hashes, key schedule, signature) in {seal_time:.1?}",
        human(seal_bytes),
    );
    println!(
        "delivery service full check (every entry's signatures and admission): {check_time:.1?}"
    );
    assert!((busiest_actual - busiest_model).abs() / busiest_model < 0.1);

    // One packet per member.
    let mut index = WindowIndex::default();
    for commit in &commits {
        index.add(&commit.updates, &commit.wraps);
    }
    for task in &city_tasks {
        index.add(&task.updates, &task.wraps);
    }
    let registry = RegistryUpdate::between(
        &state.registry.header().unwrap(),
        &sealed.header.registry,
        None,
    );
    let removed_set: HashSet<u32> = removed.iter().copied().collect();
    let island_level = shape.island_level();
    let is_wrap = |step: &cityg_core::rekey::Step| matches!(step, cityg_core::rekey::Step::Wrap(_));
    let context = RelayContext {
        gid: state.gid,
        epoch,
        island_bits,
        island: 0,
        interim: [3; 32],
    };
    let relay = Top::Relay(RelayElement::seal(&context, &[1; 32], &[2; 32]).unwrap());
    let island_pk = &state
        .tree
        .parent(shape.island_root(0))
        .unwrap()
        .encryption_key;
    let flat = Top::Flat(
        flat_element(
            &state.gid, epoch, shape, 0, island_pk, &[2; 32], &[0; 32], &mut rng,
        )
        .unwrap(),
    );
    let mut sizes = Vec::new();
    let mut wrap_counts = Vec::new();
    let mut relay_sizes = Vec::new();
    let mut flat_sizes = Vec::new();
    let mut upper_wraps = Vec::new();
    for leaf in (0..n as u32).step_by((n / 4096).max(1)) {
        if removed_set.contains(&leaf) {
            continue;
        }
        let path = index.steps(leaf, shape.height).unwrap();
        wrap_counts.push(path.values().filter(|step| is_wrap(step)).count());
        upper_wraps.push(
            path.range(island_level + 1..)
                .filter(|(_, step)| is_wrap(step))
                .count(),
        );
        let packet = Packet {
            header: sealed.seal.header.clone(),
            tag: sealed.seal.tag,
            entrant: None,
            registry: registry.clone(),
            leaf_key: [0; 32],
            path,
            top: None,
        };
        sizes.push(packet.encoded_len());
        let mut island = packet;
        island.path.retain(|level, _| *level <= island_level);
        island.top = Some(relay.clone());
        relay_sizes.push(island.encoded_len());
        island.top = Some(flat.clone());
        flat_sizes.push(island.encoded_len());
    }
    let mean = sizes.iter().sum::<usize>() as f64 / sizes.len() as f64;
    let mean_wraps = wrap_counts.iter().sum::<usize>() as f64 / wrap_counts.len() as f64;
    let model_member = mean_wraps * (1120.0 + 48.0) + 200.0;
    println!(
        "packets: mean {} ({mean_wraps:.1} wraps; model {}), max {}",
        human(mean),
        human(model_member),
        human(*sizes.iter().max().unwrap() as f64)
    );
    assert!(mean < model_member * 1.2 + 512.0);
    let average = |values: &[usize]| values.iter().sum::<usize>() as f64 / values.len() as f64;
    println!(
        "island packets (islands of 2^{island_bits}): with a relay element mean {} (max {}), with a flat element mean {}; a relay reads {:.1} wraps above its island",
        human(average(&relay_sizes)),
        human(*relay_sizes.iter().max().unwrap() as f64),
        human(average(&flat_sizes)),
        average(&upper_wraps),
    );
    assert!(average(&relay_sizes) < mean);

    // What a joiner downloads per window of the chain from its checkpoint.
    let link = SealLink {
        proof: sealed.seal.proof(),
        sealer: SealerEvidence::Member(state.tree.leaf_proof(0).unwrap()),
        registry: sealed.header.registry.clone(),
        policy: None,
    };
    println!(
        "seal link (chain from a checkpoint): {}",
        human(link.encoded_len() as f64)
    );
}
