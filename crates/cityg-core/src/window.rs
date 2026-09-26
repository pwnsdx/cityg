//! Public state of a group and the public transition of a window
//! (docs/specs-v0.4-draft.md section 12).
//!
//! Everything here depends on public data only: the delivery service runs
//! it on every window, a sealer runs it on the district commits it seals,
//! and an auditor on the entries it samples. The checks of the entries
//! themselves (signatures and admissions) are optional, so that a sealer
//! can check the structure of a wave without checking every entry (E-12).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::commit::{Change, DistrictCommit, Seal, SealKind};
use crate::crypto::{Digest, ZERO32, kem_pk_hash};
use crate::error::{CoreError, CoreResult};
use crate::objects::{ChangeKind, GroupPolicy, Request, device_id, group_id};
use crate::registry::{Registry, RegistryDelta, RegistryHeader};
use crate::rekey::{self, LeafChanges, NodeUpdate, growth_nodes, plan_city, plan_district};
use crate::schedule::{confirmed_transcript_hash, interim_transcript_hash};
use crate::tree::{LeafNode, NodeId, Occupancy, Overlay, ParentNode, PublicTree, Shape, TreeDelta};

/// Requests of a window, by reference.
pub type Requests = HashMap<Digest, Request>;

/// What every member keeps of the public state of its epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochHeader {
    pub gid: Digest,
    pub epoch: u64,
    pub shape: Shape,
    pub tree_hash: Digest,
    pub registry: RegistryHeader,
    pub interim: Digest,
    pub external_pk: Vec<u8>,
}

impl EpochHeader {
    /// `registry_hash` of the epoch.
    pub fn registry_hash(&self) -> CoreResult<Digest> {
        self.registry.hash()
    }
}

/// The public state of a group: what the delivery service holds.
#[derive(Clone, Debug)]
pub struct PublicState {
    pub gid: Digest,
    pub epoch: u64,
    pub tree: PublicTree,
    pub registry: Registry,
    /// The group policy in force (its hash is in the registry).
    pub policy: Option<GroupPolicy>,
    pub interim: Digest,
    pub external_pk: Vec<u8>,
    pub time_ms: u64,
}

impl PublicState {
    /// The header of the current epoch.
    pub fn header(&self) -> CoreResult<EpochHeader> {
        Ok(EpochHeader {
            gid: self.gid,
            epoch: self.epoch,
            shape: self.tree.shape(),
            tree_hash: self.tree.tree_hash()?,
            registry: self.registry.header()?,
            interim: self.interim,
            external_pk: self.external_pk.clone(),
        })
    }

    /// Check that this state is the one `header` describes (a committer
    /// checks the state the delivery service shows it).
    pub fn check_against(&self, header: &EpochHeader) -> CoreResult<()> {
        if self.header()? == *header {
            Ok(())
        } else {
            Err(CoreError::Invalid("state differs from the trusted header"))
        }
    }

    /// Device key of a current member.
    #[must_use]
    pub fn device_pk(&self, occupancy: Occupancy) -> Option<&[u8]> {
        self.tree
            .member(occupancy)
            .map(|leaf| leaf.device_pk.as_slice())
    }

    /// The state a genesis seal creates, after checking it.
    pub fn from_genesis(seal: &Seal) -> CoreResult<Self> {
        let header = &seal.header;
        let genesis = seal
            .body
            .genesis
            .as_ref()
            .ok_or(CoreError::Invalid("genesis seal without genesis"))?;
        let creator = Occupancy { leaf: 0, since: 0 };
        if header.kind != SealKind::Genesis
            || header.epoch != 0
            || header.prev_interim != ZERO32
            || header.sealer != creator
            || header.height != 1
            || header.gid != group_id(&genesis.creator_pk, &genesis.nonce)?
            || !seal.body.districts.is_empty()
            || !seal.body.city_updates.is_empty()
            || !seal.body.city_wraps.is_empty()
        {
            return Err(CoreError::Invalid("genesis seal"));
        }
        crate::identity::check_device_key(&genesis.creator_pk, "creator key")?;
        crate::kem::validate_public_key(&genesis.encryption_key)?;
        crate::kem::validate_public_key(&genesis.root_pk)?;
        let policy = seal
            .body
            .policy
            .as_deref()
            .map(GroupPolicy::decode)
            .transpose()?;
        if let Some(policy) = &policy {
            if policy.admin != creator {
                return Err(CoreError::Invalid("genesis policy signer"));
            }
            policy.verify_signature(&header.gid, &genesis.creator_pk)?;
        }
        let (tree, registry) = genesis_tree(
            &header.gid,
            header.district_bits,
            &genesis.creator_pk,
            &genesis.encryption_key,
            &genesis.root_pk,
            policy.as_ref(),
        )?;
        if tree.tree_hash()? != header.tree_hash
            || registry.header()?.hash()? != header.registry_hash
            || seal.body.hash()? != header.body_hash
        {
            return Err(CoreError::Invalid("genesis hashes"));
        }
        seal.proof().verify_signature(&genesis.creator_pk)?;
        let confirmed = confirmed_transcript_hash(&ZERO32, &header.hash()?)?;
        Ok(Self {
            gid: header.gid,
            epoch: 0,
            tree,
            registry,
            policy,
            interim: interim_transcript_hash(&confirmed, &seal.tag)?,
            external_pk: seal.external_pk.clone(),
            time_ms: header.time_ms,
        })
    }

    /// Apply a checked window.
    pub fn apply(&mut self, outcome: &WindowOutcome) -> CoreResult<()> {
        if outcome.epoch != self.epoch + 1 {
            return Err(CoreError::EpochMismatch {
                expected: self.epoch + 1,
                got: outcome.epoch,
            });
        }
        self.tree.apply(outcome.shape, &outcome.tree)?;
        self.registry.apply(&outcome.registry);
        if let Some(policy) = &outcome.policy {
            self.policy = Some(policy.clone());
        }
        self.epoch = outcome.epoch;
        self.interim = outcome.interim;
        self.external_pk.clone_from(&outcome.external_pk);
        self.time_ms = outcome.time_ms;
        Ok(())
    }
}

/// Tree and registry of a new group: the creator at leaf 0, admin, the root
/// keyed by it, and the group policy it chose, if any (a group without
/// policy is closed).
pub fn genesis_tree(
    gid: &Digest,
    district_bits: u8,
    creator_pk: &[u8],
    encryption_key: &[u8],
    root_pk: &[u8],
    policy: Option<&GroupPolicy>,
) -> CoreResult<(PublicTree, Registry)> {
    let creator = Occupancy { leaf: 0, since: 0 };
    let mut tree = PublicTree::new(1, district_bits)?;
    tree.set_leaf(
        0,
        Some(LeafNode {
            device_pk: creator_pk.to_vec(),
            since: 0,
            encryption_key: encryption_key.to_vec(),
            admission_hash: ZERO32,
            updated: 0,
        }),
    )?;
    tree.set_parent(
        NodeId { level: 1, index: 0 },
        Some(ParentNode {
            encryption_key: root_pk.to_vec(),
            taint: creator,
        }),
    )?;
    let mut registry = Registry::new();
    let mut delta = RegistryDelta::default();
    delta.admins_added.insert(creator, creator_pk.to_vec());
    delta
        .devices
        .insert(device_id(gid, creator_pk)?, Some(creator));
    delta.policy = policy.map(|policy| (policy.hash(), policy.open));
    registry.apply(&delta);
    Ok((tree, registry))
}

/// Smallest height not below `current` whose tree holds leaf `max_leaf`.
#[must_use]
pub fn needed_height(current: u8, max_leaf: Option<u32>) -> u8 {
    let needed = max_leaf.map_or(0, |leaf| {
        u8::try_from(u32::BITS - leaf.leading_zeros()).unwrap_or(u8::MAX)
    });
    current.max(needed)
}

/// The structure of a window: its changes by district, the members it
/// removes or re-keys, and the nodes it must re-key besides the paths of
/// the changed leaves. It follows from the change list and the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowShape {
    pub epoch: u64,
    pub shape: Shape,
    /// Changes by district, sorted by `(leaf, kind)`.
    pub changes: BTreeMap<u32, Vec<Change>>,
    /// Members removed, evicted, updated or re-entering: their taints are
    /// re-keyed.
    pub affected: BTreeSet<Occupancy>,
    /// Members removed or evicted.
    pub removed: BTreeSet<Occupancy>,
    /// Nodes to re-key besides the changed paths, by district.
    pub district_forced: BTreeMap<u32, BTreeSet<NodeId>>,
    /// City nodes to re-key besides the changed paths.
    pub city_forced: BTreeSet<NodeId>,
    /// Districts the window commits.
    pub districts: BTreeSet<u32>,
}

impl WindowShape {
    /// Structure of the window creating epoch `epoch` with `changes`.
    pub fn new(
        tree: &PublicTree,
        epoch: u64,
        shape: Shape,
        changes: impl IntoIterator<Item = Change>,
    ) -> CoreResult<Self> {
        let mut by_leaf: BTreeMap<u32, Vec<Change>> = BTreeMap::new();
        for change in changes {
            by_leaf.entry(change.leaf).or_default().push(change);
        }
        if shape.district_bits != tree.district_bits()
            || shape.height != needed_height(tree.height(), by_leaf.keys().next_back().copied())
        {
            return Err(CoreError::Invalid("window height"));
        }
        let mut affected = BTreeSet::new();
        let mut removed = BTreeSet::new();
        let mut by_district: BTreeMap<u32, Vec<Change>> = BTreeMap::new();
        for (leaf, mut list) in by_leaf {
            list.sort();
            let kinds: Vec<ChangeKind> = list.iter().map(|change| change.kind).collect();
            let occupant = tree.occupancy(leaf);
            match (kinds.as_slice(), occupant) {
                ([ChangeKind::Join], None) => {}
                (
                    [ChangeKind::Removal | ChangeKind::Eviction]
                    | [ChangeKind::Removal | ChangeKind::Eviction, ChangeKind::Join],
                    Some(occupant),
                ) => {
                    removed.insert(occupant);
                    affected.insert(occupant);
                }
                ([ChangeKind::Update | ChangeKind::ReEntry], Some(occupant)) => {
                    affected.insert(occupant);
                }
                _ => return Err(CoreError::Invalid("changes of a leaf")),
            }
            by_district
                .entry(shape.district_of(leaf))
                .or_default()
                .extend(list);
        }
        let mut district_forced: BTreeMap<u32, BTreeSet<NodeId>> = BTreeMap::new();
        let mut city_forced = BTreeSet::new();
        let mut force = |node: NodeId| {
            if node.level <= shape.district_level() {
                district_forced
                    .entry(shape.district_of_node(node))
                    .or_default()
                    .insert(node);
            } else {
                city_forced.insert(node);
            }
        };
        for occupancy in &affected {
            for node in tree.tainted_by(*occupancy) {
                force(node);
            }
        }
        if shape.height > tree.height() && tree.member_count() > 0 {
            for node in growth_nodes(tree.height(), shape) {
                force(node);
            }
        }
        let districts = by_district
            .keys()
            .chain(district_forced.keys())
            .copied()
            .collect();
        Ok(Self {
            epoch,
            shape,
            changes: by_district,
            affected,
            removed,
            district_forced,
            city_forced,
            districts,
        })
    }

    /// Changes of district `district`.
    #[must_use]
    pub fn district_changes(&self, district: u32) -> &[Change] {
        self.changes.get(&district).map_or(&[], Vec::as_slice)
    }

    /// Nodes of district `district` to re-key besides the changed paths.
    #[must_use]
    pub fn forced(&self, district: u32) -> BTreeSet<NodeId> {
        self.district_forced
            .get(&district)
            .cloned()
            .unwrap_or_default()
    }

    /// Every change of the window.
    pub fn all_changes(&self) -> impl Iterator<Item = &Change> {
        self.changes.values().flatten()
    }
}

/// The new state of the leaves of district `district`, from its changes and
/// their requests. With `entries`, also check each entry's signatures and
/// admission.
pub fn district_leaves(
    state: &PublicState,
    window: &WindowShape,
    district: u32,
    requests: &Requests,
    entries: bool,
) -> CoreResult<LeafChanges> {
    let mut leaves = LeafChanges::new();
    for change in window.district_changes(district) {
        let request = requests
            .get(&change.request)
            .ok_or(CoreError::Invalid("missing request"))?;
        if request.kind() != change.kind || request.gid() != &state.gid {
            return Err(CoreError::Invalid("request of a change"));
        }
        let occupant = state.tree.occupancy(change.leaf);
        if let Some(subject) = request.subject()
            && Some(subject) != occupant
        {
            return Err(CoreError::Invalid("change subject"));
        }
        // Sorted by kind, a join follows the removal it is paired with.
        let leaf = check_entry(state, window.epoch, change.leaf, request, entries)?;
        leaves.insert(change.leaf, leaf);
    }
    Ok(leaves)
}

/// Check one entry against the state before the window and return the new
/// state of its leaf. With `entries`, check signatures and admissions
/// (what auditors sample); the rest is always checked.
pub fn check_entry(
    state: &PublicState,
    epoch: u64,
    leaf: u32,
    request: &Request,
    entries: bool,
) -> CoreResult<Option<LeafNode>> {
    let current = state.tree.leaf(leaf);
    let admins = state.registry.admins();
    match request {
        Request::Join(join) => {
            if state.registry.device(&join.device_id()?).is_some() {
                return Err(CoreError::Invalid("device already a member"));
            }
            let admission_hash = join.token();
            if state.registry.admission(&admission_hash).is_some() {
                return Err(CoreError::Invalid("admission already used"));
            }
            if entries {
                join.verify(&state.gid, epoch, admins, state.registry.is_open())?;
            }
            Ok(Some(LeafNode {
                device_pk: join.device_pk.clone(),
                since: epoch,
                encryption_key: join.encryption_key.clone(),
                admission_hash,
                updated: epoch,
            }))
        }
        Request::Removal(proposal) => {
            let current = current.ok_or(CoreError::Invalid("removal of a blank leaf"))?;
            if entries {
                proposal.verify(&state.gid, admins, &current.device_pk)?;
            }
            Ok(None)
        }
        Request::Eviction(eviction) => {
            let current = current.ok_or(CoreError::Invalid("eviction of a blank leaf"))?;
            let policy = state
                .policy
                .as_ref()
                .ok_or(CoreError::Invalid("eviction without a policy"))?;
            if state.registry.policy() != Some(&policy.hash()) {
                return Err(CoreError::Invalid("eviction policy"));
            }
            eviction.verify(&state.gid, policy, current.updated, epoch)?;
            Ok(None)
        }
        Request::Update(update) => {
            let current = current.ok_or(CoreError::Invalid("update of a blank leaf"))?;
            if update.replaces != kem_pk_hash(&current.encryption_key)? {
                return Err(CoreError::Invalid("update replaces another key"));
            }
            if entries {
                update.verify(&state.gid, &current.device_pk)?;
            }
            Ok(Some(LeafNode {
                encryption_key: update.encryption_key.clone(),
                updated: epoch,
                ..current.clone()
            }))
        }
        Request::ReEntry(re_entry) => {
            let current = current.ok_or(CoreError::Invalid("re-entry of a blank leaf"))?;
            if re_entry.replaces != kem_pk_hash(&current.encryption_key)? {
                return Err(CoreError::Invalid("re-entry replaces another key"));
            }
            if entries {
                re_entry.verify(&state.gid, &current.device_pk)?;
            }
            Ok(Some(LeafNode {
                encryption_key: re_entry.encryption_key.clone(),
                updated: epoch,
                ..current.clone()
            }))
        }
    }
}

/// Hash of district `district` before the window, in the window's shape.
pub fn prev_district_hash(state: &PublicState, shape: Shape, district: u32) -> CoreResult<Digest> {
    let empty = TreeDelta::default();
    Overlay::new(&state.tree, shape, &empty)?.district_hash(district)
}

/// Parent nodes set by a re-key, with their taint.
#[must_use]
pub fn keyed_parents(
    updates: &[NodeUpdate],
    taint: Occupancy,
) -> BTreeMap<NodeId, Option<ParentNode>> {
    updates
        .iter()
        .map(|update| {
            (
                update.node,
                update.public_key.clone().map(|encryption_key| ParentNode {
                    encryption_key,
                    taint,
                }),
            )
        })
        .collect()
}

/// Check a district commit against the window, given the new state of its
/// leaves and the committer's device key; returns the district's delta.
pub fn check_district_commit(
    state: &PublicState,
    window: &WindowShape,
    commit: &DistrictCommit,
    leaves: &LeafChanges,
    committer_pk: &[u8],
) -> CoreResult<TreeDelta> {
    let district = commit.district;
    if commit.gid != state.gid
        || commit.epoch != window.epoch
        || commit.height != window.shape.height
        || !window.districts.contains(&district)
        || commit.changes != window.district_changes(district)
    {
        return Err(CoreError::Invalid("district commit"));
    }
    if commit.prev_district_hash != prev_district_hash(state, window.shape, district)? {
        return Err(CoreError::Invalid("district commit base"));
    }
    let plan = plan_district(
        &state.tree,
        window.shape,
        district,
        leaves,
        &window.forced(district),
    )?;
    rekey::check(&plan, &commit.updates, &commit.wraps)?;
    let delta = TreeDelta {
        leaves: leaves.clone(),
        parents: keyed_parents(&commit.updates, commit.committer),
    };
    let overlay = Overlay::new(&state.tree, window.shape, &delta)?;
    if overlay.district_hash(district)? != commit.district_hash {
        return Err(CoreError::Invalid("district hash"));
    }
    commit.verify_signature(committer_pk)?;
    Ok(delta)
}

/// The registry changes of a window: joins enter the device and admission
/// maps, removed members leave the device map and the admins, the seal may
/// set the group policy, and the sealer becomes admin if none is left.
pub fn registry_delta(
    state: &PublicState,
    window: &WindowShape,
    requests: &Requests,
    policy: Option<&GroupPolicy>,
    sealer: Occupancy,
    sealer_pk: &[u8],
) -> CoreResult<RegistryDelta> {
    let mut delta = RegistryDelta::default();
    for removed in &window.removed {
        let leaf = state
            .tree
            .member(*removed)
            .ok_or(CoreError::Invalid("removal of a non-member"))?;
        delta
            .devices
            .insert(device_id(&state.gid, &leaf.device_pk)?, None);
        if state.registry.is_admin(*removed) {
            delta.admins_removed.insert(*removed);
        }
    }
    for change in window.all_changes() {
        if change.kind != ChangeKind::Join {
            continue;
        }
        let Some(Request::Join(join)) = requests.get(&change.request) else {
            return Err(CoreError::Invalid("missing join request"));
        };
        let occupancy = Occupancy {
            leaf: change.leaf,
            since: window.epoch,
        };
        let id = join.device_id()?;
        let admission = join.token();
        if state.registry.device(&id).is_some()
            || delta.devices.get(&id).is_some_and(Option::is_some)
        {
            return Err(CoreError::Invalid("device joins twice"));
        }
        if state.registry.admission(&admission).is_some()
            || delta.admissions.contains_key(&admission)
        {
            return Err(CoreError::Invalid("admission used twice"));
        }
        delta.devices.insert(id, Some(occupancy));
        delta.admissions.insert(admission, Some(occupancy));
    }
    if let Some(policy) = policy {
        policy.verify(&state.gid, state.registry.admins())?;
        delta.policy = Some((policy.hash(), policy.open));
    }
    if state.registry.admins_with(&delta).is_empty() {
        delta.admins_added.insert(sealer, sealer_pk.to_vec());
    }
    Ok(delta)
}

/// Who sealed a window, and with what key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealerInfo {
    pub occupancy: Occupancy,
    pub device_pk: Vec<u8>,
    /// Whether the sealer is the window's entrant.
    pub entrant: bool,
}

/// Identify and check the sealer of a window: a member of the previous
/// epoch that the window leaves alone, or the entrant whose request is
/// among the window's changes (its signature and admission are always
/// checked).
pub fn check_sealer(
    state: &PublicState,
    window: &WindowShape,
    kind: SealKind,
    sealer: Occupancy,
    entrant_request: Option<&Digest>,
    requests: &Requests,
) -> CoreResult<SealerInfo> {
    match (kind, entrant_request) {
        (SealKind::Member, None) => {
            let leaf = state
                .tree
                .member(sealer)
                .ok_or(CoreError::Unauthorized("sealer is not a member"))?;
            if window.affected.contains(&sealer) {
                return Err(CoreError::Unauthorized("sealer changed by its window"));
            }
            Ok(SealerInfo {
                occupancy: sealer,
                device_pk: leaf.device_pk.clone(),
                entrant: false,
            })
        }
        (SealKind::Entrant, Some(reference)) => {
            let change = window
                .all_changes()
                .find(|change| change.request == *reference)
                .ok_or(CoreError::Invalid("entrant request not in the window"))?;
            match requests.get(reference) {
                Some(Request::Join(join)) => {
                    let occupancy = Occupancy {
                        leaf: change.leaf,
                        since: window.epoch,
                    };
                    if occupancy != sealer {
                        return Err(CoreError::Invalid("entrant occupancy"));
                    }
                    join.verify(
                        &state.gid,
                        window.epoch,
                        state.registry.admins(),
                        state.registry.is_open(),
                    )?;
                    Ok(SealerInfo {
                        occupancy,
                        device_pk: join.device_pk.clone(),
                        entrant: true,
                    })
                }
                Some(Request::ReEntry(re_entry)) => {
                    let leaf = state
                        .tree
                        .member(re_entry.member)
                        .ok_or(CoreError::Invalid("re-entry of a non-member"))?;
                    if re_entry.member != sealer {
                        return Err(CoreError::Invalid("entrant occupancy"));
                    }
                    re_entry.verify(&state.gid, &leaf.device_pk)?;
                    Ok(SealerInfo {
                        occupancy: sealer,
                        device_pk: leaf.device_pk.clone(),
                        entrant: true,
                    })
                }
                _ => Err(CoreError::Invalid("entrant request")),
            }
        }
        _ => Err(CoreError::Invalid("seal kind")),
    }
}

/// Check the committer of a district commit; returns its device key.
pub fn check_committer(
    state: &PublicState,
    window: &WindowShape,
    committer: Occupancy,
    sealer: &SealerInfo,
) -> CoreResult<Vec<u8>> {
    if sealer.entrant {
        if committer != sealer.occupancy {
            return Err(CoreError::Unauthorized(
                "district of an entrant window committed by another",
            ));
        }
        return Ok(sealer.device_pk.clone());
    }
    let leaf = state
        .tree
        .member(committer)
        .ok_or(CoreError::Unauthorized("committer is not a member"))?;
    if window.affected.contains(&committer) {
        return Err(CoreError::Unauthorized("committer changed by its window"));
    }
    Ok(leaf.device_pk.clone())
}

/// A checked window, ready to apply.
#[derive(Clone, Debug)]
pub struct WindowOutcome {
    pub epoch: u64,
    pub shape: Shape,
    pub window: WindowShape,
    pub tree: TreeDelta,
    pub registry: RegistryDelta,
    pub policy: Option<GroupPolicy>,
    pub sealer: SealerInfo,
    pub seal_hash: Digest,
    pub interim: Digest,
    pub tag: Digest,
    pub external_pk: Vec<u8>,
    pub time_ms: u64,
}

/// The joins of a window, checked against its seal: the occupancy and
/// device key of every device it let in. The body must hash to the header's
/// `body_hash`, list exactly `commits`, and every join's request must hash
/// to its reference.
pub fn joins_of(
    seal: &Seal,
    commits: &[DistrictCommit],
    requests: &Requests,
) -> CoreResult<Vec<(Occupancy, Vec<u8>)>> {
    if seal.body.hash()? != seal.header.body_hash {
        return Err(CoreError::Invalid("seal body"));
    }
    let listed: Vec<(u32, Digest)> = commits
        .iter()
        .map(|commit| (commit.district, commit.hash()))
        .collect();
    if listed != seal.body.districts {
        return Err(CoreError::Invalid("seal lists other district commits"));
    }
    let mut joins = Vec::new();
    for change in commits.iter().flat_map(|commit| commit.changes.iter()) {
        if change.kind != ChangeKind::Join {
            continue;
        }
        let Some(Request::Join(join)) = requests.get(&change.request) else {
            return Err(CoreError::Invalid("missing join request"));
        };
        if join.reference() != change.request {
            return Err(CoreError::Invalid("join request"));
        }
        joins.push((
            Occupancy {
                leaf: change.leaf,
                since: seal.header.epoch,
            },
            join.device_pk.clone(),
        ));
    }
    Ok(joins)
}

/// Roots of the districts of a window after their commits: whether each is
/// live, and its new key.
pub fn district_roots(
    shape: Shape,
    commits: &[DistrictCommit],
) -> CoreResult<BTreeMap<u32, Option<Vec<u8>>>> {
    let mut roots = BTreeMap::new();
    for commit in commits {
        let top = commit
            .updates
            .last()
            .ok_or(CoreError::Invalid("district commit re-keys nothing"))?;
        if top.node != shape.district_root(commit.district) {
            return Err(CoreError::Invalid("district commit top"));
        }
        roots.insert(commit.district, top.public_key.clone());
    }
    Ok(roots)
}

/// Check the district commits of a window: one per district of the window,
/// in district order, each by an allowed committer and following its plan.
/// Returns the delta of the districts.
pub fn check_districts(
    state: &PublicState,
    window: &WindowShape,
    commits: &[DistrictCommit],
    requests: &Requests,
    sealer: &SealerInfo,
    entries: bool,
) -> CoreResult<TreeDelta> {
    if commits
        .windows(2)
        .any(|pair| pair[0].district >= pair[1].district)
        || window.districts != commits.iter().map(|commit| commit.district).collect()
    {
        return Err(CoreError::Invalid("window districts"));
    }
    let mut delta = TreeDelta::default();
    for commit in commits {
        let committer_pk = check_committer(state, window, commit.committer, sealer)?;
        let leaves = district_leaves(state, window, commit.district, requests, entries)?;
        let district = check_district_commit(state, window, commit, &leaves, &committer_pk)?;
        delta.leaves.extend(district.leaves);
        delta.parents.extend(district.parents);
    }
    Ok(delta)
}

/// Check a whole window (district commits and seal) against the state
/// before it. With `entries`, also check every entry's signatures and
/// admission.
pub fn check_window(
    state: &PublicState,
    commits: &[DistrictCommit],
    seal: &Seal,
    requests: &Requests,
    entries: bool,
) -> CoreResult<WindowOutcome> {
    let header = &seal.header;
    if header.gid != state.gid
        || header.prev_interim != state.interim
        || header.district_bits != state.tree.district_bits()
        || header.time_ms < state.time_ms
    {
        return Err(CoreError::Invalid("seal header"));
    }
    if header.epoch != state.epoch + 1 {
        return Err(CoreError::EpochMismatch {
            expected: state.epoch + 1,
            got: header.epoch,
        });
    }
    let shape = state.tree.shape().grown(header.height)?;
    let listed: Vec<(u32, Digest)> = commits
        .iter()
        .map(|commit| (commit.district, commit.hash()))
        .collect();
    if listed != seal.body.districts {
        return Err(CoreError::Invalid("seal lists other district commits"));
    }
    let window = WindowShape::new(
        &state.tree,
        header.epoch,
        shape,
        commits
            .iter()
            .flat_map(|commit| commit.changes.iter().copied()),
    )?;
    let sealer = check_sealer(
        state,
        &window,
        header.kind,
        header.sealer,
        header.entrant.as_ref().map(|entrant| &entrant.request),
        requests,
    )?;
    let mut delta = check_districts(state, &window, commits, requests, &sealer, entries)?;
    let roots = district_roots(shape, commits)?;
    let live = roots.iter().map(|(d, key)| (*d, key.is_some())).collect();
    let city = plan_city(&state.tree, shape, &live, &window.city_forced)?;
    rekey::check(&city, &seal.body.city_updates, &seal.body.city_wraps)?;
    delta
        .parents
        .extend(keyed_parents(&seal.body.city_updates, sealer.occupancy));
    if Overlay::new(&state.tree, shape, &delta)?.tree_hash()? != header.tree_hash {
        return Err(CoreError::Invalid("tree hash"));
    }
    let policy = seal
        .body
        .policy
        .as_deref()
        .map(GroupPolicy::decode)
        .transpose()?;
    let registry = registry_delta(
        state,
        &window,
        requests,
        policy.as_ref(),
        sealer.occupancy,
        &sealer.device_pk,
    )?;
    if state.registry.header_with(&registry)?.hash()? != header.registry_hash {
        return Err(CoreError::Invalid("registry hash"));
    }
    if seal.body.hash()? != header.body_hash || seal.body.genesis.is_some() {
        return Err(CoreError::Invalid("seal body"));
    }
    seal.proof().verify_signature(&sealer.device_pk)?;
    let seal_hash = header.hash()?;
    let confirmed = confirmed_transcript_hash(&state.interim, &seal_hash)?;
    Ok(WindowOutcome {
        epoch: header.epoch,
        shape,
        window,
        tree: delta,
        registry,
        policy,
        sealer,
        seal_hash,
        interim: interim_transcript_hash(&confirmed, &seal.tag)?,
        tag: seal.tag,
        external_pk: seal.external_pk.clone(),
        time_ms: header.time_ms,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn heights_grow_only_as_needed() {
        assert_eq!(needed_height(3, None), 3);
        assert_eq!(needed_height(3, Some(7)), 3);
        assert_eq!(needed_height(3, Some(8)), 4);
        assert_eq!(needed_height(1, Some(1000)), 10);
        assert_eq!(needed_height(1, Some(0)), 1);
    }
}
