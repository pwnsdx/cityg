//! Multi-path re-key of a district or of a part of the city (docs/specs.md
//! section 7; docs/specs-v0.5-draft.md section 3.2).
//!
//! A window re-keys every ancestor of a changed base node, and every node
//! tainted by a member the window removes or updates, with its ancestors.
//! For a district the base nodes are the changed leaves; for a sub-city,
//! the roots of its districts that changed; for the top, the roots of the
//! sub-cities that changed. Nodes are processed bottom-up:
//!
//! * a node with no live child becomes blank;
//! * otherwise, if some live child was re-keyed by the same commit and the
//!   level is not a *boundary*, the node's secret is `chain(child)`, taken
//!   from the first such child (left first), and it is wrapped to the other
//!   live child, if any;
//! * otherwise the node gets a fresh secret, wrapped to every live child.
//!
//! Boundaries are the levels where the committer knows no child's new
//! secret: level 1 (the children are the members' leaves) and, in a part of
//! the city, the level above its base (the children are the roots that the
//! tier below re-keyed: districts for a sub-city, sub-cities for the top,
//! docs/specs-v0.5-draft.md section 3.2).
//!
//! The *plan* of a re-key (which nodes, blank or not, the chain source and
//! the wrap targets of each) depends only on public data, so the delivery
//! service and any verifier recompute it and check a commit against it.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rand_core::CryptoRngCore;

use crate::crypto::{
    Digest, SEALED_SECRET_BYTES, Secret, Wrap, chain, fresh_secret, node_key, unwrap, wrap,
};
use crate::error::{CoreError, CoreResult};
use crate::kem::{KEM_CIPHERTEXT_BYTES, KemSecret, validate_public_key};
use crate::tree::{CityPart, LeafNode, NodeId, ParentNode, PublicTree, Shape};

/// New state of the leaves a window changes: `None` blanks a leaf.
pub type LeafChanges = BTreeMap<u32, Option<LeafNode>>;

/// New key of a re-keyed node, or `None` when the node becomes blank.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeUpdate {
    pub node: NodeId,
    pub public_key: Option<Vec<u8>>,
}

/// One node of a re-key plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedNode {
    pub node: NodeId,
    pub blank: bool,
    /// The re-keyed child the node's secret is chained from.
    pub chain_from: Option<NodeId>,
    /// The live children the secret is wrapped to.
    pub wrap_to: Vec<NodeId>,
}

/// The public structure of a re-key, bottom-up and in index order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub nodes: Vec<PlannedNode>,
}

impl Plan {
    /// Whether the plan re-keys `node`.
    #[must_use]
    pub fn contains(&self, node: NodeId) -> bool {
        self.nodes.iter().any(|planned| planned.node == node)
    }

    /// The topmost node of the plan (a district root or the tree root).
    #[must_use]
    pub fn top(&self) -> Option<&PlannedNode> {
        self.nodes.last()
    }

    /// Number of wraps the plan calls for.
    #[must_use]
    pub fn wrap_count(&self) -> usize {
        self.nodes.iter().map(|planned| planned.wrap_to.len()).sum()
    }
}

fn collect(set: &mut BTreeSet<NodeId>, from: NodeId, top: u8) {
    for level in from.level.max(1)..=top {
        set.insert(from.ancestor(level));
    }
}

fn build(
    set: BTreeSet<NodeId>,
    base_live: impl Fn(NodeId) -> bool,
    boundary: impl Fn(u8) -> bool,
) -> Plan {
    let mut planned: HashMap<NodeId, bool> = HashMap::new();
    let mut nodes = Vec::with_capacity(set.len());
    for node in set {
        let live: Vec<NodeId> = node
            .children()
            .into_iter()
            .filter(|child| {
                planned
                    .get(child)
                    .copied()
                    .unwrap_or_else(|| base_live(*child))
            })
            .collect();
        let blank = live.is_empty();
        let chain_from = if blank || boundary(node.level) {
            None
        } else {
            live.iter()
                .copied()
                .find(|child| planned.get(child) == Some(&true))
        };
        let wrap_to = live
            .into_iter()
            .filter(|child| Some(*child) != chain_from)
            .collect();
        planned.insert(node, !blank);
        nodes.push(PlannedNode {
            node,
            blank,
            chain_from,
            wrap_to,
        });
    }
    Plan { nodes }
}

/// Plan the re-key of district `district`. `tree` is the tree before the
/// window and `shape` the window's shape (the tree may grow); `leaves` the
/// new state of the changed leaves; `forced` the other nodes to re-key
/// (tainted nodes, and the nodes above the old root when the tree grows).
pub fn plan_district(
    tree: &PublicTree,
    shape: Shape,
    district: u32,
    leaves: &LeafChanges,
    forced: &BTreeSet<NodeId>,
) -> CoreResult<Plan> {
    if district >= shape.district_count() || !shape.same_divisions(tree.shape()) {
        return Err(CoreError::Invalid("district index"));
    }
    let top = shape.district_level();
    let root = shape.district_root(district);
    let mut set = BTreeSet::new();
    for leaf in leaves.keys() {
        if !root.covers(*leaf) || !shape.contains_leaf(*leaf) {
            return Err(CoreError::Invalid("changed leaf outside its district"));
        }
        collect(&mut set, NodeId::leaf(*leaf), top);
    }
    for node in forced {
        if node.level == 0 || !root.is_above_or_at(*node) {
            return Err(CoreError::Invalid("forced node outside its district"));
        }
        collect(&mut set, *node, top);
    }
    Ok(build(
        set,
        |child| {
            if child.level == 0 {
                leaves
                    .get(&child.index)
                    .map_or_else(|| tree.leaf(child.index).is_some(), Option::is_some)
            } else {
                tree.parent(child).is_some()
            }
        },
        |level| level == 1,
    ))
}

/// Plan the re-key of a part of the city (docs/specs-v0.5-draft.md section
/// 3.2): a sub-city over the new roots of its districts of the window, or
/// the top over the new roots of the window's sub-cities. `below` gives, for
/// each such root (by index at the part's base level), whether it is live
/// after the window; `forced` the other nodes of the part to re-key.
pub fn plan_part(
    tree: &PublicTree,
    shape: Shape,
    part: CityPart,
    below: &BTreeMap<u32, bool>,
    forced: &BTreeSet<NodeId>,
) -> CoreResult<Plan> {
    if !shape.has_city() || (part == CityPart::Top && !shape.has_top()) {
        return Err(CoreError::Invalid("city part of a tree without it"));
    }
    if let CityPart::SubCity(subcity) = part
        && subcity >= shape.subcity_count()
    {
        return Err(CoreError::Invalid("sub-city index"));
    }
    let base = shape.part_base(part);
    let root = shape.part_root(part);
    let mut set = BTreeSet::new();
    for index in below.keys() {
        let node = NodeId {
            level: base,
            index: *index,
        };
        if !shape.contains(node) || !root.is_above_or_at(node) {
            return Err(CoreError::Invalid("city task root outside its part"));
        }
        collect(&mut set, node.parent(), root.level);
    }
    for node in forced {
        if node.level <= base || !shape.contains(*node) || !root.is_above_or_at(*node) {
            return Err(CoreError::Invalid("forced node outside its part"));
        }
        collect(&mut set, *node, root.level);
    }
    Ok(build(
        set,
        |child| {
            if child.level == base {
                below
                    .get(&child.index)
                    .copied()
                    .unwrap_or_else(|| tree.parent(child).is_some())
            } else {
                tree.parent(child).is_some()
            }
        },
        |level| level == base + 1,
    ))
}

/// Nodes above the old root that a window growing the tree from
/// `old_height` to `shape.height` must key: the left edge of the new levels,
/// whose subtree holds the old tree.
#[must_use]
pub fn growth_nodes(old_height: u8, shape: Shape) -> BTreeSet<NodeId> {
    (old_height + 1..=shape.height)
        .map(|level| NodeId { level, index: 0 })
        .collect()
}

/// New roots of one tier of the tree after a window's tasks, by index at
/// their level: the new public key, or `None` for a root that became blank.
pub type NewRoots = BTreeMap<u32, Option<Vec<u8>>>;

/// Where a committer finds the key of a wrap target: the changed leaves,
/// the new roots of the tier below (for a part of the city: their level and
/// keys), then the tree before the window.
pub struct KeySource<'a> {
    pub tree: &'a PublicTree,
    pub shape: Shape,
    pub leaves: &'a LeafChanges,
    pub below: Option<(u8, &'a NewRoots)>,
}

impl KeySource<'_> {
    fn key(&self, node: NodeId, fresh: &HashMap<NodeId, Vec<u8>>) -> CoreResult<Vec<u8>> {
        if let Some(key) = fresh.get(&node) {
            return Ok(key.clone());
        }
        if node.level == 0 {
            if let Some(change) = self.leaves.get(&node.index) {
                return change
                    .as_ref()
                    .map(|leaf| leaf.encryption_key.clone())
                    .ok_or(CoreError::Invalid("wrap to a blank leaf"));
            }
        } else if let Some((level, roots)) = self.below
            && node.level == level
            && let Some(change) = roots.get(&node.index)
        {
            return change
                .clone()
                .ok_or(CoreError::Invalid("wrap to a blank root"));
        }
        self.tree
            .public_key(node)
            .map(<[u8]>::to_vec)
            .ok_or(CoreError::Invalid("wrap to a blank node"))
    }
}

/// What a committer produced: node updates and wraps for its commit, and the
/// secrets it drew, which it erases once its commit is sent.
pub struct Rekeyed {
    pub updates: Vec<NodeUpdate>,
    pub wraps: Vec<Wrap>,
    secrets: BTreeMap<NodeId, Secret>,
}

impl Rekeyed {
    /// Secret the committer drew for `node`.
    #[must_use]
    pub fn secret(&self, node: NodeId) -> Option<&Secret> {
        self.secrets.get(&node)
    }

    /// The secrets it drew on the path of `leaf`, by level (an entrant keeps
    /// them and erases the rest).
    #[must_use]
    pub fn path_secrets(&self, leaf: u32) -> BTreeMap<u8, Secret> {
        self.secrets
            .iter()
            .filter(|(node, _)| node.covers(leaf))
            .map(|(node, secret)| (node.level, secret.clone()))
            .collect()
    }
}

/// Draw the secrets of `plan` and wrap them.
pub fn generate(
    plan: &Plan,
    keys: &KeySource<'_>,
    gid: &Digest,
    epoch: u64,
    hedge: &[u8; 32],
    rng: &mut impl CryptoRngCore,
) -> CoreResult<Rekeyed> {
    let mut secrets: BTreeMap<NodeId, Secret> = BTreeMap::new();
    let mut fresh_keys: HashMap<NodeId, Vec<u8>> = HashMap::new();
    let mut updates = Vec::with_capacity(plan.nodes.len());
    let mut wraps = Vec::with_capacity(plan.wrap_count());
    for planned in &plan.nodes {
        if planned.blank {
            updates.push(NodeUpdate {
                node: planned.node,
                public_key: None,
            });
            continue;
        }
        let secret = match planned.chain_from {
            Some(child) => chain(
                secrets
                    .get(&child)
                    .ok_or(CoreError::Invalid("chain from an unknown child"))?,
            )?,
            None => fresh_secret(hedge, rng)?,
        };
        for target in &planned.wrap_to {
            let target_pk = keys.key(*target, &fresh_keys)?;
            wraps.push(wrap(
                gid,
                epoch,
                planned.node,
                *target,
                &target_pk,
                &secret,
                hedge,
                rng,
            )?);
        }
        let public_key = node_key(&secret)?.public_key();
        fresh_keys.insert(planned.node, public_key.clone());
        updates.push(NodeUpdate {
            node: planned.node,
            public_key: Some(public_key),
        });
        secrets.insert(planned.node, secret);
    }
    Ok(Rekeyed {
        updates,
        wraps,
        secrets,
    })
}

/// Check that `updates` and `wraps` follow `plan`: the same nodes in the same
/// order, blank exactly where planned, valid keys, and one wrap per planned
/// target, in plan order. The ciphertexts themselves are not checkable.
pub fn check(plan: &Plan, updates: &[NodeUpdate], wraps: &[Wrap]) -> CoreResult<()> {
    if updates.len() != plan.nodes.len() || wraps.len() != plan.wrap_count() {
        return Err(CoreError::Invalid("re-key does not follow its plan"));
    }
    let mut wraps = wraps.iter();
    for (planned, update) in plan.nodes.iter().zip(updates) {
        if update.node != planned.node || update.public_key.is_none() != planned.blank {
            return Err(CoreError::Invalid("re-key does not follow its plan"));
        }
        if let Some(key) = &update.public_key {
            validate_public_key(key)?;
        }
        for target in &planned.wrap_to {
            let wrapped = wraps.next().ok_or(CoreError::Invalid("missing wrap"))?;
            if wrapped.node != planned.node
                || wrapped.target != *target
                || wrapped.sealed.len() != SEALED_SECRET_BYTES
                || wrapped.kem_ciphertext.len() != KEM_CIPHERTEXT_BYTES
            {
                return Err(CoreError::Invalid("wrap does not follow its plan"));
            }
        }
    }
    Ok(())
}

/// How the new secret of a re-keyed node reaches a member below it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Chained from the member's side child, re-keyed by the same window.
    Chain,
    /// Wrapped to the member's side child.
    Wrap(Wrap),
}

/// Index of a window's re-keyed nodes and wraps, to cut the path of any
/// member out of it.
#[derive(Clone, Debug, Default)]
pub struct WindowIndex {
    keyed: HashMap<NodeId, bool>,
    wraps: HashMap<(NodeId, NodeId), Wrap>,
}

impl WindowIndex {
    /// Index `updates` and `wraps` (several commits may be added).
    pub fn add(&mut self, updates: &[NodeUpdate], wraps: &[Wrap]) {
        for update in updates {
            self.keyed.insert(update.node, update.public_key.is_some());
        }
        for wrapped in wraps {
            self.wraps
                .insert((wrapped.node, wrapped.target), wrapped.clone());
        }
    }

    /// Whether the window re-keyed `node`, and whether it is live after.
    #[must_use]
    pub fn keyed(&self, node: NodeId) -> Option<bool> {
        self.keyed.get(&node).copied()
    }

    /// Whether the window re-keyed any node.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keyed.is_empty()
    }

    /// The window's wrap of `node`'s new secret to `target`, if any.
    #[must_use]
    pub fn wrap(&self, node: NodeId, target: NodeId) -> Option<&Wrap> {
        self.wraps.get(&(node, target))
    }

    /// The window's steps along the path of `leaf` in a tree of `height`.
    pub fn steps(&self, leaf: u32, height: u8) -> CoreResult<BTreeMap<u8, Step>> {
        let mut steps = BTreeMap::new();
        for level in 1..=height {
            let node = NodeId::of_leaf(leaf, level);
            match self.keyed.get(&node) {
                None => {}
                Some(false) => return Err(CoreError::Invalid("blank ancestor of a member")),
                Some(true) => {
                    let child = node.child_toward(leaf);
                    let step = self
                        .wraps
                        .get(&(node, child))
                        .map_or(Step::Chain, |wrapped| Step::Wrap(wrapped.clone()));
                    steps.insert(level, step);
                }
            }
        }
        Ok(steps)
    }
}

/// Secrets of a member's path by level, each with the epoch of the window
/// that set it: the node's latest re-key the member knows of.
#[derive(Clone, Default)]
pub struct PathSecrets {
    pub secrets: BTreeMap<u8, Secret>,
    pub epochs: BTreeMap<u8, u64>,
}

impl core::fmt::Debug for PathSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PathSecrets")
            .field("epochs", &self.epochs)
            .finish_non_exhaustive()
    }
}

impl PathSecrets {
    /// Every secret of `secrets`, set by the window of `epoch`.
    #[must_use]
    pub fn at(secrets: BTreeMap<u8, Secret>, epoch: u64) -> Self {
        let epochs = secrets.keys().map(|level| (*level, epoch)).collect();
        Self { secrets, epochs }
    }

    /// Secret of the ancestor at `level`.
    #[must_use]
    pub fn secret(&self, level: u8) -> Option<&Secret> {
        self.secrets.get(&level)
    }

    fn insert(&mut self, level: u8, secret: Secret, epoch: u64) {
        self.secrets.insert(level, secret);
        self.epochs.insert(level, epoch);
    }

    /// The levels up to `top` only.
    #[must_use]
    pub fn up_to(&self, top: u8) -> Self {
        Self {
            secrets: self
                .secrets
                .range(..=top)
                .map(|(level, secret)| (*level, secret.clone()))
                .collect(),
            epochs: self
                .epochs
                .range(..=top)
                .map(|(level, epoch)| (*level, *epoch))
                .collect(),
        }
    }
}

/// A member's private path: its leaf key and the secrets of its ancestors,
/// by level. An island follower knows only the levels up to its island
/// root (docs/specs-v0.5-draft.md section 2.2).
#[derive(Clone)]
pub struct MemberPath {
    leaf: u32,
    leaf_key: KemSecret,
    leaf_pk: Vec<u8>,
    path: PathSecrets,
}

impl core::fmt::Debug for MemberPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemberPath")
            .field("leaf", &self.leaf)
            .field("levels", &self.path.secrets.len())
            .finish_non_exhaustive()
    }
}

impl MemberPath {
    /// A path with only its leaf key known.
    #[must_use]
    pub fn new(leaf: u32, leaf_key: KemSecret) -> Self {
        let leaf_pk = leaf_key.public_key();
        Self {
            leaf,
            leaf_key,
            leaf_pk,
            path: PathSecrets::default(),
        }
    }

    /// The member's leaf.
    #[must_use]
    pub const fn leaf(&self) -> u32 {
        self.leaf
    }

    /// The member's leaf public key.
    #[must_use]
    pub fn leaf_public_key(&self) -> &[u8] {
        &self.leaf_pk
    }

    /// The member's leaf key.
    #[must_use]
    pub const fn leaf_key(&self) -> &KemSecret {
        &self.leaf_key
    }

    /// Secret of the ancestor at `level`.
    #[must_use]
    pub fn secret(&self, level: u8) -> Option<&Secret> {
        self.path.secret(level)
    }

    /// The known secrets, with their epochs.
    #[must_use]
    pub const fn secrets(&self) -> &PathSecrets {
        &self.path
    }

    /// Whether every level from 1 to `height` is known.
    #[must_use]
    pub fn knows(&self, height: u8) -> bool {
        (1..=height).all(|level| self.path.secrets.contains_key(&level))
    }

    /// Replace the leaf key (after an update or a re-entry the member made).
    pub fn set_leaf_key(&mut self, leaf_key: KemSecret) {
        self.leaf_pk = leaf_key.public_key();
        self.leaf_key = leaf_key;
    }

    /// Replace the path secrets.
    pub fn set_path(&mut self, path: PathSecrets) {
        self.path = path;
    }

    /// Walk levels `from..=to` from `base`, which holds the levels below
    /// `from` (and, with `keep_others`, the levels without a step).
    fn walk<'a>(
        &self,
        base: &PathSecrets,
        from: u8,
        to: u8,
        step_at: impl Fn(u8) -> Option<(u64, &'a Step)>,
        keep_others: bool,
        gid: &Digest,
    ) -> CoreResult<PathSecrets> {
        let mut path = base.up_to(from.saturating_sub(1));
        for level in from..=to {
            let Some((epoch, step)) = step_at(level) else {
                if !keep_others {
                    return Err(CoreError::Invalid("missing path step"));
                }
                let (Some(kept), Some(epoch)) = (base.secret(level), base.epochs.get(&level))
                else {
                    return Err(CoreError::Invalid("unknown path secret"));
                };
                path.insert(level, kept.clone(), *epoch);
                continue;
            };
            let secret = self.step_secret(&path, level, epoch, step, gid)?;
            path.insert(level, secret, epoch);
        }
        Ok(path)
    }

    /// The secret of the ancestor at `level` from its step, made by the
    /// window of `epoch`, and from `path`, which holds the levels below.
    fn step_secret(
        &self,
        path: &PathSecrets,
        level: u8,
        epoch: u64,
        step: &Step,
        gid: &Digest,
    ) -> CoreResult<Secret> {
        let node = NodeId::of_leaf(self.leaf, level);
        let child = NodeId::of_leaf(self.leaf, level.saturating_sub(1));
        match step {
            Step::Wrap(wrapped) => {
                if level == 0 || wrapped.node != node || wrapped.target != child {
                    return Err(CoreError::Invalid("wrap off the member's path"));
                }
                if level == 1 {
                    unwrap(gid, epoch, wrapped, &self.leaf_key, &self.leaf_pk)
                } else {
                    let below = path
                        .secret(level - 1)
                        .ok_or(CoreError::Invalid("unknown path secret"))?;
                    let key = node_key(below)?;
                    let pk = key.public_key();
                    unwrap(gid, epoch, wrapped, &key, &pk)
                }
            }
            Step::Chain => {
                if level <= 1 || path.epochs.get(&(level - 1)) != Some(&epoch) {
                    return Err(CoreError::Invalid("chain from a child not re-keyed"));
                }
                chain(
                    path.secret(level - 1)
                        .ok_or(CoreError::Invalid("unknown path secret"))?,
                )
            }
        }
    }

    /// The first level from 1 to `height` whose secret the member cannot
    /// derive as the published key of `nodes` (the path's parents, by level
    /// from 1) demands: its step does not open or does not chain, or gives
    /// another key. `steps` are by level, with the epoch of the window that
    /// made each; a level without a step keeps the secret the member holds.
    /// `None` if every level gives its published key: what a member that a
    /// faulty task cut off names in its repair request
    /// (docs/specs-v0.5-draft.md section 3.7).
    pub fn first_fault(
        &self,
        height: u8,
        steps: &BTreeMap<u8, (u64, Step)>,
        nodes: &[Option<ParentNode>],
        gid: &Digest,
    ) -> CoreResult<Option<u8>> {
        let mut path = PathSecrets::default();
        for level in 1..=height {
            let published = nodes
                .get(usize::from(level - 1))
                .and_then(Option::as_ref)
                .ok_or(CoreError::Invalid("blank ancestor of a member"))?;
            let (secret, epoch) = if let Some((epoch, step)) = steps.get(&level) {
                match self.step_secret(&path, level, *epoch, step, gid) {
                    Ok(secret) => (secret, *epoch),
                    Err(_) => return Ok(Some(level)),
                }
            } else {
                let (Some(kept), Some(epoch)) =
                    (self.path.secret(level), self.path.epochs.get(&level))
                else {
                    return Err(CoreError::Invalid("unknown path secret"));
                };
                (kept.clone(), *epoch)
            };
            if node_key(&secret)?.public_key() != published.encryption_key {
                return Ok(Some(level));
            }
            path.insert(level, secret, epoch);
        }
        Ok(None)
    }

    /// The path secrets up to `height` after a window of epoch `epoch`
    /// whose steps along this path are `steps` (by level); other levels
    /// keep their secret. With `height` the level of its island root, an
    /// island follower advances its island path only.
    pub fn advance(
        &self,
        height: u8,
        steps: &BTreeMap<u8, Step>,
        gid: &Digest,
        epoch: u64,
    ) -> CoreResult<PathSecrets> {
        self.walk(
            &self.path,
            1,
            height,
            |level| steps.get(&level).map(|step| (epoch, step)),
            true,
            gid,
        )
    }

    /// The secrets of levels 1 to `top` after `steps` (by level, with the
    /// epoch of the window that made each); levels without a step keep the
    /// member's.
    pub fn follow_steps(
        &self,
        top: u8,
        steps: &BTreeMap<u8, (u64, Step)>,
        gid: &Digest,
    ) -> CoreResult<PathSecrets> {
        self.walk(
            &self.path,
            1,
            top,
            |level| steps.get(&level).map(|(epoch, step)| (*epoch, step)),
            true,
            gid,
        )
    }

    /// The whole path from the last step of every level, each from the
    /// window that last re-keyed the node (a join, a re-entry or a jump).
    pub fn recover(
        &self,
        height: u8,
        steps: &BTreeMap<u8, (u64, Step)>,
        gid: &Digest,
    ) -> CoreResult<PathSecrets> {
        self.walk(
            &PathSecrets::default(),
            1,
            height,
            |level| steps.get(&level).map(|(epoch, step)| (*epoch, step)),
            false,
            gid,
        )
    }

    /// The levels above `below` up to `height`, from the last step of each
    /// (a refresh, docs/specs-v0.5-draft.md section 2.5), on top of `base`,
    /// which holds the levels up to `below`.
    pub fn refresh(
        &self,
        base: &PathSecrets,
        below: u8,
        height: u8,
        steps: &BTreeMap<u8, (u64, Step)>,
        gid: &Digest,
    ) -> CoreResult<PathSecrets> {
        self.walk(
            base,
            below + 1,
            height,
            |level| steps.get(&level).map(|(epoch, step)| (*epoch, step)),
            false,
            gid,
        )
    }

    /// Check path secrets against the public keys of the path's parents (by
    /// level from 1).
    pub fn check_keys(secrets: &PathSecrets, nodes: &[Option<ParentNode>]) -> CoreResult<()> {
        for (offset, node) in nodes.iter().enumerate() {
            let level = u8::try_from(offset + 1).map_err(|_| CoreError::Invalid("path"))?;
            let node = node
                .as_ref()
                .ok_or(CoreError::Invalid("blank ancestor of a member"))?;
            let secret = secrets
                .secret(level)
                .ok_or(CoreError::Invalid("unknown path secret"))?;
            if node_key(secret)?.public_key() != node.encryption_key {
                return Err(CoreError::Invalid(
                    "path key differs from the published one",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::tree::{Divisions, Occupancy, ParentNode};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const GID: Digest = [4u8; 32];

    struct Fixture {
        tree: PublicTree,
        paths: BTreeMap<u32, MemberPath>,
    }

    fn leaf_node(key: &KemSecret, since: u64) -> LeafNode {
        LeafNode {
            device_pk: vec![1; 8],
            device_id: [1; 32],
            since,
            encryption_key: key.public_key(),
            card: crate::card::Card {
                algorithm: crate::card::CARD_ML_DSA_65,
                public_key: vec![2; 8],
            },
            admission_hash: [0; 32],
            updated: since,
        }
    }

    /// A full tree of `2^height` members in districts of `2^bits`, keyed by one
    /// committer, and every member's path.
    fn fixture(height: u8, bits: u8, rng: &mut ChaCha20Rng) -> Fixture {
        fixture_with(height, Divisions::new(bits, bits, 8).unwrap(), rng)
    }

    /// The same with `divisions`: districts, then every part of the city,
    /// sub-cities before the top.
    fn fixture_with(height: u8, divisions: Divisions, rng: &mut ChaCha20Rng) -> Fixture {
        let mut tree = PublicTree::new(height, divisions).unwrap();
        let mut paths = BTreeMap::new();
        let mut leaves = LeafChanges::new();
        for leaf in 0..(1u32 << height) {
            let key = KemSecret::generate(rng);
            leaves.insert(leaf, Some(leaf_node(&key, 0)));
            paths.insert(leaf, MemberPath::new(leaf, key));
        }
        let committer = Occupancy { leaf: 0, since: 0 };
        let mut roots = BTreeMap::new();
        for district in 0..tree.shape().district_count() {
            let root = tree.shape().district_root(district);
            let mine: LeafChanges = leaves
                .iter()
                .filter(|(leaf, _)| root.covers(**leaf))
                .map(|(leaf, node)| (*leaf, node.clone()))
                .collect();
            let plan =
                plan_district(&tree, tree.shape(), district, &mine, &BTreeSet::new()).unwrap();
            let keys = KeySource {
                tree: &tree,
                shape: tree.shape(),
                leaves: &mine,
                below: None,
            };
            let rekeyed = generate(&plan, &keys, &GID, 0, &[0; 32], rng).unwrap();
            apply(&mut tree, &mine, &rekeyed.updates, committer);
            advance_all(
                &mut paths,
                &tree,
                &rekeyed.updates,
                &rekeyed.wraps,
                Some(root),
            );
            roots.insert(
                district,
                tree.parent(root).map(|p| p.encryption_key.clone()),
            );
        }
        let shape = tree.shape();
        let mut subcity_roots = BTreeMap::new();
        for subcity in 0..shape.subcity_count() {
            let part = CityPart::SubCity(subcity);
            let mine: NewRoots = roots
                .iter()
                .filter(|(district, _)| shape.subcity_of(**district) == subcity)
                .map(|(district, key)| (*district, key.clone()))
                .collect();
            let live = mine.iter().map(|(d, k)| (*d, k.is_some())).collect();
            let plan = plan_part(&tree, shape, part, &live, &BTreeSet::new()).unwrap();
            let keys = KeySource {
                tree: &tree,
                shape,
                leaves: &LeafChanges::new(),
                below: Some((shape.district_level(), &mine)),
            };
            let rekeyed = generate(&plan, &keys, &GID, 0, &[0; 32], rng).unwrap();
            apply(&mut tree, &LeafChanges::new(), &rekeyed.updates, committer);
            let root = shape.part_root(part);
            advance_all(
                &mut paths,
                &tree,
                &rekeyed.updates,
                &rekeyed.wraps,
                Some(root),
            );
            subcity_roots.insert(subcity, tree.parent(root).map(|p| p.encryption_key.clone()));
        }
        if shape.has_top() {
            let live = subcity_roots
                .iter()
                .map(|(k, key)| (*k, key.is_some()))
                .collect();
            let plan = plan_part(&tree, shape, CityPart::Top, &live, &BTreeSet::new()).unwrap();
            let keys = KeySource {
                tree: &tree,
                shape,
                leaves: &LeafChanges::new(),
                below: Some((shape.subcity_level(), &subcity_roots)),
            };
            let rekeyed = generate(&plan, &keys, &GID, 0, &[0; 32], rng).unwrap();
            apply(&mut tree, &LeafChanges::new(), &rekeyed.updates, committer);
            advance_all(&mut paths, &tree, &rekeyed.updates, &rekeyed.wraps, None);
        }
        Fixture { tree, paths }
    }

    fn apply(
        tree: &mut PublicTree,
        leaves: &LeafChanges,
        updates: &[NodeUpdate],
        taint: Occupancy,
    ) {
        for (leaf, node) in leaves {
            tree.set_leaf(*leaf, node.clone()).unwrap();
        }
        for update in updates {
            tree.set_parent(
                update.node,
                update.public_key.clone().map(|encryption_key| ParentNode {
                    encryption_key,
                    taint,
                }),
            )
            .unwrap();
        }
    }

    /// Advance every path the updates reach; `within` limits the levels to a
    /// district while the city is not keyed yet.
    fn advance_all(
        paths: &mut BTreeMap<u32, MemberPath>,
        tree: &PublicTree,
        updates: &[NodeUpdate],
        wraps: &[Wrap],
        within: Option<NodeId>,
    ) {
        for (leaf, path) in paths.iter_mut() {
            if tree.leaf(*leaf).is_none() {
                continue;
            }
            let height = within.map_or(tree.height(), |root| root.level);
            if let Some(root) = within
                && !root.covers(*leaf)
            {
                continue;
            }
            let mut index = WindowIndex::default();
            index.add(updates, wraps);
            let steps = index.steps(*leaf, height).unwrap();
            let mut all = path.advance(height, &steps, &GID, 0).unwrap();
            for level in height + 1..=tree.height() {
                if let (Some(kept), Some(epoch)) =
                    (path.secret(level), path.secrets().epochs.get(&level))
                {
                    all.secrets.insert(level, kept.clone());
                    all.epochs.insert(level, *epoch);
                }
            }
            path.set_path(all);
        }
    }

    #[test]
    fn a_full_rekey_gives_every_member_the_root() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let fixture = fixture(4, 2, &mut rng);
        let root = fixture.tree.height();
        let first = fixture.paths[&0].secret(root).unwrap().clone();
        for path in fixture.paths.values() {
            assert_eq!(**path.secret(root).unwrap(), *first);
        }
    }

    #[test]
    fn three_tiers_give_every_member_the_root() {
        // Districts of two leaves, sub-cities of two districts (roots at
        // level 2), and a top of levels 3 and 4.
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        let fixture = fixture_with(4, Divisions::new(1, 1, 1).unwrap(), &mut rng);
        assert!(fixture.tree.shape().has_top());
        let root = fixture.tree.height();
        let first = fixture.paths[&0].secret(root).unwrap().clone();
        for path in fixture.paths.values() {
            assert_eq!(**path.secret(root).unwrap(), *first);
        }
        // The top plans from the sub-city roots, with a boundary at level 3.
        let tree = &fixture.tree;
        let below = BTreeMap::from([(1u32, true)]);
        let top = plan_part(tree, tree.shape(), CityPart::Top, &below, &BTreeSet::new()).unwrap();
        assert_eq!(top.nodes[0].node, NodeId { level: 3, index: 0 });
        assert_eq!(top.nodes[0].chain_from, None);
        assert_eq!(top.nodes[0].wrap_to.len(), 2);
        assert_eq!(top.nodes[1].chain_from, Some(NodeId { level: 3, index: 0 }));
        // A sub-city plans only its own districts and nodes.
        let foreign = BTreeMap::from([(2u32, true)]);
        assert!(
            plan_part(
                tree,
                tree.shape(),
                CityPart::SubCity(0),
                &foreign,
                &BTreeSet::new()
            )
            .is_err()
        );
        let forced = BTreeSet::from([NodeId { level: 3, index: 0 }]);
        assert!(
            plan_part(
                tree,
                tree.shape(),
                CityPart::SubCity(0),
                &BTreeMap::new(),
                &forced
            )
            .is_err()
        );
        assert!(
            plan_part(
                tree,
                tree.shape(),
                CityPart::SubCity(4),
                &BTreeMap::new(),
                &BTreeSet::new()
            )
            .is_err()
        );
    }

    #[test]
    fn plans_chain_where_possible_and_stop_at_boundaries() {
        let mut rng = ChaCha20Rng::seed_from_u64(10);
        let fixture = fixture(4, 2, &mut rng);
        let tree = &fixture.tree;
        // Two changed leaves in district 1: leaves 4 and 7.
        let mut leaves = LeafChanges::new();
        leaves.insert(4, tree.leaf(4).cloned());
        leaves.insert(7, None);
        let plan = plan_district(tree, tree.shape(), 1, &leaves, &BTreeSet::new()).unwrap();
        let nodes: Vec<NodeId> = plan.nodes.iter().map(|p| p.node).collect();
        assert_eq!(
            nodes,
            vec![
                NodeId { level: 1, index: 2 },
                NodeId { level: 1, index: 3 },
                NodeId { level: 2, index: 1 },
            ]
        );
        // Level 1 is a boundary: both live leaves under (1, 2) get wraps; the
        // removed leaf 7 gets none.
        assert_eq!(plan.nodes[0].chain_from, None);
        assert_eq!(plan.nodes[0].wrap_to.len(), 2);
        assert_eq!(plan.nodes[1].wrap_to, vec![NodeId::leaf(6)]);
        // The district root chains from its left child and wraps to the right.
        assert_eq!(
            plan.nodes[2].chain_from,
            Some(NodeId { level: 1, index: 2 })
        );
        assert_eq!(plan.nodes[2].wrap_to, vec![NodeId { level: 1, index: 3 }]);
        // The city: level 3 is a boundary, level 4 chains.
        let roots = BTreeMap::from([(1u32, true)]);
        let city = plan_part(
            tree,
            tree.shape(),
            CityPart::SubCity(0),
            &roots,
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(city.nodes[0].node, NodeId { level: 3, index: 0 });
        assert_eq!(city.nodes[0].chain_from, None);
        assert_eq!(city.nodes[0].wrap_to.len(), 2);
        assert_eq!(
            city.nodes[1].chain_from,
            Some(NodeId { level: 3, index: 0 })
        );
        assert_eq!(city.nodes[1].wrap_to, vec![NodeId { level: 3, index: 1 }]);
    }

    #[test]
    fn a_window_excludes_the_removed_member_and_reaches_everyone_else() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let mut fixture = fixture(4, 2, &mut rng);
        // Remove leaf 5; leaf 9 updates its key.
        let new_key = KemSecret::generate(&mut rng);
        let mut leaves_1 = LeafChanges::new();
        leaves_1.insert(5, None);
        let mut leaves_2 = LeafChanges::new();
        leaves_2.insert(9, Some(leaf_node(&new_key, 0)));
        let before = fixture.tree.clone();
        let mut all_updates = Vec::new();
        let mut all_wraps = Vec::new();
        let mut roots = BTreeMap::new();
        for (district, leaves) in [(1u32, &leaves_1), (2, &leaves_2)] {
            let plan =
                plan_district(&before, before.shape(), district, leaves, &BTreeSet::new()).unwrap();
            let keys = KeySource {
                tree: &before,
                shape: before.shape(),
                leaves,
                below: None,
            };
            let rekeyed = generate(&plan, &keys, &GID, 1, &[0; 32], &mut rng).unwrap();
            check(&plan, &rekeyed.updates, &rekeyed.wraps).unwrap();
            let root = before.shape().district_root(district);
            let top = rekeyed.updates.last().unwrap();
            assert_eq!(top.node, root);
            roots.insert(district, top.public_key.clone());
            all_updates.extend(rekeyed.updates);
            all_wraps.extend(rekeyed.wraps);
        }
        let live = roots.iter().map(|(d, k)| (*d, k.is_some())).collect();
        let city_plan = plan_part(
            &before,
            before.shape(),
            CityPart::SubCity(0),
            &live,
            &BTreeSet::new(),
        )
        .unwrap();
        let empty = LeafChanges::new();
        let keys = KeySource {
            tree: &before,
            shape: before.shape(),
            leaves: &empty,
            below: Some((before.shape().district_level(), &roots)),
        };
        let city = generate(&city_plan, &keys, &GID, 1, &[0; 32], &mut rng).unwrap();
        check(&city_plan, &city.updates, &city.wraps).unwrap();
        all_updates.extend(city.updates.clone());
        all_wraps.extend(city.wraps.clone());
        let root_secret = city.secret(before.shape().root()).unwrap().clone();

        fixture.paths.get_mut(&9).unwrap().set_leaf_key(new_key);
        let mut index = WindowIndex::default();
        index.add(&all_updates, &all_wraps);
        for (leaf, path) in &fixture.paths {
            let result = index
                .steps(*leaf, 4)
                .and_then(|steps| path.advance(4, &steps, &GID, 1));
            if *leaf == 5 {
                assert!(result.is_err(), "the removed member must not follow");
            } else {
                let secrets = result.unwrap();
                assert_eq!(**secrets.secret(4).unwrap(), *root_secret, "leaf {leaf}");
            }
        }
        // Ignoring the index, the removed member's old path opens no wrap.
        let removed = &fixture.paths[&5];
        let forged: BTreeMap<u8, Step> = all_wraps
            .iter()
            .filter(|w| w.node == NodeId::of_leaf(5, w.node.level))
            .map(|w| (w.node.level, Step::Wrap(w.clone())))
            .collect();
        assert!(removed.advance(4, &forged, &GID, 1).is_err());
        // The removed member knew every secret of its old path: none opens a
        // wrap of the window, and none is the new root.
        let removed = &fixture.paths[&5];
        for level in 1..=4u8 {
            let old = removed.secret(level).unwrap();
            assert_ne!(**old, *root_secret);
            let key = node_key(old).unwrap();
            let pk = key.public_key();
            for wrapped in &all_wraps {
                assert!(unwrap(&GID, 1, wrapped, &key, &pk).is_err());
            }
        }
    }

    #[test]
    fn check_rejects_a_commit_that_leaves_the_plan() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let fixture = fixture(3, 2, &mut rng);
        let mut leaves = LeafChanges::new();
        leaves.insert(2, None);
        let plan = plan_district(
            &fixture.tree,
            fixture.tree.shape(),
            0,
            &leaves,
            &BTreeSet::new(),
        )
        .unwrap();
        let keys = KeySource {
            tree: &fixture.tree,
            shape: fixture.tree.shape(),
            leaves: &leaves,
            below: None,
        };
        let rekeyed = generate(&plan, &keys, &GID, 1, &[0; 32], &mut rng).unwrap();
        check(&plan, &rekeyed.updates, &rekeyed.wraps).unwrap();
        let mut missing = rekeyed.wraps.clone();
        missing.pop();
        assert!(check(&plan, &rekeyed.updates, &missing).is_err());
        let mut retargeted = rekeyed.wraps.clone();
        retargeted[0].target = NodeId::leaf(2);
        assert!(check(&plan, &rekeyed.updates, &retargeted).is_err());
        let mut blanked = rekeyed.updates.clone();
        blanked[0].public_key = None;
        assert!(check(&plan, &blanked, &rekeyed.wraps).is_err());
    }
}
