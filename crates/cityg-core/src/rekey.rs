//! Multi-path re-key of a district or of the city (docs/specs.md section 7).
//!
//! A window re-keys every ancestor of a changed base node, and every node
//! tainted by a member the window removes or updates, with its ancestors.
//! For a district the base nodes are the changed leaves; for the city, the
//! roots of the districts that changed. Nodes are processed bottom-up:
//!
//! * a node with no live child becomes blank;
//! * otherwise, if some live child was re-keyed by the same commit and the
//!   level is not a *boundary*, the node's secret is `chain(child)`, taken
//!   from the first such child (left first), and it is wrapped to the other
//!   live child, if any;
//! * otherwise the node gets a fresh secret, wrapped to every live child.
//!
//! Boundaries are the levels where the committer knows no child's new
//! secret: level 1 (the children are the members' leaves) and, in the city,
//! level `L + 1` (the children are district roots re-keyed by district
//! committers).
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
use crate::tree::{LeafNode, NodeId, ParentNode, PublicTree, Shape};

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
    if district >= shape.district_count() || shape.district_bits != tree.district_bits() {
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

/// Plan the re-key of the city. `roots` gives, for every district of the
/// window, whether its root is live after the window; `forced` the other
/// city nodes to re-key. A tree no taller than a district has no city.
pub fn plan_city(
    tree: &PublicTree,
    shape: Shape,
    roots: &BTreeMap<u32, bool>,
    forced: &BTreeSet<NodeId>,
) -> CoreResult<Plan> {
    let district_level = shape.district_bits;
    if !shape.has_city() {
        if forced.is_empty() {
            return Ok(Plan::default());
        }
        return Err(CoreError::Invalid("city node in a one-district tree"));
    }
    let top = shape.height;
    let mut set = BTreeSet::new();
    for district in roots.keys() {
        if *district >= shape.district_count() {
            return Err(CoreError::Invalid("district index"));
        }
        collect(
            &mut set,
            NodeId {
                level: district_level + 1,
                index: district >> 1,
            },
            top,
        );
    }
    for node in forced {
        if node.level <= district_level || !shape.contains(*node) {
            return Err(CoreError::Invalid("forced node outside the city"));
        }
        collect(&mut set, *node, top);
    }
    Ok(build(
        set,
        |child| {
            if child.level == district_level {
                roots
                    .get(&child.index)
                    .copied()
                    .unwrap_or_else(|| tree.parent(child).is_some())
            } else {
                tree.parent(child).is_some()
            }
        },
        |level| level == district_level + 1,
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

/// Where a committer finds the key of a wrap target: the changed leaves,
/// the new district roots (for the city), then the tree before the window.
pub struct KeySource<'a> {
    pub tree: &'a PublicTree,
    pub shape: Shape,
    pub leaves: &'a LeafChanges,
    pub roots: Option<&'a BTreeMap<u32, Option<Vec<u8>>>>,
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
        } else if node.level == self.shape.district_level()
            && let Some(change) = self.roots.and_then(|roots| roots.get(&node.index))
        {
            return change
                .clone()
                .ok_or(CoreError::Invalid("wrap to a blank district"));
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

/// A member's private path: its leaf key and the secrets of its ancestors,
/// by level.
#[derive(Clone)]
pub struct MemberPath {
    leaf: u32,
    leaf_key: KemSecret,
    leaf_pk: Vec<u8>,
    secrets: BTreeMap<u8, Secret>,
}

impl core::fmt::Debug for MemberPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemberPath")
            .field("leaf", &self.leaf)
            .field("levels", &self.secrets.len())
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
            secrets: BTreeMap::new(),
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
        self.secrets.get(&level)
    }

    /// Replace the leaf key (after an update or a re-entry the member made).
    pub fn set_leaf_key(&mut self, leaf_key: KemSecret) {
        self.leaf_pk = leaf_key.public_key();
        self.leaf_key = leaf_key;
    }

    /// Replace the path secrets.
    pub fn set_secrets(&mut self, secrets: BTreeMap<u8, Secret>) {
        self.secrets = secrets;
    }

    fn walk<'a>(
        &self,
        height: u8,
        step_at: impl Fn(u8) -> Option<(u64, &'a Step)>,
        keep_others: bool,
        gid: &Digest,
    ) -> CoreResult<BTreeMap<u8, Secret>> {
        let mut path: BTreeMap<u8, Secret> = BTreeMap::new();
        let mut epochs: BTreeMap<u8, u64> = BTreeMap::new();
        for level in 1..=height {
            let node = NodeId::of_leaf(self.leaf, level);
            let child = NodeId::of_leaf(self.leaf, level - 1);
            let Some((epoch, step)) = step_at(level) else {
                if !keep_others {
                    return Err(CoreError::Invalid("missing path step"));
                }
                let kept = self
                    .secrets
                    .get(&level)
                    .ok_or(CoreError::Invalid("unknown path secret"))?;
                path.insert(level, kept.clone());
                continue;
            };
            let secret = match step {
                Step::Wrap(wrapped) => {
                    if wrapped.node != node || wrapped.target != child {
                        return Err(CoreError::Invalid("wrap off the member's path"));
                    }
                    if level == 1 {
                        unwrap(gid, epoch, wrapped, &self.leaf_key, &self.leaf_pk)?
                    } else {
                        let below = path
                            .get(&(level - 1))
                            .ok_or(CoreError::Invalid("unknown path secret"))?;
                        let key = node_key(below)?;
                        let pk = key.public_key();
                        unwrap(gid, epoch, wrapped, &key, &pk)?
                    }
                }
                Step::Chain => {
                    if level == 1 || epochs.get(&(level - 1)) != Some(&epoch) {
                        return Err(CoreError::Invalid("chain from a child not re-keyed"));
                    }
                    chain(
                        path.get(&(level - 1))
                            .ok_or(CoreError::Invalid("unknown path secret"))?,
                    )?
                }
            };
            epochs.insert(level, epoch);
            path.insert(level, secret);
        }
        Ok(path)
    }

    /// The path secrets after a window of epoch `epoch` whose steps along
    /// this path are `steps` (by level); other levels keep their secret.
    pub fn advance(
        &self,
        height: u8,
        steps: &BTreeMap<u8, Step>,
        gid: &Digest,
        epoch: u64,
    ) -> CoreResult<BTreeMap<u8, Secret>> {
        self.walk(
            height,
            |level| steps.get(&level).map(|step| (epoch, step)),
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
    ) -> CoreResult<BTreeMap<u8, Secret>> {
        self.walk(
            height,
            |level| steps.get(&level).map(|(epoch, step)| (*epoch, step)),
            false,
            gid,
        )
    }

    /// Check path secrets against the public keys of the path's parents (by
    /// level from 1).
    pub fn check_keys(
        secrets: &BTreeMap<u8, Secret>,
        nodes: &[Option<ParentNode>],
    ) -> CoreResult<()> {
        for (offset, node) in nodes.iter().enumerate() {
            let level = u8::try_from(offset + 1).map_err(|_| CoreError::Invalid("path"))?;
            let node = node
                .as_ref()
                .ok_or(CoreError::Invalid("blank ancestor of a member"))?;
            let secret = secrets
                .get(&level)
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
    use crate::tree::{Occupancy, ParentNode};
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
            since,
            encryption_key: key.public_key(),
            admission_hash: [0; 32],
            updated: since,
        }
    }

    /// A full tree of `2^height` members in districts of `2^bits`, keyed by one
    /// committer, and every member's path.
    fn fixture(height: u8, bits: u8, rng: &mut ChaCha20Rng) -> Fixture {
        let mut tree = PublicTree::new(height, bits).unwrap();
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
                roots: None,
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
        let live: BTreeMap<u32, bool> = roots.iter().map(|(d, k)| (*d, k.is_some())).collect();
        let plan = plan_city(&tree, tree.shape(), &live, &BTreeSet::new()).unwrap();
        let keys = KeySource {
            tree: &tree,
            shape: tree.shape(),
            leaves: &LeafChanges::new(),
            roots: Some(&roots),
        };
        let rekeyed = generate(&plan, &keys, &GID, 0, &[0; 32], rng).unwrap();
        apply(&mut tree, &LeafChanges::new(), &rekeyed.updates, committer);
        advance_all(&mut paths, &tree, &rekeyed.updates, &rekeyed.wraps, None);
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
            let secrets = path.advance(height, &steps, &GID, 0).unwrap();
            let mut all = secrets;
            for level in height + 1..=tree.height() {
                if let Some(kept) = path.secret(level) {
                    all.insert(level, kept.clone());
                }
            }
            path.set_secrets(all);
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
        let city = plan_city(tree, tree.shape(), &roots, &BTreeSet::new()).unwrap();
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
                roots: None,
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
        let city_plan = plan_city(&before, before.shape(), &live, &BTreeSet::new()).unwrap();
        let empty = LeafChanges::new();
        let keys = KeySource {
            tree: &before,
            shape: before.shape(),
            leaves: &empty,
            roots: Some(&roots),
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
                assert_eq!(*secrets[&4], *root_secret, "leaf {leaf}");
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
            roots: None,
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
