//! Public tree of profile v0.4-draft: sparse, split into districts under a
//! city (docs/specs-v0.4-draft.md section 5).
//!
//! A node is addressed by `(level, index)`: leaves are level 0, and node
//! `(k, i)` is the ancestor at level `k` of leaves `i·2^k .. (i+1)·2^k`.
//! The tree has `2^height` leaves. With `L = district_bits`, a *district*
//! is the subtree of `2^L` leaves under node `(L, d)` when `height > L`; a
//! group whose tree is not taller than a district has one district, whose
//! root is the tree's root.
//!
//! Only occupied leaves and non-blank parent nodes are stored. A parent node
//! is blank exactly when its subtree holds no member; every stored parent
//! carries its X-Wing key and its *taint*, the occupancy of the committer
//! that drew its current secret.
//!
//! Hashes (no index: the position follows from the structure):
//! * `leaf_hash := H_L("tree/leaf", [leaf or null])`;
//! * `content := H_L("tree/node", [key, taint])` for a non-blank parent;
//! * `node_hash := H_L("tree/parent", [content or null, left, right])`.
//!
//! Hashing the content of a parent separately keeps a leaf proof at 64 bytes
//! per level.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Range;

use ciborium::value::Value;
use cityg_core::cbor::{array, bytes, expect_array, expect_bytes, expect_u32, expect_uint, uint};
use cityg_core::error::{CoreError, CoreResult};
use cityg_core::hash::Digest;

use crate::crypto::h_l;

/// Largest supported tree: `2^MAX_HEIGHT` leaves.
pub const MAX_HEIGHT: u8 = 24;

/// Address of a node: level 0 for leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId {
    pub level: u8,
    pub index: u32,
}

impl NodeId {
    /// The leaf `index`.
    #[must_use]
    pub const fn leaf(index: u32) -> Self {
        Self { level: 0, index }
    }

    /// The ancestor at `level` of leaf `leaf`.
    #[must_use]
    pub const fn of_leaf(leaf: u32, level: u8) -> Self {
        Self {
            level,
            index: leaf >> level,
        }
    }

    /// The ancestor of this node at `level` (`level >= self.level`).
    #[must_use]
    pub const fn ancestor(self, level: u8) -> Self {
        Self {
            level,
            index: self.index >> (level - self.level),
        }
    }

    /// Parent node.
    #[must_use]
    pub const fn parent(self) -> Self {
        self.ancestor(self.level + 1)
    }

    /// Left and right children (`level >= 1`).
    #[must_use]
    pub const fn children(self) -> [Self; 2] {
        [
            Self {
                level: self.level - 1,
                index: self.index << 1,
            },
            Self {
                level: self.level - 1,
                index: (self.index << 1) | 1,
            },
        ]
    }

    /// The child of this node on the side of leaf `leaf` (`level >= 1`).
    #[must_use]
    pub const fn child_toward(self, leaf: u32) -> Self {
        Self::of_leaf(leaf, self.level - 1)
    }

    /// Leaves under this node.
    #[must_use]
    pub fn leaves(self) -> Range<u64> {
        let first = u64::from(self.index) << self.level;
        first..first + (1u64 << self.level)
    }

    /// Whether leaf `leaf` is under this node.
    #[must_use]
    pub const fn covers(self, leaf: u32) -> bool {
        (leaf >> self.level) == self.index
    }

    /// Whether `node` is this node or below it.
    #[must_use]
    pub const fn is_above_or_at(self, node: Self) -> bool {
        node.level <= self.level && (node.index >> (self.level - node.level)) == self.index
    }

    /// CBOR `[level, index]`.
    #[must_use]
    pub fn value(self) -> Value {
        array(vec![
            uint(u64::from(self.level)),
            uint(u64::from(self.index)),
        ])
    }

    /// Read `[level, index]`.
    pub fn from_value(value: Value, what: &'static str) -> CoreResult<Self> {
        let items = expect_array(value, 2, what)?;
        let level =
            u8::try_from(expect_uint(&items[0], what)?).map_err(|_| CoreError::Malformed(what))?;
        if level > MAX_HEIGHT {
            return Err(CoreError::Malformed(what));
        }
        Ok(Self {
            level,
            index: expect_u32(&items[1], what)?,
        })
    }
}

/// An occupancy `[leaf, since]`: a member, named by its leaf and the epoch
/// it entered it. It is never reused, even when the leaf is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Occupancy {
    pub leaf: u32,
    pub since: u64,
}

impl Occupancy {
    /// CBOR `[leaf, since]`.
    #[must_use]
    pub fn value(self) -> Value {
        array(vec![uint(u64::from(self.leaf)), uint(self.since)])
    }

    /// Read `[leaf, since]`.
    pub fn from_value(value: Value, what: &'static str) -> CoreResult<Self> {
        let items = expect_array(value, 2, what)?;
        Ok(Self {
            leaf: expect_u32(&items[0], what)?,
            since: expect_uint(&items[1], what)?,
        })
    }
}

/// Dimensions of a tree: `2^height` leaves in districts of `2^district_bits`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub height: u8,
    pub district_bits: u8,
}

impl Shape {
    /// Check the dimensions.
    pub fn new(height: u8, district_bits: u8) -> CoreResult<Self> {
        if !(1..=MAX_HEIGHT).contains(&height) || !(1..=MAX_HEIGHT).contains(&district_bits) {
            return Err(CoreError::Invalid("tree dimensions"));
        }
        Ok(Self {
            height,
            district_bits,
        })
    }

    /// The same districts in a tree of `2^height` leaves (`height` not
    /// smaller than the current one).
    pub fn grown(self, height: u8) -> CoreResult<Self> {
        if height < self.height {
            return Err(CoreError::Invalid("tree growth"));
        }
        Self::new(height, self.district_bits)
    }

    /// Number of leaves, `2^height`.
    #[must_use]
    pub const fn width(self) -> u64 {
        1u64 << self.height
    }

    /// Whether the tree has levels above the districts.
    #[must_use]
    pub const fn has_city(self) -> bool {
        self.height > self.district_bits
    }

    /// Level of the district roots: `min(L, height)`.
    #[must_use]
    pub fn district_level(self) -> u8 {
        self.district_bits.min(self.height)
    }

    /// Number of districts.
    #[must_use]
    pub const fn district_count(self) -> u32 {
        if self.has_city() {
            1 << (self.height - self.district_bits)
        } else {
            1
        }
    }

    /// District of a leaf.
    #[must_use]
    pub const fn district_of(self, leaf: u32) -> u32 {
        if self.has_city() {
            leaf >> self.district_bits
        } else {
            0
        }
    }

    /// District of a node at or below the district level.
    #[must_use]
    pub fn district_of_node(self, node: NodeId) -> u32 {
        node.ancestor(self.district_level()).index
    }

    /// Root node of district `district`.
    #[must_use]
    pub fn district_root(self, district: u32) -> NodeId {
        NodeId {
            level: self.district_level(),
            index: district,
        }
    }

    /// The root.
    #[must_use]
    pub const fn root(self) -> NodeId {
        NodeId {
            level: self.height,
            index: 0,
        }
    }

    /// Whether `node` exists in a tree of this shape.
    #[must_use]
    pub fn contains(self, node: NodeId) -> bool {
        node.level <= self.height && u64::from(node.index) < (1u64 << (self.height - node.level))
    }

    /// Whether leaf `leaf` exists in a tree of this shape.
    #[must_use]
    pub fn contains_leaf(self, leaf: u32) -> bool {
        u64::from(leaf) < self.width()
    }
}

/// A member's leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafNode {
    /// ML-DSA-65 device key.
    pub device_pk: Vec<u8>,
    /// Epoch the occupancy began.
    pub since: u64,
    /// X-Wing leaf key.
    pub encryption_key: Vec<u8>,
    /// Hash of the admission it entered with (`ZERO32` for the creator).
    pub admission_hash: Digest,
    /// Epoch its leaf key last changed.
    pub updated: u64,
}

impl LeafNode {
    /// CBOR `[device_pk, since, encryption_key, admission_hash, updated]`.
    #[must_use]
    pub fn value(&self) -> Value {
        array(vec![
            bytes(&self.device_pk),
            uint(self.since),
            bytes(&self.encryption_key),
            bytes(&self.admission_hash),
            uint(self.updated),
        ])
    }

    /// Read a leaf node.
    pub fn from_value(value: Value) -> CoreResult<Self> {
        const WHAT: &str = "leaf node";
        let mut items = expect_array(value, 5, WHAT)?.into_iter();
        let mut next = || items.next().ok_or(CoreError::Malformed(WHAT));
        let device_pk = expect_bytes(next()?, WHAT)?;
        let since = expect_uint(&next()?, WHAT)?;
        let encryption_key = expect_bytes(next()?, WHAT)?;
        let admission_hash = expect_bytes(next()?, WHAT)?
            .try_into()
            .map_err(|_| CoreError::Malformed(WHAT))?;
        let updated = expect_uint(&next()?, WHAT)?;
        Ok(Self {
            device_pk,
            since,
            encryption_key,
            admission_hash,
            updated,
        })
    }

    /// The occupancy of this leaf.
    #[must_use]
    pub const fn occupancy(&self, leaf: u32) -> Occupancy {
        Occupancy {
            leaf,
            since: self.since,
        }
    }
}

/// A non-blank parent node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentNode {
    /// X-Wing key derived from the node's secret.
    pub encryption_key: Vec<u8>,
    /// Occupancy of the committer that drew the secret.
    pub taint: Occupancy,
}

impl ParentNode {
    /// `H_L("tree/node", [key, taint])`.
    pub fn content_digest(&self) -> CoreResult<Digest> {
        h_l(
            "tree/node",
            vec![bytes(&self.encryption_key), self.taint.value()],
        )
    }
}

fn leaf_hash(leaf: Option<&LeafNode>) -> CoreResult<Digest> {
    h_l("tree/leaf", vec![leaf.map_or(Value::Null, LeafNode::value)])
}

fn parent_hash(content: Option<&Digest>, left: &Digest, right: &Digest) -> CoreResult<Digest> {
    h_l(
        "tree/parent",
        vec![
            content.map_or(Value::Null, |digest| bytes(digest)),
            bytes(left),
            bytes(right),
        ],
    )
}

fn empty_hashes() -> CoreResult<Vec<Digest>> {
    let mut empty = vec![leaf_hash(None)?];
    for level in 1..=usize::from(MAX_HEIGHT) {
        let below = empty[level - 1];
        empty.push(parent_hash(None, &below, &below)?);
    }
    Ok(empty)
}

/// Changes to a tree: leaves and parent nodes to set (`Some`) or blank
/// (`None`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TreeDelta {
    pub leaves: BTreeMap<u32, Option<LeafNode>>,
    pub parents: BTreeMap<NodeId, Option<ParentNode>>,
}

/// The public tree.
#[derive(Clone, Debug)]
pub struct PublicTree {
    shape: Shape,
    leaves: BTreeMap<u32, LeafNode>,
    parents: HashMap<NodeId, ParentNode>,
    taints: HashMap<Occupancy, BTreeSet<NodeId>>,
    empty: Vec<Digest>,
    cache: RefCell<HashMap<NodeId, Digest>>,
}

impl PublicTree {
    /// An empty tree of `2^height` leaves in districts of `2^district_bits`.
    pub fn new(height: u8, district_bits: u8) -> CoreResult<Self> {
        Ok(Self {
            shape: Shape::new(height, district_bits)?,
            leaves: BTreeMap::new(),
            parents: HashMap::new(),
            taints: HashMap::new(),
            empty: empty_hashes()?,
            cache: RefCell::new(HashMap::new()),
        })
    }

    /// Dimensions of the tree.
    #[must_use]
    pub const fn shape(&self) -> Shape {
        self.shape
    }

    /// `height`: the tree has `2^height` leaves.
    #[must_use]
    pub const fn height(&self) -> u8 {
        self.shape.height
    }

    /// `L`: districts hold `2^L` leaves.
    #[must_use]
    pub const fn district_bits(&self) -> u8 {
        self.shape.district_bits
    }

    /// Hash of an empty subtree whose root is at `level`.
    #[must_use]
    pub fn empty_hash(&self, level: u8) -> Digest {
        self.empty[usize::from(level.min(MAX_HEIGHT))]
    }

    /// The leaf at `index`, if occupied.
    #[must_use]
    pub fn leaf(&self, index: u32) -> Option<&LeafNode> {
        self.leaves.get(&index)
    }

    /// Occupied leaves, in index order.
    pub fn leaves(&self) -> impl Iterator<Item = (u32, &LeafNode)> {
        self.leaves.iter().map(|(index, leaf)| (*index, leaf))
    }

    /// Occupied leaves under `node`.
    pub fn leaves_under(&self, node: NodeId) -> impl Iterator<Item = (u32, &LeafNode)> {
        let range = node.leaves();
        let start = u32::try_from(range.start).unwrap_or(u32::MAX);
        let end = u32::try_from(range.end).unwrap_or(u32::MAX);
        self.leaves
            .range(start..end)
            .map(|(index, leaf)| (*index, leaf))
    }

    /// Number of members.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.leaves.len()
    }

    /// Occupancy of leaf `index`, if occupied.
    #[must_use]
    pub fn occupancy(&self, index: u32) -> Option<Occupancy> {
        self.leaves.get(&index).map(|leaf| leaf.occupancy(index))
    }

    /// Whether `occupancy` is a current member.
    #[must_use]
    pub fn is_member(&self, occupancy: Occupancy) -> bool {
        self.occupancy(occupancy.leaf) == Some(occupancy)
    }

    /// The leaf of `occupancy`, if it is a current member.
    #[must_use]
    pub fn member(&self, occupancy: Occupancy) -> Option<&LeafNode> {
        self.leaves
            .get(&occupancy.leaf)
            .filter(|leaf| leaf.since == occupancy.since)
    }

    /// The parent node `node`, if not blank.
    #[must_use]
    pub fn parent(&self, node: NodeId) -> Option<&ParentNode> {
        self.parents.get(&node)
    }

    /// X-Wing key of `node`: the leaf key of a leaf, the key of a parent.
    #[must_use]
    pub fn public_key(&self, node: NodeId) -> Option<&[u8]> {
        if node.level == 0 {
            self.leaves
                .get(&node.index)
                .map(|leaf| leaf.encryption_key.as_slice())
        } else {
            self.parents
                .get(&node)
                .map(|parent| parent.encryption_key.as_slice())
        }
    }

    /// Nodes whose current secret was drawn by `occupancy`.
    #[must_use]
    pub fn tainted_by(&self, occupancy: Occupancy) -> BTreeSet<NodeId> {
        self.taints.get(&occupancy).cloned().unwrap_or_default()
    }

    fn invalidate(&self, node: NodeId) {
        let mut cache = self.cache.borrow_mut();
        for level in node.level..=self.shape.height {
            cache.remove(&node.ancestor(level));
        }
    }

    /// Set or blank leaf `index`.
    pub fn set_leaf(&mut self, index: u32, leaf: Option<LeafNode>) -> CoreResult<()> {
        if !self.shape.contains_leaf(index) {
            return Err(CoreError::Invalid("leaf index"));
        }
        match leaf {
            Some(leaf) => {
                self.leaves.insert(index, leaf);
            }
            None => {
                self.leaves.remove(&index);
            }
        }
        self.invalidate(NodeId::leaf(index));
        Ok(())
    }

    /// Set or blank parent node `node`.
    pub fn set_parent(&mut self, node: NodeId, parent: Option<ParentNode>) -> CoreResult<()> {
        if node.level == 0 || !self.shape.contains(node) {
            return Err(CoreError::Invalid("parent node"));
        }
        if let Some(old) = self.parents.remove(&node)
            && let Some(set) = self.taints.get_mut(&old.taint)
        {
            set.remove(&node);
            if set.is_empty() {
                self.taints.remove(&old.taint);
            }
        }
        if let Some(parent) = parent {
            self.taints.entry(parent.taint).or_default().insert(node);
            self.parents.insert(node, parent);
        }
        self.invalidate(node);
        Ok(())
    }

    /// Grow the tree to `2^height` leaves. The old root becomes the leftmost
    /// node of its level; the nodes above it are blank until a window re-keys
    /// them.
    pub fn grow_to(&mut self, height: u8) -> CoreResult<()> {
        self.shape = self.shape.grown(height)?;
        self.cache.borrow_mut().clear();
        Ok(())
    }

    /// Grow to `shape` and apply `delta`.
    pub fn apply(&mut self, shape: Shape, delta: &TreeDelta) -> CoreResult<()> {
        if shape.district_bits != self.shape.district_bits {
            return Err(CoreError::Invalid("district size"));
        }
        if shape.height != self.shape.height {
            self.grow_to(shape.height)?;
        }
        for (index, leaf) in &delta.leaves {
            self.set_leaf(*index, leaf.clone())?;
        }
        for (node, parent) in &delta.parents {
            self.set_parent(*node, parent.clone())?;
        }
        Ok(())
    }

    /// Hash of the subtree under `node`.
    pub fn node_hash(&self, node: NodeId) -> CoreResult<Digest> {
        if !self.shape.contains(node) {
            return Err(CoreError::Invalid("node"));
        }
        if let Some(hash) = self.cache.borrow().get(&node) {
            return Ok(*hash);
        }
        let hash = if node.level == 0 {
            leaf_hash(self.leaves.get(&node.index))?
        } else if !self.parents.contains_key(&node) && self.leaves_under(node).next().is_none() {
            self.empty[usize::from(node.level)]
        } else {
            let [left, right] = node.children();
            let left = self.node_hash(left)?;
            let right = self.node_hash(right)?;
            let content = self
                .parents
                .get(&node)
                .map(ParentNode::content_digest)
                .transpose()?;
            parent_hash(content.as_ref(), &left, &right)?
        };
        self.cache.borrow_mut().insert(node, hash);
        Ok(hash)
    }

    /// Hash of the whole tree.
    pub fn tree_hash(&self) -> CoreResult<Digest> {
        self.node_hash(self.shape.root())
    }

    /// Hash of district `district`.
    pub fn district_hash(&self, district: u32) -> CoreResult<Digest> {
        self.node_hash(self.shape.district_root(district))
    }

    /// Proof of leaf `index` against the tree hash.
    pub fn leaf_proof(&self, index: u32) -> CoreResult<LeafProof> {
        if !self.shape.contains_leaf(index) {
            return Err(CoreError::Invalid("leaf index"));
        }
        let mut steps = Vec::with_capacity(usize::from(self.shape.height));
        for level in 1..=self.shape.height {
            let node = NodeId::of_leaf(index, level);
            let child = NodeId::of_leaf(index, level - 1);
            let [left, right] = node.children();
            let sibling = if child == left { right } else { left };
            steps.push(ProofStep {
                content: self
                    .parents
                    .get(&node)
                    .map(ParentNode::content_digest)
                    .transpose()?,
                sibling_hash: self.node_hash(sibling)?,
            });
        }
        Ok(LeafProof {
            index,
            leaf: self.leaves.get(&index).cloned(),
            steps,
        })
    }

    /// The parent nodes on the path of leaf `index`, by level from 1 (blank
    /// levels are `None`).
    #[must_use]
    pub fn path_nodes(&self, index: u32) -> Vec<Option<ParentNode>> {
        (1..=self.shape.height)
            .map(|level| self.parents.get(&NodeId::of_leaf(index, level)).cloned())
            .collect()
    }
}

/// A tree after a window that has not been applied yet: a base tree, the
/// window's shape and its delta. Hashes of untouched subtrees come from the
/// base tree's cache.
pub struct Overlay<'a> {
    base: &'a PublicTree,
    shape: Shape,
    delta: &'a TreeDelta,
    dirty: HashSet<NodeId>,
    memo: RefCell<HashMap<NodeId, Digest>>,
}

impl<'a> Overlay<'a> {
    /// `base` grown to `shape` with `delta` applied.
    pub fn new(base: &'a PublicTree, shape: Shape, delta: &'a TreeDelta) -> CoreResult<Self> {
        if shape.district_bits != base.shape.district_bits || shape.height < base.shape.height {
            return Err(CoreError::Invalid("overlay shape"));
        }
        let mut dirty = HashSet::new();
        let changed = delta
            .leaves
            .keys()
            .map(|index| NodeId::leaf(*index))
            .chain(delta.parents.keys().copied());
        for node in changed {
            if !shape.contains(node) {
                return Err(CoreError::Invalid("changed node outside the tree"));
            }
            for level in node.level..=shape.height {
                if !dirty.insert(node.ancestor(level)) {
                    break;
                }
            }
        }
        Ok(Self {
            base,
            shape,
            delta,
            dirty,
            memo: RefCell::new(HashMap::new()),
        })
    }

    /// Shape after the window.
    #[must_use]
    pub const fn shape(&self) -> Shape {
        self.shape
    }

    /// Leaf `index` after the window.
    #[must_use]
    pub fn leaf(&self, index: u32) -> Option<&LeafNode> {
        match self.delta.leaves.get(&index) {
            Some(change) => change.as_ref(),
            None => self.base.leaf(index),
        }
    }

    /// Parent node `node` after the window.
    #[must_use]
    pub fn parent(&self, node: NodeId) -> Option<&ParentNode> {
        match self.delta.parents.get(&node) {
            Some(change) => change.as_ref(),
            None => self.base.parent(node),
        }
    }

    /// Hash of the subtree under `node` after the window.
    pub fn node_hash(&self, node: NodeId) -> CoreResult<Digest> {
        if !self.shape.contains(node) {
            return Err(CoreError::Invalid("node"));
        }
        if !self.dirty.contains(&node) {
            if self.base.shape.contains(node) {
                return self.base.node_hash(node);
            }
            if node.level <= self.base.shape.height || node.index != 0 {
                // Grown region with no change: empty.
                return Ok(self.base.empty_hash(node.level));
            }
        }
        if let Some(hash) = self.memo.borrow().get(&node) {
            return Ok(*hash);
        }
        let hash = if node.level == 0 {
            leaf_hash(self.leaf(node.index))?
        } else {
            let [left, right] = node.children();
            let left = self.node_hash(left)?;
            let right = self.node_hash(right)?;
            let content = self
                .parent(node)
                .map(ParentNode::content_digest)
                .transpose()?;
            parent_hash(content.as_ref(), &left, &right)?
        };
        self.memo.borrow_mut().insert(node, hash);
        Ok(hash)
    }

    /// Tree hash after the window.
    pub fn tree_hash(&self) -> CoreResult<Digest> {
        self.node_hash(self.shape.root())
    }

    /// Hash of district `district` after the window.
    pub fn district_hash(&self, district: u32) -> CoreResult<Digest> {
        self.node_hash(self.shape.district_root(district))
    }
}

/// One level of a leaf proof: the content digest of the parent (if not
/// blank) and the hash of the sibling subtree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofStep {
    pub content: Option<Digest>,
    pub sibling_hash: Digest,
}

/// A leaf and what it takes to recompute the tree hash from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafProof {
    pub index: u32,
    pub leaf: Option<LeafNode>,
    pub steps: Vec<ProofStep>,
}

impl LeafProof {
    /// Recompute the tree hash and compare it with `tree_hash`.
    pub fn verify(&self, tree_hash: &Digest) -> CoreResult<()> {
        if self.steps.len() > usize::from(MAX_HEIGHT)
            || u64::from(self.index) >> self.steps.len() != 0
        {
            return Err(CoreError::Invalid("leaf proof"));
        }
        let mut hash = leaf_hash(self.leaf.as_ref())?;
        for (offset, step) in self.steps.iter().enumerate() {
            let is_left = (u64::from(self.index) >> offset) & 1 == 0;
            hash = if is_left {
                parent_hash(step.content.as_ref(), &hash, &step.sibling_hash)?
            } else {
                parent_hash(step.content.as_ref(), &step.sibling_hash, &hash)?
            };
        }
        if &hash == tree_hash {
            Ok(())
        } else {
            Err(CoreError::Invalid("leaf proof"))
        }
    }

    /// The occupancy the proof shows, if the leaf is occupied.
    #[must_use]
    pub fn occupancy(&self) -> Option<Occupancy> {
        self.leaf.as_ref().map(|leaf| leaf.occupancy(self.index))
    }

    /// Check that `nodes` (by level, from 1) are the parents on the proven
    /// path.
    pub fn check_path(&self, nodes: &[Option<ParentNode>]) -> CoreResult<()> {
        if nodes.len() != self.steps.len() {
            return Err(CoreError::Invalid("path nodes"));
        }
        for (node, step) in nodes.iter().zip(&self.steps) {
            let content = node.as_ref().map(ParentNode::content_digest).transpose()?;
            if content != step.content {
                return Err(CoreError::Invalid("path nodes"));
            }
        }
        Ok(())
    }

    /// Size of the proof in bytes, as a deployment would send it (leaf
    /// encoding plus 64 bytes per level).
    pub fn encoded_len(&self) -> CoreResult<usize> {
        let leaf = self.leaf.as_ref().map_or(Value::Null, LeafNode::value);
        Ok(cityg_core::cbor::encode(&leaf)?.len() + 64 * self.steps.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn leaf(tag: u8, since: u64) -> LeafNode {
        LeafNode {
            device_pk: vec![tag; 4],
            since,
            encryption_key: vec![tag; 3],
            admission_hash: [tag; 32],
            updated: since,
        }
    }

    fn parent(tag: u8, taint: Occupancy) -> ParentNode {
        ParentNode {
            encryption_key: vec![tag; 5],
            taint,
        }
    }

    #[test]
    fn addressing_and_districts() {
        let shape = Shape::new(5, 2).unwrap();
        assert_eq!(shape.district_count(), 8);
        assert_eq!(shape.district_of(13), 3);
        assert_eq!(shape.district_root(3), NodeId { level: 2, index: 3 });
        let small = Shape::new(2, 4).unwrap();
        assert_eq!(small.district_count(), 1);
        assert_eq!(small.district_root(0), small.root());
        let node = NodeId::of_leaf(13, 2);
        assert_eq!(node, NodeId { level: 2, index: 3 });
        assert!(node.covers(12) && node.covers(15) && !node.covers(11));
        assert!(node.is_above_or_at(NodeId::leaf(14)) && !node.is_above_or_at(NodeId::leaf(4)));
        assert_eq!(node.children()[1].parent(), node);
        assert_eq!(node.child_toward(13), NodeId { level: 1, index: 6 });
        assert_eq!(node.leaves(), 12..16);
        assert!(Shape::new(0, 2).is_err() && Shape::new(25, 2).is_err());
    }

    #[test]
    fn hashes_follow_the_content_and_the_cache_is_invalidated() {
        let mut tree = PublicTree::new(3, 2).unwrap();
        let empty = tree.tree_hash().unwrap();
        tree.set_leaf(5, Some(leaf(1, 1))).unwrap();
        let one = tree.tree_hash().unwrap();
        assert_ne!(empty, one);
        let owner = Occupancy { leaf: 5, since: 1 };
        for level in 1..=3 {
            tree.set_parent(NodeId::of_leaf(5, level), Some(parent(level, owner)))
                .unwrap();
        }
        let keyed = tree.tree_hash().unwrap();
        assert_ne!(keyed, one);
        assert_eq!(tree.tainted_by(owner).len(), 3);
        // Recomputing from scratch gives the cached value.
        let mut fresh = PublicTree::new(3, 2).unwrap();
        fresh.set_leaf(5, Some(leaf(1, 1))).unwrap();
        for level in 1..=3 {
            fresh
                .set_parent(NodeId::of_leaf(5, level), Some(parent(level, owner)))
                .unwrap();
        }
        assert_eq!(fresh.tree_hash().unwrap(), keyed);
        tree.set_parent(NodeId::of_leaf(5, 1), None).unwrap();
        assert_ne!(tree.tree_hash().unwrap(), keyed);
        assert_eq!(tree.tainted_by(owner).len(), 2);
    }

    #[test]
    fn leaf_proofs_verify_and_detect_changes() {
        let mut tree = PublicTree::new(4, 2).unwrap();
        let owner = Occupancy { leaf: 0, since: 0 };
        for index in [0u32, 3, 9, 14] {
            tree.set_leaf(index, Some(leaf(u8::try_from(index).unwrap(), 2)))
                .unwrap();
            for level in 1..=4 {
                tree.set_parent(
                    NodeId::of_leaf(index, level),
                    Some(parent(level + u8::try_from(index).unwrap(), owner)),
                )
                .unwrap();
            }
        }
        let root = tree.tree_hash().unwrap();
        for index in [0u32, 3, 9, 14, 7] {
            let proof = tree.leaf_proof(index).unwrap();
            proof.verify(&root).unwrap();
            proof.check_path(&tree.path_nodes(index)).unwrap();
        }
        let mut forged = tree.leaf_proof(9).unwrap();
        forged.leaf.as_mut().unwrap().since = 3;
        assert!(forged.verify(&root).is_err());
        let mut moved = tree.leaf_proof(9).unwrap();
        moved.index = 9 + 16;
        assert!(moved.verify(&root).is_err());
        let proof = tree.leaf_proof(9).unwrap();
        let mut nodes = tree.path_nodes(9);
        nodes[1] = None;
        assert!(proof.check_path(&nodes).is_err());
        assert!(proof.encoded_len().unwrap() > 4 * 64);
    }

    #[test]
    fn growth_keeps_addresses() {
        let mut tree = PublicTree::new(2, 3).unwrap();
        tree.set_leaf(1, Some(leaf(1, 0))).unwrap();
        tree.grow_to(4).unwrap();
        assert_eq!(tree.shape().district_count(), 2);
        assert_eq!(tree.leaf(1).unwrap().since, 0);
        assert!(tree.set_leaf(15, Some(leaf(2, 1))).is_ok());
        assert!(tree.grow_to(3).is_err());
    }

    #[test]
    fn an_overlay_hashes_like_the_applied_tree() {
        let owner = Occupancy { leaf: 1, since: 0 };
        let mut base = PublicTree::new(2, 2).unwrap();
        base.set_leaf(1, Some(leaf(1, 0))).unwrap();
        base.set_leaf(2, Some(leaf(2, 0))).unwrap();
        for node in [
            NodeId { level: 1, index: 0 },
            NodeId { level: 1, index: 1 },
            NodeId { level: 2, index: 0 },
        ] {
            base.set_parent(node, Some(parent(node.level, owner)))
                .unwrap();
        }
        let before = base.tree_hash().unwrap();
        // Grow by two levels, add a leaf far right, blank leaf 2 and re-key.
        let shape = base.shape().grown(4).unwrap();
        let mut delta = TreeDelta::default();
        delta.leaves.insert(13, Some(leaf(13, 1)));
        delta.leaves.insert(2, None);
        delta.parents.insert(NodeId { level: 1, index: 1 }, None);
        for node in [
            NodeId { level: 1, index: 6 },
            NodeId { level: 2, index: 3 },
            NodeId { level: 3, index: 1 },
            NodeId { level: 3, index: 0 },
            NodeId { level: 4, index: 0 },
            NodeId { level: 2, index: 0 },
        ] {
            delta.parents.insert(node, Some(parent(9, owner)));
        }
        let overlay = Overlay::new(&base, shape, &delta).unwrap();
        let predicted = overlay.tree_hash().unwrap();
        let district = overlay.district_hash(3).unwrap();
        assert_eq!(overlay.leaf(13).unwrap().since, 1);
        assert!(overlay.leaf(2).is_none());
        assert_eq!(base.tree_hash().unwrap(), before, "the base is untouched");
        base.apply(shape, &delta).unwrap();
        assert_eq!(base.tree_hash().unwrap(), predicted);
        assert_eq!(base.district_hash(3).unwrap(), district);
        let bad = TreeDelta {
            leaves: BTreeMap::from([(40, None)]),
            parents: BTreeMap::new(),
        };
        assert!(Overlay::new(&base, shape, &bad).is_err());
    }

    #[test]
    fn an_overlay_of_pure_growth_matches_growth() {
        let owner = Occupancy { leaf: 0, since: 0 };
        let mut base = PublicTree::new(1, 3).unwrap();
        base.set_leaf(0, Some(leaf(1, 0))).unwrap();
        base.set_parent(NodeId { level: 1, index: 0 }, Some(parent(1, owner)))
            .unwrap();
        let shape = base.shape().grown(3).unwrap();
        let delta = TreeDelta::default();
        let predicted = Overlay::new(&base, shape, &delta)
            .unwrap()
            .tree_hash()
            .unwrap();
        base.grow_to(3).unwrap();
        assert_eq!(base.tree_hash().unwrap(), predicted);
    }
}
