//! Ratchet tree v3: TreeKEM over X-Wing, in the array layout of RFC 9420.
//!
//! The tree has `width` leaves, a power of two. Leaf `i` is node `2i`,
//! parent nodes have odd indices, the level of node `x` is the number of
//! trailing one bits of `x`, and the root of a tree of `width` leaves is
//! node `width - 1`. Node indices never change when the tree grows (the old
//! root becomes the left child of a new root) or shrinks (the right half is
//! dropped), so members keep their keys across both.
//!
//! * A leaf is blank or holds a member: `[device_pk, since, encryption_key,
//!   admission_hash]`. The tree is the member list of the group.
//! * A parent is blank or holds `[encryption_key, unmerged]`, where
//!   `unmerged` lists the leaves below it that entered after its key was set
//!   and therefore do not hold its private key.
//! * `width` is the smallest power of two covering the rightmost occupied
//!   leaf, and at most the group's capacity.
//! * The tree hash commits to every node:
//!   `leaf_hash(i) = H_L("tree/leaf", [i, leaf or null])` and
//!   `parent_hash(x) = H_L("tree/parent", [node_digest(x) or null,
//!   hash(left), hash(right)])`, where `node_digest(x) =
//!   H_L("tree/parent-node", [encryption_key, unmerged])`. Hashing a parent's
//!   content first keeps a [`LeafProof`] of a leaf to its leaf record and 64
//!   bytes per level.
//!
//! Changes from the v0.2 barrier tree:
//! * the tree grows by doubling and shrinks by halving instead of having a
//!   fixed number of slots, and holds the member records itself;
//! * a member that enters without committing (a batched join) keeps the keys
//!   of the parents above it: it is recorded as an *unmerged leaf* of each of
//!   them, and encryptors add it to their resolution, instead of blanking
//!   its path;
//! * the KEM is X-Wing (ML-KEM-768 and X25519);
//! * the path-secret chain has one more step, `commit_secret = path_secret[d]`,
//!   so a tree of one leaf (no parent) still yields a fresh commit secret.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ciborium::value::Value;
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_list,
    expect_u32, expect_uint, uint,
};
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, derive_secret, expand_label_into, h_l};
use crate::identity::check_device_key;
use crate::kem::{
    KEM_CIPHERTEXT_BYTES, KEM_PUBLIC_KEY_BYTES, KemSecret, encapsulate, pk_hash,
    validate_public_key,
};

/// Largest capacity a group can have. The worst-case update path of a full
/// tree then stays under 10 MB.
pub const MAX_CAPACITY: u32 = 8192;
/// Size of a wrapped path secret (32-byte secret + 16-byte tag).
pub const WRAPPED_SECRET_BYTES: usize = 48;

/// Upper bound on the encoding of an update path in a tree of at most
/// `capacity` leaves: the copath resolutions cover every other occupied leaf
/// once, so they hold at most `capacity - 1` targets overall.
#[must_use]
pub fn max_update_path_bytes(capacity: u32) -> usize {
    let n = capacity as usize;
    let depth = capacity.trailing_zeros() as usize;
    let per_key = KEM_PUBLIC_KEY_BYTES + 8;
    let per_target = KEM_CIPHERTEXT_BYTES + WRAPPED_SECRET_BYTES + 16;
    64 + per_key * (depth + 1) + 16 * depth + per_target * n.saturating_sub(1)
}

/// Validate a group capacity: a power of two between 2 and [`MAX_CAPACITY`].
pub fn validate_capacity(capacity: u32) -> CoreResult<()> {
    if !(2..=MAX_CAPACITY).contains(&capacity) || !capacity.is_power_of_two() {
        return Err(CoreError::Invalid("capacity"));
    }
    Ok(())
}

/// Node index of leaf `leaf`.
#[must_use]
pub fn leaf_node(leaf: u32) -> u32 {
    2 * leaf
}

/// Level of `node`: 0 for a leaf, the height of its subtree for a parent.
#[must_use]
pub fn level(node: u32) -> u32 {
    node.trailing_ones()
}

/// Root of a tree of `width` leaves (`width` a power of two).
#[must_use]
pub fn root(width: u32) -> u32 {
    width - 1
}

fn left(node: u32) -> u32 {
    node ^ (1 << (level(node) - 1))
}

fn right(node: u32) -> u32 {
    node ^ (3 << (level(node) - 1))
}

fn parent(node: u32) -> u32 {
    let k = level(node);
    let b = (node >> (k + 1)) & 1;
    (node | (1 << k)) ^ (b << (k + 1))
}

fn sibling(node: u32) -> u32 {
    let p = parent(node);
    if node < p { right(p) } else { left(p) }
}

/// Whether `node` is `ancestor` or lies in its subtree.
#[must_use]
pub fn is_ancestor_or_self(ancestor: u32, node: u32) -> bool {
    let span = (1u32 << level(ancestor)) - 1;
    node >= ancestor - span && node <= ancestor + span
}

/// Ancestor of `leaf` at `level` (the leaf node itself at level 0). Node
/// indices do not depend on the width of the tree.
#[must_use]
pub fn ancestor(leaf: u32, level: u32) -> u32 {
    ((leaf >> level) << (level + 1)) + (1 << level) - 1
}

/// Level of the lowest common ancestor of two distinct leaves: the author's
/// path entry `level - 1` is the one encrypted to the other leaf's side.
#[must_use]
pub fn common_ancestor_level(a: u32, b: u32) -> u32 {
    u32::BITS - (a ^ b).leading_zeros()
}

/// Canonical width of a tree whose occupied leaves are `leaves`: the
/// smallest power of two covering the rightmost one (1 when empty).
pub fn canonical_width(leaves: impl IntoIterator<Item = u32>) -> u32 {
    leaves
        .into_iter()
        .max()
        .map_or(1, |rightmost| (rightmost + 1).next_power_of_two())
}

/// Leaf the next member enters, given the occupied leaves (increasing) and
/// the capacity: the lowest blank leaf, if below the capacity.
pub fn entry_leaf_of(occupied: impl IntoIterator<Item = u32>, capacity: u32) -> Option<u32> {
    let mut candidate = 0u32;
    for leaf in occupied {
        if leaf != candidate {
            break;
        }
        candidate += 1;
    }
    (candidate < capacity).then_some(candidate)
}

/// An occupancy `[leaf, since]`: the member that entered `leaf` at epoch
/// `since`. It names a member in messages, proposals and admin changes; a
/// resync starts a new occupancy, a key rotation does not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberRef {
    pub leaf: u32,
    pub since: u64,
}

impl MemberRef {
    /// `[leaf, since]`.
    #[must_use]
    pub fn to_value(self) -> Value {
        array(vec![uint(u64::from(self.leaf)), uint(self.since)])
    }

    /// Decode `[leaf, since]`.
    pub fn from_value(value: Value) -> CoreResult<Self> {
        let mut fields = expect_array(value, 2, "member reference")?.into_iter();
        Ok(Self {
            leaf: expect_u32(&next(&mut fields, "member reference")?, "member leaf")?,
            since: expect_uint(&next(&mut fields, "member reference")?, "member since")?,
        })
    }
}

/// A member: an occupied leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafNode {
    /// ML-DSA-65 device key of the member.
    pub device_pk: Vec<u8>,
    /// Epoch at which this occupancy of the leaf began. With the leaf index,
    /// it names the occupancy for good: no later occupant of the leaf can
    /// have the same pair.
    pub since: u64,
    /// X-Wing key of the leaf.
    pub encryption_key: Vec<u8>,
    /// `H(SignedAdmission)` of the join, `ZERO32` for the group creator.
    pub admission_hash: Digest,
}

impl LeafNode {
    pub(crate) fn to_value(&self) -> Value {
        array(vec![
            bytes(&self.device_pk),
            uint(self.since),
            bytes(&self.encryption_key),
            bytes(&self.admission_hash),
        ])
    }

    pub(crate) fn from_value(value: Value) -> CoreResult<Self> {
        let mut fields = expect_array(value, 4, "tree leaf")?.into_iter();
        let device_pk = expect_bytes(next(&mut fields, "tree leaf")?, "tree leaf device key")?;
        check_device_key(&device_pk, "tree leaf device key")?;
        let since = expect_uint(&next(&mut fields, "tree leaf")?, "tree leaf since")?;
        let encryption_key = expect_bytes(next(&mut fields, "tree leaf")?, "tree leaf key")?;
        validate_public_key(&encryption_key)?;
        let admission_hash =
            expect_bytes32(next(&mut fields, "tree leaf")?, "tree leaf admission")?;
        Ok(Self {
            device_pk,
            since,
            encryption_key,
            admission_hash,
        })
    }
}

/// A non-blank parent node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentNode {
    pub encryption_key: Vec<u8>,
    /// Leaves below the node that do not hold its private key, increasing.
    pub unmerged: Vec<u32>,
}

impl ParentNode {
    /// `node_digest := H_L("tree/parent-node", [encryption_key, unmerged])`.
    pub fn digest(&self) -> CoreResult<Digest> {
        h_l(
            "tree/parent-node",
            vec![
                bytes(&self.encryption_key),
                array(
                    self.unmerged
                        .iter()
                        .map(|leaf| uint(u64::from(*leaf)))
                        .collect(),
                ),
            ],
        )
    }

    fn to_value(&self) -> Value {
        array(vec![
            bytes(&self.encryption_key),
            array(
                self.unmerged
                    .iter()
                    .map(|leaf| uint(u64::from(*leaf)))
                    .collect(),
            ),
        ])
    }

    fn from_value(value: Value) -> CoreResult<Self> {
        let mut fields = expect_array(value, 2, "tree parent")?.into_iter();
        let encryption_key = expect_bytes(next(&mut fields, "tree parent")?, "tree parent key")?;
        validate_public_key(&encryption_key)?;
        let unmerged = expect_list(next(&mut fields, "tree parent")?, "tree unmerged leaves")?
            .iter()
            .map(|leaf| expect_u32(leaf, "tree unmerged leaf"))
            .collect::<CoreResult<Vec<_>>>()?;
        Ok(Self {
            encryption_key,
            unmerged,
        })
    }
}

/// Public view of the tree, shared by every member and the delivery service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicTree {
    capacity: u32,
    leaves: Vec<Option<LeafNode>>,
    parents: Vec<Option<ParentNode>>,
}

impl PublicTree {
    /// Tree of one blank leaf, for a group of at most `capacity` members.
    pub fn new(capacity: u32) -> CoreResult<Self> {
        validate_capacity(capacity)?;
        Ok(Self {
            capacity,
            leaves: vec![None],
            parents: Vec::new(),
        })
    }

    /// Maximum number of leaves.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Current number of leaves (a power of two).
    #[must_use]
    pub fn width(&self) -> u32 {
        u32::try_from(self.leaves.len()).unwrap_or(u32::MAX)
    }

    /// Root node.
    #[must_use]
    pub fn root(&self) -> u32 {
        root(self.width())
    }

    fn check_leaf(&self, leaf: u32) -> CoreResult<()> {
        if leaf >= self.width() {
            return Err(CoreError::Invalid("leaf index"));
        }
        Ok(())
    }

    /// Member in `leaf`.
    #[must_use]
    pub fn leaf(&self, leaf: u32) -> Option<&LeafNode> {
        self.leaves.get(leaf as usize).and_then(Option::as_ref)
    }

    /// Members, with their leaf index, in increasing leaf order.
    pub fn members(&self) -> impl Iterator<Item = (u32, &LeafNode)> {
        self.leaves.iter().enumerate().filter_map(|(index, leaf)| {
            leaf.as_ref()
                .and_then(|leaf| u32::try_from(index).ok().map(|index| (index, leaf)))
        })
    }

    /// Number of members.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.leaves.iter().filter(|leaf| leaf.is_some()).count()
    }

    /// Member occupying `leaf` since epoch `since`.
    #[must_use]
    pub fn member(&self, leaf: u32, since: u64) -> Option<&LeafNode> {
        self.leaf(leaf).filter(|member| member.since == since)
    }

    /// Occupancies of the current members, by leaf.
    pub fn member_refs(&self) -> impl Iterator<Item = MemberRef> + '_ {
        self.members().map(|(leaf, member)| MemberRef {
            leaf,
            since: member.since,
        })
    }

    /// Record of the occupancy `member`, if current.
    #[must_use]
    pub fn member_by_ref(&self, member: MemberRef) -> Option<&LeafNode> {
        self.member(member.leaf, member.since)
    }

    /// Leaf of the member whose device key is `device_pk`.
    #[must_use]
    pub fn find_device(&self, device_pk: &[u8]) -> Option<u32> {
        self.members()
            .find(|(_, member)| member.device_pk == device_pk)
            .map(|(index, _)| index)
    }

    /// Parent node `node`, if it exists and is not blank.
    #[must_use]
    pub fn parent_node(&self, node: u32) -> Option<&ParentNode> {
        if node.is_multiple_of(2) {
            return None;
        }
        self.parents
            .get((node / 2) as usize)
            .and_then(Option::as_ref)
    }

    /// Public key held at `node`, if the node exists and is not blank.
    #[must_use]
    pub fn node_public_key(&self, node: u32) -> Option<&[u8]> {
        if node.is_multiple_of(2) {
            self.leaf(node / 2)
                .map(|leaf| leaf.encryption_key.as_slice())
        } else {
            self.parent_node(node)
                .map(|parent| parent.encryption_key.as_slice())
        }
    }

    /// Leaf where the next member enters: the lowest blank leaf, or the
    /// first leaf of a doubled tree when every leaf is taken and the
    /// capacity allows it.
    #[must_use]
    pub fn entry_leaf(&self) -> Option<u32> {
        match self.leaves.iter().position(Option::is_none) {
            Some(index) => u32::try_from(index).ok(),
            None if self.width() < self.capacity => Some(self.width()),
            None => None,
        }
    }

    fn grow_to_cover(&mut self, leaf: u32) -> CoreResult<()> {
        if leaf >= self.capacity {
            return Err(CoreError::Invalid("the group is full"));
        }
        while leaf >= self.width() {
            let width = self.leaves.len() * 2;
            self.leaves.resize(width, None);
            self.parents.resize(width - 1, None);
        }
        Ok(())
    }

    /// Place a member in the blank `leaf`, growing the tree if needed. The
    /// leaf becomes an unmerged leaf of every non-blank parent above it.
    pub fn add_leaf(&mut self, leaf: u32, member: LeafNode) -> CoreResult<()> {
        validate_public_key(&member.encryption_key)?;
        self.grow_to_cover(leaf)?;
        if self.leaves[leaf as usize].is_some() {
            return Err(CoreError::Invalid("leaf already occupied"));
        }
        self.leaves[leaf as usize] = Some(member);
        self.mark_unmerged(leaf)
    }

    /// Replace the member of `leaf` by a new occupancy of the same leaf (a
    /// resync). Like any entering member, it becomes an unmerged leaf of the
    /// parents above it until its update path re-keys them.
    pub fn replace_leaf(&mut self, leaf: u32, member: LeafNode) -> CoreResult<()> {
        self.check_leaf(leaf)?;
        validate_public_key(&member.encryption_key)?;
        let entry = &mut self.leaves[leaf as usize];
        if entry.is_none() {
            return Err(CoreError::Invalid("leaf is blank"));
        }
        *entry = Some(member);
        self.mark_unmerged(leaf)
    }

    fn mark_unmerged(&mut self, leaf: u32) -> CoreResult<()> {
        for node in self.direct_path(leaf)? {
            if let Some(parent) = self.parents[(node / 2) as usize].as_mut()
                && let Err(position) = parent.unmerged.binary_search(&leaf)
            {
                parent.unmerged.insert(position, leaf);
            }
        }
        Ok(())
    }

    /// Change the device key of the member in `leaf` (key rotation).
    pub fn set_device_key(&mut self, leaf: u32, device_pk: &[u8]) -> CoreResult<()> {
        self.check_leaf(leaf)?;
        let member = self.leaves[leaf as usize]
            .as_mut()
            .ok_or(CoreError::Invalid("leaf is blank"))?;
        member.device_pk = device_pk.to_vec();
        Ok(())
    }

    /// Blank `leaf` and every node of its direct path.
    pub fn remove_leaf(&mut self, leaf: u32) -> CoreResult<LeafNode> {
        self.check_leaf(leaf)?;
        let removed = self.leaves[leaf as usize]
            .take()
            .ok_or(CoreError::Invalid("leaf is blank"))?;
        for node in self.direct_path(leaf)? {
            self.parents[(node / 2) as usize] = None;
        }
        Ok(removed)
    }

    /// Halve the tree while its right half holds no member (canonical width).
    pub fn truncate(&mut self) {
        while self.leaves.len() > 1 {
            let half = self.leaves.len() / 2;
            if self.leaves[half..].iter().any(Option::is_some) {
                break;
            }
            self.leaves.truncate(half);
            self.parents.truncate(half - 1);
        }
    }

    /// Parent nodes from the parent of `leaf` up to the root.
    pub fn direct_path(&self, leaf: u32) -> CoreResult<Vec<u32>> {
        self.check_leaf(leaf)?;
        let root = self.root();
        let mut path = Vec::new();
        let mut node = leaf_node(leaf);
        while node != root {
            node = parent(node);
            path.push(node);
        }
        Ok(path)
    }

    /// For each node of the direct path, its child that is not on the path.
    pub fn copath(&self, leaf: u32) -> CoreResult<Vec<u32>> {
        self.check_leaf(leaf)?;
        let root = self.root();
        let mut copath = Vec::new();
        let mut node = leaf_node(leaf);
        while node != root {
            copath.push(sibling(node));
            node = parent(node);
        }
        Ok(copath)
    }

    /// Smallest set of nodes whose private keys cover every member below
    /// `node`: the node and its unmerged leaves if it is not blank, else the
    /// resolutions of its children. Increasing node order.
    #[must_use]
    pub fn resolution(&self, node: u32) -> Vec<u32> {
        let mut out = Vec::new();
        self.resolution_into(node, &mut out);
        out.sort_unstable();
        out
    }

    fn resolution_into(&self, node: u32, out: &mut Vec<u32>) {
        if node.is_multiple_of(2) {
            if self.leaf(node / 2).is_some() {
                out.push(node);
            }
        } else if let Some(parent) = self.parent_node(node) {
            out.push(node);
            out.extend(parent.unmerged.iter().map(|leaf| leaf_node(*leaf)));
        } else {
            self.resolution_into(left(node), out);
            self.resolution_into(right(node), out);
        }
    }

    /// Hash of every node, indexed by node (`2 * width - 1` entries).
    pub fn node_hashes(&self) -> CoreResult<Vec<Digest>> {
        let width = self.width();
        let mut hashes = vec![[0u8; 32]; (2 * width - 1) as usize];
        for leaf in 0..width {
            hashes[leaf_node(leaf) as usize] = leaf_hash(leaf, self.leaf(leaf))?;
        }
        let depth = width.trailing_zeros();
        for level in 1..=depth {
            let mut node = (1u32 << level) - 1;
            while node < 2 * width - 1 {
                let digest = self.parent_node(node).map(ParentNode::digest).transpose()?;
                hashes[node as usize] = parent_hash(
                    digest.as_ref(),
                    &hashes[left(node) as usize],
                    &hashes[right(node) as usize],
                )?;
                node += 1 << (level + 1);
            }
        }
        Ok(hashes)
    }

    /// Commitment to the whole tree: hash of the root node.
    pub fn tree_hash(&self) -> CoreResult<Digest> {
        Ok(self.node_hashes()?[self.root() as usize])
    }

    /// Merkle proof of `leaf` against the tree hash.
    pub fn leaf_proof(&self, leaf: u32) -> CoreResult<LeafProof> {
        let mut proofs = self.leaf_proofs([leaf])?;
        proofs.pop().ok_or(CoreError::Invalid("leaf index"))
    }

    /// Merkle proofs of `leaves` against the tree hash (the node hashes are
    /// computed once).
    pub fn leaf_proofs(&self, leaves: impl IntoIterator<Item = u32>) -> CoreResult<Vec<LeafProof>> {
        let hashes = self.node_hashes()?;
        let root = self.root();
        leaves
            .into_iter()
            .map(|leaf| {
                self.check_leaf(leaf)?;
                let mut path = Vec::new();
                let mut node = leaf_node(leaf);
                while node != root {
                    let up = parent(node);
                    path.push(ProofStep {
                        parent: self.parent_node(up).map(ParentNode::digest).transpose()?,
                        sibling: hashes[sibling(node) as usize],
                    });
                    node = up;
                }
                Ok(LeafProof {
                    leaf,
                    width: self.width(),
                    node: self.leaf(leaf).cloned(),
                    path,
                })
            })
            .collect()
    }

    /// Install the public keys of an accepted update path from `leaf`: the
    /// leaf key, and each direct-path node with an empty unmerged list.
    pub fn apply_update_path(&mut self, leaf: u32, path: &UpdatePath) -> CoreResult<()> {
        let direct_path = self.direct_path(leaf)?;
        if path.nodes.len() != direct_path.len() {
            return Err(CoreError::Invalid("update path length"));
        }
        let member = self.leaves[leaf as usize]
            .as_mut()
            .ok_or(CoreError::Invalid("update path from a blank leaf"))?;
        member.encryption_key = path.leaf_public_key.clone();
        for (entry, node) in path.nodes.iter().zip(direct_path) {
            if entry.node != node {
                return Err(CoreError::Invalid("update path node"));
            }
            self.parents[(node / 2) as usize] = Some(ParentNode {
                encryption_key: entry.public_key.clone(),
                unmerged: Vec::new(),
            });
        }
        Ok(())
    }

    /// Deterministic CBOR encoding: `[capacity, [leaf or null, ...],
    /// [parent or null, ...]]`.
    pub fn to_cbor(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            uint(u64::from(self.capacity)),
            array(
                self.leaves
                    .iter()
                    .map(|leaf| leaf.as_ref().map_or(Value::Null, LeafNode::to_value))
                    .collect(),
            ),
            array(
                self.parents
                    .iter()
                    .map(|node| node.as_ref().map_or(Value::Null, ParentNode::to_value))
                    .collect(),
            ),
        ]))
    }

    /// Decode a tree and check that it is well formed and canonical.
    pub fn from_cbor(encoded: &[u8]) -> CoreResult<Self> {
        let mut items = expect_array(decode(encoded, 64 << 20, "tree")?, 3, "tree")?.into_iter();
        let capacity = expect_u32(&next(&mut items, "tree")?, "tree capacity")?;
        validate_capacity(capacity)?;
        let leaves = expect_list(next(&mut items, "tree")?, "tree leaves")?
            .into_iter()
            .map(|leaf| match leaf {
                Value::Null => Ok(None),
                value => LeafNode::from_value(value).map(Some),
            })
            .collect::<CoreResult<Vec<_>>>()?;
        let parents = expect_list(next(&mut items, "tree")?, "tree parents")?
            .into_iter()
            .map(|node| match node {
                Value::Null => Ok(None),
                value => ParentNode::from_value(value).map(Some),
            })
            .collect::<CoreResult<Vec<_>>>()?;
        let tree = Self {
            capacity,
            leaves,
            parents,
        };
        tree.check_well_formed()?;
        Ok(tree)
    }

    /// Structural invariants: a power-of-two width within the capacity, one
    /// parent per inner node, the canonical width, at least one member,
    /// distinct device keys, and unmerged lists that name members below
    /// their node in increasing order.
    pub fn check_well_formed(&self) -> CoreResult<()> {
        let width = self.leaves.len();
        if !width.is_power_of_two()
            || width > self.capacity as usize
            || self.parents.len() != width - 1
        {
            return Err(CoreError::Malformed("tree size"));
        }
        if width > 1 && self.leaves[width / 2..].iter().all(Option::is_none) {
            return Err(CoreError::Malformed("tree is not truncated"));
        }
        if self.member_count() == 0 {
            return Err(CoreError::Malformed("tree without members"));
        }
        let mut keys: Vec<&[u8]> = self
            .members()
            .map(|(_, member)| member.device_pk.as_slice())
            .collect();
        keys.sort_unstable();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CoreError::Malformed("duplicate device key in the tree"));
        }
        for (index, node) in self.parents.iter().enumerate() {
            let Some(node) = node else { continue };
            let node_index = u32::try_from(2 * index + 1).unwrap_or(u32::MAX);
            if node.unmerged.windows(2).any(|pair| pair[0] >= pair[1])
                || node.unmerged.iter().any(|leaf| {
                    !is_ancestor_or_self(node_index, leaf_node(*leaf)) || self.leaf(*leaf).is_none()
                })
            {
                return Err(CoreError::Malformed("tree unmerged leaves"));
            }
        }
        Ok(())
    }
}

pub(crate) fn next(
    items: &mut impl Iterator<Item = Value>,
    what: &'static str,
) -> CoreResult<Value> {
    items.next().ok_or(CoreError::Malformed(what))
}

fn leaf_hash(leaf: u32, node: Option<&LeafNode>) -> CoreResult<Digest> {
    h_l(
        "tree/leaf",
        vec![
            uint(u64::from(leaf)),
            node.map_or(Value::Null, LeafNode::to_value),
        ],
    )
}

fn parent_hash(digest: Option<&Digest>, left: &Digest, right: &Digest) -> CoreResult<Digest> {
    h_l(
        "tree/parent",
        vec![
            digest.map_or(Value::Null, |digest| bytes(digest)),
            bytes(left),
            bytes(right),
        ],
    )
}

/// One level of a [`LeafProof`], from the leaf up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofStep {
    /// `node_digest` of the ancestor at this level, `None` if it is blank.
    pub parent: Option<Digest>,
    /// Hash of the sibling of the node one level below.
    pub sibling: Digest,
}

/// Largest encoding of a [`LeafProof`].
pub const MAX_LEAF_PROOF_BYTES: usize = 8 * 1024;

/// Merkle proof that leaf `leaf` of a tree of `width` leaves holds `node`
/// (a member, or `None` when blank):
///
/// ```text
/// LeafProof := [leaf, width, leaf or null, [[node_digest or null, sibling_hash], ...]]
/// ```
///
/// with one step per level, from the leaf's parent to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafProof {
    pub leaf: u32,
    pub width: u32,
    pub node: Option<LeafNode>,
    pub path: Vec<ProofStep>,
}

impl LeafProof {
    /// Recompute the root hash from the proof and compare it with
    /// `tree_hash`.
    pub fn verify(&self, tree_hash: &Digest) -> CoreResult<()> {
        if !self.width.is_power_of_two()
            || self.width > MAX_CAPACITY
            || self.leaf >= self.width
            || self.path.len() != self.width.trailing_zeros() as usize
        {
            return Err(CoreError::Invalid("leaf proof shape"));
        }
        let mut node = leaf_node(self.leaf);
        let mut hash = leaf_hash(self.leaf, self.node.as_ref())?;
        for step in &self.path {
            let up = parent(node);
            hash = if node < up {
                parent_hash(step.parent.as_ref(), &hash, &step.sibling)?
            } else {
                parent_hash(step.parent.as_ref(), &step.sibling, &hash)?
            };
            node = up;
        }
        if !crate::hash::digest_eq(&hash, tree_hash) {
            return Err(CoreError::Invalid(
                "leaf proof does not match the tree hash",
            ));
        }
        Ok(())
    }

    /// The member the proof shows, as `(occupancy, record)`.
    #[must_use]
    pub fn member(&self) -> Option<(MemberRef, &LeafNode)> {
        self.node.as_ref().map(|node| {
            (
                MemberRef {
                    leaf: self.leaf,
                    since: node.since,
                },
                node,
            )
        })
    }

    /// Deterministic CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        array(vec![
            uint(u64::from(self.leaf)),
            uint(u64::from(self.width)),
            self.node.as_ref().map_or(Value::Null, LeafNode::to_value),
            array(
                self.path
                    .iter()
                    .map(|step| {
                        array(vec![
                            step.parent
                                .as_ref()
                                .map_or(Value::Null, |digest| bytes(digest)),
                            bytes(&step.sibling),
                        ])
                    })
                    .collect(),
            ),
        ])
    }

    /// Decode [`LeafProof::to_value`] (structure only; see
    /// [`LeafProof::verify`]).
    pub fn from_value(value: Value) -> CoreResult<Self> {
        let mut items = expect_array(value, 4, "leaf proof")?.into_iter();
        let leaf = expect_u32(&next(&mut items, "leaf proof")?, "leaf proof leaf")?;
        let width = expect_u32(&next(&mut items, "leaf proof")?, "leaf proof width")?;
        let node = match next(&mut items, "leaf proof")? {
            Value::Null => None,
            value => Some(LeafNode::from_value(value)?),
        };
        let path = expect_list(next(&mut items, "leaf proof")?, "leaf proof path")?
            .into_iter()
            .map(|step| {
                let mut fields = expect_array(step, 2, "leaf proof step")?.into_iter();
                let parent = match next(&mut fields, "leaf proof step")? {
                    Value::Null => None,
                    value => Some(expect_bytes32(value, "leaf proof digest")?),
                };
                let sibling = expect_bytes32(next(&mut fields, "leaf proof step")?, "sibling")?;
                Ok(ProofStep { parent, sibling })
            })
            .collect::<CoreResult<Vec<_>>>()?;
        Ok(Self {
            leaf,
            width,
            node,
            path,
        })
    }

    /// Deterministic CBOR encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&self.to_value())
    }

    /// Decode an encoded proof.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        Self::from_value(decode(encoded, MAX_LEAF_PROOF_BYTES, "leaf proof")?)
    }
}

/// Path secret of one parent node, encapsulated to one resolution node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathTarget {
    pub target: u32,
    pub kem_ciphertext: Vec<u8>,
    pub wrapped_secret: Vec<u8>,
}

/// New key of one parent node of the author's direct path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathNode {
    pub node: u32,
    pub public_key: Vec<u8>,
    pub targets: Vec<PathTarget>,
}

/// Re-key of the author's leaf and direct path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePath {
    pub leaf_public_key: Vec<u8>,
    pub nodes: Vec<PathNode>,
}

/// Values bound into every wrapped path secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathContext {
    pub gid: Digest,
    /// Epoch created by the commit carrying the path.
    pub epoch: u64,
    pub author_leaf: u32,
}

impl PathContext {
    fn wrap_context(&self, node: u32, target: u32, target_pk_hash: &Digest) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            bytes(&self.gid),
            uint(self.epoch),
            uint(u64::from(self.author_leaf)),
            uint(u64::from(node)),
            uint(u64::from(target)),
            bytes(target_pk_hash),
        ]))
    }
}

/// Private keys a member holds: its leaf key and the keys of the parent
/// nodes of its direct path it knows.
#[derive(Clone, Debug, Default)]
pub struct PrivatePath {
    pub leaf: Option<KemSecret>,
    pub nodes: BTreeMap<u32, KemSecret>,
}

impl PrivatePath {
    /// Private key of `node`, for the member in `my_leaf`.
    #[must_use]
    pub fn key_for(&self, my_leaf: u32, node: u32) -> Option<&KemSecret> {
        if node == leaf_node(my_leaf) {
            self.leaf.as_ref()
        } else {
            self.nodes.get(&node)
        }
    }

    /// Forget keys of nodes that are blank or gone in `tree`.
    pub fn retain_live(&mut self, tree: &PublicTree) {
        self.nodes
            .retain(|node, _| tree.node_public_key(*node).is_some());
    }
}

/// Secrets produced by generating or decrypting an update path.
#[derive(Debug)]
pub struct PathSecrets {
    /// Keys of path nodes this member now holds.
    pub node_keys: BTreeMap<u32, KemSecret>,
    /// New leaf key (author only).
    pub leaf_key: Option<KemSecret>,
    /// `path_secret[d]`, one step past the root: the commit secret.
    pub commit_secret: Zeroizing<[u8; 32]>,
}

fn node_key(path_secret: &[u8; 32]) -> CoreResult<KemSecret> {
    KemSecret::derive(path_secret, "tree node key")
}

fn wrap_keys(shared: &[u8; 32], context: &[u8]) -> CoreResult<(Zeroizing<[u8; 32]>, [u8; 12])> {
    let mut key = Zeroizing::new([0u8; 32]);
    expand_label_into(shared, "tree path wrap key", context, key.as_mut())?;
    let mut nonce = [0u8; 12];
    expand_label_into(shared, "tree path wrap nonce", context, &mut nonce)?;
    Ok((key, nonce))
}

/// Fresh 32-byte leaf secret from which a leaf key and a path derive.
pub fn new_leaf_secret(rng: &mut impl CryptoRngCore) -> Zeroizing<[u8; 32]> {
    let mut leaf_secret = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(leaf_secret.as_mut());
    leaf_secret
}

/// Leaf key derived from a leaf secret: `KeyGen(ExpandLabel(leaf_secret,
/// "tree leaf key", h'', 32))`.
pub fn leaf_key_from_secret(leaf_secret: &[u8; 32]) -> CoreResult<KemSecret> {
    KemSecret::derive(leaf_secret, "tree leaf key")
}

/// Re-key the author's leaf with a fresh leaf secret; see
/// [`generate_update_path_from_leaf_secret`].
pub fn generate_update_path(
    tree: &PublicTree,
    context: &PathContext,
    rng: &mut impl CryptoRngCore,
) -> CoreResult<(UpdatePath, PathSecrets)> {
    let leaf_secret = new_leaf_secret(rng);
    generate_update_path_from_leaf_secret(tree, context, &leaf_secret, rng)
}

/// Re-key `context.author_leaf`: derive the path secrets from
/// `leaf_secret`, and encapsulate each to the resolution of the matching
/// copath node in `tree` (the tree the commit starts from).
pub fn generate_update_path_from_leaf_secret(
    tree: &PublicTree,
    context: &PathContext,
    leaf_secret: &[u8; 32],
    rng: &mut impl CryptoRngCore,
) -> CoreResult<(UpdatePath, PathSecrets)> {
    let leaf = context.author_leaf;
    if tree.leaf(leaf).is_none() {
        return Err(CoreError::Invalid("update path from a blank leaf"));
    }
    let direct_path = tree.direct_path(leaf)?;
    let copath = tree.copath(leaf)?;

    let leaf_key = leaf_key_from_secret(leaf_secret)?;
    let leaf_public_key = leaf_key.public_key();

    let mut secret = derive_secret(leaf_secret, "tree path")?;
    let mut nodes = Vec::with_capacity(direct_path.len());
    let mut node_keys = BTreeMap::new();
    for (index, node) in direct_path.iter().copied().enumerate() {
        let key = node_key(&secret)?;
        let public_key = key.public_key();
        let mut targets = Vec::new();
        for target in tree.resolution(copath[index]) {
            let target_pk = tree
                .node_public_key(target)
                .ok_or(CoreError::Invalid("blank resolution node"))?;
            let target_pk_hash = pk_hash(target_pk)?;
            let (kem_ciphertext, shared) = encapsulate(target_pk, rng)?;
            let wrap_context = context.wrap_context(node, target, &target_pk_hash)?;
            let (key_bytes, nonce) = wrap_keys(&shared, &wrap_context)?;
            let wrapped_secret = ChaCha20Poly1305::new(Key::from_slice(key_bytes.as_slice()))
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: secret.as_slice(),
                        aad: &wrap_context,
                    },
                )
                .map_err(|_| CoreError::Crypto("path secret wrap"))?;
            targets.push(PathTarget {
                target,
                kem_ciphertext,
                wrapped_secret,
            });
        }
        node_keys.insert(node, key);
        nodes.push(PathNode {
            node,
            public_key,
            targets,
        });
        secret = derive_secret(&secret, "tree path")?;
    }
    Ok((
        UpdatePath {
            leaf_public_key,
            nodes,
        },
        PathSecrets {
            node_keys,
            leaf_key: Some(leaf_key),
            commit_secret: secret,
        },
    ))
}

/// Check an update path from `author_leaf` against `tree` (the tree the
/// commit starts from): one entry per direct-path node, valid keys, and
/// exactly one ciphertext per resolution node of the copath, in order. Needs
/// no secret.
pub fn validate_update_path(
    tree: &PublicTree,
    author_leaf: u32,
    path: &UpdatePath,
) -> CoreResult<()> {
    if tree.leaf(author_leaf).is_none() {
        return Err(CoreError::Invalid("update path from a blank leaf"));
    }
    validate_public_key(&path.leaf_public_key)?;
    let direct_path = tree.direct_path(author_leaf)?;
    let copath = tree.copath(author_leaf)?;
    if path.nodes.len() != direct_path.len() {
        return Err(CoreError::Invalid("update path length"));
    }
    for (index, entry) in path.nodes.iter().enumerate() {
        if entry.node != direct_path[index] {
            return Err(CoreError::Invalid("update path node"));
        }
        validate_public_key(&entry.public_key)?;
        let expected = tree.resolution(copath[index]);
        if entry.targets.len() != expected.len()
            || entry
                .targets
                .iter()
                .zip(expected.iter())
                .any(|(target, node)| target.target != *node)
        {
            return Err(CoreError::Invalid("update path targets"));
        }
        for target in &entry.targets {
            if target.kem_ciphertext.len() != KEM_CIPHERTEXT_BYTES
                || target.wrapped_secret.len() != WRAPPED_SECRET_BYTES
            {
                return Err(CoreError::Malformed("update path ciphertext"));
            }
        }
    }
    Ok(())
}

/// Decrypt the path secret meant for the member in `my_leaf` and derive the
/// keys of the part of the author's path above it. `tree` is the tree the
/// commit starts from, or the tree it produces: the two agree on every
/// copath subtree, which is all this uses.
pub fn decrypt_update_path(
    tree: &PublicTree,
    context: &PathContext,
    path: &UpdatePath,
    my_leaf: u32,
    private: &PrivatePath,
) -> CoreResult<PathSecrets> {
    validate_update_path(tree, context.author_leaf, path)?;
    if my_leaf == context.author_leaf {
        return Err(CoreError::Invalid("own update path"));
    }
    let copath = tree.copath(context.author_leaf)?;
    let my_node = leaf_node(my_leaf);
    // The lowest shared ancestor is the first path node whose copath child
    // covers this member's leaf.
    let index = copath
        .iter()
        .position(|node| is_ancestor_or_self(*node, my_node))
        .ok_or(CoreError::Invalid("member not covered by the update path"))?;
    let (target, key) = path.nodes[index]
        .targets
        .iter()
        .find_map(|target| {
            private
                .key_for(my_leaf, target.target)
                .map(|key| (target, key))
        })
        .ok_or(CoreError::Decrypt("no path secret for this member"))?;
    decrypt_path_entry(context, path, index, target, key)
}

/// Open the path secret of entry `index` of `path` wrapped for `target`,
/// with `key` (the member's private key of that node), and derive the keys
/// of the author's path from that entry up to the root, checking each
/// against the public key the author published. Needs no tree: members
/// without the public tree use it directly.
pub fn decrypt_path_entry(
    context: &PathContext,
    path: &UpdatePath,
    index: usize,
    target: &PathTarget,
    key: &KemSecret,
) -> CoreResult<PathSecrets> {
    let entry = path
        .nodes
        .get(index)
        .ok_or(CoreError::Invalid("update path length"))?;
    let shared = key.decapsulate(&target.kem_ciphertext)?;
    let wrap_context =
        context.wrap_context(entry.node, target.target, &pk_hash(&key.public_key())?)?;
    let (key_bytes, nonce) = wrap_keys(&shared, &wrap_context)?;
    let plaintext = Zeroizing::new(
        ChaCha20Poly1305::new(Key::from_slice(key_bytes.as_slice()))
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &target.wrapped_secret,
                    aad: &wrap_context,
                },
            )
            .map_err(|_| CoreError::Decrypt("path secret"))?,
    );
    let mut secret = Zeroizing::new([0u8; 32]);
    if plaintext.len() != 32 {
        return Err(CoreError::Decrypt("path secret length"));
    }
    secret.copy_from_slice(&plaintext);

    let mut node_keys = BTreeMap::new();
    for entry in &path.nodes[index..] {
        let key = node_key(&secret)?;
        // Every derivable public key must match the one the author published.
        if key.public_key() != entry.public_key {
            return Err(CoreError::Invalid("update path public key mismatch"));
        }
        node_keys.insert(entry.node, key);
        secret = derive_secret(&secret, "tree path")?;
    }
    Ok(PathSecrets {
        node_keys,
        leaf_key: None,
        commit_secret: secret,
    })
}

/// Deterministic CBOR encoding of an update path.
pub fn update_path_to_value(path: &UpdatePath) -> Value {
    array(vec![
        bytes(&path.leaf_public_key),
        array(
            path.nodes
                .iter()
                .map(|node| {
                    array(vec![
                        uint(u64::from(node.node)),
                        bytes(&node.public_key),
                        array(
                            node.targets
                                .iter()
                                .map(|target| {
                                    array(vec![
                                        uint(u64::from(target.target)),
                                        bytes(&target.kem_ciphertext),
                                        bytes(&target.wrapped_secret),
                                    ])
                                })
                                .collect(),
                        ),
                    ])
                })
                .collect(),
        ),
    ])
}

/// Parse an update path value (structure only; see [`validate_update_path`]).
pub fn update_path_from_value(value: Value) -> CoreResult<UpdatePath> {
    let mut items = expect_array(value, 2, "update path")?.into_iter();
    let leaf_public_key = expect_bytes(next(&mut items, "update path")?, "update path leaf key")?;
    let nodes = expect_list(next(&mut items, "update path")?, "update path nodes")?
        .into_iter()
        .map(|node| {
            let mut fields = expect_array(node, 3, "update path node")?.into_iter();
            let index = expect_u32(&next(&mut fields, "update path node")?, "path node index")?;
            let public_key = expect_bytes(next(&mut fields, "update path node")?, "path node key")?;
            let targets = expect_list(next(&mut fields, "update path node")?, "path targets")?
                .into_iter()
                .map(|target| {
                    let mut fields = expect_array(target, 3, "path target")?.into_iter();
                    Ok(PathTarget {
                        target: expect_u32(&next(&mut fields, "path target")?, "path target")?,
                        kem_ciphertext: expect_bytes(
                            next(&mut fields, "path target")?,
                            "path target ciphertext",
                        )?,
                        wrapped_secret: expect_bytes(
                            next(&mut fields, "path target")?,
                            "path target wrap",
                        )?,
                    })
                })
                .collect::<CoreResult<Vec<_>>>()?;
            Ok(PathNode {
                node: index,
                public_key,
                targets,
            })
        })
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(UpdatePath {
        leaf_public_key,
        nodes,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;
