//! Barrier tree v2: a TreeKEM-style ratchet tree over ML-KEM-768 (audit P-3).
//!
//! The tree has `n_max` leaf slots (a power of two, `2 <= n_max <= MAX_N_MAX`)
//! stored in heap order: node 0 is the root, node `i` has children `2i + 1`
//! and `2i + 2`, and slot `s` is leaf node `n_max - 1 + s`.
//!
//! Changes from the v0.1.4 barrier:
//! * every update renews the author's leaf key from its fresh leaf secret
//!   (P-3.a, audit H-03);
//! * leaves bind `(leaf_id, generation)` into the tree hash (P-3.f);
//! * removing a member blanks its leaf and direct path once, in the tree that
//!   the next commit starts from (P-3.d);
//! * the size of an update is bounded by `max_update_path_bytes(n_max)`
//!   (P-3.g);
//! * joins are external commits authored by the joiner, which re-key its own
//!   path, so no leaf is ever added without a fresh path (this subsumes the
//!   unmerged-leaves mechanism of P-3.e).

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
use crate::kem::{
    KEM_CIPHERTEXT_BYTES, KEM_PUBLIC_KEY_BYTES, KemSecret, encapsulate, pk_hash,
    validate_public_key,
};

/// Largest tree the base profile supports: the worst-case update then stays
/// near 1.2 MB (P-3.g). Larger groups need sub-groups or federation.
pub const MAX_N_MAX: u32 = 1024;
/// Size of a wrapped path secret (32-byte secret + 16-byte tag).
pub const WRAPPED_SECRET_BYTES: usize = 48;

/// Upper bound on the encoding of an update path for a tree of `n_max`
/// leaves: every copath resolution holds at most `n_max - 1` targets overall.
#[must_use]
pub fn max_update_path_bytes(n_max: u32) -> usize {
    let n = n_max as usize;
    let depth = n_max.trailing_zeros() as usize;
    let per_key = KEM_PUBLIC_KEY_BYTES + 8;
    let per_target = KEM_CIPHERTEXT_BYTES + WRAPPED_SECRET_BYTES + 16;
    64 + per_key * (depth + 1) + 16 * depth + per_target * n.saturating_sub(1)
}

/// Validate a tree size.
pub fn validate_n_max(n_max: u32) -> CoreResult<()> {
    if !(2..=MAX_N_MAX).contains(&n_max) || !n_max.is_power_of_two() {
        return Err(CoreError::Invalid("n_max"));
    }
    Ok(())
}

/// Occupied leaf slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafNode {
    pub leaf_id: Digest,
    pub generation: u64,
    pub public_key: Vec<u8>,
}

/// Public view of the tree, shared by every member and the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicTree {
    n_max: u32,
    leaves: Vec<Option<LeafNode>>,
    parents: Vec<Option<Vec<u8>>>,
}

/// Node index of slot `slot` in a tree of `n_max` leaves.
#[must_use]
pub fn leaf_node(n_max: u32, slot: u32) -> u32 {
    n_max - 1 + slot
}

fn parent_of(node: u32) -> Option<u32> {
    if node == 0 {
        None
    } else {
        Some((node - 1) / 2)
    }
}

fn sibling_of(node: u32) -> Option<u32> {
    if node == 0 {
        None
    } else if node % 2 == 1 {
        Some(node + 1)
    } else {
        Some(node - 1)
    }
}

impl PublicTree {
    /// Empty tree of `n_max` leaves.
    pub fn new(n_max: u32) -> CoreResult<Self> {
        validate_n_max(n_max)?;
        Ok(Self {
            n_max,
            leaves: vec![None; n_max as usize],
            parents: vec![None; n_max as usize - 1],
        })
    }

    /// Number of leaf slots.
    #[must_use]
    pub fn n_max(&self) -> u32 {
        self.n_max
    }

    fn is_leaf(&self, node: u32) -> bool {
        node >= self.n_max - 1
    }

    fn check_slot(&self, slot: u32) -> CoreResult<()> {
        if slot >= self.n_max {
            return Err(CoreError::Invalid("slot index"));
        }
        Ok(())
    }

    /// Occupant of `slot`.
    #[must_use]
    pub fn leaf(&self, slot: u32) -> Option<&LeafNode> {
        self.leaves.get(slot as usize).and_then(Option::as_ref)
    }

    /// Place an occupant in an empty `slot`.
    pub fn add_leaf(&mut self, slot: u32, leaf: LeafNode) -> CoreResult<()> {
        self.check_slot(slot)?;
        validate_public_key(&leaf.public_key)?;
        let entry = &mut self.leaves[slot as usize];
        if entry.is_some() {
            return Err(CoreError::Invalid("slot already occupied"));
        }
        *entry = Some(leaf);
        Ok(())
    }

    /// Blank `slot` and every node of its direct path.
    pub fn remove_leaf(&mut self, slot: u32) -> CoreResult<LeafNode> {
        self.check_slot(slot)?;
        let removed = self.leaves[slot as usize]
            .take()
            .ok_or(CoreError::Invalid("slot is empty"))?;
        for node in self.direct_path(slot)? {
            self.parents[node as usize] = None;
        }
        Ok(removed)
    }

    /// First empty slot, if any.
    #[must_use]
    pub fn first_free_slot(&self) -> Option<u32> {
        self.leaves
            .iter()
            .position(Option::is_none)
            .and_then(|slot| u32::try_from(slot).ok())
    }

    /// Public key held at `node`, if the node is not blank.
    #[must_use]
    pub fn node_public_key(&self, node: u32) -> Option<&[u8]> {
        if self.is_leaf(node) {
            self.leaf(node - (self.n_max - 1))
                .map(|leaf| leaf.public_key.as_slice())
        } else {
            self.parents
                .get(node as usize)
                .and_then(Option::as_ref)
                .map(Vec::as_slice)
        }
    }

    /// Parent nodes from the parent of `slot`'s leaf up to the root.
    pub fn direct_path(&self, slot: u32) -> CoreResult<Vec<u32>> {
        self.check_slot(slot)?;
        let mut path = Vec::new();
        let mut node = leaf_node(self.n_max, slot);
        while let Some(parent) = parent_of(node) {
            path.push(parent);
            node = parent;
        }
        Ok(path)
    }

    /// For each node of the direct path, the child that is *not* on the path.
    pub fn copath(&self, slot: u32) -> CoreResult<Vec<u32>> {
        self.check_slot(slot)?;
        let mut copath = Vec::new();
        let mut node = leaf_node(self.n_max, slot);
        while let Some(sibling) = sibling_of(node) {
            copath.push(sibling);
            node = parent_of(node).ok_or(CoreError::Invalid("tree shape"))?;
        }
        Ok(copath)
    }

    /// Smallest set of non-blank nodes covering the leaves below `node`.
    #[must_use]
    pub fn resolution(&self, node: u32) -> Vec<u32> {
        let mut out = Vec::new();
        self.resolution_into(node, &mut out);
        out.sort_unstable();
        out
    }

    fn resolution_into(&self, node: u32, out: &mut Vec<u32>) {
        if self.node_public_key(node).is_some() {
            out.push(node);
        } else if !self.is_leaf(node) {
            self.resolution_into(2 * node + 1, out);
            self.resolution_into(2 * node + 2, out);
        }
    }

    fn node_hash(&self, node: u32) -> CoreResult<Digest> {
        if self.is_leaf(node) {
            let slot = node - (self.n_max - 1);
            let occupant = match self.leaf(slot) {
                Some(leaf) => array(vec![
                    bytes(&leaf.leaf_id),
                    uint(leaf.generation),
                    bytes(&leaf.public_key),
                ]),
                None => array(Vec::new()),
            };
            h_l(
                "tree/leaf",
                vec![uint(u64::from(self.n_max)), uint(u64::from(slot)), occupant],
            )
        } else {
            let left = self.node_hash(2 * node + 1)?;
            let right = self.node_hash(2 * node + 2)?;
            let key = self.node_public_key(node).unwrap_or(&[]);
            h_l(
                "tree/parent",
                vec![
                    uint(u64::from(node)),
                    bytes(key),
                    bytes(&left),
                    bytes(&right),
                ],
            )
        }
    }

    /// Commitment to the whole tree: hash of the root node.
    pub fn tree_hash(&self) -> CoreResult<Digest> {
        self.node_hash(0)
    }

    /// Install the public keys of an accepted update path from `slot`.
    pub fn apply_update_path(&mut self, slot: u32, path: &UpdatePath) -> CoreResult<()> {
        let direct_path = self.direct_path(slot)?;
        if path.nodes.len() != direct_path.len() {
            return Err(CoreError::Invalid("update path length"));
        }
        let leaf = self.leaves[slot as usize]
            .as_mut()
            .ok_or(CoreError::Invalid("update path from an empty slot"))?;
        leaf.public_key = path.leaf_public_key.clone();
        for (entry, node) in path.nodes.iter().zip(direct_path) {
            if entry.node != node {
                return Err(CoreError::Invalid("update path node"));
            }
            self.parents[node as usize] = Some(entry.public_key.clone());
        }
        Ok(())
    }

    /// Deterministic CBOR encoding.
    pub fn to_cbor(&self) -> CoreResult<Vec<u8>> {
        let leaves = self
            .leaves
            .iter()
            .map(|leaf| match leaf {
                Some(leaf) => array(vec![
                    bytes(&leaf.leaf_id),
                    uint(leaf.generation),
                    bytes(&leaf.public_key),
                ]),
                None => Value::Null,
            })
            .collect();
        let parents = self
            .parents
            .iter()
            .map(|node| match node {
                Some(key) => bytes(key),
                None => Value::Null,
            })
            .collect();
        encode(&array(vec![
            uint(u64::from(self.n_max)),
            array(leaves),
            array(parents),
        ]))
    }

    /// Decode and validate a tree encoding.
    pub fn from_cbor(encoded: &[u8]) -> CoreResult<Self> {
        let max = (2 * MAX_N_MAX as usize) * (KEM_PUBLIC_KEY_BYTES + 64) + 64;
        let mut items = expect_array(decode(encoded, max, "tree")?, 3, "tree")?.into_iter();
        let n_max = next(&mut items, "tree")?;
        let n_max = expect_u32(&n_max, "tree n_max")?;
        let mut tree = Self::new(n_max)?;
        let leaves = expect_list(next(&mut items, "tree")?, "tree leaves")?;
        let parents = expect_list(next(&mut items, "tree")?, "tree parents")?;
        if leaves.len() != n_max as usize || parents.len() != n_max as usize - 1 {
            return Err(CoreError::Malformed("tree size"));
        }
        for (slot, leaf) in leaves.into_iter().enumerate() {
            if leaf == Value::Null {
                continue;
            }
            let mut fields = expect_array(leaf, 3, "tree leaf")?.into_iter();
            let leaf_id = expect_bytes32(next(&mut fields, "tree leaf")?, "tree leaf id")?;
            let generation = expect_uint(&next(&mut fields, "tree leaf")?, "tree generation")?;
            let public_key = expect_bytes(next(&mut fields, "tree leaf")?, "tree leaf key")?;
            validate_public_key(&public_key)?;
            tree.leaves[slot] = Some(LeafNode {
                leaf_id,
                generation,
                public_key,
            });
        }
        for (node, key) in parents.into_iter().enumerate() {
            if key == Value::Null {
                continue;
            }
            let key = expect_bytes(key, "tree node key")?;
            validate_public_key(&key)?;
            tree.parents[node] = Some(key);
        }
        Ok(tree)
    }
}

pub(crate) fn next(
    items: &mut impl Iterator<Item = Value>,
    what: &'static str,
) -> CoreResult<Value> {
    items.next().ok_or(CoreError::Malformed(what))
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
    pub author_slot: u32,
}

impl PathContext {
    fn wrap_context(&self, node: u32, target: u32, target_pk_hash: &Digest) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            bytes(&self.gid),
            uint(self.epoch),
            uint(u64::from(self.author_slot)),
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
    fn key_for(&self, n_max: u32, my_slot: u32, node: u32) -> Option<&KemSecret> {
        if node == leaf_node(n_max, my_slot) {
            self.leaf.as_ref()
        } else {
            self.nodes.get(&node)
        }
    }

    /// Forget keys of nodes that are now blank in `tree`.
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
    /// Path secret of the root, from which the commit secret derives.
    pub root_secret: Zeroizing<[u8; 32]>,
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
/// "tree leaf key", h'', 64))`.
pub fn leaf_key_from_secret(leaf_secret: &[u8; 32]) -> CoreResult<KemSecret> {
    KemSecret::derive(leaf_secret, "tree leaf key")
}

/// Re-key `author_slot`: fresh leaf secret, derived path secrets and node
/// keys, each path secret encapsulated to the resolution of the copath in
/// `tree` (the tree the commit starts from).
pub fn generate_update_path(
    tree: &PublicTree,
    context: &PathContext,
    rng: &mut impl CryptoRngCore,
) -> CoreResult<(UpdatePath, PathSecrets)> {
    let leaf_secret = new_leaf_secret(rng);
    generate_update_path_from_leaf_secret(tree, context, &leaf_secret, rng)
}

/// [`generate_update_path`] with a leaf secret chosen by the caller. A
/// joiner uses it to place its leaf (with the key derived from
/// `leaf_secret`) in the tree before generating its path.
pub fn generate_update_path_from_leaf_secret(
    tree: &PublicTree,
    context: &PathContext,
    leaf_secret: &[u8; 32],
    rng: &mut impl CryptoRngCore,
) -> CoreResult<(UpdatePath, PathSecrets)> {
    let slot = context.author_slot;
    if tree.leaf(slot).is_none() {
        return Err(CoreError::Invalid("update path from an empty slot"));
    }
    let direct_path = tree.direct_path(slot)?;
    let copath = tree.copath(slot)?;

    let leaf_key = leaf_key_from_secret(leaf_secret)?;
    let leaf_public_key = leaf_key.public_key();

    let mut secret = derive_secret(leaf_secret, "tree path")?;
    let mut nodes = Vec::with_capacity(direct_path.len());
    let mut node_keys = BTreeMap::new();
    for (index, node) in direct_path.iter().copied().enumerate() {
        if index > 0 {
            secret = derive_secret(&secret, "tree path")?;
        }
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
    }
    let root_secret = secret;
    Ok((
        UpdatePath {
            leaf_public_key,
            nodes,
        },
        PathSecrets {
            node_keys,
            leaf_key: Some(leaf_key),
            root_secret,
        },
    ))
}

/// Check an update path from `author_slot` against `tree` (the tree the
/// commit starts from): one entry per direct-path node, valid keys, and
/// exactly one ciphertext per resolution node of the copath. Needs no secret.
pub fn validate_update_path(
    tree: &PublicTree,
    author_slot: u32,
    path: &UpdatePath,
) -> CoreResult<()> {
    if tree.leaf(author_slot).is_none() {
        return Err(CoreError::Invalid("update path from an empty slot"));
    }
    validate_public_key(&path.leaf_public_key)?;
    let direct_path = tree.direct_path(author_slot)?;
    let copath = tree.copath(author_slot)?;
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

/// Decrypt the path secret meant for this member and derive the keys of the
/// shared part of the path. `tree` is the tree the commit started from.
pub fn decrypt_update_path(
    tree: &PublicTree,
    context: &PathContext,
    path: &UpdatePath,
    my_slot: u32,
    private: &PrivatePath,
) -> CoreResult<PathSecrets> {
    validate_update_path(tree, context.author_slot, path)?;
    if my_slot == context.author_slot {
        return Err(CoreError::Invalid("own update path"));
    }
    let n_max = tree.n_max();
    let author_path = tree.direct_path(context.author_slot)?;
    let copath = tree.copath(context.author_slot)?;
    let my_leaf = leaf_node(n_max, my_slot);
    // The lowest shared ancestor is the first path node whose copath child
    // covers this member's leaf.
    let level = copath
        .iter()
        .position(|node| is_ancestor_or_self(*node, my_leaf))
        .ok_or(CoreError::Invalid("member not covered by the update path"))?;
    let entry = &path.nodes[level];
    let (target, key) = entry
        .targets
        .iter()
        .find_map(|target| {
            private
                .key_for(n_max, my_slot, target.target)
                .map(|key| (target, key))
        })
        .ok_or(CoreError::Decrypt("no path secret for this member"))?;
    let target_pk = tree
        .node_public_key(target.target)
        .ok_or(CoreError::Invalid("blank resolution node"))?;
    let shared = key.decapsulate(&target.kem_ciphertext)?;
    let wrap_context = context.wrap_context(entry.node, target.target, &pk_hash(target_pk)?)?;
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
    for (index, node) in author_path.iter().copied().enumerate().skip(level) {
        if index > level {
            secret = derive_secret(&secret, "tree path")?;
        }
        let key = node_key(&secret)?;
        // Every derivable public key must match the one the author published.
        if key.public_key() != path.nodes[index].public_key {
            return Err(CoreError::Invalid("update path public key mismatch"));
        }
        node_keys.insert(node, key);
    }
    Ok(PathSecrets {
        node_keys,
        leaf_key: None,
        root_secret: secret,
    })
}

fn is_ancestor_or_self(ancestor: u32, mut node: u32) -> bool {
    loop {
        if node == ancestor {
            return true;
        }
        match parent_of(node) {
            Some(parent) => node = parent,
            None => return false,
        }
    }
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
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    struct Member {
        slot: u32,
        private: PrivatePath,
    }

    fn add_member(tree: &mut PublicTree, slot: u32, rng: &mut ChaCha20Rng) -> Member {
        let key = KemSecret::generate(rng);
        tree.add_leaf(
            slot,
            LeafNode {
                leaf_id: [slot as u8; 32],
                generation: 0,
                public_key: key.public_key(),
            },
        )
        .unwrap();
        Member {
            slot,
            private: PrivatePath {
                leaf: Some(key),
                nodes: BTreeMap::new(),
            },
        }
    }

    fn commit(
        tree: &mut PublicTree,
        members: &mut [Member],
        author: usize,
        epoch: u64,
        rng: &mut ChaCha20Rng,
    ) -> [u8; 32] {
        let context = PathContext {
            gid: [0x42; 32],
            epoch,
            author_slot: members[author].slot,
        };
        let (path, secrets) = generate_update_path(tree, &context, rng).unwrap();
        validate_update_path(tree, context.author_slot, &path).unwrap();
        let mut roots = vec![*secrets.root_secret];
        for (index, member) in members.iter_mut().enumerate() {
            if index == author {
                continue;
            }
            let received =
                decrypt_update_path(tree, &context, &path, member.slot, &member.private).unwrap();
            roots.push(*received.root_secret);
            member.private.nodes.extend(received.node_keys);
        }
        tree.apply_update_path(context.author_slot, &path).unwrap();
        let author_member = &mut members[author];
        author_member.private.leaf = secrets.leaf_key;
        author_member.private.nodes = secrets.node_keys;
        assert!(roots.windows(2).all(|pair| pair[0] == pair[1]));
        roots[0]
    }

    #[test]
    fn tree_shape_helpers() {
        let tree = PublicTree::new(8).unwrap();
        assert_eq!(tree.direct_path(0).unwrap(), vec![3, 1, 0]);
        assert_eq!(tree.copath(0).unwrap(), vec![8, 4, 2]);
        assert_eq!(tree.direct_path(7).unwrap(), vec![6, 2, 0]);
        assert_eq!(tree.copath(5).unwrap(), vec![11, 6, 1]);
        assert!(tree.direct_path(8).is_err());
        assert!(tree.resolution(0).is_empty());
        assert_eq!(tree.first_free_slot(), Some(0));
        assert!(PublicTree::new(3).is_err());
        assert!(PublicTree::new(1).is_err());
        assert!(PublicTree::new(MAX_N_MAX * 2).is_err());
        assert!(is_ancestor_or_self(0, 9) && !is_ancestor_or_self(2, 9));
        assert!(max_update_path_bytes(1024) < 1_300_000);
        assert!(max_update_path_bytes(2) > 2 * KEM_PUBLIC_KEY_BYTES);
    }

    #[test]
    fn members_agree_on_root_secret_across_commits_and_removals() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let mut tree = PublicTree::new(8).unwrap();
        let mut members: Vec<Member> = (0..5)
            .map(|slot| add_member(&mut tree, slot, &mut rng))
            .collect();
        let first = commit(&mut tree, &mut members, 0, 1, &mut rng);
        let second = commit(&mut tree, &mut members, 3, 2, &mut rng);
        assert_ne!(first, second);
        // The resolution now uses the re-keyed parents.
        assert_eq!(tree.resolution(1), vec![1]);

        // Remove slot 1: its path is blanked, then slot 4 commits.
        let removed = members.remove(1);
        tree.remove_leaf(removed.slot).unwrap();
        for member in &mut members {
            member.private.retain_live(&tree);
        }
        let hash_before = tree.tree_hash().unwrap();
        let third = commit(&mut tree, &mut members, 3, 3, &mut rng);
        assert_ne!(hash_before, tree.tree_hash().unwrap());
        // The removed member cannot decrypt the new path.
        let context = PathContext {
            gid: [0x42; 32],
            epoch: 4,
            author_slot: 0,
        };
        let mut pre = tree.clone();
        let (path, secrets) = generate_update_path(&pre, &context, &mut rng).unwrap();
        pre.apply_update_path(0, &path).unwrap();
        assert_ne!(*secrets.root_secret, third);
        let stale = decrypt_update_path(&tree, &context, &path, removed.slot, &removed.private);
        assert!(stale.is_err(), "a removed slot is not covered");
    }

    #[test]
    fn tampered_paths_are_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let mut tree = PublicTree::new(4).unwrap();
        let members: Vec<Member> = (0..3)
            .map(|slot| add_member(&mut tree, slot, &mut rng))
            .collect();
        let context = PathContext {
            gid: [1; 32],
            epoch: 1,
            author_slot: 0,
        };
        let (path, _) = generate_update_path(&tree, &context, &mut rng).unwrap();

        let mut missing = path.clone();
        missing.nodes[0].targets.clear();
        assert_eq!(
            validate_update_path(&tree, 0, &missing),
            Err(CoreError::Invalid("update path targets"))
        );
        let mut wrong_node = path.clone();
        wrong_node.nodes[0].node = 2;
        assert!(validate_update_path(&tree, 0, &wrong_node).is_err());
        let mut short = path.clone();
        short.nodes.pop();
        assert!(validate_update_path(&tree, 0, &short).is_err());
        assert!(
            validate_update_path(&tree, 3, &path).is_err(),
            "empty author slot"
        );

        // A wrong public key is detected by the members that can derive it.
        let mut forged = path.clone();
        forged.nodes[1].public_key = KemSecret::generate(&mut rng).public_key();
        let err = decrypt_update_path(&tree, &context, &forged, 1, &members[1].private);
        assert_eq!(
            err.err(),
            Some(CoreError::Invalid("update path public key mismatch"))
        );
        // A wrong context fails authentication.
        let other = PathContext {
            epoch: 2,
            ..context
        };
        assert!(decrypt_update_path(&tree, &other, &path, 1, &members[1].private).is_err());
        assert!(decrypt_update_path(&tree, &context, &path, 0, &members[0].private).is_err());
    }

    #[test]
    fn encodings_round_trip() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let mut tree = PublicTree::new(4).unwrap();
        let _members: Vec<Member> = (0..2)
            .map(|slot| add_member(&mut tree, slot, &mut rng))
            .collect();
        let decoded = PublicTree::from_cbor(&tree.to_cbor().unwrap()).unwrap();
        assert_eq!(decoded, tree);
        assert_eq!(decoded.tree_hash().unwrap(), tree.tree_hash().unwrap());
        let context = PathContext {
            gid: [2; 32],
            epoch: 1,
            author_slot: 1,
        };
        let (path, _) = generate_update_path(&tree, &context, &mut rng).unwrap();
        let value = update_path_to_value(&path);
        assert_eq!(update_path_from_value(value).unwrap(), path);
        assert!(update_path_from_value(uint(1)).is_err());
        assert!(PublicTree::from_cbor(&[0x80]).is_err());
        assert!(tree.add_leaf(0, tree.leaf(0).unwrap().clone()).is_err());
        assert!(tree.remove_leaf(3).is_err());
    }
}
