//! Compact sparse Merkle maps from 32-byte keys to occupancies
//! (docs/specs-v0.4-draft.md section 8).
//!
//! The map is a binary trie on the bits of the keys, most significant bit
//! first, where a subtree holding one entry is replaced by that entry:
//!
//! * empty subtree: `ZERO32`;
//! * one entry: `H_L("smm/leaf", [key, [leaf, since]])`;
//! * otherwise: `H_L("smm/node", [left, right])`, split on the next bit.
//!
//! The root depends only on the set of entries. A proof lists the sibling
//! hashes down to the subtree where the key's branch ends, and that
//! subtree's single entry, if any: it shows either the key's value or that
//! the key is absent.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use crate::cbor::bytes;
use crate::crypto::{Digest, ZERO32, h_l};
use crate::error::{CoreError, CoreResult};
use crate::tree::Occupancy;

/// Nodes deeper than this are not cached (with hashed keys, a node that deep
/// holds two entries with probability about `n^2 / 2^64`).
const CACHED_DEPTH: usize = 64;

fn bit(key: &Digest, depth: usize) -> bool {
    (key[depth / 8] >> (7 - depth % 8)) & 1 == 1
}

/// Lowest and highest keys that share the first `depth` bits of `key`.
fn bounds(key: &Digest, depth: usize) -> (Digest, Digest) {
    let mut low = *key;
    let mut high = *key;
    for position in depth..256 {
        let byte = position / 8;
        let mask = 1u8 << (7 - position % 8);
        low[byte] &= !mask;
        high[byte] |= mask;
    }
    (low, high)
}

fn leaf_hash(key: &Digest, value: Occupancy) -> CoreResult<Digest> {
    h_l("smm/leaf", vec![bytes(key), value.value()])
}

fn node_hash(left: &Digest, right: &Digest) -> CoreResult<Digest> {
    h_l("smm/node", vec![bytes(left), bytes(right)])
}

/// Changes to a map: `Some` sets a key, `None` removes it.
pub type SmmDelta = BTreeMap<Digest, Option<Occupancy>>;

/// A sparse Merkle map.
#[derive(Clone, Debug, Default)]
pub struct Smm {
    entries: BTreeMap<Digest, Occupancy>,
    cache: RefCell<HashMap<(usize, Digest), Digest>>,
}

impl Smm {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Value of `key`.
    #[must_use]
    pub fn get(&self, key: &Digest) -> Option<Occupancy> {
        self.entries.get(key).copied()
    }

    fn invalidate(&self, key: &Digest) {
        let mut cache = self.cache.borrow_mut();
        for depth in 0..CACHED_DEPTH {
            cache.remove(&(depth, bounds(key, depth).0));
        }
    }

    /// Set `key` to `value`.
    pub fn insert(&mut self, key: Digest, value: Occupancy) {
        self.entries.insert(key, value);
        self.invalidate(&key);
    }

    /// Remove `key`.
    pub fn remove(&mut self, key: &Digest) {
        if self.entries.remove(key).is_some() {
            self.invalidate(key);
        }
    }

    /// Apply `delta`.
    pub fn apply(&mut self, delta: &SmmDelta) {
        for (key, value) in delta {
            match value {
                Some(value) => self.insert(*key, *value),
                None => self.remove(key),
            }
        }
    }

    /// Root hash.
    pub fn root(&self) -> CoreResult<Digest> {
        self.subtree(0, &ZERO32)
    }

    fn subtree(&self, depth: usize, prefix: &Digest) -> CoreResult<Digest> {
        let (low, high) = bounds(prefix, depth);
        let mut range = self.entries.range(low..=high);
        let first = range.next();
        let second = range.next();
        match (first, second) {
            (None, _) => Ok(ZERO32),
            (Some((key, value)), None) => leaf_hash(key, *value),
            _ => {
                if depth >= 256 {
                    return Err(CoreError::Invalid("sparse Merkle map"));
                }
                if depth < CACHED_DEPTH
                    && let Some(hash) = self.cache.borrow().get(&(depth, low))
                {
                    return Ok(*hash);
                }
                let (left_low, right_low) = split(&low, depth);
                let left = self.subtree(depth + 1, &left_low)?;
                let right = self.subtree(depth + 1, &right_low)?;
                let hash = node_hash(&left, &right)?;
                if depth < CACHED_DEPTH {
                    self.cache.borrow_mut().insert((depth, low), hash);
                }
                Ok(hash)
            }
        }
    }

    /// Root hash after `delta`, without applying it.
    pub fn root_with(&self, delta: &SmmDelta) -> CoreResult<Digest> {
        self.subtree_with(0, &ZERO32, delta)
    }

    fn subtree_with(&self, depth: usize, prefix: &Digest, delta: &SmmDelta) -> CoreResult<Digest> {
        let (low, high) = bounds(prefix, depth);
        if delta.range(low..=high).next().is_none() {
            return self.subtree(depth, prefix);
        }
        let mut merged = Merged {
            base: self.entries.range(low..=high).peekable(),
            delta: delta.range(low..=high).peekable(),
        };
        let first = merged.next();
        let second = merged.next();
        match (first, second) {
            (None, _) => Ok(ZERO32),
            (Some((key, value)), None) => leaf_hash(&key, value),
            _ => {
                if depth >= 256 {
                    return Err(CoreError::Invalid("sparse Merkle map"));
                }
                let (left_low, right_low) = split(&low, depth);
                let left = self.subtree_with(depth + 1, &left_low, delta)?;
                let right = self.subtree_with(depth + 1, &right_low, delta)?;
                node_hash(&left, &right)
            }
        }
    }

    /// Proof of the value of `key`, or of its absence.
    pub fn prove(&self, key: &Digest) -> CoreResult<SmmProof> {
        let mut siblings = Vec::new();
        let mut depth = 0usize;
        loop {
            let (low, high) = bounds(key, depth);
            let mut range = self.entries.range(low..=high);
            let first = range.next();
            let second = range.next();
            match (first, second) {
                (None, _) => {
                    return Ok(SmmProof {
                        siblings,
                        terminal: None,
                    });
                }
                (Some((found, value)), None) => {
                    return Ok(SmmProof {
                        siblings,
                        terminal: Some((*found, *value)),
                    });
                }
                _ => {
                    if depth >= 256 {
                        return Err(CoreError::Invalid("sparse Merkle map"));
                    }
                    let (left_low, right_low) = split(&low, depth);
                    let sibling = if bit(key, depth) { left_low } else { right_low };
                    siblings.push(self.subtree(depth + 1, &sibling)?);
                    depth += 1;
                }
            }
        }
    }
}

fn split(low: &Digest, depth: usize) -> (Digest, Digest) {
    let mut right = *low;
    right[depth / 8] |= 1u8 << (7 - depth % 8);
    (*low, right)
}

struct Merged<'a, B, D>
where
    B: Iterator<Item = (&'a Digest, &'a Occupancy)>,
    D: Iterator<Item = (&'a Digest, &'a Option<Occupancy>)>,
{
    base: std::iter::Peekable<B>,
    delta: std::iter::Peekable<D>,
}

impl<'a, B, D> Iterator for Merged<'a, B, D>
where
    B: Iterator<Item = (&'a Digest, &'a Occupancy)>,
    D: Iterator<Item = (&'a Digest, &'a Option<Occupancy>)>,
{
    type Item = (Digest, Occupancy);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let from_base = self.base.peek().map(|(key, _)| **key);
            let from_delta = self.delta.peek().map(|(key, _)| **key);
            match (from_base, from_delta) {
                (None, None) => return None,
                (Some(_), None) => return self.base.next().map(|(key, value)| (*key, *value)),
                (base_key, Some(delta_key)) => {
                    if base_key.is_some_and(|base_key| base_key < delta_key) {
                        return self.base.next().map(|(key, value)| (*key, *value));
                    }
                    if base_key == Some(delta_key) {
                        self.base.next();
                    }
                    if let Some((key, Some(value))) = self.delta.next() {
                        return Some((*key, *value));
                    }
                }
            }
        }
    }
}

/// Proof of a key's value or absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmmProof {
    /// Sibling hashes from the root down.
    pub siblings: Vec<Digest>,
    /// The single entry of the subtree where the key's branch ends, if any.
    pub terminal: Option<(Digest, Occupancy)>,
}

impl SmmProof {
    /// Check the proof against `root` for `key`: the key's value, or `None`
    /// when the proof shows it absent.
    pub fn verify(&self, root: &Digest, key: &Digest) -> CoreResult<Option<Occupancy>> {
        let depth = self.siblings.len();
        if depth > 256 {
            return Err(CoreError::Invalid("map proof"));
        }
        let (mut hash, value) = match &self.terminal {
            None => (ZERO32, None),
            Some((found, found_value)) => {
                if bounds(found, depth).0 != bounds(key, depth).0 {
                    return Err(CoreError::Invalid("map proof"));
                }
                (
                    leaf_hash(found, *found_value)?,
                    (found == key).then_some(*found_value),
                )
            }
        };
        for position in (0..depth).rev() {
            let sibling = &self.siblings[position];
            hash = if bit(key, position) {
                node_hash(sibling, &hash)?
            } else {
                node_hash(&hash, sibling)?
            };
        }
        if &hash == root {
            Ok(value)
        } else {
            Err(CoreError::Invalid("map proof"))
        }
    }

    /// Size in bytes as a deployment would send it.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        32 * self.siblings.len() + self.terminal.map_or(1, |_| 48)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::h;

    fn key(n: u32) -> Digest {
        h(&n.to_be_bytes())
    }

    fn occupancy(n: u32) -> Occupancy {
        Occupancy {
            leaf: n,
            since: u64::from(n) + 1,
        }
    }

    #[test]
    fn roots_depend_only_on_the_entries() {
        let mut forward = Smm::new();
        let mut backward = Smm::new();
        assert_eq!(forward.root().unwrap(), ZERO32);
        for n in 0..50 {
            forward.insert(key(n), occupancy(n));
        }
        for n in (0..50).rev() {
            backward.insert(key(n), occupancy(n));
        }
        assert_eq!(forward.root().unwrap(), backward.root().unwrap());
        let one = {
            let mut map = Smm::new();
            map.insert(key(3), occupancy(3));
            map.root().unwrap()
        };
        assert_eq!(one, leaf_hash(&key(3), occupancy(3)).unwrap());
        for n in 1..50 {
            forward.remove(&key(n));
        }
        assert_eq!(
            forward.root().unwrap(),
            leaf_hash(&key(0), occupancy(0)).unwrap()
        );
    }

    #[test]
    fn a_delta_root_matches_the_applied_map() {
        let mut map = Smm::new();
        for n in 0..200 {
            map.insert(key(n), occupancy(n));
        }
        let before = map.root().unwrap();
        let mut delta = SmmDelta::new();
        for n in 0..40 {
            delta.insert(key(n * 5), None);
        }
        for n in 200..230 {
            delta.insert(key(n), Some(occupancy(n)));
        }
        delta.insert(key(7), Some(occupancy(99)));
        let predicted = map.root_with(&delta).unwrap();
        assert_eq!(map.root().unwrap(), before);
        map.apply(&delta);
        assert_eq!(map.root().unwrap(), predicted);
        assert_eq!(map.root_with(&SmmDelta::new()).unwrap(), predicted);
        // Removing everything gives the empty root.
        let all: SmmDelta = (0..230).map(|n| (key(n), None)).collect();
        assert_eq!(map.root_with(&all).unwrap(), ZERO32);
    }

    #[test]
    fn proofs_show_values_and_absences() {
        let mut map = Smm::new();
        for n in 0..100 {
            map.insert(key(n), occupancy(n));
        }
        let root = map.root().unwrap();
        for n in [0u32, 17, 99] {
            let proof = map.prove(&key(n)).unwrap();
            assert_eq!(proof.verify(&root, &key(n)).unwrap(), Some(occupancy(n)));
        }
        for n in [100u32, 1000, 4242] {
            let proof = map.prove(&key(n)).unwrap();
            assert_eq!(proof.verify(&root, &key(n)).unwrap(), None);
        }
        // A membership proof does not pass for another key or root.
        let proof = map.prove(&key(5)).unwrap();
        assert!(
            proof.verify(&root, &key(6)).is_err()
                || proof.verify(&root, &key(6)).unwrap().is_none()
        );
        assert!(proof.verify(&[1; 32], &key(5)).is_err());
        // Hiding an entry is detected.
        let mut hidden = map.prove(&key(5)).unwrap();
        hidden.terminal = None;
        assert!(hidden.verify(&root, &key(5)).is_err());
        let mut altered = map.prove(&key(5)).unwrap();
        altered.terminal = Some((key(5), occupancy(6)));
        assert!(altered.verify(&root, &key(5)).is_err());
        let empty = Smm::new();
        assert_eq!(
            empty
                .prove(&key(1))
                .unwrap()
                .verify(&ZERO32, &key(1))
                .unwrap(),
            None
        );
    }
}
