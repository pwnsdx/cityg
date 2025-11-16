use anyhow::{Result, bail};
use blake3::Hasher;

/// Simple binary Merkle tree using Blake3 for hashing.
#[derive(Clone, Debug)]
pub struct Blake3MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl Blake3MerkleTree {
    /// Build a tree from the provided leaf payloads.
    pub fn from_leaves(leaves: &[Vec<u8>]) -> Self {
        assert!(!leaves.is_empty(), "merkle tree requires at least one leaf");
        let mut current: Vec<[u8; 32]> = leaves.iter().map(|leaf| hash_leaf(leaf)).collect();
        let mut levels = Vec::new();
        levels.push(current.clone());
        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            for chunk in current.chunks(2) {
                let parent = if chunk.len() == 2 {
                    hash_nodes(chunk[0], chunk[1])
                } else {
                    hash_nodes(chunk[0], chunk[0])
                };
                next.push(parent);
            }
            current = next;
            levels.push(current.clone());
        }
        Self { levels }
    }

    /// Return the Merkle root.
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or_else(|| {
                // This should never happen if the tree was constructed properly
                unreachable!("merkle tree root not available")
            })
    }

    /// Return the authentication path for a given leaf index (bottom-up order).
    pub fn authentication_path(&self, mut index: usize) -> Vec<[u8; 32]> {
        let mut path = Vec::new();
        for level in &self.levels {
            if level.len() == 1 {
                break;
            }
            let sibling = if index & 1 == 0 {
                if index + 1 < level.len() {
                    level[index + 1]
                } else {
                    level[index]
                }
            } else {
                level[index - 1]
            };
            path.push(sibling);
            index /= 2;
        }
        path
    }

    /// Recompute the root from a leaf, index, and authentication path.
    pub fn verify_path(index: usize, leaf: &[u8], path: &[[u8; 32]]) -> [u8; 32] {
        let mut hash = hash_leaf(leaf);
        let mut idx = index;
        for sibling in path {
            if idx & 1 == 0 {
                hash = hash_nodes(hash, *sibling);
            } else {
                hash = hash_nodes(*sibling, hash);
            }
            idx /= 2;
        }
        hash
    }
}

fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"leaf");
    hasher.update(data);
    hasher.finalize().into()
}

fn hash_nodes(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"node");
    hasher.update(&left);
    hasher.update(&right);
    hasher.finalize().into()
}

/// Verify multiple openings against a given root.
pub fn verify_auth_paths(
    root: [u8; 32],
    openings: &[(usize, Vec<u8>)],
    paths: &[Vec<[u8; 32]>],
) -> Result<()> {
    if openings.len() != paths.len() {
        bail!("merkle verification length mismatch");
    }
    for ((index, leaf), path) in openings.iter().zip(paths.iter()) {
        let computed = Blake3MerkleTree::verify_path(*index, leaf, path);
        if computed != root {
            bail!("merkle authentication path mismatch");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_roundtrip() {
        let leaves = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let tree = Blake3MerkleTree::from_leaves(&leaves);
        for (idx, leaf) in leaves.iter().enumerate() {
            let path = tree.authentication_path(idx);
            let root = Blake3MerkleTree::verify_path(idx, leaf, &path);
            assert_eq!(root, tree.root());
        }
    }
}
