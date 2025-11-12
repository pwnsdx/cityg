use crate::MsphfError;
use smallvec::SmallVec;

/// Compute the canonical Merkle set root for a sorted list of 32-byte leaves as
/// defined in Appendix F of the City‑G spec. The input must be strictly increasing in
/// byte-lexicographic order. The carry rule propagates the last digest when the
/// level has an odd cardinality.
pub fn canonical_set_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], MsphfError> {
    if leaves.len() <= 1 {
        if leaves.is_empty() {
            return Ok([0u8; 32]);
        }
        return Ok(leaves[0]);
    }
    if leaves.windows(2).any(|window| window[0] >= window[1]) {
        return Err(MsphfError::invalid_input("set must be strictly increasing"));
    }

    // Use SmallVec to avoid heap allocation for trees with ≤32 leaves (common case)
    let mut level: SmallVec<[[u8; 32]; 32]> = leaves.iter().copied().collect();
    while level.len() > 1 {
        let mut next: SmallVec<[[u8; 32]; 32]> = SmallVec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks_exact(2) {
            next.push(hash_node(&pair[0], &pair[1]));
        }
        if let (true, Some(&carry)) = (level.len() % 2 == 1, level.last()) {
            next.push(carry);
        }
        level = next;
    }
    Ok(level[0])
}

/// Compute the canonical Merkle frontier (multiset of carried digests) for the
/// provided sorted leaf set. The returned multiset is arranged in the order
/// encountered while ascending the tree and is unique for a given leaf set.
pub fn canonical_frontier(leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, MsphfError> {
    if leaves.is_empty() {
        return Ok(Vec::new());
    }
    if leaves.windows(2).any(|window| window[0] >= window[1]) {
        return Err(MsphfError::invalid_input("set must be strictly increasing"));
    }
    // Use SmallVec to avoid heap allocation for trees with ≤32 leaves (common case)
    let mut level: SmallVec<[[u8; 32]; 32]> = leaves.iter().copied().collect();
    let mut frontier = Vec::new();
    while level.len() > 1 {
        let mut next: SmallVec<[[u8; 32]; 32]> = SmallVec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks_exact(2) {
            next.push(hash_node(&pair[0], &pair[1]));
        }
        if let (true, Some(&carry)) = (level.len() % 2 == 1, level.last()) {
            frontier.push(carry);
            next.push(carry);
        }
        level = next;
    }
    Ok(frontier)
}

fn apply_path(mut acc: [u8; 32], path: &[(u8, [u8; 32])]) -> [u8; 32] {
    for (dir, sib) in path {
        acc = if *dir == 0 {
            hash_node(&acc, sib)
        } else {
            hash_node(sib, &acc)
        };
    }
    acc
}

#[inline]
pub fn hash_leaf(leaf: &[u8]) -> [u8; 32] {
    crate::rpo256::leaf(leaf)
}

#[inline]
pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    crate::rpo256::node(left, right)
}

#[inline]
pub fn hash_interval(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    crate::rpo256::interval_node(left, right)
}

#[inline]
pub fn hash_interval_binding(
    left_id: &[u8; 32],
    left_leaf: &[u8; 32],
    right_id: &[u8; 32],
    right_leaf: &[u8; 32],
    lca_left_height: u8,
    lca_right_height: u8,
) -> [u8; 32] {
    crate::rpo256::interval_binding(
        left_id,
        left_leaf,
        right_id,
        right_leaf,
        lca_left_height,
        lca_right_height,
    )
}

#[inline]
pub fn validate_membership_path(leaf: &[u8; 32], path: &[(u8, [u8; 32])]) -> [u8; 32] {
    apply_path(*leaf, path)
}

#[inline]
pub fn apply_path_from(acc: &[u8; 32], path: &[(u8, [u8; 32])]) -> [u8; 32] {
    apply_path(*acc, path)
}

#[inline]
pub fn bytes32(slice: &[u8]) -> Result<[u8; 32], MsphfError> {
    crate::rpo256::digest_from_slice(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(id: u8) -> [u8; 32] {
        let mut data = [0u8; 32];
        data[31] = id;
        hash_leaf(&data)
    }

    #[test]
    fn canonical_root_single_leaf() {
        let leaves = [leaf(1)];
        let root = canonical_set_root(&leaves).expect("root");
        assert_eq!(root, leaves[0]);
        let frontier = canonical_frontier(&leaves).expect("frontier");
        assert!(frontier.is_empty());
    }

    #[test]
    fn canonical_root_even_leaves() {
        let mut leaves = [leaf(1), leaf(2), leaf(3), leaf(4)];
        leaves.sort();
        let root = canonical_set_root(&leaves).expect("root");
        let left = hash_node(&leaves[0], &leaves[1]);
        let right = hash_node(&leaves[2], &leaves[3]);
        assert_eq!(root, hash_node(&left, &right));
        let frontier = canonical_frontier(&leaves).expect("frontier");
        assert!(frontier.is_empty());
    }

    #[test]
    fn canonical_root_odd_leaves() {
        let mut leaves = [leaf(1), leaf(2), leaf(3)];
        leaves.sort();
        let root = canonical_set_root(&leaves).expect("canonical root");
        let pair = hash_node(&leaves[0], &leaves[1]);
        let expected = hash_node(&pair, &leaves[2]);
        assert_eq!(root, expected);
        let frontier = canonical_frontier(&leaves).expect("canonical frontier");
        assert_eq!(frontier, vec![leaves[2]]);
    }

    #[test]
    fn canonical_set_requires_sorted() {
        let leaves = [leaf(2), leaf(1)];
        assert!(canonical_set_root(&leaves).is_err());
        assert!(canonical_frontier(&leaves).is_err());
    }
}
