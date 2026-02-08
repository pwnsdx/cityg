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
    crate::rpo256::v2::leaf(leaf)
}

#[inline]
pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    crate::rpo256::v2::node(left, right)
}

#[inline]
pub fn hash_interval(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    crate::rpo256::v2::interval_node(left, right)
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
    crate::rpo256::v2::hash_with_tag(
        0x4D54_5F4E_4D42_494E, // "MT_NMBIN"
        &{
            let mut payload = Vec::with_capacity(32 * 4 + 2);
            payload.extend_from_slice(left_id);
            payload.extend_from_slice(left_leaf);
            payload.extend_from_slice(right_id);
            payload.extend_from_slice(right_leaf);
            payload.push(lca_left_height);
            payload.push(lca_right_height);
            payload
        },
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

    fn hash_interval_binding_v1_compat(
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

    fn leaf(id: u8) -> [u8; 32] {
        let mut data = [0u8; 32];
        data[31] = id;
        hash_leaf(&data)
    }

    #[test]
    fn canonical_root_single_leaf() {
        let leaves = [leaf(1)];
        let root = match canonical_set_root(&leaves) {
            Ok(r) => r,
            Err(_) => unreachable!("canonical_set_root should not fail for single leaf"),
        };
        assert_eq!(root, leaves[0]);
        let frontier = match canonical_frontier(&leaves) {
            Ok(f) => f,
            Err(_) => unreachable!("canonical_frontier should not fail for single leaf"),
        };
        assert!(frontier.is_empty());
    }

    #[test]
    fn canonical_root_even_leaves() {
        let mut leaves = [leaf(1), leaf(2), leaf(3), leaf(4)];
        leaves.sort();
        let root = match canonical_set_root(&leaves) {
            Ok(r) => r,
            Err(_) => unreachable!("canonical_set_root should not fail for even leaves"),
        };
        let left = hash_node(&leaves[0], &leaves[1]);
        let right = hash_node(&leaves[2], &leaves[3]);
        assert_eq!(root, hash_node(&left, &right));
        let frontier = match canonical_frontier(&leaves) {
            Ok(f) => f,
            Err(_) => unreachable!("canonical_frontier should not fail for even leaves"),
        };
        assert!(frontier.is_empty());
    }

    #[test]
    fn canonical_root_odd_leaves() {
        let mut leaves = [leaf(1), leaf(2), leaf(3)];
        leaves.sort();
        let root = match canonical_set_root(&leaves) {
            Ok(r) => r,
            Err(_) => unreachable!("canonical_set_root should not fail for odd leaves"),
        };
        let pair = hash_node(&leaves[0], &leaves[1]);
        let expected = hash_node(&pair, &leaves[2]);
        assert_eq!(root, expected);
        let frontier = match canonical_frontier(&leaves) {
            Ok(f) => f,
            Err(_) => unreachable!("canonical_frontier should not fail for odd leaves"),
        };
        assert_eq!(frontier, vec![leaves[2]]);
    }

    #[test]
    fn canonical_set_requires_sorted() {
        let mut leaves = [leaf(1), leaf(2)];
        leaves.sort();
        leaves.swap(0, 1);
        assert!(canonical_set_root(&leaves).is_err());
        assert!(canonical_frontier(&leaves).is_err());
    }

    #[test]
    fn leaf_hash_uses_v2_trailing_zero_safe_behavior() {
        let short = [0x01u8];
        let padded = [0x01u8, 0, 0, 0, 0, 0, 0, 0];
        assert_ne!(
            hash_leaf(&short),
            hash_leaf(&padded),
            "merkle leaf hashing should use rpo-256/v2 semantics"
        );
    }

    #[test]
    fn interval_binding_switched_to_v2() {
        let left_id = [0x10u8; 32];
        let left_leaf = [0x20u8; 32];
        let right_id = [0x30u8; 32];
        let right_leaf = [0x40u8; 32];
        let v2 = hash_interval_binding(&left_id, &left_leaf, &right_id, &right_leaf, 1, 2);
        let v1 = hash_interval_binding_v1_compat(&left_id, &left_leaf, &right_id, &right_leaf, 1, 2);
        assert_ne!(v2, v1, "interval binding should route through rpo-256/v2");
    }
}
