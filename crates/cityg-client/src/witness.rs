use crate::CityGError;
use msphf_core::{
    merkle::{canonical_set_root, hash_interval_binding, hash_leaf, hash_node},
    witness::{
        CanonicalWitness, RawMembershipWitness, RawNonMembershipWitness, RawPathEntry,
        WitnessVariants,
    },
};
use msphf_orchestrator::{SrxInputs, SrxNonMembershipAnchor};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use ahash::AHashMap;

const MAX_WITNESS_CBOR_BYTES: usize = 8 * 1024 * 1024;

type NonMemResult =
    Result<(RawNonMembershipWitness, Option<[u8; 32]>, Option<[u8; 32]>), CityGError>;

type SplitPathsResult = Result<
    (
        Vec<RawPathEntry>,
        Vec<RawPathEntry>,
        Vec<RawPathEntry>,
        u8,
        u8,
    ),
    CityGError,
>;
/// Deterministic demo leaf layout (matches existing examples).
pub fn sequential_leaf(index: u32) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    leaf[28..32].copy_from_slice(&index.to_be_bytes());
    leaf
}

/// Compute the Merkle root for a single-join delta (used for anchor parts).
pub fn join_delta_root(join_leaves: &[[u8; 32]]) -> Result<[u8; 32], CityGError> {
    Ok(canonical_set_root(join_leaves)?)
}

/// Convenience helper to serialize a canonical witness to CBOR.
pub fn witness_to_cbor(witness: &CanonicalWitness) -> Result<Vec<u8>, CityGError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(witness, &mut buf)
        .map_err(|_| CityGError::InvalidInput("unable to serialise witness"))?;
    Ok(buf)
}

/// Convenience helper to deserialize a canonical witness from CBOR.
pub fn witness_from_cbor(bytes: &[u8]) -> Result<CanonicalWitness, CityGError> {
    if bytes.len() > MAX_WITNESS_CBOR_BYTES {
        return Err(CityGError::InvalidInput("witness payload too large"));
    }
    ciborium::de::from_reader(bytes)
        .map_err(|_| CityGError::InvalidInput("unable to parse witness"))
}

/// Serialized representation of SRX inputs (branch B) with owned buffers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrxInputsOwned {
    pub join_leaf_ids: Vec<[u8; 32]>,
    pub join_nonmem_parent: Vec<SrxNonMembershipAnchorOwned>,
    pub join_nonmem_revoked_since: Vec<SrxNonMembershipAnchorOwned>,
    pub since_leaf_ids: Vec<[u8; 32]>,
    pub since_mem_revoked: Vec<RawMembershipWitness>,
    pub anchor_mem_pool: Vec<RawMembershipWitness>,
    pub join_frontier: Option<Vec<[u8; 32]>>,
    pub since_frontier: Option<Vec<[u8; 32]>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrxNonMembershipAnchorOwned {
    pub witness: RawNonMembershipWitness,
    pub left_ref: Option<u32>,
    pub right_ref: Option<u32>,
}

impl SrxInputsOwned {
    pub fn into_srx_inputs(self) -> SrxInputs<'static> {
        SrxInputs {
            join_leaf_ids: Cow::Owned(self.join_leaf_ids),
            join_nonmem_parent: self
                .join_nonmem_parent
                .into_iter()
                .map(|anchor| SrxNonMembershipAnchor {
                    witness: anchor.witness,
                    left_ref: anchor.left_ref,
                    right_ref: anchor.right_ref,
                })
                .collect(),
            join_nonmem_revoked_since: self
                .join_nonmem_revoked_since
                .into_iter()
                .map(|anchor| SrxNonMembershipAnchor {
                    witness: anchor.witness,
                    left_ref: anchor.left_ref,
                    right_ref: anchor.right_ref,
                })
                .collect(),
            since_leaf_ids: Cow::Owned(self.since_leaf_ids),
            since_mem_revoked: Cow::Owned(self.since_mem_revoked),
            anchor_mem_pool: self.anchor_mem_pool,
            join_frontier: self.join_frontier.map(Cow::Owned),
            since_frontier: self.since_frontier.map(Cow::Owned),
        }
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, CityGError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)
            .map_err(|_| CityGError::InvalidInput("unable to serialise SRX inputs"))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CityGError> {
        ciborium::de::from_reader(bytes)
            .map_err(|_| CityGError::InvalidInput("unable to parse SRX inputs"))
    }
}

impl From<&SrxInputs<'_>> for SrxInputsOwned {
    fn from(inputs: &SrxInputs<'_>) -> Self {
        Self {
            join_leaf_ids: inputs.join_leaf_ids.iter().copied().collect(),
            join_nonmem_parent: inputs
                .join_nonmem_parent
                .iter()
                .map(|anchor| SrxNonMembershipAnchorOwned {
                    witness: anchor.witness.clone(),
                    left_ref: anchor.left_ref,
                    right_ref: anchor.right_ref,
                })
                .collect(),
            join_nonmem_revoked_since: inputs
                .join_nonmem_revoked_since
                .iter()
                .map(|anchor| SrxNonMembershipAnchorOwned {
                    witness: anchor.witness.clone(),
                    left_ref: anchor.left_ref,
                    right_ref: anchor.right_ref,
                })
                .collect(),
            since_leaf_ids: inputs.since_leaf_ids.iter().copied().collect(),
            since_mem_revoked: inputs.since_mem_revoked.iter().cloned().collect(),
            anchor_mem_pool: inputs.anchor_mem_pool.clone(),
            join_frontier: inputs
                .join_frontier
                .as_ref()
                .map(|v| v.iter().copied().collect()),
            since_frontier: inputs
                .since_frontier
                .as_ref()
                .map(|v| v.iter().copied().collect()),
        }
    }
}

/// Build the canonical witness and SRX inputs for branch B given the parent
/// membership leaves and the new join leaves.
pub fn build_branch_b_artifacts(
    parent_leaves: &[[u8; 32]],
    join_leaves: &[[u8; 32]],
    parent_root: [u8; 32],
    revoked_since_root: [u8; 32],
) -> Result<(CanonicalWitness, SrxInputsOwned), CityGError> {
    let join_root = canonical_set_root(join_leaves)?;
    let witness = witness_branch_b(&join_root, &revoked_since_root);
    let empty: [[u8; 32]; 0] = [];
    let srx_owned = build_srx_inputs_owned(
        join_leaves,
        parent_leaves,
        parent_root,
        &[],
        revoked_since_root,
        &empty,
        [0u8; 32],
    )?;
    Ok((witness, srx_owned))
}

pub fn build_merge_srx_inputs(
    parent_leaves: &[[u8; 32]],
    join_leaves: &[[u8; 32]],
    parent_root: [u8; 32],
    revoked_since_leaves: &[[u8; 32]],
    revoked_leaves: &[[u8; 32]],
    revoked_root: [u8; 32],
) -> Result<SrxInputsOwned, CityGError> {
    let revoked_since_root = canonical_set_root(revoked_since_leaves)?;
    build_srx_inputs_owned(
        join_leaves,
        parent_leaves,
        parent_root,
        revoked_since_leaves,
        revoked_since_root,
        revoked_leaves,
        revoked_root,
    )
}

fn witness_branch_b(join_root: &[u8; 32], revoked_root: &[u8; 32]) -> CanonicalWitness {
    CanonicalWitness {
        inner: WitnessVariants::B {
            witness: RawMembershipWitness {
                leaf_id: join_root.to_vec(),
                root: join_root.to_vec(),
                path: Vec::new(),
            },
            nonmem: Some(RawNonMembershipWitness {
                query: join_root.to_vec(),
                root: revoked_root.to_vec(),
                left: None,
                right: None,
                path: Vec::new(),
                left_below: Vec::new(),
                right_below: Vec::new(),
                above: Vec::new(),
                nmint: None,
                lca_left_height: None,
                lca_right_height: None,
            }),
            pop: None,
        },
    }
}

fn build_srx_inputs_owned(
    join_leaves: &[[u8; 32]],
    parent_leaves: &[[u8; 32]],
    parent_root: [u8; 32],
    revoked_since_leaves: &[[u8; 32]],
    revoked_since_root: [u8; 32],
    revoked_leaves: &[[u8; 32]],
    revoked_root: [u8; 32],
) -> Result<SrxInputsOwned, CityGError> {
    let mut parent_sorted = parent_leaves.to_vec();
    parent_sorted.sort();
    if !parent_sorted.is_empty() {
        let expected_parent_root = canonical_set_root(&parent_sorted)?;
        if expected_parent_root != parent_root {
            return Err(CityGError::InvalidInput("parent root mismatch"));
        }
    }

    let mut revoked_since_sorted = revoked_since_leaves.to_vec();
    revoked_since_sorted.sort();
    let expected_since_root = canonical_set_root(&revoked_since_sorted)?;
    if expected_since_root != revoked_since_root {
        return Err(CityGError::InvalidInput("revoked_since_root mismatch"));
    }

    let mut revoked_sorted = revoked_leaves.to_vec();
    revoked_sorted.sort();
    if revoked_sorted.is_empty() {
        if revoked_root != [0u8; 32] {
            return Err(CityGError::InvalidInput("revoked_root mismatch"));
        }
    } else {
        let expected_revoked_root = canonical_set_root(&revoked_sorted)?;
        if expected_revoked_root != revoked_root {
            return Err(CityGError::InvalidInput("revoked_root mismatch"));
        }
    }

    let mut anchor_map: AHashMap<([u8; 32], [u8; 32]), RawMembershipWitness> = AHashMap::new();
    let mut join_nonmem_parent_temp = Vec::new();

    for &leaf in join_leaves {
        let (witness, left_anchor, right_anchor) =
            parent_nonmem_witness(&parent_sorted, parent_root, leaf)?;
        let left_key = left_anchor.map(|anchor_leaf| (parent_root, anchor_leaf));
        let right_key = right_anchor.map(|anchor_leaf| (parent_root, anchor_leaf));

        if let Some((root, leaf_id)) = left_key {
            anchor_map
                .entry((root, leaf_id))
                .or_insert_with(|| RawMembershipWitness {
                    leaf_id: leaf_id.to_vec(),
                    root: root.to_vec(),
                    path: canonical_membership_path(&parent_sorted, &leaf_id),
                });
        }
        if let Some((root, leaf_id)) = right_key {
            anchor_map
                .entry((root, leaf_id))
                .or_insert_with(|| RawMembershipWitness {
                    leaf_id: leaf_id.to_vec(),
                    root: root.to_vec(),
                    path: canonical_membership_path(&parent_sorted, &leaf_id),
                });
        }

        join_nonmem_parent_temp.push((witness, left_key, right_key));
    }

    let mut anchor_mem_pool = Vec::new();
    let mut anchor_lookup: AHashMap<([u8; 32], [u8; 32]), u32> = AHashMap::new();
    for (idx, (key, witness)) in anchor_map.into_iter().enumerate() {
        anchor_lookup.insert(key, idx as u32);
        anchor_mem_pool.push(witness);
    }

    let join_nonmem_parent = join_nonmem_parent_temp
        .into_iter()
        .map(
            |(witness, left_key, right_key)| SrxNonMembershipAnchorOwned {
                left_ref: left_key.map(|key| anchor_lookup[&key]),
                right_ref: right_key.map(|key| anchor_lookup[&key]),
                witness,
            },
        )
        .collect();

    let join_nonmem_revoked_since = join_leaves
        .iter()
        .map(|leaf| SrxNonMembershipAnchorOwned {
            witness: sentinel_nonmem(revoked_since_root, *leaf),
            left_ref: None,
            right_ref: None,
        })
        .collect();

    let since_mem_revoked = revoked_since_sorted
        .iter()
        .map(|leaf| {
            if !revoked_sorted.contains(leaf) {
                return Err(CityGError::InvalidInput(
                    "revoked leaf missing from revoked set",
                ));
            }
            Ok(RawMembershipWitness {
                leaf_id: leaf.to_vec(),
                root: revoked_root.to_vec(),
                path: if revoked_sorted.is_empty() {
                    Vec::new()
                } else {
                    canonical_membership_path(&revoked_sorted, leaf)
                },
            })
        })
        .collect::<Result<Vec<_>, CityGError>>()?;

    Ok(SrxInputsOwned {
        join_leaf_ids: join_leaves.to_vec(),
        join_nonmem_parent,
        join_nonmem_revoked_since,
        since_leaf_ids: revoked_since_sorted,
        since_mem_revoked,
        anchor_mem_pool,
        join_frontier: None,
        since_frontier: None,
    })
}

fn parent_nonmem_witness(
    parent_leaves: &[[u8; 32]],
    parent_root: [u8; 32],
    query: [u8; 32],
) -> NonMemResult {
    if parent_leaves.is_empty() {
        return Ok((
            RawNonMembershipWitness {
                query: query.to_vec(),
                root: parent_root.to_vec(),
                left: None,
                right: None,
                path: Vec::new(),
                left_below: Vec::new(),
                right_below: Vec::new(),
                above: Vec::new(),
                nmint: None,
                lca_left_height: None,
                lca_right_height: None,
            },
            None,
            None,
        ));
    }

    let mut pos = 0;
    while pos < parent_leaves.len() && parent_leaves[pos] < query {
        pos += 1;
    }

    let left = if pos > 0 {
        Some(parent_leaves[pos - 1])
    } else {
        None
    };
    let right = if pos < parent_leaves.len() {
        Some(parent_leaves[pos])
    } else {
        None
    };

    let witness = match (left, right) {
        (Some(l), Some(r)) => {
            let left_path = canonical_membership_path(parent_leaves, &l);
            let right_path = canonical_membership_path(parent_leaves, &r);
            let (left_below, right_below, above, lca_left_h, lca_right_h) =
                split_interval_paths(l, &left_path, r, &right_path, parent_root)?;

            RawNonMembershipWitness {
                query: query.to_vec(),
                root: parent_root.to_vec(),
                left: Some(l.to_vec()),
                right: Some(r.to_vec()),
                path: Vec::new(),
                left_below,
                right_below,
                above,
                nmint: Some(
                    hash_interval_binding(&l, &l, &r, &r, lca_left_h, lca_right_h).to_vec(),
                ),
                lca_left_height: Some(lca_left_h),
                lca_right_height: Some(lca_right_h),
            }
        }
        (Some(l), None) => {
            let path = canonical_membership_path(parent_leaves, &l);
            RawNonMembershipWitness {
                query: query.to_vec(),
                root: parent_root.to_vec(),
                left: Some(l.to_vec()),
                right: None,
                path,
                left_below: Vec::new(),
                right_below: Vec::new(),
                above: Vec::new(),
                nmint: None,
                lca_left_height: None,
                lca_right_height: None,
            }
        }
        (None, Some(r)) => {
            let path = canonical_membership_path(parent_leaves, &r);
            RawNonMembershipWitness {
                query: query.to_vec(),
                root: parent_root.to_vec(),
                left: None,
                right: Some(r.to_vec()),
                path,
                left_below: Vec::new(),
                right_below: Vec::new(),
                above: Vec::new(),
                nmint: None,
                lca_left_height: None,
                lca_right_height: None,
            }
        }
        (None, None) => unreachable!("non-empty parent set must yield at least one boundary"),
    };

    Ok((witness, left, right))
}

fn sentinel_nonmem(root: [u8; 32], query: [u8; 32]) -> RawNonMembershipWitness {
    RawNonMembershipWitness {
        query: query.to_vec(),
        root: root.to_vec(),
        left: None,
        right: None,
        path: Vec::new(),
        left_below: Vec::new(),
        right_below: Vec::new(),
        above: Vec::new(),
        nmint: None,
        lca_left_height: None,
        lca_right_height: None,
    }
}

fn canonical_membership_path(leaves: &[[u8; 32]], target: &[u8; 32]) -> Vec<RawPathEntry> {
    if leaves.len() <= 1 {
        return Vec::new();
    }

    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut index = match level.iter().position(|leaf| leaf == target) {
        Some(idx) => idx,
        None => unreachable!(),
    };
    let mut path = Vec::new();

    while level.len() > 1 {
        let len = level.len();
        if index % 2 == 0 {
            if index + 1 < len {
                path.push(RawPathEntry {
                    dir: 0,
                    sibling: level[index + 1].to_vec(),
                });
            }
        } else {
            path.push(RawPathEntry {
                dir: 1,
                sibling: level[index - 1].to_vec(),
            });
        }

        level = level
            .chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 {
                    hash_node(&chunk[0], &chunk[1])
                } else {
                    chunk[0]
                }
            })
            .collect();
        index /= 2;
    }

    path
}

fn split_interval_paths(
    left_leaf: [u8; 32],
    left_path: &[RawPathEntry],
    right_leaf: [u8; 32],
    right_path: &[RawPathEntry],
    parent_root: [u8; 32],
) -> SplitPathsResult {
    let mut left_below = Vec::new();
    let mut right_below = Vec::new();
    let mut above = Vec::new();

    let mut left_acc = left_leaf;
    let mut right_acc = right_leaf;

    for (idx, entry) in left_path.iter().enumerate() {
        let sibling: [u8; 32] = entry
            .sibling
            .as_slice()
            .try_into()
            .map_err(|_| CityGError::InvalidInput("invalid path entry"))?;
        if entry.dir == 0 {
            left_acc = hash_node(&left_acc, &sibling);
        } else {
            left_acc = hash_node(&sibling, &left_acc);
        }
        if right_path.get(idx).map(|e| e.dir) == Some(entry.dir) {
            left_below.push(RawPathEntry {
                dir: entry.dir,
                sibling: entry.sibling.clone(),
            });
        } else {
            left_below.push(RawPathEntry {
                dir: entry.dir,
                sibling: entry.sibling.clone(),
            });
            break;
        }
    }

    for (idx, entry) in right_path.iter().enumerate() {
        let sibling: [u8; 32] = entry
            .sibling
            .as_slice()
            .try_into()
            .map_err(|_| CityGError::InvalidInput("invalid path entry"))?;
        if entry.dir == 0 {
            right_acc = hash_node(&right_acc, &sibling);
        } else {
            right_acc = hash_node(&sibling, &right_acc);
        }
        if left_path.get(idx).map(|e| e.dir) == Some(entry.dir) {
            right_below.push(RawPathEntry {
                dir: entry.dir,
                sibling: entry.sibling.clone(),
            });
        } else {
            right_below.push(RawPathEntry {
                dir: entry.dir,
                sibling: entry.sibling.clone(),
            });
            break;
        }
    }

    let mut left_height = left_below.len() as u8;
    let mut right_height = right_below.len() as u8;

    while left_acc != parent_root && right_acc != parent_root {
        let left_step = left_path
            .get(left_height as usize)
            .ok_or(CityGError::InvalidInput("invalid left path height"))?;
        let right_step = right_path
            .get(right_height as usize)
            .ok_or(CityGError::InvalidInput("invalid right path height"))?;

        let left_sib: [u8; 32] = left_step
            .sibling
            .as_slice()
            .try_into()
            .map_err(|_| CityGError::InvalidInput("invalid path entry"))?;
        if left_step.dir == 0 {
            left_acc = hash_node(&left_acc, &left_sib);
        } else {
            left_acc = hash_node(&left_sib, &left_acc);
        }

        let right_sib: [u8; 32] = right_step
            .sibling
            .as_slice()
            .try_into()
            .map_err(|_| CityGError::InvalidInput("invalid path entry"))?;
        if right_step.dir == 0 {
            right_acc = hash_node(&right_acc, &right_sib);
        } else {
            right_acc = hash_node(&right_sib, &right_acc);
        }

        above.push(RawPathEntry {
            dir: left_step.dir,
            sibling: left_step.sibling.clone(),
        });
        left_height += 1;
        right_height += 1;
    }

    Ok((left_below, right_below, above, left_height, right_height))
}

/// Constant PoX commitment used by the demo flows.
pub fn demo_pox_commit() -> [u8; 32] {
    hash_leaf(b"demo-pox")
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use msphf_core::witness::{RawMembershipWitness, RawNonMembershipWitness};
    use std::borrow::Cow;

    #[test]
    fn witness_from_cbor_rejects_oversized_payload() {
        let oversized = vec![0u8; MAX_WITNESS_CBOR_BYTES + 1];
        let err = witness_from_cbor(&oversized).expect_err("oversized witness must fail");
        assert!(matches!(
            err,
            CityGError::InvalidInput("witness payload too large")
        ));
    }

    #[test]
    fn srx_inputs_owned_roundtrip_preserves_frontiers() {
        let owned = SrxInputsOwned {
            join_leaf_ids: vec![[0x11; 32]],
            join_nonmem_parent: vec![SrxNonMembershipAnchorOwned {
                witness: RawNonMembershipWitness {
                    query: vec![0x01; 32],
                    root: vec![0x02; 32],
                    left: None,
                    right: None,
                    path: vec![],
                    left_below: vec![],
                    right_below: vec![],
                    above: vec![],
                    nmint: None,
                    lca_left_height: None,
                    lca_right_height: None,
                },
                left_ref: Some(0),
                right_ref: None,
            }],
            join_nonmem_revoked_since: vec![],
            since_leaf_ids: vec![[0x22; 32]],
            since_mem_revoked: vec![RawMembershipWitness {
                leaf_id: vec![0xAA; 32],
                root: vec![0xBB; 32],
                path: vec![],
            }],
            anchor_mem_pool: vec![],
            join_frontier: Some(vec![[0x33; 32]]),
            since_frontier: Some(vec![[0x44; 32]]),
        };

        let borrowed = owned.clone().into_srx_inputs();
        let roundtrip = SrxInputsOwned::from(&borrowed);
        assert_eq!(roundtrip.join_leaf_ids, owned.join_leaf_ids);
        assert_eq!(roundtrip.since_leaf_ids, owned.since_leaf_ids);
        assert_eq!(roundtrip.join_frontier, owned.join_frontier);
        assert_eq!(roundtrip.since_frontier, owned.since_frontier);

        let explicit = SrxInputs {
            join_leaf_ids: Cow::Owned(vec![[0x51; 32]]),
            join_nonmem_parent: vec![],
            join_nonmem_revoked_since: vec![],
            since_leaf_ids: Cow::Owned(vec![[0x61; 32]]),
            since_mem_revoked: Cow::Owned(vec![]),
            anchor_mem_pool: vec![],
            join_frontier: Some(Cow::Owned(vec![[0x71; 32]])),
            since_frontier: Some(Cow::Owned(vec![[0x81; 32]])),
        };
        let explicit_owned = SrxInputsOwned::from(&explicit);
        assert_eq!(explicit_owned.join_frontier, Some(vec![[0x71; 32]]));
        assert_eq!(explicit_owned.since_frontier, Some(vec![[0x81; 32]]));
    }

    #[test]
    fn split_interval_paths_rejects_invalid_sibling_lengths() {
        let err = split_interval_paths(
            [0x10; 32],
            &[RawPathEntry {
                dir: 0,
                sibling: vec![0xAA; 31],
            }],
            [0x20; 32],
            &[RawPathEntry {
                dir: 0,
                sibling: vec![0xBB; 32],
            }],
            [0x30; 32],
        )
        .expect_err("invalid left sibling length must fail");
        assert!(err.to_string().contains("invalid path entry"));

        let err = split_interval_paths(
            [0x10; 32],
            &[RawPathEntry {
                dir: 0,
                sibling: vec![0xAA; 32],
            }],
            [0x20; 32],
            &[RawPathEntry {
                dir: 0,
                sibling: vec![0xBB; 31],
            }],
            [0x30; 32],
        )
        .expect_err("invalid right sibling length must fail");
        assert!(err.to_string().contains("invalid path entry"));
    }

    #[test]
    fn split_interval_paths_rejects_missing_height_steps() {
        let err = split_interval_paths([0x10; 32], &[], [0x20; 32], &[], [0x30; 32])
            .expect_err("missing left path step must fail");
        assert!(err.to_string().contains("invalid left path height"));

        let err = split_interval_paths(
            [0x10; 32],
            &[
                RawPathEntry {
                    dir: 0,
                    sibling: vec![0xAA; 32],
                },
                RawPathEntry {
                    dir: 0,
                    sibling: vec![0xAB; 32],
                },
                RawPathEntry {
                    dir: 0,
                    sibling: vec![0xAC; 32],
                },
            ],
            [0x20; 32],
            &[RawPathEntry {
                dir: 0,
                sibling: vec![0xBB; 32],
            }],
            [0x30; 32],
        )
        .expect_err("missing right path step must fail");
        assert!(err.to_string().contains("invalid right path height"));
    }

    #[test]
    fn split_interval_paths_rejects_invalid_upper_level_entries() {
        let err = split_interval_paths(
            [0x10; 32],
            &[
                RawPathEntry {
                    dir: 0,
                    sibling: vec![0xAA; 32],
                },
                RawPathEntry {
                    dir: 0,
                    sibling: vec![0xAB; 31],
                },
            ],
            [0x20; 32],
            &[
                RawPathEntry {
                    dir: 1,
                    sibling: vec![0xCC; 32],
                },
                RawPathEntry {
                    dir: 1,
                    sibling: vec![0xCD; 32],
                },
            ],
            [0x30; 32],
        )
        .expect_err("invalid left upper-level sibling must fail");
        assert!(err.to_string().contains("invalid path entry"));

        let err = split_interval_paths(
            [0x10; 32],
            &[
                RawPathEntry {
                    dir: 0,
                    sibling: vec![0xAA; 32],
                },
                RawPathEntry {
                    dir: 0,
                    sibling: vec![0xAB; 32],
                },
            ],
            [0x20; 32],
            &[
                RawPathEntry {
                    dir: 1,
                    sibling: vec![0xCC; 32],
                },
                RawPathEntry {
                    dir: 1,
                    sibling: vec![0xCD; 31],
                },
            ],
            [0x30; 32],
        )
        .expect_err("invalid right upper-level sibling must fail");
        assert!(err.to_string().contains("invalid path entry"));
    }

    #[test]
    fn build_srx_inputs_owned_rejects_revoked_root_mismatches() {
        let parent_leaves = vec![[0x10; 32]];
        let join_leaves = vec![[0x20; 32]];
        let parent_root = canonical_set_root(&parent_leaves).expect("parent root should compute");

        let revoked_since_leaves = vec![[0xA5; 32]];
        let revoked_since_root =
            canonical_set_root(&revoked_since_leaves).expect("revoked_since root should compute");
        let revoked_leaves = vec![[0xA5; 32], [0xB5; 32]];
        let wrong_revoked_root =
            canonical_set_root(&revoked_since_leaves).expect("single-leaf root should compute");

        let err = build_srx_inputs_owned(
            &join_leaves,
            &parent_leaves,
            parent_root,
            &revoked_since_leaves,
            revoked_since_root,
            &revoked_leaves,
            wrong_revoked_root,
        )
        .expect_err("mismatched revoked_root must fail");
        assert!(err.to_string().contains("revoked_root mismatch"));

        let err = build_srx_inputs_owned(
            &join_leaves,
            &parent_leaves,
            parent_root,
            &revoked_since_leaves,
            [0xFF; 32],
            &revoked_leaves,
            canonical_set_root(&revoked_leaves).expect("revoked root should compute"),
        )
        .expect_err("mismatched revoked_since_root must fail");
        assert!(err.to_string().contains("revoked_since_root mismatch"));
    }
}
