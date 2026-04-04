use anyhow::{Result, anyhow};

use crate::barrier::{
    BarrierJoinSnapshotRecord, BarrierRevokedSnapshotRecord, apply_join_set_to_snapshot,
    apply_revoked_records_to_snapshot, compute_barrier_tree_hash,
};
use crate::barrier_update::ParsedBarrierUpdate;

#[derive(Clone, Debug)]
pub struct BarrierSnapshotTransition {
    pub expected_before: [u8; 32],
    pub expected_after: [u8; 32],
    pub snapshot_post_entries: Vec<Vec<u8>>,
}

pub fn compute_barrier_snapshot_transition(
    n_max: u64,
    snapshot_base_entries: &[Vec<u8>],
    join_records: &[BarrierJoinSnapshotRecord],
    revoked_records: &[BarrierRevokedSnapshotRecord],
    parsed_update: &ParsedBarrierUpdate,
) -> Result<BarrierSnapshotTransition> {
    let mut snapshot_pre = snapshot_base_entries.to_vec();
    apply_join_set_to_snapshot(snapshot_pre.as_mut_slice(), n_max, join_records)?;
    apply_revoked_records_to_snapshot(snapshot_pre.as_mut_slice(), n_max, revoked_records)?;
    let expected_before = compute_barrier_tree_hash(n_max, snapshot_pre.as_slice())?;

    let mut snapshot_post = snapshot_pre;
    for (node, ek) in &parsed_update.new_public_keys {
        let index =
            usize::try_from(*node).map_err(|_| anyhow!("barrier node index out of range"))?;
        let slot = snapshot_post
            .get_mut(index)
            .ok_or_else(|| anyhow!("barrier node index out of range"))?;
        *slot = ek.clone();
    }
    let expected_after = compute_barrier_tree_hash(n_max, snapshot_post.as_slice())?;

    Ok(BarrierSnapshotTransition {
        expected_before,
        expected_after,
        snapshot_post_entries: snapshot_post,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::barrier::{expected_barrier_tree_nodes, revoked_leaf_indices_from_records};
    use pqcrypto_kyber::kyber768;

    #[test]
    fn compute_barrier_snapshot_transition_applies_join_and_public_key_updates() -> Result<()> {
        let n_max = 4;
        let blank_len =
            usize::try_from(expected_barrier_tree_nodes(n_max)?).expect("tree size fits usize");
        let snapshot_base_entries = vec![Vec::new(); blank_len];
        let join_records = vec![BarrierJoinSnapshotRecord {
            leaf_index: 1,
            slot_generation: 0,
            ek_leaf: vec![0x11; kyber768::public_key_bytes()],
        }];
        let internal_pk = vec![0x22; kyber768::public_key_bytes()];
        let parsed_update = ParsedBarrierUpdate {
            barrier_version: 1,
            prev_barrier_version: 0,
            tree_size: n_max,
            revocation_roots_hash: [0u8; 32],
            kem_tree_hash_before: [0u8; 32],
            kem_tree_hash_after: [0u8; 32],
            updater_leaf: 0,
            updater_slot_generation: 0,
            path_nodes: vec![3, 1, 0],
            node_ciphertexts: Vec::new(),
            new_public_keys: BTreeMap::from([(1u64, internal_pk.clone())]),
        };

        let transition = compute_barrier_snapshot_transition(
            n_max,
            snapshot_base_entries.as_slice(),
            join_records.as_slice(),
            &[],
            &parsed_update,
        )?;

        let mut expected_snapshot_pre = snapshot_base_entries;
        apply_join_set_to_snapshot(
            expected_snapshot_pre.as_mut_slice(),
            n_max,
            join_records.as_slice(),
        )?;
        apply_revoked_records_to_snapshot(expected_snapshot_pre.as_mut_slice(), n_max, &[])?;
        let expected_before = compute_barrier_tree_hash(n_max, expected_snapshot_pre.as_slice())?;

        let mut expected_snapshot_post = expected_snapshot_pre;
        expected_snapshot_post[1] = internal_pk;
        let expected_after = compute_barrier_tree_hash(n_max, expected_snapshot_post.as_slice())?;

        assert_eq!(transition.expected_before, expected_before);
        assert_eq!(transition.expected_after, expected_after);
        assert_eq!(transition.snapshot_post_entries, expected_snapshot_post);
        Ok(())
    }

    #[test]
    fn compute_barrier_snapshot_transition_applies_versioned_revocations() -> Result<()> {
        let n_max = 4;
        let blank_len =
            usize::try_from(expected_barrier_tree_nodes(n_max)?).expect("tree size fits usize");
        let snapshot_base_entries = vec![Vec::new(); blank_len];
        let revoked_records = vec![
            BarrierRevokedSnapshotRecord {
                leaf_index: 2,
                slot_generation: 0,
            },
            BarrierRevokedSnapshotRecord {
                leaf_index: 2,
                slot_generation: 4,
            },
        ];
        let parsed_update = ParsedBarrierUpdate {
            barrier_version: 1,
            prev_barrier_version: 0,
            tree_size: n_max,
            revocation_roots_hash: [0u8; 32],
            kem_tree_hash_before: [0u8; 32],
            kem_tree_hash_after: [0u8; 32],
            updater_leaf: 0,
            updater_slot_generation: 0,
            path_nodes: vec![3, 1, 0],
            node_ciphertexts: Vec::new(),
            new_public_keys: BTreeMap::new(),
        };

        let transition = compute_barrier_snapshot_transition(
            n_max,
            snapshot_base_entries.as_slice(),
            &[],
            revoked_records.as_slice(),
            &parsed_update,
        )?;
        let mut expected_snapshot_pre = snapshot_base_entries;
        apply_revoked_records_to_snapshot(
            expected_snapshot_pre.as_mut_slice(),
            n_max,
            revoked_records.as_slice(),
        )?;
        let expected_before = compute_barrier_tree_hash(n_max, expected_snapshot_pre.as_slice())?;

        assert_eq!(
            revoked_leaf_indices_from_records(revoked_records.as_slice()),
            vec![2]
        );
        assert_eq!(transition.expected_before, expected_before);
        assert_eq!(transition.expected_after, expected_before);
        Ok(())
    }
}
