use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use ciborium::Value;
use hex::encode as hex_encode;
use msphf_orchestrator::hdr;

use crate::barrier::{
    BarrierHistoryCommitment, BarrierJoinSnapshotRecord, apply_join_set_to_snapshot,
    apply_revoked_set_to_snapshot, compute_barrier_tree_hash, encode_full_verification_receipt,
    encode_history_commitment_header, require_current_state_history_commitment,
    require_same_history_commitment,
};
use crate::barrier_build::{BarrierUpdateBuildResult, build_barrier_update_bytes};
use crate::barrier_update::normalize_max_barrier_update_bytes;

pub struct BarrierSnapshotArtifacts {
    pub header: BTreeMap<u64, Value>,
    pub barrier_update: BarrierUpdateBuildResult,
}

pub struct BarrierSnapshotArtifactsInput<'a> {
    pub header: BTreeMap<u64, Value>,
    pub gid: &'a [u8; 32],
    pub leaf_id: &'a [u8; 32],
    pub updater_leaf: u64,
    pub barrier_version: u64,
    pub barrier_update_reason: u64,
    pub barrier_n_max: u64,
    pub max_barrier_update_bytes: u64,
    pub ticket_history_commitment: &'a BarrierHistoryCommitment,
    pub snapshot_history_commitment: &'a BarrierHistoryCommitment,
    pub joins_history_commitment: &'a BarrierHistoryCommitment,
    pub revoked_history_commitment: &'a BarrierHistoryCommitment,
    pub current_global_history_attestation_bytes: &'a [u8],
    pub snapshot_pk_entries: &'a [Vec<u8>],
    pub join_records: &'a [BarrierJoinSnapshotRecord],
    pub witness_revoked_leaf_indices: &'a [u32],
    pub revocation_roots_hash: [u8; 32],
    pub pop_secret_key: &'a [u8],
}

pub fn prepare_barrier_snapshot_artifacts(
    input: BarrierSnapshotArtifactsInput<'_>,
) -> Result<BarrierSnapshotArtifacts> {
    let BarrierSnapshotArtifactsInput {
        mut header,
        gid,
        leaf_id,
        updater_leaf,
        barrier_version,
        barrier_update_reason,
        barrier_n_max,
        max_barrier_update_bytes,
        ticket_history_commitment,
        snapshot_history_commitment,
        joins_history_commitment,
        revoked_history_commitment,
        current_global_history_attestation_bytes,
        snapshot_pk_entries,
        join_records,
        witness_revoked_leaf_indices,
        revocation_roots_hash,
        pop_secret_key,
    } = input;

    if require_same_history_commitment(ticket_history_commitment, snapshot_history_commitment)
        .is_err()
    {
        return Err(anyhow!(
            "barrier merge ticket history commitment mismatch (960.9): ticket / current snapshot do not share one authenticated current-state commitment"
        ));
    }

    let history_commitment_header = encode_history_commitment_header(snapshot_history_commitment)?;
    header.insert(
        hdr::HDR_BARRIER_HISTORY_COMMITMENT,
        Value::Bytes(history_commitment_header.clone()),
    );
    if !current_global_history_attestation_bytes.is_empty() {
        header.insert(
            hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
            Value::Bytes(current_global_history_attestation_bytes.to_vec()),
        );
    }

    if require_current_state_history_commitment(
        snapshot_history_commitment,
        joins_history_commitment,
        revoked_history_commitment,
    )
    .is_err()
    {
        return Err(anyhow!(
            "barrier snapshot-auth history commitment mismatch (960.9): snapshot={}#{} joins={}#{} revoked={}#{}",
            hex_encode(snapshot_history_commitment.history_commitment_id),
            snapshot_history_commitment.history_seq,
            hex_encode(joins_history_commitment.history_commitment_id),
            joins_history_commitment.history_seq,
            hex_encode(revoked_history_commitment.history_commitment_id),
            revoked_history_commitment.history_seq,
        ));
    }

    let mut snapshot_pre = snapshot_pk_entries.to_vec();
    apply_join_set_to_snapshot(snapshot_pre.as_mut_slice(), barrier_n_max, join_records)?;
    apply_revoked_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        witness_revoked_leaf_indices,
    )?;

    let kem_tree_hash_before = compute_barrier_tree_hash(barrier_n_max, snapshot_pre.as_slice())?;
    let barrier_update = build_barrier_update_bytes(
        gid,
        barrier_n_max,
        updater_leaf,
        barrier_version.saturating_add(1),
        barrier_version,
        revocation_roots_hash,
        kem_tree_hash_before,
        snapshot_pre.as_slice(),
    )?;
    let max_barrier_update_bytes =
        normalize_max_barrier_update_bytes(max_barrier_update_bytes.max(1))?;
    if barrier_update.raw_update.len() > max_barrier_update_bytes {
        return Err(anyhow!(
            "barrier_update exceeds max_barrier_update_bytes: {} > {}",
            barrier_update.raw_update.len(),
            max_barrier_update_bytes
        ));
    }

    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(barrier_update.raw_update.clone()),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(ciborium::value::Integer::from(barrier_update_reason)),
    );

    if !current_global_history_attestation_bytes.is_empty() {
        let receipt = encode_full_verification_receipt(
            gid,
            leaf_id,
            barrier_update_reason,
            updater_leaf,
            history_commitment_header.as_slice(),
            current_global_history_attestation_bytes,
            barrier_update.raw_update.as_slice(),
            pop_secret_key,
        )?;
        header.insert(
            hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
            Value::Bytes(receipt),
        );
    }

    Ok(BarrierSnapshotArtifacts {
        header,
        barrier_update,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::barrier::{compute_revocation_roots_hash, expected_barrier_tree_nodes};
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::SecretKey;

    fn sample_commitment() -> BarrierHistoryCommitment {
        BarrierHistoryCommitment {
            history_view_id: [0x11; 32],
            history_commitment_id: [0x22; 32],
            prev_history_commitment_id: [0x33; 32],
            history_seq: 7,
        }
    }

    fn blank_snapshot(n_max: u64) -> Result<Vec<Vec<u8>>> {
        let tree_nodes = usize::try_from(expected_barrier_tree_nodes(n_max)?)
            .expect("expected tree size fits usize");
        Ok(vec![Vec::new(); tree_nodes])
    }

    #[test]
    fn prepare_barrier_snapshot_artifacts_builds_update_and_headers() -> Result<()> {
        let commitment = sample_commitment();
        let revocation_roots_hash = compute_revocation_roots_hash(&[0x44; 32], &[0x55; 32])?;
        let snapshot_entries = blank_snapshot(2)?;

        let prepared = prepare_barrier_snapshot_artifacts(BarrierSnapshotArtifactsInput {
            header: BTreeMap::new(),
            gid: &[0xAA; 32],
            leaf_id: &[0xBB; 32],
            updater_leaf: 0,
            barrier_version: 0,
            barrier_update_reason: 1,
            barrier_n_max: 2,
            max_barrier_update_bytes: 1_048_576,
            ticket_history_commitment: &commitment,
            snapshot_history_commitment: &commitment,
            joins_history_commitment: &commitment,
            revoked_history_commitment: &commitment,
            current_global_history_attestation_bytes: &[],
            snapshot_pk_entries: snapshot_entries.as_slice(),
            join_records: &[],
            witness_revoked_leaf_indices: &[],
            revocation_roots_hash,
            pop_secret_key: &[],
        })?;

        assert!(
            prepared
                .header
                .contains_key(&hdr::HDR_BARRIER_HISTORY_COMMITMENT)
        );
        assert!(prepared.header.contains_key(&hdr::HDR_BARRIER_UPDATE));
        assert_eq!(
            prepared.header.get(&hdr::HDR_BARRIER_UPDATE_REASON),
            Some(&Value::Integer(ciborium::value::Integer::from(1u64))),
        );
        assert!(
            !prepared
                .header
                .contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
        );
        assert!(!prepared.barrier_update.raw_update.is_empty());
        Ok(())
    }

    #[test]
    fn prepare_barrier_snapshot_artifacts_adds_receipt_for_attested_state() -> Result<()> {
        let commitment = sample_commitment();
        let revocation_roots_hash = compute_revocation_roots_hash(&[0x44; 32], &[0x55; 32])?;
        let (_, pop_secret_key) = dilithium5::keypair();
        let snapshot_entries = blank_snapshot(2)?;

        let prepared = prepare_barrier_snapshot_artifacts(BarrierSnapshotArtifactsInput {
            header: BTreeMap::new(),
            gid: &[0xAA; 32],
            leaf_id: &[0xBB; 32],
            updater_leaf: 0,
            barrier_version: 0,
            barrier_update_reason: 0,
            barrier_n_max: 2,
            max_barrier_update_bytes: 1_048_576,
            ticket_history_commitment: &commitment,
            snapshot_history_commitment: &commitment,
            joins_history_commitment: &commitment,
            revoked_history_commitment: &commitment,
            current_global_history_attestation_bytes: &[0xCC, 0xDD],
            snapshot_pk_entries: snapshot_entries.as_slice(),
            join_records: &[],
            witness_revoked_leaf_indices: &[],
            revocation_roots_hash,
            pop_secret_key: pop_secret_key.as_bytes(),
        })?;

        assert!(
            prepared
                .header
                .contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
        );
        Ok(())
    }
}
