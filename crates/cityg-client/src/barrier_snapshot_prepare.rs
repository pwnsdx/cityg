use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use ciborium::Value;
use hex::encode as hex_encode;
use msphf_orchestrator::{PivotParity, hdr};

use crate::barrier::{
    BarrierHistoryCommitment, BarrierJoinSnapshotRecord, BarrierRevokedSnapshotRecord,
    BarrierSlotLease, apply_join_set_to_snapshot, apply_revoked_records_to_snapshot,
    compute_barrier_tree_hash, compute_revocation_roots_hash, encode_full_verification_receipt,
    encode_history_commitment_header, require_current_state_history_commitment,
    require_same_history_commitment, revoked_leaf_indices_from_records,
};
use crate::barrier_build::{BarrierUpdateBuildResult, build_barrier_update_bytes};
use crate::barrier_update::normalize_max_barrier_update_bytes;
use crate::binary::bytes32;
use crate::pivot::select_pivot_parity;

pub struct BarrierSnapshotTicketFields {
    pub cat: [u8; 32],
    pub pox_r_commit: [u8; 32],
    pub pivot: PivotParity,
    pub parent_root: [u8; 32],
    pub join_delta_root: [u8; 32],
    pub revoked_since_root: [u8; 32],
    pub revoked_root: [u8; 32],
    pub tswe_salt_hash: [u8; 32],
    pub revocation_roots_hash: [u8; 32],
    pub committed_revocation_roots_hash: [u8; 32],
}

pub struct BarrierSnapshotWitnessSelection {
    pub witness_revoked_records: Vec<BarrierRevokedSnapshotRecord>,
    pub witness_revoked_leaf_indices: Vec<u32>,
    pub witness_revocation_roots_hash: [u8; 32],
}

pub struct BarrierSnapshotArtifacts {
    pub header: BTreeMap<u64, Value>,
    pub barrier_update: BarrierUpdateBuildResult,
}

pub struct BarrierSnapshotArtifactsInput<'a> {
    pub header: BTreeMap<u64, Value>,
    pub gid: &'a [u8; 32],
    pub leaf_id: &'a [u8; 32],
    pub updater_slot_lease: BarrierSlotLease,
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
    pub witness_revoked_records: &'a [BarrierRevokedSnapshotRecord],
    pub revocation_roots_hash: [u8; 32],
    pub pop_secret_key: &'a [u8],
}

#[allow(clippy::too_many_arguments)]
pub fn derive_barrier_snapshot_ticket_fields(
    parities: &[PivotParity],
    cat: &[u8],
    pox_r_commit: &[u8],
    parent_root: &[u8],
    join_delta_root: &[u8],
    revoked_since_root: &[u8],
    revoked_root: &[u8],
    tswe_salt_hash: &[u8],
) -> Result<BarrierSnapshotTicketFields> {
    let pivot = select_pivot_parity(parities)
        .ok_or_else(|| anyhow!("merge ticket did not include any pivot parities"))?
        .clone();
    let cat = bytes32("cat", cat)?;
    let pox_r_commit = bytes32("pox_r_commit", pox_r_commit)?;
    let parent_root = bytes32("parent_root", parent_root)?;
    let join_delta_root = bytes32("join_delta_root", join_delta_root)?;
    let revoked_since_root = bytes32("revoked_since_root", revoked_since_root)?;
    let revoked_root = bytes32("revoked_root", revoked_root)?;
    let tswe_salt_hash = bytes32("tswe_salt_hash", tswe_salt_hash)?;
    let revocation_roots_hash = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    let committed_revocation_roots_hash =
        compute_revocation_roots_hash(&pivot.revoked_since_root, &pivot.revoked_root)?;
    Ok(BarrierSnapshotTicketFields {
        cat,
        pox_r_commit,
        pivot,
        parent_root,
        join_delta_root,
        revoked_since_root,
        revoked_root,
        tswe_salt_hash,
        revocation_roots_hash,
        committed_revocation_roots_hash,
    })
}

pub fn derive_barrier_snapshot_witness_selection(
    barrier_update_reason: u64,
    updater_slot_lease: BarrierSlotLease,
    resolved_revoked_records: &[BarrierRevokedSnapshotRecord],
    revocation_roots_hash: [u8; 32],
    committed_revocation_roots_hash: [u8; 32],
    include_updater_in_revoked_set: bool,
) -> Result<BarrierSnapshotWitnessSelection> {
    let mut witness_revoked_records = resolved_revoked_records.to_vec();
    let witness_revocation_roots_hash = if barrier_update_reason == 0 {
        if include_updater_in_revoked_set {
            let updater_leaf = u32::try_from(updater_slot_lease.slot_index)
                .map_err(|_| anyhow!("slot_index out of range"))?;
            witness_revoked_records.push(BarrierRevokedSnapshotRecord {
                leaf_index: updater_leaf,
                slot_generation: updater_slot_lease.slot_generation,
            });
        }
        revocation_roots_hash
    } else {
        committed_revocation_roots_hash
    };
    witness_revoked_records.sort_by_key(|record| (record.leaf_index, record.slot_generation));
    witness_revoked_records.dedup();
    Ok(BarrierSnapshotWitnessSelection {
        witness_revoked_records: witness_revoked_records.clone(),
        witness_revoked_leaf_indices: revoked_leaf_indices_from_records(
            witness_revoked_records.as_slice(),
        ),
        witness_revocation_roots_hash,
    })
}

pub fn prepare_barrier_snapshot_artifacts(
    input: BarrierSnapshotArtifactsInput<'_>,
) -> Result<BarrierSnapshotArtifacts> {
    let BarrierSnapshotArtifactsInput {
        mut header,
        gid,
        leaf_id,
        updater_slot_lease,
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
        witness_revoked_records,
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
    apply_revoked_records_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        witness_revoked_records,
    )?;

    let kem_tree_hash_before = compute_barrier_tree_hash(barrier_n_max, snapshot_pre.as_slice())?;
    let barrier_update = build_barrier_update_bytes(
        gid,
        barrier_n_max,
        updater_slot_lease.slot_index,
        updater_slot_lease.slot_generation,
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
            updater_slot_lease.slot_index,
            updater_slot_lease.slot_generation,
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
    use crate::barrier::expected_barrier_tree_nodes;
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::SecretKey;
    use std::sync::Arc;

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

    fn sample_pivot_parity() -> PivotParity {
        PivotParity {
            gid: vec![0x11; 32],
            cat: vec![0x22; 32],
            parent_root: [0x33; 32],
            we_epoch_id: [0x44; 32],
            rho_commit: [0x45; 32],
            seed_ctx_hash: [0x46; 32],
            seed_commit: [0x47; 32],
            hp_commit: [0x48; 32],
            xk_hash: [0x49; 32],
            join_delta_root: [0x4A; 32],
            revoked_since_root: [0x4B; 32],
            revoked_root: [0x4C; 32],
            accept_seq: 7,
            crs_id: vec![0x4D],
            params_id: vec![0x4E],
            policy_version: "9".to_string(),
            proof_mode: "lin+zkvrf".to_string(),
            vrf_id: "lb-vrf/mock".to_string(),
            vrf_proof: vec![0x4F],
            vrf_public: vec![0x50],
            mask_a: [0x51; 32],
            mask_b: [0x52; 32],
            fs_capss: vec![0x53],
            proofs_commit: [0x54; 32],
            srx_commit: Some([0x55; 32]),
            srx_root_sw: Some([0x56; 32]),
            is_join: false,
            hp_envelope: Arc::from(vec![0x57]),
            fs_epoch_commit: Some([0x58; 32]),
            fs_ec: Some(59),
            fs_dev_commit: Some([0x5A; 32]),
        }
    }

    #[test]
    fn derive_ticket_fields_and_witness_selection_cover_revocation_reason() -> Result<()> {
        let fields = derive_barrier_snapshot_ticket_fields(
            &[sample_pivot_parity()],
            &[0xAA; 32],
            &[0xBB; 32],
            &[0xCC; 32],
            &[0xDD; 32],
            &[0xEE; 32],
            &[0xEF; 32],
            &[0xF0; 32],
        )?;
        assert_eq!(fields.cat, [0xAA; 32]);
        let selection = derive_barrier_snapshot_witness_selection(
            0,
            BarrierSlotLease {
                slot_index: 4,
                slot_generation: 9,
            },
            &[
                BarrierRevokedSnapshotRecord {
                    leaf_index: 1,
                    slot_generation: 0,
                },
                BarrierRevokedSnapshotRecord {
                    leaf_index: 7,
                    slot_generation: 2,
                },
            ],
            fields.revocation_roots_hash,
            fields.committed_revocation_roots_hash,
            true,
        )?;
        assert_eq!(
            selection.witness_revoked_records,
            vec![
                BarrierRevokedSnapshotRecord {
                    leaf_index: 1,
                    slot_generation: 0,
                },
                BarrierRevokedSnapshotRecord {
                    leaf_index: 4,
                    slot_generation: 9,
                },
                BarrierRevokedSnapshotRecord {
                    leaf_index: 7,
                    slot_generation: 2,
                },
            ]
        );
        assert_eq!(selection.witness_revoked_leaf_indices, vec![1, 4, 7]);
        assert_eq!(
            selection.witness_revocation_roots_hash,
            fields.revocation_roots_hash
        );
        Ok(())
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
            updater_slot_lease: BarrierSlotLease {
                slot_index: 0,
                slot_generation: 0,
            },
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
            witness_revoked_records: &[],
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
    fn derive_barrier_snapshot_witness_selection_skips_updater_for_reclaim_join() -> Result<()> {
        let selection = derive_barrier_snapshot_witness_selection(
            0,
            BarrierSlotLease {
                slot_index: 4,
                slot_generation: 3,
            },
            &[
                BarrierRevokedSnapshotRecord {
                    leaf_index: 1,
                    slot_generation: 0,
                },
                BarrierRevokedSnapshotRecord {
                    leaf_index: 4,
                    slot_generation: 1,
                },
                BarrierRevokedSnapshotRecord {
                    leaf_index: 7,
                    slot_generation: 2,
                },
            ],
            [0x44; 32],
            [0x55; 32],
            false,
        )?;
        assert_eq!(
            selection.witness_revoked_records,
            vec![
                BarrierRevokedSnapshotRecord {
                    leaf_index: 1,
                    slot_generation: 0,
                },
                BarrierRevokedSnapshotRecord {
                    leaf_index: 4,
                    slot_generation: 1,
                },
                BarrierRevokedSnapshotRecord {
                    leaf_index: 7,
                    slot_generation: 2,
                },
            ]
        );
        assert_eq!(selection.witness_revoked_leaf_indices, vec![1, 4, 7]);
        assert_eq!(selection.witness_revocation_roots_hash, [0x44; 32]);
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
            updater_slot_lease: BarrierSlotLease {
                slot_index: 0,
                slot_generation: 0,
            },
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
            witness_revoked_records: &[],
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
