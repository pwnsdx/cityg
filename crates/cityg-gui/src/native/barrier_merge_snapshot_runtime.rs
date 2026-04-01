use super::barrier_merge_ticket_runtime::PreparedBarrierMergeTicket;
use super::*;
use crate::barrier_shared::{
    encode_full_verification_receipt, encode_history_commitment_header,
    require_current_state_history_commitment, require_same_history_commitment,
};

pub(super) struct PreparedBarrierMergeSnapshot {
    pub(super) header: BTreeMap<u64, Value>,
    pub(super) cat_arr: [u8; 32],
    pub(super) parent_root_arr: [u8; 32],
    pub(super) join_delta_root_arr: [u8; 32],
    pub(super) revoked_since_root_arr: [u8; 32],
    pub(super) revoked_root_arr: [u8; 32],
    pub(super) tswe_salt_hash_arr: [u8; 32],
    pub(super) pox_r_commit_arr: [u8; 32],
    pub(super) pivot: PivotParity,
    pub(super) snapshot_hash: [u8; 32],
    pub(super) committed_revocation_roots_hash: [u8; 32],
    pub(super) revocation_roots_hash: [u8; 32],
    pub(super) barrier_update: BarrierUpdateBuildResult,
}

pub(super) async fn prepare_barrier_merge_snapshot(
    ticket: &PreparedBarrierMergeTicket,
    mode: BarrierMergeMode,
) -> Result<PreparedBarrierMergeSnapshot> {
    let client = &ticket.client;
    let room_id = ticket.room_id.as_str();
    let gid = &ticket.gid;
    let leaf_id = &ticket.leaf_id;
    let barrier_version = ticket.barrier_version;
    let cover_leaf_index = ticket.cover_leaf_index;
    let snapshot_hash = ticket.snapshot_hash;
    let barrier_n_max = ticket.barrier_n_max;
    let ticket_history_commitment = &ticket.ticket_history_commitment;
    let current_global_history_attestation_bytes =
        ticket.current_global_history_attestation_bytes.as_slice();

    let cat_arr = bytes32("cat", &ticket.cat)?;
    let pox_r_commit_arr = bytes32("pox_r_commit", &ticket.pox_r_commit)?;
    let pivot = select_pivot_parity(&ticket.parities)
        .ok_or_else(|| anyhow!("merge ticket did not include any pivot parities"))?
        .clone();
    let parent_root_arr = bytes32("parent_root", &ticket.parent_root)?;
    let join_delta_root_arr = bytes32("join_delta_root", &ticket.join_delta_root)?;
    let revoked_since_root_arr = bytes32("revoked_since_root", &ticket.revoked_since_root)?;
    let revoked_root_arr = bytes32("revoked_root", &ticket.revoked_root)?;
    let tswe_salt_hash_arr = bytes32("tswe_salt_hash", &ticket.tswe_salt_hash)?;
    let revocation_roots_hash =
        compute_revocation_roots_hash(&revoked_since_root_arr, &revoked_root_arr)?;
    let committed_revocation_roots_hash =
        compute_revocation_roots_hash(&pivot.revoked_since_root, &pivot.revoked_root)?;
    let mut header = ticket.header.clone();

    let barrier_tree_response = client
        .barrier_fetch_public_tree(room_id, &snapshot_hash)
        .await
        .context("fetch barrier public tree snapshot")?;
    let barrier_tree_snapshot = barrier_tree_response.tree;
    if barrier_tree_snapshot.n_max != barrier_n_max {
        return Err(anyhow!(
            "barrier tree snapshot n_max mismatch: expected {barrier_n_max}, got {}",
            barrier_tree_snapshot.n_max
        ));
    }
    validate_barrier_tree_snapshot_auth(&snapshot_hash, barrier_n_max, &barrier_tree_snapshot)?;
    if require_same_history_commitment(
        &ticket_history_commitment,
        &barrier_tree_response.history_commitment,
    )
    .is_err()
    {
        return Err(anyhow!(
            "barrier merge ticket history commitment mismatch (960.9): ticket / current snapshot do not share one authenticated current-state commitment"
        ));
    }
    let history_commitment_header =
        encode_history_commitment_header(&barrier_tree_response.history_commitment)?;
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
    let join_resolution = client
        .barrier_resolve_joins_since(room_id, barrier_version)
        .await
        .context("resolve barrier joins since previous version")?;
    let revoked_resolution = client
        .barrier_resolve_revoked_leaves(room_id, &committed_revocation_roots_hash)
        .await
        .context("resolve committed barrier revoked leaf indices")?;
    if require_current_state_history_commitment(
        &barrier_tree_response.history_commitment,
        &join_resolution.history_commitment,
        &revoked_resolution.history_commitment,
    )
    .is_err()
    {
        return Err(anyhow!(
            "barrier snapshot-auth history commitment mismatch (960.9): snapshot={}#{} joins={}#{} revoked={}#{}",
            hex_encode(
                barrier_tree_response
                    .history_commitment
                    .history_commitment_id
            ),
            barrier_tree_response.history_commitment.history_seq,
            hex_encode(join_resolution.history_commitment.history_commitment_id),
            join_resolution.history_commitment.history_seq,
            hex_encode(revoked_resolution.history_commitment.history_commitment_id),
            revoked_resolution.history_commitment.history_seq,
        ));
    }
    let mut snapshot_pre = barrier_tree_snapshot.pk_entries.clone();
    apply_join_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        join_resolution.records.as_slice(),
    )?;
    let mut witness_revoked_leaf_indices = revoked_resolution.leaf_indices.clone();
    let witness_revocation_roots_hash = if mode.reason() == 0 {
        let cover_leaf_index_u32 = u32::try_from(cover_leaf_index)
            .map_err(|_| anyhow!("cover_leaf_index out of range"))?;
        if let Err(insert_at) = witness_revoked_leaf_indices.binary_search(&cover_leaf_index_u32) {
            witness_revoked_leaf_indices.insert(insert_at, cover_leaf_index_u32);
        }
        revocation_roots_hash
    } else {
        committed_revocation_roots_hash
    };
    apply_revoked_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        witness_revoked_leaf_indices.as_slice(),
    )?;
    let kem_tree_hash_before = compute_barrier_tree_hash(barrier_n_max, snapshot_pre.as_slice())?;
    let next_barrier_version = barrier_version.saturating_add(1);
    let barrier_update = build_barrier_update_bytes(
        gid,
        barrier_n_max,
        cover_leaf_index,
        next_barrier_version,
        barrier_version,
        revocation_roots_hash,
        kem_tree_hash_before,
        snapshot_pre.as_slice(),
    )?;
    let ticket_max_barrier_update_bytes = ticket.max_barrier_update_bytes.max(1);
    let max_barrier_update_bytes =
        normalize_max_barrier_update_bytes(ticket_max_barrier_update_bytes)?;
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
        Value::Integer(Integer::from(mode.reason())),
    );
    if !current_global_history_attestation_bytes.is_empty() {
        let receipt = encode_full_verification_receipt(
            gid,
            leaf_id,
            mode.reason(),
            cover_leaf_index,
            history_commitment_header.as_slice(),
            current_global_history_attestation_bytes,
            barrier_update.raw_update.as_slice(),
            ticket.pop_secret_key.as_slice(),
        )?;
        header.insert(
            hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
            Value::Bytes(receipt),
        );
        if mode.reason() == 0 || mode.reason() == 1 {
            let history_authority = ticket.history_authority.as_ref().ok_or_else(|| {
                anyhow!(
                    "{} merge ticket missing history_authority descriptor for full verification witness",
                    mode.label()
                )
            })?;
            let history_authority_extension =
                ticket
                    .ticket_history_authority_extension
                    .clone()
                    .ok_or_else(|| {
                    anyhow!(
                        "{} merge ticket missing history_authority_extension for full verification witness",
                        mode.label()
                    )
                })?;
            let full_verification_witness = client
                .barrier_issue_full_verification_witness(
                    room_id,
                    leaf_id,
                    None,
                    ticket.merge_ticket_artifact_bytes.as_slice(),
                    mode.reason(),
                    barrier_update.raw_update.as_slice(),
                    barrier_n_max,
                    ticket_history_commitment,
                    history_authority_extension,
                    history_authority,
                    current_global_history_attestation_bytes,
                    barrier_version,
                    &snapshot_hash,
                    barrier_version,
                    join_resolution.records.as_slice(),
                    &witness_revocation_roots_hash,
                    witness_revoked_leaf_indices.as_slice(),
                    ticket.deployment_profile_manifest_bytes.as_slice(),
                )
                .await
                .with_context(|| format!("issue full verification witness for {}", mode.label()))?;
            header.insert(
                hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS,
                Value::Bytes(full_verification_witness),
            );
        }
    }

    Ok(PreparedBarrierMergeSnapshot {
        header,
        cat_arr,
        parent_root_arr,
        join_delta_root_arr,
        revoked_since_root_arr,
        revoked_root_arr,
        tswe_salt_hash_arr,
        pox_r_commit_arr,
        pivot,
        snapshot_hash,
        committed_revocation_roots_hash,
        revocation_roots_hash,
        barrier_update,
    })
}
