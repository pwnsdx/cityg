use super::barrier_merge_ticket_runtime::PreparedBarrierMergeTicket;
use super::*;
use cityg_api_client::{
    HistoryAuthorityDescriptor, to_core_history_commitment, to_core_join_snapshot_records,
};
use cityg_client::barrier_snapshot_prepare::{
    BarrierSnapshotArtifactsInput as CoreBarrierSnapshotArtifactsInput,
    BarrierSnapshotTicketFields as CoreBarrierSnapshotTicketFields,
    derive_barrier_snapshot_ticket_fields as derive_barrier_snapshot_ticket_fields_core,
    derive_barrier_snapshot_witness_selection as derive_barrier_snapshot_witness_selection_core,
    prepare_barrier_snapshot_artifacts as prepare_barrier_snapshot_artifacts_core,
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

pub(super) struct BarrierSnapshotRuntimeRequest<'a> {
    pub(super) client: &'a CitygApiClient,
    pub(super) room_id: &'a str,
    pub(super) gid: &'a [u8; 32],
    pub(super) leaf_id: &'a [u8; 32],
    pub(super) barrier_version: u64,
    pub(super) cover_leaf_index: u64,
    pub(super) snapshot_hash: [u8; 32],
    pub(super) barrier_n_max: u64,
    pub(super) max_barrier_update_bytes: u64,
    pub(super) header: BTreeMap<u64, Value>,
    pub(super) parities: &'a [PivotParity],
    pub(super) cat: &'a [u8],
    pub(super) pox_r_commit: &'a [u8],
    pub(super) parent_root: &'a [u8],
    pub(super) join_delta_root: &'a [u8],
    pub(super) revoked_since_root: &'a [u8],
    pub(super) revoked_root: &'a [u8],
    pub(super) tswe_salt_hash: &'a [u8],
    pub(super) ticket_history_commitment: &'a HistoryCommitment,
    pub(super) ticket_history_authority_extension: Option<HistoryAuthorityExtension>,
    pub(super) history_authority: Option<HistoryAuthorityDescriptor>,
    pub(super) current_global_history_attestation_bytes: &'a [u8],
    pub(super) merge_ticket_artifact_bytes: &'a [u8],
    pub(super) deployment_profile_manifest_bytes: &'a [u8],
    pub(super) pop_secret_key: &'a [u8],
    pub(super) full_verification_target_leaf_id: Option<[u8; 32]>,
}

pub(super) async fn prepare_barrier_merge_snapshot(
    ticket: &PreparedBarrierMergeTicket,
    mode: BarrierMergeMode,
) -> Result<PreparedBarrierMergeSnapshot> {
    prepare_barrier_snapshot_runtime(
        BarrierSnapshotRuntimeRequest {
            client: &ticket.client,
            room_id: ticket.room_id.as_str(),
            gid: &ticket.gid,
            leaf_id: &ticket.leaf_id,
            barrier_version: ticket.barrier_version,
            cover_leaf_index: ticket.cover_leaf_index,
            snapshot_hash: ticket.snapshot_hash,
            barrier_n_max: ticket.barrier_n_max,
            max_barrier_update_bytes: ticket.max_barrier_update_bytes,
            header: ticket.header.clone(),
            parities: &ticket.parities,
            cat: &ticket.cat,
            pox_r_commit: &ticket.pox_r_commit,
            parent_root: &ticket.parent_root,
            join_delta_root: &ticket.join_delta_root,
            revoked_since_root: &ticket.revoked_since_root,
            revoked_root: &ticket.revoked_root,
            tswe_salt_hash: &ticket.tswe_salt_hash,
            ticket_history_commitment: &ticket.ticket_history_commitment,
            ticket_history_authority_extension: ticket.ticket_history_authority_extension,
            history_authority: ticket.history_authority.clone(),
            current_global_history_attestation_bytes: ticket
                .current_global_history_attestation_bytes
                .as_slice(),
            merge_ticket_artifact_bytes: ticket.merge_ticket_artifact_bytes.as_slice(),
            deployment_profile_manifest_bytes: ticket.deployment_profile_manifest_bytes.as_slice(),
            pop_secret_key: ticket.pop_secret_key.as_slice(),
            full_verification_target_leaf_id: None,
        },
        mode.reason(),
        mode.label(),
    )
    .await
}

pub(super) async fn prepare_barrier_snapshot_runtime(
    request: BarrierSnapshotRuntimeRequest<'_>,
    barrier_update_reason: u64,
    operation_label: &str,
) -> Result<PreparedBarrierMergeSnapshot> {
    let BarrierSnapshotRuntimeRequest {
        client,
        room_id,
        gid,
        leaf_id,
        barrier_version,
        cover_leaf_index,
        snapshot_hash,
        barrier_n_max,
        max_barrier_update_bytes,
        header,
        parities,
        cat,
        pox_r_commit,
        parent_root,
        join_delta_root,
        revoked_since_root,
        revoked_root,
        tswe_salt_hash,
        ticket_history_commitment,
        ticket_history_authority_extension,
        history_authority,
        current_global_history_attestation_bytes,
        merge_ticket_artifact_bytes,
        deployment_profile_manifest_bytes,
        pop_secret_key,
        full_verification_target_leaf_id,
    } = request;

    let CoreBarrierSnapshotTicketFields {
        cat: cat_arr,
        pox_r_commit: pox_r_commit_arr,
        pivot,
        parent_root: parent_root_arr,
        join_delta_root: join_delta_root_arr,
        revoked_since_root: revoked_since_root_arr,
        revoked_root: revoked_root_arr,
        tswe_salt_hash: tswe_salt_hash_arr,
        revocation_roots_hash,
        committed_revocation_roots_hash,
    } = derive_barrier_snapshot_ticket_fields_core(
        parities,
        cat,
        pox_r_commit,
        parent_root,
        join_delta_root,
        revoked_since_root,
        revoked_root,
        tswe_salt_hash,
    )?;

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
    let join_resolution = client
        .barrier_resolve_joins_since(room_id, barrier_version)
        .await
        .context("resolve barrier joins since previous version")?;
    let revoked_resolution = client
        .barrier_resolve_revoked_leaves(room_id, &committed_revocation_roots_hash)
        .await
        .context("resolve committed barrier revoked leaf indices")?;
    let witness_selection = derive_barrier_snapshot_witness_selection_core(
        barrier_update_reason,
        cover_leaf_index,
        revoked_resolution.leaf_indices.as_slice(),
        revocation_roots_hash,
        committed_revocation_roots_hash,
    )?;
    let ticket_history_commitment_core = to_core_history_commitment(ticket_history_commitment);
    let snapshot_history_commitment_core =
        to_core_history_commitment(&barrier_tree_response.history_commitment);
    let joins_history_commitment_core =
        to_core_history_commitment(&join_resolution.history_commitment);
    let revoked_history_commitment_core =
        to_core_history_commitment(&revoked_resolution.history_commitment);
    let join_records_core = to_core_join_snapshot_records(join_resolution.records.as_slice());
    let prepared_snapshot =
        prepare_barrier_snapshot_artifacts_core(CoreBarrierSnapshotArtifactsInput {
            header,
            gid,
            leaf_id,
            updater_leaf: cover_leaf_index,
            barrier_version,
            barrier_update_reason,
            barrier_n_max,
            max_barrier_update_bytes,
            ticket_history_commitment: &ticket_history_commitment_core,
            snapshot_history_commitment: &snapshot_history_commitment_core,
            joins_history_commitment: &joins_history_commitment_core,
            revoked_history_commitment: &revoked_history_commitment_core,
            current_global_history_attestation_bytes,
            snapshot_pk_entries: barrier_tree_snapshot.pk_entries.as_slice(),
            join_records: join_records_core.as_slice(),
            witness_revoked_leaf_indices: witness_selection.witness_revoked_leaf_indices.as_slice(),
            revocation_roots_hash,
            pop_secret_key,
        })?;
    let mut header = prepared_snapshot.header;
    let barrier_update =
        BarrierUpdateBuildResult::from_core(barrier_n_max, prepared_snapshot.barrier_update);
    if !current_global_history_attestation_bytes.is_empty()
        && (barrier_update_reason == 0 || barrier_update_reason == 1)
    {
        let history_authority = history_authority.as_ref().ok_or_else(|| {
            anyhow!(
                "{operation_label} merge ticket missing history_authority descriptor for full verification witness"
            )
        })?;
        let history_authority_extension = ticket_history_authority_extension.ok_or_else(|| {
            anyhow!(
                "{operation_label} merge ticket missing history_authority_extension for full verification witness"
            )
        })?;
        let full_verification_witness = client
            .barrier_issue_full_verification_witness(
                room_id,
                leaf_id,
                full_verification_target_leaf_id.as_ref(),
                merge_ticket_artifact_bytes,
                barrier_update_reason,
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
                &witness_selection.witness_revocation_roots_hash,
                witness_selection.witness_revoked_leaf_indices.as_slice(),
                deployment_profile_manifest_bytes,
            )
            .await
            .with_context(|| format!("issue full verification witness for {operation_label}"))?;
        header.insert(
            hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS,
            Value::Bytes(full_verification_witness),
        );
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
