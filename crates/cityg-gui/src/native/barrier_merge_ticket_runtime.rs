use super::*;
use cityg_api_client::{
    BarrierSnapshotPreparationRequest, HistoryAuthorityDescriptor, PrepareOriginMergeTicketInput,
};
use cityg_client::barrier_state_auth::{
    BarrierOriginGuard, BarrierOriginMode, ensure_full_barrier_verification_for_origin,
    guard_barrier_origin,
};

pub(super) struct PreparedBarrierMergeTicket {
    pub(super) persist_request: LeaveRequest,
    pub(super) client: CitygApiClient,
    pub(super) room_id: String,
    pub(super) gid: [u8; 32],
    pub(super) leaf_id: [u8; 32],
    pub(super) barrier_version: u64,
    pub(super) cover_leaf_index: u64,
    pub(super) snapshot_hash: [u8; 32],
    pub(super) barrier_n_max: u64,
    pub(super) max_barrier_update_bytes: u64,
    pub(super) forward_state: ForwardSecrecyState,
    pub(super) pop_public_key: Vec<u8>,
    pub(super) pop_secret_key: Vec<u8>,
    pub(super) vrf_secret_key: Vec<u8>,
    pub(super) vrf_public_key: Vec<u8>,
    pub(super) fs_ec: u64,
    pub(super) fs_epoch_commit: [u8; 32],
    pub(super) fs_dev_prev_commit: [u8; 32],
    pub(super) k_fs_current: [u8; 32],
    pub(super) fs_forward_leap_policy: FsForwardLeapPolicy,
    pub(super) last_accepted_ec: u64,
    pub(super) proof_mode: String,
    pub(super) vrf_id: String,
    pub(super) policy_version: String,
    pub(super) cat: [u8; 32],
    pub(super) parent_root: [u8; 32],
    pub(super) join_delta_root: [u8; 32],
    pub(super) revoked_since_root: [u8; 32],
    pub(super) revoked_root: [u8; 32],
    pub(super) tswe_salt_hash: [u8; 32],
    pub(super) pox_r_commit: [u8; 32],
    pub(super) msphf_crs_id: String,
    pub(super) msphf_params_id: String,
    pub(super) fs_policy_version: String,
    pub(super) fs_epoch_base_ts: u64,
    pub(super) header: BTreeMap<u64, Value>,
    pub(super) parities: Vec<PivotParity>,
    pub(super) witness_bytes: Option<Vec<u8>>,
    pub(super) ticket_history_commitment: HistoryCommitment,
    pub(super) ticket_history_authority_extension: Option<HistoryAuthorityExtension>,
    pub(super) history_authority: Option<HistoryAuthorityDescriptor>,
    pub(super) current_global_history_attestation_bytes: Vec<u8>,
    pub(super) merge_ticket_artifact_bytes: Vec<u8>,
    pub(super) deployment_profile_manifest_bytes: Vec<u8>,
}

impl PreparedBarrierMergeTicket {
    pub(super) fn snapshot_preparation_request<'a>(
        &'a self,
        pop_secret_key: &'a [u8],
        barrier_update_reason: u64,
        operation_label: &'a str,
    ) -> BarrierSnapshotPreparationRequest<'a> {
        BarrierSnapshotPreparationRequest {
            room_id: self.room_id.as_str(),
            gid: &self.gid,
            leaf_id: &self.leaf_id,
            barrier_version: self.barrier_version,
            cover_leaf_index: self.cover_leaf_index,
            snapshot_hash: self.snapshot_hash,
            barrier_n_max: self.barrier_n_max,
            max_barrier_update_bytes: self.max_barrier_update_bytes,
            header: self.header.clone(),
            parities: self.parities.as_slice(),
            cat: &self.cat,
            pox_r_commit: &self.pox_r_commit,
            parent_root: &self.parent_root,
            join_delta_root: &self.join_delta_root,
            revoked_since_root: &self.revoked_since_root,
            revoked_root: &self.revoked_root,
            tswe_salt_hash: &self.tswe_salt_hash,
            ticket_history_commitment: &self.ticket_history_commitment,
            ticket_history_authority_extension: self.ticket_history_authority_extension,
            history_authority: self.history_authority.clone(),
            current_global_history_attestation_bytes: self
                .current_global_history_attestation_bytes
                .as_slice(),
            merge_ticket_artifact_bytes: self.merge_ticket_artifact_bytes.as_slice(),
            deployment_profile_manifest_bytes: self.deployment_profile_manifest_bytes.as_slice(),
            pop_secret_key,
            full_verification_target_leaf_id: None,
            barrier_update_reason,
            operation_label,
        }
    }
}

pub(super) async fn prepare_barrier_merge_ticket(
    request: LeaveRequest,
    mode: BarrierMergeMode,
    allow_pending_recovery: bool,
) -> Result<PreparedBarrierMergeTicket> {
    let persist_request = request.clone();
    let LeaveRequest {
        server_url,
        room_id,
        gid,
        leaf_id,
        barrier_version: local_barrier_version,
        kem_tree_hash_after: local_kem_tree_hash_after,
        current_history_commitment: local_current_history_commitment,
        current_history_authority_extension: local_current_history_authority_extension,
        forward_state,
        pop_public_key,
        pop_secret_key,
        vrf_secret_key,
        vrf_public_key,
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        k_fs_current,
        max_barrier_update_bytes: stored_max_barrier_update_bytes,
        barrier_recovery_pending,
        mut current_barrier_full_verified,
        join_finalize_auth_token,
        ..
    } = request;

    let origin_guard = guard_barrier_origin(
        match mode {
            BarrierMergeMode::PcsRefresh => BarrierOriginMode::PcsRefresh,
            BarrierMergeMode::JoinFinalize => BarrierOriginMode::JoinFinalize,
        },
        barrier_recovery_pending,
        current_barrier_full_verified,
        allow_pending_recovery,
        join_finalize_auth_token != [0u8; 32],
    )?;
    if origin_guard == BarrierOriginGuard::RequiresBootstrapVerification {
        current_barrier_full_verified =
            ensure_join_finalize_bootstrap_verified(&persist_request).await?;
        ensure_full_barrier_verification_for_origin(false, current_barrier_full_verified)?;
    }

    let client = new_api_client(&server_url);
    let ticket = client
        .merge_ticket_refresh_with_retry(&room_id, &leaf_id)
        .await
        .context(format!("failed to obtain {} merge ticket", mode.label()))?;
    let prepared_origin = ticket
        .prepare_origin_runtime(PrepareOriginMergeTicketInput {
            operation_label: mode.label(),
            local_barrier_version,
            local_kem_tree_hash_after,
            local_current_history_commitment: local_current_history_commitment.as_ref(),
            local_current_history_authority_extension,
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
            stored_max_barrier_update_bytes,
            join_finalize_auth_token: (mode == BarrierMergeMode::JoinFinalize)
                .then_some(join_finalize_auth_token),
        })
        .map_err(anyhow::Error::from)?;
    let cityg_api_client::PreparedOriginMergeTicket {
        barrier_version,
        cover_leaf_index,
        snapshot_hash,
        barrier_n_max,
        max_barrier_update_bytes,
        proof_mode,
        vrf_id,
        policy_version,
        cat,
        parent_root,
        join_delta_root,
        revoked_since_root,
        revoked_root,
        tswe_salt_hash,
        pox_r_commit,
        msphf_crs_id,
        msphf_params_id,
        fs_policy_version,
        fs_epoch_base_ts,
        fs_forward_leap_policy,
        last_accepted_ec,
        header,
        parities,
        witness_bytes,
        ticket_history_commitment,
        ticket_history_authority_extension,
        history_authority,
        current_global_history_attestation_bytes,
        merge_ticket_artifact_bytes,
        deployment_profile_manifest_bytes,
    } = prepared_origin;

    Ok(PreparedBarrierMergeTicket {
        persist_request,
        client,
        room_id,
        gid,
        leaf_id,
        barrier_version,
        cover_leaf_index,
        snapshot_hash,
        barrier_n_max,
        max_barrier_update_bytes,
        forward_state,
        pop_public_key,
        pop_secret_key,
        vrf_secret_key,
        vrf_public_key,
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        k_fs_current,
        fs_forward_leap_policy: FsForwardLeapPolicy {
            h: fs_forward_leap_policy.h,
            checkpoint_interval: fs_forward_leap_policy.checkpoint_interval,
            slack_anchor: fs_forward_leap_policy.slack_anchor,
            slack_first_device: fs_forward_leap_policy.slack_first_device,
            slack_device: fs_forward_leap_policy.slack_device,
        },
        last_accepted_ec,
        proof_mode,
        vrf_id,
        policy_version,
        cat,
        parent_root,
        join_delta_root,
        revoked_since_root,
        revoked_root,
        tswe_salt_hash,
        pox_r_commit,
        msphf_crs_id,
        msphf_params_id,
        fs_policy_version,
        fs_epoch_base_ts,
        header,
        parities,
        witness_bytes,
        ticket_history_commitment,
        ticket_history_authority_extension,
        history_authority,
        current_global_history_attestation_bytes,
        merge_ticket_artifact_bytes,
        deployment_profile_manifest_bytes,
    })
}
