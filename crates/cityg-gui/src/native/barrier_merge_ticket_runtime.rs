use super::*;
use cityg_api_client::{PrepareOriginMergeTicketInput, PreparedOriginMergeTicket};
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
    pub(super) prepared_origin: PreparedOriginMergeTicket,
}

impl PreparedBarrierMergeTicket {
    pub(super) fn snapshot_preparation_request<'a>(
        &'a self,
        pop_secret_key: &'a [u8],
        barrier_update_reason: u64,
        operation_label: &'a str,
    ) -> cityg_api_client::BarrierSnapshotPreparationRequest<'a> {
        self.prepared_origin.snapshot_preparation_request(
            self.room_id.as_str(),
            &self.gid,
            &self.leaf_id,
            pop_secret_key,
            barrier_update_reason,
            operation_label,
        )
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
    let fs_forward_leap_policy = FsForwardLeapPolicy {
        h: prepared_origin.fs_forward_leap_policy.h,
        checkpoint_interval: prepared_origin.fs_forward_leap_policy.checkpoint_interval,
        slack_anchor: prepared_origin.fs_forward_leap_policy.slack_anchor,
        slack_first_device: prepared_origin.fs_forward_leap_policy.slack_first_device,
        slack_device: prepared_origin.fs_forward_leap_policy.slack_device,
    };

    Ok(PreparedBarrierMergeTicket {
        persist_request,
        client,
        room_id,
        gid,
        leaf_id,
        forward_state,
        pop_public_key,
        pop_secret_key,
        vrf_secret_key,
        vrf_public_key,
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        k_fs_current,
        fs_forward_leap_policy,
        prepared_origin,
    })
}
