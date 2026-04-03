use super::barrier_merge_prepare_runtime::{
    PreparedBarrierMergeExecution, prepare_barrier_merge_execution,
};
use super::barrier_merge_publish_runtime::{
    BarrierMergePublishInputs, BarrierMergePublishPolicy, publish_barrier_merge,
};
use super::*;

pub(super) async fn perform_barrier_merge_inner(
    request: LeaveRequest,
    mode: BarrierMergeMode,
    allow_pending_recovery: bool,
) -> Result<PublishedBarrierMerge> {
    let PreparedBarrierMergeExecution {
        persist_request,
        client,
        gid,
        barrier_version,
        next_barrier_version,
        protocol_barrier_update_reason,
        build_barrier_update_reason,
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        k_fs_current,
        forward_state,
        fs_forward_leap_policy,
        header,
        cat_arr,
        parent_root_arr,
        pop_public_key,
        pop_secret_key,
        vrf_secret_key,
        vrf_public_key,
        prepared_origin,
        pivot,
        snapshot_hash,
        committed_revocation_roots_hash,
        revocation_roots_hash,
        barrier_update,
    } = prepare_barrier_merge_execution(request, mode, allow_pending_recovery).await?;

    let pop_secret = Box::new(
        cityg_api_client::parse_room_admin_secret_key(&pop_secret_key)
            .context("invalid POP key")?,
    );

    let prepared_orchestration = prepared_origin.prepare_barrier_orchestration(
        &gid,
        pop_public_key.as_slice(),
        pop_secret.as_ref(),
        vrf_secret_key.as_slice(),
        vrf_public_key.as_slice(),
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        next_barrier_version,
    );

    publish_barrier_merge(BarrierMergePublishInputs {
        policy: BarrierMergePublishPolicy {
            pending_barrier_update_reason: protocol_barrier_update_reason,
            build_barrier_update_reason,
            current_k_fs: mode.reseeds_k_fs().then_some(&k_fs_current),
            build_bundle_context: mode.build_bundle_context(),
            accept_bundle_context: mode.accept_bundle_context(),
            retry_on_fs_forward_jump_group: true,
            trigger_before_publish_join_finalize_fault: mode == BarrierMergeMode::JoinFinalize,
        },
        client: &client,
        persist_request: &persist_request,
        gid: &gid,
        barrier_version,
        next_barrier_version,
        fs_ec,
        fs_dev_prev_commit,
        header,
        cat_arr,
        parent_root_arr,
        params: prepared_orchestration.params,
        parts: prepared_orchestration.parts,
        parities: &prepared_origin.parities,
        witness_bytes: prepared_origin.witness_bytes.as_deref(),
        pivot: &pivot,
        snapshot_hash,
        committed_revocation_roots_hash,
        revocation_roots_hash,
        ticket_history_commitment: prepared_origin.ticket_history_commitment,
        ticket_history_authority_extension: prepared_origin.ticket_history_authority_extension,
        current_global_history_attestation_bytes: prepared_origin
            .current_global_history_attestation_bytes
            .clone(),
        barrier_update,
        forward_state,
        fs_forward_leap_policy,
        last_accepted_ec: prepared_origin.last_accepted_ec,
    })
    .await
}
