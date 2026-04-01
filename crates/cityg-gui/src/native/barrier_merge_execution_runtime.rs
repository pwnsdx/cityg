use super::barrier_merge_prepare_runtime::{
    PreparedBarrierMergeExecution, prepare_barrier_merge_execution,
};
use super::barrier_merge_publish_runtime::{BarrierMergePublishInputs, publish_barrier_merge};
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
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        k_fs_current,
        forward_state,
        fs_forward_leap_policy,
        last_accepted_ec,
        header,
        cat_arr,
        parent_root_arr,
        join_delta_root_arr,
        revoked_since_root_arr,
        revoked_root_arr,
        tswe_salt_hash_arr,
        pox_r_commit_arr,
        pop_public_key,
        pop_secret_key,
        vrf_secret_key,
        vrf_public_key,
        msphf_crs_id,
        msphf_params_id,
        proof_mode,
        vrf_id,
        policy_version,
        fs_policy_version,
        fs_epoch_base_ts,
        parities,
        witness_bytes,
        pivot,
        snapshot_hash,
        committed_revocation_roots_hash,
        revocation_roots_hash,
        ticket_history_commitment,
        ticket_history_authority_extension,
        current_global_history_attestation_bytes,
        barrier_update,
    } = prepare_barrier_merge_execution(request, mode, allow_pending_recovery).await?;

    let pop_secret =
        Box::new(dilithium5::SecretKey::from_bytes(&pop_secret_key).context("invalid POP key")?);

    let params = OrchestrationParams {
        msphf_crs_id: msphf_crs_id.as_str(),
        params_id: msphf_params_id.as_str(),
        srx: None,
        srx_mode: SrxMode::Complete,
        pop_keys: Some(PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: pop_public_key.as_slice(),
            secret_key: pop_secret.as_ref(),
        }),
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode: proof_mode.as_str(),
        vrf_id: vrf_id.as_str(),
        policy_version: policy_version.as_str(),
        vrf_secret_key: Some(vrf_secret_key.as_slice()),
        vrf_public_key: Some(vrf_public_key.as_slice()),
        fs_policy_version: fs_policy_version.as_str(),
        fs_epoch_base_ts,
        barrier_version: next_barrier_version,
        fs_join: FsJoinInputs {
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
        },
        fs_merge: FsMergeInputs::default(),
    };

    let parts = AnchorInstanceParts {
        gid: &gid,
        cat: cat_arr.as_slice(),
        tswe_salt_hash: tswe_salt_hash_arr.as_slice(),
        parent_root: parent_root_arr.as_slice(),
        join_delta_root: join_delta_root_arr.as_slice(),
        revoked_since_prev_root: revoked_since_root_arr.as_slice(),
        revoked_root: revoked_root_arr.as_slice(),
        pox_r_commit: Some(pox_r_commit_arr.as_slice()),
    };

    publish_barrier_merge(BarrierMergePublishInputs {
        mode,
        client: &client,
        persist_request: &persist_request,
        gid: &gid,
        barrier_version,
        next_barrier_version,
        fs_ec,
        fs_dev_prev_commit,
        k_fs_current: &k_fs_current,
        header,
        cat_arr,
        parent_root_arr,
        params,
        parts,
        parities: &parities,
        witness_bytes: witness_bytes.as_deref(),
        pivot: &pivot,
        snapshot_hash,
        committed_revocation_roots_hash,
        revocation_roots_hash,
        ticket_history_commitment,
        ticket_history_authority_extension,
        current_global_history_attestation_bytes,
        barrier_update,
        forward_state,
        fs_forward_leap_policy,
        last_accepted_ec,
    })
    .await
}
