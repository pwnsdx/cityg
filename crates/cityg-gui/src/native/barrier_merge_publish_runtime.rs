use super::*;
use cityg_client::barrier_merge_bundle::{
    BarrierMergeBundleInputs as CoreBarrierMergeBundleInputs,
    build_barrier_merge_bundle as build_barrier_merge_bundle_core,
};

pub(super) struct BarrierMergePublishInputs<'a> {
    pub(super) mode: BarrierMergeMode,
    pub(super) client: &'a CitygApiClient,
    pub(super) persist_request: &'a LeaveRequest,
    pub(super) gid: &'a [u8; 32],
    pub(super) barrier_version: u64,
    pub(super) next_barrier_version: u64,
    pub(super) fs_ec: u64,
    pub(super) fs_dev_prev_commit: [u8; 32],
    pub(super) k_fs_current: &'a [u8; 32],
    pub(super) header: BTreeMap<u64, Value>,
    pub(super) cat_arr: [u8; 32],
    pub(super) parent_root_arr: [u8; 32],
    pub(super) params: OrchestrationParams<'a>,
    pub(super) parts: AnchorInstanceParts<'a>,
    pub(super) parities: &'a [PivotParity],
    pub(super) witness_bytes: Option<&'a [u8]>,
    pub(super) pivot: &'a PivotParity,
    pub(super) snapshot_hash: [u8; 32],
    pub(super) committed_revocation_roots_hash: [u8; 32],
    pub(super) revocation_roots_hash: [u8; 32],
    pub(super) ticket_history_commitment: HistoryCommitment,
    pub(super) ticket_history_authority_extension: Option<HistoryAuthorityExtension>,
    pub(super) current_global_history_attestation_bytes: Vec<u8>,
    pub(super) barrier_update: BarrierUpdateBuildResult,
    pub(super) forward_state: ForwardSecrecyState,
    pub(super) fs_forward_leap_policy: FsForwardLeapPolicy,
    pub(super) last_accepted_ec: u64,
}

#[derive(Clone)]
struct PreparedBarrierMerge {
    bundle: ClientEpochBundle,
    pending_barrier_state: BarrierPendingState,
    forward_state_after: ForwardSecrecyState,
}

pub(super) async fn publish_barrier_merge(
    inputs: BarrierMergePublishInputs<'_>,
) -> Result<PublishedBarrierMerge> {
    let BarrierMergePublishInputs {
        mode,
        client,
        persist_request,
        gid,
        barrier_version,
        next_barrier_version,
        fs_ec,
        fs_dev_prev_commit,
        k_fs_current,
        header,
        cat_arr,
        parent_root_arr,
        params,
        parts,
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
        forward_state,
        fs_forward_leap_policy,
        last_accepted_ec,
    } = inputs;

    let pending_barrier_state = BarrierPendingState {
        barrier_version: next_barrier_version,
        we_epoch_id: [0u8; 32],
        fs_ec,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash,
        kem_tree_hash_after: barrier_update.kem_tree_hash_after,
        k_barrier_new: barrier_update.k_barrier_new.clone(),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(mode.reason()),
        barrier_update_digest: barrier_update.barrier_update_digest,
        on_path_key_material: barrier_update.on_path_key_material.clone(),
        activation_source: Some(BarrierPendingActivationSource {
            barrier_version,
            barrier_roots_hash: committed_revocation_roots_hash,
            kem_tree_hash_after: snapshot_hash,
            current_history_commitment: Some(ticket_history_commitment),
            current_history_authority_extension: ticket_history_authority_extension,
            current_global_history_attestation_bytes: current_global_history_attestation_bytes
                .clone(),
            fs_ec,
            fs_dev_prev_commit,
        }),
    };

    let pending_barrier_state_template = pending_barrier_state.clone();
    let build_published_merge = |forward_state: ForwardSecrecyState,
                                 disable_autonomic_evolve: bool|
     -> Result<PreparedBarrierMerge> {
        let built = build_barrier_merge_bundle_core(CoreBarrierMergeBundleInputs {
            header: header.clone(),
            parts: parts.clone(),
            params: params.clone(),
            forward_state,
            parities,
            witness_bytes,
            pivot,
            gid,
            cat: &cat_arr,
            parent_root: &parent_root_arr,
            current_k_fs: mode.reseeds_k_fs().then_some(k_fs_current),
            next_barrier_version,
            barrier_key: &barrier_update.k_barrier_new,
            barrier_update_reason: mode.reason(),
            disable_autonomic_evolve,
        })
        .context(mode.build_bundle_context())?;

        let mut pending_barrier_state = pending_barrier_state_template.clone();
        pending_barrier_state.we_epoch_id = built.bundle.we_epoch_id;
        pending_barrier_state.fs_ec = built.observed_fs_ec;
        let next_forward = built.forward_state_after.snapshot();
        pending_barrier_state.next_forward_fs_ec = next_forward.fs_ec;
        pending_barrier_state.next_forward_fs_dev_commit = next_forward.fs_dev_commit;
        pending_barrier_state.next_forward_last_weid = next_forward.last_weid;
        pending_barrier_state.k_fs_after_pcs = built.k_fs_after_pcs;

        Ok(PreparedBarrierMerge {
            bundle: built.bundle,
            pending_barrier_state,
            forward_state_after: built.forward_state_after,
        })
    };

    let pristine_forward_state = forward_state.clone();
    let mut prepared = build_published_merge(forward_state, false)?;

    persist_pending_barrier_state_before_publish(
        persist_request,
        prepared.pending_barrier_state.clone(),
    )?;

    #[cfg(test)]
    if mode == BarrierMergeMode::JoinFinalize {
        fault_injection::trigger_fault(FaultInjectionCutPoint::BeforePublishJoinFinalize, None)?;
    }

    match client.refresh_pivot(&prepared.bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            status, message, ..
        }) if is_refresh_pivot_conflict(status.as_u16(), &message) => {
            debug!(status = status.as_u16(), "refresh pivot skipped: {message}");
        }
        Err(err) => return Err(err).context("refresh pivot parity"),
    }

    match client.accept_epoch_bundle(&prepared.bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            freeze_code,
            freeze_reason,
            ..
        }) if is_fs_forward_jump_group_http_error(freeze_code, freeze_reason.as_deref()) => {
            prepared = build_published_merge(pristine_forward_state, true)?;
            persist_pending_barrier_state_before_publish(
                persist_request,
                prepared.pending_barrier_state.clone(),
            )?;
            match client.refresh_pivot(&prepared.bundle).await {
                Ok(_) => {}
                Err(ApiClientError::HttpStatus {
                    status, message, ..
                }) if is_refresh_pivot_conflict(status.as_u16(), &message) => {
                    debug!(
                        status = status.as_u16(),
                        "refresh pivot skipped after stale-group retry: {message}"
                    );
                }
                Err(err) => {
                    return Err(err).context("refresh pivot parity after stale-group retry");
                }
            }
            client
                .accept_epoch_bundle(&prepared.bundle)
                .await
                .context(mode.accept_bundle_context())?;
        }
        Err(err) => return Err(err).context(mode.accept_bundle_context()),
    }

    Ok(PublishedBarrierMerge {
        bundle: prepared.bundle,
        pending_barrier_state: prepared.pending_barrier_state,
        pre_publish_barrier_version: barrier_version,
        pre_publish_barrier_roots_hash: committed_revocation_roots_hash,
        pre_publish_kem_tree_hash_after: snapshot_hash,
        pre_publish_current_history_commitment: ticket_history_commitment,
        pre_publish_current_history_authority_extension: ticket_history_authority_extension,
        pre_publish_current_global_history_attestation_bytes:
            current_global_history_attestation_bytes,
        forward_state_after: prepared.forward_state_after,
        fs_forward_leap_policy,
        last_accepted_ec,
        current_public_tree: barrier_update.snapshot_post.clone(),
    })
}
