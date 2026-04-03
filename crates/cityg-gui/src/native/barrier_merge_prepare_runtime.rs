use super::barrier_merge_ticket_runtime::prepare_barrier_merge_ticket;
use super::*;
use cityg_api_client::PreparedBarrierSnapshot;

pub(super) struct PreparedBarrierMergeExecution {
    pub(super) persist_request: LeaveRequest,
    pub(super) client: CitygApiClient,
    pub(super) gid: [u8; 32],
    pub(super) barrier_version: u64,
    pub(super) next_barrier_version: u64,
    pub(super) protocol_barrier_update_reason: u64,
    pub(super) build_barrier_update_reason: u64,
    pub(super) fs_ec: u64,
    pub(super) fs_epoch_commit: [u8; 32],
    pub(super) fs_dev_prev_commit: [u8; 32],
    pub(super) k_fs_current: [u8; 32],
    pub(super) forward_state: ForwardSecrecyState,
    pub(super) fs_forward_leap_policy: FsForwardLeapPolicy,
    pub(super) header: BTreeMap<u64, Value>,
    pub(super) cat_arr: [u8; 32],
    pub(super) parent_root_arr: [u8; 32],
    pub(super) pop_public_key: Vec<u8>,
    pub(super) pop_secret_key: Vec<u8>,
    pub(super) vrf_secret_key: Vec<u8>,
    pub(super) vrf_public_key: Vec<u8>,
    pub(super) prepared_origin: cityg_api_client::PreparedOriginMergeTicket,
    pub(super) pivot: PivotParity,
    pub(super) snapshot_hash: [u8; 32],
    pub(super) committed_revocation_roots_hash: [u8; 32],
    pub(super) revocation_roots_hash: [u8; 32],
    pub(super) barrier_update: BarrierUpdateBuildResult,
}

fn resolve_barrier_publish_reasons(
    mode: BarrierMergeMode,
    local_barrier_roots_hash: [u8; 32],
    ticket_barrier_roots_hash: [u8; 32],
) -> (u64, u64) {
    let reclaims_revoked_slot = mode == BarrierMergeMode::JoinFinalize
        && local_barrier_roots_hash != ticket_barrier_roots_hash;
    let protocol_barrier_update_reason = if reclaims_revoked_slot {
        0
    } else {
        mode.reason()
    };
    let build_barrier_update_reason = if reclaims_revoked_slot {
        BarrierMergeMode::JoinFinalize.reason()
    } else {
        mode.reason()
    };
    (protocol_barrier_update_reason, build_barrier_update_reason)
}

pub(super) async fn prepare_barrier_merge_execution(
    request: LeaveRequest,
    mode: BarrierMergeMode,
    allow_pending_recovery: bool,
) -> Result<PreparedBarrierMergeExecution> {
    let ticket = prepare_barrier_merge_ticket(request, mode, allow_pending_recovery).await?;
    let ticket_barrier_roots_hash = compute_revocation_roots_hash(
        &ticket.prepared_origin.revoked_since_root,
        &ticket.prepared_origin.revoked_root,
    )?;
    let (protocol_barrier_update_reason, build_barrier_update_reason) =
        resolve_barrier_publish_reasons(
            mode,
            ticket.persist_request.barrier_roots_hash,
            ticket_barrier_roots_hash,
        );
    let PreparedBarrierSnapshot {
        header,
        cat: cat_arr,
        parent_root: parent_root_arr,
        join_delta_root: _join_delta_root_arr,
        revoked_since_root: _revoked_since_root_arr,
        revoked_root: _revoked_root_arr,
        tswe_salt_hash: _tswe_salt_hash_arr,
        pox_r_commit: _pox_r_commit_arr,
        pivot,
        snapshot_hash,
        committed_revocation_roots_hash,
        revocation_roots_hash,
        barrier_update,
    } = ticket
        .client
        .barrier_prepare_snapshot(ticket.snapshot_preparation_request(
            ticket.pop_secret_key.as_slice(),
            protocol_barrier_update_reason,
            mode.label(),
        ))
        .await
        .map_err(anyhow::Error::from)?;
    let barrier_update =
        BarrierUpdateBuildResult::from_core(ticket.prepared_origin.barrier_n_max, barrier_update);

    let super::barrier_merge_ticket_runtime::PreparedBarrierMergeTicket {
        persist_request,
        client,
        gid,
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
        ..
    } = ticket;
    let barrier_version = prepared_origin.barrier_version;
    let next_barrier_version = barrier_version.saturating_add(1);

    Ok(PreparedBarrierMergeExecution {
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_barrier_publish_reasons_keeps_standard_join_finalize_reason() {
        let (protocol_reason, build_reason) =
            resolve_barrier_publish_reasons(BarrierMergeMode::JoinFinalize, [0x11; 32], [0x11; 32]);
        assert_eq!(protocol_reason, 2);
        assert_eq!(build_reason, 2);
    }

    #[test]
    fn resolve_barrier_publish_reasons_downgrades_reclaim_join_to_reason_zero() {
        let (protocol_reason, build_reason) =
            resolve_barrier_publish_reasons(BarrierMergeMode::JoinFinalize, [0x11; 32], [0x22; 32]);
        assert_eq!(protocol_reason, 0);
        assert_eq!(build_reason, 2);
    }
}
