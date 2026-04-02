use super::barrier_merge_ticket_runtime::prepare_barrier_merge_ticket;
use super::*;
use cityg_api_client::PreparedBarrierSnapshot;

pub(super) struct PreparedBarrierMergeExecution {
    pub(super) persist_request: LeaveRequest,
    pub(super) client: CitygApiClient,
    pub(super) gid: [u8; 32],
    pub(super) barrier_version: u64,
    pub(super) next_barrier_version: u64,
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

pub(super) async fn prepare_barrier_merge_execution(
    request: LeaveRequest,
    mode: BarrierMergeMode,
    allow_pending_recovery: bool,
) -> Result<PreparedBarrierMergeExecution> {
    let ticket = prepare_barrier_merge_ticket(request, mode, allow_pending_recovery).await?;
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
            mode.reason(),
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
