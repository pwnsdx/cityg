use super::*;
use cityg_api_client::HistoryAuthorityDescriptor;
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
    let mut retry_attempt = 0u32;
    let ticket = loop {
        match client.merge_ticket_refresh(&room_id, &leaf_id).await {
            Ok(ticket) => break ticket,
            Err(err) => {
                if let ApiClientError::HttpStatus {
                    status,
                    message,
                    freeze_code,
                    ..
                } = &err
                    && should_retry_ticket_http_error(status.as_u16(), message, *freeze_code)
                    && retry_attempt < TICKET_RETRY_MAX_ATTEMPTS
                {
                    let delay = ticket_retry_delay(retry_attempt);
                    retry_attempt = retry_attempt.saturating_add(1);
                    warn!(
                        attempt = retry_attempt,
                        delay_ms = delay.as_millis() as u64,
                        status = status.as_u16(),
                        message = %message,
                        "merge_ticket_refresh race/concurrency rejection; retrying"
                    );
                    sleep(delay).await;
                    continue;
                }

                return Err(err).context(format!("failed to obtain {} merge ticket", mode.label()));
            }
        }
    };

    let MergeTicket {
        we_epoch_id: _,
        parities: raw_parities,
        witness_cbor,
        srx_cbor,
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
        kbroad_public,
        msphf_crs_id,
        msphf_params_id,
        fs_policy_version,
        fs_epoch_base_ts,
        fs_forward_leap_policy,
        last_accepted_ec,
        kbroad_generation: _,
        barrier_version,
        cover_leaf_index,
        kem_tree_hash_after,
        current_history_commitment: ticket_history_commitment,
        history_authority_extension: ticket_history_authority_extension,
        history_authority,
        current_global_history_attestation_bytes,
        merge_ticket_artifact_bytes,
        deployment_profile_manifest_bytes,
        n_max,
        max_barrier_update_bytes,
        ..
    } = ticket;

    ensure_supported_attested_current_state_extension(
        mode.label(),
        ticket_history_authority_extension,
        current_global_history_attestation_bytes.as_slice(),
    )?;

    ensure_non_regressing_authenticated_current_state(
        local_barrier_version,
        &local_kem_tree_hash_after,
        local_current_history_commitment.as_ref(),
        local_current_history_authority_extension,
        barrier_version,
        &bytes32("kem_tree_hash_after", &kem_tree_hash_after)?,
        &ticket_history_commitment,
        ticket_history_authority_extension,
        mode.label(),
    )?;

    if !srx_cbor.is_empty() {
        return Err(anyhow!(
            "{} merge ticket unexpectedly contained SRX payload",
            mode.label()
        ));
    }

    let barrier_n_max = validate_barrier_n_max(if n_max == 0 {
        DEFAULT_BARRIER_N_MAX
    } else {
        n_max
    })?;
    if cover_leaf_index >= barrier_n_max {
        return Err(anyhow!(
            "cover_leaf_index out of range for barrier tree: {cover_leaf_index} >= {barrier_n_max}"
        ));
    }
    if stored_max_barrier_update_bytes != 0
        && stored_max_barrier_update_bytes != max_barrier_update_bytes.max(1)
    {
        return Err(anyhow!(
            "max_barrier_update_bytes mismatch: local={} server={}",
            stored_max_barrier_update_bytes,
            max_barrier_update_bytes.max(1)
        ));
    }

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header.insert(hdr::HDR_KBROAD_PUB, Value::Bytes(kbroad_public));
    if mode == BarrierMergeMode::JoinFinalize {
        header.insert(
            hdr::HDR_JOIN_FINALIZE_AUTH,
            Value::Bytes(join_finalize_auth_token.to_vec()),
        );
    }

    Ok(PreparedBarrierMergeTicket {
        persist_request,
        client,
        room_id,
        gid,
        leaf_id,
        barrier_version,
        cover_leaf_index,
        snapshot_hash: bytes32("kem_tree_hash_after", &kem_tree_hash_after)?,
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
        parities: hydrate_parities(&raw_parities, fs_ec, fs_epoch_commit, fs_dev_prev_commit),
        witness_bytes: if witness_cbor.is_empty() {
            None
        } else {
            Some(witness_cbor)
        },
        ticket_history_commitment,
        ticket_history_authority_extension,
        history_authority,
        current_global_history_attestation_bytes,
        merge_ticket_artifact_bytes,
        deployment_profile_manifest_bytes,
    })
}
