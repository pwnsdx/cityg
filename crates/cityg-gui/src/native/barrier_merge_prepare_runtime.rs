use super::*;
use crate::barrier_shared::{
    encode_full_verification_receipt, encode_history_commitment_header,
    require_current_state_history_commitment, require_same_history_commitment,
};

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
    pub(super) last_accepted_ec: u64,
    pub(super) header: BTreeMap<u64, Value>,
    pub(super) cat_arr: [u8; 32],
    pub(super) parent_root_arr: [u8; 32],
    pub(super) join_delta_root_arr: [u8; 32],
    pub(super) revoked_since_root_arr: [u8; 32],
    pub(super) revoked_root_arr: [u8; 32],
    pub(super) tswe_salt_hash_arr: [u8; 32],
    pub(super) pox_r_commit_arr: [u8; 32],
    pub(super) pop_public_key: Vec<u8>,
    pub(super) pop_secret_key: Vec<u8>,
    pub(super) vrf_secret_key: Vec<u8>,
    pub(super) vrf_public_key: Vec<u8>,
    pub(super) msphf_crs_id: String,
    pub(super) msphf_params_id: String,
    pub(super) proof_mode: String,
    pub(super) vrf_id: String,
    pub(super) policy_version: String,
    pub(super) fs_policy_version: String,
    pub(super) fs_epoch_base_ts: u64,
    pub(super) parities: Vec<PivotParity>,
    pub(super) witness_bytes: Option<Vec<u8>>,
    pub(super) pivot: PivotParity,
    pub(super) snapshot_hash: [u8; 32],
    pub(super) committed_revocation_roots_hash: [u8; 32],
    pub(super) revocation_roots_hash: [u8; 32],
    pub(super) ticket_history_commitment: HistoryCommitment,
    pub(super) ticket_history_authority_extension: Option<HistoryAuthorityExtension>,
    pub(super) current_global_history_attestation_bytes: Vec<u8>,
    pub(super) barrier_update: BarrierUpdateBuildResult,
}

pub(super) async fn prepare_barrier_merge_execution(
    request: LeaveRequest,
    mode: BarrierMergeMode,
    allow_pending_recovery: bool,
) -> Result<PreparedBarrierMergeExecution> {
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
    } = request;

    if barrier_recovery_pending && !allow_pending_recovery {
        return Err(anyhow!(mode.pending_guard_message()));
    }
    if !current_barrier_full_verified
        && allow_pending_recovery
        && barrier_recovery_pending
        && mode == BarrierMergeMode::JoinFinalize
    {
        current_barrier_full_verified =
            ensure_join_finalize_bootstrap_verified(&persist_request).await?;
    }
    if !current_barrier_full_verified {
        return Err(anyhow!(
            "cannot originate barrier updates from recover-only barrier state; re-establish FULL barrier verification first"
        ));
    }
    if mode == BarrierMergeMode::JoinFinalize && join_finalize_auth_token == [0u8; 32] {
        return Err(anyhow!(
            "cannot originate join_finalize without server-issued join_finalize auth token"
        ));
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

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header.insert(hdr::HDR_KBROAD_PUB, Value::Bytes(kbroad_public.clone()));
    if mode == BarrierMergeMode::JoinFinalize {
        header.insert(
            hdr::HDR_JOIN_FINALIZE_AUTH,
            Value::Bytes(join_finalize_auth_token.to_vec()),
        );
    }

    let cat_arr = bytes32("cat", &cat)?;
    let pox_r_commit_arr = bytes32("pox_r_commit", &pox_r_commit)?;

    let witness_bytes = if witness_cbor.is_empty() {
        None
    } else {
        Some(witness_cbor)
    };

    let parities = hydrate_parities(&raw_parities, fs_ec, fs_epoch_commit, fs_dev_prev_commit);

    let pivot = select_pivot_parity(&parities)
        .ok_or_else(|| anyhow!("merge ticket did not include any pivot parities"))?
        .clone();
    let parent_root_arr = bytes32("parent_root", &parent_root)?;
    let join_delta_root_arr = bytes32("join_delta_root", &join_delta_root)?;
    let revoked_since_root_arr = bytes32("revoked_since_root", &revoked_since_root)?;
    let revoked_root_arr = bytes32("revoked_root", &revoked_root)?;
    let tswe_salt_hash_arr = bytes32("tswe_salt_hash", &tswe_salt_hash)?;
    let revocation_roots_hash =
        compute_revocation_roots_hash(&revoked_since_root_arr, &revoked_root_arr)?;
    let committed_revocation_roots_hash =
        compute_revocation_roots_hash(&pivot.revoked_since_root, &pivot.revoked_root)?;
    let snapshot_hash = bytes32("kem_tree_hash_after", &kem_tree_hash_after)?;
    let barrier_tree_response = client
        .barrier_fetch_public_tree(&room_id, &snapshot_hash)
        .await
        .context("fetch barrier public tree snapshot")?;
    let barrier_tree_snapshot = barrier_tree_response.tree;
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
            Value::Bytes(current_global_history_attestation_bytes.clone()),
        );
    }
    let join_resolution = client
        .barrier_resolve_joins_since(&room_id, barrier_version)
        .await
        .context("resolve barrier joins since previous version")?;
    let revoked_resolution = client
        .barrier_resolve_revoked_leaves(&room_id, &committed_revocation_roots_hash)
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
        &gid,
        barrier_n_max,
        cover_leaf_index,
        next_barrier_version,
        barrier_version,
        revocation_roots_hash,
        kem_tree_hash_before,
        snapshot_pre.as_slice(),
    )?;
    let ticket_max_barrier_update_bytes = max_barrier_update_bytes.max(1);
    if stored_max_barrier_update_bytes != 0
        && stored_max_barrier_update_bytes != ticket_max_barrier_update_bytes
    {
        return Err(anyhow!(
            "max_barrier_update_bytes mismatch: local={} server={}",
            stored_max_barrier_update_bytes,
            ticket_max_barrier_update_bytes
        ));
    }
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
            &gid,
            &leaf_id,
            mode.reason(),
            cover_leaf_index,
            history_commitment_header.as_slice(),
            current_global_history_attestation_bytes.as_slice(),
            barrier_update.raw_update.as_slice(),
            pop_secret_key.as_slice(),
        )?;
        header.insert(
            hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
            Value::Bytes(receipt),
        );
        if mode.reason() == 0 || mode.reason() == 1 {
            let history_authority = history_authority.as_ref().ok_or_else(|| {
                anyhow!(
                    "{} merge ticket missing history_authority descriptor for full verification witness",
                    mode.label()
                )
            })?;
            let history_authority_extension =
                ticket_history_authority_extension.ok_or_else(|| {
                    anyhow!(
                        "{} merge ticket missing history_authority_extension for full verification witness",
                        mode.label()
                    )
                })?;
            let full_verification_witness = client
                .barrier_issue_full_verification_witness(
                    &room_id,
                    &leaf_id,
                    None,
                    merge_ticket_artifact_bytes.as_slice(),
                    mode.reason(),
                    barrier_update.raw_update.as_slice(),
                    barrier_n_max,
                    &ticket_history_commitment,
                    history_authority_extension,
                    history_authority,
                    current_global_history_attestation_bytes.as_slice(),
                    barrier_version,
                    &snapshot_hash,
                    barrier_version,
                    join_resolution.records.as_slice(),
                    &witness_revocation_roots_hash,
                    witness_revoked_leaf_indices.as_slice(),
                    deployment_profile_manifest_bytes.as_slice(),
                )
                .await
                .with_context(|| format!("issue full verification witness for {}", mode.label()))?;
            header.insert(
                hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS,
                Value::Bytes(full_verification_witness),
            );
        }
    }

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
        fs_forward_leap_policy: FsForwardLeapPolicy {
            h: fs_forward_leap_policy.h,
            checkpoint_interval: fs_forward_leap_policy.checkpoint_interval,
            slack_anchor: fs_forward_leap_policy.slack_anchor,
            slack_first_device: fs_forward_leap_policy.slack_first_device,
            slack_device: fs_forward_leap_policy.slack_device,
        },
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
    })
}
