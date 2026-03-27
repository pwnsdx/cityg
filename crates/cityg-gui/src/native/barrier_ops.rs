use super::epoch_sync::perform_epoch_sync;
use super::*;
use crate::barrier_shared::{
    encode_full_verification_receipt, encode_history_commitment_header,
    require_current_state_history_commitment, require_same_history_commitment,
};

fn is_fs_forward_jump_group_http_error(
    freeze_code: Option<u32>,
    freeze_reason: Option<&str>,
) -> bool {
    freeze_code == Some(9476) || freeze_reason == Some("fs_forward_jump_group")
}

pub(super) fn persist_pending_barrier_state_before_publish(
    request: &LeaveRequest,
    pending: BarrierPendingState,
) -> Result<()> {
    let Some(mut session) = load_session_at(&request.server_url, &request.room_id)? else {
        return Err(anyhow!(
            "session snapshot missing before barrier publish; refusing to publish barrier update"
        ));
    };
    if session.gid != request.gid || session.leaf_id != request.leaf_id {
        return Err(anyhow!(
            "session snapshot identity mismatch before barrier publish; refusing to publish barrier update"
        ));
    }
    session.barrier_state.pending = Some(pending);
    persist_session(&session).context("persist pending barrier state before publish")?;
    Ok(())
}

pub(super) fn persist_activated_joined_session(session: &AppSession) -> Result<()> {
    persist_session(session)?;
    #[cfg(test)]
    fault_injection::trigger_fault(FaultInjectionCutPoint::AfterPersistBeforePendingClear, None)?;
    Ok(())
}

pub(super) fn reload_join_finalization_session(
    session: &AppSession,
    err: anyhow::Error,
    context: &'static str,
) -> Result<AppSession> {
    match load_session_at(&session.server_url, &session.room_id) {
        Ok(Some(reloaded))
            if reloaded.gid == session.gid
                && reloaded.leaf_id == session.leaf_id
                && !reloaded.barrier_state.barrier_recovery_pending =>
        {
            Ok(reloaded)
        }
        Ok(Some(_)) => Err(err).context(context),
        Ok(None) => Err(err).context(context),
        Err(load_err) => Err(err).context(format!(
            "{context} (and reload persisted session failed: {load_err})"
        )),
    }
}

pub(super) async fn finalize_bootstrapped_room_join(session: AppSession) -> Result<AppSession> {
    finalize_joined_room(session, BarrierMergeMode::JoinFinalize).await
}

pub(super) async fn finalize_pending_join(session: AppSession) -> Result<AppSession> {
    finalize_joined_room(session, BarrierMergeMode::JoinFinalize).await
}

async fn finalize_joined_room(session: AppSession, mode: BarrierMergeMode) -> Result<AppSession> {
    persist_session(&session).context("persist joined session before initial room setup")?;

    let published = match mode {
        BarrierMergeMode::PcsRefresh => {
            perform_pcs_refresh_inner(LeaveRequest::from_session(&session), true).await
        }
        BarrierMergeMode::JoinFinalize => {
            perform_join_finalize_inner(LeaveRequest::from_session(&session)).await
        }
    }
    .context(mode.publish_context())?;

    #[cfg(test)]
    if mode == BarrierMergeMode::JoinFinalize {
        fault_injection::trigger_fault(FaultInjectionCutPoint::AfterPublishBeforeReload, None)?;
    }

    let mut updated = session.clone();
    match apply_local_published_barrier_merge(&mut updated, published) {
        Ok(()) => {
            persist_activated_joined_session(&updated).context(mode.persist_context())?;
            Ok(updated)
        }
        Err(local_err) => {
            warn!(
                "local activation of barrier merge failed; falling back to epoch sync: {local_err:#}"
            );
            let persisted =
                load_session_at(&session.server_url, &session.room_id)?.ok_or_else(|| {
                    anyhow!("persisted joined session missing after barrier merge publish")
                })?;
            let sync = perform_epoch_sync(persisted)
                .await
                .context(mode.fallback_sync_context())?;
            if sync.session.barrier_state.barrier_recovery_pending {
                return Err(anyhow!(mode.still_pending_message()));
            }
            persist_activated_joined_session(&sync.session).context(mode.persist_context())?;
            Ok(sync.session)
        }
    }
}

fn apply_local_published_barrier_merge(
    session: &mut AppSession,
    published: PublishedBarrierMerge,
) -> Result<()> {
    let PublishedBarrierMerge {
        bundle,
        pending_barrier_state,
        pre_publish_barrier_version,
        pre_publish_barrier_roots_hash,
        pre_publish_kem_tree_hash_after,
        pre_publish_current_history_commitment,
        pre_publish_current_history_authority_extension,
        pre_publish_current_global_history_attestation_bytes,
        mut forward_state_after,
        fs_forward_leap_policy,
        last_accepted_ec,
        current_public_tree,
    } = published;
    session.fs_forward_leap_policy = fs_forward_leap_policy;
    session.last_accepted_ec = session.last_accepted_ec.max(last_accepted_ec);
    install_authenticated_current_state(
        session,
        pre_publish_barrier_version,
        pre_publish_barrier_roots_hash,
        pre_publish_kem_tree_hash_after,
        pre_publish_current_history_commitment,
        pre_publish_current_history_authority_extension,
        pre_publish_current_global_history_attestation_bytes,
    );
    let activation_source_before_apply = capture_barrier_pending_activation_source(session);
    let has_barrier_update = matches!(
        bundle.header_map.get(&hdr::HDR_BARRIER_UPDATE),
        Some(Value::Bytes(_))
    );
    if has_barrier_update {
        validate_client_visible_activation_guards(session, &bundle.header_map)?;
    }
    session.barrier_state.pending = Some(pending_barrier_state.clone());
    session.we_epoch_id = bundle.we_epoch_id;
    session.xk_hash = bundle.hp_binding.xk_hash;
    session.epoch_key = bundle.epoch_key;
    session.parent_root = bundle.anchor.parent_root;
    session.join_delta_root = bundle.anchor.join_delta_root;
    session.revoked_since_root = bundle.anchor.revoked_since_prev_root;
    session.revoked_root = bundle.anchor.revoked_root;
    session.cat = bytes32("cat", &bundle.anchor.cat)?;
    session.tswe_salt_hash = bytes32("tswe_salt_hash", &bundle.anchor.tswe_salt_hash)?;
    if let Some(commit) = bundle.anchor.pox_r_commit {
        session.pox_r_commit = commit;
    }
    if let Some(fs_ec) = header_u64(&bundle.header_map, hdr::HDR_FS_EC) {
        session.fs_ec = fs_ec;
        session.last_accepted_ec = session.last_accepted_ec.max(fs_ec);
    }
    if let Some(commit) = header_bytes32(&bundle.header_map, hdr::HDR_FS_EPOCH_COMMIT) {
        session.fs_epoch_commit = commit;
    }
    if bundle_authored_by_local_device(session, &bundle.header_map)
        && let Some(commit) = header_bytes32(&bundle.header_map, hdr::HDR_FS_DEV_COMMIT)
            .or_else(|| header_bytes32(&bundle.header_map, hdr::HDR_FS_DEV_PREV_COMMIT))
    {
        session.fs_dev_prev_commit = commit;
    }
    if let Some(base_ts) = header_u64(&bundle.header_map, hdr::HDR_FS_EPOCH_BASE_TS) {
        session.fs_epoch_base_ts = base_ts;
    }
    if let Some(policy) = header_policy_version(&bundle.header_map, hdr::HDR_FS_POLICY_VERSION) {
        session.fs_policy_version = policy;
    }
    session.policy_version = session.fs_policy_version.clone();
    if let Some(vrf_id) = header_text(&bundle.header_map, hdr::HDR_VRF_ID) {
        session.vrf_id = vrf_id.to_string();
    }
    if let Some(proof_mode) = header_text(&bundle.header_map, hdr::HDR_PROOF_MODE) {
        session.proof_mode = proof_mode.to_string();
    }
    if let Some(Value::Bytes(kbroad_pub)) = bundle.header_map.get(&hdr::HDR_KBROAD_PUB) {
        session.kbroad_public = kbroad_pub.clone();
    }

    let observed_barrier_version = header_u64(&bundle.header_map, hdr::HDR_BARRIER_VERSION)
        .unwrap_or(pending_barrier_state.barrier_version);
    let observed_fs_ec = header_u64(&bundle.header_map, hdr::HDR_FS_EC);
    let observed_barrier_update_reason =
        header_u64(&bundle.header_map, hdr::HDR_BARRIER_UPDATE_REASON);
    if !apply_pending_barrier_activation_with_source(
        session,
        &activation_source_before_apply,
        observed_barrier_version,
        observed_fs_ec,
        observed_barrier_update_reason,
        Some(pending_barrier_state.barrier_update_digest),
    )? {
        return Err(anyhow!(
            "accepted local refresh bundle did not match persisted pending barrier state"
        ));
    }
    install_current_public_tree_cache(session, (*current_public_tree).clone())?;
    // The accepted local publish advances the authenticated current state, but
    // the post-accept HistoryCommitment is only available from a subsequent
    // helper lookup / merge ticket refresh. Drop the current-tree cache at the
    // same time so later full-chain checks cannot reuse a snapshot without an
    // authenticated current-state commitment.
    clear_current_public_tree_cache(&mut session.barrier_state);
    session.barrier_state.current_history_view_id = [0u8; 32];
    session.barrier_state.current_history_commitment = None;
    session.barrier_state.current_history_authority_extension = None;
    session
        .barrier_state
        .current_global_history_attestation_bytes
        .clear();

    session.regular_fingerprint = Some(bundle.hp_binding.seed_ctx_hash);
    session.fs_fingerprint = compute_fs_fingerprint_from_header(&bundle.header_map).or_else(|| {
        derive_fs_fingerprint_from_fields(
            session.fs_policy_version.as_str(),
            session.fs_ec,
            &session.fs_epoch_commit,
            session.fs_epoch_base_ts,
        )
    });
    session.fs_epoch_created_at = SystemTime::now();
    session.last_fetch_timestamp_ms = None;
    forward_state_after.set_last_we_epoch_id(session.we_epoch_id);
    forward_state_after.set_epoch_base_ts(session.fs_epoch_base_ts);
    session.forward_state = forward_state_after;
    Ok(())
}

fn cover_leaf_index_for_n_max(leaf_id: &[u8; 32], n_max: u64) -> u64 {
    let n_max = n_max.max(1).min(u32::MAX as u64) as u32;
    let leaf_suffix: [u8; 4] = leaf_id[28..32].try_into().unwrap_or_default();
    u64::from(u32::from_be_bytes(leaf_suffix) % n_max)
}

fn ensure_full_barrier_verification_for_origin(
    barrier_recovery_pending: bool,
    current_barrier_full_verified: bool,
) -> Result<()> {
    if barrier_recovery_pending {
        return Err(anyhow!(
            "cannot originate barrier updates while barrier recovery is pending; complete FULL barrier recovery first"
        ));
    }
    if !current_barrier_full_verified {
        return Err(anyhow!(
            "cannot originate barrier updates from recover-only barrier state; re-establish FULL barrier verification first"
        ));
    }
    Ok(())
}

fn ensure_supported_attested_current_state_extension(
    context: &str,
    extension: Option<HistoryAuthorityExtension>,
    current_global_history_attestation_bytes: &[u8],
) -> Result<()> {
    if current_global_history_attestation_bytes.is_empty() {
        if extension.is_some() {
            return Err(anyhow!(
                "{context} carries history authority extension without current global history attestation"
            ));
        }
        return Ok(());
    }
    if extension != Some(HistoryAuthorityExtension::LocalHistoryAuthorityV1) {
        return Err(anyhow!(
            "{context} carries attested current state without supported history authority extension"
        ));
    }
    Ok(())
}

async fn ensure_join_finalize_bootstrap_verified(request: &LeaveRequest) -> Result<bool> {
    let Some(mut session) = load_session_at(&request.server_url, &request.room_id)? else {
        return Err(anyhow!(
            "persisted session missing before join_finalize bootstrap verification"
        ));
    };
    if session.gid != request.gid || session.leaf_id != request.leaf_id {
        return Err(anyhow!(
            "session snapshot identity mismatch before join_finalize bootstrap verification"
        ));
    }
    if session.barrier_state.current_barrier_full_verified {
        return Ok(true);
    }
    if !session.barrier_state.barrier_recovery_pending {
        return Ok(false);
    }

    if session.parent_root == [0u8; 32] && session.barrier_state.barrier_version == 0 {
        session.barrier_state.current_barrier_full_verified = true;
        session.barrier_state.barrier_recovery_issue = None;
        clear_join_finalize_bootstrap_artifact(&mut session.barrier_state);
        persist_session(&session)
            .context("persist genesis join_finalize bootstrap verification state")?;
        return Ok(true);
    }

    let client = new_api_client(&request.server_url);
    verify_join_finalize_bootstrap_current_state(&client, &request.room_id, &mut session).await?;
    session.barrier_state.current_barrier_full_verified = true;
    session.barrier_state.barrier_recovery_issue = None;
    clear_join_finalize_bootstrap_artifact(&mut session.barrier_state);
    persist_session(&session).context("persist join_finalize bootstrap verification state")?;
    Ok(true)
}

async fn publish_revocation_merge_from_ticket(
    request: LeaveRequest,
    ticket: MergeTicket,
    operation_label: &'static str,
) -> Result<PublishedBarrierMerge> {
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
        mut forward_state,
        pop_public_key,
        pop_secret_key,
        vrf_secret_key,
        vrf_public_key,
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        max_barrier_update_bytes: stored_max_barrier_update_bytes,
        barrier_recovery_pending,
        current_barrier_full_verified,
        ..
    } = request;

    ensure_full_barrier_verification_for_origin(
        barrier_recovery_pending,
        current_barrier_full_verified,
    )?;

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
        cover_leaf_index: revoked_cover_leaf_index,
        kem_tree_hash_after,
        current_history_commitment: ticket_history_commitment,
        history_authority_extension: ticket_history_authority_extension,
        current_global_history_attestation_bytes,
        n_max,
        max_barrier_update_bytes,
        ..
    } = ticket;

    ensure_supported_attested_current_state_extension(
        operation_label,
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
        operation_label,
    )?;

    let srx_inputs = if srx_cbor.is_empty() {
        return Err(anyhow!(
            "{operation_label} merge ticket missing SRX payload"
        ));
    } else {
        SrxInputsOwned::from_cbor(&srx_cbor)
            .context("unable to decode SRX bundle from server")?
            .into_srx_inputs()
    };

    let client = new_api_client(&server_url);
    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header.insert(hdr::HDR_KBROAD_PUB, Value::Bytes(kbroad_public.clone()));

    let cat_arr = bytes32("cat", &cat)?;
    let pox_r_commit_arr = bytes32("pox_r_commit", &pox_r_commit)?;

    let pop_secret =
        Box::new(dilithium5::SecretKey::from_bytes(&pop_secret_key).context("invalid POP key")?);

    let witness_bytes = if witness_cbor.is_empty() {
        None
    } else {
        Some(witness_cbor.as_slice())
    };

    let parities = hydrate_parities(&raw_parities, fs_ec, fs_epoch_commit, fs_dev_prev_commit);
    let pivot = select_pivot_parity(&parities).ok_or_else(|| {
        anyhow!("{operation_label} merge ticket did not include any pivot parities")
    })?;
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
    if revoked_cover_leaf_index >= barrier_n_max {
        return Err(anyhow!(
            "cover_leaf_index out of range for barrier tree: {revoked_cover_leaf_index} >= {barrier_n_max}"
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
            "barrier snapshot-auth history commitment mismatch (960.9): snapshot / joins / revoked leaves do not share one authenticated current-state commitment"
        ));
    }
    let mut snapshot_pre = barrier_tree_snapshot.pk_entries.clone();
    apply_join_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        join_resolution.records.as_slice(),
    )?;
    apply_revoked_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        revoked_resolution.leaf_indices.as_slice(),
    )?;
    let leaf_base = barrier_n_max.saturating_sub(1);
    let revoked_leaf_node = leaf_base.saturating_add(revoked_cover_leaf_index);
    blank_leaf_and_path(snapshot_pre.as_mut_slice(), revoked_leaf_node)?;
    let kem_tree_hash_before = compute_barrier_tree_hash(barrier_n_max, snapshot_pre.as_slice())?;
    let next_barrier_version = barrier_version.saturating_add(1);
    let updater_leaf = cover_leaf_index_for_n_max(&leaf_id, barrier_n_max);
    let barrier_update = build_barrier_update_bytes(
        &gid,
        barrier_n_max,
        updater_leaf,
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
        Value::Integer(Integer::from(0u64)),
    );
    if !current_global_history_attestation_bytes.is_empty() {
        let receipt = encode_full_verification_receipt(
            &gid,
            &leaf_id,
            0,
            updater_leaf,
            history_commitment_header.as_slice(),
            current_global_history_attestation_bytes.as_slice(),
            barrier_update.raw_update.as_slice(),
            pop_secret_key.as_slice(),
        )?;
        header.insert(
            hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
            Value::Bytes(receipt),
        );
    }
    let mut pending_barrier_state = BarrierPendingState {
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
        barrier_update_reason: Some(0),
        barrier_update_digest: barrier_update.barrier_update_digest,
        on_path_key_material: barrier_update.on_path_key_material.clone(),
        activation_source: Some(BarrierPendingActivationSource {
            barrier_version,
            barrier_roots_hash: committed_revocation_roots_hash,
            kem_tree_hash_after: snapshot_hash,
            current_history_commitment: Some(ticket_history_commitment.clone()),
            current_history_authority_extension: ticket_history_authority_extension,
            current_global_history_attestation_bytes: current_global_history_attestation_bytes
                .clone(),
            fs_ec,
            fs_dev_prev_commit,
        }),
    };

    let params = OrchestrationParams {
        msphf_crs_id: msphf_crs_id.as_str(),
        params_id: msphf_params_id.as_str(),
        srx: Some(srx_inputs),
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

    let mut bundle = CityGClient::generate_merge_with_forward_state(
        header,
        parts,
        params,
        Some(&mut forward_state),
        &parities,
        None,
        witness_bytes,
    )
    .with_context(|| format!("failed to build {operation_label} merge bundle"))?;

    strip_rollup_metadata(&mut bundle.header_map);
    apply_pivot_alignment(&mut bundle.header_map, pivot);
    let anchor_ctx =
        build_anchor_seed_ctx(&bundle.header_map).context("compute anchor seed ctx")?;
    let seed_ctx_hash = compute_seed_ctx_hash(&anchor_ctx).context("compute seed_ctx_hash")?;
    let seed_commit = compute_seed_commit(
        &anchor_ctx,
        &SeedCommitFields {
            gid: &gid,
            cat: cat_arr.as_slice(),
            we_epoch_id: bundle.we_epoch_id,
        },
    )
    .context("compute seed_commit")?;
    let seed_bundle_commit = compute_seed_bundle_commit(
        &anchor_ctx,
        &bundle.hp_binding.rho_commit,
        &gid,
        cat_arr.as_slice(),
        &parent_root_arr,
    )
    .context("compute seed_bundle_commit")?;
    let derived_we_epoch_id =
        derive_we_epoch_id(&gid, &parent_root_arr, &seed_ctx_hash).context("derive we_epoch_id")?;

    bundle.anchor.anchor_hdr_ctx = anchor_ctx.clone();
    bundle.hp_binding.seed_ctx_hash = seed_ctx_hash;
    bundle.hp_binding.seed_commit = seed_commit;
    bundle.hp_binding.seed_bundle_commit = seed_bundle_commit;
    bundle.we_epoch_id = derived_we_epoch_id;
    bundle
        .rebind_local_hp_envelope_with_barrier_key(&barrier_update.k_barrier_new)
        .with_context(|| format!("rebind merge HP envelope for {operation_label}"))?;
    pending_barrier_state.we_epoch_id = bundle.we_epoch_id;
    bundle
        .header_map
        .insert(hdr::HDR_SEED_CTX_HASH, Value::Bytes(seed_ctx_hash.to_vec()));
    bundle.header_map.insert(
        hdr::HDR_RHO_COMMIT,
        Value::Bytes(bundle.hp_binding.rho_commit.to_vec()),
    );
    bundle.header_map.insert(
        hdr::HDR_SEED_BUNDLE_COMMIT,
        Value::Bytes(seed_bundle_commit.to_vec()),
    );

    if let Some(commit) = recompute_srx_commit(&bundle.header_map)? {
        bundle
            .header_map
            .insert(hdr::HDR_SRX_COMMIT, Value::Bytes(commit.to_vec()));
    }

    if let Some(recomputed) = recompute_proofs_commit(&bundle.header_map)
        .ok()
        .map(|arr| arr.to_vec())
    {
        bundle
            .header_map
            .insert(hdr::HDR_PROOFS_COMMIT, Value::Bytes(recomputed));
    }

    persist_pending_barrier_state_before_publish(&persist_request, pending_barrier_state.clone())?;

    match client.refresh_pivot(&bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            status, message, ..
        }) if is_refresh_pivot_conflict(status.as_u16(), &message) => {
            warn!("refresh pivot skipped: {message}");
        }
        Err(err) => return Err(err).context("refresh pivot parity"),
    }

    client
        .accept_epoch_bundle(&bundle)
        .await
        .with_context(|| format!("server rejected {operation_label} merge bundle"))?;

    Ok(PublishedBarrierMerge {
        bundle,
        pending_barrier_state,
        pre_publish_barrier_version: barrier_version,
        pre_publish_barrier_roots_hash: committed_revocation_roots_hash,
        pre_publish_kem_tree_hash_after: snapshot_hash,
        pre_publish_current_history_commitment: ticket_history_commitment,
        pre_publish_current_history_authority_extension: ticket_history_authority_extension,
        pre_publish_current_global_history_attestation_bytes:
            current_global_history_attestation_bytes,
        forward_state_after: forward_state,
        fs_forward_leap_policy: FsForwardLeapPolicy {
            h: fs_forward_leap_policy.h,
            checkpoint_interval: fs_forward_leap_policy.checkpoint_interval,
            slack_anchor: fs_forward_leap_policy.slack_anchor,
            slack_first_device: fs_forward_leap_policy.slack_first_device,
            slack_device: fs_forward_leap_policy.slack_device,
        },
        last_accepted_ec,
        current_public_tree: barrier_update.snapshot_post.clone(),
    })
}

pub(super) async fn perform_leave(request: LeaveRequest) -> Result<()> {
    ensure_full_barrier_verification_for_origin(
        request.barrier_recovery_pending,
        request.current_barrier_full_verified,
    )?;

    let client = new_api_client(&request.server_url);
    let room_id = request.room_id.clone();
    let leaf_id = request.leaf_id;
    let mut retry_attempt = 0u32;
    let ticket = loop {
        match client.merge_ticket(&room_id, &leaf_id).await {
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
                        "merge_ticket race/concurrency rejection; retrying"
                    );
                    sleep(delay).await;
                    continue;
                }

                return Err(err).context("failed to obtain leave merge ticket");
            }
        }
    };

    publish_revocation_merge_from_ticket(request, ticket, "leave").await?;
    Ok(())
}

pub(super) async fn perform_room_admin_expel(
    session: AppSession,
    target_leaf_id: [u8; 32],
) -> Result<AppSession> {
    if session.leaf_id == target_leaf_id {
        return Err(anyhow!(
            "cannot expel the local device; use Leave room for controlled self-revocation"
        ));
    }

    let request = LeaveRequest::from_session(&session);
    ensure_full_barrier_verification_for_origin(
        request.barrier_recovery_pending,
        request.current_barrier_full_verified,
    )?;
    let client = new_api_client(&request.server_url);
    let room_id = request.room_id.clone();
    let author_leaf_id = request.leaf_id;
    let admin_proof = build_room_admin_leaf_pair_proof(
        RoomAdminOperation::ExpelMember,
        &room_id,
        &author_leaf_id,
        &target_leaf_id,
        &request.pop_public_key,
        &request.pop_secret_key,
    )
    .context("build expel member room admin proof")?;

    let mut retry_attempt = 0u32;
    let ticket = loop {
        match client
            .expel_member_ticket(
                &room_id,
                &author_leaf_id,
                &target_leaf_id,
                admin_proof.clone(),
            )
            .await
        {
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
                        "expel_member_ticket race/concurrency rejection; retrying"
                    );
                    sleep(delay).await;
                    continue;
                }

                return Err(err).context("failed to obtain expel merge ticket");
            }
        }
    };

    let published = publish_revocation_merge_from_ticket(request, ticket, "expel").await?;
    let mut updated = session.clone();
    match apply_local_published_barrier_merge(&mut updated, published) {
        Ok(()) => {
            persist_activated_joined_session(&updated)
                .context("persist room session after expel")?;
            Ok(updated)
        }
        Err(local_err) => {
            warn!(
                "local activation of expel merge failed; falling back to epoch sync: {local_err:#}"
            );
            let persisted = load_session_at(&session.server_url, &session.room_id)?
                .ok_or_else(|| anyhow!("persisted session missing after expel merge publish"))?;
            let sync = perform_epoch_sync(persisted)
                .await
                .context("sync room after expel merge")?;
            if sync.session.barrier_state.barrier_recovery_pending {
                return Err(anyhow!("barrier recovery still pending after expel merge"));
            }
            persist_activated_joined_session(&sync.session)
                .context("persist room session after expel merge sync")?;
            Ok(sync.session)
        }
    }
}

pub(super) async fn perform_pcs_refresh(request: LeaveRequest) -> Result<()> {
    perform_barrier_merge_inner(request, BarrierMergeMode::PcsRefresh, false)
        .await
        .map(|_| ())
}

async fn perform_pcs_refresh_inner(
    request: LeaveRequest,
    allow_pending_recovery: bool,
) -> Result<PublishedBarrierMerge> {
    perform_barrier_merge_inner(
        request,
        BarrierMergeMode::PcsRefresh,
        allow_pending_recovery,
    )
    .await
}

pub(super) async fn perform_join_finalize_inner(
    request: LeaveRequest,
) -> Result<PublishedBarrierMerge> {
    perform_barrier_merge_inner(request, BarrierMergeMode::JoinFinalize, true).await
}

async fn perform_barrier_merge_inner(
    request: LeaveRequest,
    mode: BarrierMergeMode,
    allow_pending_recovery: bool,
) -> Result<PublishedBarrierMerge> {
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
        current_global_history_attestation_bytes,
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
        if join_finalize_auth_token == [0u8; 32] {
            return Err(anyhow!(
                "cannot originate join_finalize without server-issued join_finalize auth token"
            ));
        }
        header.insert(
            hdr::HDR_JOIN_FINALIZE_AUTH,
            Value::Bytes(join_finalize_auth_token.to_vec()),
        );
    }

    let cat_arr = bytes32("cat", &cat)?;
    let pox_r_commit_arr = bytes32("pox_r_commit", &pox_r_commit)?;

    let pop_secret =
        Box::new(dilithium5::SecretKey::from_bytes(&pop_secret_key).context("invalid POP key")?);

    let witness_bytes = if witness_cbor.is_empty() {
        None
    } else {
        Some(witness_cbor.as_slice())
    };

    let parities = hydrate_parities(&raw_parities, fs_ec, fs_epoch_commit, fs_dev_prev_commit);

    let pivot = select_pivot_parity(&parities)
        .ok_or_else(|| anyhow!("merge ticket did not include any pivot parities"))?;
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
            "barrier snapshot-auth history commitment mismatch (960.9): snapshot / joins / revoked leaves do not share one authenticated current-state commitment"
        ));
    }
    let mut snapshot_pre = barrier_tree_snapshot.pk_entries.clone();
    apply_join_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        join_resolution.records.as_slice(),
    )?;
    apply_revoked_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        revoked_resolution.leaf_indices.as_slice(),
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
    }
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
            current_history_commitment: Some(ticket_history_commitment.clone()),
            current_history_authority_extension: ticket_history_authority_extension,
            current_global_history_attestation_bytes: current_global_history_attestation_bytes
                .clone(),
            fs_ec,
            fs_dev_prev_commit,
        }),
    };

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

    #[derive(Clone)]
    struct PreparedBarrierMerge {
        bundle: ClientEpochBundle,
        pending_barrier_state: BarrierPendingState,
        forward_state_after: ForwardSecrecyState,
    }

    let pending_barrier_state_template = pending_barrier_state.clone();
    let build_published_merge = |mut forward_state: ForwardSecrecyState,
                                 disable_autonomic_evolve: bool|
     -> Result<PreparedBarrierMerge> {
        let mut bundle = if disable_autonomic_evolve {
            CityGClient::generate_merge_with_forward_state_without_evolve(
                header.clone(),
                parts.clone(),
                params.clone(),
                Some(&mut forward_state),
                &parities,
                None,
                witness_bytes,
            )
        } else {
            CityGClient::generate_merge_with_forward_state(
                header.clone(),
                parts.clone(),
                params.clone(),
                Some(&mut forward_state),
                &parities,
                None,
                witness_bytes,
            )
        }
        .context(mode.build_bundle_context())?;

        strip_rollup_metadata(&mut bundle.header_map);
        apply_pivot_alignment(&mut bundle.header_map, pivot);
        let anchor_ctx =
            build_anchor_seed_ctx(&bundle.header_map).context("compute anchor seed ctx")?;
        let seed_ctx_hash = compute_seed_ctx_hash(&anchor_ctx).context("compute seed_ctx_hash")?;
        let seed_commit = compute_seed_commit(
            &anchor_ctx,
            &SeedCommitFields {
                gid: &gid,
                cat: cat_arr.as_slice(),
                we_epoch_id: bundle.we_epoch_id,
            },
        )
        .context("compute seed_commit")?;
        let seed_bundle_commit = compute_seed_bundle_commit(
            &anchor_ctx,
            &bundle.hp_binding.rho_commit,
            &gid,
            cat_arr.as_slice(),
            &parent_root_arr,
        )
        .context("compute seed_bundle_commit")?;
        let derived_we_epoch_id = derive_we_epoch_id(&gid, &parent_root_arr, &seed_ctx_hash)
            .context("derive we_epoch_id")?;
        let observed_fs_ec = header_u64(&bundle.header_map, hdr::HDR_FS_EC)
            .ok_or_else(|| anyhow!("{} merge bundle missing fs_ec", mode.label()))?;
        let k_fs_after_pcs = if mode.reseeds_k_fs() {
            Some(derive_k_fs_after_pcs(
                &k_fs_current,
                &derived_we_epoch_id,
                observed_fs_ec,
                next_barrier_version,
                &barrier_update.k_barrier_new,
            )?)
        } else {
            None
        };

        bundle.anchor.anchor_hdr_ctx = anchor_ctx.clone();
        bundle.hp_binding.seed_ctx_hash = seed_ctx_hash;
        bundle.hp_binding.seed_commit = seed_commit;
        bundle.hp_binding.seed_bundle_commit = seed_bundle_commit;
        bundle.we_epoch_id = derived_we_epoch_id;
        let has_local_hp_material =
            !bundle.hp_ciphertext.is_empty() && bundle.hp_aead_key != [0u8; 32];
        if has_local_hp_material {
            if mode.reason() == 2 {
                bundle
                    .seal_local_hp_header_with_barrier_key(&barrier_update.k_barrier_new)
                    .context(format!("seal merge HP envelope for {}", mode.label()))?;
            } else {
                bundle
                    .rebind_local_hp_envelope_with_barrier_key(&barrier_update.k_barrier_new)
                    .context(format!("rebind merge HP envelope for {}", mode.label()))?;
            }
        } else {
            return Err(anyhow!(
                "{} merge bundle missing local HP material",
                mode.label()
            ));
        }
        let mut pending_barrier_state = pending_barrier_state_template.clone();
        pending_barrier_state.we_epoch_id = bundle.we_epoch_id;
        pending_barrier_state.fs_ec = observed_fs_ec;
        let next_forward = forward_state.snapshot();
        pending_barrier_state.next_forward_fs_ec = next_forward.fs_ec;
        pending_barrier_state.next_forward_fs_dev_commit = next_forward.fs_dev_commit;
        pending_barrier_state.next_forward_last_weid = next_forward.last_weid;
        if let Some(k_fs_after_pcs) = k_fs_after_pcs {
            pending_barrier_state.k_fs_after_pcs = Some(Zeroizing::new(k_fs_after_pcs));
        }
        bundle
            .header_map
            .insert(hdr::HDR_SEED_CTX_HASH, Value::Bytes(seed_ctx_hash.to_vec()));
        bundle.header_map.insert(
            hdr::HDR_RHO_COMMIT,
            Value::Bytes(bundle.hp_binding.rho_commit.to_vec()),
        );
        bundle.header_map.insert(
            hdr::HDR_SEED_BUNDLE_COMMIT,
            Value::Bytes(seed_bundle_commit.to_vec()),
        );

        if let Some(commit) = recompute_srx_commit(&bundle.header_map)? {
            bundle
                .header_map
                .insert(hdr::HDR_SRX_COMMIT, Value::Bytes(commit.to_vec()));
        }

        if let Some(recomputed) = recompute_proofs_commit(&bundle.header_map)
            .ok()
            .map(|arr| arr.to_vec())
        {
            bundle
                .header_map
                .insert(hdr::HDR_PROOFS_COMMIT, Value::Bytes(recomputed));
        }

        Ok(PreparedBarrierMerge {
            bundle,
            pending_barrier_state,
            forward_state_after: forward_state,
        })
    };

    let pristine_forward_state = forward_state.clone();
    let mut prepared = build_published_merge(forward_state, false)?;

    persist_pending_barrier_state_before_publish(
        &persist_request,
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
            warn!("refresh pivot skipped: {message}");
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
                &persist_request,
                prepared.pending_barrier_state.clone(),
            )?;
            match client.refresh_pivot(&prepared.bundle).await {
                Ok(_) => {}
                Err(ApiClientError::HttpStatus {
                    status, message, ..
                }) if is_refresh_pivot_conflict(status.as_u16(), &message) => {
                    warn!("refresh pivot skipped after stale-group retry: {message}");
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
        fs_forward_leap_policy: FsForwardLeapPolicy {
            h: fs_forward_leap_policy.h,
            checkpoint_interval: fs_forward_leap_policy.checkpoint_interval,
            slack_anchor: fs_forward_leap_policy.slack_anchor,
            slack_first_device: fs_forward_leap_policy.slack_first_device,
            slack_device: fs_forward_leap_policy.slack_device,
        },
        last_accepted_ec,
        current_public_tree: barrier_update.snapshot_post.clone(),
    })
}
