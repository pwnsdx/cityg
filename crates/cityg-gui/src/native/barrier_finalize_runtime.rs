use super::epoch_sync::perform_epoch_sync;
use super::*;

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
            if reloaded.gid == session.gid && reloaded.leaf_id == session.leaf_id =>
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
            let mut sync = perform_epoch_sync(persisted)
                .await
                .context(mode.fallback_sync_context())?;
            if sync.session.barrier_state.barrier_recovery_pending {
                return Err(anyhow!(mode.still_pending_message()));
            }
            sync.session.barrier_state.pending = None;
            persist_activated_joined_session(&sync.session).context(mode.persist_context())?;
            Ok(sync.session)
        }
    }
}

pub(super) fn apply_local_published_barrier_merge(
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

pub(super) fn ensure_full_barrier_verification_for_origin(
    barrier_recovery_pending: bool,
    current_barrier_full_verified: bool,
) -> Result<()> {
    cityg_client::barrier_state_auth::ensure_full_barrier_verification_for_origin(
        barrier_recovery_pending,
        current_barrier_full_verified,
    )
}

pub(super) fn ensure_supported_attested_current_state_extension(
    context: &str,
    extension: Option<HistoryAuthorityExtension>,
    current_global_history_attestation_bytes: &[u8],
) -> Result<()> {
    cityg_api_client::ensure_supported_attested_current_state_extension(
        context,
        extension,
        current_global_history_attestation_bytes,
    )
    .map_err(anyhow::Error::from)
}

pub(super) async fn ensure_join_finalize_bootstrap_verified(
    request: &LeaveRequest,
) -> Result<bool> {
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
