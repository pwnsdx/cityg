use super::*;

pub(super) async fn perform_epoch_sync(mut session: AppSession) -> Result<EpochSyncOutcome> {
    let client = new_api_client(&session.server_url);
    let mut retry_attempt = 0u32;
    let ticket = loop {
        match client
            .merge_ticket_refresh(&session.room_id, &session.leaf_id)
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
                        "merge_ticket_refresh race/concurrency rejection during epoch sync; retrying"
                    );
                    sleep(delay).await;
                    continue;
                }

                return Err(err).context("failed to fetch merge ticket for epoch sync");
            }
        }
    };
    let ticket_kem_tree_hash_after = bytes32("kem_tree_hash_after", &ticket.kem_tree_hash_after)?;
    let ticket_history_commitment = ticket.current_history_commitment.clone();
    let ticket_n_max = validate_barrier_n_max(if ticket.n_max == 0 {
        DEFAULT_BARRIER_N_MAX
    } else {
        ticket.n_max
    })?;
    let ticket_max_barrier_update_bytes_u64 = ticket.max_barrier_update_bytes.max(1);
    let ticket_max_barrier_update_bytes =
        normalize_max_barrier_update_bytes(ticket_max_barrier_update_bytes_u64)?;
    if session.barrier_state.max_barrier_update_bytes != 0
        && session.barrier_state.max_barrier_update_bytes != ticket_max_barrier_update_bytes_u64
    {
        return Err(anyhow!(
            "max_barrier_update_bytes mismatch: local={} server={}",
            session.barrier_state.max_barrier_update_bytes,
            ticket_max_barrier_update_bytes_u64
        ));
    }
    if ticket.cover_leaf_index >= ticket_n_max {
        return Err(anyhow!(
            "merge ticket cover_leaf_index out of range: {} >= {}",
            ticket.cover_leaf_index,
            ticket_n_max
        ));
    }
    ensure_non_regressing_authenticated_current_state(
        session.barrier_state.barrier_version,
        &session.barrier_state.kem_tree_hash_after,
        session.barrier_state.current_history_commitment.as_ref(),
        ticket.barrier_version,
        &ticket_kem_tree_hash_after,
        &ticket_history_commitment,
        "epoch sync merge ticket",
    )?;
    let previous_we_epoch_id = session.we_epoch_id;
    let activation_source_before_sync = capture_barrier_pending_activation_source(&session);
    session.fs_forward_leap_policy = FsForwardLeapPolicy {
        h: ticket.fs_forward_leap_policy.h,
        checkpoint_interval: ticket.fs_forward_leap_policy.checkpoint_interval,
        slack_anchor: ticket.fs_forward_leap_policy.slack_anchor,
        slack_first_device: ticket.fs_forward_leap_policy.slack_first_device,
        slack_device: ticket.fs_forward_leap_policy.slack_device,
    };
    session.last_accepted_ec = session.last_accepted_ec.max(ticket.last_accepted_ec);
    session.barrier_state.max_barrier_update_bytes = ticket_max_barrier_update_bytes_u64;
    session.barrier_state.n_max = ticket_n_max;
    session.barrier_state.cover_leaf_index = ticket.cover_leaf_index;
    let pending_history_outcome = apply_pending_barrier_activation_from_history(
        &client,
        &mut session,
        ticket.barrier_version,
    )
    .await?;
    let barrier_changed = session.barrier_state.barrier_version != ticket.barrier_version
        || session.barrier_state.kem_tree_hash_after != ticket_kem_tree_hash_after
        || session.barrier_state.max_barrier_update_bytes != ticket_max_barrier_update_bytes_u64
        || session.barrier_state.n_max != ticket_n_max
        || session.barrier_state.cover_leaf_index != ticket.cover_leaf_index;

    if let Some(pivot) = select_pivot_parity(&ticket.parities) {
        session.xk_hash = pivot.xk_hash;
    }

    if ticket.we_epoch_id == session.we_epoch_id {
        session.last_accepted_ec = session.last_accepted_ec.max(ticket.last_accepted_ec);
        session.barrier_state.barrier_version = ticket.barrier_version;
        session.barrier_state.kem_tree_hash_after = ticket_kem_tree_hash_after;
        session.barrier_state.current_history_view_id = ticket_history_commitment.history_view_id;
        session.barrier_state.current_history_commitment = Some(ticket_history_commitment);
        session
            .barrier_state
            .current_global_history_attestation_bytes =
            ticket.current_global_history_attestation_bytes.clone();
        if !session
            .barrier_state
            .current_public_tree
            .as_ref()
            .is_some_and(|snapshot| current_public_tree_cache_matches(&session, snapshot))
        {
            clear_current_public_tree_cache(&mut session.barrier_state);
        }
        return Ok(EpochSyncOutcome {
            session,
            changed: barrier_changed
                || !matches!(
                    pending_history_outcome,
                    PendingBarrierHistoryOutcome::Unchanged
                ),
        });
    }

    let bundle_response = client
        .get_bundle(&ticket.we_epoch_id)
        .await
        .context("failed to fetch latest epoch bundle")?;
    let mut bundle = ClientEpochBundle::from_cbor(&bundle_response.bundle_cbor)
        .context("failed to decode latest epoch bundle")?;

    if bundle.we_epoch_id != ticket.we_epoch_id {
        return Err(anyhow!(
            "merge ticket/bundle mismatch: ticket={} bundle={}",
            hex_encode(ticket.we_epoch_id),
            hex_encode(bundle.we_epoch_id)
        ));
    }

    if !ticket.witness_cbor.is_empty() {
        bundle.witness = Some(ticket.witness_cbor.clone());
    }

    let uses_barrier_hp_envelope = matches!(
        bundle
            .header_map
            .get(&hdr::HDR_HP_BYTES)
            .and_then(|value| match value {
                Value::Array(items) => items.first(),
                _ => None,
            }),
        Some(Value::Text(mode)) if mode == BARRIER_HP_MODE
    );
    let has_barrier_update = matches!(
        bundle.header_map.get(&hdr::HDR_BARRIER_UPDATE),
        Some(Value::Bytes(_))
    );

    let gid = bytes32("gid", &bundle.anchor.gid)?;
    if gid != session.gid {
        return Err(anyhow!(
            "bundle gid mismatch: expected {}, got {}",
            hex_encode(session.gid),
            hex_encode(gid)
        ));
    }
    if has_barrier_update {
        validate_client_visible_activation_guards(&session, &bundle.header_map)?;
    }

    let defer_epoch_derivation = uses_barrier_hp_envelope && has_barrier_update;
    let mut derived_epoch_key = None;
    if !defer_epoch_derivation {
        let (epoch_key, _) = if uses_barrier_hp_envelope {
            bundle
                .derive_epoch_secrets_with_barrier_key(&session.barrier_state.k_barrier)
                .context("failed to derive epoch key during sync from barrier state")?
        } else {
            bundle
                .derive_epoch_secrets()
                .map_err(|err| anyhow!("failed to derive epoch key during sync: {err}"))?
        };
        derived_epoch_key = Some(epoch_key);
    }

    session.we_epoch_id = bundle.we_epoch_id;
    session.xk_hash = bundle.hp_binding.xk_hash;
    session.epoch_key = derived_epoch_key.unwrap_or([0u8; 32]);
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
    if bundle_authored_by_local_device(&session, &bundle.header_map)
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

    let accepted_digest = extract_barrier_update_digest(&bundle.header_map)?;
    let observed_fs_ec = header_u64(&bundle.header_map, hdr::HDR_FS_EC);
    let observed_barrier_update_reason =
        header_u64(&bundle.header_map, hdr::HDR_BARRIER_UPDATE_REASON);
    let pending_changed_with_bundle = apply_pending_barrier_activation_with_source(
        &mut session,
        &activation_source_before_sync,
        ticket.barrier_version,
        observed_fs_ec,
        observed_barrier_update_reason,
        accepted_digest,
    )?;
    let pending_applied = pending_changed_with_bundle
        || matches!(
            pending_history_outcome,
            PendingBarrierHistoryOutcome::Activated(we_epoch_id) if we_epoch_id == bundle.we_epoch_id
        );

    if !pending_applied && has_barrier_update {
        let raw_update = match bundle.header_map.get(&hdr::HDR_BARRIER_UPDATE) {
            Some(Value::Bytes(raw)) => raw.as_slice(),
            Some(_) => return Err(anyhow!("header barrier_update must be bytes")),
            None => return Err(anyhow!("missing barrier_update bytes")),
        };
        let room_id = session.room_id.clone();
        let chain_check_result = full_chain_check_barrier_update(
            &client,
            room_id.as_str(),
            &mut session,
            &bundle.header_map,
            raw_update,
            ticket_max_barrier_update_bytes,
        )
        .await;

        let is_version_gap = chain_check_result.as_ref().is_err_and(|err| {
            err.to_string()
                .contains("local barrier version progression mismatch")
        });
        let gap_barrier_update_reason =
            header_u64(&bundle.header_map, hdr::HDR_BARRIER_UPDATE_REASON);

        if is_version_gap {
            if gap_barrier_update_reason == Some(1) {
                warn!(
                    local_barrier_version = session.barrier_state.barrier_version,
                    ticket_barrier_version = ticket.barrier_version,
                    "barrier version gap crosses an unauthenticated pcs_refresh boundary; entering recovery-required state"
                );
                enter_barrier_recovery_required(
                    &mut session,
                    BarrierRecoveryIssue::InsufficientAuthenticatedHistory,
                )?;
            } else {
                // The local barrier state is behind by 2+ versions.  Full
                // chain-check is impossible (we missed intermediate updates), so
                // attempt a best-effort recovery using the leaf KEM key which
                // remains valid across barrier versions.
                warn!(
                    local_barrier_version = session.barrier_state.barrier_version,
                    ticket_barrier_version = ticket.barrier_version,
                    "barrier version gap detected; attempting best-effort recovery"
                );
                match try_recover_barrier_best_effort(
                    &session,
                    &bundle.header_map,
                    &session.we_epoch_id,
                    session.fs_ec,
                    ticket_max_barrier_update_bytes,
                ) {
                    Ok(Some(recovered)) => {
                        if recovered.kem_tree_hash_after != ticket_kem_tree_hash_after {
                            return Err(anyhow!(
                                "barrier recover hash-chain mismatch: recovered hash does not match merge ticket"
                            ));
                        }
                        info!(
                            "best-effort barrier recovery succeeded; caught up to barrier version {}",
                            ticket.barrier_version
                        );
                        apply_recovered_barrier_state(&mut session, recovered, false)?;
                    }
                    Ok(None) => {
                        // Cannot decrypt the current barrier update (our path was
                        // not targeted. Accept the ticket's barrier version and
                        // wait for the next barrier update that targets our leaf.
                        warn!(
                            "best-effort barrier recovery produced no match; entering barrier_recovery_pending"
                        );
                        enter_barrier_recovery_pending(&mut session)?;
                    }
                    Err(err)
                        if err
                            .to_string()
                            .contains("candidate unwrap/decrypt failure (960.7)") =>
                    {
                        // We found a candidate update on our path, but local
                        // internal node secrets are too stale to unwrap it.
                        // Preserve the accepted public state and wait for a future
                        // barrier update that targets our leaf directly.
                        warn!(
                            detail = %err,
                            "best-effort barrier recovery could not decrypt candidate; entering barrier_recovery_pending"
                        );
                        enter_barrier_recovery_pending(&mut session)?;
                    }
                    Err(err) => {
                        let detail = err.to_string();
                        if detail.contains("960.") {
                            return Err(anyhow!("barrier recover failed: {detail}"));
                        }
                        return Err(anyhow!("barrier recover failed (960.7): {detail}"));
                    }
                }
            }
        } else {
            let chain_check_result = chain_check_result?;
            match try_recover_barrier_from_header_with_expected_before(
                &session,
                &bundle.header_map,
                &session.we_epoch_id,
                session.fs_ec,
                ticket_max_barrier_update_bytes,
                Some(chain_check_result.expected_before),
            ) {
                Ok(Some(recovered)) => {
                    if recovered.kem_tree_hash_after != ticket_kem_tree_hash_after {
                        return Err(anyhow!(
                            "barrier recover hash-chain mismatch: recovered hash does not match merge ticket"
                        ));
                    }
                    apply_recovered_barrier_state(&mut session, recovered, true)?;
                    session.barrier_state.barrier_version = ticket.barrier_version;
                    session.barrier_state.kem_tree_hash_after = ticket_kem_tree_hash_after;
                    install_current_public_tree_cache(
                        &mut session,
                        (*chain_check_result.snapshot_post).clone(),
                    )?;
                }
                Ok(None) => {
                    return Err(anyhow!(
                        "barrier recover produced no match (960.6) for a barrier update"
                    ));
                }
                Err(err) => {
                    let detail = err.to_string();
                    if detail.contains("960.") {
                        return Err(anyhow!("barrier recover failed: {detail}"));
                    }
                    return Err(anyhow!("barrier recover failed (960.7): {detail}"));
                }
            }
        }
    }

    if defer_epoch_derivation && !session.barrier_state.barrier_recovery_pending {
        let (epoch_key, _) = bundle
            .derive_epoch_secrets_with_barrier_key(&session.barrier_state.k_barrier)
            .context("failed to derive epoch key during sync from recovered barrier state")?;
        session.epoch_key = epoch_key;
    }
    session.barrier_state.barrier_version = ticket.barrier_version;
    session.barrier_state.kem_tree_hash_after = ticket_kem_tree_hash_after;
    session.barrier_state.current_history_view_id = ticket_history_commitment.history_view_id;
    session.barrier_state.current_history_commitment = Some(ticket_history_commitment);
    session
        .barrier_state
        .current_global_history_attestation_bytes =
        ticket.current_global_history_attestation_bytes.clone();
    if session
        .barrier_state
        .current_public_tree
        .as_ref()
        .is_some_and(|snapshot| current_public_tree_cache_matches(&session, snapshot))
    {
        retain_authenticated_current_public_tree(&mut session)?;
    } else {
        clear_current_public_tree_cache(&mut session.barrier_state);
    }

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
    session
        .forward_state
        .set_last_we_epoch_id(session.we_epoch_id);
    session
        .forward_state
        .set_epoch_base_ts(session.fs_epoch_base_ts);

    Ok(EpochSyncOutcome {
        session,
        changed: previous_we_epoch_id != ticket.we_epoch_id
            || barrier_changed
            || !matches!(
                pending_history_outcome,
                PendingBarrierHistoryOutcome::Unchanged
            ),
    })
}
