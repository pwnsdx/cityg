use super::*;

pub(super) fn ensure_epoch_sync_pending_bundle_has_authenticated_source(
    validation_session: &AppSession,
    authored_by_local_device: bool,
    pending_bundle_match: bool,
    header_map: &BTreeMap<u64, Value>,
) -> Result<()> {
    if !authored_by_local_device || !pending_bundle_match {
        return Ok(());
    }
    if !header_map.contains_key(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION) {
        return Ok(());
    }
    if validation_session
        .barrier_state
        .current_global_history_attestation_bytes
        .is_empty()
        || validation_session
            .barrier_state
            .current_history_authority_extension
            .is_none()
    {
        return Err(anyhow!(
            "epoch sync cannot validate a local pending authority-bound barrier bundle without authenticated pre-publish authority state (960.7)"
        ));
    }
    Ok(())
}

pub(super) fn validate_epoch_sync_barrier_bundle(
    session: &AppSession,
    bundle: &ClientEpochBundle,
    pending_history_outcome: PendingBarrierHistoryOutcome,
) -> Result<()> {
    let has_barrier_update = matches!(
        bundle.header_map.get(&hdr::HDR_BARRIER_UPDATE),
        Some(Value::Bytes(_))
    );
    if !has_barrier_update {
        return Ok(());
    }

    let bundle_digest = extract_barrier_update_digest(&bundle.header_map)?;
    let pending_bundle_match = session
        .barrier_state
        .pending
        .as_ref()
        .is_some_and(|pending| {
            bundle_digest == Some(pending.barrier_update_digest)
                || bundle.we_epoch_id == pending.we_epoch_id
        });
    let authored_by_local_device = bundle_authored_by_local_device(session, &bundle.header_map);
    let mut validation_session = session.clone();
    if authored_by_local_device
        && let Some(pending) = session.barrier_state.pending.as_ref()
        && pending_bundle_match
        && let Some(source) = pending.activation_source.as_ref()
    {
        if let Some(history_commitment) = source.current_history_commitment {
            install_authenticated_current_state(
                &mut validation_session,
                source.barrier_version,
                source.barrier_roots_hash,
                source.kem_tree_hash_after,
                history_commitment,
                source.current_history_authority_extension,
                source.current_global_history_attestation_bytes.clone(),
            );
        } else {
            validation_session.barrier_state.barrier_version = source.barrier_version;
            validation_session.barrier_state.barrier_roots_hash = source.barrier_roots_hash;
            validation_session.barrier_state.kem_tree_hash_after = source.kem_tree_hash_after;
            validation_session.barrier_state.current_history_view_id = [0u8; 32];
            validation_session.barrier_state.current_history_commitment = None;
            validation_session
                .barrier_state
                .current_history_authority_extension = None;
            validation_session
                .barrier_state
                .current_global_history_attestation_bytes =
                source.current_global_history_attestation_bytes.clone();
        }
    }
    ensure_epoch_sync_pending_bundle_has_authenticated_source(
        &validation_session,
        authored_by_local_device,
        pending_bundle_match,
        &bundle.header_map,
    )?;
    if pending_bundle_match
        || !matches!(
            pending_history_outcome,
            PendingBarrierHistoryOutcome::Activated(_)
        )
    {
        validate_client_visible_activation_guards(&validation_session, &bundle.header_map)?;
    }
    Ok(())
}

pub(super) async fn reconcile_epoch_sync_barrier_bundle(
    client: &CitygApiClient,
    session: &mut AppSession,
    bundle: &ClientEpochBundle,
    activation_source_before_sync: &BarrierPendingActivationSource,
    pending_history_outcome: PendingBarrierHistoryOutcome,
    ticket_barrier_version: u64,
    ticket_kem_tree_hash_after: [u8; 32],
    ticket_max_barrier_update_bytes: usize,
) -> Result<()> {
    let has_barrier_update = matches!(
        bundle.header_map.get(&hdr::HDR_BARRIER_UPDATE),
        Some(Value::Bytes(_))
    );
    let accepted_digest = extract_barrier_update_digest(&bundle.header_map)?;
    let observed_fs_ec = header_u64(&bundle.header_map, hdr::HDR_FS_EC);
    let observed_barrier_update_reason =
        header_u64(&bundle.header_map, hdr::HDR_BARRIER_UPDATE_REASON);
    let pending_changed_with_bundle = apply_pending_barrier_activation_with_source(
        session,
        activation_source_before_sync,
        ticket_barrier_version,
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
            client,
            room_id.as_str(),
            session,
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
                    ticket_barrier_version,
                    "barrier version gap crosses an unauthenticated pcs_refresh boundary; entering recovery-required state"
                );
                enter_barrier_recovery_required(
                    session,
                    BarrierRecoveryIssue::InsufficientAuthenticatedHistory,
                )?;
            } else {
                warn!(
                    local_barrier_version = session.barrier_state.barrier_version,
                    ticket_barrier_version,
                    "barrier version gap detected; attempting best-effort recovery"
                );
                match try_recover_barrier_best_effort(
                    session,
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
                            ticket_barrier_version
                        );
                        apply_recovered_barrier_state(session, recovered, false)?;
                    }
                    Ok(None) => {
                        warn!(
                            "best-effort barrier recovery produced no match; entering barrier_recovery_pending"
                        );
                        enter_barrier_recovery_pending(session)?;
                    }
                    Err(err)
                        if err
                            .to_string()
                            .contains("candidate unwrap/decrypt failure (960.7)") =>
                    {
                        warn!(
                            detail = %err,
                            "best-effort barrier recovery could not decrypt candidate; entering barrier_recovery_pending"
                        );
                        enter_barrier_recovery_pending(session)?;
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
                session,
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
                    apply_recovered_barrier_state(session, recovered, true)?;
                    install_current_public_tree_cache(
                        session,
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

    Ok(())
}
