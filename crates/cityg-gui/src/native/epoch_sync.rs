use std::{future::Future, pin::Pin};

use super::*;
use cityg_client::join_bundle::parse_accepted_bundle_runtime_state;

pub(super) fn perform_epoch_sync(
    session: AppSession,
) -> Pin<Box<dyn Future<Output = Result<EpochSyncOutcome>> + Send>> {
    Box::pin(perform_epoch_sync_inner(session))
}

async fn perform_epoch_sync_inner(mut session: AppSession) -> Result<EpochSyncOutcome> {
    let client = new_api_client(&session.server_url);
    let ticket = client
        .merge_ticket_refresh_with_retry(&session.room_id, &session.leaf_id)
        .await
        .context("failed to fetch merge ticket for epoch sync")?;
    let prepared_runtime = ticket
        .prepare_epoch_sync_runtime(cityg_api_client::PrepareEpochSyncMergeTicketInput {
            local_barrier_version: session.barrier_state.barrier_version,
            local_kem_tree_hash_after: session.barrier_state.kem_tree_hash_after,
            local_current_history_commitment: session
                .barrier_state
                .current_history_commitment
                .as_ref(),
            local_current_history_authority_extension: session
                .barrier_state
                .current_history_authority_extension,
            fs_ec: session.fs_ec,
            fs_epoch_commit: session.fs_epoch_commit,
            fs_dev_prev_commit: session.fs_dev_prev_commit,
            stored_max_barrier_update_bytes: session.barrier_state.max_barrier_update_bytes,
        })
        .map_err(anyhow::Error::from)?;
    let ticket_kem_tree_hash_after = prepared_runtime.snapshot_hash;
    let ticket_history_commitment = prepared_runtime.ticket_history_commitment;
    let ticket_n_max = prepared_runtime.barrier_n_max;
    let ticket_max_barrier_update_bytes_u64 = prepared_runtime.max_barrier_update_bytes;
    let ticket_max_barrier_update_bytes = prepared_runtime.max_barrier_update_bytes_normalized;
    let ticket_cover_leaf_index = prepared_runtime.cover_leaf_index;
    let ticket_slot_generation = prepared_runtime.slot_generation;
    let ticket_barrier_roots_hash = prepared_runtime.ticket_barrier_roots_hash;
    let previous_we_epoch_id = session.we_epoch_id;
    let activation_source_before_sync = capture_barrier_pending_activation_source(&session);
    session.fs_forward_leap_policy = FsForwardLeapPolicy {
        h: prepared_runtime.fs_forward_leap_policy.h,
        checkpoint_interval: prepared_runtime.fs_forward_leap_policy.checkpoint_interval,
        slack_anchor: prepared_runtime.fs_forward_leap_policy.slack_anchor,
        slack_first_device: prepared_runtime.fs_forward_leap_policy.slack_first_device,
        slack_device: prepared_runtime.fs_forward_leap_policy.slack_device,
    };
    session.last_accepted_ec = session
        .last_accepted_ec
        .max(prepared_runtime.last_accepted_ec);
    session.barrier_state.max_barrier_update_bytes = ticket_max_barrier_update_bytes_u64;
    session.barrier_state.n_max = ticket_n_max;
    session.barrier_state.cover_leaf_index = ticket_cover_leaf_index;
    session.barrier_state.slot_generation = ticket_slot_generation;
    let pending_history_outcome = apply_pending_barrier_activation_from_history(
        &client,
        &mut session,
        prepared_runtime.barrier_version,
    )
    .await?;
    let barrier_changed = session.barrier_state.barrier_version != prepared_runtime.barrier_version
        || session.barrier_state.kem_tree_hash_after != ticket_kem_tree_hash_after
        || session.barrier_state.max_barrier_update_bytes != ticket_max_barrier_update_bytes_u64
        || session.barrier_state.n_max != ticket_n_max
        || session.barrier_state.cover_leaf_index != ticket_cover_leaf_index
        || session.barrier_state.slot_generation != ticket_slot_generation;

    if let Some(pivot) = select_pivot_parity(&prepared_runtime.parities) {
        session.xk_hash = pivot.xk_hash;
    }

    if prepared_runtime.we_epoch_id == session.we_epoch_id {
        session.last_accepted_ec = session
            .last_accepted_ec
            .max(prepared_runtime.last_accepted_ec);
        install_authenticated_current_state(
            &mut session,
            prepared_runtime.barrier_version,
            ticket_barrier_roots_hash,
            ticket_kem_tree_hash_after,
            ticket_history_commitment,
            prepared_runtime.ticket_history_authority_extension,
            prepared_runtime
                .current_global_history_attestation_bytes
                .clone(),
        );
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
        .get_bundle(&prepared_runtime.we_epoch_id)
        .await
        .context("failed to fetch latest epoch bundle")?;
    let mut bundle = ClientEpochBundle::from_cbor(&bundle_response.bundle_cbor)
        .context("failed to decode latest epoch bundle")?;

    if bundle.we_epoch_id != prepared_runtime.we_epoch_id {
        return Err(anyhow!(
            "merge ticket/bundle mismatch: ticket={} bundle={}",
            hex_encode(prepared_runtime.we_epoch_id),
            hex_encode(bundle.we_epoch_id)
        ));
    }

    if let Some(witness_bytes) = prepared_runtime.witness_bytes {
        bundle.witness = Some(witness_bytes);
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
    validate_epoch_sync_barrier_bundle(&session, &bundle, pending_history_outcome)?;

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

    let accepted_bundle = parse_accepted_bundle_runtime_state(
        &bundle,
        session.fs_policy_version.as_str(),
        session.fs_epoch_base_ts,
    )?;
    let local_bundle = bundle_authored_by_local_device(&session, &bundle.header_map);
    session.fs_ec = accepted_bundle.fs_ec;
    session.last_accepted_ec = session.last_accepted_ec.max(accepted_bundle.fs_ec);
    session.fs_epoch_commit = accepted_bundle.fs_epoch_commit;
    if local_bundle && let Some(commit) = accepted_bundle.fs_dev_prev_commit {
        session.fs_dev_prev_commit = commit;
    }
    session.fs_epoch_base_ts = accepted_bundle.fs_epoch_base_ts;
    session.fs_policy_version = accepted_bundle.fs_policy_version;
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

    Box::pin(reconcile_epoch_sync_barrier_bundle(
        &client,
        &mut session,
        &bundle,
        &activation_source_before_sync,
        pending_history_outcome,
        prepared_runtime.barrier_version,
        ticket_kem_tree_hash_after,
        ticket_max_barrier_update_bytes,
    ))
    .await?;

    if defer_epoch_derivation && !session.barrier_state.barrier_recovery_pending {
        let (epoch_key, _) = bundle
            .derive_epoch_secrets_with_barrier_key(&session.barrier_state.k_barrier)
            .context("failed to derive epoch key during sync from recovered barrier state")?;
        session.epoch_key = epoch_key;
    }
    install_authenticated_current_state(
        &mut session,
        prepared_runtime.barrier_version,
        ticket_barrier_roots_hash,
        ticket_kem_tree_hash_after,
        ticket_history_commitment,
        prepared_runtime.ticket_history_authority_extension,
        prepared_runtime
            .current_global_history_attestation_bytes
            .clone(),
    );
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

    session.regular_fingerprint = Some(accepted_bundle.seed_ctx_hash);
    session.fs_fingerprint = accepted_bundle.fs_fingerprint;
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
        changed: previous_we_epoch_id != prepared_runtime.we_epoch_id
            || barrier_changed
            || !matches!(
                pending_history_outcome,
                PendingBarrierHistoryOutcome::Unchanged
            ),
    })
}
