use super::*;
use crate::barrier_shared::require_current_state_history_commitment;
use cityg_api_client::{
    to_core_history_commitment, to_core_join_snapshot_records, to_core_revoked_snapshot_records,
};
use cityg_client::barrier::BarrierSlotLease as CoreBarrierSlotLease;
use cityg_client::barrier_prevalidation::{
    BootstrapCurrentStateInput, prevalidate_bootstrap_current_state, prevalidate_full_chain_update,
    validate_bootstrap_provisioning, validate_full_chain_reason,
};
use cityg_client::barrier_transition::compute_barrier_snapshot_transition;
use cityg_client::barrier_update::parse_barrier_update_for_recover;

#[derive(Clone, Debug)]
pub(super) struct FullChainCheckResult {
    pub(super) expected_before: [u8; 32],
    pub(super) snapshot_post: Arc<BarrierPublicTree>,
}

pub(super) async fn full_chain_check_barrier_update(
    client: &CitygApiClient,
    room_id: &str,
    session: &mut AppSession,
    header_map: &BTreeMap<u64, Value>,
    raw_update: &[u8],
    max_barrier_update_bytes: usize,
) -> Result<FullChainCheckResult> {
    let n_max = session.barrier_state.n_max.max(1);
    let parsed = parse_barrier_update_for_recover(raw_update, n_max, max_barrier_update_bytes)
        .map_err(|err| anyhow!("barrier full chain-check prevalidation failed (960.7): {err}"))?;
    let local_barrier_version = session.barrier_state.barrier_version;
    let local_barrier_initialized = session.barrier_state.barrier_initialized;
    let barrier_reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON).ok_or_else(|| {
        anyhow!("barrier full chain-check prevalidation failed (960.7): missing barrier_update_reason")
    })?;
    let (snapshot_prev, snapshot_prev_history_commitment) =
        resolve_authenticated_snapshot_for_hash(
            client,
            room_id,
            session,
            &parsed.kem_tree_hash_before,
            n_max,
        )
        .await?;

    let revoked_since_root =
        header_bytes32(header_map, hdr::HDR_REVOKED_SINCE_ROOT).ok_or_else(|| {
            anyhow!(
                "barrier full chain-check prevalidation failed (960.7): missing revoked_since_root"
            )
        })?;
    let revoked_root = header_bytes32(header_map, hdr::HDR_REVOKED_ROOT).ok_or_else(|| {
        anyhow!("barrier full chain-check prevalidation failed (960.7): missing revoked_root")
    })?;
    let prevalidated = prevalidate_full_chain_update(
        &parsed,
        local_barrier_initialized,
        local_barrier_version,
        revoked_since_root,
        revoked_root,
    )?;
    let join_resolution = client
        .barrier_resolve_joins_since(room_id, parsed.prev_barrier_version)
        .await
        .map_err(|err| anyhow!("barrier full chain-check dependency failure (960.8): {err}"))?;
    let revoked_resolution = client
        .barrier_resolve_revoked_leaves(room_id, &prevalidated.revocation_roots_hash)
        .await
        .map_err(|err| anyhow!("barrier full chain-check dependency failure (960.8): {err}"))?;
    let join_record_count = join_resolution.records.len();
    let revoked_record_count = revoked_resolution.records.len();
    let (snapshot_prev, snapshot_prev_history_commitment) =
        ensure_current_state_commitment_aligned_snapshot(
            client,
            room_id,
            &prevalidated.expected_snapshot_hash,
            n_max,
            snapshot_prev,
            snapshot_prev_history_commitment,
            &join_resolution.history_commitment,
            &revoked_resolution.history_commitment,
        )
        .await?;
    if require_current_state_history_commitment(
        &snapshot_prev_history_commitment,
        &join_resolution.history_commitment,
        &revoked_resolution.history_commitment,
    )
    .is_err()
    {
        return Err(anyhow!(
            "barrier full chain-check prevalidation failed (960.9): before={} snapshot={}#{} joins={}#{} revoked={}#{}",
            hex_encode(parsed.kem_tree_hash_before),
            hex_encode(snapshot_prev_history_commitment.history_commitment_id),
            snapshot_prev_history_commitment.history_seq,
            hex_encode(join_resolution.history_commitment.history_commitment_id),
            join_resolution.history_commitment.history_seq,
            hex_encode(revoked_resolution.history_commitment.history_commitment_id),
            revoked_resolution.history_commitment.history_seq,
        ));
    }

    let join_records_core = to_core_join_snapshot_records(join_resolution.records.as_slice());
    validate_full_chain_reason(
        prevalidated.genesis_local_case,
        session.barrier_state.barrier_roots_hash,
        parsed.revocation_roots_hash,
        barrier_reason,
        join_records_core.as_slice(),
        CoreBarrierSlotLease {
            slot_index: parsed.updater_leaf,
            slot_generation: parsed.updater_slot_generation,
        },
    )?;

    let parsed_for_hash = parsed.clone();
    let snapshot_prev_entries = snapshot_prev.pk_entries.clone();
    let revoked_records_core =
        to_core_revoked_snapshot_records(revoked_resolution.records.as_slice());
    let (expected_before, expected_after, snapshot_post) =
        tokio::task::spawn_blocking(move || -> Result<([u8; 32], [u8; 32], BarrierPublicTree)> {
            let transition = compute_barrier_snapshot_transition(
                n_max,
                snapshot_prev_entries.as_slice(),
                join_records_core.as_slice(),
                revoked_records_core.as_slice(),
                &parsed_for_hash,
            )?;
            Ok((
                transition.expected_before,
                transition.expected_after,
                BarrierPublicTree {
                    n_max,
                    kem_tree_hash_after: transition.expected_after,
                    pk_entries: transition.snapshot_post_entries,
                },
            ))
        })
        .await
        .map_err(|err| anyhow!("barrier full chain-check worker join failure (960.8): {err}"))??;

    if expected_before != parsed.kem_tree_hash_before {
        warn!(
            local_barrier_version,
            parsed_prev_barrier_version = parsed.prev_barrier_version,
            parsed_barrier_version = parsed.barrier_version,
            join_record_count,
            revoked_record_count,
            expected_before = %hex_encode(expected_before),
            parsed_before = %hex_encode(parsed.kem_tree_hash_before),
            snapshot_prev_hash = %hex_encode(prevalidated.expected_snapshot_hash),
            "barrier full chain-check pre-state hash mismatch"
        );
        return Err(anyhow!(
            "barrier tree hash-chain failure (960.8): kem_tree_hash_before mismatch"
        ));
    }
    if expected_after != parsed.kem_tree_hash_after {
        return Err(anyhow!(
            "barrier tree hash-chain failure (960.8): kem_tree_hash_after mismatch"
        ));
    }

    Ok(FullChainCheckResult {
        expected_before,
        snapshot_post: Arc::new(snapshot_post),
    })
}

pub(super) async fn verify_join_finalize_bootstrap_current_state(
    client: &CitygApiClient,
    room_id: &str,
    session: &mut AppSession,
) -> Result<()> {
    let expected_commitment = session
        .barrier_state
        .bootstrap_history_commitment
        .ok_or_else(|| anyhow!("join_finalize bootstrap missing current_history_commitment"))?;
    let expected_extension = session.barrier_state.current_history_authority_extension;
    let current_commitment = session
        .barrier_state
        .current_history_commitment
        .as_ref()
        .ok_or_else(|| {
            anyhow!("join_finalize bootstrap missing local current_history_commitment")
        })?;
    let predecessor_hash = session
        .barrier_state
        .bootstrap_predecessor_kem_tree_hash_after;
    let n_max = session.barrier_state.n_max.max(1);
    let expected_commitment_core = to_core_history_commitment(&expected_commitment);
    let current_commitment_core = to_core_history_commitment(current_commitment);
    let parsed = prevalidate_bootstrap_current_state(BootstrapCurrentStateInput {
        expected_commitment: &expected_commitment_core,
        current_commitment: &current_commitment_core,
        expected_extension_present: expected_extension.is_some(),
        current_global_history_attestation_bytes: session
            .barrier_state
            .current_global_history_attestation_bytes
            .as_slice(),
        predecessor_hash,
        raw_update: session
            .barrier_state
            .bootstrap_current_barrier_update
            .as_slice(),
        local_barrier_version: session.barrier_state.barrier_version,
        local_kem_tree_hash_after: session.barrier_state.kem_tree_hash_after,
        local_n_max: session.barrier_state.n_max,
        local_max_barrier_update_bytes: session.barrier_state.max_barrier_update_bytes,
    })?;

    let current_snapshot =
        resolve_bootstrap_current_snapshot(client, room_id, session, n_max).await?;
    if current_snapshot.n_max != n_max {
        return Err(anyhow!(
            "join_finalize bootstrap snapshot auth failure (960.9): current n_max mismatch"
        ));
    }
    validate_barrier_tree_snapshot_auth(
        &session.barrier_state.kem_tree_hash_after,
        n_max,
        &current_snapshot,
    )?;
    // The provisioned current barrier_update bytes already bind the current
    // tree hash. After the JOIN itself is accepted, the same current tree can
    // legitimately be re-attested under a later local HistoryCommitment.

    let snapshot_base = resolve_bootstrap_predecessor_snapshot(
        client,
        room_id,
        session,
        &predecessor_hash,
        parsed.prev_barrier_version,
        n_max,
    )
    .await?;
    if snapshot_base.n_max != n_max {
        return Err(anyhow!(
            "join_finalize bootstrap snapshot auth failure (960.9): predecessor n_max mismatch"
        ));
    }
    validate_barrier_tree_snapshot_auth(&predecessor_hash, n_max, &snapshot_base)?;

    let join_records = session.barrier_state.bootstrap_join_records.clone();
    let revoked_records = session.barrier_state.bootstrap_revoked_records.clone();
    let join_records_core = to_core_join_snapshot_records(join_records.as_slice());
    let revoked_records_core = to_core_revoked_snapshot_records(revoked_records.as_slice());
    validate_bootstrap_provisioning(
        join_records_core.as_slice(),
        revoked_records_core.as_slice(),
        &parsed,
    )?;

    let parsed_for_hash = parsed.clone();
    let snapshot_base_entries = snapshot_base.pk_entries.clone();
    let (expected_before, expected_after) =
        tokio::task::spawn_blocking(move || -> Result<([u8; 32], [u8; 32])> {
            let transition = compute_barrier_snapshot_transition(
                n_max,
                snapshot_base_entries.as_slice(),
                join_records_core.as_slice(),
                revoked_records_core.as_slice(),
                &parsed_for_hash,
            )?;
            Ok((transition.expected_before, transition.expected_after))
        })
        .await
        .map_err(|err| anyhow!("join_finalize bootstrap worker join failure (960.8): {err}"))??;

    if expected_before != parsed.kem_tree_hash_before {
        return Err(anyhow!(
            "join_finalize bootstrap hash-chain failure (960.8): kem_tree_hash_before mismatch"
        ));
    }
    if expected_after != parsed.kem_tree_hash_after {
        return Err(anyhow!(
            "join_finalize bootstrap hash-chain failure (960.8): kem_tree_hash_after mismatch"
        ));
    }

    install_current_public_tree_cache(session, current_snapshot)?;
    retain_authenticated_current_public_tree(session)?;

    Ok(())
}
