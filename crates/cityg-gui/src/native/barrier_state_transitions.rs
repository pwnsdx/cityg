use super::*;
use cityg_client::barrier_pending::{
    PendingBarrierObservation as CorePendingBarrierObservation, pending_activation_source_matches,
    pending_barrier_matches_observation,
};

pub(super) fn clear_join_finalize_bootstrap_artifact(state: &mut BarrierSecretState) {
    state.bootstrap_history_commitment = None;
    state.bootstrap_predecessor_kem_tree_hash_after = [0u8; 32];
    state.bootstrap_join_records.clear();
    state.bootstrap_revoked_records.clear();
    state.bootstrap_join_finalize_auth_token = [0u8; 32];
    state.bootstrap_current_barrier_update.clear();
}

pub(super) fn reset_pending_history_trace(session: &mut AppSession) {
    session.barrier_state.last_pending_history_trace = None;
}

pub(super) fn record_pending_history_trace(
    session: &mut AppSession,
    trace: BarrierPendingHistoryTrace,
) {
    session.barrier_state.last_pending_history_trace = Some(trace);
}

pub(super) fn clear_barrier_recovery_issue(session: &mut AppSession) {
    session.barrier_state.barrier_recovery_issue = None;
}

pub(super) fn discard_pending_barrier_state(session: &mut AppSession) {
    session.barrier_state.pending = None;
    clear_barrier_recovery_issue(session);
}

pub(super) fn apply_recovered_barrier_state(
    session: &mut AppSession,
    recovered: BarrierRecoverResult,
    current_barrier_full_verified: bool,
) -> Result<()> {
    let BarrierRecoverResult {
        barrier_version,
        k_barrier_new,
        kem_tree_hash_after,
        k_fs_after_pcs,
        derived_node_key_material,
        ..
    } = recovered;
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.barrier_version = barrier_version;
    session.barrier_state.barrier_roots_hash =
        compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
    session.barrier_state.k_barrier = k_barrier_new;
    session.barrier_state.kem_tree_hash_after = kem_tree_hash_after;
    for (node, material) in derived_node_key_material {
        session.barrier_state.dk_nodes.insert(node, material);
    }
    if let Some(k_fs_after_pcs) = k_fs_after_pcs {
        apply_forward_state_k_fs(session, *k_fs_after_pcs);
    }
    clear_all_public_tree_caches(&mut session.barrier_state);
    session.barrier_state.barrier_recovery_pending = false;
    session.barrier_state.barrier_recovery_issue = None;
    session.barrier_state.current_barrier_full_verified = current_barrier_full_verified;
    clear_join_finalize_bootstrap_artifact(&mut session.barrier_state);
    Ok(())
}

pub(super) fn enter_barrier_recovery_pending(session: &mut AppSession) -> Result<()> {
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.barrier_roots_hash =
        compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
    clear_all_public_tree_caches(&mut session.barrier_state);
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.barrier_recovery_issue = None;
    session.barrier_state.current_barrier_full_verified = false;
    Ok(())
}

pub(super) fn enter_barrier_recovery_required(
    session: &mut AppSession,
    issue: BarrierRecoveryIssue,
) -> Result<()> {
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.barrier_roots_hash =
        compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
    clear_all_public_tree_caches(&mut session.barrier_state);
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.barrier_recovery_issue = Some(issue);
    session.barrier_state.current_barrier_full_verified = false;
    Ok(())
}

pub(super) fn mark_barrier_recovery_required(
    session: &mut AppSession,
    issue: BarrierRecoveryIssue,
) -> PendingBarrierHistoryOutcome {
    clear_all_public_tree_caches(&mut session.barrier_state);
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.barrier_recovery_issue = Some(issue);
    session.barrier_state.current_barrier_full_verified = false;
    PendingBarrierHistoryOutcome::RecoveryRequired(issue)
}

pub(super) fn apply_forward_state_k_fs(session: &mut AppSession, k_fs: [u8; 32]) {
    let snapshot = session.forward_state.snapshot();
    let mut updated_state = ForwardSecrecyState::with_state(
        k_fs,
        snapshot.fs_ec,
        session.fs_dev_prev_commit,
        session.we_epoch_id,
    );
    updated_state.set_epoch_base_ts(session.fs_epoch_base_ts);
    session.forward_state = updated_state;
}

pub(super) fn apply_forward_state_snapshot(
    session: &mut AppSession,
    k_fs: [u8; 32],
    fs_ec: u64,
    fs_dev_commit: [u8; 32],
    last_weid: [u8; 32],
) {
    let mut updated_state = ForwardSecrecyState::with_state(k_fs, fs_ec, fs_dev_commit, last_weid);
    updated_state.set_epoch_base_ts(session.fs_epoch_base_ts);
    session.forward_state = updated_state;
}

pub(super) fn capture_barrier_pending_activation_source(
    session: &AppSession,
) -> BarrierPendingActivationSource {
    BarrierPendingActivationSource {
        barrier_version: session.barrier_state.barrier_version,
        barrier_roots_hash: session.barrier_state.barrier_roots_hash,
        kem_tree_hash_after: session.barrier_state.kem_tree_hash_after,
        current_history_commitment: session.barrier_state.current_history_commitment,
        current_history_authority_extension: session
            .barrier_state
            .current_history_authority_extension,
        current_global_history_attestation_bytes: session
            .barrier_state
            .current_global_history_attestation_bytes
            .clone(),
        fs_ec: session.fs_ec,
        fs_dev_prev_commit: session.fs_dev_prev_commit,
    }
}

fn validate_pending_activation_source_state(
    current_source: &BarrierPendingActivationSource,
    pending: &BarrierPendingState,
) -> Result<()> {
    if !pending_activation_source_matches(current_source, pending.activation_source.as_ref()) {
        return Err(anyhow!(
            "pending barrier activation preconditions no longer match the locally persisted pre-publish state (960.9)"
        ));
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PendingBarrierHistoryOutcome {
    Unchanged,
    Activated([u8; 32]),
    Discarded,
    RecoveryRequired(BarrierRecoveryIssue),
}

#[cfg(test)]
pub(super) fn apply_pending_barrier_activation(
    session: &mut AppSession,
    observed_barrier_version: u64,
    observed_fs_ec: Option<u64>,
    observed_barrier_update_reason: Option<u64>,
    accepted_digest: Option<[u8; 32]>,
) -> Result<bool> {
    let current_source = capture_barrier_pending_activation_source(session);
    apply_pending_barrier_activation_with_source(
        session,
        &current_source,
        observed_barrier_version,
        observed_fs_ec,
        observed_barrier_update_reason,
        accepted_digest,
    )
}

pub(super) fn apply_pending_barrier_activation_with_source(
    session: &mut AppSession,
    current_source: &BarrierPendingActivationSource,
    observed_barrier_version: u64,
    observed_fs_ec: Option<u64>,
    observed_barrier_update_reason: Option<u64>,
    accepted_digest: Option<[u8; 32]>,
) -> Result<bool> {
    let Some(pending) = session.barrier_state.pending.clone() else {
        return Ok(false);
    };

    if observed_barrier_version < pending.barrier_version {
        return Ok(false);
    }

    if pending_barrier_matches_observation(
        pending.barrier_version,
        pending.fs_ec,
        pending.barrier_update_reason,
        pending.barrier_update_digest,
        CorePendingBarrierObservation {
            observed_barrier_version,
            observed_fs_ec,
            observed_barrier_update_reason,
            accepted_digest,
        },
    ) {
        validate_pending_activation_source_state(current_source, &pending)?;
        let BarrierPendingState {
            barrier_version,
            fs_ec,
            k_barrier_new,
            kem_tree_hash_after,
            k_fs_after_pcs,
            next_forward_fs_ec,
            next_forward_fs_dev_commit,
            next_forward_last_weid,
            revocation_roots_hash,
            on_path_key_material,
            ..
        } = pending;
        session.barrier_state.barrier_initialized = true;
        session.barrier_state.barrier_version = barrier_version;
        session.barrier_state.barrier_roots_hash = revocation_roots_hash;
        session.barrier_state.k_barrier = k_barrier_new;
        session.barrier_state.kem_tree_hash_after = kem_tree_hash_after;
        clear_all_public_tree_caches(&mut session.barrier_state);
        session.last_accepted_ec = session.last_accepted_ec.max(fs_ec);
        for (node, material) in on_path_key_material {
            session.barrier_state.dk_nodes.insert(node, material);
        }
        let reseeded_k_fs = k_fs_after_pcs.as_deref().copied();
        if next_forward_fs_ec != 0 {
            let k_fs = reseeded_k_fs.unwrap_or_else(|| session.forward_state.snapshot().k_fs);
            apply_forward_state_snapshot(
                session,
                k_fs,
                next_forward_fs_ec,
                next_forward_fs_dev_commit,
                next_forward_last_weid,
            );
        } else if let Some(k_fs_after_pcs) = reseeded_k_fs {
            apply_forward_state_k_fs(session, k_fs_after_pcs);
        }
        #[cfg(test)]
        fault_injection::trigger_fault(
            FaultInjectionCutPoint::AfterAuthenticatedAcceptBeforePersist,
            None,
        )?;
        session.barrier_state.pending = None;
        session.barrier_state.barrier_recovery_pending = false;
        session.barrier_state.barrier_recovery_issue = None;
        session.barrier_state.current_barrier_full_verified = true;
        clear_join_finalize_bootstrap_artifact(&mut session.barrier_state);
        return Ok(true);
    }

    Ok(false)
}
