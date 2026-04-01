use super::*;
use crate::barrier_shared::to_core_history_commitment;
use cityg_client::barrier_activation::{
    ClientVisibleBarrierActivationInput,
    bundle_authored_by_local_device as bundle_authored_by_local_device_core,
    extract_barrier_update_digest as extract_barrier_update_digest_core,
    validate_client_visible_activation_guards as validate_client_visible_activation_guards_core,
};
use cityg_client::barrier_build::{
    BarrierUpdateBuildResult as CoreBarrierUpdateBuildResult,
    build_barrier_update_bytes as build_barrier_update_bytes_core,
};
use cityg_client::barrier_pending::{
    PendingBarrierHistoryInput as CorePendingBarrierHistoryInput,
    PendingBarrierHistoryResolution as CorePendingBarrierHistoryResolution,
    PendingBarrierLookupStatus as CorePendingBarrierLookupStatus,
    PendingBarrierObservation as CorePendingBarrierObservation,
    PendingBarrierRecoveryReason as CorePendingBarrierRecoveryReason,
    pending_activation_source_matches, pending_barrier_matches_observation,
    resolve_pending_barrier_history,
};
use cityg_client::barrier_recovery::{
    BarrierRecoverResult as CoreBarrierRecoverResult,
    BarrierRecoveryInput as CoreBarrierRecoveryInput,
    BarrierRecoveryNodeMaterialRef as CoreBarrierRecoveryNodeMaterialRef,
    recover_barrier_update as recover_barrier_update_core,
};
pub(super) fn clear_join_finalize_bootstrap_artifact(state: &mut BarrierSecretState) {
    state.bootstrap_history_commitment = None;
    state.bootstrap_predecessor_kem_tree_hash_after = [0u8; 32];
    state.bootstrap_join_records.clear();
    state.bootstrap_revoked_leaf_indices.clear();
    state.bootstrap_join_finalize_auth_token = [0u8; 32];
    state.bootstrap_current_barrier_update.clear();
}

pub(super) fn try_recover_barrier_from_header_with_expected_before(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
    expected_before_hash: Option<[u8; 32]>,
) -> Result<Option<BarrierRecoverResult>> {
    try_recover_barrier_inner(
        session,
        header_map,
        weid,
        fs_ec,
        max_barrier_update_bytes,
        expected_before_hash,
        false,
    )
}

/// Best-effort barrier recovery that skips local version progression and
/// hash-chain checks.  Used when the client is behind by multiple barrier
/// versions and cannot validate the chain, but can still attempt to decrypt
/// the barrier update using its leaf KEM key.
pub(super) fn try_recover_barrier_best_effort(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
) -> Result<Option<BarrierRecoverResult>> {
    try_recover_barrier_inner(
        session,
        header_map,
        weid,
        fs_ec,
        max_barrier_update_bytes,
        None,
        true,
    )
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

fn mark_barrier_recovery_required(
    session: &mut AppSession,
    issue: BarrierRecoveryIssue,
) -> PendingBarrierHistoryOutcome {
    clear_all_public_tree_caches(&mut session.barrier_state);
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.barrier_recovery_issue = Some(issue);
    session.barrier_state.current_barrier_full_verified = false;
    PendingBarrierHistoryOutcome::RecoveryRequired(issue)
}

fn map_pending_barrier_recovery_reason(
    reason: CorePendingBarrierRecoveryReason,
) -> BarrierRecoveryIssue {
    match reason {
        CorePendingBarrierRecoveryReason::InsufficientAuthenticatedHistory => {
            BarrierRecoveryIssue::InsufficientAuthenticatedHistory
        }
        CorePendingBarrierRecoveryReason::ContradictoryAuthenticatedHistory => {
            BarrierRecoveryIssue::ContradictoryAuthenticatedHistory
        }
        CorePendingBarrierRecoveryReason::LegacyPendingLocatorMissing => {
            BarrierRecoveryIssue::LegacyPendingLocatorMissing
        }
    }
}

pub(super) fn try_recover_barrier_inner(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
    expected_before_hash: Option<[u8; 32]>,
    skip_local_checks: bool,
) -> Result<Option<BarrierRecoverResult>> {
    let raw_update = match header_map.get(&hdr::HDR_BARRIER_UPDATE) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        Some(_) => return Err(anyhow!("header barrier_update must be bytes")),
        None => return Ok(None),
    };
    let reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON)
        .ok_or_else(|| anyhow!("barrier_update_reason is missing or malformed"))?;
    let revoked_since_root = header_bytes32(header_map, hdr::HDR_REVOKED_SINCE_ROOT)
        .ok_or_else(|| anyhow!("header revoked_since_prev_root is missing or malformed"))?;
    let revoked_root = header_bytes32(header_map, hdr::HDR_REVOKED_ROOT)
        .ok_or_else(|| anyhow!("header revoked_root is missing or malformed"))?;
    let core_local_node_materials = session
        .barrier_state
        .dk_nodes
        .iter()
        .map(|(node, material)| {
            (
                *node,
                CoreBarrierRecoveryNodeMaterialRef {
                    dk: material.dk.as_slice(),
                    pkhash: material.pkhash,
                },
            )
        })
        .collect();

    match recover_barrier_update_core(CoreBarrierRecoveryInput {
        gid: &session.gid,
        local_n_max: session.barrier_state.n_max,
        local_cover_leaf_index: session.barrier_state.cover_leaf_index,
        local_barrier_initialized: session.barrier_state.barrier_initialized,
        local_barrier_version: session.barrier_state.barrier_version,
        local_barrier_roots_hash: session.barrier_state.barrier_roots_hash,
        local_kem_tree_hash_after: session.barrier_state.kem_tree_hash_after,
        local_pop_public_key: session.pop_public_key.as_slice(),
        local_leaf_material: CoreBarrierRecoveryNodeMaterialRef {
            dk: session.barrier_state.dk_leaf.as_slice(),
            pkhash: session.barrier_state.pkhash_leaf,
        },
        local_node_materials: core_local_node_materials,
        local_k_fs_before: session.forward_state.snapshot().k_fs,
        weid,
        fs_ec,
        raw_update,
        barrier_update_reason: reason,
        revoked_since_root,
        revoked_root,
        author_pop_public_key: header_map
            .get(&hdr::HDR_POP_PK)
            .and_then(Value::as_bytes)
            .map(Vec::as_slice),
        max_barrier_update_bytes,
        expected_before_hash,
        skip_local_checks,
    })? {
        Some(CoreBarrierRecoverResult {
            barrier_version,
            k_barrier_new,
            kem_tree_hash_after,
            k_fs_after_pcs,
            derived_node_key_material,
        }) => Ok(Some(BarrierRecoverResult {
            barrier_version,
            k_barrier_new,
            kem_tree_hash_after,
            k_fs_after_pcs,
            derived_node_key_material: derived_node_key_material
                .into_iter()
                .map(|(node, material)| {
                    (
                        node,
                        BarrierNodeKeyMaterial {
                            dk: material.dk,
                            pkhash: material.pkhash,
                        },
                    )
                })
                .collect(),
        })),
        None => {
            if header_map
                .get(&hdr::HDR_POP_PK)
                .and_then(Value::as_bytes)
                .is_some_and(|pk| pk != session.pop_public_key.as_slice())
            {
                warn!(
                    code = BARRIER_CODE_RECOVER_NO_MATCH,
                    "barrier recover produced no matching ciphertext"
                );
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
pub(super) fn try_recover_barrier_from_header(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
) -> Result<Option<BarrierRecoverResult>> {
    try_recover_barrier_from_header_with_expected_before(
        session,
        header_map,
        weid,
        fs_ec,
        max_barrier_update_bytes,
        None,
    )
}

pub(super) fn extract_barrier_update_digest(
    header: &BTreeMap<u64, Value>,
) -> Result<Option<[u8; 32]>> {
    extract_barrier_update_digest_core(header)
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

pub(super) fn validate_client_visible_activation_guards(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
) -> Result<()> {
    let current_history_commitment = session
        .barrier_state
        .current_history_commitment
        .as_ref()
        .map(to_core_history_commitment);

    validate_client_visible_activation_guards_core(
        ClientVisibleBarrierActivationInput {
            gid: &session.gid,
            local_pop_public_key: session.pop_public_key.as_slice(),
            local_current_history_commitment: current_history_commitment.as_ref(),
            local_current_history_view_id: session.barrier_state.current_history_view_id,
            local_current_history_authority_extension_present: session
                .barrier_state
                .current_history_authority_extension
                .is_some(),
            local_current_global_history_attestation_bytes: session
                .barrier_state
                .current_global_history_attestation_bytes
                .as_slice(),
            local_n_max: session.barrier_state.n_max,
            local_max_barrier_update_bytes: session.barrier_state.max_barrier_update_bytes,
            local_fs_policy_version: session.fs_policy_version.as_str(),
            local_fs_epoch_base_ts: session.fs_epoch_base_ts,
            local_last_accepted_ec: session.last_accepted_ec,
            local_fs_ec: session.fs_ec,
            local_fs_dev_prev_commit: session.fs_dev_prev_commit,
            fs_forward_leap_h: session.fs_forward_leap_policy.h,
            fs_forward_leap_checkpoint_interval: session.fs_forward_leap_policy.checkpoint_interval,
            fs_forward_leap_slack_anchor: session.fs_forward_leap_policy.slack_anchor,
            fs_forward_leap_slack_first_device: session.fs_forward_leap_policy.slack_first_device,
            fs_forward_leap_slack_device: session.fs_forward_leap_policy.slack_device,
        },
        header_map,
    )
}

pub(super) fn bundle_authored_by_local_device(
    session: &AppSession,
    header: &BTreeMap<u64, Value>,
) -> bool {
    bundle_authored_by_local_device_core(session.pop_public_key.as_slice(), header)
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

pub(super) async fn apply_pending_barrier_activation_from_history(
    client: &CitygApiClient,
    session: &mut AppSession,
    current_barrier_version: u64,
) -> Result<PendingBarrierHistoryOutcome> {
    let Some(pending) = session.barrier_state.pending.clone() else {
        return Ok(PendingBarrierHistoryOutcome::Unchanged);
    };

    let lookup_resolution = if pending.we_epoch_id == [0u8; 32] {
        resolve_pending_barrier_history(CorePendingBarrierHistoryInput {
            current_barrier_version,
            pending_barrier_version: pending.barrier_version,
            pending_we_epoch_id: pending.we_epoch_id,
            status: CorePendingBarrierLookupStatus::Pending,
            accepted_barrier_version: None,
            accepted_fs_ec: None,
            accepted_reason: None,
            accepted_digest: None,
        })?
    } else {
        match client
            .barrier_lookup_merge_acceptance(
                &session.room_id,
                pending.barrier_version,
                &pending.barrier_update_digest,
                &pending.we_epoch_id,
            )
            .await
        {
            Ok(lookup) => {
                let status = match lookup.status {
                    MergeAcceptanceStatus::Pending => CorePendingBarrierLookupStatus::Pending,
                    MergeAcceptanceStatus::Accepted => CorePendingBarrierLookupStatus::Accepted,
                    MergeAcceptanceStatus::Superseded => CorePendingBarrierLookupStatus::Superseded,
                    MergeAcceptanceStatus::FinalRejected => {
                        CorePendingBarrierLookupStatus::FinalRejected
                    }
                };
                resolve_pending_barrier_history(CorePendingBarrierHistoryInput {
                    current_barrier_version,
                    pending_barrier_version: pending.barrier_version,
                    pending_we_epoch_id: pending.we_epoch_id,
                    status,
                    accepted_barrier_version: lookup.accepted_barrier_version,
                    accepted_fs_ec: lookup.accepted_fs_ec,
                    accepted_reason: lookup.accepted_reason,
                    accepted_digest: lookup.accepted_digest,
                })?
            }
            Err(ApiClientError::HttpStatus { status, .. }) if status.as_u16() == 404 => {
                resolve_pending_barrier_history(CorePendingBarrierHistoryInput {
                    current_barrier_version,
                    pending_barrier_version: pending.barrier_version,
                    pending_we_epoch_id: pending.we_epoch_id,
                    status: CorePendingBarrierLookupStatus::NotFound,
                    accepted_barrier_version: None,
                    accepted_fs_ec: None,
                    accepted_reason: None,
                    accepted_digest: None,
                })?
            }
            Err(err) => {
                return Err(anyhow!(
                    "pending barrier activation history lookup failed (960.9): {err}"
                ));
            }
        }
    };

    match lookup_resolution {
        CorePendingBarrierHistoryResolution::Unchanged => {
            Ok(PendingBarrierHistoryOutcome::Unchanged)
        }
        CorePendingBarrierHistoryResolution::Discard => {
            session.barrier_state.pending = None;
            session.barrier_state.barrier_recovery_issue = None;
            Ok(PendingBarrierHistoryOutcome::Discarded)
        }
        CorePendingBarrierHistoryResolution::RecoveryRequired(reason) => {
            let issue = map_pending_barrier_recovery_reason(reason);
            if matches!(
                reason,
                CorePendingBarrierRecoveryReason::LegacyPendingLocatorMissing
            ) {
                warn!(
                    code = BARRIER_CODE_SNAPSHOT_AUTH_FAILURE,
                    pending_barrier_version = pending.barrier_version,
                    current_barrier_version,
                    "pending barrier state predates pending we_epoch_id persistence; entering recovery-required state after newer barrier version observed"
                );
            }
            Ok(mark_barrier_recovery_required(session, issue))
        }
        CorePendingBarrierHistoryResolution::Activate {
            we_epoch_id,
            observation,
        } => {
            let activation_source = pending
                .activation_source
                .clone()
                .unwrap_or_else(|| capture_barrier_pending_activation_source(session));
            if apply_pending_barrier_activation_with_source(
                session,
                &activation_source,
                observation.observed_barrier_version,
                observation.observed_fs_ec,
                observation.observed_barrier_update_reason,
                observation.accepted_digest,
            )? {
                Ok(PendingBarrierHistoryOutcome::Activated(we_epoch_id))
            } else {
                Ok(mark_barrier_recovery_required(
                    session,
                    BarrierRecoveryIssue::ContradictoryAuthenticatedHistory,
                ))
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_barrier_update_bytes(
    gid: &[u8; 32],
    n_max: u64,
    updater_leaf: u64,
    barrier_version: u64,
    prev_barrier_version: u64,
    revocation_roots_hash: [u8; 32],
    kem_tree_hash_before: [u8; 32],
    snapshot_pre: &[Vec<u8>],
) -> Result<BarrierUpdateBuildResult> {
    let CoreBarrierUpdateBuildResult {
        raw_update,
        barrier_update_digest,
        kem_tree_hash_after,
        k_barrier_new,
        on_path_key_material,
        snapshot_post,
    } = build_barrier_update_bytes_core(
        gid,
        n_max,
        updater_leaf,
        barrier_version,
        prev_barrier_version,
        revocation_roots_hash,
        kem_tree_hash_before,
        snapshot_pre,
    )?;

    Ok(BarrierUpdateBuildResult {
        raw_update,
        barrier_update_digest,
        kem_tree_hash_after,
        k_barrier_new,
        on_path_key_material: on_path_key_material
            .into_iter()
            .map(|(node, material)| {
                (
                    node,
                    BarrierNodeKeyMaterial {
                        dk: material.dk,
                        pkhash: material.pkhash,
                    },
                )
            })
            .collect(),
        snapshot_post: Arc::new(BarrierPublicTree {
            n_max,
            kem_tree_hash_after,
            pk_entries: snapshot_post,
        }),
    })
}
