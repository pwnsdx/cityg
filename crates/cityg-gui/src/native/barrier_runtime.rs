use super::*;
use crate::barrier_shared::{
    header_history_commitment, require_same_history_commitment, verify_full_verification_receipt,
};
use cityg_client::barrier_build::{
    BarrierUpdateBuildResult as CoreBarrierUpdateBuildResult,
    build_barrier_update_bytes as build_barrier_update_bytes_core,
};
use cityg_client::barrier_recovery::{
    BarrierRecoverResult as CoreBarrierRecoverResult,
    BarrierRecoveryInput as CoreBarrierRecoveryInput,
    BarrierRecoveryNodeMaterialRef as CoreBarrierRecoveryNodeMaterialRef,
    recover_barrier_update as recover_barrier_update_core,
};
use msphf_orchestrator::{LeafIdMode, compute_leaf_id};

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
    match header.get(&hdr::HDR_BARRIER_UPDATE) {
        Some(Value::Bytes(raw)) => Ok(Some(compute_barrier_update_digest(raw)?)),
        Some(_) => Err(anyhow!("header barrier_update must be bytes")),
        None => Ok(None),
    }
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
    let Some(expected_source) = pending.activation_source.as_ref() else {
        return Ok(());
    };

    if current_source != expected_source {
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
    let has_barrier_update = matches!(
        header_map.get(&hdr::HDR_BARRIER_UPDATE),
        Some(Value::Bytes(_))
    );
    let global_history_attestation = match header_map
        .get(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION)
    {
        Some(Value::Bytes(raw)) => Some(raw),
        Some(_) => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): header[182] global_history_attestation must be bytes"
            ));
        }
        None => None,
    };
    if !session
        .barrier_state
        .current_global_history_attestation_bytes
        .is_empty()
    {
        if session
            .barrier_state
            .current_history_authority_extension
            .is_none()
        {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): unsupported or missing history authority extension for local attested current state"
            ));
        }
        let supplied = global_history_attestation.ok_or_else(|| {
            anyhow!(
                "client-side activation guard failed (960.7): missing header[182] global_history_attestation for authority-bound barrier state"
            )
        })?;
        if supplied.as_slice()
            != session
                .barrier_state
                .current_global_history_attestation_bytes
                .as_slice()
        {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): header[182] global_history_attestation mismatch with local authenticated current state"
            ));
        }
    } else if global_history_attestation.is_some() && !has_barrier_update {
        return Err(anyhow!(
            "client-side activation guard failed (960.7): unexpected header[182] global_history_attestation without pinned local authority state"
        ));
    }
    if global_history_attestation.is_some()
        && !header_map.contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
    {
        return Err(anyhow!(
            "client-side activation guard failed (960.7): missing header[181] full_verification_receipt for authority-bound barrier state"
        ));
    }
    if header_map.contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
        && global_history_attestation.is_none()
    {
        return Err(anyhow!(
            "client-side activation guard failed (960.7): header[181] full_verification_receipt requires header[182] global_history_attestation"
        ));
    }
    if let Some(global_history_attestation) = global_history_attestation {
        verify_client_visible_full_verification_receipt(
            session,
            header_map,
            global_history_attestation.as_slice(),
        )?;
    }
    let fs_policy_version = header_policy_version(header_map, hdr::HDR_FS_POLICY_VERSION)
        .ok_or_else(|| {
            anyhow!("client-side activation guard failed (944.6): missing fs_policy_version")
        })?;
    if !session.fs_policy_version.is_empty() && fs_policy_version != session.fs_policy_version {
        return Err(anyhow!(
            "client-side activation guard failed (944.6): fs_policy_version mismatch"
        ));
    }
    let fs_epoch_base_ts = header_u64(header_map, hdr::HDR_FS_EPOCH_BASE_TS).ok_or_else(|| {
        anyhow!("client-side activation guard failed (945.0): missing fs_epoch_base_ts")
    })?;
    if session.fs_epoch_base_ts != 0 && fs_epoch_base_ts != session.fs_epoch_base_ts {
        return Err(anyhow!(
            "client-side activation guard failed (945.0): fs_epoch_base_ts mismatch"
        ));
    }

    let author_device_pk = header_map
        .get(&hdr::HDR_POP_PK)
        .and_then(Value::as_bytes)
        .ok_or_else(|| {
            anyhow!("client-side activation guard failed (947.2): missing author_device_pk")
        })?;
    let fs_ec = header_u64(header_map, hdr::HDR_FS_EC)
        .ok_or_else(|| anyhow!("client-side activation guard failed (947.2): missing fs_ec"))?;
    let fs_dev_prev_commit =
        header_bytes32(header_map, hdr::HDR_FS_DEV_PREV_COMMIT).ok_or_else(|| {
            anyhow!("client-side activation guard failed (947.2): missing fs_dev_prev_commit")
        })?;
    let fs_dev_commit = header_bytes32(header_map, hdr::HDR_FS_DEV_COMMIT).ok_or_else(|| {
        anyhow!("client-side activation guard failed (947.2): missing fs_dev_commit")
    })?;
    let barrier_version = header_u64(header_map, hdr::HDR_BARRIER_VERSION).ok_or_else(|| {
        anyhow!("client-side activation guard failed (947.2): missing barrier_version")
    })?;
    let barrier_update_digest = extract_barrier_update_digest(header_map)?.unwrap_or([0u8; 32]);
    let fs_caps = session.fs_forward_leap_policy.caps().map_err(|_| {
        anyhow!("client-side activation guard failed (948.0): invalid local fs policy window")
    })?;
    if fs_ec > session.last_accepted_ec.saturating_add(fs_caps.anchor_max) {
        return Err(anyhow!(
            "client-side activation guard failed (947.6): fs_ec exceeds local group forward-jump window"
        ));
    }
    if fs_dev_prev_commit == [0u8; 32] {
        if fs_ec
            > session
                .last_accepted_ec
                .saturating_add(fs_caps.first_device_max)
        {
            return Err(anyhow!(
                "client-side activation guard failed (947.5): new-device fs_ec exceeds local first-device forward-jump window"
            ));
        }
    } else if author_device_pk == session.pop_public_key.as_slice()
        && fs_ec > session.fs_ec.saturating_add(fs_caps.device_max)
    {
        return Err(anyhow!(
            "client-side activation guard failed (947.4): local device fs_ec exceeds local device forward-jump window"
        ));
    }
    let expected_fs_dev_commit = compute_fs_dev_commit_v2(
        author_device_pk,
        fs_ec,
        &fs_dev_prev_commit,
        barrier_version,
        &barrier_update_digest,
    )
    .map_err(|err| anyhow!("client-side activation guard failed (947.2): {err}"))?;
    if fs_dev_commit != expected_fs_dev_commit {
        return Err(anyhow!(
            "client-side activation guard failed (947.2): fs_dev_chain_bind mismatch"
        ));
    }

    if author_device_pk == session.pop_public_key.as_slice()
        && (fs_dev_prev_commit != session.fs_dev_prev_commit || fs_ec < session.fs_ec)
    {
        return Err(anyhow!(
            "client-side activation guard failed (947.0): local device chain continuity mismatch"
        ));
    }

    let Some(bundle_history_commitment) = header_history_commitment(header_map)? else {
        return Err(anyhow!(
            "client-side activation guard failed (960.9): missing barrier history commitment header"
        ));
    };
    let authored_by_local_device = bundle_authored_by_local_device(session, header_map);
    if !authored_by_local_device && session.barrier_state.pending.is_none() {
        if let Some(current_history_commitment) =
            session.barrier_state.current_history_commitment.as_ref()
        {
            require_same_history_commitment(current_history_commitment, &bundle_history_commitment)
                .map_err(|_| {
                    anyhow!(
                        "client-side activation guard failed (960.9): bundle barrier history commitment mismatch with local authenticated current state"
                    )
                })?;
        } else if session.barrier_state.current_history_view_id != [0u8; 32]
            && bundle_history_commitment.history_view_id
                != session.barrier_state.current_history_view_id
        {
            return Err(anyhow!(
                "client-side activation guard failed (960.9): bundle barrier history commitment view mismatch"
            ));
        }
    }

    Ok(())
}

fn verify_client_visible_full_verification_receipt(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    global_history_attestation: &[u8],
) -> Result<()> {
    let raw_receipt = match header_map.get(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT) {
        Some(Value::Bytes(raw)) => raw.as_slice(),
        Some(_) => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): header[181] full_verification_receipt must be bytes"
            ));
        }
        None => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): missing header[181] full_verification_receipt for authority-bound barrier state"
            ));
        }
    };
    let raw_history_commitment = match header_map.get(&hdr::HDR_BARRIER_HISTORY_COMMITMENT) {
        Some(Value::Bytes(raw)) => raw.as_slice(),
        Some(_) => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): barrier history commitment header must be bytes"
            ));
        }
        None => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): missing barrier history commitment header for authority-bound barrier state"
            ));
        }
    };
    let raw_barrier_update = match header_map.get(&hdr::HDR_BARRIER_UPDATE) {
        Some(Value::Bytes(raw)) => raw.as_slice(),
        Some(_) => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): barrier_update must be bytes for authority-bound barrier state"
            ));
        }
        None => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): missing barrier_update for authority-bound barrier state"
            ));
        }
    };
    let barrier_update_reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON)
        .ok_or_else(|| {
            anyhow!(
                "client-side activation guard failed (960.7): missing barrier_update_reason for authority-bound barrier state"
            )
        })?;
    let max_barrier_update_bytes = normalize_max_barrier_update_bytes(
        session
            .barrier_state
            .max_barrier_update_bytes
            .max(u64::try_from(raw_barrier_update.len()).unwrap_or(u64::MAX)),
    )
    .map_err(|err| anyhow!("client-side activation guard failed (960.7): {err}"))?;
    let parsed = parse_barrier_update_for_recover(
        raw_barrier_update,
        session.barrier_state.n_max,
        max_barrier_update_bytes,
    )
    .map_err(|err| {
        anyhow!(
            "client-side activation guard failed (960.7): invalid barrier_update for receipt verification: {err}"
        )
    })?;
    let author_device_pk = header_map
        .get(&hdr::HDR_POP_PK)
        .and_then(Value::as_bytes)
        .ok_or_else(|| {
            anyhow!("client-side activation guard failed (960.7): missing author_device_pk")
        })?;
    let author_leaf_id = compute_leaf_id(
        LeafIdMode::PerGroup,
        &session.gid,
        "ML-DSA-65",
        author_device_pk,
    )
    .map_err(|err| {
        anyhow!("client-side activation guard failed (960.7): author leaf derivation failed: {err}")
    })?;
    verify_full_verification_receipt(
        raw_receipt,
        &session.gid,
        &author_leaf_id,
        barrier_update_reason,
        parsed.updater_leaf,
        raw_history_commitment,
        global_history_attestation,
        raw_barrier_update,
        author_device_pk,
    )
    .map_err(|err| {
        anyhow!(
            "client-side activation guard failed (960.7): invalid header[181] full_verification_receipt: {err}"
        )
    })
}

pub(super) fn bundle_authored_by_local_device(
    session: &AppSession,
    header: &BTreeMap<u64, Value>,
) -> bool {
    matches!(
        header.get(&hdr::HDR_POP_PK),
        Some(Value::Bytes(pop_pk)) if pop_pk.as_slice() == session.pop_public_key.as_slice()
    )
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

    if let Some(digest) = accepted_digest
        && digest == pending.barrier_update_digest
        && observed_barrier_version == pending.barrier_version
        && observed_fs_ec == Some(pending.fs_ec)
        && observed_barrier_update_reason == pending.barrier_update_reason
    {
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

    if pending.we_epoch_id == [0u8; 32] {
        if current_barrier_version > pending.barrier_version {
            warn!(
                code = BARRIER_CODE_SNAPSHOT_AUTH_FAILURE,
                pending_barrier_version = pending.barrier_version,
                current_barrier_version,
                "pending barrier state predates pending we_epoch_id persistence; entering recovery-required state after newer barrier version observed"
            );
            return Ok(mark_barrier_recovery_required(
                session,
                BarrierRecoveryIssue::LegacyPendingLocatorMissing,
            ));
        }
        return Ok(PendingBarrierHistoryOutcome::Unchanged);
    }

    match client
        .barrier_lookup_merge_acceptance(
            &session.room_id,
            pending.barrier_version,
            &pending.barrier_update_digest,
            &pending.we_epoch_id,
        )
        .await
    {
        Ok(lookup) => match lookup.status {
            MergeAcceptanceStatus::Accepted => {
                let observed_barrier_version =
                    lookup.accepted_barrier_version.ok_or_else(|| {
                        anyhow!(
                            "pending barrier activation history missing accepted barrier_version (960.9)"
                        )
                    });
                let Some(observed_barrier_version) = observed_barrier_version.ok() else {
                    return Ok(mark_barrier_recovery_required(
                        session,
                        BarrierRecoveryIssue::ContradictoryAuthenticatedHistory,
                    ));
                };
                let activation_source = pending
                    .activation_source
                    .clone()
                    .unwrap_or_else(|| capture_barrier_pending_activation_source(session));
                if apply_pending_barrier_activation_with_source(
                    session,
                    &activation_source,
                    observed_barrier_version,
                    lookup.accepted_fs_ec,
                    lookup.accepted_reason,
                    lookup.accepted_digest,
                )? {
                    return Ok(PendingBarrierHistoryOutcome::Activated(pending.we_epoch_id));
                }
                Ok(mark_barrier_recovery_required(
                    session,
                    BarrierRecoveryIssue::ContradictoryAuthenticatedHistory,
                ))
            }
            MergeAcceptanceStatus::Superseded | MergeAcceptanceStatus::FinalRejected => {
                session.barrier_state.pending = None;
                session.barrier_state.barrier_recovery_issue = None;
                Ok(PendingBarrierHistoryOutcome::Discarded)
            }
            MergeAcceptanceStatus::Pending => {
                Ok(if current_barrier_version > pending.barrier_version {
                    mark_barrier_recovery_required(
                        session,
                        BarrierRecoveryIssue::InsufficientAuthenticatedHistory,
                    )
                } else {
                    PendingBarrierHistoryOutcome::Unchanged
                })
            }
        },
        Err(ApiClientError::HttpStatus { status, .. }) if status.as_u16() == 404 => {
            Ok(if current_barrier_version > pending.barrier_version {
                mark_barrier_recovery_required(
                    session,
                    BarrierRecoveryIssue::InsufficientAuthenticatedHistory,
                )
            } else {
                PendingBarrierHistoryOutcome::Unchanged
            })
        }
        Err(err) => Err(anyhow!(
            "pending barrier activation history lookup failed (960.9): {err}"
        )),
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
