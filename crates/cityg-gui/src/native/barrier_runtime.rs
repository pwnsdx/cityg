use super::*;

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
        k_barrier_new,
        k_fs_after_pcs,
        derived_node_key_material,
        ..
    } = recovered;
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.barrier_roots_hash =
        compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
    session.barrier_state.k_barrier = k_barrier_new;
    for (node, material) in derived_node_key_material {
        session.barrier_state.dk_nodes.insert(node, material);
    }
    if let Some(k_fs_after_pcs) = k_fs_after_pcs {
        apply_forward_state_k_fs(session, *k_fs_after_pcs);
    }
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
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.barrier_recovery_issue = None;
    session.barrier_state.current_barrier_full_verified = false;
    Ok(())
}

fn mark_barrier_recovery_required(
    session: &mut AppSession,
    issue: BarrierRecoveryIssue,
) -> PendingBarrierHistoryOutcome {
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
    if max_barrier_update_bytes == 0 {
        return Err(anyhow!("max_barrier_update_bytes must be positive"));
    }

    let raw_update = match header_map.get(&hdr::HDR_BARRIER_UPDATE) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        Some(_) => return Err(anyhow!("header barrier_update must be bytes")),
        None => return Ok(None),
    };

    let n_max = session.barrier_state.n_max.max(1);
    let parsed = parse_barrier_update_for_recover(raw_update, n_max, max_barrier_update_bytes)?;

    let valid_progression = (parsed.prev_barrier_version == 0 && parsed.barrier_version == 0)
        || parsed.prev_barrier_version.saturating_add(1) == parsed.barrier_version;
    if !valid_progression {
        return Err(anyhow!("barrier version progression is invalid"));
    }

    if !skip_local_checks {
        let local_barrier_version = session.barrier_state.barrier_version;
        let genesis_local_case = !session.barrier_state.barrier_initialized
            && parsed.prev_barrier_version == 0
            && parsed.barrier_version == 0;
        let valid_local_progression = genesis_local_case
            || (session.barrier_state.barrier_initialized
                && parsed.prev_barrier_version == local_barrier_version
                && parsed.barrier_version == local_barrier_version.saturating_add(1));
        if !valid_local_progression {
            return Err(anyhow!(
                "barrier version progression does not match local barrier state"
            ));
        }
    }

    if parsed.tree_size != n_max {
        return Err(anyhow!("barrier tree_size mismatch for local state"));
    }
    let reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON)
        .ok_or_else(|| anyhow!("barrier_update_reason is missing or malformed"))?;

    if !skip_local_checks {
        let required_before_hash =
            expected_before_hash.unwrap_or(session.barrier_state.kem_tree_hash_after);
        if reason != 2 && parsed.kem_tree_hash_before != required_before_hash {
            return Err(anyhow!("barrier hash-chain before-hash mismatch"));
        }
    }

    let revoked_since_root = header_bytes32(header_map, hdr::HDR_REVOKED_SINCE_ROOT)
        .ok_or_else(|| anyhow!("header revoked_since_prev_root is missing or malformed"))?;
    let revoked_root = header_bytes32(header_map, hdr::HDR_REVOKED_ROOT)
        .ok_or_else(|| anyhow!("header revoked_root is missing or malformed"))?;
    let expected_rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    if parsed.revocation_roots_hash != expected_rrh {
        return Err(anyhow!("barrier revocation_roots_hash mismatch"));
    }

    if !skip_local_checks {
        let genesis_local_case = !session.barrier_state.barrier_initialized
            && parsed.prev_barrier_version == 0
            && parsed.barrier_version == 0;
        if !genesis_local_case {
            if session.barrier_state.barrier_roots_hash == parsed.revocation_roots_hash {
                if !matches!(reason, 1 | 2) {
                    return Err(anyhow!(
                        "barrier_update_reason must be pcs_refresh (1) or join_finalize (2) when local barrier_roots_hash is unchanged"
                    ));
                }
            } else if reason != 0 {
                return Err(anyhow!(
                    "barrier_update_reason must be revocation_or_bootstrap (0) when local barrier_roots_hash changed"
                ));
            }
        }
    }

    let author_matches = header_map
        .get(&hdr::HDR_POP_PK)
        .and_then(Value::as_bytes)
        .map(|pk| pk == session.pop_public_key.as_slice())
        .unwrap_or(false);
    if author_matches && parsed.updater_leaf == session.barrier_state.cover_leaf_index {
        return Ok(None);
    }

    let self_path = self_path_nodes(n_max, session.barrier_state.cover_leaf_index);
    let self_path_set: HashSet<u64> = self_path.iter().copied().collect();
    let leaf_node = self_path
        .first()
        .copied()
        .ok_or_else(|| anyhow!("local self path is empty"))?;

    let mut matches: Vec<(u64, u64, [u8; 32])> = Vec::new();
    let mut candidate_decrypt_failure = false;
    for node in &parsed.node_ciphertexts {
        if !self_path_set.contains(&node.target_node) {
            continue;
        }

        let (dk_bytes, pkhash_t) = if node.target_node == leaf_node {
            (
                session.barrier_state.dk_leaf.as_slice(),
                session.barrier_state.pkhash_leaf,
            )
        } else if let Some(material) = session
            .barrier_state
            .dk_nodes
            .get(&(node.target_node as u32))
        {
            (material.dk.as_slice(), material.pkhash)
        } else {
            continue;
        };

        let mut target_prefix = [0u8; 16];
        target_prefix.copy_from_slice(&pkhash_t[..16]);
        if target_prefix != node.target_pk_hash {
            continue;
        }

        let mut ss = if node.target_node == leaf_node {
            if dk_bytes.len() != kyber768::secret_key_bytes() {
                continue;
            }
            let ct = match kyber768::Ciphertext::from_bytes(node.kem_ct.as_slice()) {
                Ok(ct) => ct,
                Err(_) => continue,
            };
            let dk = match kyber768::SecretKey::from_bytes(dk_bytes) {
                Ok(sk) => sk,
                Err(_) => continue,
            };
            let shared = kyber768::decapsulate(&ct, &dk);
            let mut ss = [0u8; 32];
            ss.copy_from_slice(shared.as_bytes());
            ss
        } else if dk_bytes.len() == ML_KEM_EXPANDED_DK_BYTES {
            match decapsulate_internal_node_shared_secret(dk_bytes, node.kem_ct.as_slice()) {
                Ok(ss) => ss,
                Err(_) => {
                    candidate_decrypt_failure = true;
                    continue;
                }
            }
        } else {
            candidate_decrypt_failure = true;
            continue;
        };

        let aad = to_cbor_vec(&BarrierWrapAadPreimage(
            &session.gid,
            parsed.barrier_version,
            &parsed.revocation_roots_hash,
            parsed.updater_leaf,
            node.source_node,
            node.target_node,
            &pkhash_t,
        ))
        .map_err(|err| anyhow!("encode barrier wrap aad: {err}"))?;
        let nonce_full = h_l(
            "barrier/wrap/nonce",
            &BarrierWrapNoncePreimage(node.source_node, node.target_node),
        )
        .map_err(|err| anyhow!("derive barrier wrap nonce: {err}"))?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);

        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, KeyInit, Payload},
        };
        let cipher = ChaCha20Poly1305::new((&ss).into());
        let mut plaintext = match cipher.decrypt(
            (&nonce).into(),
            Payload {
                msg: node.wrapped_ps.as_slice(),
                aad: aad.as_slice(),
            },
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                ss.zeroize();
                candidate_decrypt_failure = true;
                continue;
            }
        };
        ss.zeroize();
        if plaintext.len() != 32 {
            plaintext.zeroize();
            candidate_decrypt_failure = true;
            continue;
        }
        let mut path_secret = [0u8; 32];
        path_secret.copy_from_slice(plaintext.as_slice());
        plaintext.zeroize();
        matches.push((node.source_node, node.target_node, path_secret));
    }

    if matches.is_empty() {
        if candidate_decrypt_failure {
            return Err(anyhow!(
                "barrier recover rejected: candidate unwrap/decrypt failure (960.7)"
            ));
        }
        warn!(
            code = BARRIER_CODE_RECOVER_NO_MATCH,
            "barrier recover produced no matching ciphertext"
        );
        return Ok(None);
    }
    if matches.len() > 1 {
        for (_, _, secret) in &mut matches {
            secret.zeroize();
        }
        return Err(anyhow!("barrier recover rejected: multi-match (960.2)"));
    }

    let (source_node, target_node, source_secret) = matches.remove(0);
    if !self_path_set.contains(&source_node) || !self_path_set.contains(&target_node) {
        return Err(anyhow!(
            "barrier recover rejected: off-path source/target (960.7)"
        ));
    }
    let source_index = parsed
        .path_nodes
        .iter()
        .position(|node| *node == source_node)
        .ok_or_else(|| {
            anyhow!("barrier recover rejected: source missing from path_nodes (960.7)")
        })?;

    let mut path_secrets = BTreeMap::new();
    path_secrets.insert(source_node, source_secret);
    for k in (source_index + 1)..parsed.path_nodes.len() {
        let parent_node = parsed.path_nodes[k];
        let child_node = parsed.path_nodes[k - 1];
        let child_secret = path_secrets
            .get(&child_node)
            .ok_or_else(|| anyhow!("barrier recover missing child path secret"))?;
        let salt = h_l(
            "barrier/tree/path",
            &BarrierTreePathSaltPreimage(session.gid.as_slice(), parent_node),
        )
        .map_err(|err| anyhow!("derive barrier tree salt: {err}"))?;
        let parent_secret = hkdf_blake3(&salt, child_secret, BARRIER_TREE_INFO);
        path_secrets.insert(parent_node, parent_secret);
    }

    let root_secret = path_secrets
        .get(&0)
        .ok_or_else(|| anyhow!("barrier recover failed to derive root path secret"))?;
    let barrier_salt = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(
            session.gid.as_slice(),
            parsed.barrier_version,
            &parsed.revocation_roots_hash,
        ),
    )
    .map_err(|err| anyhow!("derive barrier key salt: {err}"))?;
    let k_barrier_new = hkdf_blake3(&barrier_salt, root_secret, BARRIER_KEY_INFO);

    let expected_node_set: HashSet<u64> = parsed.path_nodes.iter().copied().skip(1).collect();
    let mut derived_node_key_material = BTreeMap::new();
    for node in parsed.path_nodes.iter().copied().skip(source_index) {
        if node == leaf_node || !self_path_set.contains(&node) {
            continue;
        }
        let path_secret = path_secrets
            .get(&node)
            .ok_or_else(|| anyhow!("barrier recover missing path secret for node {node}"))?;
        let (dk_bytes, pkhash, ek_bytes) = derive_internal_node_key_material(
            session.gid.as_slice(),
            path_secret,
            parsed.barrier_version,
            &parsed.revocation_roots_hash,
            parsed.tree_size,
            node,
        )?;
        if expected_node_set.contains(&node) {
            let announced_ek = parsed.new_public_keys.get(&node).ok_or_else(|| {
                anyhow!("barrier recover rejected: missing new_public_keys for node {node} (960.7)")
            })?;
            if announced_ek.as_slice() != ek_bytes.as_slice() {
                return Err(anyhow!(
                    "barrier recover rejected: new_public_keys mismatch for node {node} (960.7)"
                ));
            }
        }
        let node_index = u32::try_from(node).map_err(|_| anyhow!("barrier node index overflow"))?;
        derived_node_key_material.insert(
            node_index,
            BarrierNodeKeyMaterial {
                dk: Zeroizing::new(dk_bytes),
                pkhash,
            },
        );
    }

    let reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON);
    let k_fs_after_pcs = if reason == Some(1) {
        let k_fs_before = session.forward_state.snapshot().k_fs;
        Some(derive_k_fs_after_pcs(
            &k_fs_before,
            weid,
            fs_ec,
            parsed.barrier_version,
            &k_barrier_new,
        )?)
    } else {
        None
    };

    zeroize_path_secret_map(&mut path_secrets);

    Ok(Some(BarrierRecoverResult {
        k_barrier_new: Zeroizing::new(k_barrier_new),
        kem_tree_hash_after: parsed.kem_tree_hash_after,
        k_fs_after_pcs: k_fs_after_pcs.map(Zeroizing::new),
        derived_node_key_material,
    }))
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

    if author_device_pk == session.pop_public_key.as_slice() {
        if fs_dev_prev_commit != session.fs_dev_prev_commit || fs_ec < session.fs_ec {
            return Err(anyhow!(
                "client-side activation guard failed (947.0): local device chain continuity mismatch"
            ));
        }
    }

    Ok(())
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
                if apply_pending_barrier_activation(
                    session,
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
    let n_max = validate_barrier_n_max(n_max)?;
    if updater_leaf >= n_max {
        return Err(anyhow!("invalid barrier update tree parameters"));
    }
    let expected_nodes = expected_barrier_tree_nodes(n_max)?;
    if snapshot_pre.len() != expected_nodes {
        return Err(anyhow!(
            "barrier snapshot size mismatch: expected {expected_nodes}, got {}",
            snapshot_pre.len()
        ));
    }

    let leaf_base = n_max.saturating_sub(1);
    let path_nodes = barrier_path_nodes(n_max, updater_leaf)?;

    let mut path_secrets = BTreeMap::new();
    let mut ps_leaf = [0u8; 32];
    rng().fill(&mut ps_leaf);
    path_secrets.insert(path_nodes[0], ps_leaf);
    ps_leaf.zeroize();
    for k in 1..path_nodes.len() {
        let parent_node = path_nodes[k];
        let child_node = path_nodes[k - 1];
        let child_secret = path_secrets
            .get(&child_node)
            .ok_or_else(|| anyhow!("barrier path secret derivation missing child"))?;
        let salt = h_l(
            "barrier/tree/path",
            &BarrierTreePathSaltPreimage(gid.as_slice(), parent_node),
        )
        .map_err(|err| anyhow!("derive barrier tree/path salt: {err}"))?;
        let parent_secret = hkdf_blake3(&salt, child_secret, BARRIER_TREE_INFO);
        path_secrets.insert(parent_node, parent_secret);
    }

    let root_secret = path_secrets
        .get(&0)
        .ok_or_else(|| anyhow!("barrier path secret derivation missing root"))?;
    let barrier_salt = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(gid.as_slice(), barrier_version, &revocation_roots_hash),
    )
    .map_err(|err| anyhow!("derive barrier/derive/salt: {err}"))?;
    let k_barrier_new = hkdf_blake3(&barrier_salt, root_secret, BARRIER_KEY_INFO);

    let mut expected_nodes: Vec<u64> = path_nodes.iter().copied().skip(1).collect();
    expected_nodes.sort_unstable();
    let mut on_path_key_material = BTreeMap::new();
    let mut new_public_keys = Vec::with_capacity(expected_nodes.len());
    for node in expected_nodes {
        let path_secret = path_secrets
            .get(&node)
            .ok_or_else(|| anyhow!("missing path secret for node {node}"))?;
        let (dk_bytes, pkhash, ek_bytes) = derive_internal_node_key_material(
            gid.as_slice(),
            path_secret,
            barrier_version,
            &revocation_roots_hash,
            n_max,
            node,
        )?;
        let node_index = u32::try_from(node).map_err(|_| anyhow!("barrier node index overflow"))?;
        on_path_key_material.insert(
            node_index,
            BarrierNodeKeyMaterial {
                dk: Zeroizing::new(dk_bytes),
                pkhash,
            },
        );
        new_public_keys.push(NewPublicKeyWire(node, ek_bytes));
    }

    let mut snapshot_post = snapshot_pre.to_vec();
    for NewPublicKeyWire(node, ek) in &new_public_keys {
        let idx = usize::try_from(*node).map_err(|_| anyhow!("barrier node index out of range"))?;
        let slot = snapshot_post
            .get_mut(idx)
            .ok_or_else(|| anyhow!("barrier node index out of range"))?;
        *slot = ek.clone();
    }
    let kem_tree_hash_after = compute_barrier_tree_hash(n_max, snapshot_post.as_slice())?;

    let mut node_ciphertexts = Vec::new();
    for step in 0..path_nodes.len().saturating_sub(1) {
        let child_node = path_nodes[step];
        let source_node = path_nodes[step + 1];
        let sibling =
            sibling_node(child_node).ok_or_else(|| anyhow!("barrier sibling missing for root"))?;
        let mut targets = Vec::new();
        collect_resolution_targets(snapshot_pre, sibling, leaf_base, &mut targets)?;
        targets.sort_unstable();
        for target_node in targets {
            let target_index = usize::try_from(target_node)
                .map_err(|_| anyhow!("barrier node index out of range"))?;
            let target_pk = snapshot_pre
                .get(target_index)
                .ok_or_else(|| anyhow!("barrier node index out of range"))?;
            if target_pk.is_empty() {
                return Err(anyhow!("barrier resolution produced blank target node"));
            }
            let target_pkhash = compute_barrier_pkhash(target_pk.as_slice())?;
            let target_ek = kyber768::PublicKey::from_bytes(target_pk.as_slice())
                .map_err(|_| anyhow!("invalid ML-KEM target public key in snapshot_pre"))?;
            let (ss, kem_ct) = kyber768::encapsulate(&target_ek);
            let mut ss_bytes = [0u8; 32];
            ss_bytes.copy_from_slice(ss.as_bytes());

            let aad = to_cbor_vec(&BarrierWrapAadPreimage(
                gid,
                barrier_version,
                &revocation_roots_hash,
                updater_leaf,
                source_node,
                target_node,
                &target_pkhash,
            ))
            .map_err(|err| anyhow!("encode barrier wrap aad: {err}"))?;
            let nonce_full = h_l(
                "barrier/wrap/nonce",
                &BarrierWrapNoncePreimage(source_node, target_node),
            )
            .map_err(|err| anyhow!("derive barrier wrap nonce: {err}"))?;
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&nonce_full[..12]);

            let source_secret = path_secrets
                .get(&source_node)
                .ok_or_else(|| anyhow!("missing path secret for source node {source_node}"))?;
            use chacha20poly1305::{
                ChaCha20Poly1305,
                aead::{Aead, KeyInit, Payload},
            };
            let cipher = ChaCha20Poly1305::new((&ss_bytes).into());
            let wrapped_ps = match cipher.encrypt(
                (&nonce).into(),
                Payload {
                    msg: source_secret.as_slice(),
                    aad: aad.as_slice(),
                },
            ) {
                Ok(wrapped_ps) => wrapped_ps,
                Err(_) => {
                    ss_bytes.zeroize();
                    return Err(anyhow!("barrier wrap encrypt failed"));
                }
            };
            ss_bytes.zeroize();
            node_ciphertexts.push(NodeCiphertextWire(
                source_node,
                target_node,
                target_pkhash[..16].to_vec(),
                KemCiphertext::as_bytes(&kem_ct).to_vec(),
                wrapped_ps,
            ));
        }
    }
    node_ciphertexts.sort_by_key(|entry| (entry.0, entry.1));

    let cover_payload = KemTreeCoverPayloadWire(
        updater_leaf,
        path_nodes,
        None,
        node_ciphertexts,
        new_public_keys,
    );
    let cover_bytes = to_cbor_vec(&cover_payload).context("encode barrier cover payload")?;

    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        barrier_version,
        prev_barrier_version,
        n_max,
        revocation_roots_hash.to_vec(),
        kem_tree_hash_before.to_vec(),
        kem_tree_hash_after.to_vec(),
        cover_bytes,
    );
    let raw_update = to_cbor_vec(&update).context("encode barrier update")?;
    let barrier_update_digest = compute_barrier_update_digest(raw_update.as_slice())?;
    zeroize_path_secret_map(&mut path_secrets);
    Ok(BarrierUpdateBuildResult {
        raw_update,
        barrier_update_digest,
        kem_tree_hash_after,
        k_barrier_new: Zeroizing::new(k_barrier_new),
        on_path_key_material,
    })
}
