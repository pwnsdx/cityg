use super::*;
use crate::barrier_shared::{
    BarrierJoinSnapshotRecord, expected_same_rrh_barrier_reason,
    require_current_state_history_commitment, require_same_history_commitment,
};
#[allow(unused_imports)]
pub(super) use cityg_client::barrier_build::{BarrierWrapAadPreimage, BarrierWrapNoncePreimage};
#[allow(unused_imports)]
pub(super) use cityg_client::barrier_crypto::{
    ML_KEM_EXPANDED_DK_BYTES, decapsulate_internal_node_shared_secret,
    derive_internal_node_key_material, derive_k_fs_after_pcs,
};
pub(super) use cityg_client::barrier_transition::compute_barrier_snapshot_transition;
#[allow(unused_imports)]
pub(super) use cityg_client::barrier_update::{
    BarrierUpdateWire, KemTreeCoverPayloadWire, NewPublicKeyWire, NodeCiphertextWire,
    ParsedBarrierUpdate, ParsedNodeCiphertext, compute_barrier_update_digest,
    normalize_max_barrier_update_bytes, parse_barrier_update_for_recover,
};

pub(super) const BARRIER_CODE_RECOVER_NO_MATCH: u32 = 9606;
pub(super) const BARRIER_CODE_SNAPSHOT_AUTH_FAILURE: u32 = 9609;

#[derive(Clone, Debug)]
pub(super) struct BarrierRecoverResult {
    pub(super) barrier_version: u64,
    pub(super) k_barrier_new: Zeroizing<[u8; 32]>,
    pub(super) kem_tree_hash_after: [u8; 32],
    pub(super) k_fs_after_pcs: Option<Zeroizing<[u8; 32]>>,
    pub(super) derived_node_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
}

#[derive(Clone, Debug)]
pub(super) struct BarrierUpdateBuildResult {
    pub(super) raw_update: Vec<u8>,
    pub(super) barrier_update_digest: [u8; 32],
    pub(super) kem_tree_hash_after: [u8; 32],
    pub(super) k_barrier_new: Zeroizing<[u8; 32]>,
    pub(super) on_path_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
    pub(super) snapshot_post: Arc<BarrierPublicTree>,
}

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
    let genesis_local_case = !local_barrier_initialized
        && parsed.prev_barrier_version == 0
        && parsed.barrier_version == 0;
    let valid_local_progression = genesis_local_case
        || (local_barrier_initialized
            && parsed.prev_barrier_version == local_barrier_version
            && parsed.barrier_version == local_barrier_version.saturating_add(1));
    if !valid_local_progression {
        return Err(anyhow!(
            "barrier full chain-check prevalidation failed (960.7): local barrier version progression mismatch"
        ));
    }

    let expected_snapshot_hash = parsed.kem_tree_hash_before;
    let (mut snapshot_prev, mut snapshot_prev_history_commitment) = if let Some(snapshot_prev) =
        (session.barrier_state.kem_tree_hash_after == expected_snapshot_hash)
            .then(|| current_public_tree_cache(session))
            .flatten()
    {
        let current_history_commitment = session
            .barrier_state
            .current_history_commitment
            .ok_or_else(|| {
                anyhow!(
                    "barrier tree snapshot auth failure (960.9): missing authenticated current-state history commitment for cached current public tree"
                )
            })?;
        ((*snapshot_prev).clone(), current_history_commitment)
    } else if let Some((snapshot_prev, current_history_commitment)) =
        (session.barrier_state.kem_tree_hash_after == expected_snapshot_hash)
            .then(|| retained_authenticated_current_public_tree_cache(session))
            .flatten()
    {
        ((*snapshot_prev).clone(), current_history_commitment)
    } else {
        let snapshot_prev_response = client
            .barrier_fetch_public_tree(room_id, &expected_snapshot_hash)
            .await
            .map_err(|err| anyhow!("barrier tree snapshot auth failure (960.9): {err}"))?;
        let snapshot_prev = snapshot_prev_response.tree;
        if snapshot_prev.n_max != n_max {
            return Err(anyhow!(
                "barrier tree snapshot auth failure (960.9): n_max mismatch (expected {n_max}, got {})",
                snapshot_prev.n_max
            ));
        }
        validate_barrier_tree_snapshot_auth(&expected_snapshot_hash, n_max, &snapshot_prev)?;
        (snapshot_prev, snapshot_prev_response.history_commitment)
    };

    let revoked_since_root =
        header_bytes32(header_map, hdr::HDR_REVOKED_SINCE_ROOT).ok_or_else(|| {
            anyhow!(
                "barrier full chain-check prevalidation failed (960.7): missing revoked_since_root"
            )
        })?;
    let revoked_root = header_bytes32(header_map, hdr::HDR_REVOKED_ROOT).ok_or_else(|| {
        anyhow!("barrier full chain-check prevalidation failed (960.7): missing revoked_root")
    })?;
    let revocation_roots_hash = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    if parsed.revocation_roots_hash != revocation_roots_hash {
        return Err(anyhow!(
            "barrier full chain-check prevalidation failed (960.7): revocation_roots_hash mismatch"
        ));
    }
    let join_resolution = client
        .barrier_resolve_joins_since(room_id, parsed.prev_barrier_version)
        .await
        .map_err(|err| anyhow!("barrier full chain-check dependency failure (960.8): {err}"))?;
    let revoked_resolution = client
        .barrier_resolve_revoked_leaves(room_id, &revocation_roots_hash)
        .await
        .map_err(|err| anyhow!("barrier full chain-check dependency failure (960.8): {err}"))?;
    let join_record_count = join_resolution.records.len();
    let revoked_leaf_count = revoked_resolution.leaf_indices.len();
    if require_current_state_history_commitment(
        &snapshot_prev_history_commitment,
        &join_resolution.history_commitment,
        &revoked_resolution.history_commitment,
    )
    .is_err()
    {
        let snapshot_prev_response = client
            .barrier_fetch_public_tree(room_id, &expected_snapshot_hash)
            .await
            .map_err(|err| anyhow!("barrier tree snapshot auth failure (960.9): {err}"))?;
        if snapshot_prev_response.tree.n_max != n_max {
            return Err(anyhow!(
                "barrier tree snapshot auth failure (960.9): n_max mismatch (expected {n_max}, got {})",
                snapshot_prev_response.tree.n_max
            ));
        }
        validate_barrier_tree_snapshot_auth(
            &expected_snapshot_hash,
            n_max,
            &snapshot_prev_response.tree,
        )?;
        snapshot_prev = snapshot_prev_response.tree;
        snapshot_prev_history_commitment = snapshot_prev_response.history_commitment;
    }
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

    if !genesis_local_case {
        if session.barrier_state.barrier_roots_hash == parsed.revocation_roots_hash {
            let expected_reason = expected_same_rrh_barrier_reason(
                join_resolution.records.as_slice(),
                parsed.updater_leaf,
            );
            if barrier_reason != expected_reason {
                return Err(anyhow!(
                    "barrier full chain-check prevalidation failed (960.7): local barrier_roots_hash unchanged but barrier_update_reason != {expected_reason}"
                ));
            }
        } else if barrier_reason != 0 {
            return Err(anyhow!(
                "barrier full chain-check prevalidation failed (960.7): local barrier_roots_hash changed but barrier_update_reason != 0"
            ));
        }
    }

    let parsed_for_hash = parsed.clone();
    let snapshot_prev_entries = snapshot_prev.pk_entries.clone();
    let join_records_core: Vec<_> = join_resolution
        .records
        .iter()
        .map(|record| BarrierJoinSnapshotRecord {
            leaf_index: record.leaf_index,
            ek_leaf: record.ek_leaf.clone(),
        })
        .collect();
    let revoked_leaf_indices = revoked_resolution.leaf_indices.clone();
    let (expected_before, expected_after, snapshot_post) =
        tokio::task::spawn_blocking(move || -> Result<([u8; 32], [u8; 32], BarrierPublicTree)> {
            let transition = compute_barrier_snapshot_transition(
                n_max,
                snapshot_prev_entries.as_slice(),
                join_records_core.as_slice(),
                revoked_leaf_indices.as_slice(),
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
            revoked_leaf_count,
            expected_before = %hex_encode(expected_before),
            parsed_before = %hex_encode(parsed.kem_tree_hash_before),
            snapshot_prev_hash = %hex_encode(expected_snapshot_hash),
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
    require_same_history_commitment(current_commitment, &expected_commitment)
        .map_err(|_| anyhow!("join_finalize bootstrap current_history_commitment mismatch"))?;
    if session
        .barrier_state
        .current_global_history_attestation_bytes
        .is_empty()
    {
        if expected_extension.is_some() {
            return Err(anyhow!(
                "join_finalize bootstrap missing current global history attestation bytes for authority-bound current state"
            ));
        }
    } else if expected_extension.is_none() {
        return Err(anyhow!(
            "join_finalize bootstrap uses unsupported or missing history authority extension for attested current state"
        ));
    }
    if predecessor_hash == [0u8; 32] {
        return Err(anyhow!(
            "join_finalize bootstrap missing predecessor committed kem_tree_hash_after"
        ));
    }
    if session
        .barrier_state
        .bootstrap_current_barrier_update
        .is_empty()
    {
        return Err(anyhow!(
            "join_finalize bootstrap missing current barrier_update bytes"
        ));
    }

    let n_max = session.barrier_state.n_max.max(1);
    let max_barrier_update_bytes =
        normalize_max_barrier_update_bytes(session.barrier_state.max_barrier_update_bytes.max(1))?;
    let parsed = parse_barrier_update_for_recover(
        session
            .barrier_state
            .bootstrap_current_barrier_update
            .as_slice(),
        n_max,
        max_barrier_update_bytes,
    )
    .map_err(|err| anyhow!("join_finalize bootstrap verification failed (960.7): {err}"))?;

    if parsed.barrier_version != session.barrier_state.barrier_version {
        return Err(anyhow!(
            "join_finalize bootstrap verification failed (960.7): current barrier_version mismatch"
        ));
    }
    if parsed.kem_tree_hash_after != session.barrier_state.kem_tree_hash_after {
        return Err(anyhow!(
            "join_finalize bootstrap verification failed (960.7): current kem_tree_hash_after mismatch"
        ));
    }

    let current_snapshot =
        if let Some((snapshot, _)) = retained_authenticated_current_public_tree_cache(session) {
            (*snapshot).clone()
        } else {
            let current_snapshot_response = client
                .barrier_fetch_public_tree(room_id, &session.barrier_state.kem_tree_hash_after)
                .await
                .map_err(|err| {
                    anyhow!("join_finalize bootstrap snapshot auth failure (960.9): {err}")
                })?;
            if current_snapshot_response.tree.n_max != n_max {
                return Err(anyhow!(
                    "join_finalize bootstrap snapshot auth failure (960.9): current n_max mismatch"
                ));
            }
            current_snapshot_response.tree
        };
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

    let snapshot_base = if let Some(snapshot) =
        retained_public_tree_cache(session, &predecessor_hash, n_max)
    {
        (*snapshot).clone()
    } else {
        let snapshot_base_response = client
            .barrier_fetch_public_tree(room_id, &predecessor_hash)
            .await
            .map_err(|err| {
                anyhow!("join_finalize bootstrap snapshot auth failure (960.9): {err}")
            })?;
        if snapshot_base_response.tree.n_max != n_max {
            return Err(anyhow!(
                "join_finalize bootstrap snapshot auth failure (960.9): predecessor n_max mismatch"
            ));
        }
        validate_barrier_tree_snapshot_auth(
            &predecessor_hash,
            n_max,
            &snapshot_base_response.tree,
        )?;
        retain_tree_hash_authenticated_public_tree(
            &mut session.barrier_state,
            parsed.prev_barrier_version,
            Arc::new(snapshot_base_response.tree.clone()),
        );
        snapshot_base_response.tree
    };
    if snapshot_base.n_max != n_max {
        return Err(anyhow!(
            "join_finalize bootstrap snapshot auth failure (960.9): predecessor n_max mismatch"
        ));
    }
    validate_barrier_tree_snapshot_auth(&predecessor_hash, n_max, &snapshot_base)?;

    if session.barrier_state.bootstrap_join_records.is_empty()
        && session
            .barrier_state
            .bootstrap_revoked_leaf_indices
            .is_empty()
        && (parsed.prev_barrier_version != 0 || parsed.revocation_roots_hash != [0u8; 32])
    {
        return Err(anyhow!(
            "join_finalize bootstrap missing authenticated JoinSet / RevokedLeafSet provisioning"
        ));
    }

    let join_records = session.barrier_state.bootstrap_join_records.clone();
    let revoked_leaf_indices = session.barrier_state.bootstrap_revoked_leaf_indices.clone();

    let parsed_for_hash = parsed.clone();
    let snapshot_base_entries = snapshot_base.pk_entries.clone();
    let join_records_core: Vec<_> = join_records
        .iter()
        .map(|record| BarrierJoinSnapshotRecord {
            leaf_index: record.leaf_index,
            ek_leaf: record.ek_leaf.clone(),
        })
        .collect();
    let (expected_before, expected_after) =
        tokio::task::spawn_blocking(move || -> Result<([u8; 32], [u8; 32])> {
            let transition = compute_barrier_snapshot_transition(
                n_max,
                snapshot_base_entries.as_slice(),
                join_records_core.as_slice(),
                revoked_leaf_indices.as_slice(),
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
