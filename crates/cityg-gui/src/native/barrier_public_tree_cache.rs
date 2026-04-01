use super::*;

pub(super) fn validate_barrier_tree_snapshot_auth(
    expected_hash: &[u8; 32],
    expected_n_max: u64,
    snapshot: &BarrierPublicTree,
) -> Result<()> {
    if snapshot.kem_tree_hash_after != *expected_hash {
        return Err(anyhow!(
            "barrier tree snapshot auth failure (960.9): hash mismatch"
        ));
    }
    let computed_hash = compute_barrier_tree_hash(expected_n_max, snapshot.pk_entries.as_slice())?;
    if computed_hash != *expected_hash {
        return Err(anyhow!(
            "barrier tree snapshot auth failure (960.9): tree hash mismatch"
        ));
    }
    Ok(())
}

pub(super) fn current_public_tree_cache_matches(
    session: &AppSession,
    snapshot: &BarrierPublicTree,
) -> bool {
    snapshot.n_max == session.barrier_state.n_max.max(1)
        && snapshot.kem_tree_hash_after == session.barrier_state.kem_tree_hash_after
}

pub(super) fn current_public_tree_cache(session: &AppSession) -> Option<Arc<BarrierPublicTree>> {
    session
        .barrier_state
        .current_public_tree
        .as_ref()
        .filter(|snapshot| current_public_tree_cache_matches(session, snapshot))
        .cloned()
}

const MAX_RETAINED_LOCAL_PUBLIC_TREE_SNAPSHOTS: usize = 8;

fn retained_public_tree_cache_matches(
    expected_hash: &[u8; 32],
    expected_n_max: u64,
    snapshot: &BarrierPublicTree,
) -> bool {
    snapshot.n_max == expected_n_max.max(1) && snapshot.kem_tree_hash_after == *expected_hash
}

fn retain_public_tree_snapshot(
    state: &mut BarrierSecretState,
    barrier_version: u64,
    history_commitment: Option<HistoryCommitment>,
    snapshot: Arc<BarrierPublicTree>,
) {
    state.retained_public_trees.retain(|entry| {
        !retained_public_tree_cache_matches(
            &snapshot.kem_tree_hash_after,
            snapshot.n_max,
            entry.snapshot.as_ref(),
        )
    });
    state.retained_public_trees.insert(
        0,
        RetainedBarrierPublicTree {
            barrier_version,
            history_commitment,
            snapshot,
        },
    );
    state
        .retained_public_trees
        .truncate(MAX_RETAINED_LOCAL_PUBLIC_TREE_SNAPSHOTS);
}

pub(super) fn retain_authenticated_current_public_tree(session: &mut AppSession) -> Result<()> {
    let snapshot = current_public_tree_cache(session).ok_or_else(|| {
        anyhow!(
            "cannot retain authenticated current public tree without a matching cached snapshot"
        )
    })?;
    let history_commitment = session
        .barrier_state
        .current_history_commitment
        .ok_or_else(|| {
            anyhow!("cannot retain authenticated current public tree without HistoryCommitment")
        })?;
    let barrier_version = session.barrier_state.barrier_version;
    retain_public_tree_snapshot(
        &mut session.barrier_state,
        barrier_version,
        Some(history_commitment),
        snapshot,
    );
    Ok(())
}

pub(super) fn retain_tree_hash_authenticated_public_tree(
    state: &mut BarrierSecretState,
    barrier_version: u64,
    snapshot: Arc<BarrierPublicTree>,
) {
    retain_public_tree_snapshot(state, barrier_version, None, snapshot);
}

pub(super) fn retained_authenticated_current_public_tree_cache(
    session: &AppSession,
) -> Option<(Arc<BarrierPublicTree>, HistoryCommitment)> {
    let current_history_commitment = session.barrier_state.current_history_commitment?;
    session
        .barrier_state
        .retained_public_trees
        .iter()
        .find(|entry| {
            entry.barrier_version == session.barrier_state.barrier_version
                && entry.history_commitment == Some(current_history_commitment)
                && retained_public_tree_cache_matches(
                    &session.barrier_state.kem_tree_hash_after,
                    session.barrier_state.n_max,
                    entry.snapshot.as_ref(),
                )
        })
        .map(|entry| (entry.snapshot.clone(), current_history_commitment))
}

pub(super) fn retained_public_tree_cache(
    session: &AppSession,
    expected_hash: &[u8; 32],
    expected_n_max: u64,
) -> Option<Arc<BarrierPublicTree>> {
    current_public_tree_cache(session)
        .filter(|snapshot| {
            retained_public_tree_cache_matches(expected_hash, expected_n_max, snapshot)
        })
        .or_else(|| {
            session
                .barrier_state
                .retained_public_trees
                .iter()
                .find(|entry| {
                    retained_public_tree_cache_matches(
                        expected_hash,
                        expected_n_max,
                        entry.snapshot.as_ref(),
                    )
                })
                .map(|entry| entry.snapshot.clone())
        })
}

pub(super) fn clear_current_public_tree_cache(state: &mut BarrierSecretState) {
    state.current_public_tree = None;
}

pub(super) fn clear_all_public_tree_caches(state: &mut BarrierSecretState) {
    state.current_public_tree = None;
    state.retained_public_trees.clear();
}

#[allow(clippy::too_many_arguments)]
pub(super) fn ensure_non_regressing_authenticated_current_state(
    local_barrier_version: u64,
    local_kem_tree_hash_after: &[u8; 32],
    local_history_commitment: Option<&HistoryCommitment>,
    local_history_authority_extension: Option<HistoryAuthorityExtension>,
    advertised_barrier_version: u64,
    advertised_kem_tree_hash_after: &[u8; 32],
    advertised_history_commitment: &HistoryCommitment,
    advertised_history_authority_extension: Option<HistoryAuthorityExtension>,
    context: &str,
) -> Result<()> {
    if advertised_barrier_version < local_barrier_version {
        return Err(anyhow!(
            "{context} current barrier_version regressed below locally authenticated state (960.9)"
        ));
    }

    let Some(local_history_commitment) = local_history_commitment else {
        return Ok(());
    };

    if advertised_history_commitment.history_seq < local_history_commitment.history_seq {
        return Err(anyhow!(
            "{context} current history commitment regressed below locally authenticated state (960.9)"
        ));
    }

    if advertised_history_commitment.history_seq == local_history_commitment.history_seq {
        if advertised_history_commitment != local_history_commitment {
            return Err(anyhow!(
                "{context} current history commitment conflicts with locally authenticated state (960.9)"
            ));
        }
        if advertised_barrier_version != local_barrier_version {
            return Err(anyhow!(
                "{context} current barrier_version conflicts with locally authenticated current history commitment (960.9)"
            ));
        }
        if advertised_kem_tree_hash_after != local_kem_tree_hash_after {
            return Err(anyhow!(
                "{context} current kem_tree_hash_after conflicts with locally authenticated current history commitment (960.9)"
            ));
        }
        if advertised_history_authority_extension != local_history_authority_extension {
            return Err(anyhow!(
                "{context} history authority extension conflicts with locally authenticated state (960.9)"
            ));
        }
    }

    Ok(())
}

pub(super) fn install_current_public_tree_cache(
    session: &mut AppSession,
    snapshot: BarrierPublicTree,
) -> Result<()> {
    validate_barrier_tree_snapshot_auth(
        &session.barrier_state.kem_tree_hash_after,
        session.barrier_state.n_max.max(1),
        &snapshot,
    )?;
    session.barrier_state.current_public_tree = Some(Arc::new(snapshot));
    Ok(())
}

pub(super) fn install_authenticated_current_state(
    session: &mut AppSession,
    barrier_version: u64,
    barrier_roots_hash: [u8; 32],
    kem_tree_hash_after: [u8; 32],
    history_commitment: HistoryCommitment,
    history_authority_extension: Option<HistoryAuthorityExtension>,
    global_history_attestation_bytes: Vec<u8>,
) {
    let authenticated_public_state_changed = session.barrier_state.barrier_version
        != barrier_version
        || session.barrier_state.barrier_roots_hash != barrier_roots_hash
        || session.barrier_state.kem_tree_hash_after != kem_tree_hash_after;
    session.barrier_state.barrier_version = barrier_version;
    session.barrier_state.barrier_roots_hash = barrier_roots_hash;
    session.barrier_state.kem_tree_hash_after = kem_tree_hash_after;
    session.barrier_state.current_history_view_id = history_commitment.history_view_id;
    session.barrier_state.current_history_commitment = Some(history_commitment);
    session.barrier_state.current_history_authority_extension = history_authority_extension;
    session
        .barrier_state
        .current_global_history_attestation_bytes = global_history_attestation_bytes;
    if !session
        .barrier_state
        .current_public_tree
        .as_ref()
        .is_some_and(|snapshot| current_public_tree_cache_matches(session, snapshot))
    {
        clear_current_public_tree_cache(&mut session.barrier_state);
    }
    if authenticated_public_state_changed {
        session.barrier_state.current_barrier_full_verified = false;
    }
}
