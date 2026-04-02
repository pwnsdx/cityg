use super::*;
use crate::barrier_shared::require_current_state_history_commitment;
use cityg_api_client::to_core_history_commitment;
use cityg_client::barrier_state_auth::{
    ensure_non_regressing_authenticated_current_state as ensure_non_regressing_authenticated_current_state_core,
    validate_barrier_tree_snapshot_auth as validate_barrier_tree_snapshot_auth_core,
};

pub(super) fn validate_barrier_tree_snapshot_auth(
    expected_hash: &[u8; 32],
    expected_n_max: u64,
    snapshot: &BarrierPublicTree,
) -> Result<()> {
    validate_barrier_tree_snapshot_auth_core(
        expected_hash,
        expected_n_max,
        &snapshot.kem_tree_hash_after,
        snapshot.pk_entries.as_slice(),
    )
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

fn cached_authenticated_snapshot_for_hash(
    session: &AppSession,
    expected_hash: &[u8; 32],
) -> Result<Option<(BarrierPublicTree, HistoryCommitment)>> {
    if session.barrier_state.kem_tree_hash_after != *expected_hash {
        return Ok(None);
    }
    if let Some(snapshot) = current_public_tree_cache(session) {
        let current_history_commitment = session
            .barrier_state
            .current_history_commitment
            .ok_or_else(|| {
                anyhow!(
                    "missing authenticated current-state history commitment for cached current public tree"
                )
            })?;
        return Ok(Some(((*snapshot).clone(), current_history_commitment)));
    }
    Ok(retained_authenticated_current_public_tree_cache(session)
        .map(|(snapshot, history_commitment)| ((*snapshot).clone(), history_commitment)))
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

async fn fetch_validated_public_tree(
    client: &CitygApiClient,
    room_id: &str,
    expected_hash: &[u8; 32],
    expected_n_max: u64,
) -> Result<(BarrierPublicTree, HistoryCommitment)> {
    let snapshot_response = client
        .barrier_fetch_public_tree(room_id, expected_hash)
        .await?;
    if snapshot_response.tree.n_max != expected_n_max {
        return Err(anyhow!(
            "n_max mismatch (expected {expected_n_max}, got {})",
            snapshot_response.tree.n_max
        ));
    }
    validate_barrier_tree_snapshot_auth(expected_hash, expected_n_max, &snapshot_response.tree)?;
    Ok((snapshot_response.tree, snapshot_response.history_commitment))
}

pub(super) async fn resolve_authenticated_snapshot_for_hash(
    client: &CitygApiClient,
    room_id: &str,
    session: &AppSession,
    expected_hash: &[u8; 32],
    expected_n_max: u64,
) -> Result<(BarrierPublicTree, HistoryCommitment)> {
    if let Some(snapshot) = cached_authenticated_snapshot_for_hash(session, expected_hash)? {
        return Ok(snapshot);
    }
    fetch_validated_public_tree(client, room_id, expected_hash, expected_n_max)
        .await
        .map_err(|err| anyhow!("barrier tree snapshot auth failure (960.9): {err}"))
}

pub(super) async fn ensure_current_state_commitment_aligned_snapshot(
    client: &CitygApiClient,
    room_id: &str,
    expected_hash: &[u8; 32],
    expected_n_max: u64,
    snapshot: BarrierPublicTree,
    snapshot_history_commitment: HistoryCommitment,
    join_history_commitment: &HistoryCommitment,
    revoked_history_commitment: &HistoryCommitment,
) -> Result<(BarrierPublicTree, HistoryCommitment)> {
    if require_current_state_history_commitment(
        &snapshot_history_commitment,
        join_history_commitment,
        revoked_history_commitment,
    )
    .is_ok()
    {
        return Ok((snapshot, snapshot_history_commitment));
    }

    let (snapshot, snapshot_history_commitment) =
        fetch_validated_public_tree(client, room_id, expected_hash, expected_n_max)
            .await
            .map_err(|err| anyhow!("barrier tree snapshot auth failure (960.9): {err}"))?;

    if require_current_state_history_commitment(
        &snapshot_history_commitment,
        join_history_commitment,
        revoked_history_commitment,
    )
    .is_err()
    {
        return Err(anyhow!(
            "barrier full chain-check prevalidation failed (960.9): before={} snapshot={}#{} joins={}#{} revoked={}#{}",
            hex_encode(expected_hash),
            hex_encode(snapshot_history_commitment.history_commitment_id),
            snapshot_history_commitment.history_seq,
            hex_encode(join_history_commitment.history_commitment_id),
            join_history_commitment.history_seq,
            hex_encode(revoked_history_commitment.history_commitment_id),
            revoked_history_commitment.history_seq,
        ));
    }

    Ok((snapshot, snapshot_history_commitment))
}

pub(super) async fn resolve_bootstrap_current_snapshot(
    client: &CitygApiClient,
    room_id: &str,
    session: &AppSession,
    expected_n_max: u64,
) -> Result<BarrierPublicTree> {
    if let Some((snapshot, _)) = retained_authenticated_current_public_tree_cache(session) {
        return Ok((*snapshot).clone());
    }
    let (snapshot, _) = fetch_validated_public_tree(
        client,
        room_id,
        &session.barrier_state.kem_tree_hash_after,
        expected_n_max,
    )
    .await
    .map_err(|err| anyhow!("join_finalize bootstrap snapshot auth failure (960.9): {err}"))?;
    Ok(snapshot)
}

pub(super) async fn resolve_bootstrap_predecessor_snapshot(
    client: &CitygApiClient,
    room_id: &str,
    session: &mut AppSession,
    predecessor_hash: &[u8; 32],
    predecessor_barrier_version: u64,
    expected_n_max: u64,
) -> Result<BarrierPublicTree> {
    if let Some(snapshot) = retained_public_tree_cache(session, predecessor_hash, expected_n_max) {
        return Ok((*snapshot).clone());
    }

    let (snapshot, _) =
        fetch_validated_public_tree(client, room_id, predecessor_hash, expected_n_max)
            .await
            .map_err(|err| {
                anyhow!("join_finalize bootstrap snapshot auth failure (960.9): {err}")
            })?;
    retain_tree_hash_authenticated_public_tree(
        &mut session.barrier_state,
        predecessor_barrier_version,
        Arc::new(snapshot.clone()),
    );
    Ok(snapshot)
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
    let local_history_commitment_core = local_history_commitment.map(to_core_history_commitment);
    let advertised_history_commitment_core =
        to_core_history_commitment(advertised_history_commitment);
    ensure_non_regressing_authenticated_current_state_core(
        local_barrier_version,
        local_kem_tree_hash_after,
        local_history_commitment_core.as_ref(),
        local_history_authority_extension.as_ref(),
        advertised_barrier_version,
        advertised_kem_tree_hash_after,
        &advertised_history_commitment_core,
        advertised_history_authority_extension.as_ref(),
        context,
    )
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
